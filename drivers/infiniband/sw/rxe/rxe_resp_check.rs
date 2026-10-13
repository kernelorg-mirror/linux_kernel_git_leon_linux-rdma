// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Responder admission over checked packets and owned memory state.

#![forbid(unsafe_code)]

use super::{
    rxe_mr::MrRef,
    rxe_mw_state::Window,
    rxe_param::*,
    rxe_resp_memory::RequestMemory,
    rxe_types::ResponderState,
    rxe_wire::{
        psn_compare,
        Transport, //
    },
    rxe_wqe::ReceiveWqe, //
};
use kernel::rdma::{
    Access,
    AccessFlags, //
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Protocol {
    Reliable,
    Unreliable,
    Datagram,
}

// FETH placement type and selectivity level (IBA A19.4.1).
const FLUSH_GLOBAL: u8 = 1;
const FLUSH_PERSISTENT: u8 = 2;
const FLUSH_MR: u8 = 1;
// UD receives reserve a GRH even when the incoming network header is IPv4.
const GRH_BYTES: u64 = 40;

/// Checks wrapping PSN order and updates duplicate-NAK and UC drop suppression.
pub(super) fn check_psn(
    protocol: Protocol,
    psn: u32,
    expected: u32,
    mask: u32,
    sent_nak: &mut bool,
    drop_message: &mut bool,
) -> ResponderState {
    let diff = psn_compare(psn, expected);
    match protocol {
        Protocol::Reliable => {
            if diff > 0 {
                if *sent_nak {
                    return ResponderState::Cleanup;
                }
                *sent_nak = true;
                return ResponderState::ErrPsnOutOfSeq;
            }
            if diff < 0 {
                return ResponderState::DuplicateRequest;
            }
            *sent_nak = false;
        }
        Protocol::Unreliable if *drop_message || diff != 0 => {
            *drop_message = mask & RXE_START_MASK == 0;
            if *drop_message {
                return ResponderState::Cleanup;
            }
        }
        _ => (),
    }
    ResponderState::ChkOpSeq
}

/// Checks first/middle/last sequencing; RC and UC use the same low opcode bits.
pub(super) fn check_sequence(protocol: Protocol, previous: i32, opcode: u8) -> ResponderState {
    if protocol == Protocol::Datagram {
        return ResponderState::ChkOpValid;
    }
    let base = if protocol == Protocol::Unreliable {
        0x20
    } else {
        0
    };
    let current = i32::from(opcode) - base;
    let previous = previous - base;
    let send_tail = matches!(current, 1..=3) || (protocol == Protocol::Reliable && current == 22);
    let write_tail = matches!(current, 7..=9);
    let valid = match previous {
        0 | 1 => send_tail,
        6 | 7 => write_tail,
        _ => true,
    };
    if !valid {
        return if protocol == Protocol::Reliable {
            ResponderState::ErrMissingOpcodeLastC
        } else {
            ResponderState::ErrMissingOpcodeLastD1E
        };
    }
    if !matches!(previous, 0 | 1 | 6 | 7) && (send_tail || write_tail) {
        return if protocol == Protocol::Reliable {
            ResponderState::ErrMissingOpcodeFirst
        } else {
            ResponderState::Cleanup
        };
    }
    ResponderState::ChkOpValid
}

fn flush_access(kind: u8) -> AccessFlags {
    let mut access = AccessFlags::empty();
    if kind & FLUSH_GLOBAL != 0 {
        access |= Access::FlushGlobal;
    }
    if kind & FLUSH_PERSISTENT != 0 {
        access |= Access::FlushPersistent;
    }
    access
}

/// Checks the requested operation against the QP's enabled access flags.
pub(super) fn check_operation(
    protocol: Protocol,
    access: AccessFlags,
    wire: &Transport<'_>,
) -> ResponderState {
    let mask = wire.mask();
    if protocol == Protocol::Reliable {
        let mut required = AccessFlags::empty();
        if mask & RXE_READ_MASK != 0 {
            required |= Access::RemoteRead;
        }
        if mask & (RXE_WRITE_MASK | RXE_ATOMIC_WRITE_MASK) != 0 {
            required |= Access::RemoteWrite;
        }
        if mask & RXE_ATOMIC_MASK != 0 {
            required |= Access::RemoteAtomic;
        }
        if mask & RXE_FLUSH_MASK != 0 {
            let Ok(flush) = wire.flush() else {
                return ResponderState::ErrUnsupportedOpcode;
            };
            if flush.kind == 0
                || flush.kind & !(FLUSH_GLOBAL | FLUSH_PERSISTENT) != 0
                || flush.level > FLUSH_MR
            {
                return ResponderState::ErrUnsupportedOpcode;
            }
            required |= flush_access(flush.kind);
        }
        if !access.contains_all(required) {
            return ResponderState::ErrUnsupportedOpcode;
        }
    } else if protocol == Protocol::Unreliable
        && mask & RXE_WRITE_MASK != 0
        && !access.contains(Access::RemoteWrite)
    {
        return ResponderState::Cleanup;
    }
    ResponderState::ChkResource
}

/// Checks payload, datagram receive capacity and declared remote transfer length.
pub(super) fn check_length(
    protocol: Protocol,
    wire: &Transport<'_>,
    mtu: u32,
    receive: Option<&ReceiveWqe>,
) -> ResponderState {
    let payload = wire.payload_len() as u64;
    let mask = wire.mask();
    if protocol == Protocol::Datagram
        && receive.is_none_or(|wqe| payload + GRH_BYTES > wqe.capacity())
    {
        return ResponderState::ErrLength;
    }
    if mask & RXE_PAYLOAD_MASK != 0 && protocol != Protocol::Datagram {
        let mtu = u64::from(mtu);
        let invalid = if mask & RXE_START_MASK != 0 && mask & RXE_END_MASK != 0 {
            payload > mtu
        } else if mask & (RXE_START_MASK | RXE_MIDDLE_MASK) != 0 {
            payload != mtu
        } else if mask & RXE_END_MASK != 0 {
            payload == 0 || payload > mtu
        } else {
            false
        };
        if invalid {
            return ResponderState::ErrLength;
        }
    }
    if mask & RXE_RETH_MASK != 0
        && !wire.remote().is_ok_and(|remote| {
            remote.length <= (1 << 31)
                && (mask & RXE_READ_MASK == 0
                    || (mtu != 0 && remote.length.div_ceil(mtu) <= 0x800000))
        })
    {
        return ResponderState::ErrLength;
    }
    if mask & RXE_RDMA_OP_MASK != 0 {
        ResponderState::ChkRkey
    } else {
        ResponderState::Execute
    }
}

/// Acquires an owned registration and checks window bounds and retained authorization.
///
/// Lookup callbacks return handles whose captured registration and binding versions are checked
/// again when the request accesses memory. No reference to a pool or QP is retained here.
pub(super) fn check_key(
    remote: &mut RequestMemory,
    wire: &Transport<'_>,
    mtu: u32,
    lookup: impl FnOnce(AccessFlags, u32) -> Option<MrRef>,
    lookup_window: impl FnOnce(AccessFlags, u32) -> Option<Window>,
) -> ResponderState {
    let mask = wire.mask();
    let violation = key_violation(mask);
    if mask & RXE_RETH_MASK != 0 {
        let Ok(request) = wire.remote() else {
            return ResponderState::ErrLength;
        };
        // Empty reads skip authorization, but replay must still match the wire key.
        remote.start(request.address, request.length, request.key);
    }
    let mut access = AccessFlags::empty();
    if mask & (RXE_READ_OR_WRITE_MASK | RXE_ATOMIC_WRITE_MASK) != 0 {
        access |= if mask & RXE_READ_MASK != 0 {
            Access::RemoteRead
        } else {
            Access::RemoteWrite
        };
    } else if mask & RXE_FLUSH_MASK != 0 {
        let Ok(flush) = wire.flush() else {
            return ResponderState::ErrLength;
        };
        access = flush_access(flush.kind);
    } else if mask & RXE_ATOMIC_MASK != 0 {
        let Ok(atomic) = wire.atomic() else {
            return ResponderState::ErrLength;
        };
        remote.start(atomic.address, 8, atomic.key);
        access = Access::RemoteAtomic.into();
    }
    let length = remote.residual;
    let payload = wire.payload_len();
    let pad = u32::from(wire.pad());
    if mask & RXE_ATOMIC_WRITE_MASK != 0 {
        if length != 8 || payload != 8 || pad != 0 {
            return ResponderState::ErrLength;
        }
    } else if mask & RXE_WRITE_MASK != 0 {
        if (mask & RXE_END_MASK != 0) != (length <= mtu) {
            return ResponderState::ErrLength;
        }
        if length > mtu {
            if payload != mtu as usize || pad != 0 {
                return ResponderState::ErrLength;
            }
        } else if payload != length as usize || pad != length.wrapping_neg() & 3 {
            return ResponderState::ErrLength;
        }
    }
    drop(remote.region.take());
    if mask & RXE_READ_OR_WRITE_MASK != 0 && mask & RXE_RETH_MASK != 0 && remote.length == 0 {
        if mask & RXE_WRITE_MASK != 0 && (wire.payload_len() != 0 || mask & RXE_END_MASK == 0) {
            return ResponderState::ErrLength;
        }
        return ResponderState::Execute;
    }
    let key = remote.key;
    let whole_mr =
        mask & RXE_FLUSH_MASK != 0 && wire.flush().is_ok_and(|flush| flush.level == FLUSH_MR);
    let (memory, window_version) = if (RXE_MIN_MW_INDEX..=RXE_MAX_MW_INDEX).contains(&(key >> 8)) {
        if whole_mr {
            return violation;
        }
        let Some(window) = lookup_window(access, key) else {
            return violation;
        };
        remote.offset = window.offset;
        if !whole_mr
            && remote
                .translated_address()
                .and_then(|address| window.check_range(address, u64::from(remote.residual)))
                .is_err()
        {
            return violation;
        }
        (window.memory, Some(window.version))
    } else {
        let Some(memory) = lookup(access, key) else {
            return violation;
        };
        (memory, None)
    };
    let length = remote.residual;
    if !whole_mr {
        let address = match remote.translated_address() {
            Ok(address) => address,
            Err(_) => return violation,
        };
        if memory
            .access()
            .check_range(address, u64::from(length))
            .is_err()
        {
            return violation;
        }
    }
    if remote.admit(memory, window_version).is_err() {
        return violation;
    }
    ResponderState::Execute
}

/// Selects a receive-work error or an asynchronous remote-access event.
pub(super) fn key_violation(mask: u32) -> ResponderState {
    if mask & RXE_IMMDT_MASK != 0 {
        ResponderState::ErrRkeyViolation
    } else {
        ResponderState::ErrRkeyViolationEvent
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_resp_check)]
mod tests {
    use super::*;
    use crate::{
        rxe_ring::Storage,
        rxe_wire::{
            packet_len,
            Base,
            Extension,
            TransportMut,
            ICRC_BYTES, //
        },
        rxe_wqe::{
            RECV_HEADER_SIZE,
            SGE_SIZE, //
        }, //
    };
    use kernel::prelude::*;

    fn packet<const N: usize>(
        opcode: u8,
        payload: usize,
        extensions: [Extension; N],
    ) -> Result<KVec<u8>> {
        let mut bytes = KVec::from_elem(0, packet_len(opcode, payload)?, GFP_KERNEL)?;
        let mut wire = TransportMut::initialize(
            &mut bytes,
            Base {
                opcode,
                psn: 0,
                qpn: 1,
                solicited: false,
                ack: false,
            },
            payload,
        )?;
        for extension in extensions {
            wire.set(extension)?;
        }
        bytes.truncate(bytes.len() - ICRC_BYTES);
        Ok(bytes)
    }

    #[test]
    fn wrapping_psns_suppress_repeated_naks_and_restart_uc_messages() {
        let mut nak = false;
        let mut discard = false;
        for (psn, expected, state, sent) in [
            (0, 0xffffff, ResponderState::ErrPsnOutOfSeq, true),
            (1, 0xffffff, ResponderState::Cleanup, true),
            (0xffffff, 0, ResponderState::DuplicateRequest, true),
            (0, 0, ResponderState::ChkOpSeq, false),
            (1, 0, ResponderState::ErrPsnOutOfSeq, true),
        ] {
            assert_eq!(
                check_psn(Protocol::Reliable, psn, expected, 0, &mut nak, &mut discard),
                state
            );
            assert_eq!(nak, sent);
        }
        assert_eq!(
            check_psn(
                Protocol::Unreliable,
                2,
                0,
                RXE_MIDDLE_MASK,
                &mut nak,
                &mut discard
            ),
            ResponderState::Cleanup
        );
        assert!(discard);
        assert_eq!(
            check_psn(
                Protocol::Unreliable,
                0,
                0,
                RXE_END_MASK,
                &mut nak,
                &mut discard
            ),
            ResponderState::Cleanup
        );
        assert_eq!(
            check_psn(
                Protocol::Unreliable,
                3,
                0,
                RXE_START_MASK,
                &mut nak,
                &mut discard
            ),
            ResponderState::ChkOpSeq
        );
        assert!(!discard);
        for protocol in [Protocol::Reliable, Protocol::Unreliable] {
            let base = if protocol == Protocol::Reliable {
                0
            } else {
                0x20
            };
            for (previous, opcode) in [(0, 1), (1, 2), (6, 7), (7, 9), (4, 0)] {
                assert_eq!(
                    check_sequence(protocol, previous + base, (opcode + base) as u8),
                    ResponderState::ChkOpValid
                );
            }
        }
        assert_eq!(
            check_sequence(Protocol::Reliable, 0, 6),
            ResponderState::ErrMissingOpcodeLastC
        );
        assert_eq!(
            check_sequence(Protocol::Unreliable, 0x20, 0x26),
            ResponderState::ErrMissingOpcodeLastD1E
        );
        assert_eq!(
            check_sequence(Protocol::Reliable, -1, 1),
            ResponderState::ErrMissingOpcodeFirst
        );
        assert_eq!(
            check_sequence(Protocol::Unreliable, -1, 0x21),
            ResponderState::Cleanup
        );
    }

    #[test]
    fn lengths_cover_fragment_boundaries_and_datagram_grh() -> Result {
        for (opcode, payload, valid) in [
            (0x04, 0, true),
            (0x04, 1024, true),
            (0x04, 1025, false),
            (0x00, 1023, false),
            (0x00, 1024, true),
            (0x01, 1025, false),
            (0x01, 1024, true),
            (0x02, 0, false),
            (0x02, 1, true),
            (0x02, 1024, true),
            (0x02, 1025, false),
        ] {
            for protocol in [Protocol::Reliable, Protocol::Unreliable] {
                let base = if protocol == Protocol::Reliable {
                    0
                } else {
                    0x20
                };
                let bytes = packet(opcode + base, payload, [])?;
                let expected = if valid {
                    ResponderState::Execute
                } else {
                    ResponderState::ErrLength
                };
                assert_eq!(
                    check_length(protocol, &Transport::parse(&bytes)?, 1024, None),
                    expected
                );
            }
        }
        for length in [1 << 31, (1 << 31) + 1] {
            let bytes = packet(
                0x0c,
                0,
                [Extension::Remote {
                    address: 0,
                    key: 1,
                    length,
                }],
            )?;
            let expected = if length == 1 << 31 {
                ResponderState::ChkRkey
            } else {
                ResponderState::ErrLength
            };
            for mtu in [256, 512, 1024, 2048, 4096] {
                assert_eq!(
                    check_length(Protocol::Reliable, &Transport::parse(&bytes)?, mtu, None),
                    expected
                );
            }
        }
        let storage = Storage::new(1, (RECV_HEADER_SIZE + SGE_SIZE) as u32, 64)?;
        let mut request = [0; RECV_HEADER_SIZE + SGE_SIZE];
        request[16..20].copy_from_slice(&41u32.to_ne_bytes());
        request[28..32].copy_from_slice(&1u32.to_ne_bytes());
        request[48..52].copy_from_slice(&41u32.to_ne_bytes());
        storage.memory().write(storage.offset(0), &request)?;
        let receive = ReceiveWqe::read(&storage, 0, 1)?;
        for (payload, expected) in [(1, ResponderState::Execute), (2, ResponderState::ErrLength)] {
            let bytes = packet(0x64, payload, [])?;
            assert_eq!(
                check_length(
                    Protocol::Datagram,
                    &Transport::parse(&bytes)?,
                    1024,
                    Some(&receive)
                ),
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn flush_rejects_reserved_placement_and_selectivity() -> Result {
        for kind in 0..16 {
            for level in 0..4 {
                let bytes = packet(0x1c, 0, [Extension::Flush { kind, level }])?;
                let expected = if (1..=3).contains(&kind) && level <= 1 {
                    ResponderState::ChkResource
                } else {
                    ResponderState::ErrUnsupportedOpcode
                };
                assert_eq!(
                    check_operation(
                        Protocol::Reliable,
                        Access::FlushGlobal | Access::FlushPersistent,
                        &Transport::parse(&bytes)?,
                    ),
                    expected
                );
            }
        }
        Ok(())
    }

    #[test]
    fn remote_operations_require_exact_rights_and_zero_length_skips_lookup() -> Result {
        for (opcode, required) in [
            (0x0c, Access::RemoteRead),
            (0x0a, Access::RemoteWrite),
            (0x13, Access::RemoteAtomic),
            (0x1d, Access::RemoteWrite),
        ] {
            let bytes = packet(opcode, 0, [])?;
            let wire = Transport::parse(&bytes)?;
            assert_eq!(
                check_operation(Protocol::Reliable, AccessFlags::empty(), &wire),
                ResponderState::ErrUnsupportedOpcode
            );
            assert_eq!(
                check_operation(Protocol::Reliable, required.into(), &wire),
                ResponderState::ChkResource
            );
        }
        let bytes = packet(0x1c, 0, [Extension::Flush { kind: 3, level: 1 }])?;
        let wire = Transport::parse(&bytes)?;
        assert_eq!(
            check_operation(Protocol::Reliable, Access::FlushGlobal.into(), &wire),
            ResponderState::ErrUnsupportedOpcode
        );
        assert_eq!(
            check_operation(
                Protocol::Reliable,
                Access::FlushGlobal | Access::FlushPersistent,
                &wire
            ),
            ResponderState::ChkResource
        );
        let mut remote = RequestMemory::default();
        for opcode in [0x0a, 0x0c] {
            let bytes = packet(
                opcode,
                0,
                [Extension::Remote {
                    address: u64::MAX,
                    key: u32::MAX,
                    length: 0,
                }],
            )?;
            assert_eq!(
                check_key(
                    &mut remote,
                    &Transport::parse(&bytes)?,
                    1024,
                    |_, _| panic!("zero-length operation looked up an MR"),
                    |_, _| panic!("zero-length operation looked up an MW")
                ),
                ResponderState::Execute
            );
            assert_eq!(remote.key, u32::MAX);
            assert!(remote.region.is_none());
        }
        for (opcode, length, rights, expected) in [
            (
                0x0a,
                1,
                Access::RemoteWrite,
                ResponderState::ErrRkeyViolationEvent,
            ),
            (
                0x0b,
                1,
                Access::RemoteWrite,
                ResponderState::ErrRkeyViolation,
            ),
            (
                0x0c,
                1,
                Access::RemoteRead,
                ResponderState::ErrRkeyViolationEvent,
            ),
        ] {
            let key = RXE_MIN_MW_INDEX << 8;
            let bytes = packet(
                opcode,
                if opcode == 0x0c { 0 } else { length as usize },
                [Extension::Remote {
                    address: 0,
                    key,
                    length,
                }],
            )?;
            let mut called = false;
            assert_eq!(
                check_key(
                    &mut remote,
                    &Transport::parse(&bytes)?,
                    1024,
                    |_, _| panic!("window key looked up as an MR"),
                    |access, requested| {
                        called = true;
                        assert_eq!(access, rights.into());
                        assert_eq!(requested, key);
                        None
                    }
                ),
                expected
            );
            assert!(called);
        }
        Ok(())
    }
    #[test]
    fn whole_region_window_flush_is_rejected_before_lookup() -> Result {
        let mut remote = RequestMemory::default();
        let bytes = packet(
            0x1c,
            0,
            [
                Extension::Remote {
                    address: u64::MAX,
                    key: RXE_MIN_MW_INDEX << 8,
                    length: 0,
                },
                Extension::Flush {
                    kind: 1,
                    level: FLUSH_MR,
                },
            ],
        )?;
        assert_eq!(
            check_key(
                &mut remote,
                &Transport::parse(&bytes)?,
                1024,
                |_, _| panic!("window flush looked up MR"),
                |_, _| panic!("whole-region window flush reached lookup")
            ),
            ResponderState::ErrRkeyViolationEvent
        );
        Ok(())
    }

    #[test]
    fn writes_cannot_finish_before_declared_length_or_continue_after_it() -> Result {
        for (opcode, length, payload) in [
            (0x0a, 2048, 1024),
            (0x0b, 2048, 1024),
            (0x08, 2048, 1024),
            (0x06, 1024, 1024),
            (0x0a, 0, 4),
        ] {
            let mut remote = RequestMemory::default();
            remote.start(0, length, 1);
            let bytes = packet(
                opcode,
                payload,
                [Extension::Remote {
                    address: 0,
                    key: 1,
                    length,
                }],
            );
            // LAST has no RETH; retain the original WRITE's residual instead.
            let bytes = if opcode == 0x08 {
                packet(opcode, payload, [])?
            } else {
                bytes?
            };
            assert_eq!(
                check_key(
                    &mut remote,
                    &Transport::parse(&bytes)?,
                    1024,
                    |_, _| panic!("malformed write reached MR lookup"),
                    |_, _| panic!("malformed write reached MW lookup")
                ),
                ResponderState::ErrLength
            );
        }
        Ok(())
    }
}
