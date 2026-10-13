// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Responder data movement and replies over borrowed native state.

#![forbid(unsafe_code)]

use super::{
    rxe_mr::MrRef,
    rxe_mw_state::Window,
    rxe_param::*,
    rxe_replay::Kind,
    rxe_resp_check::{
        key_violation,
        Protocol, //
    },
    rxe_resp_memory::{
        Authorization,
        RequestMemory, //
    },
    rxe_resp_state::{
        Responder,
        State as ResponderState, //
    },
    rxe_wire::{
        psn_compare,
        Transport, //
    }, //
};
use kernel::{
    bindings::{
        ib_placement_type_IB_FLUSH_GLOBAL as IB_FLUSH_GLOBAL,
        ib_placement_type_IB_FLUSH_PERSISTENT as IB_FLUSH_PERSISTENT,
        ib_selectivity_level_IB_FLUSH_RANGE as IB_FLUSH_RANGE,
        ib_wc_status_IB_WC_SUCCESS as IB_WC_SUCCESS,
        IB_OPCODE_RC_ACKNOWLEDGE,
        IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE,
        IB_OPCODE_RC_COMPARE_SWAP,
        IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST,
        IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST,
        IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE,
        IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY,
        NET_XMIT_CN, //
    },
    prelude::*,
    sync::barrier::{
        mb,
        Write, //
    }, //
};

/// A read segment retains its registration through copying and network handoff.
pub(super) struct ReadPayload<'a> {
    memory: &'a MrRef,
    address: u64,
    length: u32,
}

/// An acknowledgment description, independent of packet allocation and QP storage.
pub(super) struct Reply<'a> {
    pub(super) opcode: u8,
    pub(super) psn: u32,
    pub(super) syndrome: u8,
    pub(super) sequence: u32,
    pub(super) original: Option<u64>,
    payload: Option<ReadPayload<'a>>,
}

impl Reply<'_> {
    pub(super) fn acknowledge(sequence: u32, syndrome: u8, psn: u32) -> Self {
        Self {
            opcode: IB_OPCODE_RC_ACKNOWLEDGE as u8,
            psn,
            syndrome,
            sequence,
            original: None,
            payload: None,
        }
    }

    pub(super) fn payload_len(&self) -> u32 {
        self.payload.as_ref().map_or(0, |payload| payload.length)
    }

    /// Fills only the declared payload, rechecking the retained registration version.
    pub(super) fn copy_payload(&self, output: &mut [u8]) -> Result {
        if output.len() != self.payload_len() as usize {
            return Err(EINVAL);
        }
        if let Some(payload) = &self.payload {
            payload
                .memory
                .access()
                .read(payload.memory.device(), payload.address, output)?;
        }
        Ok(())
    }
}

/// Distinguishes packet preparation failure from a revoked or inaccessible registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SendError {
    Packet,
    Memory,
}

/// Congestion notification can accompany accepted output, as with `net_xmit_eval()`.
pub(super) fn output_result(status: c_int) -> core::result::Result<(), SendError> {
    if status == 0 || status == NET_XMIT_CN as c_int {
        Ok(())
    } else {
        Err(SendError::Packet)
    }
}

fn prepare_resource(resp: &mut Responder, wire: &Transport<'_>, mtu: u32, kind: u32) -> Result {
    use super::rxe_replay::Request;
    let remote = resp.memory.as_ref().unwrap();
    let request = match kind {
        RXE_READ_MASK => Request::Read {
            address: remote.address,
            key: remote.key,
            length: remote.residual,
            authorization: remote.authorization(),
        },
        RXE_ATOMIC_MASK => Request::Atomic,
        RXE_ATOMIC_WRITE_MASK => Request::AtomicWrite,
        RXE_FLUSH_MASK => {
            let flush = wire.flush()?;
            Request::Flush {
                address: remote.address,
                length: remote.length,
                kind: flush.kind,
                level: flush.level,
            }
        }
        _ => return Err(EINVAL),
    };
    let cache = resp.resources.as_mut().ok_or(EINVAL)?;
    cache.start(request, wire.psn(), mtu, remote.offset)?;
    if kind == RXE_READ_MASK {
        // The accepted request consumes the full response PSN range. Retain that
        // reservation across transient transmit failure, so a partial retry uses
        // the replay cache and original memory authorization without new admission.
        let end = cache.read_end()?;
        resp.advance_psn(end);
    }
    Ok(())
}

fn update(resp: &mut Responder, wire: &Transport<'_>) {
    resp.advance_psn(wire.psn().wrapping_add(1));
    resp.ack_psn = resp.psn;
    resp.opcode = i32::from(wire.opcode());
    resp.status = IB_WC_SUCCESS;
}

/// Performs a remote flush, or acknowledges its replay.
pub(super) fn process_flush(
    resp: &mut Responder,
    wire: &Transport<'_>,
    mtu: u32,
) -> ResponderState {
    if resp.resources.as_ref().is_none_or(|cache| !cache.active()) {
        match prepare_resource(resp, wire, mtu, RXE_FLUSH_MASK) {
            Ok(()) => (),
            // FLUSH does not consume a read credit. Leave its PSN unaccepted while
            // unfinished READs occupy every slot, so their retries can make room.
            Err(EAGAIN) => return ResponderState::Cleanup,
            Err(_) => return ResponderState::ErrTooManyRdmaAtmReq,
        }
    }
    let cache = resp.resources.as_ref().unwrap();
    let Ok(replay) = cache.replaying(Kind::Flush) else {
        return ResponderState::ErrRkeyViolation;
    };
    if replay {
        return ResponderState::Acknowledge;
    }
    let Ok(flush) = cache.flush() else {
        return ResponderState::ErrRkeyViolation;
    };
    let Ok(memory) = resp.memory.as_ref().unwrap().registration() else {
        return key_violation(wire.mask());
    };
    let (start, length) = if u32::from(flush.level) == IB_FLUSH_RANGE {
        (flush.address, u64::from(flush.length))
    } else {
        if resp
            .memory
            .as_ref()
            .unwrap()
            .authorization()
            .is_some_and(|auth| auth.is_window())
        {
            return key_violation(wire.mask());
        }
        let attributes = memory.attributes();
        (attributes.address, attributes.length)
    };
    if u32::from(flush.kind) & IB_FLUSH_PERSISTENT != 0 {
        let result = usize::try_from(length)
            .map_err(|_| EINVAL)
            .and_then(|length| memory.access().flush(start, length));
        if result.is_err() {
            return key_violation(wire.mask());
        }
        // Complete cache writeback before acknowledging persistence.
        mb(Write);
    } else if u32::from(flush.kind) & IB_FLUSH_GLOBAL != 0 {
        // Publish prior stores before acknowledging global visibility.
        mb(Write);
    }
    resp.msn = resp.msn.wrapping_add(1);
    update(resp, wire);
    ResponderState::Acknowledge
}

/// Executes an atomic request once and records the original value for replay.
pub(super) fn atomic_reply(resp: &mut Responder, wire: &Transport<'_>, mtu: u32) -> ResponderState {
    if resp.resources.as_ref().is_none_or(|cache| !cache.active())
        && prepare_resource(resp, wire, mtu, RXE_ATOMIC_MASK).is_err()
    {
        return ResponderState::ErrTooManyRdmaAtmReq;
    }
    let Ok(replay) = resp.resources.as_ref().unwrap().replaying(Kind::Atomic) else {
        return ResponderState::ErrRkeyViolation;
    };
    if !replay {
        let remote = resp.memory.as_ref().unwrap();
        let Ok(address) = remote.translated_address() else {
            return ResponderState::ErrRkeyViolation;
        };
        let Ok(atomic) = wire.atomic() else {
            return ResponderState::ErrLength;
        };
        if address & 7 != 0 {
            return ResponderState::ErrMisalignedAtomic;
        }
        let Ok(memory) = remote.registration() else {
            return ResponderState::ErrRkeyViolation;
        };
        let device = memory.device();
        let result = if u32::from(wire.opcode()) == IB_OPCODE_RC_COMPARE_SWAP {
            memory
                .access()
                .compare_exchange(device, address, atomic.compare, atomic.swap)
        } else {
            memory.access().fetch_add(device, address, atomic.swap)
        };
        if result
            .and_then(|value| resp.resources.as_mut().unwrap().record_atomic(value))
            .is_err()
        {
            return ResponderState::ErrRkeyViolation;
        }
        resp.msn = resp.msn.wrapping_add(1);
        update(resp, wire);
    }
    ResponderState::Acknowledge
}

/// Executes an eight-byte atomic write, or acknowledges its replay.
pub(super) fn atomic_write_reply(
    resp: &mut Responder,
    wire: &Transport<'_>,
    mtu: u32,
) -> ResponderState {
    if resp.resources.as_ref().is_none_or(|cache| !cache.active())
        && prepare_resource(resp, wire, mtu, RXE_ATOMIC_WRITE_MASK).is_err()
    {
        return ResponderState::ErrTooManyRdmaAtmReq;
    }
    let Ok(replay) = resp
        .resources
        .as_ref()
        .unwrap()
        .replaying(Kind::AtomicWrite)
    else {
        return ResponderState::ErrRkeyViolation;
    };
    if replay {
        return ResponderState::Acknowledge;
    }
    let remote = resp.memory.as_ref().unwrap();
    let Ok(memory) = remote.registration() else {
        return ResponderState::ErrRkeyViolation;
    };
    let Ok(value) = wire.payload().and_then(|payload| {
        payload
            .try_into()
            .map(u64::from_ne_bytes)
            .map_err(|_| EINVAL)
    }) else {
        return ResponderState::ErrLength;
    };
    let Ok(address) = remote.translated_address() else {
        return ResponderState::ErrRkeyViolation;
    };
    if address & 7 != 0 {
        return ResponderState::ErrMisalignedAtomic;
    }
    if memory
        .access()
        .store_release(memory.device(), address, value)
        .is_err()
    {
        return ResponderState::ErrRkeyViolation;
    }
    resp.memory.as_mut().unwrap().residual = 0;
    resp.msn = resp.msn.wrapping_add(1);
    update(resp, wire);
    ResponderState::Acknowledge
}

/// Reacquires a read registration without retaining a window or QP borrow.
fn recheck_mr(
    key: u32,
    address: u64,
    length: u32,
    lookup: impl FnOnce(u32) -> Option<MrRef>,
    lookup_window: impl FnOnce(u32) -> Option<Window>,
) -> Option<(MrRef, Authorization)> {
    let (memory, window) = if (RXE_MIN_MW_INDEX..=RXE_MAX_MW_INDEX).contains(&(key >> 8)) {
        let window = lookup_window(key)?;
        window.check_range(address, u64::from(length)).ok()?;
        (window.memory, Some(window.version))
    } else {
        (lookup(key)?, None)
    };
    let authorization = Authorization::new(memory.version(), window);
    Some((memory, authorization))
}

/// Sends one read segment while retaining its registration and original admission versions.
///
/// Progress advances only after successful handoff. The lookup and transmit callbacks borrow
/// neither responder state nor its replay cache.
pub(super) fn read_reply(
    resp: &mut Responder,
    wire: &Transport<'_>,
    mtu: u32,
    lookup: impl FnOnce(u32) -> Option<MrRef>,
    lookup_window: impl FnOnce(u32) -> Option<Window>,
    transmit: impl FnOnce(Reply<'_>) -> core::result::Result<(), SendError>,
) -> ResponderState {
    if resp.resources.as_ref().is_none_or(|cache| !cache.active())
        && prepare_resource(resp, wire, mtu, RXE_READ_MASK).is_err()
    {
        return ResponderState::ErrTooManyRdmaAtmReq;
    }
    let Ok(read) = resp.resources.as_ref().unwrap().read() else {
        return ResponderState::ErrRkeyViolation;
    };
    let first = read.first;
    let registration = if read.residual == 0 {
        None
    } else if first && !read.replay {
        let remote = resp.memory.as_mut().unwrap();
        remote.region.take().zip(remote.authorization())
    } else {
        recheck_mr(read.key, read.address, read.residual, lookup, lookup_window)
    };
    if read.residual != 0
        && registration
            .as_ref()
            .is_none_or(|(_, authorization)| Some(*authorization) != read.authorization)
    {
        return ResponderState::ErrRkeyViolation;
    }
    let more = read.residual > mtu;
    let opcode = match (first, more) {
        (true, true) => IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST,
        (true, false) => IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY,
        (false, true) => IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE,
        (false, false) => IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST,
    };
    let payload = read.residual.min(mtu);
    let reply = Reply {
        opcode: opcode as u8,
        psn: read.psn,
        syndrome: AETH_ACK_UNLIMITED as u8,
        sequence: resp.msn,
        original: None,
        payload: registration.as_ref().map(|(memory, _)| ReadPayload {
            memory,
            address: read.address,
            length: payload,
        }),
    };
    match transmit(reply) {
        Ok(()) => (),
        Err(SendError::Packet) => return ResponderState::ErrRnr,
        Err(SendError::Memory) => return ResponderState::ErrRkeyViolation,
    }
    let Ok(read) = resp.resources.as_mut().unwrap().advance_read(payload) else {
        return ResponderState::ErrRkeyViolation;
    };
    if read.residual > 0 {
        return ResponderState::Done;
    }
    resp.resources.as_mut().unwrap().finish();
    if !read.replay {
        resp.opcode = -1;
    }
    if psn_compare(read.psn, resp.psn) >= 0 {
        resp.advance_psn(read.psn);
    }
    ResponderState::Cleanup
}

fn receive_data(
    remote: &mut RequestMemory,
    data: &[u8],
    lookup: impl FnMut(u32) -> Option<MrRef>,
) -> ResponderState {
    match remote.write_receive(data, lookup) {
        Ok(()) => ResponderState::None,
        Err(ENOSPC) => ResponderState::ErrLength,
        Err(_) => ResponderState::ErrMalformedWqe,
    }
}

/// Moves send/write data or selects a reply, borrowing packet bytes only for this call.
///
/// Datagram callers supply a copied GRH, with IPv4 headers right-aligned in the 40-byte array.
/// Lookup and invalidation callbacks do not access responder state.
pub(super) fn execute(
    resp: &mut Responder,
    wire: &Transport<'_>,
    protocol: Protocol,
    grh: Option<&[u8; 40]>,
    mut lookup: impl FnMut(u32) -> Option<MrRef>,
    invalidate: impl FnOnce(u32) -> Result,
) -> ResponderState {
    let mask = wire.mask();
    if mask & RXE_SEND_MASK != 0 {
        if protocol == Protocol::Datagram {
            let Some(header) = grh else {
                return ResponderState::ErrLength;
            };
            let state = receive_data(resp.memory.as_mut().unwrap(), header, &mut lookup);
            if state != ResponderState::None {
                return state;
            }
        }
        let Ok(payload) = wire.payload() else {
            return ResponderState::ErrLength;
        };
        let state = receive_data(resp.memory.as_mut().unwrap(), payload, lookup);
        if state != ResponderState::None {
            return state;
        }
    } else if mask & RXE_WRITE_MASK != 0 {
        let Ok(payload) = wire.payload() else {
            return ResponderState::ErrLength;
        };
        if resp.memory.as_mut().unwrap().write(payload).is_err() {
            return key_violation(wire.mask());
        }
    } else if mask & RXE_READ_MASK != 0 {
        resp.msn = resp.msn.wrapping_add(1);
        return ResponderState::ReadReply;
    } else if mask & RXE_ATOMIC_MASK != 0 {
        return ResponderState::AtomicReply;
    } else if mask & RXE_ATOMIC_WRITE_MASK != 0 {
        return ResponderState::AtomicWriteReply;
    } else if mask & RXE_FLUSH_MASK != 0 {
        return ResponderState::ProcessFlush;
    }
    if mask & RXE_IETH_MASK != 0 {
        let Ok(key) = wire.invalidate() else {
            return ResponderState::ErrInvalidateRkey;
        };
        if invalidate(key).is_err() {
            return ResponderState::ErrInvalidateRkey;
        }
    }
    if mask & RXE_END_MASK != 0 {
        resp.msn = resp.msn.wrapping_add(1);
    }
    update(resp, wire);
    if mask & RXE_COMP_MASK != 0 {
        ResponderState::Complete
    } else if protocol == Protocol::Reliable {
        ResponderState::Acknowledge
    } else {
        ResponderState::Cleanup
    }
}

/// Sends an acknowledgment and retires the active replay entry after a completed operation.
pub(super) fn acknowledge(
    resp: &mut Responder,
    wire: &Transport<'_>,
    protocol: Protocol,
    transmit: impl FnOnce(Reply<'_>) -> core::result::Result<(), SendError>,
) -> ResponderState {
    if protocol != Protocol::Reliable {
        return ResponderState::Cleanup;
    }
    let syndrome = resp.aeth_syndrome;
    let mut reply = Reply::acknowledge(resp.msn, syndrome, wire.psn());
    if u32::from(syndrome) != AETH_ACK_UNLIMITED {
        let _ = transmit(reply);
    } else if wire.mask() & (RXE_ATOMIC_MASK | RXE_FLUSH_MASK | RXE_ATOMIC_WRITE_MASK) != 0 {
        reply.opcode = if wire.mask() & RXE_ATOMIC_MASK != 0 {
            let Ok(original) = resp
                .resources
                .as_ref()
                .ok_or(EINVAL)
                .and_then(|cache| cache.atomic_original())
            else {
                resp.resources.as_mut().unwrap().finish();
                return ResponderState::Cleanup;
            };
            reply.original = Some(original);
            IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE as u8
        } else {
            IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY as u8
        };
        let _ = transmit(reply);
        resp.resources.as_mut().unwrap().finish();
    } else if wire.ack_requested() {
        let _ = transmit(reply);
    }
    ResponderState::Cleanup
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_resp_data)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_receive_is_a_length_error() -> Result {
        let storage =
            crate::rxe_ring::Storage::new(1, crate::rxe_wqe::RECV_HEADER_SIZE as u32, 64)?;
        let mut remote = RequestMemory::default();
        remote.receive = Some(crate::rxe_wqe::ReceiveWqe::read(&storage, 0, 0)?);
        assert_eq!(
            receive_data(&mut remote, &[1], |_| None),
            ResponderState::ErrLength
        );
        assert_eq!(remote.receive.as_ref().unwrap().received(), 0);
        Ok(())
    }

    use crate::{
        rxe_replay::{
            Cache,
            Duplicate,
            Request, //
        },
        rxe_ring::Storage,
        rxe_wire::bth,
        rxe_wqe::{
            ReceiveWqe,
            RECV_HEADER_SIZE, //
        }, //
    };

    fn responder() -> Result<Responder> {
        let mut resp = Responder::new()?;
        resp.resources = Some(Cache::new(4)?);
        resp.aeth_syndrome = AETH_ACK_UNLIMITED as u8;
        Ok(resp)
    }

    #[test]
    fn ordinary_sequence_progress_expires_reads_before_psn_reuse() -> Result {
        let mut resp = responder()?;
        resp.resources = Some(Cache::new(2)?);
        let cache = resp.resources.as_mut().unwrap();
        cache.start(
            Request::Read {
                address: 0x1000,
                key: 7,
                length: 512,
                authorization: None,
            },
            5,
            256,
            0,
        )?;
        cache.advance_read(256)?;
        cache.finish();
        resp.advance_psn(7);
        // Sample forward SEND progress in increments below half a sequence space. None of
        // these advances allocates a replay slot, and the last crosses numeric PSN wrap.
        for psn in [0x400006, 0x800006, 0xc00006, 4] {
            let packet = bth(0x04, psn, false, 0, 1, false);
            update(&mut resp, &Transport::parse(&packet)?);
        }
        assert_eq!(resp.psn, 5);
        let cache = resp.resources.as_mut().unwrap();
        cache.start(Request::Atomic, 5, 256, 0)?;
        cache.record_atomic(17)?;
        cache.finish();
        assert_eq!(cache.replay(Duplicate::Atomic, 5), Some(Kind::Atomic));
        assert_eq!(cache.atomic_original()?, 17);
        Ok(())
    }

    #[test]
    fn atomic_and_flush_replays_need_no_live_registration() -> Result {
        let mut resp = responder()?;
        resp.msn = 17;
        resp.psn = 20;
        resp.opcode = -1;
        let cases = [
            (0x13, Request::Atomic, Duplicate::Atomic, Kind::Atomic),
            (
                0x1d,
                Request::AtomicWrite,
                Duplicate::AtomicWrite,
                Kind::AtomicWrite,
            ),
            (
                0x1c,
                Request::Flush {
                    address: 0x1000,
                    length: 32,
                    kind: 3,
                    level: 1,
                },
                Duplicate::Flush,
                Kind::Flush,
            ),
        ];
        for (index, (opcode, request, duplicate, kind)) in cases.into_iter().enumerate() {
            let psn = 7 + index as u32;
            let cache = resp.resources.as_mut().unwrap();
            cache.start(request, psn, 1024, 0)?;
            if kind == Kind::Atomic {
                cache.record_atomic(0x123456789abcdef0)?;
            }
            cache.finish();
            assert_eq!(cache.replay(duplicate, psn), Some(kind));
            let mut bytes = [0; 40];
            bytes[..12].copy_from_slice(&bth(opcode, psn, false, 0, 1, false));
            let length = match kind {
                Kind::Atomic => 40,      // BTH and AtomicETH.
                Kind::AtomicWrite => 36, // BTH, RETH and eight data bytes.
                Kind::Flush => 32,       // BTH, RETH and FETH, without payload.
                Kind::Read => unreachable!(),
            };
            let wire = Transport::parse(&bytes[..length])?;
            let state = match kind {
                Kind::Atomic => atomic_reply(&mut resp, &wire, 1024),
                Kind::AtomicWrite => atomic_write_reply(&mut resp, &wire, 1024),
                _ => process_flush(&mut resp, &wire, 1024),
            };
            assert_eq!(state, ResponderState::Acknowledge);
            assert_eq!(resp.msn, 17);
            assert_eq!(resp.psn, 20);
            assert_eq!(resp.opcode, -1);
            let mut sent = false;
            assert_eq!(
                acknowledge(&mut resp, &wire, Protocol::Reliable, |reply| {
                    sent = true;
                    assert_eq!(reply.psn, psn);
                    assert_eq!(reply.sequence, 17);
                    assert_eq!(reply.payload_len(), 0);
                    assert_eq!(reply.copy_payload(&mut []), Ok(()));
                    assert_eq!(reply.copy_payload(&mut [0]), Err(EINVAL));
                    if kind == Kind::Atomic {
                        assert_eq!(reply.opcode, 0x12);
                        assert_eq!(reply.original, Some(0x123456789abcdef0));
                    } else {
                        assert_eq!(reply.opcode, 0x10);
                        assert_eq!(reply.original, None);
                    }
                    Ok(())
                }),
                ResponderState::Cleanup
            );
            assert!(sent);
            assert!(!resp.resources.as_ref().unwrap().active());
        }
        Ok(())
    }

    #[test]
    fn zero_length_read_reserves_psn_and_replays_after_failed_handoff() -> Result {
        let mut resp = responder()?;
        resp.psn = 0xffffff;
        resp.memory.as_mut().unwrap().start(u64::MAX, 0, 0);
        let mut bytes = [0; 28];
        bytes[..12].copy_from_slice(&bth(0x0c, 0xffffff, false, 0, 1, false));
        bytes[12..20].copy_from_slice(&u64::MAX.to_be_bytes());
        let wire = Transport::parse(&bytes)?;
        assert_eq!(
            read_reply(
                &mut resp,
                &wire,
                1024,
                |_| panic!("zero read looked up an MR"),
                |_| panic!("zero read looked up an MW"),
                |_| Err(SendError::Packet)
            ),
            ResponderState::ErrRnr
        );
        let before = resp.resources.as_ref().unwrap().read()?;
        assert_eq!(before.psn, 0xffffff);
        assert!(before.first);
        assert_eq!(resp.psn, 0);
        // Exercise the same cleanup and duplicate-selection path as ErrRnr.
        resp.finish_request();
        assert_eq!(
            resp.replay(&wire),
            super::super::rxe_resp_state::Replay::Continue(ResponderState::ReadReply)
        );
        assert_eq!(
            read_reply(
                &mut resp,
                &wire,
                1024,
                |_| panic!("zero read looked up an MR"),
                |_| panic!("zero read looked up an MW"),
                |reply| {
                    assert_eq!(reply.opcode, 0x10);
                    assert_eq!(reply.psn, 0xffffff);
                    assert_eq!(reply.payload_len(), 0);
                    Ok(())
                }
            ),
            ResponderState::Cleanup
        );
        assert_eq!(resp.psn, 0);
        assert_eq!(resp.opcode, -1);
        let cache = resp.resources.as_mut().unwrap();
        assert!(!cache.active());
        assert_eq!(
            cache.replay(
                Duplicate::Read {
                    address: u64::MAX,
                    key: 0,
                    length: 0
                },
                0xffffff
            ),
            Some(Kind::Read)
        );
        assert_eq!(
            read_reply(
                &mut resp,
                &wire,
                1024,
                |_| panic!("zero replay looked up an MR"),
                |_| panic!("zero replay looked up an MW"),
                |_| Ok(())
            ),
            ResponderState::Cleanup
        );
        assert_eq!(resp.psn, 0);
        Ok(())
    }

    #[test]
    fn unfinished_read_defers_flush_until_retry_releases_its_slot() -> Result {
        let mut resp = responder()?;
        resp.resources = Some(Cache::new(1)?);
        resp.memory.as_mut().unwrap().start(0x1000, 0, 7);
        let mut read = [0; 28];
        read[..12].copy_from_slice(&bth(0x0c, 0, false, 0, 1, false));
        read[12..20].copy_from_slice(&0x1000u64.to_be_bytes());
        read[20..24].copy_from_slice(&7u32.to_be_bytes());
        let read = Transport::parse(&read)?;
        assert_eq!(
            read_reply(
                &mut resp,
                &read,
                256,
                |_| panic!("empty READ looked up an MR"),
                |_| panic!("empty READ looked up an MW"),
                |_| Err(SendError::Packet)
            ),
            ResponderState::ErrRnr
        );
        resp.finish_request();
        assert_eq!(resp.psn, 1);
        let mut flush = [0; 32];
        flush[..12].copy_from_slice(&bth(0x1c, 1, false, 0, 1, false));
        flush[12..16].copy_from_slice(&IB_FLUSH_GLOBAL.to_be_bytes());
        flush[16..24].copy_from_slice(&0x2000u64.to_be_bytes());
        flush[24..28].copy_from_slice(&9u32.to_be_bytes());
        let flush = Transport::parse(&flush)?;
        assert_eq!(u32::from(flush.flush()?.kind), IB_FLUSH_GLOBAL);
        assert_eq!(u32::from(flush.flush()?.level), IB_FLUSH_RANGE);
        let remote = flush.remote()?;
        assert_eq!(remote.address, 0x2000);
        assert_eq!(remote.key, 9);
        assert_eq!(remote.length, 0);
        assert_eq!(
            super::super::rxe_resp_check::check_operation(
                Protocol::Reliable,
                kernel::rdma::Access::FlushGlobal.into(),
                &flush
            ),
            ResponderState::ChkResource
        );
        assert_eq!(
            super::super::rxe_resp_check::check_length(Protocol::Reliable, &flush, 256, None),
            ResponderState::ChkRkey
        );
        for _ in 0..2 {
            resp.memory
                .as_mut()
                .unwrap()
                .start(remote.address, remote.length, remote.key);
            assert_eq!(
                process_flush(&mut resp, &flush, 256),
                ResponderState::Cleanup
            );
            assert_eq!(resp.psn, 1);
            assert_eq!(resp.msn, 0);
            assert!(!resp.goto_error);
            assert!(!resp.resources.as_ref().unwrap().active());
            resp.finish_request();
        }
        assert_eq!(
            resp.replay(&read),
            super::super::rxe_resp_state::Replay::Continue(ResponderState::ReadReply)
        );
        assert_eq!(
            read_reply(
                &mut resp,
                &read,
                256,
                |_| panic!("empty READ looked up an MR"),
                |_| panic!("empty READ looked up an MW"),
                |_| Ok(())
            ),
            ResponderState::Cleanup
        );
        resp.finish_request();
        resp.memory
            .as_mut()
            .unwrap()
            .start(remote.address, remote.length, remote.key);
        prepare_resource(&mut resp, &flush, 256, RXE_FLUSH_MASK)?;
        assert_eq!(resp.resources.as_ref().unwrap().flush()?.address, 0x2000);
        resp.finish_request();

        // No configured replay storage remains a permanent resource error.
        resp.resources = Some(Cache::new(0)?);
        assert_eq!(
            process_flush(&mut resp, &flush, 256),
            ResponderState::ErrTooManyRdmaAtmReq
        );
        Ok(())
    }

    #[test]
    fn congested_read_handoff_releases_its_reservation() -> Result {
        for (status, accepted) in [
            (0, true),
            (NET_XMIT_CN as c_int, true),
            (kernel::bindings::NET_XMIT_DROP as c_int, false),
            (ENOBUFS.to_errno(), false),
        ] {
            let mut resp = responder()?;
            resp.resources = Some(Cache::new(1)?);
            resp.memory.as_mut().unwrap().start(0x1000, 0, 7);
            let mut read = [0; 28];
            read[..12].copy_from_slice(&bth(0x0c, 0, false, 0, 1, false));
            read[12..20].copy_from_slice(&0x1000u64.to_be_bytes());
            read[20..24].copy_from_slice(&7u32.to_be_bytes());
            let read = Transport::parse(&read)?;
            assert_eq!(
                read_reply(
                    &mut resp,
                    &read,
                    256,
                    |_| panic!("empty READ looked up an MR"),
                    |_| panic!("empty READ looked up an MW"),
                    |_| output_result(status)
                ),
                if accepted {
                    ResponderState::Cleanup
                } else {
                    ResponderState::ErrRnr
                }
            );
            resp.finish_request();
            assert_eq!(
                resp.resources
                    .as_mut()
                    .unwrap()
                    .start(Request::Atomic, 1, 256, 0),
                if accepted { Ok(()) } else { Err(EAGAIN) }
            );
        }
        Ok(())
    }

    #[test]
    fn invalidation_failure_does_not_complete_send_progress() -> Result {
        let mut resp = responder()?;
        let storage = Storage::new(1, RECV_HEADER_SIZE as u32, 64)?;
        storage
            .memory()
            .fill(storage.offset(0), RECV_HEADER_SIZE, 0)?;
        resp.memory.as_mut().unwrap().receive = Some(ReceiveWqe::read(&storage, 0, 0)?);
        let mut bytes = [0; 16];
        bytes[..12].copy_from_slice(&bth(0x17, 0xffffff, false, 0, 1, false));
        bytes[12..].copy_from_slice(&0x12345678u32.to_be_bytes());
        let wire = Transport::parse(&bytes)?;
        resp.psn = 0xffffff;
        resp.opcode = -1;
        for fail in [true, false] {
            let mut called = false;
            let state = execute(
                &mut resp,
                &wire,
                Protocol::Reliable,
                None,
                |_| panic!("empty receive looked up an MR"),
                |key| {
                    called = true;
                    assert_eq!(key, 0x12345678);
                    if fail {
                        Err(EINVAL)
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(called);
            if fail {
                assert_eq!(state, ResponderState::ErrInvalidateRkey);
                assert_eq!(resp.psn, 0xffffff);
                assert_eq!(resp.msn, 0);
                assert_eq!(resp.opcode, -1);
            } else {
                assert_eq!(state, ResponderState::Complete);
                assert_eq!(resp.psn, 0);
                assert_eq!(resp.msn, 1);
                assert_eq!(resp.opcode, 0x17);
            }
        }
        Ok(())
    }
    #[test]
    fn partial_read_retry_uses_reserved_psns_after_packet_failure() -> Result {
        let mut resp = responder()?;
        resp.psn = 0xfffffe;
        resp.msn = 17;
        resp.memory.as_mut().unwrap().start(0x1000, 512, 9);
        let mut bytes = [0; 28];
        bytes[..12].copy_from_slice(&bth(0x0c, 0xfffffe, false, 0, 1, false));
        bytes[12..20].copy_from_slice(&0x1000u64.to_be_bytes());
        bytes[20..24].copy_from_slice(&9u32.to_be_bytes());
        bytes[24..28].copy_from_slice(&512u32.to_be_bytes());
        prepare_resource(&mut resp, &Transport::parse(&bytes)?, 256, RXE_READ_MASK)?;
        assert_eq!(resp.psn, 0);
        resp.resources.as_mut().unwrap().advance_read(256)?;
        // The second packet fails: ErrRnr releases the packet and its MR.
        resp.finish_request();
        bytes[..12].copy_from_slice(&bth(0x0c, 0xffffff, false, 0, 1, false));
        bytes[12..20].copy_from_slice(&0x1100u64.to_be_bytes());
        bytes[24..28].copy_from_slice(&256u32.to_be_bytes());
        assert_eq!(
            super::super::rxe_resp_check::check_psn(
                Protocol::Reliable,
                0xffffff,
                resp.psn,
                RXE_READ_MASK,
                &mut resp.sent_psn_nak,
                &mut resp.drop_msg,
            ),
            ResponderState::DuplicateRequest
        );
        assert_eq!(
            resp.replay(&Transport::parse(&bytes)?),
            super::super::rxe_resp_state::Replay::Continue(ResponderState::ReadReply)
        );
        let read = resp.resources.as_ref().unwrap().read()?;
        assert_eq!(read.address, 0x1100);
        assert_eq!(read.residual, 256);
        assert!(read.replay);
        assert_eq!(resp.msn, 17);
        Ok(())
    }
}
