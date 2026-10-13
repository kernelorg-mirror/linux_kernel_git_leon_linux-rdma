// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Native completion records and userspace ABI encoding.

#![forbid(unsafe_code)]

use super::{
    rxe_send::SendWqe,
    rxe_wire::Transport,
    rxe_wqe::ReceiveWqe, //
};
use crate::rxe_param::{
    RXE_DETH_MASK,
    RXE_IETH_MASK,
    RXE_IMMDT_MASK,
    RXE_WRITE_MASK, //
};
use kernel::bindings;
use kernel::bindings::{
    ib_send_flags_IB_SEND_SIGNALED as IB_SEND_SIGNALED,
    ib_wc_flags_IB_WC_GRH as IB_WC_GRH,
    ib_wc_flags_IB_WC_WITH_IMM as IB_WC_WITH_IMM,
    ib_wc_flags_IB_WC_WITH_INVALIDATE as IB_WC_WITH_INVALIDATE,
    ib_wc_flags_IB_WC_WITH_NETWORK_HDR_TYPE as IB_WC_WITH_NETWORK_HDR_TYPE,
    ib_wc_flags_IB_WC_WITH_VLAN as IB_WC_WITH_VLAN,
    ib_wc_opcode_IB_WC_ATOMIC_WRITE as IB_WC_ATOMIC_WRITE,
    ib_wc_opcode_IB_WC_BIND_MW as IB_WC_BIND_MW,
    ib_wc_opcode_IB_WC_COMP_SWAP as IB_WC_COMP_SWAP,
    ib_wc_opcode_IB_WC_FETCH_ADD as IB_WC_FETCH_ADD,
    ib_wc_opcode_IB_WC_FLUSH as IB_WC_FLUSH,
    ib_wc_opcode_IB_WC_LOCAL_INV as IB_WC_LOCAL_INV,
    ib_wc_opcode_IB_WC_LSO as IB_WC_LSO,
    ib_wc_opcode_IB_WC_RDMA_READ as IB_WC_RDMA_READ,
    ib_wc_opcode_IB_WC_RDMA_WRITE as IB_WC_RDMA_WRITE,
    ib_wc_opcode_IB_WC_RECV as IB_WC_RECV,
    ib_wc_opcode_IB_WC_RECV_RDMA_WITH_IMM as IB_WC_RECV_RDMA_WITH_IMM,
    ib_wc_opcode_IB_WC_REG_MR as IB_WC_REG_MR,
    ib_wc_opcode_IB_WC_SEND as IB_WC_SEND,
    ib_wc_status_IB_WC_SUCCESS as IB_WC_SUCCESS,
    ib_wr_opcode_IB_WR_ATOMIC_CMP_AND_SWP as IB_WR_ATOMIC_CMP_AND_SWP,
    ib_wr_opcode_IB_WR_ATOMIC_FETCH_AND_ADD as IB_WR_ATOMIC_FETCH_AND_ADD,
    ib_wr_opcode_IB_WR_ATOMIC_WRITE as IB_WR_ATOMIC_WRITE,
    ib_wr_opcode_IB_WR_BIND_MW as IB_WR_BIND_MW,
    ib_wr_opcode_IB_WR_FLUSH as IB_WR_FLUSH,
    ib_wr_opcode_IB_WR_LOCAL_INV as IB_WR_LOCAL_INV,
    ib_wr_opcode_IB_WR_LSO as IB_WR_LSO,
    ib_wr_opcode_IB_WR_RDMA_READ as IB_WR_RDMA_READ,
    ib_wr_opcode_IB_WR_RDMA_READ_WITH_INV as IB_WR_RDMA_READ_WITH_INV,
    ib_wr_opcode_IB_WR_RDMA_WRITE as IB_WR_RDMA_WRITE,
    ib_wr_opcode_IB_WR_RDMA_WRITE_WITH_IMM as IB_WR_RDMA_WRITE_WITH_IMM,
    ib_wr_opcode_IB_WR_REG_MR as IB_WR_REG_MR,
    ib_wr_opcode_IB_WR_SEND as IB_WR_SEND,
    ib_wr_opcode_IB_WR_SEND_WITH_IMM as IB_WR_SEND_WITH_IMM,
    ib_wr_opcode_IB_WR_SEND_WITH_INV as IB_WR_SEND_WITH_INV, //
};
use kernel::{
    prelude::*,
    rdma::CompletionId, //
};

/// Userspace completion size, including its reserved byte.
pub(super) const USER_BYTES: usize = 48;

/// Packet metadata present only in successful kernel receive completions.
#[derive(Clone, Copy)]
pub(super) struct Network {
    pub(super) kind: u8,
    pub(super) vlan: Option<u16>,
}

/// Owned completion data and private request provenance, independent of reusable slots.
#[derive(Default)]
pub(super) struct Record {
    pub(super) id: CompletionId,
    pub(super) status: u32,
    pub(super) opcode: u32,
    pub(super) length: u32,
    pub(super) flags: u32,
    pub(super) immediate: [u8; 4],
    pub(super) source: u32,
    pub(super) port: u32,
    pub(super) network: Option<Network>,
}

/// A completed send with no remaining borrow of its reusable request slot.
pub(super) struct SendCompletion {
    pub(super) opcode: u32,
    pub(super) status: u32,
    pub(super) record: Option<Record>,
}

impl SendCompletion {
    pub(super) fn new(wqe: SendWqe<'_>, signal_all: bool) -> Self {
        let status = wqe.status;
        let post = signal_all
            || wqe.wr.send_flags & IB_SEND_SIGNALED as u32 != 0
            || status != IB_WC_SUCCESS;
        Self {
            opcode: wqe.wr.opcode,
            status,
            record: post.then(|| Record::send(&wqe, status)),
        }
    }
}

impl Record {
    pub(super) fn error(id: CompletionId, status: u32) -> Self {
        Self {
            id,
            status,
            ..Self::default()
        }
    }

    pub(super) fn send(wqe: &SendWqe<'_>, status: u32) -> Self {
        let mut entry = Self::error(wqe.wr.wr_id.clone(), status);
        if status == IB_WC_SUCCESS {
            entry.opcode = completion_opcode(wqe.wr.opcode);
            entry.length = wqe.dma.length;
            if matches!(
                wqe.wr.opcode,
                IB_WR_RDMA_WRITE_WITH_IMM | IB_WR_SEND_WITH_IMM
            ) {
                entry.flags = IB_WC_WITH_IMM;
            }
        }
        entry
    }

    pub(super) fn receive(
        wqe: &ReceiveWqe,
        written: u32,
        port: u32,
        wire: &Transport<'_>,
    ) -> Result<Self> {
        let mask = wire.mask();
        let write = mask & (RXE_IMMDT_MASK | RXE_WRITE_MASK) == RXE_IMMDT_MASK | RXE_WRITE_MASK;
        let mut entry = Self {
            id: wqe.id(),
            status: IB_WC_SUCCESS,
            opcode: if write {
                IB_WC_RECV_RDMA_WITH_IMM
            } else {
                IB_WC_RECV
            },
            length: if write { written } else { wqe.received() },
            flags: IB_WC_GRH,
            port,
            ..Self::default()
        };
        if mask & RXE_IMMDT_MASK != 0 {
            entry.flags |= IB_WC_WITH_IMM;
            entry.immediate = wire.immediate()?;
        }
        if mask & RXE_IETH_MASK != 0 {
            entry.flags |= IB_WC_WITH_INVALIDATE;
            entry.immediate = wire.invalidate()?.to_ne_bytes();
        }
        if mask & RXE_DETH_MASK != 0 {
            entry.source = wire.datagram()?.source;
        }
        Ok(entry)
    }

    /// Builds kernel scalar metadata without exposing or dereferencing a QP pointer.
    pub(super) fn kernel_data(&self) -> kernel::rdma::CompletionData {
        let mut data = kernel::rdma::CompletionData {
            id: self.id.clone(),
            status: self.status,
            opcode: self.opcode,
            length: self.length,
            immediate: self.immediate,
            source: self.source,
            flags: self.flags,
            port: self.port,
            ..Default::default()
        };
        if let Some(network) = self.network {
            data.flags |= IB_WC_WITH_NETWORK_HDR_TYPE;
            data.network = network.kind;
            if let Some(vlan) = network.vlan {
                data.flags |= IB_WC_WITH_VLAN;
                data.vlan = vlan;
            }
        }
        data
    }

    /// Encodes the userspace ABI without copying Rust or C padding.
    pub(super) fn user_bytes(&self, qpn: u32) -> [u8; USER_BYTES] {
        let mut bytes = [0; USER_BYTES];
        bytes[..8].copy_from_slice(&self.id.value().to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.status.to_ne_bytes());
        bytes[12..16].copy_from_slice(&self.opcode.to_ne_bytes());
        bytes[20..24].copy_from_slice(&self.length.to_ne_bytes());
        bytes[24..28].copy_from_slice(&self.immediate);
        bytes[28..32].copy_from_slice(&qpn.to_ne_bytes());
        bytes[32..36].copy_from_slice(&self.source.to_ne_bytes());
        bytes[36..40].copy_from_slice(&self.flags.to_ne_bytes());
        bytes[46] = self.port as u8;
        bytes
    }
}

fn completion_opcode(opcode: u32) -> u32 {
    match opcode {
        IB_WR_RDMA_WRITE | IB_WR_RDMA_WRITE_WITH_IMM => IB_WC_RDMA_WRITE,
        IB_WR_SEND | IB_WR_SEND_WITH_IMM | IB_WR_SEND_WITH_INV => IB_WC_SEND,
        IB_WR_RDMA_READ | IB_WR_RDMA_READ_WITH_INV => IB_WC_RDMA_READ,
        IB_WR_ATOMIC_CMP_AND_SWP => IB_WC_COMP_SWAP,
        IB_WR_ATOMIC_FETCH_AND_ADD => IB_WC_FETCH_ADD,
        IB_WR_LSO => IB_WC_LSO,
        IB_WR_LOCAL_INV => IB_WC_LOCAL_INV,
        IB_WR_REG_MR => IB_WC_REG_MR,
        IB_WR_BIND_MW => IB_WC_BIND_MW,
        IB_WR_ATOMIC_WRITE => IB_WC_ATOMIC_WRITE,
        IB_WR_FLUSH => IB_WC_FLUSH,
        _ => 0xff,
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_completion)]
mod tests {
    use super::*;
    use crate::{
        rxe_ring::Storage,
        rxe_send::SendSnapshots,
        rxe_wire::{
            packet_len,
            Base,
            Extension,
            TransportMut, //
        },
        rxe_wqe::{
            RECV_HEADER_SIZE,
            SEND_HEADER_SIZE,
            SGE_SIZE, //
        }, //
    };

    fn receive() -> Result<ReceiveWqe> {
        let mut bytes = [0; RECV_HEADER_SIZE + SGE_SIZE];
        bytes[..8].copy_from_slice(&0x123456789abcdef0u64.to_ne_bytes());
        bytes[16..20].copy_from_slice(&100u32.to_ne_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_ne_bytes());
        bytes[40..48].copy_from_slice(&0x1000u64.to_ne_bytes());
        bytes[48..52].copy_from_slice(&100u32.to_ne_bytes());
        let storage = Storage::new(1, bytes.len() as u32, 64)?;
        storage.memory().write(storage.offset(0), &bytes)?;
        let mut work = ReceiveWqe::read(&storage, 0, 1)?;
        work.dma()?.advance(43)?;
        Ok(work)
    }

    fn packet(opcode: u8, extension: Extension) -> Result<KVec<u8>> {
        let mut bytes = KVec::from_elem(0, packet_len(opcode, 0)?, GFP_KERNEL)?;
        let mut wire = TransportMut::initialize(
            &mut bytes,
            Base {
                opcode,
                psn: 1,
                qpn: 7,
                solicited: false,
                ack: false,
            },
            0,
        )?;
        wire.set(extension)?;
        if wire.mask() & RXE_DETH_MASK != 0 {
            wire.set(Extension::Datagram {
                key: 0x11223344,
                source: 0x556677,
            })?;
        }
        Ok(bytes)
    }

    #[test]
    fn receive_completions_keep_immediate_and_invalidation_byte_orders() -> Result {
        let work = receive()?;
        for opcode in [0x05, 0x0b, 0x65] {
            let bytes = packet(opcode, Extension::Immediate([0x12, 0x34, 0x56, 0x78]))?;
            let wire = Transport::parse(&bytes[..bytes.len() - 4])?;
            let mut record = Record::receive(&work, 4097, 1, &wire)?;
            assert_eq!(record.id.value(), 0x123456789abcdef0);
            assert_eq!(record.flags, IB_WC_GRH | IB_WC_WITH_IMM);
            assert_eq!(record.length, if opcode == 0x0b { 4097 } else { 43 });
            assert_eq!(
                record.opcode,
                if opcode == 0x0b {
                    IB_WC_RECV_RDMA_WITH_IMM
                } else {
                    IB_WC_RECV
                }
            );
            assert_eq!(record.source, if opcode == 0x65 { 0x556677 } else { 0 });
            record.network = Some(Network {
                kind: 2,
                vlan: Some(17),
            });
            let encoded = record.user_bytes(7);
            assert_eq!(&encoded[24..28], &[0x12, 0x34, 0x56, 0x78]);
            assert_eq!(
                &encoded[36..40],
                &(IB_WC_GRH | IB_WC_WITH_IMM).to_ne_bytes()
            );
            assert_eq!(&encoded[16..20], &[0; 4]);
            assert_eq!(&encoded[40..46], &[0; 6]);
            assert_eq!(encoded[46], 1);
            assert_eq!(encoded[47], 0);
        }
        let bytes = packet(0x17, Extension::Invalidate(0x12345678))?;
        let wire = Transport::parse(&bytes[..bytes.len() - 4])?;
        let record = Record::receive(&work, 0, 1, &wire)?;
        assert_eq!(record.flags, IB_WC_GRH | IB_WC_WITH_INVALIDATE);
        assert_eq!(&record.user_bytes(7)[24..28], &0x12345678u32.to_ne_bytes());
        Ok(())
    }

    #[test]
    fn failed_send_completions_do_not_expose_success_metadata() -> Result {
        let storage = Storage::new(1, SEND_HEADER_SIZE as u32, 64)?;
        let mut bytes = [0; SEND_HEADER_SIZE];
        bytes[..8].copy_from_slice(&u64::MAX.to_ne_bytes());
        bytes[12..16].copy_from_slice(&IB_WR_RDMA_WRITE_WITH_IMM.to_ne_bytes());
        bytes[20..24].copy_from_slice(&[0xaa; 4]);
        bytes[184..188].copy_from_slice(&123u32.to_ne_bytes());
        storage.memory().write(storage.offset(0), &bytes)?;
        let mut snapshots = SendSnapshots::new(&storage, SEND_HEADER_SIZE)?;
        let work = snapshots.get(&storage, 0)?;
        let success = Record::send(&work, IB_WC_SUCCESS);
        assert_eq!(success.opcode, IB_WC_RDMA_WRITE);
        assert_eq!(success.length, 123);
        assert_eq!(success.flags, IB_WC_WITH_IMM);
        assert_eq!(success.immediate, [0; 4]);
        for status in [1, 5, 10] {
            let failure = Record::send(&work, status);
            let encoded = failure.user_bytes(7);
            assert_eq!(&encoded[..8], &u64::MAX.to_ne_bytes());
            assert_eq!(&encoded[8..12], &status.to_ne_bytes());
            assert_eq!(&encoded[12..28], &[0; 16]);
            assert_eq!(&encoded[28..32], &7u32.to_ne_bytes());
            assert_eq!(&encoded[32..], &[0; 16]);
            assert!(failure.network.is_none());
        }
        Ok(())
    }
}

const _: () = assert!(core::mem::size_of::<bindings::ib_uverbs_wc>() == USER_BYTES);
const _: () = assert!(core::mem::size_of::<bindings::ib_wc>() >= USER_BYTES);
const _: () = assert!(core::mem::offset_of!(bindings::ib_uverbs_wc, wr_id) == 0);
const _: () = assert!(core::mem::offset_of!(bindings::ib_uverbs_wc, status) == 8);
const _: () = assert!(core::mem::offset_of!(bindings::ib_uverbs_wc, opcode) == 12);
const _: () = assert!(core::mem::offset_of!(bindings::ib_uverbs_wc, byte_len) == 20);
const _: () = assert!(core::mem::offset_of!(bindings::ib_uverbs_wc, ex) == 24);
const _: () = assert!(core::mem::offset_of!(bindings::ib_uverbs_wc, qp_num) == 28);
const _: () = assert!(core::mem::offset_of!(bindings::ib_uverbs_wc, src_qp) == 32);
const _: () = assert!(core::mem::offset_of!(bindings::ib_uverbs_wc, wc_flags) == 36);
const _: () = assert!(core::mem::offset_of!(bindings::ib_uverbs_wc, port_num) == 46);
