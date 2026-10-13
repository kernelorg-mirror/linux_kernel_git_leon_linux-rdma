// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Checked kernel work-request validation and queue encoding.

#![forbid(unsafe_code)]

use super::{
    rxe_device::DeviceData,
    rxe_mr::{
        FastRegistration,
        Regions, //
    },
    rxe_opcode::work_mask,
    rxe_param::{
        RXE_PORT_MAX_MSG_SZ,
        WR_ATOMIC_MASK,
        WR_INLINE_MASK,
        WR_LOCAL_OP_MASK,
        WR_MAX_QPT, //
    },
    rxe_wqe::{
        RECV_HEADER_SIZE,
        SEND_DMA_OFFSET,
        SEND_HEADER_SIZE,
        SGE_SIZE, //
    }, //
};
use kernel::bindings::{
    ib_wr_opcode_IB_WR_ATOMIC_CMP_AND_SWP as CAS,
    ib_wr_opcode_IB_WR_ATOMIC_FETCH_AND_ADD as FAA,
    ib_wr_opcode_IB_WR_ATOMIC_WRITE as ATOMIC_WRITE,
    ib_wr_opcode_IB_WR_BIND_MW as BIND_MW,
    ib_wr_opcode_IB_WR_FLUSH as FLUSH,
    ib_wr_opcode_IB_WR_LOCAL_INV as LOCAL_INV,
    ib_wr_opcode_IB_WR_RDMA_READ as READ,
    ib_wr_opcode_IB_WR_RDMA_READ_WITH_INV as READ_INV,
    ib_wr_opcode_IB_WR_RDMA_WRITE as WRITE,
    ib_wr_opcode_IB_WR_RDMA_WRITE_WITH_IMM as WRITE_IMM,
    ib_wr_opcode_IB_WR_REG_MR as REG_MR,
    ib_wr_opcode_IB_WR_SEND as SEND,
    ib_wr_opcode_IB_WR_SEND_WITH_IMM as SEND_IMM,
    ib_wr_opcode_IB_WR_SEND_WITH_INV as SEND_INV, //
};
use kernel::{
    bindings::ib_send_flags_IB_SEND_INLINE as IB_SEND_INLINE,
    prelude::*,
    rdma::{
        ScatterGather,
        SendRequest, //
    }, //
};

const MAX_SGE: usize = 32;
const MAX_DATA: usize = MAX_SGE * SGE_SIZE;

/// Copied queue limits, fixed before the queue is published.
pub(super) struct Limits {
    pub(super) kind: u32,
    pub(super) max_sge: usize,
    pub(super) max_inline: usize,
}

/// Scalar operation metadata captured by the kernel verbs adapter.
pub(super) enum Operation {
    None,
    Remote {
        address: u64,
        key: u32,
    },
    Atomic {
        address: u64,
        key: u32,
        compare_add: u64,
        swap: u64,
    },
    Datagram {
        destination: u32,
        key: u32,
        pkey: u16,
        address_handle: u32,
    },
}

pub(super) struct Request {
    pub(super) id: u64,
    pub(super) opcode: u32,
    pub(super) flags: u32,
    pub(super) immediate: [u8; 4],
    pub(super) operation: Operation,
}

impl Request {
    /// Captures selected kernel metadata and retains any registration capability.
    pub(super) fn capture(
        request: &SendRequest<'_, DeviceData>,
        regions: &Regions,
    ) -> Result<(Self, Option<FastRegistration>)> {
        let mut registration = None;
        let operation = if !request.kind().is_connected() {
            let datagram = request.datagram().ok_or(EINVAL)?;
            Operation::Datagram {
                destination: datagram.destination,
                key: datagram.key,
                pkey: datagram.pkey,
                address_handle: datagram.address.number(),
            }
        } else {
            match request.opcode() {
                WRITE_IMM | WRITE | READ | READ_INV => {
                    let remote = request.remote().ok_or(EINVAL)?;
                    Operation::Remote {
                        address: remote.address,
                        key: remote.key,
                    }
                }
                CAS | FAA => {
                    let atomic = request.atomic().ok_or(EINVAL)?;
                    Operation::Atomic {
                        address: atomic.address,
                        key: atomic.key,
                        compare_add: atomic.compare_add,
                        swap: atomic.swap,
                    }
                }
                REG_MR => {
                    let selected = request.registration().ok_or(EINVAL)?;
                    registration = Some(regions.prepare_registration(
                        selected.region,
                        selected.key,
                        selected.access,
                        selected.address,
                        selected.length,
                    )?);
                    Operation::None
                }
                SEND | SEND_IMM | SEND_INV | LOCAL_INV => Operation::None,
                _ => return Err(EINVAL),
            }
        };
        Ok((
            Self {
                id: request.id(),
                opcode: request.opcode(),
                flags: request.flags(),
                immediate: request.immediate(),
                operation,
            },
            registration,
        ))
    }
}

fn message_length(list: &[ScatterGather], max_sge: usize) -> Result<u32> {
    if list.len() > max_sge || list.len() > MAX_SGE {
        return Err(EINVAL);
    }
    let length: u64 = list.iter().map(|entry| u64::from(entry.length())).sum();
    if length > u64::from(RXE_PORT_MAX_MSG_SZ) {
        return Err(EINVAL);
    }
    Ok(length as u32)
}

/// Validates common metadata before the adapter reads an opcode-specific C extension.
pub(super) fn validate(limits: &Limits, opcode: u32, flags: u32, list: &[ScatterGather]) -> Result {
    if opcode >= 33 || limits.kind >= WR_MAX_QPT || opcode == READ_INV {
        return Err(EINVAL);
    }
    // The native verbs API supplies no typed metadata for these operations.
    // Userspace requests carry their metadata through the separate shared-ring decoder.
    if matches!(opcode, BIND_MW | FLUSH | ATOMIC_WRITE) {
        return Err(EOPNOTSUPP);
    }
    let mask = work_mask(opcode, limits.kind);
    if mask == 0 {
        return Err(EINVAL);
    }
    let length = message_length(list, limits.max_sge)?;
    if flags & IB_SEND_INLINE as u32 != 0
        && (mask & WR_INLINE_MASK == 0 || length as usize > limits.max_inline)
    {
        return Err(EINVAL);
    }
    Ok(())
}

/// Validates operation metadata before checking or consuming queue capacity.
pub(super) fn validate_request(
    request: &Request,
    list: &[ScatterGather],
    limits: &Limits,
) -> Result {
    validate(limits, request.opcode, request.flags, list)?;
    if work_mask(request.opcode, limits.kind) & WR_ATOMIC_MASK != 0 {
        let Operation::Atomic { address, .. } = request.operation else {
            return Err(EINVAL);
        };
        if address & 7 != 0 || message_length(list, limits.max_sge)? != 8 {
            return Err(EINVAL);
        }
    }
    Ok(())
}

/// Initialized bytes for one unpublished kernel submission.
pub(super) struct Submission {
    bytes: [u8; SEND_HEADER_SIZE + MAX_DATA],
    length: usize,
}

impl Submission {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    pub(super) fn send(
        request: &Request,
        list: &[ScatterGather],
        limits: &Limits,
        mut read_inline: impl FnMut(u64, &mut [u8]) -> Result,
    ) -> Result<Self> {
        validate_request(request, list, limits)?;
        let mask = work_mask(request.opcode, limits.kind);
        let length = message_length(list, limits.max_sge)?;
        let mut submission = Self {
            bytes: [0; SEND_HEADER_SIZE + MAX_DATA],
            length: SEND_HEADER_SIZE,
        };
        let bytes = &mut submission.bytes;
        bytes[..8].copy_from_slice(&request.id.to_ne_bytes());
        bytes[12..16].copy_from_slice(&request.opcode.to_ne_bytes());
        bytes[16..20].copy_from_slice(&request.flags.to_ne_bytes());
        bytes[20..24].copy_from_slice(&request.immediate);
        match request.operation {
            Operation::None => (),
            Operation::Remote { address, key } => {
                bytes[24..32].copy_from_slice(&address.to_ne_bytes());
                bytes[32..36].copy_from_slice(&key.to_ne_bytes());
            }
            Operation::Atomic {
                address,
                key,
                compare_add,
                swap,
            } => {
                bytes[24..32].copy_from_slice(&address.to_ne_bytes());
                bytes[32..40].copy_from_slice(&compare_add.to_ne_bytes());
                bytes[40..48].copy_from_slice(&swap.to_ne_bytes());
                bytes[48..52].copy_from_slice(&key.to_ne_bytes());
            }
            Operation::Datagram {
                destination,
                key,
                pkey,
                address_handle,
            } => {
                bytes[24..28].copy_from_slice(&destination.to_ne_bytes());
                bytes[28..32].copy_from_slice(&key.to_ne_bytes());
                bytes[32..34].copy_from_slice(&pkey.to_ne_bytes());
                bytes[36..40].copy_from_slice(&address_handle.to_ne_bytes());
            }
        }
        if mask & WR_LOCAL_OP_MASK != 0 {
            return Ok(submission);
        }
        bytes[SEND_DMA_OFFSET..SEND_DMA_OFFSET + 4].copy_from_slice(&length.to_ne_bytes());
        bytes[SEND_DMA_OFFSET + 4..SEND_DMA_OFFSET + 8].copy_from_slice(&length.to_ne_bytes());
        bytes[SEND_DMA_OFFSET + 12..SEND_DMA_OFFSET + 16]
            .copy_from_slice(&(list.len() as u32).to_ne_bytes());
        if request.flags & IB_SEND_INLINE as u32 != 0 {
            let data = bytes[SEND_HEADER_SIZE..]
                .get_mut(..length as usize)
                .ok_or(EINVAL)?;
            let mut offset = 0;
            for entry in list {
                let end = offset + entry.length() as usize;
                if offset != end {
                    read_inline(entry.address(), &mut data[offset..end])?;
                }
                offset = end;
            }
            submission.length += length as usize;
        } else {
            for (entry, output) in list
                .iter()
                .zip(bytes[SEND_HEADER_SIZE..].chunks_exact_mut(SGE_SIZE))
            {
                encode_sge(entry, output);
            }
            submission.length += list.len() * SGE_SIZE;
        }
        Ok(submission)
    }

    pub(super) fn receive(id: u64, list: &[ScatterGather], max_sge: usize) -> Result<Self> {
        let length = message_length(list, max_sge)?;
        let mut submission = Self {
            bytes: [0; SEND_HEADER_SIZE + MAX_DATA],
            length: RECV_HEADER_SIZE + list.len() * SGE_SIZE,
        };
        submission.bytes[..8].copy_from_slice(&id.to_ne_bytes());
        submission.bytes[16..20].copy_from_slice(&length.to_ne_bytes());
        submission.bytes[20..24].copy_from_slice(&length.to_ne_bytes());
        submission.bytes[28..32].copy_from_slice(&(list.len() as u32).to_ne_bytes());
        for (entry, output) in list
            .iter()
            .zip(submission.bytes[RECV_HEADER_SIZE..].chunks_exact_mut(SGE_SIZE))
        {
            encode_sge(entry, output);
        }
        Ok(submission)
    }
}

fn encode_sge(entry: &ScatterGather, output: &mut [u8]) {
    output[..8].copy_from_slice(&entry.address().to_ne_bytes());
    output[8..12].copy_from_slice(&entry.length().to_ne_bytes());
    output[12..16].copy_from_slice(&entry.key().to_ne_bytes());
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_submission)]
mod tests {
    use super::*;
    use crate::{
        rxe_ring::Storage,
        rxe_send::SendSnapshots,
        rxe_wqe::ReceiveWqe, //
    };
    use kernel::bindings::{
        ib_qp_type_IB_QPT_RC as RC,
        ib_wr_opcode_IB_WR_ATOMIC_CMP_AND_SWP as CAS,
        ib_wr_opcode_IB_WR_RDMA_WRITE_WITH_IMM as WRITE_IMM,
        ib_wr_opcode_IB_WR_REG_MR as REG_MR,
        ib_wr_opcode_IB_WR_SEND as SEND, //
    };

    fn limits() -> Limits {
        Limits {
            kind: RC,
            max_sge: 32,
            max_inline: 512,
        }
    }

    #[test]
    fn inline_submission_concatenates_only_nonempty_sources() -> Result {
        let limits = limits();
        let request = Request {
            id: 0x1122334455667788,
            opcode: WRITE_IMM,
            flags: IB_SEND_INLINE as u32,
            immediate: [0x12, 0x34, 0x56, 0x78],
            operation: Operation::Remote {
                address: 0x1003,
                key: 0x12345678,
            },
        };
        let list = [
            ScatterGather::new(1, 3, 0),
            ScatterGather::new(0, 0, 0),
            ScatterGather::new(2, 5, 0),
        ];
        let mut calls = 0;
        let submission = Submission::send(&request, &list, &limits, |address, output| {
            calls += 1;
            output.copy_from_slice(match address {
                1 => b"abc",
                2 => b"defgh",
                _ => panic!("empty SGE accessed"),
            });
            Ok(())
        })?;
        assert_eq!(calls, 2);
        let storage = Storage::new(1, (SEND_HEADER_SIZE + 16) as u32, 64)?;
        storage.write(0, 0, submission.bytes())?;
        let mut snapshots = SendSnapshots::new(&storage, SEND_HEADER_SIZE + 16)?;
        let mut work = snapshots.get(&storage, 0)?;
        assert_eq!(work.wr.wr_id.value(), request.id);
        assert_eq!(work.wr.immediate(), request.immediate);
        assert_eq!(work.wr.address(), 0x1003);
        assert_eq!(work.wr.remote_key(), 0x12345678);
        assert_eq!(work.dma.num_sge, 3);
        let mut payload = [0; 8];
        work.copy_inline(&mut payload, 512)?;
        assert_eq!(&payload, b"abcdefgh");
        assert!(Submission::send(
            &request,
            &list,
            &Limits {
                max_inline: 7,
                ..limits
            },
            |_, _| panic!("invalid inline copy")
        )
        .is_err());
        assert!(Submission::send(&request, &list, &limits, |_, _| Err(EFAULT)).is_err());
        Ok(())
    }

    #[test]
    fn receive_submission_preserves_sges_and_rejects_overflow() -> Result {
        let list = [
            ScatterGather::new(0x1003, 3, 7),
            ScatterGather::new(0x2001, 5, 9),
        ];
        let submission = Submission::receive(u64::MAX, &list, 2)?;
        let storage = Storage::new(1, submission.bytes().len() as u32, 64)?;
        storage.write(0, 0, submission.bytes())?;
        let mut work = ReceiveWqe::read(&storage, 0, 2)?;
        assert_eq!(work.id().value(), u64::MAX);
        assert_eq!(work.capacity(), 8);
        work.dma()?.advance(4)?;
        assert_eq!(work.received(), 4);
        assert!(Submission::receive(0, &list, 1).is_err());
        assert!(Submission::receive(0, &[ScatterGather::new(0, u32::MAX, 0)], 1).is_err());
        assert!(Submission::receive(0, &[ScatterGather::new(0, 0, 0); 33], 33).is_err());
        let empty = Submission::receive(7, &[], 0)?;
        assert_eq!(empty.bytes().len(), RECV_HEADER_SIZE);
        assert!(empty.bytes()[8..].iter().all(|byte| *byte == 0));
        assert_eq!(
            storage.write(0, submission.bytes().len(), &[1]),
            Err(EINVAL)
        );
        Ok(())
    }

    #[test]
    fn atomic_and_registration_submissions_keep_native_metadata() -> Result {
        let limits = limits();
        let mut request = Request {
            id: 7,
            opcode: CAS,
            flags: 0,
            immediate: [0; 4],
            operation: Operation::Atomic {
                address: 0x1000,
                key: 0x12345678,
                compare_add: 0xaabbccdd,
                swap: 0x11223344,
            },
        };
        let list = [ScatterGather::new(0x2000, 8, 9)];
        let submission = Submission::send(&request, &list, &limits, |_, _| {
            panic!("atomic inline copy")
        })?;
        let storage = Storage::new(1, (SEND_HEADER_SIZE + SGE_SIZE) as u32, 64)?;
        storage.write(0, 0, submission.bytes())?;
        let mut snapshots = SendSnapshots::new(&storage, SEND_HEADER_SIZE + SGE_SIZE)?;
        {
            let mut work = snapshots.get(&storage, 0)?;
            assert_eq!(work.wr.address(), 0x1000);
            assert_eq!(work.wr.atomic_key(), 0x12345678);
            assert_eq!(work.wr.compare_add(), 0xaabbccdd);
            assert_eq!(work.wr.swap(), 0x11223344);
            work.dma()?.advance(8)?;
            assert_eq!(work.dma.resid, 0);
        }
        request.operation = Operation::Atomic {
            address: 0x1001,
            key: 7,
            compare_add: 0,
            swap: 0,
        };
        assert!(Submission::send(&request, &list, &limits, |_, _| panic!(
            "invalid atomic copy"
        ))
        .is_err());
        request.opcode = REG_MR;
        request.operation = Operation::None;
        let submission = Submission::send(&request, &[], &limits, |_, _| {
            panic!("registration payload")
        })?;
        storage.write(0, 0, submission.bytes())?;
        snapshots.release(0);
        let work = snapshots.get(&storage, 0)?;
        assert_eq!(
            &submission.bytes()[24..SEND_DMA_OFFSET],
            &[0; SEND_DMA_OFFSET - 24]
        );
        assert_eq!(work.dma.length, 0);
        assert_eq!(
            validate(
                &Limits {
                    kind: u32::MAX,
                    ..limits
                },
                SEND,
                0,
                &[]
            ),
            Err(EINVAL)
        );
        assert_eq!(validate(&limits, u32::MAX, 0, &[]), Err(EINVAL));
        Ok(())
    }
}
