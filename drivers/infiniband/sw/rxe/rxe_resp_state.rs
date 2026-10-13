// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Owned responder progress, replay selection and error recovery.

#![forbid(unsafe_code)]

use super::{
    rxe_param::{
        AETH_NAK_INVALID_REQ,
        AETH_NAK_REM_ACC_ERR,
        AETH_NAK_REM_OP_ERR,
        RXE_ATOMIC_MASK,
        RXE_ATOMIC_WRITE_MASK,
        RXE_FLUSH_MASK,
        RXE_READ_MASK,
        RXE_SEND_MASK,
        RXE_WRITE_MASK, //
    },
    rxe_queue::{
        Consumer,
        WorkQueue, //
    },
    rxe_replay::{
        Duplicate,
        Kind, //
    },
    rxe_resp_check::Protocol,
    rxe_wire::Transport, //
};
use kernel::{
    bindings::{
        ib_wc_status_IB_WC_LOC_QP_OP_ERR as LOCAL_OPERATION,
        ib_wc_status_IB_WC_REM_ACCESS_ERR as REMOTE_ACCESS,
        ib_wc_status_IB_WC_REM_INV_REQ_ERR as INVALID_REQUEST, //
    },
    prelude::*, //
};

/// States of the serialized receive-side transport engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum State {
    None,
    GetReq,
    ChkPsn,
    ChkOpSeq,
    ChkOpValid,
    ChkResource,
    ChkLength,
    ChkRkey,
    Execute,
    ReadReply,
    AtomicReply,
    AtomicWriteReply,
    ProcessFlush,
    Complete,
    Acknowledge,
    Cleanup,
    DuplicateRequest,
    ErrMalformedWqe,
    ErrUnsupportedOpcode,
    ErrMisalignedAtomic,
    ErrPsnOutOfSeq,
    ErrMissingOpcodeFirst,
    ErrMissingOpcodeLastC,
    ErrMissingOpcodeLastD1E,
    ErrTooManyRdmaAtmReq,
    ErrRnr,
    ErrRkeyViolationEvent,
    ErrRkeyViolation,
    ErrInvalidateRkey,
    ErrLength,
    ErrCqOverflow,
    Error,
    Done,
    Exit,
}

/// Responder state owned by RXE.
#[derive(Zeroable)]
pub(crate) struct Responder {
    pub(super) consumer: Consumer,
    pub(crate) msn: u32,
    pub(crate) psn: u32,
    pub(crate) ack_psn: u32,
    pub(crate) opcode: i32,
    pub(crate) drop_msg: bool,
    pub(crate) goto_error: bool,
    pub(crate) sent_psn_nak: bool,
    pub(crate) status: u32,
    pub(crate) aeth_syndrome: u8,
    pub(super) memory: Option<KBox<super::rxe_resp_memory::RequestMemory>>,
    pub(super) resources: Option<KBox<super::rxe_replay::Cache>>,
}

/// A replay decision contains no borrow of packet or responder storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Replay {
    Acknowledge(u32),
    Continue(State),
}

impl Responder {
    pub(super) fn new() -> Result<Self> {
        let mut state = Self::zeroed();
        state.memory = Some(super::rxe_resp_memory::RequestMemory::new()?);
        state.opcode = -1;
        Ok(state)
    }

    pub(super) fn reset(&mut self) {
        self.msn = 0;
        self.opcode = -1;
        self.drop_msg = false;
        self.goto_error = false;
        self.sent_psn_nak = false;
        self.memory.as_mut().unwrap().reset();
        if let Some(resources) = &mut self.resources {
            resources.reset();
        }
    }

    /// Captures a private receive without advancing it before completion.
    pub(super) fn capture_receive(&mut self, queue: &WorkQueue, max_sge: u32) -> State {
        let snapshot = match self.consumer.receive(queue, max_sge) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => return State::ErrRnr,
            Err(failure) => {
                self.memory.as_mut().unwrap().receive = failure.completion();
                return State::ErrMalformedWqe;
            }
        };
        self.memory.as_mut().unwrap().receive = Some(snapshot);
        State::ChkLength
    }

    /// Releases the current registration while retaining completed replay entries.
    pub(super) fn finish_request(&mut self) {
        drop(self.memory.as_mut().unwrap().region.take());
        if let Some(cache) = self.resources.as_mut() {
            cache.finish();
        }
    }

    /// Advances accepted sequencing and ages replay slots, including after SEND/WRITE traffic.
    pub(super) fn advance_psn(&mut self, expected: u32) {
        self.psn = expected & 0xffffff;
        if let Some(cache) = &mut self.resources {
            cache.expire(self.psn);
        }
    }

    pub(super) fn replay(&mut self, wire: &Transport<'_>) -> Replay {
        let mask = wire.mask();
        if mask & (RXE_SEND_MASK | RXE_WRITE_MASK) != 0 {
            return Replay::Acknowledge(self.ack_psn.wrapping_sub(1) & 0xffffff);
        }
        let request = if mask & RXE_FLUSH_MASK != 0 {
            Duplicate::Flush
        } else if mask & RXE_READ_MASK != 0 {
            let Ok(remote) = wire.remote() else {
                return Replay::Continue(State::Cleanup);
            };
            Duplicate::Read {
                address: remote.address,
                key: remote.key,
                length: remote.length,
            }
        } else if mask & RXE_ATOMIC_MASK != 0 {
            Duplicate::Atomic
        } else if mask & RXE_ATOMIC_WRITE_MASK != 0 {
            Duplicate::AtomicWrite
        } else {
            return Replay::Continue(State::Cleanup);
        };
        let kind = self
            .resources
            .as_mut()
            .and_then(|cache| cache.replay(request, wire.psn()));
        Replay::Continue(match kind {
            Some(Kind::Read) => State::ReadReply,
            Some(Kind::Atomic) => State::AtomicReply,
            Some(Kind::AtomicWrite) => State::AtomicWriteReply,
            Some(Kind::Flush) => State::ProcessFlush,
            None => State::Cleanup,
        })
    }

    fn fail(&mut self, syndrome: u32, status: u32) -> State {
        self.aeth_syndrome = syndrome as u8;
        self.status = status;
        self.goto_error = true;
        State::Complete
    }

    fn discard_segment(&mut self, shared_receive: bool) -> State {
        // A missing UC tail abandons sequencing even when WRITE has no receive
        // request, or an SRQ request must first complete with an error.
        self.opcode = -1;
        let memory = self.memory.as_mut().unwrap();
        if shared_receive {
            self.drop_msg = true;
            if memory.receive.is_none() {
                State::Cleanup
            } else {
                self.status = INVALID_REQUEST;
                State::Complete
            }
        } else {
            if let Some(wqe) = memory.receive.as_mut() {
                wqe.reset();
            }
            drop(memory.region.take());
            State::Cleanup
        }
    }

    /// Selects recovery for protocol errors, leaving other transitions unchanged.
    pub(super) fn recover(
        &mut self,
        error: State,
        protocol: Protocol,
        shared_receive: bool,
    ) -> State {
        match error {
            State::ErrTooManyRdmaAtmReq
            | State::ErrMissingOpcodeFirst
            | State::ErrMissingOpcodeLastC
            | State::ErrUnsupportedOpcode
            | State::ErrMisalignedAtomic => self.fail(AETH_NAK_INVALID_REQ, INVALID_REQUEST),
            State::ErrMissingOpcodeLastD1E => self.discard_segment(shared_receive),
            State::ErrRkeyViolation => {
                if protocol == Protocol::Reliable {
                    self.fail(AETH_NAK_REM_ACC_ERR, REMOTE_ACCESS)
                } else {
                    self.drop_msg = true;
                    self.opcode = -1;
                    if shared_receive {
                        self.status = REMOTE_ACCESS;
                        State::Complete
                    } else {
                        State::Cleanup
                    }
                }
            }
            State::ErrInvalidateRkey => {
                self.goto_error = true;
                self.status = INVALID_REQUEST;
                State::Complete
            }
            State::ErrLength => {
                if protocol == Protocol::Reliable {
                    self.fail(AETH_NAK_INVALID_REQ, INVALID_REQUEST)
                } else {
                    self.drop_msg = true;
                    self.opcode = -1;
                    if shared_receive {
                        self.status = INVALID_REQUEST;
                        State::Complete
                    } else {
                        State::Cleanup
                    }
                }
            }
            State::ErrMalformedWqe => self.fail(AETH_NAK_REM_OP_ERR, LOCAL_OPERATION),
            other => other,
        }
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_resp_state)]
mod tests {
    use super::*;
    use crate::{
        rxe_replay::{
            Cache,
            Request, //
        },
        rxe_resp_memory::RequestMemory,
        rxe_ring::Storage,
        rxe_wire::bth,
        rxe_wqe::{
            ReceiveWqe,
            RECV_HEADER_SIZE,
            SGE_SIZE, //
        },
    };

    fn responder() -> Result<Responder> {
        let mut resp = Responder::zeroed();
        resp.memory = Some(RequestMemory::new()?);
        resp.resources = Some(Cache::new(4)?);
        Ok(resp)
    }

    #[test]
    fn malformed_private_receive_preserves_error_identity() -> Result {
        let queue = WorkQueue::new(1, (RECV_HEADER_SIZE + SGE_SIZE) as u32)?;
        for (length, capacity) in [(4u32, 8u32), (8, 4)] {
            let mut bytes = [0; RECV_HEADER_SIZE + SGE_SIZE];
            bytes[..8].copy_from_slice(&77u64.to_ne_bytes());
            bytes[16..20].copy_from_slice(&length.to_ne_bytes());
            bytes[28..32].copy_from_slice(&1u32.to_ne_bytes());
            bytes[48..52].copy_from_slice(&capacity.to_ne_bytes());
            queue.storage().write(0, 0, &bytes)?;
            queue.storage().publish_producer(1);
            let mut resp = responder()?;
            let state = resp.capture_receive(&queue, 1);
            assert_eq!(state, State::ErrMalformedWqe);
            // Selection leaves the offending entry for the normal completion path.
            assert_eq!(resp.consumer.position(), 0);
            assert_eq!(
                resp.recover(state, Protocol::Reliable, false),
                State::Complete
            );
            assert!(resp.goto_error);
            assert_eq!(resp.status, LOCAL_OPERATION);
            // Later mapped writes cannot change the retained error completion identity.
            queue.storage().write(0, 0, &99u64.to_ne_bytes())?;
            let receive = resp.memory.as_ref().unwrap().receive.as_ref().unwrap();
            let completion = super::super::rxe_completion::Record::error(receive.id(), resp.status);
            assert_eq!(completion.id.value(), 77);
            assert_eq!(completion.status, LOCAL_OPERATION);
            assert_eq!(receive.remaining(), 0);
            assert_eq!(receive.capacity(), 0);
        }
        Ok(())
    }

    #[test]
    fn reliable_and_unreliable_error_recovery() {
        for shared in [false, true] {
            for (error, status, syndrome) in [
                (State::ErrLength, INVALID_REQUEST, AETH_NAK_INVALID_REQ),
                (State::ErrRkeyViolation, REMOTE_ACCESS, AETH_NAK_REM_ACC_ERR),
            ] {
                let mut resp = Responder::zeroed();
                assert_eq!(
                    resp.recover(error, Protocol::Reliable, shared),
                    State::Complete
                );
                assert!(resp.goto_error);
                assert_eq!(resp.status, status);
                assert_eq!(u32::from(resp.aeth_syndrome), syndrome);

                let mut resp = Responder::zeroed();
                resp.opcode = 0x26;
                assert_eq!(
                    resp.recover(error, Protocol::Unreliable, shared),
                    if shared {
                        State::Complete
                    } else {
                        State::Cleanup
                    }
                );
                assert!(!resp.goto_error);
                assert!(resp.drop_msg);
                assert_eq!(resp.opcode, -1);
                assert_eq!(
                    super::super::rxe_resp_check::check_sequence(
                        Protocol::Unreliable,
                        resp.opcode,
                        0x2a,
                    ),
                    State::ChkOpValid
                );
                if shared {
                    assert_eq!(resp.status, status);
                }
            }
        }
        let mut resp = Responder::zeroed();
        assert_eq!(
            resp.recover(State::ErrMalformedWqe, Protocol::Datagram, false),
            State::Complete
        );
        assert!(resp.goto_error);
        assert_eq!(resp.status, LOCAL_OPERATION);
        assert_eq!(u32::from(resp.aeth_syndrome), AETH_NAK_REM_OP_ERR);
    }

    #[test]
    fn missing_segment_preserves_srq_work_and_rewinds_private_work() -> Result {
        let storage = Storage::new(1, (RECV_HEADER_SIZE + SGE_SIZE) as u32, 64)?;
        let mut bytes = [0; RECV_HEADER_SIZE + SGE_SIZE];
        bytes[..8].copy_from_slice(&77u64.to_ne_bytes());
        bytes[16..20].copy_from_slice(&8u32.to_ne_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_ne_bytes());
        bytes[48..52].copy_from_slice(&8u32.to_ne_bytes());
        storage.memory().write(storage.offset(0), &bytes)?;
        for shared in [false, true] {
            let mut resp = responder()?;
            let mut receive = ReceiveWqe::read(&storage, 0, 1)?;
            receive.dma()?.advance(3)?;
            resp.memory.as_mut().unwrap().receive = Some(receive);
            resp.opcode = 0x20;
            assert_eq!(
                resp.recover(State::ErrMissingOpcodeLastD1E, Protocol::Unreliable, shared),
                if shared {
                    State::Complete
                } else {
                    State::Cleanup
                }
            );
            let receive = resp.memory.as_ref().unwrap().receive.as_ref().unwrap();
            assert_eq!(receive.id().value(), 77);
            assert_eq!(receive.received(), if shared { 3 } else { 0 });
            assert_eq!(resp.opcode, -1);
            assert_eq!(
                super::super::rxe_resp_check::check_sequence(
                    Protocol::Unreliable,
                    resp.opcode,
                    0x24,
                ),
                State::ChkOpValid
            );
            assert_eq!(resp.drop_msg, shared);
            assert!(!resp.goto_error);
        }
        let mut resp = responder()?;
        resp.opcode = 0x26;
        assert_eq!(
            resp.recover(State::ErrMissingOpcodeLastD1E, Protocol::Unreliable, true),
            State::Cleanup
        );
        assert!(resp.drop_msg);
        assert_eq!(
            super::super::rxe_resp_check::check_sequence(Protocol::Unreliable, resp.opcode, 0x2a,),
            State::ChkOpValid
        );
        Ok(())
    }

    #[test]
    fn duplicate_ack_and_read_replay_wrap_psn() -> Result {
        let mut resp = responder()?;
        let send = bth(0x04, 0xffffff, false, 0, 1, false);
        assert_eq!(
            resp.replay(&Transport::parse(&send)?),
            Replay::Acknowledge(0xffffff)
        );
        resp.resources.as_mut().unwrap().start(
            Request::Read {
                address: 0x1000,
                key: 123,
                length: 2048,
                authorization: None,
            },
            0xffffff,
            1024,
            0,
        )?;
        resp.finish_request();
        let mut bytes = [0; 28];
        bytes[..12].copy_from_slice(&bth(0x0c, 0, false, 0, 1, false));
        bytes[12..20].copy_from_slice(&0x1400u64.to_be_bytes());
        bytes[20..24].copy_from_slice(&123u32.to_be_bytes());
        bytes[24..28].copy_from_slice(&1024u32.to_be_bytes());
        assert_eq!(
            resp.replay(&Transport::parse(&bytes)?),
            Replay::Continue(State::ReadReply)
        );
        let read = resp.resources.as_ref().unwrap().read()?;
        assert_eq!(read.address, 0x1400);
        assert_eq!(read.residual, 1024);
        assert_eq!(read.psn, 0);
        resp.finish_request();
        bytes[12..20].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            resp.replay(&Transport::parse(&bytes)?),
            Replay::Continue(State::Cleanup)
        );
        Ok(())
    }
}
