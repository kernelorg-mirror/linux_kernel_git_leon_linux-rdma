// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Completion sequencing, bounded response copies and retry decisions.

#![forbid(unsafe_code)]

use super::{
    rxe_mr::MrRef,
    rxe_mr_data::Buffer,
    rxe_send::SendWqe,
    rxe_wire::{
        psn_compare,
        Transport, //
    }, //
};
use crate::rxe_param::{
    AETH_ACK,
    AETH_NAK,
    AETH_NAK_INVALID_REQ,
    AETH_NAK_PSN_SEQ_ERROR,
    AETH_NAK_REM_ACC_ERR,
    AETH_NAK_REM_OP_ERR,
    AETH_RNR_NAK,
    AETH_TYPE_MASK,
    RXE_END_MASK,
    RXE_START_MASK,
    WQE_STATE_DONE,
    WQE_STATE_ERROR,
    WQE_STATE_PENDING,
    WQE_STATE_POSTED,
    WR_ATOMIC_OR_READ_MASK,
    WR_ATOMIC_WRITE_MASK,
    WR_FLUSH_MASK, //
};
use kernel::bindings::{
    ib_wc_status_IB_WC_BAD_RESP_ERR as IB_WC_BAD_RESP_ERR,
    ib_wc_status_IB_WC_FATAL_ERR as IB_WC_FATAL_ERR,
    ib_wc_status_IB_WC_LOC_LEN_ERR as IB_WC_LOC_LEN_ERR,
    ib_wc_status_IB_WC_LOC_PROT_ERR as IB_WC_LOC_PROT_ERR,
    ib_wc_status_IB_WC_REM_ACCESS_ERR as IB_WC_REM_ACCESS_ERR,
    ib_wc_status_IB_WC_REM_INV_REQ_ERR as IB_WC_REM_INV_REQ_ERR,
    ib_wc_status_IB_WC_REM_OP_ERR as IB_WC_REM_OP_ERR,
    ib_wc_status_IB_WC_RETRY_EXC_ERR as IB_WC_RETRY_EXC_ERR,
    ib_wc_status_IB_WC_RNR_RETRY_EXC_ERR as IB_WC_RNR_RETRY_EXC_ERR,
    ib_wc_status_IB_WC_SUCCESS as IB_WC_SUCCESS,
    ib_wr_opcode_IB_WR_ATOMIC_CMP_AND_SWP as IB_WR_ATOMIC_CMP_AND_SWP,
    ib_wr_opcode_IB_WR_ATOMIC_FETCH_AND_ADD as IB_WR_ATOMIC_FETCH_AND_ADD,
    ib_wr_opcode_IB_WR_ATOMIC_WRITE as IB_WR_ATOMIC_WRITE,
    ib_wr_opcode_IB_WR_FLUSH as IB_WR_FLUSH,
    ib_wr_opcode_IB_WR_RDMA_READ as IB_WR_RDMA_READ,
    ib_wr_opcode_IB_WR_RDMA_READ_WITH_INV as IB_WR_RDMA_READ_WITH_INV,
    IB_OPCODE_RC_ACKNOWLEDGE,
    IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE,
    IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST,
    IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST,
    IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE,
    IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY, //
};

use kernel::prelude::*;

/// Completer state owned by RXE.
#[derive(Zeroable)]
pub(crate) struct Completer {
    pub(crate) psn: u32,
    pub(crate) opcode: i32,
    pub(crate) timeout_retry: bool,
    pub(crate) started_retry: bool,
    pub(crate) retry_cnt: u32,
    pub(crate) rnr_retry: u32,
}

impl Completer {
    /// Includes the half-space reservation of a maximum-length READ at MTU 256.
    pub(super) fn has_outstanding(&self, requester_psn: u32) -> bool {
        let outstanding = requester_psn.wrapping_sub(self.psn) & 0xffffff;
        outstanding != 0 && outstanding <= 0x800000
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum State {
    GetWqe,
    CompleteWqe,
    CompleteAck,
    CheckPsn,
    CheckAck,
    Read,
    Atomic,
    WriteSend,
    Update,
    Retry,
    RnrRetry(u8),
    Error,
    Exit,
    Done,
}

// These operations require their specific response, not an implicit ACK of later work.
const RESULT_MASK: u32 = WR_ATOMIC_OR_READ_MASK | WR_ATOMIC_WRITE_MASK | WR_FLUSH_MASK;

const RNR_USEC: [u32; 32] = [
    655360, 10, 20, 30, 40, 60, 80, 120, 160, 240, 320, 480, 640, 960, 1280, 1920, 2560, 3840,
    5120, 7680, 10240, 15360, 20480, 30720, 40960, 61440, 81920, 122880, 163840, 245760, 327680,
    491520,
];

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub(super) retry: u8,
    pub(super) rnr: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Event {
    None,
    ReceiverNotReady,
    SequenceError,
}

pub(super) struct Transition {
    pub(super) state: State,
    pub(super) event: Event,
}

fn reset_retry(progress: &mut Completer, limits: Limits) {
    progress.retry_cnt = u32::from(limits.retry);
    progress.rnr_retry = u32::from(limits.rnr);
    progress.started_retry = false;
}

pub(super) fn select_work(wqe: Option<&SendWqe<'_>>, has_response: bool) -> State {
    let idle = if has_response {
        State::Done
    } else {
        State::Exit
    };
    match wqe.map(|work| work.state) {
        None | Some(WQE_STATE_POSTED) => idle,
        Some(WQE_STATE_DONE) => State::CompleteWqe,
        Some(WQE_STATE_ERROR) => State::Error,
        _ => {
            if has_response {
                State::CheckPsn
            } else {
                State::Exit
            }
        }
    }
}

/// A response can only acknowledge PSNs already reserved by transmitted requests.
pub(super) fn response_was_requested(wire: &Transport<'_>, next_psn: u32) -> bool {
    psn_compare(wire.psn(), next_psn) < 0
}

fn implicit_ack_valid(wire: &Transport<'_>) -> bool {
    let opcode = u32::from(wire.opcode());
    if opcode == IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE {
        return true;
    }
    let Ok(syndrome) = wire.syndrome() else {
        return false;
    };
    let syndrome = u32::from(syndrome);
    match opcode {
        IB_OPCODE_RC_ACKNOWLEDGE => {
            matches!(syndrome & AETH_TYPE_MASK, AETH_ACK | AETH_RNR_NAK)
                || matches!(
                    syndrome,
                    AETH_NAK_PSN_SEQ_ERROR
                        | AETH_NAK_INVALID_REQ
                        | AETH_NAK_REM_ACC_ERR
                        | AETH_NAK_REM_OP_ERR
                )
        }
        IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST
        | IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST
        | IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY
        | IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE => syndrome & AETH_TYPE_MASK == AETH_ACK,
        _ => false,
    }
}

pub(super) fn check_psn(
    progress: &mut Completer,
    limits: Limits,
    wire: &Transport<'_>,
    wqe: &SendWqe<'_>,
) -> State {
    if psn_compare(wire.psn(), wqe.last_psn) > 0 {
        if !implicit_ack_valid(wire) || wqe.state != WQE_STATE_PENDING {
            return State::Done;
        }
        if wqe.mask & RESULT_MASK != 0 {
            return State::Retry;
        }
        reset_retry(progress, limits);
        return State::CompleteWqe;
    }
    let diff = psn_compare(wire.psn(), progress.psn);
    if diff < 0 {
        if psn_compare(wire.psn(), wqe.first_psn) < 0
            && u32::from(wire.opcode()) == IB_OPCODE_RC_ACKNOWLEDGE
            && wire
                .syndrome()
                .is_ok_and(|syn| u32::from(syn) & AETH_TYPE_MASK == AETH_ACK)
        {
            // A delayed successful ACK for earlier work says nothing about this request.
            return State::Done;
        }
        if wire.psn() == wqe.last_psn && wqe.mask & RESULT_MASK == 0 {
            // A duplicate final ACK still needs its syndrome and operation checked.
            return State::CheckAck;
        }
        if u32::from(wire.opcode()) == IB_OPCODE_RC_ACKNOWLEDGE
            && matches!(
                progress.opcode as u32,
                IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST | IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE
            )
        {
            return State::CheckAck;
        }
        State::Done
    } else if diff > 0 && wqe.mask & RESULT_MASK != 0 {
        State::Done
    } else {
        State::CheckAck
    }
}

pub(super) fn check_ack(
    progress: &mut Completer,
    limits: Limits,
    wire: &Transport<'_>,
    wqe: &mut SendWqe<'_>,
) -> Transition {
    let mut event = Event::None;
    let state = (|| {
        let opcode = u32::from(wire.opcode());
        let previous = progress.opcode;
        if previous == -1 {
            if wire.mask() & RXE_START_MASK == 0 {
                return State::Error;
            }
        } else if matches!(
            previous as u32,
            IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST | IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE
        ) && !matches!(
            opcode,
            IB_OPCODE_RC_ACKNOWLEDGE
                | IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE
                | IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST
        ) && !(wire.psn() == wqe.first_psn
            && opcode == IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST)
            && !(wqe.first_psn == wqe.last_psn && opcode == IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY)
        {
            return State::Error;
        }

        match opcode {
            IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST
            | IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST
            | IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY
            | IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE => {
                if opcode != IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE {
                    if !wire
                        .syndrome()
                        .is_ok_and(|syn| u32::from(syn) & AETH_TYPE_MASK == AETH_ACK)
                    {
                        return State::Error;
                    }
                    if wqe.wr.opcode == IB_WR_ATOMIC_WRITE {
                        if opcode != IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY
                            || wire.psn() != wqe.last_psn
                            || wire.payload_len() != 0
                        {
                            return State::Error;
                        }
                        reset_retry(progress, limits);
                        return State::WriteSend;
                    }
                }
                if !matches!(
                    wqe.wr.opcode,
                    IB_WR_RDMA_READ | IB_WR_RDMA_READ_WITH_INV | IB_WR_FLUSH
                ) {
                    wqe.status = IB_WC_FATAL_ERR;
                    return State::Error;
                }
                reset_retry(progress, limits);
                State::Read
            }
            IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE => {
                if !wire
                    .syndrome()
                    .is_ok_and(|syn| u32::from(syn) & AETH_TYPE_MASK == AETH_ACK)
                    || !matches!(
                        wqe.wr.opcode,
                        IB_WR_ATOMIC_CMP_AND_SWP | IB_WR_ATOMIC_FETCH_AND_ADD
                    )
                {
                    return State::Error;
                }
                reset_retry(progress, limits);
                State::Atomic
            }
            IB_OPCODE_RC_ACKNOWLEDGE => {
                let Ok(syn) = wire.syndrome() else {
                    return State::Error;
                };
                let syn = u32::from(syn);
                match syn & AETH_TYPE_MASK {
                    AETH_ACK => {
                        if wqe.mask & RESULT_MASK != 0
                            || matches!(wqe.wr.opcode, IB_WR_FLUSH | IB_WR_ATOMIC_WRITE)
                        {
                            return State::Error;
                        }
                        reset_retry(progress, limits);
                        State::WriteSend
                    }
                    AETH_RNR_NAK => {
                        event = Event::ReceiverNotReady;
                        State::RnrRetry(syn as u8)
                    }
                    AETH_NAK => match syn {
                        AETH_NAK_PSN_SEQ_ERROR => {
                            if psn_compare(wire.psn(), progress.psn) > 0 {
                                event = Event::SequenceError;
                                progress.psn = wire.psn();
                            }
                            State::Retry
                        }
                        _ => {
                            wqe.status = match syn {
                                AETH_NAK_INVALID_REQ => IB_WC_REM_INV_REQ_ERR,
                                AETH_NAK_REM_ACC_ERR => IB_WC_REM_ACCESS_ERR,
                                _ => IB_WC_REM_OP_ERR,
                            };
                            State::Error
                        }
                    },
                    _ => State::Error,
                }
            }
            _ => State::Error,
        }
    })();
    if state == State::Error && wqe.status == IB_WC_SUCCESS {
        wqe.status = IB_WC_BAD_RESP_ERR;
    }
    Transition { state, event }
}

/// Copies a checked response through the request's native scatter cursor.
pub(super) fn read_response(
    wire: &Transport<'_>,
    wqe: &mut SendWqe<'_>,
    atomic: bool,
    mtu: u32,
    lookup: impl FnMut(u32) -> Option<MrRef>,
) -> State {
    let original;
    let data = if atomic {
        let Ok(value) = wire.atomic_reply() else {
            return State::Error;
        };
        original = value.to_ne_bytes();
        &original[..]
    } else {
        let Ok(payload) = wire.payload() else {
            return State::Error;
        };
        let terminal = wire.mask() & RXE_END_MASK != 0;
        if terminal != (wire.psn() == wqe.last_psn)
            || (terminal
                && (payload.len() != wqe.dma.resid as usize || payload.len() > mtu as usize))
            || (!terminal && (payload.len() != mtu as usize || wqe.dma.resid <= mtu))
        {
            wqe.status = IB_WC_LOC_LEN_ERR;
            return State::Error;
        }
        payload
    };
    if !data.is_empty() {
        let result = wqe
            .dma()
            .and_then(|mut dma| dma.copy(Buffer::Write(data), lookup));
        if result.is_err() {
            wqe.status = IB_WC_LOC_PROT_ERR;
            return State::Error;
        }
    }
    if atomic || (wqe.dma.resid == 0 && wire.mask() & RXE_END_MASK != 0) {
        State::CompleteAck
    } else {
        State::Update
    }
}

pub(super) fn update(progress: &mut Completer, wire: &Transport<'_>) {
    progress.opcode = if wire.mask() & RXE_END_MASK != 0 {
        -1
    } else {
        i32::from(wire.opcode())
    };
    if psn_compare(wire.psn(), progress.psn) >= 0 {
        progress.psn = wire.psn().wrapping_add(1) & 0xffffff;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Retry {
    Wait,
    Send,
    Exhausted,
}

pub(super) fn retry(progress: &mut Completer, requester_psn: u32, wqe: &mut SendWqe<'_>) -> Retry {
    if progress.started_retry && !progress.timeout_retry {
        return Retry::Wait;
    }
    if progress.retry_cnt == 0 {
        wqe.status = IB_WC_RETRY_EXC_ERR;
        return Retry::Exhausted;
    }
    if progress.retry_cnt != 7 {
        progress.retry_cnt -= 1;
    }
    if progress.has_outstanding(requester_psn) {
        progress.started_retry = true;
        Retry::Send
    } else {
        Retry::Wait
    }
}

/// Returns the RNR delay in microseconds, or records retry exhaustion.
pub(super) fn rnr_retry(
    progress: &mut Completer,
    syndrome: u8,
    wqe: &mut SendWqe<'_>,
) -> Option<u32> {
    if progress.rnr_retry == 0 {
        wqe.status = IB_WC_RNR_RETRY_EXC_ERR;
        return None;
    }
    if progress.rnr_retry != 7 {
        progress.rnr_retry -= 1;
    }
    Some(RNR_USEC[usize::from(syndrome & 0x1f)])
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_comp_state)]
mod tests {
    use super::*;
    use crate::{
        rxe_opcode,
        rxe_param::RXE_AETH_MASK,
        rxe_ring::Storage,
        rxe_send::SendSnapshots,
        rxe_wire::bth,
        rxe_wqe::{
            SEND_HEADER_SIZE,
            SGE_SIZE, //
        }, //
    };

    fn queue() -> Result<(Storage, KBox<SendSnapshots>)> {
        let size = SEND_HEADER_SIZE + SGE_SIZE;
        let storage = Storage::new(1, size as u32, 64)?;
        let mut bytes = [0; SEND_HEADER_SIZE + SGE_SIZE];
        bytes[184..188].copy_from_slice(&8u32.to_ne_bytes());
        bytes[196..200].copy_from_slice(&1u32.to_ne_bytes());
        bytes[208..216].copy_from_slice(&0x1000u64.to_ne_bytes());
        bytes[216..220].copy_from_slice(&8u32.to_ne_bytes());
        bytes[220..224].copy_from_slice(&9u32.to_ne_bytes());
        storage.memory().write(storage.offset(0), &bytes)?;
        let snapshots = SendSnapshots::new(&storage, size)?;
        Ok((storage, snapshots))
    }

    fn packet(opcode: u8, psn: u32, syndrome: u8, data: &[u8]) -> Result<KVec<u8>> {
        let layout = rxe_opcode::info(opcode);
        let header = layout.length as usize;
        let pad = (4 - (data.len() & 3)) & 3;
        let mut bytes = KVec::from_elem(0, header + data.len() + pad, GFP_KERNEL)?;
        bytes[..12].copy_from_slice(&bth(opcode, psn, false, pad as u8, 1, false));
        if layout.mask & RXE_AETH_MASK != 0 {
            bytes[12] = syndrome;
        }
        bytes[header..header + data.len()].copy_from_slice(data);
        Ok(bytes)
    }

    #[test]
    fn malformed_ack_and_short_terminal_read_report_errors() -> Result {
        let (storage, mut snapshots) = queue()?;
        let mut work = snapshots.get(&storage, 0)?;
        work.wr.opcode = IB_WR_RDMA_READ;
        let mut progress = Completer::zeroed();
        progress.opcode = -1;
        let bytes = packet(0x10, 0, 0x80, &[])?;
        assert_eq!(
            check_ack(
                &mut progress,
                Limits { retry: 3, rnr: 2 },
                &Transport::parse(&bytes)?,
                &mut work
            )
            .state,
            State::Error
        );
        assert_eq!(work.status, IB_WC_BAD_RESP_ERR);
        work.dma.resid = 8;
        let bytes = packet(0x10, 0, 0, &[1, 2, 3, 4])?;
        assert_eq!(
            read_response(
                &Transport::parse(&bytes)?,
                &mut work,
                false,
                256,
                |_| panic!("short terminal response must fail before MR access")
            ),
            State::Error
        );
        assert_eq!(work.status, IB_WC_LOC_LEN_ERR);
        assert_eq!(work.dma.resid, 8);
        work.wr.opcode = IB_WR_ATOMIC_WRITE;
        let bytes = packet(0x10, 0, 0, &[])?;
        assert_eq!(
            check_ack(
                &mut progress,
                Limits { retry: 3, rnr: 2 },
                &Transport::parse(&bytes)?,
                &mut work
            )
            .state,
            State::WriteSend
        );
        assert_eq!((progress.retry_cnt, progress.rnr_retry), (3, 2));
        Ok(())
    }

    #[test]
    fn implicit_acknowledgments_reject_reserved_syndromes_and_future_psns() -> Result {
        let (storage, mut snapshots) = queue()?;
        let mut work = snapshots.get(&storage, 0)?;
        work.state = WQE_STATE_PENDING;
        work.first_psn = 0xfffffe;
        work.last_psn = 0xfffffe;
        let mut progress = Completer::zeroed();
        let limits = Limits { retry: 3, rnr: 4 };
        for (opcode, syndrome, valid) in [
            (0x11, 0, true),
            (0x11, 0x20, true),
            (0x11, 0x60, true),
            (0x11, 0x40, false),
            (0x11, 0x64, false),
            (0x10, 0x20, false),
            (0x12, 0x60, false),
        ] {
            let bytes = packet(opcode, 0xffffff, syndrome, &[])?;
            let wire = Transport::parse(&bytes)?;
            assert_eq!(
                check_psn(&mut progress, limits, &wire, &work),
                if valid {
                    State::CompleteWqe
                } else {
                    State::Done
                }
            );
            assert!(response_was_requested(&wire, 0));
            assert!(!response_was_requested(&wire, 0xffffff));
            assert!(!response_was_requested(&wire, 0xfffffe));
        }
        Ok(())
    }

    #[test]
    fn psn_wrap_and_work_selection_preserve_completion_order() -> Result {
        let (storage, mut snapshots) = queue()?;
        let mut work = snapshots.get(&storage, 0)?;
        assert_eq!(select_work(None, false), State::Exit);
        assert_eq!(select_work(Some(&work), true), State::Done);
        work.state = WQE_STATE_PENDING;
        work.first_psn = 0xfffffe;
        work.last_psn = 0;
        assert_eq!(select_work(Some(&work), true), State::CheckPsn);
        let mut progress = Completer::zeroed();
        let limits = Limits { retry: 3, rnr: 4 };
        progress.psn = 0xffffff;
        let bytes = packet(0x11, 1, 0, &[])?;
        let wire = Transport::parse(&bytes)?;
        assert_eq!(
            check_psn(&mut progress, limits, &wire, &work),
            State::CompleteWqe
        );
        assert_eq!(progress.retry_cnt, 3);
        assert_eq!(progress.rnr_retry, 4);
        work.mask = WR_ATOMIC_OR_READ_MASK;
        assert_eq!(check_psn(&mut progress, limits, &wire, &work), State::Retry);
        work.state = WQE_STATE_POSTED;
        assert_eq!(check_psn(&mut progress, limits, &wire, &work), State::Done);
        work.state = WQE_STATE_PENDING;
        progress.psn = 1;
        let bytes = packet(0x11, 0, 0, &[])?;
        assert_eq!(
            check_psn(&mut progress, limits, &Transport::parse(&bytes)?, &work),
            State::Done
        );
        work.mask = 0;
        assert_eq!(
            check_psn(&mut progress, limits, &Transport::parse(&bytes)?, &work),
            State::CheckAck
        );
        work.mask = WR_ATOMIC_OR_READ_MASK;
        let bytes = packet(0x11, 0xfffffd, 0, &[])?;
        assert_eq!(
            check_psn(&mut progress, limits, &Transport::parse(&bytes)?, &work),
            State::Done
        );
        progress.opcode = 0x0d;
        assert_eq!(
            check_psn(&mut progress, limits, &Transport::parse(&bytes)?, &work),
            State::Done
        );
        progress.psn = 0xffffff;
        let bytes = packet(0x10, 0xffffff, 0, &[])?;
        update(&mut progress, &Transport::parse(&bytes)?);
        assert_eq!(progress.psn, 0);
        assert_eq!(progress.opcode, -1);
        update(&mut progress, &Transport::parse(&bytes)?);
        assert_eq!(progress.psn, 0);
        Ok(())
    }

    #[test]
    fn delayed_send_ack_does_not_fail_an_outstanding_read() -> Result {
        let (storage, mut snapshots) = queue()?;
        let mut work = snapshots.get(&storage, 0)?;
        work.wr.opcode = IB_WR_RDMA_READ;
        work.mask = super::super::rxe_param::WR_READ_MASK;
        work.state = WQE_STATE_PENDING;
        let mut progress = Completer::zeroed();
        progress.opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST as i32;
        let limits = Limits { retry: 3, rnr: 4 };
        for first in [1u32, 0] {
            work.first_psn = first;
            work.last_psn = first + 1;
            progress.psn = work.last_psn;
            let previous = first.wrapping_sub(1) & 0xffffff;
            let bytes = packet(0x11, previous, AETH_ACK as u8, &[])?;
            assert_eq!(
                check_psn(&mut progress, limits, &Transport::parse(&bytes)?, &work),
                State::Done
            );
            // Error syndromes still enter ACK handling during a read sequence.
            let bytes = packet(0x11, previous, AETH_NAK_REM_ACC_ERR as u8, &[])?;
            assert_eq!(
                check_psn(&mut progress, limits, &Transport::parse(&bytes)?, &work),
                State::CheckAck
            );
            // An ordinary ACK naming this read remains a malformed response.
            let bytes = packet(0x11, first, AETH_ACK as u8, &[])?;
            let wire = Transport::parse(&bytes)?;
            assert_eq!(
                check_psn(&mut progress, limits, &wire, &work),
                State::CheckAck
            );
            assert_eq!(
                check_ack(&mut progress, limits, &wire, &mut work).state,
                State::Error
            );
        }
        Ok(())
    }

    #[test]
    fn acknowledgments_distinguish_retry_events_and_read_sequences() -> Result {
        let (storage, mut snapshots) = queue()?;
        let mut work = snapshots.get(&storage, 0)?;
        let mut progress = Completer::zeroed();
        progress.opcode = -1;
        progress.psn = 0xffffff;
        let limits = Limits { retry: 3, rnr: 4 };
        let bytes = packet(0x11, 0, AETH_NAK_PSN_SEQ_ERROR as u8, &[])?;
        let wire = Transport::parse(&bytes)?;
        let next = check_ack(&mut progress, limits, &wire, &mut work);
        assert_eq!(next.state, State::Retry);
        assert_eq!(next.event, Event::SequenceError);
        assert_eq!(progress.psn, 0);
        assert_eq!(
            check_ack(&mut progress, limits, &wire, &mut work).event,
            Event::None
        );
        let bytes = packet(0x11, 0, AETH_RNR_NAK as u8 | 31, &[])?;
        let next = check_ack(&mut progress, limits, &Transport::parse(&bytes)?, &mut work);
        assert_eq!(next.state, State::RnrRetry(AETH_RNR_NAK as u8 | 31));
        assert_eq!(next.event, Event::ReceiverNotReady);
        for (syndrome, status) in [
            (AETH_NAK_INVALID_REQ, IB_WC_REM_INV_REQ_ERR),
            (AETH_NAK_REM_ACC_ERR, IB_WC_REM_ACCESS_ERR),
            (0x63, IB_WC_REM_OP_ERR),
        ] {
            let bytes = packet(0x11, 0, syndrome as u8, &[])?;
            assert_eq!(
                check_ack(&mut progress, limits, &Transport::parse(&bytes)?, &mut work).state,
                State::Error
            );
            assert_eq!(work.status, status);
        }
        work.wr.opcode = IB_WR_RDMA_READ;
        work.first_psn = 3;
        work.last_psn = 5;
        progress.opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST as i32;
        for (opcode, psn, expected) in [
            (0x0e, 4, State::Read),
            (0x0d, 3, State::Read),
            (0x0d, 4, State::Error),
            (0x12, 4, State::Error),
        ] {
            let bytes = packet(opcode, psn, 0, &[])?;
            assert_eq!(
                check_ack(&mut progress, limits, &Transport::parse(&bytes)?, &mut work).state,
                expected
            );
        }
        assert_eq!(progress.retry_cnt, 3);
        assert_eq!(progress.rnr_retry, 4);
        work.first_psn = 5;
        let bytes = packet(0x10, 5, 0, &[])?;
        assert_eq!(
            check_ack(&mut progress, limits, &Transport::parse(&bytes)?, &mut work).state,
            State::Read
        );
        work.wr.opcode = IB_WR_ATOMIC_WRITE;
        assert_eq!(
            check_ack(&mut progress, limits, &Transport::parse(&bytes)?, &mut work).state,
            State::WriteSend
        );
        Ok(())
    }

    #[test]
    fn retry_budgets_distinguish_duplicate_naks_timeouts_and_infinity() -> Result {
        let (storage, mut snapshots) = queue()?;
        let mut work = snapshots.get(&storage, 0)?;
        let mut progress = Completer::zeroed();
        progress.psn = 0xffffff;
        progress.retry_cnt = 2;
        assert_eq!(retry(&mut progress, 0, &mut work), Retry::Send);
        assert_eq!(progress.retry_cnt, 1);
        assert_eq!(retry(&mut progress, 0, &mut work), Retry::Wait);
        assert_eq!(progress.retry_cnt, 1);
        progress.timeout_retry = true;
        assert_eq!(retry(&mut progress, 0, &mut work), Retry::Send);
        assert_eq!(retry(&mut progress, 0, &mut work), Retry::Exhausted);
        assert_eq!(work.status, IB_WC_RETRY_EXC_ERR);
        progress.retry_cnt = 7;
        progress.rnr_retry = 7;
        for _ in 0..9 {
            assert_eq!(retry(&mut progress, 0, &mut work), Retry::Send);
            assert_eq!(rnr_retry(&mut progress, 0x20, &mut work), Some(655360));
        }
        assert_eq!(progress.retry_cnt, 7);
        assert_eq!(progress.rnr_retry, 7);
        progress.rnr_retry = 1;
        assert_eq!(rnr_retry(&mut progress, 0xff, &mut work), Some(491520));
        assert_eq!(rnr_retry(&mut progress, 0x21, &mut work), None);
        assert_eq!(work.status, IB_WC_RNR_RETRY_EXC_ERR);
        Ok(())
    }

    #[test]
    fn maximum_read_keeps_retry_and_response_progress() -> Result {
        let (storage, mut snapshots) = queue()?;
        let mut work = snapshots.get(&storage, 0)?;
        work.state = WQE_STATE_PENDING;
        work.wr.opcode = IB_WR_RDMA_READ;
        work.mask = super::super::rxe_param::WR_READ_MASK;
        for first in [0u32, 0x800001, 0xffffff] {
            let next = first.wrapping_add(0x800000) & 0xffffff;
            work.first_psn = first;
            work.last_psn = next.wrapping_sub(1) & 0xffffff;
            let mut progress = Completer::zeroed();
            progress.psn = first;
            progress.retry_cnt = 2;
            assert!(progress.has_outstanding(next));
            assert!(!progress.has_outstanding(first));
            assert!(!progress.has_outstanding(next.wrapping_add(1) & 0xffffff));
            assert_eq!(retry(&mut progress, next, &mut work), Retry::Send);
            assert_eq!(progress.retry_cnt, 1);
            progress.timeout_retry = true;
            assert_eq!(retry(&mut progress, next, &mut work), Retry::Send);

            let bytes = packet(0x0d, first, 0, &[])?;
            let wire = Transport::parse(&bytes)?;
            assert!(response_was_requested(&wire, next));
            assert_eq!(
                check_psn(&mut progress, Limits { retry: 2, rnr: 2 }, &wire, &work),
                State::CheckAck
            );
            update(&mut progress, &wire);
            assert_eq!(progress.psn, first.wrapping_add(1) & 0xffffff);
            assert!(progress.has_outstanding(next));

            // After all middle fragments, the inclusive last PSN still completes normally.
            progress.psn = work.last_psn;
            let bytes = packet(0x0f, work.last_psn, 0, &[])?;
            let wire = Transport::parse(&bytes)?;
            assert!(response_was_requested(&wire, next));
            assert_eq!(
                check_psn(&mut progress, Limits { retry: 2, rnr: 2 }, &wire, &work),
                State::CheckAck
            );
            update(&mut progress, &wire);
            assert_eq!(progress.psn, next);
            assert!(!progress.has_outstanding(next));
            let bytes = packet(0x0f, next, 0, &[])?;
            assert!(!response_was_requested(&Transport::parse(&bytes)?, next));
        }
        Ok(())
    }

    #[test]
    fn rejected_response_memory_does_not_advance_private_cursor() -> Result {
        let (storage, mut snapshots) = queue()?;
        let mut work = snapshots.get(&storage, 0)?;
        let original = work.dma;
        let bytes = packet(0x10, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8])?;
        let mut called = false;
        assert_eq!(
            read_response(&Transport::parse(&bytes)?, &mut work, false, 256, |key| {
                called = true;
                assert_eq!(key, 9);
                None
            }),
            State::Error
        );
        assert!(called);
        assert_eq!(work.status, IB_WC_LOC_PROT_ERR);
        assert_eq!(work.dma, original);
        let bytes = packet(0x12, 0, 0, &[])?;
        assert_eq!(
            read_response(&Transport::parse(&bytes)?, &mut work, true, 256, |_| None),
            State::Error
        );
        assert_eq!(work.dma, original);
        work.dma.resid = 0;
        let bytes = packet(0x10, 0, 0, &[])?;
        assert_eq!(
            read_response(
                &Transport::parse(&bytes)?,
                &mut work,
                false,
                256,
                |_| panic!("empty copy looked up MR")
            ),
            State::CompleteAck
        );
        Ok(())
    }

    #[test]
    fn empty_responses_do_not_construct_unused_scatter_cursors() -> Result {
        let storage = Storage::new(1, SEND_HEADER_SIZE as u32, 64)?;
        let mut snapshots = SendSnapshots::new(&storage, SEND_HEADER_SIZE)?;
        let mut work = snapshots.get(&storage, 0)?;
        work.state = WQE_STATE_PENDING;
        work.first_psn = 7;
        work.last_psn = 7;
        for (opcode, length, count) in [
            (IB_WR_FLUSH, 4096, 1),
            (IB_WR_FLUSH, 4096, u32::MAX),
            (IB_WR_RDMA_READ, 0, 0),
        ] {
            work.wr.opcode = opcode;
            work.dma.length = length;
            work.dma.resid = 0;
            work.dma.num_sge = count;
            work.status = IB_WC_SUCCESS;
            let original = work.dma;
            let mut progress = Completer::zeroed();
            progress.opcode = -1;
            let bytes = packet(0x10, 7, 0, &[])?;
            let wire = Transport::parse(&bytes)?;
            assert_eq!(
                check_ack(&mut progress, Limits { retry: 2, rnr: 2 }, &wire, &mut work).state,
                State::Read
            );
            assert_eq!(
                read_response(&wire, &mut work, false, 256, |_| {
                    panic!("empty response accessed a memory region")
                }),
                State::CompleteAck
            );
            assert_eq!(work.dma, original);
            assert_eq!(work.status, IB_WC_SUCCESS);

            // Empty-copy handling must not bypass PSN, fragment or residual checks.
            for (response, psn, resid) in [(0x10, 6, 0), (0x0d, 7, 0), (0x10, 7, 1)] {
                work.dma.resid = resid;
                let bytes = packet(response, psn, 0, &[])?;
                assert_eq!(
                    read_response(&Transport::parse(&bytes)?, &mut work, false, 256, |_| {
                        panic!("invalid response accessed a memory region")
                    }),
                    State::Error
                );
                assert_eq!(work.status, IB_WC_LOC_LEN_ERR);
                assert_eq!(work.dma.resid, resid);
            }
        }
        Ok(())
    }

    #[test]
    fn malformed_read_fragments_and_plain_ack_never_complete_read() -> Result {
        let (storage, mut snapshots) = queue()?;
        let mut work = snapshots.get(&storage, 0)?;
        work.wr.opcode = IB_WR_RDMA_READ;
        work.mask = super::super::rxe_param::WR_READ_MASK;
        work.state = WQE_STATE_PENDING;
        let mut progress = Completer::zeroed();
        progress.opcode = -1;
        let limits = Limits { retry: 3, rnr: 2 };
        for (opcode, psn, last, residual, payload) in [
            (0x0d, 0, 0, 8, 4),
            (0x0d, 0, 1, 512, 128),
            (0x0e, 1, 1, 256, 256),
            (0x0f, 0, 1, 256, 256),
        ] {
            work.last_psn = last;
            work.dma.resid = residual;
            let data = KVec::from_elem(0, payload, GFP_KERNEL)?;
            let bytes = packet(opcode, psn, 0, &data)?;
            assert_eq!(
                read_response(&Transport::parse(&bytes)?, &mut work, false, 256, |_| {
                    panic!("malformed fragment reached memory")
                }),
                State::Error
            );
            assert_eq!(work.dma.resid, residual);
        }
        work.last_psn = 0;
        progress.psn = 1;
        let bytes = packet(0x0d, 0, 0, &[0; 4])?;
        assert_eq!(
            check_psn(&mut progress, limits, &Transport::parse(&bytes)?, &work),
            State::Done
        );
        progress.psn = 0;
        let bytes = packet(0x11, 0, 0, &[])?;
        assert_eq!(
            check_ack(&mut progress, limits, &Transport::parse(&bytes)?, &mut work).state,
            State::Error
        );
        // RNR remains valid for the same outstanding operation.
        let bytes = packet(0x11, 0, AETH_RNR_NAK as u8, &[])?;
        assert!(matches!(
            check_ack(&mut progress, limits, &Transport::parse(&bytes)?, &mut work).state,
            State::RnrRetry(_)
        ));
        work.wr.opcode = IB_WR_ATOMIC_FETCH_AND_ADD;
        work.mask = super::super::rxe_param::WR_ATOMIC_MASK;
        let bytes = packet(0x11, 0, 0, &[])?;
        assert_eq!(
            check_ack(&mut progress, limits, &Transport::parse(&bytes)?, &mut work).state,
            State::Error
        );
        Ok(())
    }
}
