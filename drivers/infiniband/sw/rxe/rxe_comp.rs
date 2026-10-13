// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Send completion, acknowledgment sequencing and retry control.

#![forbid(unsafe_code)]

use super::rxe_hw_counters::Counter;
use super::{
    rxe_comp_state::{
        self as policy,
        Event,
        Limits,
        Retry,
        State, //
    },
    rxe_send::{
        Progress,
        SendSnapshots, //
    }, //
};
use super::{
    rxe_completion::{
        Record,
        SendCompletion, //
    },
    rxe_packet::{
        transport,
        Packet, //
    }, //
};
use crate::rxe_param::{
    WQE_STATE_PENDING,
    WQE_STATE_POSTED, //
};
use crate::rxe_types::{
    QueuePair, //
};
use kernel::bindings::{
    ib_qp_state_IB_QPS_ERR as IB_QPS_ERR,
    ib_qp_state_IB_QPS_RESET as IB_QPS_RESET,
    ib_qp_state_IB_QPS_RTS as IB_QPS_RTS,
    ib_qp_state_IB_QPS_SQD as IB_QPS_SQD,
    ib_qp_type_IB_QPT_RC as IB_QPT_RC,
    ib_wc_status_IB_WC_SUCCESS as IB_WC_SUCCESS,
    ib_wc_status_IB_WC_WR_FLUSH_ERR as IB_WC_WR_FLUSH_ERR,
    ib_wr_opcode_IB_WR_SEND as IB_WR_SEND,
    ib_wr_opcode_IB_WR_SEND_WITH_IMM as IB_WR_SEND_WITH_IMM,
    ib_wr_opcode_IB_WR_SEND_WITH_INV as IB_WR_SEND_WITH_INV, //
};
use kernel::{
    prelude::*,
    rdma::Access, //
};

/// Retains a QP through expiration or cancellation of its timer.
pub(crate) struct Retransmit(pub(crate) super::rxe_types::QueuePairRef, pub(crate) u32);
impl kernel::time::timer::Event for Retransmit {
    fn expire(self, context: kernel::time::timer::Context<'_>) {
        let qp = &*self.0;
        let mut shared = qp.data().control.state.lock();
        if shared.valid && !shared.resetting && self.1 == shared.generation && !context.is_pending()
        {
            shared.retrans_timeout = true;
            super::rxe_task_ffi::schedule_send(qp);
        }
    }
}

/// Queues a validated response and schedules the send task.
///
/// Admission and enqueue share the state lock with the final retirement flush.
pub(crate) fn rxe_comp_queue_pkt(qp: &QueuePair, packet: Packet) {
    // The packet retains the queue and task. Admission and enqueue share the same
    // state lock as retirement, preventing a delayed receiver from enqueueing after flushing.
    let shared = qp.data().control.state.lock();
    if !shared.valid
        || shared.resetting
        || packet.context().generation != shared.generation
        || shared.attributes.qp_state < IB_QPS_RTS
        || shared.attributes.qp_state == IB_QPS_ERR
    {
        return;
    }
    let device = qp.provider();
    let counters = &device.counters;
    counters.increment(Counter::SenderScheduled);
    qp.data().sq.packets.push(packet);
    super::rxe_task_ffi::schedule_send(qp);
}

// The serialized send task owns completion and retry state throughout these
// helpers. Packet inputs are validated and completed records no longer borrow their slots.
fn complete(qp: &QueuePair, progress: &mut Progress, completed: SendCompletion) {
    // The send task retains the QP and its completion queue. Native completion data
    // was captured before consuming the request; client reuse cannot change this record.
    let device = qp.provider();
    let counters = &device.counters;
    let SendCompletion {
        opcode,
        status,
        record,
    } = completed;
    if status != IB_WC_SUCCESS && status != IB_WC_WR_FLUSH_ERR {
        pr_err!(
            "qp#{} non-flush error status = {}\n",
            qp.identity().number(),
            status
        );
    }
    if let Some(cqe) = record.as_ref() {
        let _ = qp
            .send_completion_data()
            .post(qp.send_completion(), qp.identity(), cqe, false);
    }
    if matches!(
        opcode,
        IB_WR_SEND | IB_WR_SEND_WITH_IMM | IB_WR_SEND_WITH_INV
    ) {
        counters.increment(Counter::RdmaSend);
    }
    progress.req.wake_fence();
}

fn check_drained(qp: &QueuePair, progress: &mut Progress) {
    // State changes are locked; the QP remains pinned while its event
    // callback runs outside the state lock, as required by RDMA event callbacks.
    {
        let mut shared = qp.data().control.state.lock();
        if shared.attributes.qp_state != IB_QPS_SQD
            || shared.attributes.sq_draining == 0
            || progress.comp.psn != progress.req.psn
        {
            return;
        }
        shared.attributes.sq_draining = 0;
    }
    super::rxe_task_ffi::defer_event(qp, super::rxe_task_ffi::Event::SendQueueDrained);
}

fn drain(qp: &QueuePair, progress: &mut Progress, snapshots: &mut SendSnapshots, mut notify: bool) {
    // The caller pins the QP and serializes the send task. Control paths
    // drain this task before resetting its storage. No state lock spans callbacks.
    let send = &qp.data().sq;
    while let Some(packet) = send.packets.pop() {
        drop(packet);
    }
    for _ in 0..=send.queue().mask() {
        let Some(cqe) = snapshots.head(send.queue()).map(|mut wqe| {
            progress.release_credit(&mut wqe, &qp.data().read_credits);
            Record::error(wqe.wr.wr_id.clone(), IB_WC_WR_FLUSH_ERR)
        }) else {
            break;
        };
        snapshots.consume(qp.data().sq.queue());
        if notify {
            if qp
                .send_completion_data()
                .post(qp.send_completion(), qp.identity(), &cqe, false)
                .is_err()
            {
                notify = false;
            }
        }
    }
}

fn reset_timer(qp: &QueuePair, progress: &mut Progress) {
    // The live QP owns the timer. State locking serializes rearming
    // with the state change that precedes timer shutdown during destruction.
    let shared = qp.data().control.state.lock();
    let timeout = shared.traffic.timeout_jiffies;
    if qp.kind().encoding() != IB_QPT_RC || timeout == 0 {
        return;
    }
    if shared.valid
        && !shared.resetting
        && shared.attributes.qp_state >= IB_QPS_RTS
        && progress.comp.has_outstanding(progress.req.psn)
    {
        drop(qp.data().retrans_timer.arm(
            timeout as usize,
            super::rxe_comp::Retransmit(qp.try_ref().unwrap(), shared.generation),
        ));
    }
}

// Returns true after consuming an ACK, false when the task should yield unless
// the requester was explicitly woken. The caller serializes the send task.
fn run(qp: &QueuePair, progress: &mut Progress, snapshots: &mut SendSnapshots) -> bool {
    // Task ownership pins the QP, queues and timers. A response guard
    // releases all receive ownership regardless of the state-machine exit.
    let device = qp.provider();
    let counters = &device.counters;
    let config = {
        let mut shared = qp.data().control.state.lock();
        if !shared.valid || matches!(shared.attributes.qp_state, IB_QPS_ERR | IB_QPS_RESET) {
            let notify = shared.valid && shared.attributes.qp_state == IB_QPS_ERR;
            drop(shared);
            drain(qp, progress, snapshots, notify);
            return false;
        }
        progress.comp.timeout_retry = shared.retrans_timeout;
        shared.retrans_timeout = false;
        shared.traffic
    };
    if progress.req.need_retry {
        return false;
    }
    let mut pkt = qp.data().sq.packets.pop();
    if pkt.is_some() {
        progress.comp.timeout_retry = false;
    }
    let queue = qp.data().sq.queue();
    let signal_all = qp.signals_all_sends();
    let mut selected = None;
    let mut state = State::GetWqe;
    loop {
        // Each state borrows the current slot only until this iteration ends. Completing
        // it releases that borrow before the consumer permits the producer to reuse it.
        // Keep the selected index until completion, even if userspace withdraws publication.
        if matches!(state, State::GetWqe) {
            selected = snapshots.pending(queue);
        }
        let mut wqe = selected.map(|index| snapshots.slot(queue, index));
        state = match state {
            State::GetWqe => policy::select_work(wqe.as_ref(), pkt.is_some()),
            State::CheckPsn | State::CheckAck | State::Read | State::Atomic => {
                match transport(pkt.as_mut().unwrap()) {
                    Err(_) => State::Error,
                    Ok(wire) => {
                        let limits = Limits {
                            retry: config.retry,
                            rnr: config.rnr,
                        };
                        match state {
                            State::CheckPsn => {
                                if policy::response_was_requested(&wire, progress.req.psn) {
                                    policy::check_psn(
                                        &mut progress.comp,
                                        limits,
                                        &wire,
                                        wqe.as_ref().unwrap(),
                                    )
                                } else {
                                    State::Done
                                }
                            }
                            State::CheckAck => {
                                let next = policy::check_ack(
                                    &mut progress.comp,
                                    limits,
                                    &wire,
                                    wqe.as_mut().unwrap(),
                                );
                                match next.event {
                                    Event::None => (),
                                    Event::ReceiverNotReady => {
                                        counters.increment(Counter::ReceivedRnr)
                                    }
                                    Event::SequenceError => {
                                        counters.increment(Counter::SequenceError);
                                        progress.req.wake_psn();
                                    }
                                }
                                next.state
                            }
                            _ => {
                                let pd = qp.data().pd;
                                policy::read_response(
                                    &wire,
                                    wqe.as_mut().unwrap(),
                                    state == State::Atomic,
                                    config.mtu,
                                    |key| device.regions.lookup(pd, Access::LocalWrite.into(), key),
                                )
                            }
                        }
                    }
                }
            }
            State::WriteSend => {
                let wqe = wqe.as_ref().unwrap();
                if wqe.state == WQE_STATE_PENDING
                    && wqe.last_psn == pkt.as_ref().unwrap().context().psn
                {
                    State::CompleteAck
                } else {
                    State::Update
                }
            }
            State::CompleteAck => {
                let next = progress.acknowledge(
                    wqe.as_mut().unwrap(),
                    &qp.data().read_credits,
                    pkt.as_ref().unwrap().context().psn,
                );
                check_drained(qp, progress);
                let completed = SendCompletion::new(wqe.unwrap(), signal_all);
                snapshots.consume(queue);
                selected = None;
                complete(qp, progress, completed);
                next
            }
            State::CompleteWqe => {
                progress.release_credit(wqe.as_mut().unwrap(), &qp.data().read_credits);
                progress.complete_pending(wqe.as_ref().unwrap(), pkt.is_some());
                let completed = SendCompletion::new(wqe.unwrap(), signal_all);
                snapshots.consume(queue);
                selected = None;
                complete(qp, progress, completed);
                State::GetWqe
            }
            State::Update => match transport(pkt.as_mut().unwrap()) {
                Err(_) => State::Error,
                Ok(wire) => {
                    policy::update(&mut progress.comp, &wire);
                    progress.req.wake_psn();
                    State::Done
                }
            },
            State::Done => return true,
            State::Exit => {
                if progress.comp.timeout_retry && wqe.is_some() {
                    State::Retry
                } else {
                    reset_timer(qp, progress);
                    return false;
                }
            }
            State::Retry => {
                if wqe.as_ref().is_none_or(|wqe| wqe.state == WQE_STATE_POSTED) {
                    return false;
                }
                match policy::retry(&mut progress.comp, progress.req.psn, wqe.as_mut().unwrap()) {
                    Retry::Wait => return true,
                    Retry::Send => {
                        counters.increment(Counter::Retry);
                        progress.req.need_retry = true;
                        progress.req.again = true;
                        return true;
                    }
                    Retry::Exhausted => {
                        counters.increment(Counter::RetryExceeded);
                        State::Error
                    }
                }
            }
            State::RnrRetry(syndrome) => {
                if let Some(usecs) =
                    policy::rnr_retry(&mut progress.comp, syndrome, wqe.as_mut().unwrap())
                {
                    progress.req.wait_for_rnr_timer = true;
                    let delay = kernel::time::usecs_to_jiffies(usecs).max(1);
                    let mut shared = qp.data().control.state.lock();
                    if !shared.valid || shared.resetting {
                        return false;
                    }
                    shared.rnr_timeout = false;
                    drop(qp.data().rnr_nak_timer.arm(
                        delay,
                        super::rxe_req::ReceiverReady(qp.try_ref().unwrap(), shared.generation),
                    ));
                    return false;
                }
                counters.increment(Counter::RnrRetryExceeded);
                State::Error
            }
            State::Error => {
                if let Some(work) = wqe.as_mut() {
                    progress.release_credit(work, &qp.data().read_credits);
                    if work.status == IB_WC_SUCCESS {
                        work.status = kernel::bindings::ib_wc_status_IB_WC_BAD_RESP_ERR;
                    }
                }
                let completed = SendCompletion::new(wqe.unwrap(), signal_all);
                snapshots.consume(queue);
                complete(qp, progress, completed);
                crate::rxe_qp::rxe_qp_error(qp);
                return false;
            }
        };
    }
}

/// Processes one response or advances the oldest send work request.
///
/// The send-state mutex supplies the progress and snapshots shared with the requester.
pub(crate) fn rxe_completer(
    qp: &QueuePair,
    progress: &mut Progress,
    snapshots: &mut SendSnapshots,
) -> c_int {
    // The caller serializes task state and pins all QP resources.
    progress.req.again = false;
    let done = run(qp, progress, snapshots);
    let result = if done || progress.req.again {
        0
    } else {
        EAGAIN.to_errno()
    };
    progress.req.again = false;
    result
}
