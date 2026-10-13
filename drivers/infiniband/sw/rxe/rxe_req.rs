// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Send work selection, segmentation and retransmission.

#![forbid(unsafe_code)]

use super::{
    rxe_comp::rxe_completer,
    rxe_packet::psn_compare,
    rxe_req_state as policy,
    rxe_send::{
        Progress,
        SendSnapshots,
        SendState,
        SendWqe, //
    }, //
};
use crate::rxe_param::{
    RXE_ATOMIC_WRITE_MASK,
    RXE_MAX_MW_INDEX,
    RXE_MAX_UNACKED_PSNS,
    RXE_MIN_MW_INDEX,
    RXE_READ_OR_ATOMIC_MASK,
    RXE_WRITE_OR_SEND_MASK,
    WQE_STATE_DONE,
    WQE_STATE_ERROR,
    WQE_STATE_POSTED,
    WR_LOCAL_OP_MASK, //
};
use crate::rxe_types::{
    PacketInfo,
    QueuePair, //
};
use kernel::bindings::{
    ib_qp_state_IB_QPS_ERR as IB_QPS_ERR,
    ib_qp_state_IB_QPS_RESET as IB_QPS_RESET,
    ib_qp_state_IB_QPS_SQD as IB_QPS_SQD,
    ib_qp_type_IB_QPT_GSI as IB_QPT_GSI,
    ib_qp_type_IB_QPT_RC as IB_QPT_RC,
    ib_qp_type_IB_QPT_UC as IB_QPT_UC,
    ib_qp_type_IB_QPT_UD as IB_QPT_UD,
    ib_send_flags_IB_SEND_FENCE as IB_SEND_FENCE,
    ib_wc_status_IB_WC_LOC_PROT_ERR as IB_WC_LOC_PROT_ERR,
    ib_wc_status_IB_WC_LOC_QP_OP_ERR as IB_WC_LOC_QP_OP_ERR,
    ib_wc_status_IB_WC_MW_BIND_ERR as IB_WC_MW_BIND_ERR,
    ib_wc_status_IB_WC_SUCCESS as IB_WC_SUCCESS,
    ib_wr_opcode_IB_WR_BIND_MW as IB_WR_BIND_MW,
    ib_wr_opcode_IB_WR_LOCAL_INV as IB_WR_LOCAL_INV,
    ib_wr_opcode_IB_WR_REG_MR as IB_WR_REG_MR,
    IB_OPCODE_UD_SEND_ONLY, //
};
use kernel::{
    prelude::*,
    rdma::AccessFlags,
    sync::atomic::Relaxed, //
};

// The caller exclusively borrows send progress and snapshots from the same mutex.
fn retry(
    queue: &super::rxe_queue::WorkQueue,
    snapshots: &mut SendSnapshots,
    progress: &mut Progress,
    config: &policy::Config,
) -> bool {
    let mut index = snapshots.position();
    progress.req.wqe_index = index as i32;
    progress.req.psn = progress.comp.psn;
    progress.req.opcode = -1;
    let mut first = true;
    for _ in 0..=config.queue_mask {
        let Some(mut wqe) = snapshots.request(queue, index) else {
            break;
        };
        index = index.wrapping_add(1) & config.queue_mask;
        match policy::retry_work(
            &mut progress.req,
            &mut wqe,
            config,
            progress.comp.psn,
            &mut first,
        ) {
            Ok(policy::Replay::Stop) => break,
            Ok(_) => (),
            Err(_) => return false,
        }
    }
    true
}

/// Retains a QP through expiration or cancellation of its timer.
pub(crate) struct ReceiverReady(pub(crate) super::rxe_types::QueuePairRef, pub(crate) u32);
impl kernel::time::timer::Event for ReceiverReady {
    fn expire(self, context: kernel::time::timer::Context<'_>) {
        let qp = &*self.0;
        let mut shared = qp.data().control.state.lock();
        if shared.valid && !shared.resetting && self.1 == shared.generation && !context.is_pending()
        {
            shared.rnr_timeout = true;
            super::rxe_task_ffi::schedule_send(qp);
        }
    }
}

fn check_drained(qp: &QueuePair, progress: &mut Progress, snapshots: &mut SendSnapshots) {
    // State transitions are locked and the live QP pins the callback.
    {
        let mut shared = qp.data().control.state.lock();
        if shared.attributes.qp_state != IB_QPS_SQD || shared.attributes.sq_draining == 0 {
            return;
        }
        let q = qp.data().sq.queue();
        let cons = snapshots.position();
        if progress.req.wqe_index as u32 != cons {
            return;
        }
        if snapshots.pending(q).is_some() {
            let work = snapshots.slot(q, cons);
            if work.state != WQE_STATE_POSTED || work.replaying {
                return;
            }
        }
        shared.attributes.sq_draining = 0;
    }
    super::rxe_task_ffi::defer_event(qp, super::rxe_task_ffi::Event::SendQueueDrained);
}

fn next<'a>(
    qp: &QueuePair,
    progress: &mut Progress,
    snapshots: &'a mut SendSnapshots,
) -> Option<SendWqe<'a>> {
    // Task ownership serializes snapshots. The caller retains the QP for the borrow.
    check_drained(qp, progress, snapshots);
    let mut wqe = snapshots.request(qp.data().sq.queue(), progress.req.wqe_index as u32)?;
    let shared = qp.data().control.state.lock();
    if shared.attributes.qp_state == IB_QPS_SQD && wqe.state == WQE_STATE_POSTED && !wqe.replaying {
        return None;
    }
    wqe.mask = policy::work_mask(qp.kind().encoding(), wqe.wr.opcode);
    Some(wqe)
}

fn init_packet(
    qp: &QueuePair,
    progress: &mut Progress,
    av: &super::rxe_av::AddressVector,
    wqe: &mut SendWqe<'_>,
    config: &policy::Config,
    payload: u32,
    pkt: &mut PacketInfo,
) -> Result<super::rxe_net_tx::TransmitPacket> {
    // The task pins routing inputs and owns the private request. The allocation is
    // owned before native policy borrows its checked transport bytes.
    let length = super::rxe_wire::packet_len(pkt.opcode, payload as usize)?;
    pkt.paylen = u16::try_from(length)?;
    let mut packet = crate::rxe_net_tx::rxe_init_packet(qp, av, config.source_port, length, pkt)?;
    let base = policy::base(&mut progress.req, wqe, config, pkt.opcode);
    let mut wire = packet.initialize(base, payload as usize)?;
    policy::encode(&mut wire, wqe, config)?;
    Ok(packet)
}

fn finish_packet(
    qp: &QueuePair,
    av: &super::rxe_av::AddressVector,
    wqe: &mut SendWqe<'_>,
    pkt: &mut PacketInfo,
    packet: super::rxe_net_tx::TransmitPacket,
    max_inline: usize,
) -> Result<super::rxe_net_tx::PreparedPacket> {
    // The caller pins route and PD inputs and owns the transmit allocation. Native
    // payload operations retain registrations acquired by the immutable PD lookup.
    let mut packet = crate::rxe_route::rxe_prepare(qp, av, pkt, packet)?;
    let pd = qp.data().pd;
    let device = qp.provider();
    policy::fill(&mut packet.transport()?, wqe, max_inline, |key| {
        device.regions.lookup(pd, AccessFlags::default(), key)
    })?;
    Ok(packet)
}

fn update(
    qp: &QueuePair,
    progress: &mut Progress,
    wqe: &mut SendWqe<'_>,
    config: &policy::Config,
    opcode: u8,
    payload: u32,
) {
    // The send task owns requester progress and the private request. The QP
    // reference retains the timer until teardown synchronizes the task and callback.
    policy::update(&mut progress.req, wqe, config, opcode, payload);
    let shared = qp.data().control.state.lock();
    let timeout = shared.traffic.timeout_jiffies;
    if shared.valid && !shared.resetting && timeout != 0 && !qp.data().retrans_timer.is_pending() {
        drop(qp.data().retrans_timer.arm(
            timeout as usize,
            super::rxe_comp::Retransmit(qp.try_ref().unwrap(), shared.generation),
        ));
    }
}

fn local(qp: &QueuePair, progress: &mut Progress, wqe: &mut SendWqe<'_>) -> bool {
    // Each operation validates its keys and registered objects. The current
    // slot remains owned by the send task until the completer consumes it.
    let opcode = wqe.wr.opcode;
    let device = qp.provider();
    let ret = match opcode {
        IB_WR_LOCAL_INV => {
            let key = wqe.wr.invalidate_key();
            if (RXE_MIN_MW_INDEX..=RXE_MAX_MW_INDEX).contains(&(key >> 8)) {
                device
                    .windows
                    .invalidate(qp.data().pd, key)
                    .map_or_else(Error::to_errno, |()| 0)
            } else {
                device
                    .regions
                    .invalidate(qp.data().pd, key)
                    .map_or_else(Error::to_errno, |()| 0)
            }
        }
        IB_WR_REG_MR => wqe
            .registration
            .as_ref()
            .ok_or(EINVAL)
            .and_then(|registration| registration.execute(qp.data().pd))
            .map_or_else(Error::to_errno, |()| 0),
        IB_WR_BIND_MW => {
            let request = wqe.wr.window();
            let memory = if request.length != 0 {
                device
                    .regions
                    .lookup(qp.data().pd, AccessFlags::default(), request.region_key)
            } else {
                None
            };
            device
                .windows
                .bind(super::rxe_qp::QpRef::acquire(qp), memory, request)
                .map_or_else(Error::to_errno, |()| 0)
        }
        _ => EINVAL.to_errno(),
    };
    if ret != 0 {
        wqe.status = if opcode == IB_WR_BIND_MW {
            IB_WC_MW_BIND_ERR
        } else {
            IB_WC_LOC_QP_OP_ERR
        };
        return false;
    }
    wqe.state = WQE_STATE_DONE;
    wqe.status = IB_WC_SUCCESS;
    policy::advance(&mut progress.req, qp.data().sq.queue().mask());
    true
}

fn fail(qp: &QueuePair, progress: &mut Progress, wqe: &mut SendWqe<'_>) -> c_int {
    // The caller supplies the current live slot; QP error serializes
    // the state transition and arranges flushing of the remaining requests.
    {
        policy::advance(&mut progress.req, qp.data().sq.queue().mask());
        wqe.state = WQE_STATE_ERROR;
        crate::rxe_qp::rxe_qp_error(qp);
    }
    EAGAIN.to_errno()
}

/// Advances the send queue by one packet or local operation.
///
/// The send-state mutex supplies the progress and snapshots shared with the completer.
pub(crate) fn rxe_requester(
    qp: &QueuePair,
    progress: &mut Progress,
    snapshots: &mut SendSnapshots,
) -> c_int {
    // Task ownership pins QP resources and serializes both state
    // machines. Temporary AH references are released by their guard.
    let limits = {
        let shared = qp.data().control.state.lock();
        if !shared.valid || shared.attributes.qp_state == IB_QPS_ERR {
            // The completer flushes from the consumer index. Its drain can overtake the
            // requester cursor, which must not capture an already consumed slot again.
            return EAGAIN.to_errno();
        }
        if shared.attributes.qp_state == IB_QPS_RESET {
            progress.req.wqe_index = snapshots.position() as i32;
            progress.req.opcode = -1;
            progress.req.need_rd_atomic = false;
            progress.req.wait_psn = false;
            progress.req.need_retry = false;
            progress.req.wait_for_rnr_timer = false;
            return EAGAIN.to_errno();
        }
        shared.traffic
    };
    let Some(mtu) = core::num::NonZeroU32::new(limits.mtu) else {
        crate::rxe_qp::rxe_qp_error(qp);
        return EAGAIN.to_errno();
    };
    let config = policy::Config {
        kind: qp.kind().encoding(),
        mtu,
        max_sge: qp.data().sq.max_sge as u32,
        max_inline: qp.data().sq.max_inline as usize,
        queue_mask: qp.data().sq.queue().mask(),
        source: qp.identity().number(),
        destination: limits.destination,
        source_port: limits.source_port,
    };
    if progress.req.need_retry && !progress.req.wait_for_rnr_timer {
        if !retry(qp.data().sq.queue(), snapshots, progress, &config) {
            crate::rxe_qp::rxe_qp_error(qp);
            return EAGAIN.to_errno();
        }
        progress.req.need_retry = false;
    }
    let consumer = snapshots.position();
    let Some(mut wqe) = next(qp, progress, snapshots) else {
        return EAGAIN.to_errno();
    };
    if wqe.state == WQE_STATE_DONE {
        // Retry traversal can revisit completed local operations retained behind an
        // unacknowledged request. Only the completer may consume their snapshots.
        policy::advance(&mut progress.req, config.queue_mask);
        return 0;
    }
    if policy::validate_work(&wqe, &config).is_err() {
        wqe.status = IB_WC_LOC_QP_OP_ERR;
        return fail(qp, progress, &mut wqe);
    }
    let fenced = if wqe.wr.opcode == IB_WR_LOCAL_INV {
        progress.req.wqe_index as u32 != consumer
    } else {
        // The fence ordered admission before the original transmission. Waiting
        // again can deadlock on credits held by this request or later requests.
        wqe.state == WQE_STATE_POSTED
            && !wqe.replaying
            && wqe.wr.send_flags & IB_SEND_FENCE as u32 != 0
            && qp.data().read_credits.outstanding() != 0
    };
    if fenced {
        progress.req.wait_fence = true;
        return EAGAIN.to_errno();
    }
    if wqe.mask & WR_LOCAL_OP_MASK != 0 {
        return if local(qp, progress, &mut wqe) {
            0
        } else {
            fail(qp, progress, &mut wqe)
        };
    }
    if qp.kind().encoding() == IB_QPT_RC
        && (psn_compare(
            progress.req.psn,
            progress.comp.psn.wrapping_add(RXE_MAX_UNACKED_PSNS),
        ) > 0
            || !policy::read_fits_window(&wqe, &config, progress.req.psn, progress.comp.psn))
    {
        progress.req.wait_psn = true;
        return EAGAIN.to_errno();
    }
    if qp.data().inflight.should_wait() {
        return EAGAIN.to_errno();
    }
    let opcode = match policy::next_opcode(&progress.req, &wqe, &config) {
        Ok(op) => op,
        Err(_) => {
            wqe.status = IB_WC_LOC_QP_OP_ERR;
            return fail(qp, progress, &mut wqe);
        }
    };
    let mask = super::rxe_opcode::info(opcode as u8).mask;
    if mask & (RXE_READ_OR_ATOMIC_MASK | RXE_ATOMIC_WRITE_MASK) != 0 && wqe.has_rd_atomic == 0 {
        if !progress.req.take_read_credit(&qp.data().read_credits) {
            return EAGAIN.to_errno();
        }
        wqe.has_rd_atomic = 1;
    }
    let mtu = if matches!(qp.kind().encoding(), IB_QPT_RC | IB_QPT_UC) {
        limits.mtu
    } else {
        qp.provider().port.mtu().bytes()
    };
    let mut payload = if mask & (RXE_WRITE_OR_SEND_MASK | RXE_ATOMIC_WRITE_MASK) != 0 {
        wqe.dma.resid
    } else {
        0
    };
    if payload > mtu {
        if matches!(qp.kind().encoding(), IB_QPT_UD | IB_QPT_GSI) {
            wqe.first_psn = progress.req.psn;
            wqe.last_psn = progress.req.psn;
            progress.req.psn = progress.req.psn.wrapping_add(1) & 0xffffff;
            progress.req.opcode = IB_OPCODE_UD_SEND_ONLY as i32;
            policy::advance(&mut progress.req, qp.data().sq.queue().mask());
            wqe.state = WQE_STATE_DONE;
            wqe.status = IB_WC_SUCCESS;
            return 0;
        }
        payload = mtu;
    }
    let mut pkt = PacketInfo::zeroed();

    pkt.opcode = opcode;
    pkt.psn = progress.req.psn;
    pkt.mask = mask;
    let device = qp.provider();
    let Some(av) = qp.data().control.address(
        matches!(qp.kind().encoding(), IB_QPT_RC | IB_QPT_UC),
        &device.addresses,
        qp.data().pd,
        &wqe.wr,
    ) else {
        wqe.status = IB_WC_LOC_QP_OP_ERR;
        return fail(qp, progress, &mut wqe);
    };
    let Ok(skb) = init_packet(qp, progress, &av, &mut wqe, &config, payload, &mut pkt) else {
        wqe.status = IB_WC_LOC_QP_OP_ERR;
        return fail(qp, progress, &mut wqe);
    };
    let packet = match finish_packet(qp, &av, &mut wqe, &mut pkt, skb, config.max_inline) {
        Ok(packet) => packet,
        Err(error) => {
            wqe.status = if error == EFAULT {
                IB_WC_LOC_PROT_ERR
            } else {
                IB_WC_LOC_QP_OP_ERR
            };
            return fail(qp, progress, &mut wqe);
        }
    };
    if crate::rxe_net_tx::rxe_xmit_packet(qp, &pkt, packet) != 0 {
        wqe.status = IB_WC_LOC_QP_OP_ERR;
        return fail(qp, progress, &mut wqe);
    }
    update(qp, progress, &mut wqe, &config, pkt.opcode, payload);
    0
}

/// Runs the requester and completer once in the shared send task.
///
/// The send-state mutex serializes progress, snapshots and queue consumption.
/// Control paths drain the workqueue runtime before calling directly.
pub(crate) fn rxe_sender(qp: &QueuePair) -> c_int {
    // The caller retains the fully initialized native owner and permits sleeping.
    // The state mutex serializes progress, snapshots and queue consumption.
    let send = &qp.data().sq;
    let mut guard = send.state.lock();
    let SendState {
        progress,
        snapshots,
    } = &mut *guard;
    {
        let mut shared = qp.data().control.state.lock();
        if shared.rnr_timeout {
            shared.rnr_timeout = false;
            progress.req.need_retry = true;
            progress.req.wait_for_rnr_timer = false;
        }
    }
    let request = rxe_requester(qp, progress, snapshots);
    // Queries sample a separate atomic field after the requester's exclusive work ends.
    qp.data().send_psn.store(progress.req.psn, Relaxed);
    let complete = rxe_completer(qp, progress, snapshots);
    if request != 0 && complete != 0 {
        EAGAIN.to_errno()
    } else {
        0
    }
}
