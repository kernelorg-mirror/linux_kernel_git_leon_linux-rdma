// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Receive state machine, completion generation and replay selection.

#![forbid(unsafe_code)]

use super::rxe_hw_counters::Counter;
use super::{
    rxe_completion::{
        Record, //
    },
    rxe_packet::{
        transport, //
        Packet,    //
    },
    rxe_resp_check::{
        self as admission,
        Protocol, //
    },
    rxe_resp_data::{
        self as data,
        Reply,
        SendError, //
    },
    rxe_resp_state::Responder, //
};
use crate::rxe_param::{
    AETH_ACK_UNLIMITED,
    AETH_NAK_PSN_SEQ_ERROR,
    AETH_RNR_NAK,
    AETH_TYPE_MASK,
    RXE_AETH_MASK,
    RXE_ATMACK_MASK,
    RXE_ATOMIC_WRITE_MASK,
    RXE_MAX_MW_INDEX,
    RXE_MIN_MW_INDEX,
    RXE_READ_OR_ATOMIC_MASK,
    RXE_RWR_MASK, //
};
use crate::rxe_types::{
    PacketInfo,
    QueuePair,
    ResponderState, //
};
use kernel::bindings::{
    ib_qp_state_IB_QPS_ERR as IB_QPS_ERR,
    ib_qp_state_IB_QPS_RESET as IB_QPS_RESET,
    ib_qp_type_IB_QPT_RC as IB_QPT_RC,
    ib_qp_type_IB_QPT_UC as IB_QPT_UC,
    ib_wc_status_IB_WC_SUCCESS as IB_WC_SUCCESS,
    ib_wc_status_IB_WC_WR_FLUSH_ERR as IB_WC_WR_FLUSH_ERR, //
};
use kernel::{
    bindings,
    prelude::*,
    rdma::Access, //
    sync::atomic::{
        Relaxed, //
    }, //
};

/// Enqueues a validated request and transfers its receive references.
///
/// Admission and enqueue share the state lock with the final retirement flush.
pub(crate) fn rxe_resp_queue_pkt(qp: &QueuePair, packet: Packet) {
    // The packet retains the QP and its queue owners. Admission and enqueue hold the
    // same state lock as retirement, excluding packets arriving after the final flush.
    let shared = qp.data().control.state.lock();
    if !shared.valid
        || shared.resetting
        || packet.context().generation != shared.generation
        || shared.attributes.qp_state < bindings::ib_qp_state_IB_QPS_RTR
        || shared.attributes.qp_state == IB_QPS_ERR
    {
        return;
    }
    qp.data().rq.packets.push(packet);
    super::rxe_task_ffi::schedule_receive(qp);
}

const _: () = assert!(size_of::<bindings::rxe_recv_wqe>() == super::rxe_wqe::RECV_HEADER_SIZE);
const _: () = assert!(size_of::<bindings::rxe_sge>() == super::rxe_wqe::SGE_SIZE);
const _: () = assert!(size_of::<bindings::ib_sge>() == super::rxe_wqe::SGE_SIZE);
const _: () = assert!(
    core::mem::offset_of!(bindings::rxe_recv_wqe, dma)
        + core::mem::offset_of!(bindings::rxe_dma_info, num_sge)
        == super::rxe_wqe::NUM_SGE_OFFSET
);

fn srq_work(qp: &QueuePair, progress: &mut Responder) -> ResponderState {
    // The core retains the SRQ through synchronous QP destruction. The QP
    // reference excludes that destruction; the receive task exclusively owns its snapshot.
    // Native SRQ locking protects selection and arming, and event delivery follows unlocking.
    let core = qp.shared_receive().unwrap();
    let srq = qp.shared_receive_data().unwrap();
    let (work, notify) = match srq.receive(core.has_event_handler()) {
        Some(work) => work,
        None => return ResponderState::ErrRnr,
    };
    if notify {
        // The SRQ owns queued delivery independently of this QP's RESET or retirement.
        let _ = core.event(kernel::rdma::SharedReceiveEvent::LimitReached);
    }
    let work = match work {
        Ok(work) => work,
        Err(failure) => {
            progress.memory.as_mut().unwrap().receive = failure.completion();
            return ResponderState::ErrMalformedWqe;
        }
    };
    progress.memory.as_mut().unwrap().receive = Some(work);
    ResponderState::ChkLength
}

/// Obtains receive work or checks responder read/atomic capacity.
///
/// # Synchronization
///
/// The caller must own the serialized receive task and pin the QP and its
/// initialized receive queue, or its referenced SRQ.
fn check_resource(
    qp: &QueuePair,
    progress: &mut Responder,
    mask: u32,
    max_dest_rd_atomic: u8,
) -> ResponderState {
    // The receive task owns the private snapshot and RQ consumer.
    if mask & (RXE_READ_OR_ATOMIC_MASK | RXE_ATOMIC_WRITE_MASK) != 0 {
        return if max_dest_rd_atomic > 0 {
            ResponderState::ChkLength
        } else {
            ResponderState::ErrTooManyRdmaAtmReq
        };
    }
    if mask & RXE_RWR_MASK != 0 {
        if qp.shared_receive().is_some() {
            return srq_work(qp, progress);
        }
        return progress.capture_receive(
            qp.data().rq.queue.as_ref().unwrap(),
            qp.data().rq.max_sge as u32,
        );
    }
    ResponderState::ChkLength
}

// The caller pins the QP and packet data and owns the serialized receive task.
// This boundary reads immutable QP identity and network state, never responder state.
fn transmit_reply(qp: &QueuePair, reply: Reply<'_>) -> core::result::Result<(), SendError> {
    // The receive task retains the QP and its route throughout allocation and handoff.
    // The reply contains only copied fields and a registration borrow covering payload copying.
    let prepare = || -> Result<_> {
        let (av, config) = {
            let shared = qp.data().control.state.lock();
            (shared.primary, shared.traffic)
        };
        let mut ack = PacketInfo::zeroed();
        let length = super::rxe_wire::packet_len(reply.opcode, reply.payload_len() as usize)?;
        let mut packet =
            crate::rxe_net_tx::rxe_init_packet(qp, &av, config.source_port, length, &mut ack)?;
        ack.opcode = reply.opcode;
        ack.mask = super::rxe_opcode::info(reply.opcode).mask;
        ack.paylen = u16::try_from(length)?;
        ack.psn = reply.psn;
        let mut wire = packet.initialize(
            super::rxe_wire::Base {
                opcode: reply.opcode,
                psn: reply.psn,
                qpn: config.destination,
                solicited: false,
                ack: false,
            },
            reply.payload_len() as usize,
        )?;
        if ack.mask & RXE_AETH_MASK != 0 {
            wire.set(super::rxe_wire::Extension::Acknowledge {
                syndrome: reply.syndrome,
                sequence: reply.sequence,
            })?;
        }
        if ack.mask & RXE_ATMACK_MASK != 0 {
            wire.set(super::rxe_wire::Extension::AtomicReply(
                reply.original.ok_or(EINVAL)?,
            ))?;
        }
        let packet = crate::rxe_route::rxe_prepare(qp, &av, &mut ack, packet)?;
        Ok((ack, packet))
    };
    let (ack, mut packet) = prepare().map_err(|_| SendError::Packet)?;
    if reply.payload_len() != 0 {
        let mut wire = packet.transport().map_err(|_| SendError::Memory)?;
        reply
            .copy_payload(wire.payload().map_err(|_| SendError::Memory)?)
            .map_err(|_| SendError::Memory)?;
    }
    data::output_result(crate::rxe_net_tx::rxe_xmit_packet(qp, &ack, packet))
}

// The receive task retains the QP and exclusively owns its reply sequence.
fn send_ack(qp: &QueuePair, msn: u32, syndrome: u8, psn: u32) {
    // Reply construction copies protocol fields before network handoff.
    let reply = Reply::acknowledge(msn, syndrome, psn);
    let _ = transmit_reply(qp, reply);
}

// All helpers run under the serialized receive task with its QP reference.

fn complete(
    qp: &QueuePair,
    progress: &mut Responder,
    mut pkt: Option<&mut Packet>,
) -> ResponderState {
    // The responder owns a private receive-work snapshot. It reads
    // packet fields only for successful work, which has a validated packet.
    let device = qp.provider();
    let counters = &device.counters;
    if let Some(wqe) = progress.memory.as_ref().unwrap().receive.as_ref() {
        let status = progress.status;
        let mut cqe = Record::error(wqe.id(), status);
        if status == IB_WC_SUCCESS {
            let network = pkt.as_ref().unwrap().context().network;
            let Ok(wire) = transport(pkt.as_deref_mut().unwrap()) else {
                return ResponderState::ErrLength;
            };
            let port = qp.data().control.state.lock().attributes.port_num;
            let Ok(entry) =
                Record::receive(wqe, progress.memory.as_ref().unwrap().length, port, &wire)
            else {
                return ResponderState::ErrLength;
            };
            cqe = entry;
            counters.increment(Counter::RdmaReceive);
            if !qp.receive_completion_data().is_user() {
                cqe.network = Some(network);
            }
        } else if status != IB_WC_WR_FLUSH_ERR {
            pr_err!(
                "qp#{} non-flush error status = {}\n",
                qp.identity().number(),
                status
            );
        }
        if qp.shared_receive().is_none() {
            progress
                .consumer
                .advance(qp.data().rq.queue.as_ref().unwrap());
        }
        progress.memory.as_mut().unwrap().receive = None;
        let solicited = pkt
            .as_deref_mut()
            .is_none_or(|packet| transport(packet).is_ok_and(|wire| wire.solicited()));
        if qp
            .receive_completion_data()
            .post(qp.receive_completion(), qp.identity(), &cqe, solicited)
            .is_err()
        {
            return ResponderState::ErrCqOverflow;
        }
    }
    {
        let shared = qp.data().control.state.lock();
        if shared.attributes.qp_state == IB_QPS_ERR {
            // Consume an already executed packet once; subsequent work is
            // flushed by the entry path, never with this packet's payload.
            return if pkt.is_none() {
                ResponderState::ChkResource
            } else {
                ResponderState::Cleanup
            };
        }
    }
    if pkt.is_none() {
        ResponderState::Done
    } else if qp.kind().encoding() == IB_QPT_RC {
        ResponderState::Acknowledge
    } else {
        ResponderState::Cleanup
    }
}

fn cleanup(progress: &mut Responder, packet: &mut Option<Packet>) -> ResponderState {
    drop(packet.take());
    progress.finish_request();
    ResponderState::Done
}

fn flush(qp: &QueuePair, progress: &mut Responder, packet: &mut Option<Packet>, mut notify: bool) {
    // The receive task is the sole request/RQ consumer; control paths
    // drain it before resetting storage. No state lock spans packet drops or callbacks.
    drop(packet.take());
    while let Some(packet) = qp.data().rq.packets.pop() {
        drop(packet);
    }
    // A partial operation must not retain its MR after entering error or reset.
    progress.finish_request();
    if qp.shared_receive().is_some() {
        // SRQ selection already consumed this entry from the shared queue. Complete the
        // private snapshot before reporting that this QP has no outstanding receive work.
        if let Some(wqe) = progress.memory.as_mut().unwrap().receive.take() {
            if notify {
                let cqe = Record::error(wqe.id(), IB_WC_WR_FLUSH_ERR);
                let _ = qp.receive_completion_data().post(
                    qp.receive_completion(),
                    qp.identity(),
                    &cqe,
                    false,
                );
            }
        }
        if notify {
            super::rxe_task_ffi::defer_event(qp, super::rxe_task_ffi::Event::LastReceiveCompleted);
        }
        return;
    }
    let Some(q) = qp.data().rq.queue.as_ref() else {
        return;
    };
    let mut pending = progress.memory.as_mut().unwrap().receive.take();
    for _ in 0..=q.mask() {
        let Some(id) = pending
            .take()
            .map(|wqe| wqe.id())
            .or_else(|| progress.consumer.receive_id(q))
        else {
            break;
        };
        progress.consumer.advance(q);
        if notify {
            let cqe = Record::error(id, IB_WC_WR_FLUSH_ERR);
            if qp
                .receive_completion_data()
                .post(qp.receive_completion(), qp.identity(), &cqe, false)
                .is_err()
            {
                notify = false;
            }
        }
    }
}

/// Processes one request or one read-response segment.
///
/// The receive-state mutex serializes progress, queued packets and replay storage.
/// Control paths drain the workqueue runtime before calling directly.
pub(crate) fn rxe_receiver(qp: &QueuePair) -> c_int {
    // The caller retains the fully initialized native owner and permits sleeping.
    // The state mutex serializes progress, the current packet and queue consumption.
    let receive = &qp.data().rq;
    let mut guard = receive.state.lock();
    let super::rxe_queue::ReceiveState {
        progress,
        packet: pkt,
    } = &mut *guard;
    let device = qp.provider();
    let counters = &device.counters;
    let windows = &device.windows;
    let qp_index = qp.data().index;
    let config = {
        let shared = qp.data().control.state.lock();
        if !shared.valid || matches!(shared.attributes.qp_state, IB_QPS_ERR | IB_QPS_RESET) {
            let notify = shared.valid && shared.attributes.qp_state == IB_QPS_ERR;
            drop(shared);
            flush(qp, progress, pkt, notify);
            return EAGAIN.to_errno();
        }
        shared.traffic
    };
    progress.aeth_syndrome = AETH_ACK_UNLIMITED as u8;
    let protocol = match qp.kind().encoding() {
        IB_QPT_RC => Protocol::Reliable,
        IB_QPT_UC => Protocol::Unreliable,
        _ => Protocol::Datagram,
    };
    let mut state = ResponderState::GetReq;
    loop {
        state = match state {
            ResponderState::GetReq => {
                if pkt.is_none() {
                    *pkt = receive.packets.pop();
                }
                if pkt.is_none() {
                    ResponderState::Exit
                } else if progress
                    .resources
                    .as_ref()
                    .is_none_or(|cache| !cache.active())
                {
                    ResponderState::ChkPsn
                } else {
                    ResponderState::ReadReply
                }
            }
            ResponderState::ChkPsn => {
                let next = admission::check_psn(
                    protocol,
                    pkt.as_ref().unwrap().context().psn,
                    progress.psn,
                    pkt.as_ref().unwrap().context().mask,
                    &mut progress.sent_psn_nak,
                    &mut progress.drop_msg,
                );
                match next {
                    ResponderState::ErrPsnOutOfSeq => counters.increment(Counter::OutOfSequence),
                    ResponderState::DuplicateRequest => {
                        counters.increment(Counter::DuplicateRequest)
                    }
                    _ => (),
                }
                next
            }
            ResponderState::ChkOpSeq => {
                let next = admission::check_sequence(
                    protocol,
                    progress.opcode,
                    pkt.as_ref().unwrap().context().opcode,
                );
                if next == ResponderState::Cleanup {
                    progress.drop_msg = true;
                }
                next
            }
            ResponderState::ChkResource => check_resource(
                qp,
                progress,
                pkt.as_ref().unwrap().context().mask,
                config.max_dest_rd_atomic,
            ),
            ResponderState::ChkOpValid | ResponderState::ChkLength | ResponderState::ChkRkey => {
                match transport(pkt.as_mut().unwrap()) {
                    Err(_) => ResponderState::ErrLength,
                    Ok(wire) => match state {
                        ResponderState::ChkOpValid => {
                            let next = admission::check_operation(protocol, config.access(), &wire);
                            if next == ResponderState::Cleanup {
                                progress.drop_msg = true;
                            }
                            next
                        }
                        ResponderState::ChkLength => admission::check_length(
                            protocol,
                            &wire,
                            config.mtu,
                            progress.memory.as_ref().unwrap().receive.as_ref(),
                        ),
                        _ => {
                            // Lookup borrows only immutable QP identity and its registries;
                            // neither closure accesses the exclusively borrowed request state.
                            let pd = qp.data().pd;
                            admission::check_key(
                                progress.memory.as_mut().unwrap(),
                                &wire,
                                config.mtu,
                                |access, key| device.regions.lookup(pd, access, key),
                                |access, key| windows.lookup(pd, qp_index, key, access),
                            )
                        }
                    },
                }
            }
            ResponderState::Execute
            | ResponderState::ReadReply
            | ResponderState::AtomicReply
            | ResponderState::AtomicWriteReply
            | ResponderState::ProcessFlush
            | ResponderState::Acknowledge => {
                let header = (protocol == Protocol::Datagram && state == ResponderState::Execute)
                    .then(|| super::rxe_packet::grh(pkt.as_ref().unwrap()))
                    .transpose();
                match (header, transport(pkt.as_mut().unwrap())) {
                    (Err(_), _) | (_, Err(_)) => ResponderState::ErrLength,
                    (Ok(header), Ok(wire)) => {
                        // Each callback accesses only the QP's identity, registries or network
                        // resources. The serialized receive task exclusively borrows resp.
                        let pd = qp.data().pd;
                        let mtu = config.mtu;
                        let next = match state {
                            ResponderState::Execute => data::execute(
                                progress,
                                &wire,
                                protocol,
                                header.as_ref(),
                                |key| device.regions.lookup(pd, Access::LocalWrite.into(), key),
                                |key| {
                                    if (RXE_MIN_MW_INDEX..=RXE_MAX_MW_INDEX).contains(&(key >> 8)) {
                                        windows.invalidate(pd, key)
                                    } else {
                                        device.regions.invalidate(pd, key)
                                    }
                                },
                            ),
                            ResponderState::ReadReply => data::read_reply(
                                progress,
                                &wire,
                                mtu,
                                |key| device.regions.lookup(pd, Access::RemoteRead.into(), key),
                                |key| windows.lookup(pd, qp_index, key, Access::RemoteRead.into()),
                                |reply| transmit_reply(qp, reply),
                            ),
                            ResponderState::AtomicReply => data::atomic_reply(progress, &wire, mtu),
                            ResponderState::AtomicWriteReply => {
                                data::atomic_write_reply(progress, &wire, mtu)
                            }
                            ResponderState::ProcessFlush => {
                                data::process_flush(progress, &wire, mtu)
                            }
                            _ => data::acknowledge(progress, &wire, protocol, |reply| {
                                transmit_reply(qp, reply)
                            }),
                        };
                        // Publish only a scalar query snapshot after the exclusive borrow
                        // ends. Queries never access the task-owned responder itself.
                        qp.data().recv_psn.store(progress.psn, Relaxed);
                        next
                    }
                }
            }
            ResponderState::Complete => complete(qp, progress, pkt.as_mut()),
            ResponderState::Cleanup => cleanup(progress, pkt),
            ResponderState::DuplicateRequest => match transport(pkt.as_mut().unwrap()) {
                Ok(wire) => match progress.replay(&wire) {
                    super::rxe_resp_state::Replay::Acknowledge(psn) => {
                        send_ack(qp, progress.msn, AETH_ACK_UNLIMITED as u8, psn);
                        ResponderState::Cleanup
                    }
                    super::rxe_resp_state::Replay::Continue(next) => next,
                },
                Err(_) => ResponderState::Cleanup,
            },
            ResponderState::ErrPsnOutOfSeq => {
                send_ack(qp, progress.msn, AETH_NAK_PSN_SEQ_ERROR as u8, progress.psn);
                ResponderState::Cleanup
            }
            ResponderState::ErrRnr => {
                if qp.kind().encoding() == IB_QPT_RC {
                    counters.increment(Counter::SentRnr);
                    let syndrome =
                        AETH_RNR_NAK | (u32::from(config.min_rnr_timer) & !AETH_TYPE_MASK);
                    send_ack(
                        qp,
                        progress.msn,
                        syndrome as u8,
                        pkt.as_ref().unwrap().context().psn,
                    );
                } else {
                    progress.drop_msg = true;
                }
                ResponderState::Cleanup
            }
            ResponderState::ErrRkeyViolationEvent => {
                if qp.kind().encoding() == IB_QPT_RC {
                    super::rxe_task_ffi::defer_event(qp, super::rxe_task_ffi::Event::AccessError);
                }
                ResponderState::ErrRkeyViolation
            }
            ResponderState::ErrTooManyRdmaAtmReq
            | ResponderState::ErrMissingOpcodeFirst
            | ResponderState::ErrMissingOpcodeLastC
            | ResponderState::ErrUnsupportedOpcode
            | ResponderState::ErrMisalignedAtomic
            | ResponderState::ErrMissingOpcodeLastD1E
            | ResponderState::ErrRkeyViolation
            | ResponderState::ErrInvalidateRkey
            | ResponderState::ErrLength
            | ResponderState::ErrMalformedWqe => {
                progress.recover(state, protocol, qp.shared_receive().is_some())
            }
            ResponderState::ErrCqOverflow => ResponderState::Error,
            ResponderState::Done | ResponderState::Exit => {
                if progress.goto_error {
                    ResponderState::Error
                } else {
                    return if state == ResponderState::Done {
                        0
                    } else {
                        EAGAIN.to_errno()
                    };
                }
            }
            _ => {
                progress.goto_error = false;
                crate::rxe_qp::rxe_qp_error(qp);
                return EAGAIN.to_errno();
            }
        };
    }
}
