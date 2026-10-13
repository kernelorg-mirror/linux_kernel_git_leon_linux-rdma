// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Queue-pair modification, reset and final resource cleanup.

#![forbid(unsafe_code)]

use super::{
    rxe_qp_config::Paths,
    rxe_req::rxe_sender,
    rxe_resp::rxe_receiver, //
};
use crate::rxe_types::{
    QueuePair, //
};
use kernel::bindings::{
    ib_qp_state_IB_QPS_ERR as IB_QPS_ERR,
    ib_qp_state_IB_QPS_RESET as IB_QPS_RESET,
    ib_qp_state_IB_QPS_SQD as IB_QPS_SQD, //
};
use kernel::{
    prelude::*,
    rdma::{
        QueuePairChange,
        QueuePairState, //
    },
    sync::atomic::Relaxed, //
};

// Admission has already been closed and both task runtimes are stopped.
fn reset(qp: &QueuePair) {
    rxe_sender(qp);
    rxe_receiver(qp);
    qp.data().rq.reset();
    qp.data().sq.reset();
    qp.data().read_credits.reset();
}

// A producer which passed admission before RESET or retirement must finish before
// queue storage is reset. New producers recheck admission while holding this lock.
fn synchronize_producers(qp: &QueuePair) {
    drop(qp.data().control.send_producer.lock());
    drop(qp.data().control.receive_producer.lock());
}

/// Enters error state and schedules both tasks to drain their work.
///
/// # Synchronization
///
/// The caller must pin an initialized QP and must not hold its state lock.
pub(crate) fn rxe_qp_error(qp: &QueuePair) {
    // The caller pins the initialized lock and tasks. Publication and
    // scheduling are serialized with all other QP state transitions.
    let mut shared = qp.data().control.state.lock();
    if !shared.valid || shared.resetting || shared.attributes.qp_state == IB_QPS_RESET {
        return;
    }
    shared.attributes.qp_state = IB_QPS_ERR;
    super::rxe_task_ffi::schedule_receive(qp);
    super::rxe_task_ffi::schedule_send(qp);
}

/// Applies validated QP state and transport attributes under the control mutex.
fn apply(qp: &QueuePair, change: &QueuePairChange, paths: Paths) -> Result {
    let control = &qp.data().control;
    // Allocate the only fallible replacement before publishing any state or attributes.
    let resources = change
        .max_destination_read_atomic
        .map(|value| {
            let value = u32::from(value);
            let value = if value == 0 {
                0
            } else {
                value.next_power_of_two()
            };
            super::rxe_replay::Cache::new(value as usize).map(|cache| (value, cache))
        })
        .transpose()?;
    let resetting = change
        .state
        .is_some_and(|state| state.encoding() == IB_QPS_RESET);
    let original = {
        // Delivery and generation changes share this exclusion, including extracted events.
        let mut events = control.events.lock();
        let mut shared = control.state.lock();
        let current = change
            .current_state
            .map_or(shared.attributes.qp_state, |state| state.encoding());
        change.check_transition(QueuePairState::from_encoding(current)?, qp.kind())?;
        if let Some(next) = change.state {
            if current == IB_QPS_SQD
                && shared.attributes.sq_draining != 0
                && !matches!(next.encoding(), IB_QPS_ERR | IB_QPS_RESET)
            {
                return Err(EINVAL);
            }
        }
        let original = shared.attributes.qp_state;
        // RESET closes kernel and packet admission before synchronizing producers.
        if resetting {
            shared.generation = shared.generation.checked_add(1).ok_or(EOVERFLOW)?;
            *events = 0;
            shared.resetting = true;
            shared.attributes.qp_state = IB_QPS_RESET;
            shared.attributes.sq_draining = 0;
            shared.rnr_timeout = false;
            shared.retrans_timeout = false;
        }
        original
    };
    if resetting {
        synchronize_producers(qp);
    }
    // Every engine samples a coherent configuration. Quiesce both before changing
    // private progress, then publish all shared attributes with one state-lock hold.
    qp.data().recv_task.disable();
    qp.data().send_task.disable();
    if resetting {
        drop(qp.data().rnr_nak_timer.cancel());
        drop(qp.data().retrans_timer.cancel());
        reset(qp);
    }
    {
        let mut receive = qp.data().rq.state.lock();
        if let Some((_, resources)) = resources {
            receive.progress.resources = Some(resources);
        }
        if let Some(value) = change.receive_psn {
            receive.progress.psn = value & 0xffffff;
            qp.data().recv_psn.store(receive.progress.psn, Relaxed);
        }
    }
    {
        let mut send = qp.data().sq.state.lock();
        let progress = &mut send.progress;
        if let Some(value) = change.retry {
            progress.comp.retry_cnt = u32::from(value);
        }
        if let Some(value) = change.rnr_retry {
            progress.comp.rnr_retry = u32::from(value);
        }
        if let Some(value) = change.send_psn {
            progress.req.psn = value & 0xffffff;
            qp.data().send_psn.store(progress.req.psn, Relaxed);
            progress.comp.psn = progress.req.psn;
        }
    }
    {
        let mut shared = control.state.lock();
        if let Some(value) = change.max_read_atomic {
            let value = u32::from(value).checked_next_power_of_two().unwrap_or(0);
            let value = if change.max_read_atomic == Some(0) {
                0
            } else {
                value
            };
            shared.traffic.max_rd_atomic = value as u8;
            qp.data().read_credits.set(value);
        }
        if let Some(value) = change.max_destination_read_atomic {
            shared.traffic.max_dest_rd_atomic = if value == 0 {
                0
            } else {
                value.next_power_of_two()
            };
        }
        if let Some(value) = change.draining_notification {
            shared.attributes.en_sqd_async_notify = value;
        }
        if let Some(value) = change.access {
            shared.traffic.access_bits = value.into();
        }
        if let Some(value) = change.pkey_index {
            shared.attributes.pkey_index = value;
        }
        if let Some(value) = change.qkey {
            shared.attributes.qkey = value;
        }
        if let Some(value) = change.port {
            shared.attributes.port_num = value;
        }
        if let Some(vector) = paths.primary {
            shared.primary = vector;
        }
        if let Some(vector) = paths.alternate {
            let alternate = change.alternate.as_ref().unwrap();
            shared.alternate = vector;
            shared.attributes.alt_port_num = alternate.port;
            shared.attributes.alt_pkey_index = alternate.pkey_index;
            shared.attributes.alt_timeout = alternate.timeout;
        }
        if let Some(value) = change.path_mtu {
            shared.traffic.path_mtu = value;
            shared.traffic.mtu = 128u32 << value;
        }
        if let Some(value) = change.timeout {
            shared.traffic.timeout = value;
            shared.traffic.timeout_jiffies = if value == 0 {
                0
            } else {
                kernel::time::nsecs_to_jiffies(4096u64 << value).max(1) as u64
            };
        }
        if let Some(value) = change.min_rnr_timer {
            shared.traffic.min_rnr_timer = value;
        }
        if let Some(value) = change.retry {
            shared.traffic.retry = value;
        }
        if let Some(value) = change.rnr_retry {
            shared.traffic.rnr = value;
        }
        if let Some(value) = change.migration_state {
            shared.attributes.path_mig_state = value;
        }
        if let Some(value) = change.destination {
            shared.traffic.destination = value;
        }
        if let Some(vector) = paths.primary {
            shared.traffic.source_port =
                qp.udp_source_port(vector.grh.flow_label, shared.traffic.destination);
        }
        if let Some(next) = change.state {
            // A concurrent link failure may have forced ERR while tasks stopped.
            // Do not resurrect it by publishing an earlier activation request.
            if resetting || shared.attributes.qp_state != IB_QPS_ERR || original == IB_QPS_ERR {
                shared.attributes.qp_state = next.encoding();
                if next.encoding() == IB_QPS_SQD {
                    shared.attributes.sq_draining = 1;
                }
            }
        }
    }
    if resetting {
        control.state.lock().resetting = false;
    }
    qp.data().recv_task.enable();
    qp.data().send_task.enable();
    // Enqueueing while either task was stopped could not reserve an invocation.
    super::rxe_task_ffi::schedule_receive(qp);
    super::rxe_task_ffi::schedule_send(qp);
    Ok(())
}

/// Stops admission and asynchronous owners before the core waits for QP references.
pub(crate) fn retire(qp: &QueuePair) {
    let data = qp.data();
    if data.gsi {
        qp.provider()
            .port
            .release_gsi(core::num::NonZero::new(data.index).unwrap());
    }
    qp.provider().pairs.unpublish(data.index);
    {
        let mut events = data.control.events.lock();
        let mut shared = data.control.state.lock();
        *events = 0;
        shared.valid = false;
        shared.traffic.timeout_jiffies = 0;
    }
    synchronize_producers(qp);
    drop(data.retrans_timer.shutdown());
    drop(data.rnr_nak_timer.shutdown());
    // Admission is closed before waiting for workers. Client producer indices cannot
    // keep an otherwise live requester or responder running during retirement.
    data.send_task.stop();
    data.recv_task.stop();
    // Networking may retain transmitted packets indefinitely, for example in NFQUEUE.
    // Revoke their QP events after stopping producers, before waiting for native references.
    data.sq.completions.shutdown();
    // Both task runtimes are permanently stopped and admission is closed. Flushing
    // releases packet references before core draining, while the core still owns the QP.
    rxe_sender(qp);
    rxe_receiver(qp);
    // Type-2 windows retain QP references. The stopped sender cannot create another
    // binding, so release existing bindings before the core waits for those references.
    qp.provider().windows.unbind_qp(data.index);
}

pub(crate) fn modify(qp: &QueuePair, change: QueuePairChange) -> Result {
    let _operation = qp.data().control.operation.lock();
    let paths = super::rxe_qp_config::check_change(
        &change,
        matches!(
            qp.kind(),
            kernel::rdma::QueuePairType::ReliableConnected
                | kernel::rdma::QueuePairType::UnreliableConnected
        ),
    )?;
    let result = apply(qp, &change, paths);
    drop(_operation);
    super::rxe_task_ffi::dispatch_events(qp);
    result
}

pub(crate) fn query(qp: &QueuePair) -> Result<kernel::rdma::QueuePairQuery> {
    use super::rxe_qp_config::{
        Capacity,
        QueueCapacity, //
    };
    let data = qp.data();
    let _operation = data.control.operation.lock();
    let capacity = Capacity {
        send: QueueCapacity {
            work_requests: data.sq.max_wr as u32,
            scatter_gather: data.sq.max_sge as u32,
        },
        receive: qp.shared_receive().is_none().then_some(QueueCapacity {
            work_requests: data.rq.max_wr as u32,
            scatter_gather: data.rq.max_sge as u32,
        }),
        inline: data.sq.max_inline as u32,
    };
    let attributes = data.control.query(
        capacity,
        data.recv_psn.load(Relaxed),
        data.send_psn.load(Relaxed),
    );
    Ok(kernel::rdma::QueuePairQuery {
        attributes,
        creation_port: 1,
    })
}

/// A native QP reference retained by a window binding or multicast membership.
pub(super) struct QpRef {
    reference: super::rxe_types::QueuePairRef,
}

impl QpRef {
    pub(super) fn acquire(qp: &QueuePair) -> Self {
        Self {
            reference: qp.try_ref().expect("live QP reference"),
        }
    }
    pub(super) fn index(&self) -> u32 {
        self.reference.data().index
    }
    pub(super) fn pd(&self) -> u32 {
        self.reference.data().pd
    }
}
