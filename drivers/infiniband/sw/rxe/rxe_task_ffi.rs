// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Native QP references retained only by admitted task invocations.

#![forbid(unsafe_code)]

use crate::{
    rxe_task::{
        Runner,
        Runtime,
        State, //
    },
    rxe_types::{
        QueuePair,
        QueuePairRef, //
    }, //
};
use kernel::{
    prelude::*,
    workqueue::OwnedQueue, //
};

/// Idle runtimes own no reference back to their enclosing QP.
pub(crate) struct Task {
    runtime: Pin<KBox<Runtime>>,
}

impl Task {
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            runtime: KBox::pin_init(Runtime::new()?, GFP_KERNEL)?,
        })
    }

    pub(super) fn disable(&self) {
        self.runtime.drain(State::Drained);
    }

    pub(super) fn enable(&self) {
        self.runtime.enable();
    }

    pub(super) fn stop(&self) {
        self.runtime.drain(State::Invalid);
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Send,
    Receive,
}

/// A queued invocation retains native state and the core's immutable parent shadows.
#[derive(Clone)]
pub(super) struct Execution {
    qp: QueuePairRef,
    kind: Kind,
}

impl Execution {
    pub(super) fn runtime(&self) -> &Runtime {
        match self.kind {
            Kind::Send => &self.qp.data().send_task.runtime,
            Kind::Receive => &self.qp.data().recv_task.runtime,
        }
    }

    pub(super) fn dispatch_events(&self) {
        dispatch_events(&self.qp);
    }

    pub(super) fn queue(&self) -> &OwnedQueue {
        &self.qp.provider().get_ref().workqueue
    }
}

pub(super) fn step(runner: &mut Runner) -> c_int {
    let execution = runner.execution();
    // Runner serializes transport execution and the owned reference retains all
    // native state and parents until the invocation returns.
    match execution.kind {
        Kind::Send => super::rxe_req::rxe_sender(&execution.qp),
        Kind::Receive => super::rxe_resp::rxe_receiver(&execution.qp),
    }
}

fn schedule(qp: &QueuePair, kind: Kind) {
    if let Some(qp) = qp.try_ref() {
        let execution = Execution { qp, kind };
        execution.runtime().schedule(&execution);
    }
}

pub(super) fn schedule_send(qp: &QueuePair) {
    schedule(qp, Kind::Send);
}

pub(super) fn schedule_receive(qp: &QueuePair) {
    schedule(qp, Kind::Receive);
}

/// Events are delivered only after engine locks and execution authority are released.
#[derive(Clone, Copy)]
pub(super) enum Event {
    SendQueueDrained = 1,
    AccessError = 2,
    LastReceiveCompleted = 4,
}

pub(super) fn defer_event(qp: &QueuePair, event: Event) {
    let control = &qp.data().control;
    let mut events = control.events.lock();
    let shared = control.state.lock();
    if shared.valid
        && !shared.resetting
        && shared.attributes.qp_state != kernel::bindings::ib_qp_state_IB_QPS_RESET
    {
        *events |= event as u32;
    }
}

pub(super) fn dispatch_events(qp: &QueuePair) {
    let control = &qp.data().control;
    // Serialize extracting and queueing events against reset. The native callbacks run later
    // without this lock, so they may modify the QP without recursively acquiring it.
    let mut pending = control.events.lock();
    let events = core::mem::replace(&mut *pending, 0);
    {
        let shared = control.state.lock();
        if !shared.valid
            || shared.resetting
            || shared.attributes.qp_state == kernel::bindings::ib_qp_state_IB_QPS_RESET
        {
            return;
        }
    }
    for (bit, event) in [
        (
            Event::SendQueueDrained,
            kernel::rdma::QueuePairEvent::SendQueueDrained,
        ),
        (
            Event::AccessError,
            kernel::rdma::QueuePairEvent::AccessError,
        ),
        (
            Event::LastReceiveCompleted,
            kernel::rdma::QueuePairEvent::LastReceiveCompleted,
        ),
    ] {
        if events & bit as u32 != 0 {
            // Counted delivery allocates no storage here; only counter overflow can fail.
            let _ = qp.event(event);
        }
    }
}
