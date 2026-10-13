// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Kernel work-request publication and userspace send doorbells.

#![forbid(unsafe_code)]

use super::{
    rxe_device::DeviceData,
    rxe_submission::Limits,
    rxe_task_ffi::{
        schedule_receive,
        schedule_send, //
    },
    rxe_types::QueuePair, //
};
use kernel::{
    bindings,
    prelude::*,
    rdma::{
        ReceiveRequests,
        SendRequests, //
    }, //
};

fn ready(qp: &QueuePair, minimum: u32) -> bool {
    let shared = qp.data().control.state.lock();
    shared.valid && !shared.resetting && shared.attributes.qp_state >= minimum
}

pub(crate) fn ring(qp: &QueuePair) -> Result {
    if !ready(qp, bindings::ib_qp_state_IB_QPS_RTS) {
        return Err(EINVAL);
    }
    schedule_send(qp);
    Ok(())
}

pub(crate) fn send(qp: &QueuePair, requests: SendRequests<'_, DeviceData>) -> Result {
    let sq = &qp.data().sq;
    let limits = Limits {
        kind: qp.kind().encoding(),
        max_sge: sq.max_sge as usize,
        max_inline: sq.max_inline as usize,
    };
    let mut good = false;
    let result = {
        let mut producer = qp.data().control.send_producer.lock();
        if !ready(qp, bindings::ib_qp_state_IB_QPS_RTS) {
            return requests.reject(EINVAL);
        }
        requests.try_for_each(|request| {
            producer.post_send(sq.queue(), &qp.provider().regions, request, &limits)?;
            good = true;
            Ok(())
        })
    };
    if good {
        schedule_send(qp);
    }
    result
}

pub(crate) fn receive(qp: &QueuePair, requests: ReceiveRequests<'_>) -> Result {
    if qp.shared_receive().is_some() {
        return requests.reject(EINVAL);
    }
    let rq = &qp.data().rq;
    let result = {
        let mut producer = qp.data().control.receive_producer.lock();
        if !ready(qp, bindings::ib_qp_state_IB_QPS_INIT) {
            return requests.reject(EINVAL);
        }
        requests.try_for_each(|request| {
            producer.post_receive(rq.queue.as_ref().unwrap(), request, rq.max_sge as usize)
        })
    };
    let shared = qp.data().control.state.lock();
    if shared.attributes.qp_state == bindings::ib_qp_state_IB_QPS_ERR {
        schedule_receive(qp);
    }
    result
}
