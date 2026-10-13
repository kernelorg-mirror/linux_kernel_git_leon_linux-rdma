// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2017 Mellanox Technologies Ltd. All rights reserved.

//! RXE statistics exported through the RDMA core.

#![forbid(unsafe_code)]

use crate::rxe_param as params;
use kernel::{
    prelude::*,
    str::CStr,
    sync::atomic::{
        Atomic,
        Relaxed, //
    },
};

pub(crate) const NUM_COUNTERS: usize = params::RXE_NUM_OF_COUNTERS as usize;
const _: () = assert!(NUM_COUNTERS == 17);

/// Independently sampled atomic counters; this is not a coherent device snapshot.
pub(crate) type Snapshot = [i64; NUM_COUNTERS];

/// Named indices in the existing RDMA statistics ABI.
#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum Counter {
    SentPackets = params::RXE_CNT_SENT_PKTS,
    ReceivedPackets = params::RXE_CNT_RCVD_PKTS,
    DuplicateRequest = params::RXE_CNT_DUP_REQ,
    OutOfSequence = params::RXE_CNT_OUT_OF_SEQ_REQ,
    ReceivedRnr = params::RXE_CNT_RCV_RNR,
    SentRnr = params::RXE_CNT_SND_RNR,
    SequenceError = params::RXE_CNT_RCV_SEQ_ERR,
    SenderScheduled = params::RXE_CNT_SENDER_SCHED,
    RetryExceeded = params::RXE_CNT_RETRY_EXCEEDED,
    RnrRetryExceeded = params::RXE_CNT_RNR_RETRY_EXCEEDED,
    Retry = params::RXE_CNT_COMP_RETRY,
    SendError = params::RXE_CNT_SEND_ERR,
    LinkDown = params::RXE_CNT_LINK_DOWNED,
    RdmaSend = params::RXE_CNT_RDMA_SEND,
    RdmaReceive = params::RXE_CNT_RDMA_RECV,
    SentBytes = params::RXE_CNT_SENT_BYTES,
    ReceivedBytes = params::RXE_CNT_RCVD_BYTES,
}

/// Device-owned statistics, shared with transport engines through immutable borrows.
#[derive(Zeroable)]
pub(crate) struct Counters {
    values: [Atomic<i64>; NUM_COUNTERS],
}

impl Counters {
    pub(crate) fn increment(&self, counter: Counter) {
        self.add(counter, 1);
    }

    pub(crate) fn add(&self, counter: Counter, value: i64) {
        self.values[counter as usize].add(value, Relaxed);
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        core::array::from_fn(|index| self.values[index].load(Relaxed))
    }
}

const NAMES: [&CStr; NUM_COUNTERS] = names();

pub(crate) static STATISTICS: kernel::rdma::Statistics<NUM_COUNTERS> =
    kernel::rdma::Statistics::new(NAMES);

const fn names() -> [&'static CStr; NUM_COUNTERS] {
    let mut names = [c""; NUM_COUNTERS];
    names[params::RXE_CNT_SENT_PKTS as usize] = c"sent_pkts";
    names[params::RXE_CNT_RCVD_PKTS as usize] = c"rcvd_pkts";
    names[params::RXE_CNT_DUP_REQ as usize] = c"duplicate_request";
    names[params::RXE_CNT_OUT_OF_SEQ_REQ as usize] = c"out_of_seq_request";
    names[params::RXE_CNT_RCV_RNR as usize] = c"rcvd_rnr_err";
    names[params::RXE_CNT_SND_RNR as usize] = c"send_rnr_err";
    names[params::RXE_CNT_RCV_SEQ_ERR as usize] = c"rcvd_seq_err";
    names[params::RXE_CNT_SENDER_SCHED as usize] = c"ack_deferred";
    names[params::RXE_CNT_RETRY_EXCEEDED as usize] = c"retry_exceeded_err";
    names[params::RXE_CNT_RNR_RETRY_EXCEEDED as usize] = c"retry_rnr_exceeded_err";
    names[params::RXE_CNT_COMP_RETRY as usize] = c"completer_retry_err";
    names[params::RXE_CNT_SEND_ERR as usize] = c"send_err";
    names[params::RXE_CNT_LINK_DOWNED as usize] = c"link_downed";
    names[params::RXE_CNT_RDMA_SEND as usize] = c"rdma_sends";
    names[params::RXE_CNT_RDMA_RECV as usize] = c"rdma_recvs";
    names[params::RXE_CNT_SENT_BYTES as usize] = c"sent_bytes";
    names[params::RXE_CNT_RCVD_BYTES as usize] = c"rcvd_bytes";
    names
}
