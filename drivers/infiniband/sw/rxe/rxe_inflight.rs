// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Packet accounting and requester wakeups without a separate wait-flag race.

#![forbid(unsafe_code)]

use super::rxe_param::{
    RXE_INFLIGHT_SKBS_PER_QP_HIGH,
    RXE_INFLIGHT_SKBS_PER_QP_LOW, //
};
use kernel::{
    prelude::*,
    sync::atomic::{
        Atomic,
        Relaxed, //
    },
};

const WAITING: u64 = 1 << 63;
const COUNT: u64 = !WAITING;

/// Counts packets handed to networking and records requester backpressure.
///
/// Each installed packet destructor pairs one `start` with one `finish`.
/// The count and wait flag share an atomic value: a requester cannot publish a
/// stale wait after the final packet release. No other memory is published here,
/// so relaxed ordering suffices; the scheduler provides execution synchronization.
#[derive(Zeroable)]
pub(crate) struct Inflight {
    state: Atomic<u64>,
}

impl Inflight {
    /// Accounts for one packet before its destructor can run.
    pub(crate) fn start(&self) {
        self.state.fetch_add(1, Relaxed);
    }

    /// Returns whether the requester should yield for packet releases.
    pub(crate) fn should_wait(&self) -> bool {
        let mut state = self.state.load(Relaxed);
        loop {
            let count = state & COUNT;
            let wait = count > u64::from(RXE_INFLIGHT_SKBS_PER_QP_HIGH);
            let next = count | if wait { WAITING } else { 0 };
            match self.state.cmpxchg(state, next, Relaxed) {
                Ok(_) => return wait,
                Err(current) => state = current,
            }
        }
    }

    /// Releases one packet and returns whether to schedule the requester.
    pub(crate) fn finish(&self) -> bool {
        let mut state = self.state.load(Relaxed);
        loop {
            let count = (state & COUNT) - 1;
            let wake = state & WAITING != 0 && count < u64::from(RXE_INFLIGHT_SKBS_PER_QP_LOW);
            let next = count | if wake { 0 } else { state & WAITING };
            match self.state.cmpxchg(state, next, Relaxed) {
                Ok(_) => return wake,
                Err(current) => state = current,
            }
        }
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_inflight)]
mod tests {
    use super::*;

    #[test]
    fn wake_once_below_low_watermark() {
        let flights = Inflight::zeroed();
        assert!(!flights.should_wait());
        for _ in 0..RXE_INFLIGHT_SKBS_PER_QP_HIGH {
            flights.start();
        }
        assert!(!flights.should_wait());
        flights.start();
        assert!(flights.should_wait());
        // Replies can add packets while the requester waits.
        flights.start();
        for _ in RXE_INFLIGHT_SKBS_PER_QP_LOW..RXE_INFLIGHT_SKBS_PER_QP_HIGH + 2 {
            assert!(!flights.finish());
        }
        assert!(flights.finish());
        for _ in 1..RXE_INFLIGHT_SKBS_PER_QP_LOW {
            assert!(!flights.finish());
        }
        assert!(!flights.should_wait());
        assert_eq!(flights.state.load(Relaxed), 0);
    }

    #[test]
    fn release_before_wait_does_not_strand_requester() {
        let flights = Inflight::zeroed();
        for _ in 0..=RXE_INFLIGHT_SKBS_PER_QP_HIGH {
            flights.start();
        }
        // No wait was published when networking released the packets.
        for _ in 0..=RXE_INFLIGHT_SKBS_PER_QP_HIGH {
            assert!(!flights.finish());
        }
        assert!(!flights.should_wait());
        flights.start();
        assert!(!flights.finish());
        assert_eq!(flights.state.load(Relaxed), 0);
    }
}
