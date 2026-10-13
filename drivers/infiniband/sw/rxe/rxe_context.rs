// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Admission accounting for core-owned userspace contexts.

#![forbid(unsafe_code)]

use super::rxe_version::Version;
use kernel::{
    prelude::*,
    sync::atomic::{
        Atomic,
        Relaxed, //
    }, //
};

/// Native identity used to authorize pending queue mappings.
pub(crate) struct Context {
    identity: Version,
}

impl Context {
    pub(crate) fn new() -> Result<KBox<Self>> {
        Ok(KBox::new(
            Self {
                identity: Version::new()?,
            },
            GFP_KERNEL,
        )?)
    }

    pub(super) fn identity(&self) -> Version {
        self.identity
    }
}

/// Counts contexts admitted until the core invokes their final release callback.
///
/// Contexts have no RXE lookup index or asynchronous pool references. The RDMA core owns their
/// lifetime; this counter enforces the device limit without allocating unused XArray entries.
pub(crate) struct Contexts {
    count: Atomic<u32>,
    limit: u32,
}

impl Contexts {
    pub(crate) const fn new(limit: u32) -> Self {
        Self {
            count: Atomic::new(0),
            limit,
        }
    }

    /// Reserves one admission. A successful call must have one matching release.
    pub(crate) fn acquire(&self) -> Result {
        let mut count = self.count.load(Relaxed);
        loop {
            if count >= self.limit {
                return Err(EINVAL);
            }
            match self.count.cmpxchg(count, count + 1, Relaxed) {
                Ok(_) => return Ok(()),
                Err(current) => count = current,
            }
        }
    }

    /// Returns one admission when the core destroys a successfully created context.
    pub(crate) fn release(&self) {
        self.count.fetch_sub(1, Relaxed);
    }
}

impl Drop for Contexts {
    fn drop(&mut self) {
        kernel::warn_on!(self.count.load(Relaxed) != 0);
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_context)]
mod tests {
    use super::*;

    #[test]
    fn limit_and_reuse() {
        let contexts = Contexts::new(2);
        assert_eq!(contexts.acquire(), Ok(()));
        assert_eq!(contexts.acquire(), Ok(()));
        for _ in 0..16 {
            assert_eq!(contexts.acquire(), Err(EINVAL));
        }
        contexts.release();
        assert_eq!(contexts.acquire(), Ok(()));
        assert_eq!(contexts.acquire(), Err(EINVAL));
        contexts.release();
        contexts.release();
        assert_eq!(contexts.acquire(), Ok(()));
        contexts.release();
    }
}
