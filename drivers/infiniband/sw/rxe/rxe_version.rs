// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Non-reusable object incarnations and publication versions.

#![forbid(unsafe_code)]

use kernel::{
    prelude::*,
    sync::atomic::{
        Atomic,
        Relaxed, //
    },
};

static NEXT_OBJECT: Atomic<u64> = Atomic::new(0);

fn allocate(counter: &Atomic<u64>) -> Result<u64> {
    let mut current = counter.load(Relaxed);
    loop {
        let next = current.checked_add(1).ok_or(EOVERFLOW)?;
        // Only uniqueness is published here. Each object's ordinary lock publishes its state.
        match counter.cmpxchg(current, next, Relaxed) {
            Ok(_) => return Ok(next),
            Err(actual) => current = actual,
        }
    }
}

/// Names one publication of one object without retaining its allocation.
///
/// Both counters stop at exhaustion. Reusing a pool index or key cannot recreate an old version.
/// Advancing publications is serialized by the owning object's state lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Version {
    object: u64,
    generation: u64,
}

impl Version {
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            object: allocate(&NEXT_OBJECT)?,
            generation: 0,
        })
    }

    pub(super) fn next(self) -> Result<Self> {
        Ok(Self {
            object: self.object,
            generation: self.generation.checked_add(1).ok_or(EOVERFLOW)?,
        })
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_version)]
mod tests {
    use super::*;

    #[test]
    fn object_and_publication_versions_do_not_repeat() -> Result {
        let first = Version::new()?;
        let second = Version::new()?;
        assert_ne!(first, second);
        assert_ne!(first.next()?, second.next()?);
        assert_ne!(first, first.next()?);
        let exhausted = Version {
            object: first.object,
            generation: u64::MAX,
        };
        assert_eq!(exhausted.next(), Err(EOVERFLOW));
        let counter = Atomic::new(u64::MAX - 1);
        assert_eq!(allocate(&counter)?, u64::MAX);
        assert_eq!(allocate(&counter), Err(EOVERFLOW));
        assert_eq!(allocate(&counter), Err(EOVERFLOW));
        assert_eq!(counter.load(Relaxed), u64::MAX);
        Ok(())
    }
}
