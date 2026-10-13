// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Cyclic identities for native RXE objects.

#![forbid(unsafe_code)]

use kernel::{
    id_pool::IdPool,
    prelude::*, //
};

/// Allocates within an inclusive range while enforcing a separate live-object limit.
///
/// Owners serialize access with their creation mutex and release each identity after its
/// object has drained. Allocation may sleep while growing the bitmap; transport lookups must
/// use separate synchronization and never hold an IRQ lock across this operation.
pub(super) struct Identities {
    ids: IdPool,
    first: u32,
    last: u32,
    next: u32,
    count: u32,
    limit: u32,
}

impl Identities {
    pub(super) fn new(first: u32, last: u32, limit: u32) -> Self {
        assert!(first <= last && u64::from(limit) <= u64::from(last) - u64::from(first) + 1);
        Self {
            ids: IdPool::new(),
            first,
            last,
            next: 0,
            count: 0,
            limit,
        }
    }

    pub(super) fn allocate(&mut self) -> Result<u32> {
        if self.count == self.limit {
            return Err(EINVAL);
        }
        let last = self.last - self.first;
        loop {
            // Search both cyclic segments before allocating a larger bitmap. The bitmap
            // API requires a start strictly below capacity even when no free bit exists.
            for start in [self.next as usize, 0] {
                if start >= self.ids.capacity() {
                    continue;
                }
                if let Some(id) = self.ids.find_unused_id(start) {
                    if id.as_u32() <= last {
                        let index = id.acquire() as u32;
                        self.next = if index == last { 0 } else { index + 1 };
                        self.count += 1;
                        return Ok(self.first + index);
                    }
                }
            }
            if self.ids.capacity() <= last as usize {
                let request = self.ids.grow_request().ok_or(ENOSPC)?;
                self.ids.grow(request.realloc(GFP_KERNEL)?);
            } else {
                self.next = 0;
            }
        }
    }

    pub(super) fn release(&mut self, number: u32) {
        self.ids.release_id((number - self.first) as usize);
        self.count -= 1;
    }
}

impl Drop for Identities {
    fn drop(&mut self) {
        kernel::warn_on!(self.count != 0);
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_id)]
mod tests {
    use super::*;

    #[test]
    fn released_ids_are_reused_without_bitmap_growth() -> Result {
        let mut ids = Identities::new(1, 1 << 20, 1 << 20);
        let capacity = ids.ids.capacity();
        for _ in 0..4 * capacity {
            let id = ids.allocate()?;
            ids.release(id);
            assert_eq!(ids.ids.capacity(), capacity);
        }
        Ok(())
    }
}
