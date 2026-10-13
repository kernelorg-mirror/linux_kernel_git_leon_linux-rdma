// SPDX-License-Identifier: GPL-2.0

//! Ownership of dynamically allocated workqueues with immediate submission.

use super::{
    Queue,
    RawWorkItem, //
};
use crate::{
    alloc::{
        AllocError,
        Flags, //
    },
    bindings,
    prelude::*, //
};
use core::ptr::NonNull;

/// Owns an unbound workqueue and drains its immediate work before releasing it.
///
/// Creation and destruction may sleep. Owners must arrange to drop the queue outside its
/// own work callbacks and without locks needed by those callbacks. Submission may run with
/// interrupts disabled. A borrow prevents destruction during a submission, and destruction
/// waits for previously submitted work to finish.
///
/// This type deliberately exposes no delayed submission or borrowed [`Queue`]: a timer can
/// retain a delayed workqueue pointer after `destroy_workqueue()` has returned.
///
/// # Invariants
///
/// `queue` is an exclusively owned, live unbound workqueue. Only immediate work is submitted
/// through it, and ownership is released exactly once by `Drop`.
pub struct OwnedQueue {
    queue: NonNull<bindings::workqueue_struct>,
}

// SAFETY: The workqueue has no thread-affine owner and its C implementation synchronizes access.
unsafe impl Send for OwnedQueue {}
// SAFETY: Shared access submits work through the C workqueue's internal synchronization.
unsafe impl Sync for OwnedQueue {}

impl OwnedQueue {
    /// Maximum supported number of active work items.
    pub const MAX_ACTIVE: u32 = bindings::wq_consts_WQ_MAX_ACTIVE;

    /// Allocates an unbound queue, using the kernel default concurrency when `max_active` is zero.
    ///
    /// The name is copied during allocation and is not interpreted as a format string.
    /// Values above [`Self::MAX_ACTIVE`] are rejected before calling the C allocator.
    #[inline]
    pub fn new_unbound(name: &CStr, max_active: u32) -> Result<Self> {
        if max_active > Self::MAX_ACTIVE {
            return Err(EINVAL);
        }
        // SAFETY: The constant format has exactly one string conversion, supplied by a valid
        // NUL-terminated name which the allocator copies. The flags and concurrency are valid.
        let queue = unsafe {
            bindings::alloc_workqueue_noprof(
                c"%s".as_char_ptr(),
                bindings::wq_flags_WQ_UNBOUND,
                max_active as c_int,
                name.as_char_ptr(),
            )
        };
        // INVARIANT: A non-null result transfers unique ownership of an empty unbound queue.
        Ok(Self {
            queue: NonNull::new(queue).ok_or(ENOMEM)?,
        })
    }

    #[inline]
    fn queue(&self) -> &Queue {
        // SAFETY: The invariant retains the allocation for this borrow. Keeping this accessor
        // private prevents callers from submitting delayed work through the borrowed API.
        unsafe { Queue::from_raw(self.queue.as_ptr()) }
    }

    /// Submits immediate work, preserving its pointer type's duplicate-submission behavior.
    #[inline]
    pub fn enqueue<W, const ID: u64>(&self, work: W) -> W::EnqueueOutput
    where
        W: RawWorkItem<ID> + Send + 'static,
    {
        self.queue().enqueue(work)
    }

    /// Allocates and submits a closure for immediate execution.
    #[inline]
    pub fn try_spawn<T: 'static + Send + FnOnce()>(
        &self,
        flags: Flags,
        function: T,
    ) -> Result<(), AllocError> {
        self.queue().try_spawn(flags, function)
    }
}

impl Drop for OwnedQueue {
    fn drop(&mut self) {
        // SAFETY: Unique ownership and the exclusive drop borrow exclude concurrent external
        // submissions. No delayed work can retain a timer-side pointer. The C destructor
        // drains pending callbacks before releasing the queue's allocation.
        unsafe { bindings::destroy_workqueue(self.queue.as_ptr()) };
    }
}

#[cfg(CONFIG_RUST_KUNIT_TESTS)]
#[crate::macros::kunit_tests(rust_owned_workqueue)]
mod tests {
    use super::*;
    use crate::sync::atomic::{
        Atomic,
        Relaxed, //
    };

    #[test]
    fn release_drains_submitted_work() -> Result {
        static FINISHED: Atomic<u32> = Atomic::new(0);
        FINISHED.store(0, Relaxed);
        let queue = OwnedQueue::new_unbound(c"rust_owned_wq%", 1)?;
        for _ in 0..64 {
            queue.try_spawn(GFP_KERNEL, || {
                FINISHED.fetch_add(1, Relaxed);
            })?;
        }
        drop(queue);
        assert_eq!(FINISHED.load(Relaxed), 64);
        Ok(())
    }
}
