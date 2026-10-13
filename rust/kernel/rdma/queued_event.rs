// SPDX-License-Identifier: GPL-2.0

//! Deferred object events whose callbacks drain before native destruction.

use crate::{
    bindings,
    prelude::*,
    sync::{
        Arc,
        SpinLockIrq, //
    },
    workqueue::{
        self,
        Work,
        WorkItem, //
    }, //
};
use core::ptr::NonNull;

const EVENT_TYPES: usize = bindings::ib_event_type_IB_EVENT_DEVICE_SPEED_CHANGE as usize + 1;
const BATCH: usize = 64;

struct Pending {
    counts: [u64; EVENT_TYPES],
    next: usize,
    scheduled: bool,
    draining: bool,
    owner: Option<NonNull<Events>>,
}

impl Pending {
    fn take(&mut self) -> Option<bindings::ib_event_type> {
        let index = (0..EVENT_TYPES)
            .map(|offset| (self.next + offset) % EVENT_TYPES)
            .find(|&index| self.counts[index] != 0)?;
        self.counts[index] -= 1;
        self.next = (index + 1) % EVENT_TYPES;
        Some(index as bindings::ib_event_type)
    }
}

/// Callback state retained independently until every queued invocation has returned.
#[pin_data]
pub(super) struct Events {
    event: bindings::ib_event,
    handler: Option<unsafe extern "C" fn(*mut bindings::ib_event, *mut c_void)>,
    context: *mut c_void,
    workqueue: NonNull<bindings::workqueue_struct>,
    #[pin]
    queue: SpinLockIrq<Pending>,
    #[pin]
    work: Work<Self>,
}

// SAFETY: The callback state is immutable. Native destruction retains the target, callback and
// context until every counted invocation has returned and drain() completes.
unsafe impl Send for Events {}
// SAFETY: Shared queue access is locked, and cancellation joins executing work before drainage.
// Callback state is immutable and native handlers accept delivery from sleepable task context.
unsafe impl Sync for Events {}

impl Events {
    /// # Safety
    ///
    /// The event must identify stable native target and device storage. Before releasing
    /// that storage or the callback/context, the owner must exclude further posts and drain
    /// every queued invocation. The handler and context must remain immutable until then.
    pub(super) unsafe fn new(
        event: bindings::ib_event,
        handler: Option<unsafe extern "C" fn(*mut bindings::ib_event, *mut c_void)>,
        context: *mut c_void,
    ) -> Result<Arc<Self>> {
        // SAFETY: The caller retains the callback state through drainage. The system queue
        // remains initialized throughout this allocation's lifetime.
        unsafe {
            Self::new_on_queue(
                event,
                handler,
                context,
                NonNull::new_unchecked(bindings::system_dfl_wq),
            )
        }
    }

    /// # Safety
    ///
    /// The callback state must satisfy new()'s contract. The queue must stay initialized
    /// until this control has drained for the final time and no further posts are possible.
    unsafe fn new_on_queue(
        event: bindings::ib_event,
        handler: Option<unsafe extern "C" fn(*mut bindings::ib_event, *mut c_void)>,
        context: *mut c_void,
        workqueue: NonNull<bindings::workqueue_struct>,
    ) -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(Self {
                event,
                handler,
                context,
                workqueue,
                queue <- crate::new_spinlock_irq!(Pending {
                    counts: [0; EVENT_TYPES], next: 0, scheduled: false,
                    draining: false, owner: None,
                }),
                work <- workqueue::new_work!("rdma_object_event"),
            }),
            GFP_KERNEL_ACCOUNT,
        )
    }

    fn enqueue(self: &Arc<Self>, queue: &mut Pending) {
        let owner = Arc::into_raw(self.clone());
        // Retain the original ownership pointer for cancellation, rather than rebuilding
        // ownership from a shared reference to the control.
        queue.owner = NonNull::new(owner.cast_mut());
        // SAFETY: The pointer owns one Arc reference. Its initialized work uses the Arc
        // callback, which recovers that reference on execution. The locked scheduled/draining
        // state excludes duplicate submissions and submissions during cancellation.
        let queued = unsafe {
            bindings::queue_work_on(
                bindings::wq_misc_consts_WORK_CPU_UNBOUND as c_int,
                self.workqueue.as_ptr(),
                Work::raw_get(&raw const (*owner).work),
            )
        };
        if !queued {
            queue.owner = None;
            // SAFETY: A rejected enqueue did not consume the transferred Arc reference.
            unsafe { drop(Arc::from_raw(owner)) };
        }
        debug_assert!(queued);
    }

    pub(super) fn post(self: &Arc<Self>, kind: bindings::ib_event_type) -> Result {
        if self.handler.is_none() {
            return Ok(());
        }
        let mut queue = self.queue.lock();
        if queue.draining {
            return Err(ESHUTDOWN);
        }
        let count = queue.counts.get_mut(kind as usize).ok_or(EINVAL)?;
        *count = count.checked_add(1).ok_or(EOVERFLOW)?;
        if !queue.scheduled {
            queue.scheduled = true;
            // The counters and work item were charged to the creator. Posting allocates nothing.
            self.enqueue(&mut queue);
        }
        Ok(())
    }

    fn deliver(&self, kind: bindings::ib_event_type) {
        if let Some(handler) = self.handler {
            // SAFETY: The owner retains the target and immutable callback context through
            // drainage. Delivery runs in sleepable worker or destruction context without
            // holding the event queue lock.
            unsafe {
                let mut event = self.event;
                event.event = kind;
                handler(&mut event, self.context);
            }
        }
    }

    /// Drains accepted callbacks and rearms the control for a possible failed destruction.
    ///
    /// # Safety
    ///
    /// The owner must exclude new posts and other drains until this method returns. It must
    /// permit sleepable callbacks in the calling task, without holding locks they require.
    pub(super) unsafe fn drain(&self) {
        self.queue.lock().draining = true;
        // SAFETY: The pinned work stays live through this call. Producers are excluded and
        // workers observe draining under the same lock as requeue, so cancellation joins all
        // executing callbacks and removes any pending ownership transfer.
        let canceled = unsafe { bindings::cancel_work_sync(Work::raw_get(&self.work)) };
        if canceled {
            let owner = self.queue.lock().owner.take().unwrap();
            // SAFETY: Successful cancellation returns exactly the queued Arc reference. Any
            // older invocation has finished; the saved pointer came from that enqueue.
            unsafe { drop(Arc::from_raw(owner.as_ptr())) };
        }
        // Pending events do not depend on another worker or on a rescuer becoming available.
        // The native owner and callback state remain installed throughout these calls.
        let mut delivered = 0;
        loop {
            let kind = self.queue.lock().take();
            let Some(kind) = kind else { break };
            self.deliver(kind);
            delivered += 1;
            if delivered == BATCH {
                // SAFETY: Drainage requires sleepable task context, and no event lock is held.
                unsafe { crate::task::cond_resched() };
                delivered = 0;
            }
        }
        let mut queue = self.queue.lock();
        queue.scheduled = false;
        queue.draining = false;
    }
}

workqueue::impl_has_work! {
    impl HasWork<Self> for Events { self.work }
}

impl WorkItem for Events {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        // WorkItemPointer recovered this submission's Arc before entering this method.
        this.queue.lock().owner = None;
        for _ in 0..BATCH {
            let kind = {
                let mut queue = this.queue.lock();
                if queue.draining {
                    queue.scheduled = false;
                    return;
                }
                let kind = queue.take();
                if kind.is_none() {
                    queue.scheduled = false;
                }
                kind
            };
            let Some(kind) = kind else { return };
            this.deliver(kind);
        }
        // Bound each invocation and serialize requeue against the destruction gate.
        let mut queue = this.queue.lock();
        if queue.draining {
            queue.scheduled = false;
        } else {
            this.enqueue(&mut queue);
        }
    }
}

#[cfg(CONFIG_RUST_KUNIT_TESTS)]
#[crate::macros::kunit_tests(rust_rdma_object_events)]
mod tests {
    use super::*;
    use crate::{
        sync::atomic::{
            Atomic,
            Relaxed, //
        },
        types::Opaque, //
    };

    struct CallbackState {
        count: Atomic<u32>,
        target: *mut c_void,
        kind: bindings::ib_event_type,
        slow: bool,
    }

    /// # Safety
    ///
    /// The context must retain initialized state until the callback returns. The event
    /// must carry the pointer member corresponding to the expected event kind.
    unsafe extern "C" fn count_event(event: *mut bindings::ib_event, context: *mut c_void) {
        // SAFETY: The test retains the initialized callback state through every drain.
        let state = unsafe { &*context.cast::<CallbackState>() };
        // SAFETY: Event dispatch initializes this native event and its selected target.
        let event = unsafe { &*event };
        assert_eq!(event.event, state.kind);
        // SAFETY: The test constructs the selected pointer member for this event kind.
        let target = unsafe {
            if state.kind == bindings::ib_event_type_IB_EVENT_SRQ_LIMIT_REACHED {
                event.element.srq.cast::<c_void>()
            } else {
                event.element.qp.cast::<c_void>()
            }
        };
        assert_eq!(target, state.target);
        crate::task::might_sleep();
        if state.slow {
            // SAFETY: Event dispatch runs in sleepable process context.
            unsafe { bindings::msleep(1) };
        }
        state.count.fetch_add(1, Relaxed);
    }

    fn exercise(event: bindings::ib_event, target: *mut c_void) -> Result {
        let state = KBox::new(
            CallbackState {
                count: Atomic::new(0),
                target,
                kind: event.event,
                slow: true,
            },
            GFP_KERNEL,
        )?;
        let kind = event.event;
        // SAFETY: The caller retains the target during this test. Callback state stays live
        // through both drains, and no producer survives either posting loop.
        let events = unsafe {
            Events::new(
                event,
                Some(count_event),
                core::ptr::from_ref(&*state).cast_mut().cast(),
            )?
        };
        let mut delivered = 0;
        for _ in 0..2 {
            let mut posted = 0;
            for _ in 0..8 {
                if events.post(kind).is_ok() {
                    posted += 1;
                }
            }
            // SAFETY: This test is the only producer and drain caller. A second iteration
            // exercises reuse after a failed destruction restores the original owner.
            unsafe { events.drain() };
            assert!(posted > 0);
            delivered += posted;
            assert_eq!(state.count.load(Relaxed), delivered);
        }
        Ok(())
    }

    #[test]
    fn qp_events_drain_in_sleepable_context_and_rearm() -> Result {
        let mut qp = KBox::new(bindings::ib_qp::default(), GFP_KERNEL)?;
        let target = core::ptr::from_mut(&mut *qp);
        exercise(
            bindings::ib_event {
                element: bindings::ib_event__bindgen_ty_1 { qp: target },
                event: bindings::ib_event_type_IB_EVENT_QP_FATAL,
                ..Default::default()
            },
            target.cast(),
        )
    }

    #[test]
    fn srq_events_drain_in_sleepable_context_and_rearm() -> Result {
        let mut srq = KBox::new(bindings::ib_srq::default(), GFP_KERNEL)?;
        let target = core::ptr::from_mut(&mut *srq);
        exercise(
            bindings::ib_event {
                element: bindings::ib_event__bindgen_ty_1 { srq: target },
                event: bindings::ib_event_type_IB_EVENT_SRQ_LIMIT_REACHED,
                ..Default::default()
            },
            target.cast(),
        )
    }

    struct TestQueue(NonNull<bindings::workqueue_struct>);

    impl TestQueue {
        fn new() -> Result<Self> {
            // SAFETY: The name has no conversions and the flags and active limit are valid.
            let queue = unsafe {
                bindings::alloc_workqueue_noprof(
                    c"rust_event_drain_test".as_char_ptr(),
                    bindings::wq_flags_WQ_PERCPU,
                    1,
                )
            };
            Ok(Self(NonNull::new(queue).ok_or(ENOMEM)?))
        }

        fn queue(&self) -> &workqueue::Queue {
            // SAFETY: This owner retains the queue throughout the returned borrow.
            unsafe { workqueue::Queue::from_raw(self.0.as_ptr()) }
        }
    }

    impl Drop for TestQueue {
        fn drop(&mut self) {
            // SAFETY: This owner is dropped outside its workers after event drainage.
            unsafe { bindings::destroy_workqueue(self.0.as_ptr()) };
        }
    }

    #[pin_data]
    struct Drainer {
        #[pin]
        work: Work<Self>,
        events: Arc<Events>,
        after_batch: bool,
        phase: Atomic<u32>,
        pending: Atomic<u32>,
        #[pin]
        done: Opaque<bindings::completion>,
    }

    // SAFETY: The retained event control and atomic fields are thread-safe. Native completion
    // operations synchronize the pinned done field, and the test retains callback state.
    unsafe impl Send for Drainer {}
    // SAFETY: Concurrent access uses atomic fields or native completion synchronization.
    unsafe impl Sync for Drainer {}

    workqueue::impl_has_work! {
        impl HasWork<Self> for Drainer { self.work }
    }

    impl WorkItem for Drainer {
        type Pointer = Arc<Self>;

        fn run(this: Self::Pointer) {
            let kind = bindings::ib_event_type_IB_EVENT_QP_FATAL;
            if this.phase.fetch_add(1, Relaxed) == 0 {
                for _ in 0..BATCH * 2 {
                    assert!(this.events.post(kind).is_ok());
                }
                if this.after_batch {
                    // Both items were queued from this bound worker. With max_active=1,
                    // one event batch runs before this work, and requeues behind it.
                    // SAFETY: The test retains this queue through both invocations.
                    let queue =
                        unsafe { workqueue::Queue::from_raw(this.events.workqueue.as_ptr()) };
                    let _ = queue.enqueue(this.clone());
                    return;
                }
            }
            this.pending.store(
                this.events.queue.lock().counts[kind as usize] as u32,
                Relaxed,
            );
            // SAFETY: This worker is the sole producer and drain caller, and the test retains
            // callback state. Drain must cancel work pending behind this max_active=1 worker.
            unsafe { this.events.drain() };
            for _ in 0..8 {
                assert!(this.events.post(kind).is_ok());
            }
            // SAFETY: Posting is again finished, exercising reuse after a failed destruction.
            unsafe { this.events.drain() };
            // SAFETY: The completion stays initialized and pinned until this worker returns.
            unsafe { bindings::complete_all(this.done.get()) };
        }
    }

    fn exercise_pending_drain(after_batch: bool) -> Result {
        let queue = TestQueue::new()?;
        let state = KBox::new(
            CallbackState {
                count: Atomic::new(0),
                target: core::ptr::null_mut(),
                kind: bindings::ib_event_type_IB_EVENT_QP_FATAL,
                slow: false,
            },
            GFP_KERNEL,
        )?;
        // SAFETY: The handler only compares the null target; this test retains the callback
        // state and queue through drainage. Only the drainer worker produces events.
        let events = unsafe {
            Events::new_on_queue(
                bindings::ib_event::default(),
                Some(count_event),
                core::ptr::from_ref(&*state).cast_mut().cast(),
                queue.0,
            )?
        };
        let retained = events.clone();
        let drainer = Arc::pin_init(
            pin_init!(Drainer {
                work <- workqueue::new_work!("rust_event_drain_caller"),
                events: retained,
                after_batch,
                phase: Atomic::new(0),
                pending: Atomic::new(0),
                done <- Opaque::ffi_init(|slot| {
                    // SAFETY: The pinned slot is writable, uninitialized completion storage.
                    unsafe { bindings::init_completion(slot) };
                }),
            }),
            GFP_KERNEL,
        )?;
        let _ = queue.queue().enqueue(drainer.clone());
        // SAFETY: The initialized completion remains pinned through worker drainage.
        let completed = unsafe {
            bindings::wait_for_completion_timeout(
                drainer.done.get(),
                crate::time::msecs_to_jiffies(1000),
            )
        } != 0;
        if !completed {
            // SAFETY: Let a pending event run if drainage regresses, so the test fails without
            // leaving the suite hung behind the single active worker.
            unsafe {
                bindings::workqueue_set_max_active(queue.0.as_ptr(), 2);
                bindings::wait_for_completion(drainer.done.get());
            }
        }
        // SAFETY: No new submissions are possible; wait for the caller's final Arc drop.
        unsafe { bindings::__flush_workqueue(queue.0.as_ptr()) };
        let pending = drainer.pending.load(Relaxed);
        drop(drainer);
        let unique = Arc::into_unique_or_drop(events).is_some();
        assert!(completed);
        assert_eq!(
            pending as usize,
            if after_batch { BATCH } else { BATCH * 2 }
        );
        assert_eq!(state.count.load(Relaxed) as usize, BATCH * 2 + 8);
        assert!(unique);
        Ok(())
    }

    #[test]
    fn pending_events_drain_behind_the_current_worker() -> Result {
        exercise_pending_drain(false)
    }

    #[test]
    fn requeued_event_batch_drains_behind_the_current_worker() -> Result {
        exercise_pending_drain(true)
    }

    #[pin_data]
    struct BlockedCallback {
        #[pin]
        entered: crate::sync::Completion,
        #[pin]
        resume: crate::sync::Completion,
        count: Atomic<u32>,
    }

    /// # Safety
    ///
    /// `context` must retain an initialized, pinned callback state until this call returns.
    unsafe extern "C" fn blocked_event(_: *mut bindings::ib_event, context: *mut c_void) {
        // SAFETY: The test retains this pinned callback state through every accepted event.
        let state = unsafe { &*context.cast::<BlockedCallback>() };
        state.entered.complete_all();
        state.resume.wait_for_completion();
        state.count.fetch_add(1, Relaxed);
    }

    #[test]
    fn stalled_handler_preserves_occurrences_without_event_allocations() -> Result {
        let state = Arc::pin_init(
            pin_init!(BlockedCallback {
                entered <- crate::sync::Completion::new(),
                resume <- crate::sync::Completion::new(),
                count: Atomic::new(0),
            }),
            GFP_KERNEL,
        )?;
        let kind = bindings::ib_event_type_IB_EVENT_SRQ_LIMIT_REACHED;
        // SAFETY: This handler does not dereference the native target. Its pinned context is
        // retained through both drains, and only this test posts or drains events.
        let events = unsafe {
            Events::new(
                bindings::ib_event::default(),
                Some(blocked_event),
                core::ptr::from_ref(&*state).cast_mut().cast(),
            )?
        };
        events.post(kind)?;
        state.entered.wait_for_completion();
        let mut accepted = 0;
        const POSTS: usize = 1024;
        for _ in 0..POSTS {
            if events.post(kind).is_ok() {
                accepted += 1;
            }
        }
        let resume = state.clone();
        let draining = events.clone();
        let queued = workqueue::system_dfl().try_spawn(GFP_KERNEL, move || {
            while !draining.queue.lock().draining {
                // SAFETY: This independent worker holds no locks and may sleep.
                unsafe { crate::task::cond_resched() };
            }
            // SAFETY: Keep the callback active while drainage joins its work invocation.
            unsafe { bindings::msleep(20) };
            resume.resume.complete_all();
        });
        if let Err(error) = queued {
            state.resume.complete_all();
            // SAFETY: No new posts are possible; drain before releasing callback state.
            unsafe { events.drain() };
            return Err(error.into());
        }
        // SAFETY: All accepted posts precede this drain and the callback context is retained.
        unsafe { events.drain() };
        assert_eq!(accepted, POSTS);
        assert_eq!(state.count.load(Relaxed), POSTS as u32 + 1);

        events.post(kind)?;
        // SAFETY: This test remains the only producer and retains the callback context.
        unsafe { events.drain() };
        assert_eq!(state.count.load(Relaxed), POSTS as u32 + 2);
        Ok(())
    }
}
