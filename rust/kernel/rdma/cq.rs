// SPDX-License-Identifier: GPL-2.0

//! Owned completion queues with serialized, deferred completion callbacks.

use super::{
    queued_event::Events,
    CompletionOutput,
    ContextData,
    Operations,
    UserContextOperations,
    UserData, //
};
use crate::{
    bindings,
    prelude::*,
    sync::{
        atomic::{
            Atomic,
            Relaxed, //
        },
        Arc,
        Mutex,
        SpinLockIrq, //
    },
    types::{
        ForeignOwnable,
        Opaque, //
    },
    workqueue::{
        self,
        Work,
        WorkItem, //
    }, //
};
use core::{
    marker::PhantomData,
    ptr::{
        self,
        NonNull, //
    }, //
};

/// A capacity representable by the core's signed `cqe` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionCapacity(u32);

impl CompletionCapacity {
    /// Checks that the capacity fits the core ABI.
    #[inline]
    pub fn new(entries: u32) -> Result<Self> {
        c_int::try_from(entries)?;
        Ok(Self(entries))
    }

    /// Returns the number of usable completion entries.
    #[inline]
    pub fn entries(self) -> u32 {
        self.0
    }
}

/// Requested completion queue attributes.
pub struct CompletionAttributes {
    /// Requested number of usable entries.
    pub entries: u32,
    /// Requested completion vector.
    pub vector: u32,
    /// Core creation flags, including unrecognized bits for provider validation.
    pub flags: u32,
}

/// Private ownership and actual capacity returned by successful creation.
pub struct CompletionCreation<T> {
    /// Private data retained until successful release.
    pub owner: T,
    /// Actual usable capacity to publish in the core header.
    pub capacity: CompletionCapacity,
}

/// Notification selectors supplied by the core caller.
pub struct CompletionNotify {
    /// Arm notification for the next completion of any kind.
    pub next: bool,
    /// Arm notification for a solicited completion.
    pub solicited: bool,
    /// Request a hint indicating already queued completions.
    pub report_missed: bool,
    /// Other mask bits, retained for provider validation.
    pub unknown_mask: u32,
}

/// Completion queue operations implemented by pinned provider data.
///
/// Creation, resize and release may sleep. Polling, peeking and arming may run with interrupts
/// disabled and must not sleep. Providers synchronize their own queue state; this adapter
/// additionally serializes resize callbacks through core capacity publication. The core or
/// kernel caller excludes release while QPs and ordinary verbs callbacks retain the CQ.
/// Completion and error handlers must not synchronously destroy their own CQ or create a
/// cycle with another active handler's destruction. Destruction cancels pending completion
/// dispatchers and drains accepted error events and executing handlers before releasing callback
/// state.
/// Error events and completion notifications may run concurrently.
///
/// Creation uses the core's `create_cq` fallback and provider-specific user data. Explicit
/// VA and dma-buf CQ buffer attributes requiring `create_user_cq` are not exposed here.
pub trait CompletionQueueOperations: UserContextOperations {
    /// The provider's native queue owner.
    type CompletionQueue: ForeignOwnable + Send + Sync + 'static;

    /// Creates private queue state before publication.
    fn create_completion_queue(
        self: Pin<&Self>,
        attributes: CompletionAttributes,
        data: Option<ContextData<'_, Self>>,
    ) -> Result<CompletionCreation<Self::CompletionQueue>>;

    /// Resizes storage and returns the actual capacity while core resizing is serialized.
    fn resize_completion_queue(
        self: Pin<&Self>,
        queue: <Self::CompletionQueue as ForeignOwnable>::Borrowed<'_>,
        entries: u32,
        data: Option<ContextData<'_, Self>>,
    ) -> Result<CompletionCapacity>;

    /// Moves completed entries into bounded kernel output.
    fn poll_completion_queue(
        self: Pin<&Self>,
        queue: <Self::CompletionQueue as ForeignOwnable>::Borrowed<'_>,
        output: &mut CompletionOutput<'_>,
    ) -> Result;

    /// Returns the number of available completions, capped at `maximum`.
    fn peek_completion_queue(
        self: Pin<&Self>,
        queue: <Self::CompletionQueue as ForeignOwnable>::Borrowed<'_>,
        maximum: u32,
    ) -> u32;

    /// Arms notifications and returns the requested hint about missed events.
    fn arm_completion_queue(
        self: Pin<&Self>,
        queue: <Self::CompletionQueue as ForeignOwnable>::Borrowed<'_>,
        flags: CompletionNotify,
    ) -> Result<bool>;

    /// Releases private state after completion callbacks have drained.
    ///
    /// The provider must unpublish and drain any additional internal users before returning.
    /// Mandatory kernel cleanup frees the core CQ immediately after this callback.
    fn release_completion_queue(
        self: Pin<&Self>,
        owner: Self::CompletionQueue,
        _data: Option<UserData<'_, Self>>,
    ) {
        drop(owner);
    }
}

#[repr(C)]
struct OwnedQueue {
    core: bindings::ib_cq,
    private_data: *mut c_void,
    control: *mut c_void,
}

#[pin_data]
struct Dispatch {
    #[pin]
    work: Work<Self>,
    target: NonNull<OwnedQueue>,
    queue: NonNull<bindings::workqueue_struct>,
}

// SAFETY: The target's core allocation is pinned. Its installed control owner drains this
// invocation before the release adapter consumes private data or permits core deallocation.
unsafe impl Send for Dispatch {}

workqueue::impl_has_work! {
    impl HasWork<Self> for Dispatch { self.work }
}

struct Notification {
    work: Option<Pin<KBox<Dispatch>>>,
    pending: u64,
    stopping: bool,
}

#[pin_data]
struct Control {
    dispatch: NonNull<Dispatch>,
    events: Arc<Events>,
    #[pin]
    resize: Mutex<()>,
    #[pin]
    notification: SpinLockIrq<Notification>,
}

impl Control {
    // The unpublished core target must remain pinned and be released through this adapter.
    // The target's control slot is installed before any invocation can be requested.
    /// # Safety
    ///
    /// The target must be unpublished, pinned adapter-owned storage. The caller must install
    /// its control slot before publication and release it only through this adapter.
    /// `queue` must remain live until the target's dispatchers have drained.
    unsafe fn new(
        target: NonNull<OwnedQueue>,
        queue: NonNull<bindings::workqueue_struct>,
    ) -> Result<Pin<KBox<Self>>> {
        // SAFETY: Native creation initializes the callback fields before calling this adapter.
        // The installed control drains accepted events before the target or context is freed.
        let events = unsafe {
            let cq = target.as_ptr().cast::<bindings::ib_cq>();
            Events::new(
                bindings::ib_event {
                    device: (*cq).device,
                    element: bindings::ib_event__bindgen_ty_1 { cq },
                    event: bindings::ib_event_type_IB_EVENT_CQ_ERR,
                },
                (*cq).event_handler,
                (*cq).cq_context,
            )?
        };
        let work = KBox::pin_init(
            pin_init!(Dispatch {
                work <- workqueue::new_work!("rdma_cq_completion"),
                target,
                queue,
            }),
            GFP_KERNEL,
        )?;
        // SAFETY: The allocation stays pinned through this ownership round trip. Keep the
        // allocation pointer rather than deriving reclaiming ownership from a shared borrow.
        let dispatch =
            unsafe { NonNull::new_unchecked(KBox::into_raw(Pin::into_inner_unchecked(work))) };
        // SAFETY: The pointer still owns this live, pinned allocation.
        let work = unsafe { Pin::new_unchecked(KBox::from_raw(dispatch.as_ptr())) };
        KBox::pin_init(
            try_pin_init!(Self {
                dispatch,
                events,
                resize <- crate::new_mutex!(()),
                notification <- crate::new_spinlock_irq!(Notification {
                    work: Some(work), pending: 0, stopping: false,
                }),
            }),
            GFP_KERNEL,
        )
    }

    #[inline]
    fn notify(&self) -> Result {
        let mut state = self.notification.lock();
        if state.stopping {
            return Err(ESHUTDOWN);
        }
        state.pending = state.pending.checked_add(1).ok_or(EOVERFLOW)?;
        if let Some(work) = state.work.take() {
            // A unique work box prevents duplicate pending submissions. Use the same queue
            // on every submission, including reuse while the preceding C callback returns.
            // SAFETY: Creation retains the queue until this control has stopped delivery.
            unsafe { workqueue::Queue::from_raw(work.queue.as_ptr()) }.enqueue(work);
        }
        Ok(())
    }

    fn error(&self) -> Result {
        let state = self.notification.lock();
        if state.stopping {
            return Err(ESHUTDOWN);
        }
        self.events.post(bindings::ib_event_type_IB_EVENT_CQ_ERR)
    }

    fn stop(&self) {
        self.notification.lock().stopping = true;
        // SAFETY: The dispatch allocation never moves or frees before this control. Its box
        // is either held by notification.work or transferred to the workqueue. New submissions
        // are excluded, and the native destruction contract serializes calls to stop().
        let canceled = unsafe {
            bindings::cancel_work_sync(Work::raw_get(&raw const (*self.dispatch.as_ptr()).work))
        };
        if canceled {
            // SAFETY: Successful cancellation returns the one ownership transfer from enqueue.
            // Any older invocation has finished, and no new submission can consume the box.
            let work = unsafe { Pin::new_unchecked(KBox::from_raw(self.dispatch.as_ptr())) };
            self.notification.lock().work = Some(work);
        }
        // SAFETY: The stopping flag excludes new error posts, and native destruction
        // serializes stop calls. Error work runs independently of completion dispatch.
        unsafe { self.events.drain() };
    }
}

// The caller retains an initialized adapter-owned CQ and excludes control release for 'a.
#[inline]
/// # Safety
///
/// The CQ must belong to this adapter, and its initialized control owner must remain live for
/// the returned borrow.
unsafe fn control<'a>(cq: *mut bindings::ib_cq) -> Pin<&'a Control> {
    // SAFETY: Creation installed one pinned owner which is retained for the caller's borrow.
    unsafe { <Pin<KBox<Control>>>::borrow((*cq.cast::<OwnedQueue>()).control) }
}

impl WorkItem for Dispatch {
    type Pointer = Pin<KBox<Self>>;

    fn run(this: Self::Pointer) {
        let cq = this.target.as_ptr().cast::<bindings::ib_cq>();
        // SAFETY: Release cancels pending submissions and waits for this invocation to return
        // before consuming either owner. The installed control remains pinned until then.
        let control = unsafe { control(cq) };
        let mut remaining = 16;
        loop {
            let completion = {
                let mut state = control.notification.lock();
                let pending = state.pending != 0;
                if pending {
                    state.pending -= 1;
                }
                pending
            };
            // SAFETY: The core allocation, immutable callback and callback context remain live.
            // This unique invocation serializes delivery and runs outside every verbs call.
            unsafe {
                if completion {
                    if let Some(handler) = (*cq).comp_handler {
                        handler(cq, (*cq).cq_context);
                    }
                }
            }
            let mut state = control.notification.lock();
            if state.stopping {
                state.pending = 0;
            }
            if state.pending != 0 {
                remaining -= 1;
                if remaining == 0 {
                    // A unique box and a single queue preserve native work serialization.
                    // SAFETY: Creation retains the queue until this control stops delivery.
                    unsafe { workqueue::Queue::from_raw(this.queue.as_ptr()) }.enqueue(this);
                    return;
                }
                drop(state);
                continue;
            }
            state.work = Some(this);
            // Return ownership before cancel_work_sync() lets destruction release the control.
            drop(state);
            return;
        }
    }
}

/// A borrowed CQ belonging to this module's ownership adapter.
///
/// # Invariants
///
/// The core CQ and installed private/control owners remain initialized and pinned throughout
/// a borrow. Its device and immutable callbacks and contexts remain live. Release is excluded.
#[repr(transparent)]
pub struct CompletionQueue<T: CompletionQueueOperations> {
    inner: Opaque<bindings::ib_cq>,
    _provider: PhantomData<T>,
}

impl<T: CompletionQueueOperations> CompletionQueue<T> {
    /// Borrows an initialized CQ installed by [`CompletionQueues::<T>`].
    ///
    /// # Safety
    ///
    /// The caller must guarantee the type invariant for `'a`, including excluding release
    /// attempts even when the provider would reject them.
    #[inline]
    pub unsafe fn from_raw<'a>(cq: *mut bindings::ib_cq) -> &'a Self {
        // SAFETY: The caller retains initialized adapter state; transparent layout matches.
        unsafe { &*cq.cast() }
    }

    /// Schedules serialized completion delivery outside the current verbs call.
    ///
    /// Each accepted request causes a separate callback unless destruction cancels pending
    /// delivery. Notification arming belongs to the provider. This call allocates nothing;
    /// a saturated counter returns [`EOVERFLOW`] and stopped delivery returns [`ESHUTDOWN`].
    /// On PREEMPT_RT, call from task or threaded interrupt context with interrupts enabled,
    /// outside raw spinlocks, as required by the regular spinlock protecting notifications.
    #[inline]
    pub fn notify(&self) -> Result {
        // SAFETY: The type invariant retains the installed control owner for this call.
        unsafe { control(self.inner.get()) }.notify()
    }

    /// Defers a CQ error to the creator's asynchronous event handler, if present.
    ///
    /// Every accepted occurrence is drained before destruction. Posting allocates nothing;
    /// a saturated event counter returns [`EOVERFLOW`], and stopped delivery returns
    /// [`ESHUTDOWN`]. Error handlers run in a system worker or the destroying task, outside
    /// provider locks, and may overlap completion notifications. The context requirements of
    /// [`Self::notify`] also apply here.
    /// Handlers must obey the destruction restrictions in [`CompletionQueueOperations`].
    #[inline]
    pub fn error(&self) -> Result {
        // SAFETY: The type invariant retains the installed control owner for this call.
        unsafe { control(self.inner.get()) }.error()
    }

    /// Borrows the CQ's parent device for diagnostics.
    #[inline]
    pub fn device(&self) -> &crate::device::Device {
        // SAFETY: A live core CQ retains its initialized RDMA device, whose embedded device
        // reference count remains nonzero until the CQ and its callback/control owners drain.
        unsafe {
            crate::device::Device::from_raw(
                &raw mut (*(*self.inner.get()).device).__bindgen_anon_1.dev,
            )
        }
    }
}

/// Installs owned CQ data, bounded polling and deferred, serialized completion delivery.
pub struct CompletionQueues<T: CompletionQueueOperations>(PhantomData<T>);

impl<T: CompletionQueueOperations> CompletionQueues<T> {
    /// Installs callbacks before device publication.
    ///
    /// # Safety
    ///
    /// The device must be exclusively owned and unpublished, with [`Operations::<T>::install`]
    /// and [`super::UserContexts::<T>::install`] completed. Its `create_cq`, `create_user_cq`,
    /// `resize_user_cq`, `poll_cq`, `peek_cq`, `req_notify_cq`, `destroy_cq`, `pre_destroy_cq`,
    /// `post_destroy_cq` and `size_ib_cq` slots must be unused and remain managed by this adapter.
    /// All queues must be destroyed through the adapter so callback draining completes before
    /// core polling work is canceled or core and provider memory is released.
    pub unsafe fn install(device: *mut bindings::ib_device) {
        // SAFETY: The caller reserves these slots and exclusively owns the unpublished device.
        unsafe {
            (*device).ops.size_ib_cq = size_of::<OwnedQueue>();
            (*device).ops.create_cq = Some(Self::create);
            (*device).ops.resize_user_cq = Some(Self::resize);
            (*device).ops.poll_cq = Some(Self::poll);
            (*device).ops.peek_cq = Some(Self::peek);
            (*device).ops.req_notify_cq = Some(Self::arm);
            (*device).ops.destroy_cq = Some(Self::release);
            (*device).ops.pre_destroy_cq = Some(Self::stop);
        }
    }

    /// Borrows private data while the initialized core CQ is retained.
    ///
    /// # Safety
    ///
    /// The CQ must belong to this adapter, with its device retained and all release attempts
    /// excluded for `'a`, including those which the provider would reject.
    #[inline]
    pub unsafe fn data<'a>(
        cq: *mut bindings::ib_cq,
    ) -> <T::CompletionQueue as ForeignOwnable>::Borrowed<'a> {
        // SAFETY: The caller retains the initialized foreign slot and excludes owner extraction.
        unsafe { T::CompletionQueue::borrow((*cq.cast::<OwnedQueue>()).private_data) }
    }

    /// # Safety
    ///
    /// The core must provide unpublished storage of the installed size, retain this adapter's
    /// initialized device and parents, and supply stable selected attributes and original
    /// uverbs data with disassociation excluded.
    unsafe extern "C" fn create(
        cq: *mut bindings::ib_cq,
        attributes: *const bindings::ib_cq_init_attr,
        bundle: *mut bindings::uverbs_attr_bundle,
    ) -> c_int {
        // SAFETY: The core owns initialized unpublished storage of our configured size and
        // retains its device. A present original bundle pins an initialized context while
        // disassociation is excluded. No invocation is possible before both owners are installed.
        unsafe {
            let data = if bundle.is_null() {
                ptr::null_mut()
            } else {
                &raw mut (*bundle).__bindgen_anon_1.__bindgen_anon_1.driver_udata
            };
            let data = match ContextData::from_raw(data) {
                Ok(data) => data,
                Err(error) => return error.to_errno(),
            };
            // Keep the modular symbol reference in this provider callback. The core device
            // retains ib_core and its workqueue until this CQ's dispatchers have drained.
            let queue = NonNull::new_unchecked(bindings::ib_comp_wq);
            let control = match Control::new(NonNull::new_unchecked(cq.cast()), queue) {
                Ok(control) => control,
                Err(error) => return error.to_errno(),
            };
            let attr = CompletionAttributes {
                entries: (*attributes).cqe,
                vector: (*attributes).comp_vector,
                flags: (*attributes).flags,
            };
            match Operations::<T>::data((*cq).device).create_completion_queue(attr, data) {
                Ok(CompletionCreation { owner, capacity }) => {
                    (*cq).cqe = capacity.entries() as c_int;
                    (*cq.cast::<OwnedQueue>()).private_data = owner.into_foreign();
                    (*cq.cast::<OwnedQueue>()).control = control.into_foreign();
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain this adapter's initialized CQ and device and exclude release.
    /// Any userspace data must belong to an original live uverbs bundle with disassociation
    /// excluded.
    unsafe extern "C" fn resize(
        cq: *mut bindings::ib_cq,
        entries: u32,
        data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core retains CQ data and its device with release excluded. The original
        // userspace bundle retains an initialized context and excludes disassociation. The
        // control mutex serializes the callback through capacity publication in the core header.
        unsafe {
            let data = match ContextData::from_raw(data) {
                Ok(data) => data,
                Err(error) => return error.to_errno(),
            };
            let control = control(cq);
            let _resize = control.resize.lock();
            match Operations::<T>::data((*cq).device).resize_completion_queue(
                Self::data(cq),
                entries,
                data,
            ) {
                Ok(capacity) => {
                    Atomic::<c_int>::from_ptr(&raw mut (*cq).cqe)
                        .store(capacity.entries() as c_int, Relaxed);
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain this adapter's initialized CQ and device and exclude release. A
    /// positive count requires that many aligned, exclusively writable output elements.
    /// Kernel callers retain native request callbacks and QPs until returned completions have
    /// been handled, including when synchronizing release of requests across QP reset.
    unsafe extern "C" fn poll(
        cq: *mut bindings::ib_cq,
        count: c_int,
        output: *mut bindings::ib_wc,
    ) -> c_int {
        // SAFETY: The caller retains the CQ, its device with a fixed registered port range,
        // and native callback state through completion handling. It grants count writable
        // elements when count is positive; neither the adapter nor the cursor reads them.
        unsafe {
            let mut output = CompletionOutput::from_raw(cq, output, count);
            match Operations::<T>::data((*cq).device)
                .poll_completion_queue(Self::data(cq), &mut output)
            {
                Ok(()) => output.written() as c_int,
                Err(error) if output.written() == 0 => error.to_errno(),
                Err(_) => output.written() as c_int,
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain this adapter's initialized CQ and device and exclude release
    /// attempts.
    unsafe extern "C" fn peek(cq: *mut bindings::ib_cq, count: c_int) -> c_int {
        // SAFETY: The caller retains initialized CQ data and its device and excludes release.
        unsafe {
            Operations::<T>::data((*cq).device)
                .peek_completion_queue(Self::data(cq), count.max(0) as u32)
                .min(count.max(0) as u32) as c_int
        }
    }

    /// # Safety
    ///
    /// The caller must retain this adapter's initialized CQ and device and exclude release
    /// attempts.
    unsafe extern "C" fn arm(
        cq: *mut bindings::ib_cq,
        flags: bindings::ib_cq_notify_flags,
    ) -> c_int {
        let known = bindings::ib_cq_notify_flags_IB_CQ_NEXT_COMP
            | bindings::ib_cq_notify_flags_IB_CQ_SOLICITED
            | bindings::ib_cq_notify_flags_IB_CQ_REPORT_MISSED_EVENTS;
        let flags = CompletionNotify {
            next: flags & bindings::ib_cq_notify_flags_IB_CQ_NEXT_COMP != 0,
            solicited: flags & bindings::ib_cq_notify_flags_IB_CQ_SOLICITED != 0,
            report_missed: flags & bindings::ib_cq_notify_flags_IB_CQ_REPORT_MISSED_EVENTS != 0,
            unknown_mask: flags & !known,
        };
        // SAFETY: The caller retains initialized private data and excludes release.
        unsafe {
            Operations::<T>::data((*cq).device)
                .arm_completion_queue(Self::data(cq), flags)
                .map_or_else(|error| error.to_errno(), c_int::from)
        }
    }

    /// # Safety
    ///
    /// The core must retain this adapter's initialized CQ and both installed owners, exclude
    /// attached QPs and further verbs calls, and permit sleeping.
    unsafe extern "C" fn stop(cq: *mut bindings::ib_cq) -> c_int {
        // SAFETY: ib_free_cq retains both installed owners and excludes attached QPs. Drain
        // notification delivery before the core cancels the polling work those handlers queue.
        // The subsequent release callback can stop this already-idle controller again.
        unsafe { control(cq) }.stop();
        0
    }

    /// # Safety
    ///
    /// The core must retain this adapter's initialized CQ and device, exclude attached QPs
    /// and further verbs calls, and permit sleeping. Optional udata must satisfy
    /// UserData::from_raw.
    unsafe extern "C" fn release(cq: *mut bindings::ib_cq, data: *mut bindings::ib_udata) -> c_int {
        // SAFETY: The core or kernel caller excludes new verbs calls and attached QPs. Stop
        // completion delivery and wait before extracting private ownership: an active handler
        // can still poll or rearm the CQ. Release then consumes both owners exactly once.
        unsafe {
            let core = cq.cast::<OwnedQueue>();
            control(cq).stop();
            let slot = &raw mut (*core).private_data;
            let owner = T::CompletionQueue::from_foreign(ptr::replace(slot, ptr::null_mut()));
            Operations::<T>::data((*cq).device)
                .release_completion_queue(owner, UserData::from_raw(data));
            let state = ptr::replace(&raw mut (*core).control, ptr::null_mut());
            drop(<Pin<KBox<Control>>>::from_foreign(state));
            0
        }
    }
}

#[cfg(CONFIG_RUST_KUNIT_TESTS)]
#[crate::macros::kunit_tests(rust_rdma_cq_dispatch)]
mod tests {
    use super::*;
    use crate::sync::{
        Arc,
        Completion, //
    };

    struct TestQueue(NonNull<bindings::workqueue_struct>);

    impl TestQueue {
        fn new() -> Result<Self> {
            // SAFETY: The name has no conversions and the flags and active limit are valid.
            let raw = unsafe {
                bindings::alloc_workqueue_noprof(
                    c"rust_cq_dispatch_test".as_char_ptr(),
                    bindings::wq_flags_WQ_PERCPU,
                    1,
                )
            };
            Ok(Self(NonNull::new(raw).ok_or(ENOMEM)?))
        }

        fn queue(&self) -> &workqueue::Queue {
            // SAFETY: This owner retains the initialized native queue during the borrow.
            unsafe { workqueue::Queue::from_raw(self.0.as_ptr()) }
        }
    }

    impl Drop for TestQueue {
        fn drop(&mut self) {
            // SAFETY: The test excludes submissions and drops this owner outside its workers.
            unsafe { bindings::destroy_workqueue(self.0.as_ptr()) };
        }
    }

    #[pin_data]
    struct CallbackState {
        #[pin]
        entered: Completion,
        #[pin]
        resume: Completion,
        count: Atomic<u32>,
        expected: u32,
        #[pin]
        delivered: Opaque<bindings::completion>,
        errors: Atomic<u32>,
        block: bool,
    }

    // SAFETY: Callback state contains immutable scalars, atomic counters and pinned completions.
    // Completion operations synchronize their internal pointers and may run on any task.
    unsafe impl Send for CallbackState {}
    // SAFETY: All mutable state uses atomic counters or native completion synchronization.
    unsafe impl Sync for CallbackState {}

    impl CallbackState {
        fn new(block: bool, expected: u32) -> Result<Arc<Self>> {
            Arc::pin_init(
                pin_init!(Self {
                    entered <- Completion::new(),
                    resume <- Completion::new(),
                    count: Atomic::new(0),
                    expected,
                    delivered <- Opaque::ffi_init(|slot| {
                        // SAFETY: The pinned slot is writable, uninitialized completion storage.
                        unsafe { bindings::init_completion(slot) };
                    }),
                    errors: Atomic::new(0),
                    block,
                }),
                GFP_KERNEL,
            )
        }
    }

    /// # Safety
    ///
    /// The caller retains the initialized callback state until this invocation returns.
    unsafe extern "C" fn complete(_: *mut bindings::ib_cq, context: *mut c_void) {
        // SAFETY: The test retains this pinned state through the controller's stop operation.
        let state = unsafe { &*context.cast::<CallbackState>() };
        state.entered.complete_all();
        if state.block {
            state.resume.wait_for_completion();
        }
        if state.count.fetch_add(1, Relaxed) + 1 == state.expected {
            // SAFETY: The test retains this initialized completion through callback drainage.
            unsafe { bindings::complete_all(state.delivered.get()) };
        }
    }

    /// # Safety
    ///
    /// The caller retains the initialized event and callback state through this invocation.
    unsafe extern "C" fn error(event: *mut bindings::ib_event, context: *mut c_void) {
        // SAFETY: The event and pinned callback state remain live until stop() returns.
        let (event, state) = unsafe { (&*event, &*context.cast::<CallbackState>()) };
        assert_eq!(event.event, bindings::ib_event_type_IB_EVENT_CQ_ERR);
        // SAFETY: CQ error events initialize the CQ member of the target union.
        assert!(!unsafe { event.element.cq }.is_null());
        state.entered.complete_all();
        if state.block {
            state.resume.wait_for_completion();
        }
        state.errors.fetch_add(1, Relaxed);
    }

    struct TestCq {
        target: KBox<OwnedQueue>,
        _state: Arc<CallbackState>,
    }

    impl TestCq {
        fn new(queue: &TestQueue, state: Arc<CallbackState>) -> Result<Self> {
            let mut target = KBox::new(
                OwnedQueue {
                    core: bindings::ib_cq {
                        comp_handler: Some(complete),
                        event_handler: Some(error),
                        cq_context: Arc::as_ptr(&state).cast_mut().cast(),
                        ..Default::default()
                    },
                    private_data: ptr::null_mut(),
                    control: ptr::null_mut(),
                },
                GFP_KERNEL,
            )?;
            // SAFETY: This heap allocation stays pinned. The test retains the queue until
            // after this owner stops delivery, and installs the control before any posting.
            target.control =
                unsafe { Control::new(NonNull::from(&mut *target), queue.0)? }.into_foreign();
            Ok(Self {
                target,
                _state: state,
            })
        }

        fn control(&self) -> Pin<&Control> {
            // SAFETY: This owner retains the initialized target and its installed control.
            unsafe { control(ptr::from_ref(&self.target.core).cast_mut()) }
        }
    }

    impl Drop for TestCq {
        fn drop(&mut self) {
            self.control().stop();
            // SAFETY: Delivery is stopped and this is the only installed control owner.
            unsafe { drop(<Pin<KBox<Control>>>::from_foreign(self.target.control)) };
        }
    }

    #[pin_data]
    struct Stopper {
        #[pin]
        work: Work<Self>,
        target: NonNull<Control>,
        #[pin]
        done: Opaque<bindings::completion>,
    }

    // SAFETY: The test retains the control until this invocation signals its final access.
    unsafe impl Send for Stopper {}
    // SAFETY: Only the single worker accesses the control; completion state is synchronized.
    unsafe impl Sync for Stopper {}

    workqueue::impl_has_work! {
        impl HasWork<Self> for Stopper { self.work }
    }

    impl WorkItem for Stopper {
        type Pointer = Arc<Self>;

        fn run(this: Arc<Self>) {
            // SAFETY: The test retains this control until the final completion below.
            let target = unsafe { this.target.as_ref() };
            for _ in 0..64 {
                assert!(target.error().is_ok());
            }
            assert!(target.notify().is_ok());
            target.stop();
            // SAFETY: The pinned completion is initialized and retained by this Arc.
            unsafe { bindings::complete_all(this.done.get()) };
        }
    }

    #[test]
    fn stop_cancels_a_dispatcher_behind_the_current_worker() -> Result {
        let queue = TestQueue::new()?;
        let state = CallbackState::new(false, 0)?;
        let target = TestCq::new(&queue, state.clone())?;
        let control = NonNull::from(&*target.control());
        let stopper = Arc::pin_init(
            pin_init!(Stopper {
                work <- workqueue::new_work!("rust_cq_test_stop"),
                target: control,
                done <- Opaque::ffi_init(|slot| {
                    // SAFETY: The pinned slot is writable, uninitialized completion storage.
                    unsafe { bindings::init_completion(slot) };
                }),
            }),
            GFP_KERNEL,
        )?;
        let _ = queue.queue().enqueue(stopper.clone());
        // SAFETY: The completion remains pinned; this test is its only waiter.
        let completed = unsafe {
            bindings::wait_for_completion_timeout(
                stopper.done.get(),
                crate::time::msecs_to_jiffies(1000),
            )
        } != 0;
        if !completed {
            // SAFETY: A regression must fail without hanging the suite. A second active slot
            // allows the pending dispatcher to run and releases the blocked stopping worker.
            unsafe {
                bindings::workqueue_set_max_active(queue.0.as_ptr(), 2);
                bindings::wait_for_completion(stopper.done.get());
            }
        }
        assert!(completed);
        assert_eq!(state.count.load(Relaxed), 0);
        assert_eq!(state.errors.load(Relaxed), 64);
        assert!(target.control().notification.lock().work.is_some());
        // Stopping twice must not reconstruct a second box for the canceled submission.
        target.control().stop();
        Ok(())
    }

    #[test]
    fn stop_drains_an_executing_handler() -> Result {
        let queue = TestQueue::new()?;
        let state = CallbackState::new(true, 0)?;
        let target = TestCq::new(&queue, state.clone())?;
        target.control().notify()?;
        state.entered.wait_for_completion();
        let resume = state.clone();
        let queued = workqueue::system_dfl().try_spawn(GFP_KERNEL, move || {
            // SAFETY: This independent worker runs in sleepable context.
            unsafe { bindings::msleep(20) };
            resume.resume.complete_all();
        });
        if let Err(error) = queued {
            state.resume.complete_all();
            return Err(error.into());
        }
        target.control().stop();
        assert_eq!(state.count.load(Relaxed), 1);
        assert!(target.control().notification.lock().work.is_some());
        Ok(())
    }

    #[test]
    fn notifications_preserve_separate_arms_behind_a_stalled_handler() -> Result {
        let queue = TestQueue::new()?;
        let state = CallbackState::new(true, 1025)?;
        let target = TestCq::new(&queue, state.clone())?;
        target.control().notify()?;
        state.entered.wait_for_completion();
        let mut accepted = 0;
        for _ in 0..1024 {
            if target.control().notify().is_ok() {
                accepted += 1;
            }
        }
        state.resume.complete_all();
        // SAFETY: The pinned completion is initialized and retained through stop(). A timeout
        // reports a coalescing regression without leaving the test waiting for missing events.
        let delivered = unsafe {
            bindings::wait_for_completion_timeout(
                state.delivered.get(),
                crate::time::msecs_to_jiffies(1000),
            )
        } != 0;
        target.control().stop();
        assert_eq!(accepted, 1024);
        assert!(delivered);
        assert_eq!(state.count.load(Relaxed), 1025);
        assert_eq!(target.control().notify(), Err(ESHUTDOWN));
        Ok(())
    }

    #[test]
    fn stop_preserves_errors_queued_behind_a_stalled_handler() -> Result {
        let queue = TestQueue::new()?;
        let state = CallbackState::new(true, 0)?;
        let target = TestCq::new(&queue, state.clone())?;
        target.control().error()?;
        state.entered.wait_for_completion();
        let mut accepted = 0;
        for _ in 0..1024 {
            if target.control().error().is_ok() {
                accepted += 1;
            }
        }
        let resume = state.clone();
        let queued = workqueue::system_dfl().try_spawn(GFP_KERNEL, move || {
            // SAFETY: This independent worker runs in sleepable context.
            unsafe { bindings::msleep(20) };
            resume.resume.complete_all();
        });
        if let Err(error) = queued {
            state.resume.complete_all();
            return Err(error.into());
        }
        target.control().stop();
        assert_eq!(accepted, 1024);
        assert_eq!(state.errors.load(Relaxed), 1025);
        assert_eq!(target.control().error(), Err(ESHUTDOWN));
        target.control().stop();
        assert_eq!(state.errors.load(Relaxed), 1025);
        Ok(())
    }
}
