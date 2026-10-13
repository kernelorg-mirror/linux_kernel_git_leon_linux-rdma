// SPDX-License-Identifier: GPL-2.0

//! Owned provider data and callbacks for basic shared receive queues.

use super::{
    queued_event::Events,
    ContextData,
    Operations,
    ProtectionDomainOperations,
    ProtectionDomains,
    ReleaseError,
    ScatterGather,
    UserContextOperations,
    UserData, //
};
use crate::{
    bindings,
    prelude::*,
    sync::Arc,
    types::{
        ForeignOwnable,
        Opaque, //
    }, //
};
use core::{
    marker::PhantomData,
    ptr, //
};

/// One immutable kernel receive request and its scatter/gather descriptors.
///
/// # Invariants
///
/// The request's identifier, count and next pointer remain initialized and unchanged for
/// `'a`. A positive descriptor count requires an initialized pointer satisfying
/// [`ScatterGather::from_raw`]; described addresses confer no permission to access memory.
pub struct ReceiveRequest<'a> {
    raw: *const bindings::ib_recv_wr,
    _borrow: PhantomData<&'a bindings::ib_recv_wr>,
}

impl ReceiveRequest<'_> {
    /// Returns the opaque identifier to reproduce in a completion.
    #[inline]
    pub fn id(&self) -> u64 {
        // SAFETY: The caller initialized either identifier member. The native boundary
        // materializes unused bytes when a pointer is narrower than the opaque identifier.
        unsafe { bindings::ib_recv_wr_id(self.raw) }
    }

    /// Returns the supplied descriptor count before validation.
    #[inline]
    pub fn scatter_gather_count(&self) -> c_int {
        // SAFETY: The initialized count remains stable for this borrow.
        unsafe { (*self.raw).num_sge }
    }

    /// Borrows descriptors without borrowing or accessing their described memory.
    #[inline]
    pub fn scatter_gather(&self) -> Result<&[ScatterGather]> {
        let count = self.scatter_gather_count();
        if count < 0 {
            return Err(EINVAL);
        }
        if count == 0 {
            return Ok(&[]);
        }
        // SAFETY: A positive count requires an initialized pointer and a stable descriptor
        // array. Zero and negative counts do not read the potentially uninitialized pointer.
        unsafe { ScatterGather::from_raw((*self.raw).sg_list, count) }
    }
}

/// A kernel receive-request chain and its first-failure output.
///
/// # Invariants
///
/// The acyclic chain and descriptor arrays remain live and unchanged for `'a`. Each node
/// satisfies [`ReceiveRequest`]'s invariant. `bad` is writable on failure and does not alias
/// any request or descriptor. No other writer accesses `bad` while this cursor exists.
pub struct ReceiveRequests<'a> {
    next: *const bindings::ib_recv_wr,
    bad: *mut *const bindings::ib_recv_wr,
    _borrow: PhantomData<&'a mut *const bindings::ib_recv_wr>,
}

#[cfg(CONFIG_RUST_KUNIT_TESTS)]
#[crate::macros::kunit_tests(rust_rdma_receive_requests)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    #[test]
    fn early_rejection_initializes_failure_output() -> Result {
        let request = bindings::ib_recv_wr::default();
        let mut bad = MaybeUninit::uninit();
        // SAFETY: The initialized request remains live and has no descriptors. The failure
        // output is writable but deliberately uninitialized.
        let requests = unsafe { ReceiveRequests::from_raw(&request, bad.as_mut_ptr()) };
        let reject = |_requests: ReceiveRequests<'_>| Err::<(), _>(EINVAL);
        assert_eq!(reject(requests), Err(EINVAL));
        // SAFETY: Construction initializes the failure output even without cursor traversal.
        assert_eq!(unsafe { bad.assume_init() }, &raw const request);
        Ok(())
    }
}

impl<'a> ReceiveRequests<'a> {
    /// Borrows a kernel posting chain, which may be empty.
    ///
    /// # Safety
    ///
    /// The chain, descriptor arrays and failure output must satisfy the type invariant for
    /// `'a`. Each caller initializes either `wr_id` or `wr_cqe`; unused union bytes are not
    /// required to be initialized.
    #[inline]
    pub unsafe fn from_raw(
        first: *const bindings::ib_recv_wr,
        bad: *mut *const bindings::ib_recv_wr,
    ) -> Self {
        // SAFETY: The caller grants writable, nonaliasing output. A provider may reject
        // the entire chain before visiting it, so establish that failure result now.
        unsafe { bad.write(first) };
        // INVARIANT: The caller retains the stable chain and grants the output exclusively.
        Self {
            next: first,
            bad,
            _borrow: PhantomData,
        }
    }

    /// Visits requests in order and records the first request rejected by the provider.
    ///
    /// A successful prefix remains posted. The failure output is unspecified on success.
    pub fn try_for_each(mut self, mut post: impl FnMut(ReceiveRequest<'_>) -> Result) -> Result {
        while !self.next.is_null() {
            // INVARIANT: The cursor's contract retains this request and its descriptor array.
            if let Err(error) = post(ReceiveRequest {
                raw: self.next,
                _borrow: PhantomData,
            }) {
                // SAFETY: The caller grants writable, nonaliasing failure output.
                unsafe { self.bad.write(self.next) };
                return Err(error);
            }
            // SAFETY: The cursor retains the initialized, unchanged next link.
            self.next = unsafe { (*self.next).next };
        }
        Ok(())
    }

    /// Rejects posting before visiting requests and records the first request, possibly null.
    #[inline]
    pub fn reject(self, error: Error) -> Result {
        // SAFETY: The cursor owns writable, nonaliasing failure output even for an empty chain.
        unsafe { self.bad.write(self.next) };
        Err(error)
    }
}

/// Initial or queried basic SRQ attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedReceiveAttributes {
    /// Maximum outstanding receive requests.
    pub max_wr: u32,
    /// Maximum scatter/gather descriptors per request.
    pub max_sge: u32,
    /// Armed one-shot notification threshold, or zero when disarmed.
    pub limit: u32,
}

/// Selected changes; unselected C fields are never read.
pub struct SharedReceiveChange {
    /// Requested queue capacity, if selected.
    pub max_wr: Option<u32>,
    /// Requested notification threshold, if selected.
    pub limit: Option<u32>,
    /// Mask bits not represented by this interface, for provider validation.
    pub unknown_mask: u32,
}

/// Asynchronous events pertaining to a shared receive queue.
pub enum SharedReceiveEvent {
    /// The queue encountered a fatal error.
    Error,
    /// The number of available requests fell below the armed threshold.
    LimitReached,
}

/// A borrowed core SRQ; a borrow does not confer access to mutable core fields.
///
/// # Invariants
///
/// This is an initialized SRQ created by [`BasicSharedReceiveQueues<T>`]. The core SRQ,
/// device, event callback and callback context remain live throughout a borrow, with
/// destruction excluded.
#[repr(transparent)]
pub struct SharedReceiveQueue<T> {
    core: Opaque<bindings::ib_srq>,
    _provider: PhantomData<T>,
}

impl<T> SharedReceiveQueue<T> {
    /// Borrows an initialized core SRQ with its destruction excluded.
    ///
    /// # Safety
    ///
    /// `srq` must satisfy the type invariant for `'a`.
    #[inline]
    pub unsafe fn from_raw<'a>(srq: *mut bindings::ib_srq) -> &'a Self {
        // SAFETY: The caller retains the initialized core object; transparent layout matches.
        unsafe { &*srq.cast() }
    }

    /// Returns whether the creator installed an event callback.
    #[inline]
    pub fn has_event_handler(&self) -> bool {
        // SAFETY: The callback is immutable after creation and the core allocation is retained.
        unsafe { (*self.core.get()).event_handler.is_some() }
    }

    /// Schedules an SRQ event for sleepable task context.
    ///
    /// Posting uses preallocated counters; overflow returns [`EOVERFLOW`] and active drainage
    /// returns [`ESHUTDOWN`]. Delivery uses a system worker or the task destroying the object.
    /// Repeated occurrences are preserved; delivery order between different kinds is unspecified.
    /// Accepted events remain independent of any attached QP and drain before SRQ private state
    /// is released. The callback must not synchronously destroy this SRQ.
    ///
    /// Call from process or softirq context without a raw spinlock held. On PREEMPT_RT this
    /// requires task or threaded interrupt context with hard interrupts enabled.
    pub fn event(&self, kind: SharedReceiveEvent) -> Result {
        let encoding = match kind {
            SharedReceiveEvent::Error => bindings::ib_event_type_IB_EVENT_SRQ_ERR,
            SharedReceiveEvent::LimitReached => bindings::ib_event_type_IB_EVENT_SRQ_LIMIT_REACHED,
        };
        // SAFETY: This borrow retains the initialized adapter allocation and excludes release.
        unsafe {
            (*self.core.get().cast::<OwnedQueue>())
                .events
                .post(encoding)
        }
    }
}

/// Basic SRQ operations implemented by pinned provider device data.
///
/// Creation, modification, query and release may sleep. Posting cannot sleep and may run
/// with interrupts disabled on non-RT kernels, but must not hold a raw spinlock. On PREEMPT_RT,
/// posting requires task or threaded interrupt context with hard interrupts enabled. The provider
/// must serialize its queue and control state; the core does not serialize concurrent modification,
/// query, posting or internal consumers.
/// The core or kernel caller excludes release while attached QPs and ordinary verbs callbacks
/// remain live.
pub trait BasicSharedReceiveOperations: ProtectionDomainOperations + UserContextOperations {
    /// Private state owned by the core SRQ until successful release.
    type SharedReceive: ForeignOwnable + Send + Sync + 'static;

    /// Creates a basic SRQ and updates its actual capacities before publication.
    fn create_shared_receive(
        self: Pin<&Self>,
        domain: <Self::Domain as ForeignOwnable>::Borrowed<'_>,
        attributes: &mut SharedReceiveAttributes,
        data: Option<ContextData<'_, Self>>,
    ) -> Result<Self::SharedReceive>;

    /// Applies selected changes and returns any rounded capacity through `change`.
    fn modify_shared_receive(
        self: Pin<&Self>,
        queue: <Self::SharedReceive as ForeignOwnable>::Borrowed<'_>,
        change: &mut SharedReceiveChange,
        data: Option<ContextData<'_, Self>>,
    ) -> Result;

    /// Samples current queue attributes.
    fn query_shared_receive(
        self: Pin<&Self>,
        queue: <Self::SharedReceive as ForeignOwnable>::Borrowed<'_>,
    ) -> Result<SharedReceiveAttributes>;

    /// Posts a linked kernel request chain, recording the first failure through its cursor.
    fn post_shared_receive(
        self: Pin<&Self>,
        queue: <Self::SharedReceive as ForeignOwnable>::Borrowed<'_>,
        requests: ReceiveRequests<'_>,
    ) -> Result;

    /// Releases private state after attached QPs and core users have drained.
    ///
    /// Additional internal users may retain private provider state, which must be unpublished
    /// and drained before success. They must not retain a [`SharedReceiveQueue`] borrow across
    /// entry to this callback: such a borrow excludes release, including event drainage.
    /// Failure returns a valid owner for subsequent operations and release attempts.
    fn release_shared_receive(
        self: Pin<&Self>,
        owner: Self::SharedReceive,
        _data: Option<UserData<'_, Self>>,
    ) -> Result<(), ReleaseError<Self::SharedReceive>> {
        drop(owner);
        Ok(())
    }
}

#[repr(C)]
struct OwnedQueue {
    core: bindings::ib_srq,
    private_data: *mut c_void,
    events: Arc<Events>,
}

/// Installs owned provider data and callbacks for basic SRQs.
///
/// XRC and tag-matching creation are rejected because their extended resources are not
/// represented by this adapter. The core retains ownership of each SRQ's header and memory.
pub struct BasicSharedReceiveQueues<T: BasicSharedReceiveOperations>(PhantomData<T>);

impl<T: BasicSharedReceiveOperations> BasicSharedReceiveQueues<T> {
    /// Installs callbacks before device publication.
    ///
    /// # Safety
    ///
    /// The device must be exclusively owned and unpublished, with [`Operations::<T>::install`],
    /// [`ProtectionDomains::<T>::install`] and [`super::UserContexts::<T>::install`] completed.
    /// Its `create_srq`, `modify_srq`, `query_srq`, `post_srq_recv`, `destroy_srq` and
    /// `size_ib_srq` slots must be unused and remain exclusively managed by this adapter.
    pub unsafe fn install(device: *mut bindings::ib_device) {
        // SAFETY: The caller exclusively owns the unpublished device and reserves these slots.
        unsafe {
            (*device).ops.size_ib_srq = size_of::<OwnedQueue>();
            (*device).ops.create_srq = Some(Self::create);
            (*device).ops.modify_srq = Some(Self::modify);
            (*device).ops.query_srq = Some(Self::query);
            (*device).ops.post_srq_recv = Some(Self::post);
            (*device).ops.destroy_srq = Some(Self::release);
        }
    }

    /// Borrows private data while the core retains this initialized SRQ.
    ///
    /// # Safety
    ///
    /// The SRQ must belong to this adapter. The caller must retain it and its device and
    /// exclude release attempts, including unsuccessful ones, for `'a`.
    #[inline]
    pub unsafe fn data<'a>(
        srq: *mut bindings::ib_srq,
    ) -> <T::SharedReceive as ForeignOwnable>::Borrowed<'a> {
        // SAFETY: The initialized slot retains its foreign owner and release is excluded.
        unsafe { T::SharedReceive::borrow((*srq.cast::<OwnedQueue>()).private_data) }
    }

    /// # Safety
    ///
    /// The core must provide unpublished storage of the installed size, retain this adapter's
    /// initialized device and parents, and supply stable selected attributes and original
    /// uverbs data with disassociation excluded.
    unsafe extern "C" fn create(
        srq: *mut bindings::ib_srq,
        attributes: *mut bindings::ib_srq_init_attr,
        data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core owns unpublished storage of our configured size, retains the device
        // and domain, and initializes the header. Only basic attributes are read. The original
        // uverbs bundle retains a successfully initialized context and excludes disassociation.
        unsafe {
            if (*attributes).srq_type != bindings::ib_srq_type_IB_SRQT_BASIC {
                return EOPNOTSUPP.to_errno();
            }
            let data = match ContextData::from_raw(data) {
                Ok(data) => data,
                Err(error) => return error.to_errno(),
            };
            let events = match Events::new(
                bindings::ib_event {
                    device: (*srq).device,
                    element: bindings::ib_event__bindgen_ty_1 { srq },
                    ..Default::default()
                },
                (*srq).event_handler,
                if (*srq).uobject.is_null() {
                    (*srq).srq_context
                } else {
                    // The uverbs handler uses the SRQ's uobject. Legacy creation does not
                    // initialize its unused context, so do not read it into a Rust value.
                    ptr::null_mut()
                },
            ) {
                Ok(events) => events,
                Err(error) => return error.to_errno(),
            };
            let mut attr = SharedReceiveAttributes {
                max_wr: (*attributes).attr.max_wr,
                max_sge: (*attributes).attr.max_sge,
                limit: (*attributes).attr.srq_limit,
            };
            match Operations::<T>::data((*srq).device).create_shared_receive(
                ProtectionDomains::<T>::data((*srq).pd),
                &mut attr,
                data,
            ) {
                Ok(owner) => {
                    (*attributes).attr.max_wr = attr.max_wr;
                    (*attributes).attr.max_sge = attr.max_sge;
                    (*attributes).attr.srq_limit = attr.limit;
                    (*srq.cast::<OwnedQueue>()).private_data = owner.into_foreign();
                    (&raw mut (*srq.cast::<OwnedQueue>()).events).write(events);
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain this adapter's initialized object and parents, exclude release
    /// attempts, and supply stable initialized selected attributes and any original uverbs
    /// data.
    unsafe extern "C" fn modify(
        srq: *mut bindings::ib_srq,
        attributes: *mut bindings::ib_srq_attr,
        mask: bindings::ib_srq_attr_mask,
        data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The caller retains the SRQ and device, excludes release and owns attributes.
        // Unselected attribute fields may be uninitialized and are not read. The original
        // userspace bundle retains its initialized context with disassociation excluded.
        unsafe {
            let data = match ContextData::from_raw(data) {
                Ok(data) => data,
                Err(error) => return error.to_errno(),
            };
            let mut change = SharedReceiveChange {
                max_wr: (mask & bindings::ib_srq_attr_mask_IB_SRQ_MAX_WR != 0)
                    .then(|| (*attributes).max_wr),
                limit: (mask & bindings::ib_srq_attr_mask_IB_SRQ_LIMIT != 0)
                    .then(|| (*attributes).srq_limit),
                unknown_mask: mask
                    & !(bindings::ib_srq_attr_mask_IB_SRQ_MAX_WR
                        | bindings::ib_srq_attr_mask_IB_SRQ_LIMIT),
            };
            match Operations::<T>::data((*srq).device).modify_shared_receive(
                Self::data(srq),
                &mut change,
                data,
            ) {
                Ok(()) => {
                    if mask & bindings::ib_srq_attr_mask_IB_SRQ_MAX_WR != 0 {
                        if let Some(count) = change.max_wr {
                            (*attributes).max_wr = count;
                        }
                    }
                    if mask & bindings::ib_srq_attr_mask_IB_SRQ_LIMIT != 0 {
                        if let Some(limit) = change.limit {
                            (*attributes).srq_limit = limit;
                        }
                    }
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain this adapter's initialized object and parents, exclude release
    /// attempts, and provide aligned, exclusively writable complete output storage.
    unsafe extern "C" fn query(
        srq: *mut bindings::ib_srq,
        attributes: *mut bindings::ib_srq_attr,
    ) -> c_int {
        // SAFETY: The caller retains initialized SRQ data, excludes release and grants writable
        // output. Whole-field writes initialize the result without reading uninitialized bytes.
        unsafe {
            match Operations::<T>::data((*srq).device).query_shared_receive(Self::data(srq)) {
                Ok(attr) => {
                    (*attributes).max_wr = attr.max_wr;
                    (*attributes).max_sge = attr.max_sge;
                    (*attributes).srq_limit = attr.limit;
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The posting caller retains the SRQ and immutable request chain, initializes
    /// identifiers and descriptor arrays, and must grant writable first-failure output.
    unsafe extern "C" fn post(
        srq: *mut bindings::ib_srq,
        request: *const bindings::ib_recv_wr,
        bad: *mut *const bindings::ib_recv_wr,
    ) -> c_int {
        // SAFETY: The posting caller retains the SRQ and immutable request chain, initializes
        // identifiers and descriptor arrays, and grants writable first-failure output.
        unsafe {
            Operations::<T>::data((*srq).device)
                .post_shared_receive(Self::data(srq), ReceiveRequests::from_raw(request, bad))
                .map_or_else(|error| error.to_errno(), |()| 0)
        }
    }

    /// # Safety
    ///
    /// The core must exclude further operations and release this adapter's initialized owner
    /// exactly once, while retaining its allocation and parents until this callback returns.
    unsafe extern "C" fn release(
        srq: *mut bindings::ib_srq,
        data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core or kernel caller drained attached QPs and excludes further callbacks
        // during release. The installed device stays live; an error restores the returned owner
        // before the core permits further operations. No private owner escapes on success.
        unsafe {
            // Native users and attached QPs are excluded, so no safe event producer remains.
            // Drain before taking private ownership: callbacks may query the live SRQ. The
            // control is rearmed so a failed release can restore ordinary event delivery.
            (*srq.cast::<OwnedQueue>()).events.drain();
            let slot = &raw mut (*srq.cast::<OwnedQueue>()).private_data;
            let owner = T::SharedReceive::from_foreign(ptr::replace(slot, ptr::null_mut()));
            match Operations::<T>::data((*srq).device)
                .release_shared_receive(owner, UserData::from_raw(data))
            {
                Ok(()) => {
                    ptr::drop_in_place(&raw mut (*srq.cast::<OwnedQueue>()).events);
                    0
                }
                Err(ReleaseError { error, owner }) => {
                    slot.write(owner.into_foreign());
                    error.to_errno()
                }
            }
        }
    }
}
