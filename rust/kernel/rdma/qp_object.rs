// SPDX-License-Identifier: GPL-2.0

//! Core-allocated queue pairs with opaque headers and drained provider references.

mod drain;

use super::{
    completion::PostingOutcome,
    queued_event::Events,
    AddressHandleOperations,
    BasicSharedReceiveOperations,
    BasicSharedReceiveQueues,
    CompletionQueue,
    CompletionQueueOperations,
    CompletionQueues,
    ContextData,
    Device,
    MemoryRegionOperations,
    Operations,
    ProtectionDomainOperations,
    ProtectionDomains,
    QueuePairAttributes,
    QueuePairCapacity,
    QueuePairChange,
    QueuePairIdentity,
    QueuePairInitAttributes,
    QueuePairState,
    QueuePairType,
    ReceiveRequests,
    SendRequests,
    SharedReceiveQueue,
    UserData, //
};
use crate::{
    bindings,
    prelude::*,
    sync::{
        Arc,
        Refcount, //
    },
    types::{
        ForeignOwnable,
        Opaque, //
    }, //
};

use core::{
    marker::PhantomData,
    ops::Deref,
    ptr::{
        self,
        NonNull, //
    }, //
};

/// Private ownership, publication storage and actual attributes of a newly built QP.
pub struct QueuePairCreation<O, P> {
    /// Native state retained until successful destruction drains every provider reference.
    pub owner: O,
    /// Preallocated provider storage for infallible publication.
    pub publication: P,
    /// QP number to publish in the core header.
    pub number: u32,
    /// Actual queue capacities, preserving the requested private receive mode.
    pub capacity: QueuePairCapacity,
}

/// A provider's complete query response.
pub struct QueuePairQuery {
    /// Current native attributes.
    pub attributes: QueuePairAttributes,
    /// Port to report in the creation-attribute output.
    pub creation_port: u32,
}

/// Asynchronous events reported for a retained QP.
#[derive(Clone, Copy)]
pub enum QueuePairEvent {
    /// The QP encountered a fatal error.
    Fatal,
    /// A work request could not be processed.
    RequestError,
    /// The QP encountered an access violation.
    AccessError,
    /// Communication has been established.
    CommunicationEstablished,
    /// The send queue has drained.
    SendQueueDrained,
    /// The last receive request associated with an SRQ-backed QP has completed.
    LastReceiveCompleted,
    /// The alternate path has become active.
    PathMigrated,
    /// Automatic migration could not use the alternate path.
    PathMigrationError,
}

impl QueuePairEvent {
    fn encoding(self) -> bindings::ib_event_type {
        match self {
            Self::Fatal => bindings::ib_event_type_IB_EVENT_QP_FATAL,
            Self::RequestError => bindings::ib_event_type_IB_EVENT_QP_REQ_ERR,
            Self::AccessError => bindings::ib_event_type_IB_EVENT_QP_ACCESS_ERR,
            Self::CommunicationEstablished => bindings::ib_event_type_IB_EVENT_COMM_EST,
            Self::SendQueueDrained => bindings::ib_event_type_IB_EVENT_SQ_DRAINED,
            Self::PathMigrated => bindings::ib_event_type_IB_EVENT_PATH_MIG,
            Self::PathMigrationError => bindings::ib_event_type_IB_EVENT_PATH_MIG_ERR,
            Self::LastReceiveCompleted => bindings::ib_event_type_IB_EVENT_QP_LAST_WQE_REACHED,
        }
    }
}

/// Native queue-pair operations implemented by pinned provider data.
///
/// Creation, modification, query, retirement and release may sleep. Posting and ringing a
/// userspace doorbell may run with interrupts disabled and must not sleep or hold a raw spinlock.
/// On PREEMPT_RT, posting requires task or threaded interrupt context with hard interrupts enabled,
/// as required by the adapter's regular admission spinlock. The provider
/// serializes mutable native state; the core does not serialize query against modification.
pub trait QueuePairOperations:
    ProtectionDomainOperations
    + CompletionQueueOperations
    + BasicSharedReceiveOperations
    + AddressHandleOperations
    + MemoryRegionOperations
{
    /// One owner transferred into each successfully created queue pair.
    type QueuePair: ForeignOwnable + Send + Sync + 'static;
    /// Preallocated storage consumed by publication.
    type QueuePairPublication;

    /// Builds native state while the core retains the unpublished QP's parents.
    ///
    /// No fallible adapter operation follows success. The returned capacity must preserve
    /// whether the request uses a private receive queue. Creation must retain no reference to
    /// temporary attributes or user buffers; mapped backing requires independent ownership.
    fn create_queue_pair(
        self: Pin<&Self>,
        parents: QueuePairParents<'_, Self>,
        attributes: QueuePairInitAttributes,
        data: Option<ContextData<'_, Self>>,
    ) -> Result<QueuePairCreation<Self::QueuePair, Self::QueuePairPublication>>;

    /// Publishes the first provider reference after native and core initialization completes.
    ///
    /// Retain this reference in the provider lookup structure until retirement. Idle work
    /// items must not retain a reference back to their own QP; queued invocations may do so.
    fn publish_queue_pair(
        self: Pin<&Self>,
        qp: QueuePairRef<Self>,
        publication: Self::QueuePairPublication,
    );

    /// Applies selected native attributes while the core retains the QP and optional udata.
    fn modify_queue_pair(
        self: Pin<&Self>,
        qp: &QueuePair<Self>,
        change: QueuePairChange,
        data: Option<UserData<'_, Self>>,
    ) -> Result;

    /// Returns owned attributes and the reported creation port.
    fn query_queue_pair(
        self: Pin<&Self>,
        qp: &QueuePair<Self>,
        mask: u32,
    ) -> Result<QueuePairQuery>;

    /// Posts kernel send work, preserving the successful prefix on failure.
    fn post_send(
        self: Pin<&Self>,
        qp: &QueuePair<Self>,
        requests: SendRequests<'_, Self>,
    ) -> Result;

    /// Posts kernel receive work to a private receive queue.
    fn post_receive(
        self: Pin<&Self>,
        qp: &QueuePair<Self>,
        requests: ReceiveRequests<'_>,
    ) -> Result;

    /// Schedules work published by the userspace provider.
    fn ring_send_queue(self: Pin<&Self>, qp: &QueuePair<Self>) -> Result;

    /// Stops publication and releases provider references before destruction waits for users.
    ///
    /// Retirement must complete even during creation rollback, when the core immediately frees
    /// its allocation. Stop timers and workers and flush packets holding QP references before
    /// returning. Leaving such references dependent on later release would deadlock the drain.
    fn retire_queue_pair(self: Pin<&Self>, qp: &QueuePair<Self>, data: Option<UserData<'_, Self>>);

    /// Releases native state in the destroying task after every provider reference has drained.
    ///
    /// The device and parents remain live until this returns. The core frees its own allocation.
    fn release_queue_pair(self: Pin<&Self>, owner: Self::QueuePair) {
        drop(owner);
    }
}

// Immutable shadow pointers, initialized before publication. Core creation rewrites CQ fields
// after the provider callback returns, so asynchronous provider users must not read that header.
struct Parents {
    device: *mut bindings::ib_device,
    domain: *mut bindings::ib_pd,
    send: *mut bindings::ib_cq,
    receive: *mut bindings::ib_cq,
    shared: *mut bindings::ib_srq,
}

/// Parents retained by the core or its creator during QP construction.
///
/// # Invariants
///
/// The device, domain and both CQs belong to T's installed adapters and remain initialized
/// with release excluded throughout `'a`. A non-null shared queue satisfies the same contract.
pub struct QueuePairParents<'a, T> {
    inner: &'a Parents,
    _provider: PhantomData<T>,
}

impl<T: QueuePairOperations> QueuePairParents<'_, T> {
    /// Borrows the parent RDMA device.
    #[inline]
    pub fn device(&self) -> &Device<T> {
        // SAFETY: The invariant retains the initialized device belonging to T.
        unsafe { Device::from_raw(self.inner.device) }
    }

    /// Borrows native protection-domain data.
    #[inline]
    pub fn domain(&self) -> <T::Domain as ForeignOwnable>::Borrowed<'_> {
        // SAFETY: The invariant excludes release of T's installed domain owner.
        unsafe { ProtectionDomains::<T>::data(self.inner.domain) }
    }

    /// Borrows the send CQ during fallible QP construction.
    #[inline]
    pub fn send_completion(&self) -> &CompletionQueue<T> {
        // SAFETY: The construction invariant retains the initialized CQ belonging to T.
        unsafe { CompletionQueue::from_raw(self.inner.send) }
    }

    /// Borrows the receive CQ during fallible QP construction.
    #[inline]
    pub fn receive_completion(&self) -> &CompletionQueue<T> {
        // SAFETY: The construction invariant retains the initialized CQ belonging to T.
        unsafe { CompletionQueue::from_raw(self.inner.receive) }
    }

    /// Borrows the optional SRQ during fallible QP construction.
    #[inline]
    pub fn shared_receive(&self) -> Option<&SharedReceiveQueue<T>> {
        if self.inner.shared.is_null() {
            None
        } else {
            // SAFETY: A non-null shadow names T's retained, initialized basic SRQ.
            Some(unsafe { SharedReceiveQueue::from_raw(self.inner.shared) })
        }
    }

    /// Returns whether the QP owns a private receive queue.
    #[inline]
    pub fn has_private_receive(&self) -> bool {
        self.inner.shared.is_null()
    }
}

/// A borrowed QP whose C header remains opaque to native provider users.
///
/// # Invariants
///
/// Published instances are initialized by `QueuePairs<T>` for a QueuePairOperations provider.
/// Their immutable shadow fields, initialized foreign owner and parents remain live throughout
/// a core callback or provider reference. Destruction waits for `drained` before consuming
/// native ownership. The core retains the allocation and parents through final release.
#[repr(C)]
pub struct QueuePair<T> {
    core: Opaque<bindings::ib_qp>,
    parents: Parents,
    identity: QueuePairIdentity,
    private_data: Opaque<*mut c_void>,
    users: Refcount,
    drained: Opaque<bindings::completion>,
    kind: QueuePairType,
    signaling: u32,
    user: bool,
    events: Arc<Events>,
    event_context: *mut c_void,
    _provider: PhantomData<fn() -> T>,
}

// SAFETY: Only initialized instances with Send + Sync foreign ownership are published.
// Mutable C fields are opaque; native shared data is synchronized by its own types. Core
// ownership retains the allocation and parents until all provider references drain.
unsafe impl<T> Send for QueuePair<T> {}
// SAFETY: Shared access observes only immutable shadows or synchronized native ownership.
unsafe impl<T> Sync for QueuePair<T> {}

impl<T: QueuePairOperations> QueuePair<T> {
    /// Borrows native state while a core callback or provider reference retains it.
    #[inline]
    pub fn data(&self) -> <T::QueuePair as ForeignOwnable>::Borrowed<'_> {
        // SAFETY: The initialized foreign owner is immutable and retained for this borrow.
        unsafe { T::QueuePair::borrow(*self.private_data.get()) }
    }

    /// Borrows the provider data retained by the QP's parent device.
    #[inline]
    pub fn provider(&self) -> Pin<&T> {
        // SAFETY: The type invariant retains the initialized Operations<T> installation.
        unsafe { Operations::<T>::data(self.parents.device) }
    }

    /// Borrows immutable parent identities without reading mutable core QP fields.
    #[inline]
    pub fn parents(&self) -> QueuePairParents<'_, T> {
        // INVARIANT: Core ownership retains these initialized parents through QP destruction.
        QueuePairParents {
            inner: &self.parents,
            _provider: PhantomData,
        }
    }

    /// Borrows the parent RDMA device.
    #[inline]
    pub fn device(&self) -> &Device<T> {
        // SAFETY: Core ownership retains the initialized parent device for this borrow.
        unsafe { Device::from_raw(self.parents.device) }
    }

    /// Returns the transport fixed during creation.
    #[inline]
    pub fn kind(&self) -> QueuePairType {
        self.kind
    }

    /// Returns whether the QP was created through userspace verbs.
    #[inline]
    pub fn is_user(&self) -> bool {
        self.user
    }

    /// Returns whether every send should produce a completion.
    #[inline]
    pub fn signals_all_sends(&self) -> bool {
        self.signaling == bindings::ib_sig_type_IB_SIGNAL_ALL_WR
    }

    /// Acquires an asynchronous reference unless retirement has drained the last one.
    #[inline]
    pub fn try_ref(&self) -> Option<QueuePairRef<T>> {
        if !self.users.inc_not_zero() {
            return None;
        }
        // INVARIANT: This borrow retained initialized storage until a nonzero reference was
        // acquired. Destruction now waits for the returned handle; zero cannot be resurrected.
        Some(QueuePairRef {
            qp: NonNull::from(self),
        })
    }

    /// Captures the immutable core number and opaque completion identity.
    #[inline]
    pub fn identity(&self) -> QueuePairIdentity {
        self.identity.clone()
    }

    /// Selects a RoCEv2 UDP source port using the common RDMA flow-label convention.
    ///
    /// A zero flow label is derived symmetrically from this QP's number and `remote`.
    #[inline]
    pub fn udp_source_port(&self, flow_label: u32, remote: u32) -> u16 {
        // SAFETY: The helper accepts scalar inputs and masks its result to the valid port range.
        unsafe { bindings::rdma_get_udp_sport(flow_label, self.identity().number(), remote) }
    }

    /// Borrows the send CQ, whose destruction is excluded by the core QP parent reference.
    #[inline]
    pub fn send_completion(&self) -> &CompletionQueue<T> {
        // SAFETY: The immutable shadow retains the CQ belonging to T's installed adapter.
        unsafe { CompletionQueue::from_raw(self.parents.send) }
    }

    /// Borrows native send CQ data for completion publication.
    #[inline]
    pub fn send_completion_data(&self) -> <T::CompletionQueue as ForeignOwnable>::Borrowed<'_> {
        // SAFETY: The core QP reference excludes all CQ release attempts.
        unsafe { CompletionQueues::<T>::data(self.parents.send) }
    }

    /// Borrows the receive CQ retained by the core QP.
    #[inline]
    pub fn receive_completion(&self) -> &CompletionQueue<T> {
        // SAFETY: The immutable shadow retains the CQ belonging to T's installed adapter.
        unsafe { CompletionQueue::from_raw(self.parents.receive) }
    }

    /// Borrows native receive CQ data for completion publication.
    #[inline]
    pub fn receive_completion_data(&self) -> <T::CompletionQueue as ForeignOwnable>::Borrowed<'_> {
        // SAFETY: The core QP reference excludes all CQ release attempts.
        unsafe { CompletionQueues::<T>::data(self.parents.receive) }
    }

    /// Borrows an attached SRQ, if present.
    #[inline]
    pub fn shared_receive(&self) -> Option<&SharedReceiveQueue<T>> {
        if self.parents.shared.is_null() {
            None
        } else {
            // SAFETY: A non-null shadow names T's retained, initialized basic SRQ.
            Some(unsafe { SharedReceiveQueue::from_raw(self.parents.shared) })
        }
    }

    /// Borrows the attached SRQ's native data, if present.
    #[inline]
    pub fn shared_receive_data(
        &self,
    ) -> Option<<T::SharedReceive as ForeignOwnable>::Borrowed<'_>> {
        if self.parents.shared.is_null() {
            None
        } else {
            // SAFETY: The retained SRQ belongs to this adapter and release is excluded.
            Some(unsafe { BasicSharedReceiveQueues::<T>::data(self.parents.shared) })
        }
    }

    /// Schedules a QP event for sleepable task context.
    ///
    /// Posting uses preallocated counters; overflow returns [`EOVERFLOW`] and active drainage
    /// returns [`ESHUTDOWN`]. Delivery uses a system worker or the task destroying the object.
    /// Repeated occurrences are preserved; delivery order between different kinds is unspecified.
    /// Accepted events retain the callback state through delivery; destruction waits for them
    /// before releasing provider state. The callback must not synchronously destroy this QP.
    ///
    /// Call from process or softirq context without a raw spinlock held. On PREEMPT_RT this
    /// requires task or threaded interrupt context with hard interrupts enabled.
    pub fn event(&self, kind: QueuePairEvent) -> Result {
        self.events.post(kind.encoding())
    }
}

/// One provider reference which delays QP destruction until it is dropped.
///
/// The last drop signals the destroying task; it does not release native state or parents.
///
/// # Invariants
///
/// `qp` names an initialized `QueuePair<T>` and this handle owns one nonzero provider reference.
/// The core retains the allocation, foreign owner and parents until all references drain.
pub struct QueuePairRef<T> {
    qp: NonNull<QueuePair<T>>,
}

// SAFETY: The counted reference retains a synchronized QP on any thread.
unsafe impl<T> Send for QueuePairRef<T> {}
// SAFETY: Sharing a handle exposes shared borrows and atomic reference operations only.
unsafe impl<T> Sync for QueuePairRef<T> {}

impl<T> Deref for QueuePairRef<T> {
    type Target = QueuePair<T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: The counted reference excludes destruction throughout the borrow.
        unsafe { self.qp.as_ref() }
    }
}

impl<T> Clone for QueuePairRef<T> {
    #[inline]
    fn clone(&self) -> Self {
        self.users.inc();
        // INVARIANT: The increment retains the same initialized QP and its parent owners.
        Self { qp: self.qp }
    }
}

impl<T> Drop for QueuePairRef<T> {
    fn drop(&mut self) {
        let drained = self.drained.get();
        if self.users.dec_and_test() {
            // SAFETY: Destruction retains this completion until the signal. No QP borrow
            // spans complete(), and no field is accessed afterward: the waiter may permit
            // core deallocation as soon as complete() releases its internal lock.
            unsafe { bindings::complete(drained) };
        }
    }
}

/// Installs basic QP callbacks while leaving the C allocation owned by the RDMA core.
pub struct QueuePairs<T: QueuePairOperations>(PhantomData<T>);

impl<T: QueuePairOperations> QueuePairs<T> {
    /// Installs callbacks and core-tail size before publishing a device.
    ///
    /// # Safety
    ///
    /// The caller exclusively owns an unpublished device with `Operations<T>`, `UserContexts<T>`,
    /// `ProtectionDomains<T>`, `CompletionQueues<T>`, `BasicSharedReceiveQueues<T>`,
    /// `AddressHandles<T>` and `MemoryRegions<T>` installed. QP create, destroy, modify, query,
    /// post, drain and size slots must be unused and remain managed by this adapter. The core or
    /// kernel caller retains the matching parents during creation and through successful
    /// synchronous destruction, and excludes other core QP operations during destruction.
    /// These basic QPs must not be opened as shared XRC QPs or have their core parent,
    /// callback, context or number fields replaced.
    pub unsafe fn install(device: *mut bindings::ib_device) {
        // SAFETY: The caller reserves these slots and owns the unpublished device exclusively.
        unsafe {
            (*device).ops.size_ib_qp = size_of::<QueuePair<T>>();
            (*device).ops.create_qp = Some(Self::create);
            (*device).ops.destroy_qp = Some(Self::destroy);
            (*device).ops.modify_qp = Some(Self::modify);
            (*device).ops.query_qp = Some(Self::query);
            (*device).ops.post_send = Some(Self::send);
            (*device).ops.post_recv = Some(Self::receive);
            (*device).ops.drain_sq = Some(Self::drain_send);
            (*device).ops.drain_rq = Some(Self::drain_receive);
        }
    }

    /// Borrows a successfully initialized QP while a core operation excludes destruction.
    ///
    /// # Safety
    ///
    /// `qp` must belong to this adapter and satisfy `QueuePair<T>`'s invariant for `'a`.
    #[inline]
    pub unsafe fn borrow<'a>(qp: *mut bindings::ib_qp) -> &'a QueuePair<T> {
        // SAFETY: The retained core header is the leading field of the initialized allocation.
        unsafe { &*qp.cast() }
    }

    /// # Safety
    ///
    /// The core must provide unpublished storage of the installed size, retain this adapter's
    /// initialized device and parents, and supply stable selected attributes and original
    /// uverbs data with disassociation excluded.
    unsafe extern "C" fn create(
        core: *mut bindings::ib_qp,
        attributes: *mut bindings::ib_qp_init_attr,
        data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core owns unpublished storage of the installed size, retains parents
        // belonging to T, and supplies stable selected input fields and original uverbs data.
        unsafe {
            let user = !data.is_null();
            let data = match ContextData::<T>::from_raw(data) {
                Ok(data) => data,
                Err(error) => return error.to_errno(),
            };
            let selected = match QueuePairInitAttributes::from_raw(attributes) {
                Ok(selected) => selected,
                Err(error) => return error.to_errno(),
            };
            let kind = selected.kind;
            let signaling = selected.signaling;
            let parents = Parents {
                device: (*core).device,
                domain: (*core).pd,
                send: (*attributes).send_cq,
                receive: (*attributes).recv_cq,
                shared: (*attributes).srq,
            };
            let shared = if parents.shared.is_null() {
                None
            } else {
                BasicSharedReceiveQueues::<T>::completion_identity(parents.shared)
            };
            let mut identity =
                match QueuePairIdentity::new(core, parents.send, parents.receive, shared) {
                    Ok(identity) => identity,
                    Err(error) => return error.to_errno(),
                };
            let provider = Operations::<T>::data(parents.device);
            let events = match Events::new(
                bindings::ib_event {
                    device: parents.device,
                    element: bindings::ib_event__bindgen_ty_1 { qp: core },
                    ..Default::default()
                },
                (*core).event_handler,
                (*core).qp_context,
            ) {
                Ok(events) => events,
                Err(error) => return error.to_errno(),
            };
            // INVARIANT: The core retains the matching initialized parents for creation.
            let borrowed = QueuePairParents {
                inner: &parents,
                _provider: PhantomData,
            };
            let created = match provider.create_queue_pair(borrowed, selected, data) {
                Ok(created) => created,
                Err(error) => return error.to_errno(),
            };
            identity.set_number(created.number);
            let raw = core.cast::<QueuePair<T>>();
            // Initialize only tail fields. A whole-object write or reference here would cover
            // the C header which the core has already initialized and will continue to mutate.
            (&raw mut (*raw).parents).write(parents);
            (&raw mut (*raw).identity).write(identity);
            (&raw mut (*raw).private_data).write(Opaque::new(created.owner.into_foreign()));
            (&raw mut (*raw).users).write(Refcount::new(1));
            (&raw mut (*raw).drained).write(Opaque::uninit());
            bindings::init_completion((*raw).drained.get());
            (&raw mut (*raw).kind).write(kind);
            (&raw mut (*raw).signaling).write(signaling);
            (&raw mut (*raw).user).write(user);
            (&raw mut (*raw).events).write(events);
            (&raw mut (*raw).event_context).write((*core).qp_context);
            (&raw mut (*raw)._provider).write(PhantomData);
            (*core).qp_num = created.number;
            created.capacity.write_to(&raw mut (*attributes).cap);
            // INVARIANT: Native ownership and immutable shadows are initialized. The core
            // owns stable storage and the initial reference is transferred to publication.
            provider.publish_queue_pair(
                QueuePairRef {
                    qp: NonNull::new_unchecked(raw),
                },
                created.publication,
            );
        }
        0
    }

    /// # Safety
    ///
    /// The caller must retain this adapter's initialized QP and parents in sleepable context,
    /// exclude destruction and supply stable selected fields and any original uverbs data.
    unsafe extern "C" fn modify(
        core: *mut bindings::ib_qp,
        attributes: *mut bindings::ib_qp_attr,
        mask: c_int,
        data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core retains the initialized QP and selected fields in sleepable context.
        unsafe {
            let qp = Self::borrow(core);
            let change = match QueuePairChange::from_raw(
                attributes,
                mask as u32,
                qp.parents.shared.is_null(),
            ) {
                Ok(change) => change,
                Err(error) => return error.to_errno(),
            };
            qp.identity
                .modify(change.state == Some(QueuePairState::Reset), || {
                    qp.provider()
                        .modify_queue_pair(qp, change, UserData::from_raw(data))
                })
        }
        .map_or_else(Error::to_errno, |()| 0)
    }

    /// # Safety
    ///
    /// The caller must retain this adapter's initialized object and parents, exclude release
    /// attempts, and provide aligned, exclusively writable complete output storage.
    unsafe extern "C" fn query(
        core: *mut bindings::ib_qp,
        attributes: *mut bindings::ib_qp_attr,
        mask: c_int,
        initial: *mut bindings::ib_qp_init_attr,
    ) -> c_int {
        // SAFETY: The core retains the QP and grants both complete output objects exclusively.
        unsafe {
            let qp = Self::borrow(core);
            let queried = match qp.provider().query_queue_pair(qp, mask as u32) {
                Ok(queried) => queried,
                Err(error) => return error.to_errno(),
            };
            let mut output = bindings::ib_qp_init_attr {
                event_handler: (*core).registered_event_handler,
                qp_context: qp.event_context,
                send_cq: qp.parents.send,
                recv_cq: qp.parents.receive,
                srq: qp.parents.shared,
                qp_type: qp.kind.encoding(),
                sq_sig_type: qp.signaling,
                port_num: queried.creation_port,
                ..Default::default()
            };
            queried.attributes.capacity.write_to(&mut output.cap);
            initial.write(output);
            queried.attributes.write_to(attributes);
        }
        0
    }

    /// # Safety
    ///
    /// The caller must retain the QP. Kernel callers retain each unaccepted request and its
    /// selected extensions, objects and inline sources, and grant exclusive failure output.
    /// Accepted nodes may be released by completion processing.
    unsafe extern "C" fn send(
        core: *mut bindings::ib_qp,
        first: *const bindings::ib_send_wr,
        bad: *mut *const bindings::ib_send_wr,
    ) -> c_int {
        // SAFETY: The core retains the QP. Kernel callers retain unaccepted requests and their
        // selected extensions, objects and inline sources, and grant exclusive failure output.
        unsafe {
            let qp = Self::borrow(core);
            if qp.user && !first.is_null() {
                bad.write(first);
                return EOPNOTSUPP.to_errno();
            }
            let _posting = match qp.identity.begin_post() {
                Ok(posting) => posting,
                Err(error) => {
                    bad.write(first);
                    return error.to_errno();
                }
            };
            if qp.user {
                qp.provider()
                    .ring_send_queue(qp)
                    .inspect_err(|_| bad.write(first))
            } else {
                let outcome = PostingOutcome::new(None);
                let requests = SendRequests::from_raw(first, bad, qp.kind)
                    .track(Some(qp.identity.origin(false)), &outcome);
                let result = qp.provider().post_send(qp, requests);
                outcome.get().unwrap_or(result)
            }
        }
        .map_or_else(Error::to_errno, |()| 0)
    }

    /// # Safety
    ///
    /// The caller must retain the QP; kernel callers retain each unaccepted receive request
    /// and its descriptors, and grant exclusive failure output. Accepted nodes may be released
    /// by completion processing. Providers reject unsupported receive modes.
    unsafe extern "C" fn receive(
        core: *mut bindings::ib_qp,
        first: *const bindings::ib_recv_wr,
        bad: *mut *const bindings::ib_recv_wr,
    ) -> c_int {
        // SAFETY: The core retains the QP; kernel callers retain unaccepted receive requests
        // and their descriptors, and grant exclusive failure output.
        unsafe {
            let qp = Self::borrow(core);
            let _posting = match qp.identity.begin_post() {
                Ok(posting) => posting,
                Err(error) => {
                    bad.write(first);
                    return error.to_errno();
                }
            };
            let outcome = PostingOutcome::new(None);
            let origin = (!qp.user).then(|| qp.identity.origin(true));
            let requests = ReceiveRequests::from_raw(first, bad).track(origin, &outcome);
            let result = qp.provider().post_receive(qp, requests);
            outcome.get().unwrap_or(result)
        }
        .map_or_else(Error::to_errno, |()| 0)
    }

    /// # Safety
    ///
    /// The core must retain this adapter's initialized QP allocation and parents, exclude
    /// other core operations, and permit sleeping. Optional udata must satisfy
    /// UserData::from_raw.
    unsafe extern "C" fn destroy(
        core: *mut bindings::ib_qp,
        data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core excludes other core operations and retains the allocation/parents
        // through release. Retirement stops lookup and reference-producing work before waiting.
        // The foreign borrow ends before ownership is recovered; only the core frees its header.
        unsafe {
            let raw = core.cast::<QueuePair<T>>();
            let provider = Operations::<T>::data((*raw).parents.device);
            provider.retire_queue_pair(Self::borrow(core), UserData::from_raw(data));
            bindings::wait_for_completion((*raw).drained.get());
            (*raw).events.drain();
            (*raw).identity.revoke();
            let owner = T::QueuePair::from_foreign(*(*raw).private_data.get());
            (*raw).private_data.get().write(ptr::null_mut());
            provider.release_queue_pair(owner);
            ptr::drop_in_place(&raw mut (*raw).identity);
            ptr::drop_in_place(&raw mut (*raw).events);
        }
        0
    }
}
