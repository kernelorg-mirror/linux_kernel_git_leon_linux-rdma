// SPDX-License-Identifier: GPL-2.0

//! Owned completion values and bounded writes to kernel polling output.

use crate::{
    bindings,
    prelude::*,
    sync::{
        atomic::{
            Acquire,
            Atomic,
            AtomicFlag,
            Relaxed,
            Release, //
        },
        Arc,
        Completion as DrainCompletion,
        Mutex,
        Refcount,
        SpinLockIrq, //
    }, //
};
use core::{
    cell::Cell,
    marker::PhantomData, //
};

/// A revocable completion identity, independent of the core QP allocation.
///
/// Kernel consumers must retain their QPs while handling returned completions. This handle
/// does not retain QP resources, and the adapter revokes it before freeing the core header.
/// Revocation rejects subsequent authorization; it does not wait for concurrent polling or
/// completion handling. Native callers must synchronize those operations before releasing
/// request callback storage, including across QP reset.
#[derive(Clone)]
pub struct QueuePairIdentity {
    inner: Arc<QueuePairLifetime>,
    number: u32,
}

struct PostingState {
    generation: Arc<AtomicFlag>,
    gate: Arc<PostingGate>,
    closed: bool,
}

#[pin_data]
struct PostingGate {
    users: Refcount,
    #[pin]
    drained: DrainCompletion,
}

impl PostingGate {
    fn new() -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(Self {
                users: Refcount::new(1),
                drained <- DrainCompletion::new(),
            }),
            GFP_KERNEL_ACCOUNT,
        )
    }

    fn put(&self) {
        if self.users.dec_and_test() {
            self.drained.complete_all();
        }
    }
}

/// One posting callback admitted before RESET closes the current gate.
pub(super) struct PostingGuard(Arc<PostingGate>);

impl Drop for PostingGuard {
    fn drop(&mut self) {
        self.0.put();
    }
}

struct QueuePairLifetime {
    address: usize,
    send: usize,
    receive: usize,
    shared: Option<SharedReceiveIdentity>,
    live: AtomicFlag,
    posting: Pin<KBox<SpinLockIrq<PostingState>>>,
    modification: Pin<KBox<Mutex<()>>>,
    send_drain: Arc<DrainControl>,
    receive_drain: Arc<DrainControl>,
}

#[derive(Clone)]
pub(super) struct SharedReceiveIdentity(Arc<()>);

impl SharedReceiveIdentity {
    pub(super) fn new() -> Result<Self> {
        Ok(Self(Arc::new((), GFP_KERNEL_ACCOUNT)?))
    }
}

impl QueuePairIdentity {
    /// # Safety
    ///
    /// The adapter must supply the QP and its retained completion parents, publish the final
    /// number before exposing the identity, and revoke it before releasing the core header.
    pub(super) unsafe fn new(
        qp: *mut bindings::ib_qp,
        send: *mut bindings::ib_cq,
        receive: *mut bindings::ib_cq,
        shared: Option<SharedReceiveIdentity>,
    ) -> Result<Self> {
        let posting = new_posting_state()?;
        let modification = KBox::pin_init(crate::new_mutex!(()), GFP_KERNEL_ACCOUNT)?;
        Ok(Self {
            inner: Arc::new(
                QueuePairLifetime {
                    address: qp as usize,
                    send: send as usize,
                    receive: receive as usize,
                    shared,
                    live: AtomicFlag::new(true),
                    posting,
                    modification,
                    send_drain: DrainControl::new()?,
                    receive_drain: DrainControl::new()?,
                },
                GFP_KERNEL_ACCOUNT,
            )?,
            number: 0,
        })
    }

    fn new_generation() -> Result<Arc<AtomicFlag>> {
        Ok(Arc::new(AtomicFlag::new(true), GFP_KERNEL_ACCOUNT)?)
    }

    pub(super) fn begin_post(&self) -> Result<PostingGuard> {
        let posting = self.inner.posting.lock();
        if posting.closed {
            return Err(EBUSY);
        }
        // An open gate retains its initial reference until RESET closes it under this lock.
        posting.gate.users.inc();
        Ok(PostingGuard(posting.gate.clone()))
    }

    /// Serializes modification and drains admitted posting callbacks before a RESET.
    pub(super) fn modify(&self, reset: bool, apply: impl FnOnce() -> Result) -> Result {
        let _modification = self.inner.modification.lock();
        if !reset {
            return apply();
        }
        // Allocate before closing admission or changing provider state. A fresh gate is
        // needed even on failure because completion notifications are permanent.
        let replacement = PostingGate::new()?;
        let generation = Self::new_generation()?;
        let gate = {
            let mut posting = self.inner.posting.lock();
            posting.closed = true;
            posting.gate.put();
            posting.gate.clone()
        };
        gate.drained.wait_for_completion();
        let result = apply();
        let mut posting = self.inner.posting.lock();
        if result.is_ok() {
            posting.generation.store(false, Release);
            posting.generation = generation;
        }
        posting.gate = replacement;
        posting.closed = false;
        result
    }

    pub(super) fn drain_control(&self, receive: bool) -> &Arc<DrainControl> {
        if receive {
            &self.inner.receive_drain
        } else {
            &self.inner.send_drain
        }
    }

    pub(super) fn set_number(&mut self, number: u32) {
        self.number = number;
    }

    pub(super) fn revoke(&self) {
        self.inner.live.store(false, Release);
    }

    pub(super) fn origin(&self, receive: bool) -> CompletionOrigin {
        CompletionOrigin::QueuePair(self.clone(), receive)
    }

    /// Returns the captured QP number without accessing the QP allocation.
    #[inline]
    pub fn number(&self) -> u32 {
        self.number
    }
}

fn new_posting_state() -> Result<Pin<KBox<SpinLockIrq<PostingState>>>> {
    let state = PostingState {
        generation: QueuePairIdentity::new_generation()?,
        gate: PostingGate::new()?,
        closed: false,
    };
    KBox::pin_init(crate::new_spinlock_irq!(state), GFP_KERNEL_ACCOUNT)
}

#[derive(Clone)]
pub(super) enum CompletionOrigin {
    QueuePair(QueuePairIdentity, bool),
    SharedReceive(SharedReceiveIdentity),
}

struct NativeIdentifier {
    value: u64,
    origin: CompletionOrigin,
    emitted: AtomicFlag,
    generation: Option<Arc<AtomicFlag>>,
}

const DRAIN_ACTIVE: u64 = 1;
const DRAIN_EMITTED: u64 = 2;
const DRAIN_FLAGS: u64 = DRAIN_ACTIVE | DRAIN_EMITTED;
const DRAIN_EPOCH_STEP: u64 = DRAIN_FLAGS + 1;

/// Creator-accounted capability storage reserved exclusively for one native drain direction.
///
/// This control never retains its QP. Escaped identifiers retain independent control storage,
/// and their captured epoch prevents an old clone from authorizing a later drain callback.
/// One atomic word combines the 62-bit epoch and its active/emitted flags. Authorization may
/// run beneath a provider's raw lock, so it must not acquire a regular kernel spinlock.
/// The word does not publish other data: the immutable identifier is published by its owner.
pub(super) struct DrainControl {
    state: Atomic<u64>,
}

impl DrainControl {
    fn new() -> Result<Arc<Self>> {
        Ok(Arc::new(
            Self {
                state: Atomic::new(0),
            },
            GFP_KERNEL_ACCOUNT,
        )?)
    }

    /// A successful caller owns this reservation until it revokes the epoch after completion.
    /// Reject overlap and exhaustion without invalidating any previously captured identifier.
    pub(super) fn capture(
        self: &Arc<Self>,
        qp: &QueuePairIdentity,
        receive: bool,
        value: u64,
    ) -> Result<CompletionId> {
        let mut state = self.state.load(Relaxed);
        let epoch = loop {
            if state & DRAIN_ACTIVE != 0 {
                return Err(EBUSY);
            }
            let epoch = (state & !DRAIN_FLAGS)
                .checked_add(DRAIN_EPOCH_STEP)
                .ok_or(EOVERFLOW)?;
            match self.state.cmpxchg(state, epoch | DRAIN_ACTIVE, Relaxed) {
                Ok(_) => break epoch,
                Err(current) => state = current,
            }
        };
        Ok(CompletionId(Identifier::Drain(DrainIdentifier {
            value,
            origin: qp.origin(receive),
            control: self.clone(),
            epoch,
        })))
    }

    /// Releases the current reservation; only its successful capture owner may call this.
    pub(super) fn revoke(&self) {
        let mut state = self.state.load(Relaxed);
        while let Err(current) = self.state.cmpxchg(state, state & !DRAIN_FLAGS, Relaxed) {
            state = current;
        }
    }
}

#[derive(Clone)]
struct DrainIdentifier {
    value: u64,
    origin: CompletionOrigin,
    control: Arc<DrainControl>,
    epoch: u64,
}

#[derive(Clone)]
enum Identifier {
    User(u64),
    Native(Arc<NativeIdentifier>),
    Drain(DrainIdentifier),
}

/// An opaque completion identifier with a single native emission capability.
///
/// Scalar userspace identifiers cannot authorize native callbacks. Native request cursors
/// supply capabilities only for accepted requests; clones share one emission state.
#[derive(Clone)]
pub struct CompletionId(Identifier);

impl Default for CompletionId {
    fn default() -> Self {
        Self::user(0)
    }
}

impl CompletionId {
    /// Copies a userspace identifier, without authorizing a kernel completion callback.
    #[inline]
    pub const fn user(value: u64) -> Self {
        Self(Identifier::User(value))
    }

    pub(super) fn capture(value: u64, origin: Option<&CompletionOrigin>) -> Result<Self> {
        match origin {
            Some(origin) => Ok(Self(Identifier::Native(Arc::new(
                NativeIdentifier {
                    value,
                    origin: origin.clone(),
                    emitted: AtomicFlag::new(false),
                    generation: match origin {
                        CompletionOrigin::QueuePair(qp, _) => {
                            Some(qp.inner.posting.lock().generation.clone())
                        }
                        CompletionOrigin::SharedReceive(_) => None,
                    },
                },
                GFP_ATOMIC,
            )?))),
            None => Ok(Self::user(value)),
        }
    }

    /// Returns scalar ABI bytes without granting permission to invoke a native callback.
    #[inline]
    pub fn value(&self) -> u64 {
        match &self.0 {
            Identifier::User(value) => *value,
            Identifier::Native(native) => native.value,
            Identifier::Drain(drain) => drain.value,
        }
    }

    fn emit(&self, qp: &QueuePairIdentity, cq: usize) -> Result<u64> {
        let (origin, generation, value) = match &self.0 {
            Identifier::User(_) => return Err(EINVAL),
            Identifier::Native(native) => {
                (&native.origin, native.generation.as_ref(), native.value)
            }
            // The drain owns its callback storage until its active reservation is revoked.
            // A queued sentinel must survive RESET just like a native CQ entry does.
            Identifier::Drain(drain) => (&drain.origin, None, drain.value),
        };
        if !qp.inner.live.load(Acquire) {
            return Err(ENODEV);
        }
        if generation.is_some_and(|generation| !generation.load(Acquire)) {
            return Err(ENODEV);
        }
        let expected = match origin {
            CompletionOrigin::QueuePair(origin, receive) => {
                if !Arc::ptr_eq(&origin.inner, &qp.inner) {
                    return Err(EINVAL);
                }
                if *receive {
                    qp.inner.receive
                } else {
                    qp.inner.send
                }
            }
            CompletionOrigin::SharedReceive(origin) => {
                if !qp
                    .inner
                    .shared
                    .as_ref()
                    .is_some_and(|shared| Arc::ptr_eq(&origin.0, &shared.0))
                {
                    return Err(EINVAL);
                }
                qp.inner.receive
            }
        };
        if cq != expected {
            return Err(EINVAL);
        }
        match &self.0 {
            Identifier::Native(native) => {
                if native.emitted.xchg(true, Relaxed) {
                    return Err(EALREADY);
                }
            }
            Identifier::Drain(drain) => {
                let expected = drain.epoch | DRAIN_ACTIVE;
                match drain
                    .control
                    .state
                    .cmpxchg(expected, expected | DRAIN_EMITTED, Relaxed)
                {
                    Ok(_) => {}
                    Err(state) if state == expected | DRAIN_EMITTED => return Err(EALREADY),
                    Err(_) => return Err(ENODEV),
                }
            }
            Identifier::User(_) => unreachable!(),
        }
        Ok(value)
    }
}

/// Records the cursor's authoritative accepted prefix for its native posting adapter.
pub(super) type PostingOutcome = Cell<Option<Result>>;

/// Completion metadata and request provenance, without a QP pointer or storage borrow.
#[derive(Clone, Default)]
pub struct CompletionData {
    /// Opaque identifier supplied with the posted request.
    pub id: CompletionId,
    /// Completion status from `enum ib_wc_status`.
    pub status: u32,
    /// Completed operation from `enum ib_wc_opcode`.
    pub opcode: u32,
    /// Provider-specific diagnostic value.
    pub vendor_error: u32,
    /// Number of completed bytes.
    pub length: u32,
    /// Immediate or invalidation data in the byte order of the selected union member.
    pub immediate: [u8; 4],
    /// Source QP number.
    pub source: u32,
    /// Source local identifier.
    pub source_lid: u32,
    /// Flags from `enum ib_wc_flags` selecting valid optional fields.
    pub flags: u32,
    /// Partition key index.
    pub pkey_index: u16,
    /// Service level.
    pub service_level: u8,
    /// Destination local identifier path bits.
    pub destination_path: u8,
    /// Local port number.
    pub port: u32,
    /// Source Ethernet address.
    pub source_mac: [u8; 6],
    /// Received VLAN identifier.
    pub vlan: u16,
    /// Received network header type.
    pub network: u8,
}

/// A completion value which can be kept in provider-owned kernel storage.
///
/// Its QP identity is only copied to the polling caller; no method dereferences it.
#[derive(Clone)]
pub struct Completion {
    qp: QueuePairIdentity,
    data: CompletionData,
}

impl Completion {
    /// Size of the C kernel completion ABI, including its padding.
    pub const CORE_SIZE: usize = size_of::<bindings::ib_wc>();

    /// Constructs a completion without retaining its QP or request storage.
    #[inline]
    pub fn new(qp: QueuePairIdentity, data: CompletionData) -> Self {
        Self { qp, data }
    }

    fn into_raw(self, cq: usize) -> Result<bindings::ib_wc> {
        let mut wc = bindings::ib_wc::default();
        wc.__bindgen_anon_1.wr_id = self.data.id.emit(&self.qp, cq)?;
        wc.status = self.data.status;
        wc.opcode = self.data.opcode;
        wc.vendor_err = self.data.vendor_error;
        wc.byte_len = self.data.length;
        wc.qp = self.qp.inner.address as *mut bindings::ib_qp;
        wc.ex.imm_data = u32::from_ne_bytes(self.data.immediate);
        wc.src_qp = self.data.source;
        wc.slid = self.data.source_lid;
        wc.wc_flags = self.data.flags as c_int;
        wc.pkey_index = self.data.pkey_index;
        wc.sl = self.data.service_level;
        wc.dlid_path_bits = self.data.destination_path;
        wc.port_num = self.data.port;
        wc.smac = self.data.source_mac;
        wc.vlan_id = self.data.vlan;
        wc.network_hdr_type = self.data.network;
        Ok(wc)
    }
}

/// Bounded output granted by a kernel completion-polling caller.
///
/// # Invariants
///
/// `output` denotes `capacity` writable C completions, with exclusive access for `'a`.
/// Their contents need not be initialized. `written` never exceeds `capacity`.
/// `device` is the retained CQ's device and its port range remains unchanged for `'a`.
pub struct CompletionOutput<'a> {
    cq: usize,
    device: *mut bindings::ib_device,
    output: *mut bindings::ib_wc,
    capacity: usize,
    written: usize,
    _borrow: PhantomData<&'a mut [core::mem::MaybeUninit<bindings::ib_wc>]>,
}

impl<'a> CompletionOutput<'a> {
    /// Borrows a polling caller's output array without reading uninitialized entries.
    ///
    /// # Safety
    ///
    /// Positive `count` requires an aligned array of that many writable completions, fitting
    /// within Rust's maximum allocation size, with exclusive access for `'a`. A nonpositive
    /// count denotes an empty array and permits a null output pointer. `cq` must be non-null and
    /// identify the retained, initialized CQ, whose initialized device and port range remain
    /// live and unchanged for `'a`. Kernel callers must retain native request callbacks and QPs
    /// while handling the returned completions, according to the verbs completion contract.
    #[inline]
    pub unsafe fn from_raw(
        cq: *mut bindings::ib_cq,
        output: *mut bindings::ib_wc,
        count: c_int,
    ) -> Self {
        // INVARIANT: The caller retains the CQ's initialized device and grants the complete
        // array exclusively; nothing is written yet.
        Self {
            cq: cq as usize,
            // SAFETY: The caller retains this initialized CQ and its device.
            device: unsafe { (*cq).device },
            output,
            capacity: count.max(0) as usize,
            written: 0,
            _borrow: PhantomData,
        }
    }

    /// Returns how many more entries fit in this output.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.capacity - self.written
    }

    /// Returns the number of initialized completions written so far.
    #[inline]
    pub fn written(&self) -> usize {
        self.written
    }

    /// Writes one completion after checking its native provenance and consuming its token.
    ///
    /// A user scalar, mismatched CQ or QP, revoked QP, duplicate emission, out-of-range port,
    /// or full output fails without writing an entry. Port zero remains valid for completions
    /// without port metadata. Only a successful write consumes the native token.
    pub fn push(&mut self, completion: Completion) -> Result {
        if self.remaining() == 0 {
            return Err(ENOSPC);
        }
        // Native completion consumers may index port_data regardless of status or flags.
        // Port zero is its allocated initial slot and represents absent completion metadata.
        // SAFETY: The invariant retains the device and its initialized, unchanged port range.
        if unsafe { bindings::rdma_is_port_valid(self.device, completion.data.port) } == 0
            && completion.data.port != 0
        {
            return Err(EINVAL);
        }
        // SAFETY: The invariant grants this in-bounds element exclusively. A whole-value write
        // initializes every field without reading the old storage or dereferencing the QP.
        unsafe {
            self.output
                .add(self.written)
                .write(completion.into_raw(self.cq)?)
        };
        self.written += 1;
        Ok(())
    }
}

#[cfg(CONFIG_RUST_KUNIT_TESTS)]
#[crate::macros::kunit_tests(rust_rdma_completion)]
mod tests {
    use super::*;

    // Synthetic QP addresses are never dereferenced; CQ addresses are compared as identities.
    fn identity(shared: Option<SharedReceiveIdentity>) -> Result<QueuePairIdentity> {
        identity_for_cq(shared, 1)
    }

    fn identity_for_cq(
        shared: Option<SharedReceiveIdentity>,
        send: usize,
    ) -> Result<QueuePairIdentity> {
        Ok(QueuePairIdentity {
            inner: Arc::new(
                QueuePairLifetime {
                    address: 0,
                    send,
                    receive: 2,
                    shared,
                    live: AtomicFlag::new(true),
                    posting: new_posting_state()?,
                    modification: KBox::pin_init(crate::new_mutex!(()), GFP_KERNEL)?,
                    send_drain: DrainControl::new()?,
                    receive_drain: DrainControl::new()?,
                },
                GFP_KERNEL,
            )?,
            number: 17,
        })
    }

    #[test]
    fn native_identifier_checks_generation_direction_and_single_emission() -> Result {
        let qp = identity(None)?;
        let other = identity(None)?;
        let id = CompletionId::capture(0x1234, Some(&qp.origin(false)))?;
        let duplicate = id.clone();
        assert_eq!(CompletionId::user(0x1234).emit(&qp, 1), Err(EINVAL));
        assert_eq!(id.emit(&other, 1), Err(EINVAL));
        assert_eq!(id.emit(&qp, 2), Err(EINVAL));
        assert_eq!(id.emit(&qp, 1), Ok(0x1234));
        assert_eq!(duplicate.emit(&qp, 1), Err(EALREADY));
        let receive = CompletionId::capture(7, Some(&qp.origin(true)))?;
        assert_eq!(receive.emit(&qp, 1), Err(EINVAL));
        assert_eq!(receive.emit(&qp, 2), Ok(7));
        Ok(())
    }

    #[test]
    fn shared_receive_identifier_matches_attached_generation() -> Result {
        let shared = SharedReceiveIdentity::new()?;
        let qp = identity(Some(shared.clone()))?;
        let other = identity(Some(SharedReceiveIdentity::new()?))?;
        let private = identity(None)?;
        let origin = CompletionOrigin::SharedReceive(shared);
        let id = CompletionId::capture(19, Some(&origin))?;
        assert_eq!(id.emit(&other, 2), Err(EINVAL));
        assert_eq!(id.emit(&private, 2), Err(EINVAL));
        assert_eq!(id.emit(&qp, 1), Err(EINVAL));
        assert_eq!(id.emit(&qp, 2), Ok(19));
        Ok(())
    }

    #[test]
    fn revocation_rejects_retained_completion_identifiers() -> Result {
        let qp = identity(None)?;
        let retained = qp.clone();
        let id = CompletionId::capture(29, Some(&qp.origin(false)))?;
        qp.revoke();
        assert_eq!(id.emit(&retained, 1), Err(ENODEV));
        Ok(())
    }

    #[test]
    fn reset_revokes_old_requests_without_retiring_the_qp() -> Result {
        let qp = identity(None)?;
        let old = CompletionId::capture(37, Some(&qp.origin(false)))?;
        let duplicate = old.clone();
        qp.modify(true, || {
            assert!(matches!(qp.begin_post(), Err(EBUSY)));
            Ok(())
        })?;
        assert_eq!(old.emit(&qp, 1), Err(ENODEV));
        assert_eq!(duplicate.emit(&qp, 1), Err(ENODEV));
        let new = CompletionId::capture(37, Some(&qp.origin(false)))?;
        assert_eq!(new.emit(&qp, 1), Ok(37));
        Ok(())
    }

    #[test]
    fn failed_reset_reopens_posting_and_preserves_old_requests() -> Result {
        let qp = identity(None)?;
        let old = CompletionId::capture(43, Some(&qp.origin(false)))?;
        assert_eq!(
            qp.modify(true, || {
                assert!(matches!(qp.begin_post(), Err(EBUSY)));
                Err(EINVAL)
            }),
            Err(EINVAL)
        );
        let _posting = qp.begin_post()?;
        assert_eq!(old.emit(&qp, 1), Ok(43));
        Ok(())
    }

    #[test]
    fn reserved_drain_rejects_old_clones_and_duplicate_delivery() -> Result {
        let qp = identity(None)?;
        let other = identity(None)?;
        let control = qp.drain_control(false);
        let first = control.capture(&qp, false, 61)?;
        let old = first.clone();
        assert_eq!(first.emit(&other, 1), Err(EINVAL));
        assert_eq!(first.emit(&qp, 2), Err(EINVAL));
        assert_eq!(first.emit(&qp, 1), Ok(61));
        assert_eq!(old.emit(&qp, 1), Err(EALREADY));
        control.revoke();
        assert_eq!(old.emit(&qp, 1), Err(ENODEV));
        let next = control.capture(&qp, false, 61)?;
        assert_eq!(old.emit(&qp, 1), Err(ENODEV));
        assert_eq!(next.emit(&qp, 1), Ok(61));
        control.revoke();
        Ok(())
    }

    #[test]
    fn reserved_drain_revokes_unemitted_requests() -> Result {
        let qp = identity(None)?;
        let control = qp.drain_control(true);
        let abandoned = control.capture(&qp, true, 67)?;
        control.revoke();
        let next = control.capture(&qp, true, 71)?;
        assert_eq!(abandoned.emit(&qp, 2), Err(ENODEV));
        assert_eq!(next.emit(&qp, 2), Ok(71));
        control.revoke();
        assert_eq!(next.emit(&qp, 2), Err(ENODEV));
        Ok(())
    }

    #[test]
    fn queued_drain_completion_survives_reset() -> Result {
        let qp = identity(None)?;
        let control = qp.drain_control(false);
        let reserved = control.capture(&qp, false, 91)?;
        let ordinary = CompletionId::capture(93, Some(&qp.origin(false)))?;
        let queued = Completion::new(
            qp.clone(),
            CompletionData {
                id: reserved.clone(),
                ..Default::default()
            },
        );
        let normal = Completion::new(
            qp.clone(),
            CompletionData {
                id: ordinary,
                ..Default::default()
            },
        );
        qp.modify(true, || Ok(()))?;
        assert!(matches!(normal.into_raw(1), Err(ENODEV)));
        let raw = queued.clone().into_raw(1)?;
        // SAFETY: into_raw initialized the scalar member with this captured identifier.
        assert_eq!(unsafe { raw.__bindgen_anon_1.wr_id }, 91);
        assert!(matches!(queued.clone().into_raw(1), Err(EALREADY)));
        control.revoke();
        assert!(matches!(queued.into_raw(1), Err(ENODEV)));
        let next = control.capture(&qp, false, 97)?;
        qp.revoke();
        assert_eq!(next.emit(&qp, 1), Err(ENODEV));
        control.revoke();
        Ok(())
    }

    #[test]
    fn reserved_drain_busy_capture_preserves_original_request() -> Result {
        let qp = identity(None)?;
        let control = qp.drain_control(false);
        let first = control.capture(&qp, false, 87)?;
        let epoch = control.state.load(Relaxed);
        assert!(matches!(control.capture(&qp, false, 89), Err(EBUSY)));
        assert_eq!(control.state.load(Relaxed), epoch);
        assert_eq!(first.emit(&qp, 1), Ok(87));
        // Emission does not release the reservation: its callback still has to return.
        assert!(matches!(control.capture(&qp, false, 89), Err(EBUSY)));
        assert_eq!(first.emit(&qp, 1), Err(EALREADY));
        control.revoke();
        let next = control.capture(&qp, false, 89)?;
        assert_eq!(first.emit(&qp, 1), Err(ENODEV));
        assert_eq!(next.emit(&qp, 1), Ok(89));
        control.revoke();
        Ok(())
    }

    #[test]
    fn reserved_drain_epoch_exhaustion_never_revalidates_a_clone() -> Result {
        let qp = identity(None)?;
        let control = qp.drain_control(false);
        let first = control.capture(&qp, false, 73)?;
        control.revoke();
        control.state.store(!DRAIN_FLAGS, Relaxed);
        assert!(matches!(control.capture(&qp, false, 73), Err(EOVERFLOW)));
        assert_eq!(first.emit(&qp, 1), Err(ENODEV));
        Ok(())
    }

    #[pin_data]
    struct EmissionRace {
        #[pin]
        ready: DrainCompletion,
        #[pin]
        start: DrainCompletion,
        #[pin]
        done: DrainCompletion,
        result: Atomic<i32>,
    }

    #[test]
    fn concurrent_reserved_emission_authorizes_only_one_callback() -> Result {
        let qp = identity(None)?;
        let control = qp.drain_control(false);
        let id = control.capture(&qp, false, 101)?;
        let race = Arc::pin_init(
            pin_init!(EmissionRace {
                ready <- DrainCompletion::new(),
                start <- DrainCompletion::new(),
                done <- DrainCompletion::new(),
                result: Atomic::new(EIO.to_errno()),
            }),
            GFP_KERNEL,
        )?;
        let worker = race.clone();
        let other_id = id.clone();
        let other_qp = qp.clone();
        crate::workqueue::system_dfl().try_spawn(GFP_KERNEL, move || {
            worker.ready.complete_all();
            worker.start.wait_for_completion();
            let result = other_id
                .emit(&other_qp, 1)
                .map_or_else(|error| error.to_errno(), |_| 0);
            worker.result.store(result, Relaxed);
            worker.done.complete_all();
        })?;
        race.ready.wait_for_completion();
        race.start.complete_all();
        let result = id.emit(&qp, 1).map_or_else(|error| error.to_errno(), |_| 0);
        race.done.wait_for_completion();
        let other = race.result.load(Relaxed);
        assert!(
            (result == 0 && other == EALREADY.to_errno())
                || (other == 0 && result == EALREADY.to_errno())
        );
        control.revoke();
        Ok(())
    }

    struct RawEmission<'a> {
        id: &'a CompletionId,
        qp: &'a QueuePairIdentity,
        result: Result<u64>,
    }

    /// # Safety
    ///
    /// The caller exclusively borrows a live RawEmission until this callback returns.
    unsafe extern "C" fn emit_under_raw_lock(context: *mut crate::ffi::c_void) {
        // SAFETY: The test retains this exclusive context and both borrowed owners across
        // the synchronous callback. Emission does not allocate or release either owner.
        let context = unsafe { &mut *context.cast::<RawEmission<'_>>() };
        context.result = context.id.emit(context.qp, 1);
    }

    #[test]
    fn reserved_emission_is_valid_beneath_a_raw_provider_lock() -> Result {
        let qp = identity(None)?;
        let control = qp.drain_control(false);
        let id = control.capture(&qp, false, 103)?;
        let mut context = RawEmission {
            id: &id,
            qp: &qp,
            result: Err(EIO),
        };
        // SAFETY: The helper synchronously invokes this nonblocking callback under its
        // private raw lock. All referenced allocations remain owned outside that lock.
        unsafe {
            bindings::rust_rdma_test_with_raw_lock(
                Some(emit_under_raw_lock),
                core::ptr::from_mut(&mut context).cast(),
            )
        };
        assert_eq!(context.result, Ok(103));
        assert_eq!(id.emit(&qp, 1), Err(EALREADY));
        control.revoke();
        Ok(())
    }

    #[test]
    fn reserved_cursors_accept_the_sentinel_before_provider_error() -> Result {
        let qp = identity(None)?;
        let send = bindings::ib_send_wr::default();
        let receive = bindings::ib_recv_wr::default();
        let mut bad_send = core::ptr::null();
        let mut bad_receive = core::ptr::null();
        let send_outcome = PostingOutcome::new(None);
        let receive_outcome = PostingOutcome::new(None);
        let send_control = qp.drain_control(false);
        let receive_control = qp.drain_control(true);
        let send_id = send_control.capture(&qp, false, 79)?;
        // SAFETY: The descriptor-free nodes and exclusive failure outputs remain live. The
        // distinct reserved IDs prove traversal uses the prepared capability, not wr_id=0.
        let sends = unsafe {
            super::super::SendRequests::<()>::from_raw(
                &send,
                &mut bad_send,
                super::super::QueuePairType::ReliableConnected,
            )
        }
        .track(Some(qp.origin(false)), &send_outcome)
        .with_reserved(send_id);
        assert_eq!(
            sends.try_for_each(|request| {
                assert_eq!(request.completion_id().emit(&qp, 1), Ok(79));
                Err(EIO)
            }),
            Ok(())
        );
        assert_eq!(send_outcome.get(), Some(Ok(())));
        send_control.revoke();

        let receive_id = receive_control.capture(&qp, true, 83)?;
        // SAFETY: The initialized receive node and exclusive failure output remain live.
        let receives =
            unsafe { super::super::ReceiveRequests::from_raw(&receive, &mut bad_receive) }
                .track(Some(qp.origin(true)), &receive_outcome)
                .with_reserved(receive_id);
        assert_eq!(
            receives.try_for_each(|request| {
                assert_eq!(request.completion_id().emit(&qp, 2), Ok(83));
                Err(EIO)
            }),
            Ok(())
        );
        assert_eq!(receive_outcome.get(), Some(Ok(())));
        receive_control.revoke();
        Ok(())
    }

    #[test]
    fn full_output_preserves_the_unemitted_capability() -> Result {
        let mut device = KBox::new(bindings::ib_device::default(), GFP_KERNEL)?;
        let mut cq = bindings::ib_cq {
            device: &raw mut *device,
            ..Default::default()
        };
        let cq_address = &raw mut cq;
        let qp = identity_for_cq(None, cq_address as usize)?;
        let id = CompletionId::capture(31, Some(&qp.origin(false)))?;
        // SAFETY: The initialized CQ and device remain live, and an empty output permits null.
        let mut output =
            unsafe { CompletionOutput::from_raw(cq_address, core::ptr::null_mut(), 0) };
        let completion = Completion::new(
            qp.clone(),
            CompletionData {
                id: id.clone(),
                ..Default::default()
            },
        );
        assert_eq!(output.push(completion), Err(ENOSPC));
        assert_eq!(id.emit(&qp, cq_address as usize), Ok(31));
        Ok(())
    }

    #[test]
    fn invalid_port_preserves_output_and_completion_capability() -> Result {
        let mut device = KBox::new(bindings::ib_device::default(), GFP_KERNEL)?;
        device.phys_port_cnt = 1;
        let mut cq = bindings::ib_cq {
            device: &raw mut *device,
            ..Default::default()
        };
        let cq_address = &raw mut cq;
        let qp = identity_for_cq(None, cq_address as usize)?;
        let id = CompletionId::capture(47, Some(&qp.origin(false)))?;
        let mut raw = [bindings::ib_wc {
            port_num: 0xdead,
            ..Default::default()
        }; 2];
        // SAFETY: The initialized local CQ and device outlive the cursor, their port range
        // remains unchanged, and raw is exclusively writable for this scope.
        let mut output = unsafe { CompletionOutput::from_raw(cq_address, raw.as_mut_ptr(), 2) };
        let completion = |port| {
            Completion::new(
                qp.clone(),
                CompletionData {
                    id: id.clone(),
                    port,
                    ..Default::default()
                },
            )
        };
        assert_eq!(output.push(completion(2)), Err(EINVAL));
        assert_eq!(output.push(completion(u32::MAX)), Err(EINVAL));
        assert_eq!(output.written(), 0);
        // SAFETY: Failed pushes wrote no element and there is no concurrent cursor access.
        assert_eq!(unsafe { (*output.output).port_num }, 0xdead);
        output.push(completion(1))?;
        assert_eq!(output.written(), 1);
        // SAFETY: Successful push initialized this element and no access is concurrent.
        assert_eq!(unsafe { (*output.output).port_num }, 1);
        assert_eq!(id.emit(&qp, cq_address as usize), Err(EALREADY));
        output.push(Completion::new(
            qp.clone(),
            CompletionData {
                id: CompletionId::capture(53, Some(&qp.origin(false)))?,
                ..Default::default()
            },
        ))?;
        assert_eq!(output.written(), 2);
        // SAFETY: Both entries are initialized and retained exclusively by this cursor.
        assert_eq!(unsafe { (*output.output.add(1)).port_num }, 0);
        Ok(())
    }
}
