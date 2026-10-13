// SPDX-License-Identifier: GPL-2.0

//! Typed per-namespace state with revocable, generation-checked access.

use super::{
    Namespace,
    NamespaceRef, //
};
use crate::{
    bindings,
    error::{
        from_err_ptr,
        to_result, //
    },
    prelude::*,
    rbtree::{
        RBTree,
        RBTreeNodeReservation, //
    },
    sync::{
        Mutex,
        SetOnce,
        Srcu, //
    },
    types::{
        ForeignOwnable,
        Opaque,
        ScopeGuard, //
    }, //
};
use core::{
    any::TypeId,
    marker::PhantomData,
    ptr::NonNull, //
};

/// Owned state initialized separately in every network namespace.
///
/// Construction and destruction may sleep. They run under the core's namespace registration
/// semaphore and must not register or unregister namespace subsystems or network notifiers.
/// They must not register or unregister module notifiers either: initial construction can hold
/// the directory lifecycle lock, while module fallback cleanup takes that lock under the module
/// notifier read lock. State must retain any resources it needs through destruction, which can
/// follow the owning module's exit handler.
/// Avoid retaining active namespace references in this state: they can prevent its cleanup.
pub trait State: Send + Sync + Sized + 'static {
    /// Initializes state without retaining a namespace that is still being constructed.
    fn new() -> impl PinInit<Self, Error>;
}

struct Record {
    id: NonNull<c_uint>,
    operations: NonNull<bindings::pernet_operations>,
    owner: *mut bindings::module,
    generation: u64,
    active: bool,
}

// SAFETY: Registration storage stays pinned until its directory record is removed. The
// lifecycle lock excludes its destruction while module cleanup uses the stored pointers.
// The module notifier consumes owner identities before their modules are freed.
unsafe impl Send for Record {}

struct Entries {
    types: RBTree<TypeId, Record>,
    generation: u64,
}

#[pin_data]
struct Directory {
    #[pin]
    lifecycle: Mutex<()>,
    #[pin]
    entries: Mutex<Entries>,
    #[pin]
    readers: Srcu,
    #[pin]
    notifier: Opaque<bindings::notifier_block>,
}

// SAFETY: Both mutexes and SRCU synchronize directory access. The module notifier chain
// serializes its own linkage and retains this permanent pinned storage during callbacks.
unsafe impl Send for Directory {}
// SAFETY: Shared accesses use the directory locks or the native notifier-chain lock.
unsafe impl Sync for Directory {}

crate::sync::global_lock! {
    // SAFETY: directory() completes the single initializer before using this mutex.
    unsafe(uninit) static DIRECTORY: Mutex<Option<Pin<KBox<Directory>>>> = None;
}

static DIRECTORY_REF: SetOnce<&'static Directory> = SetOnce::new();

struct Initialization(Opaque<bindings::atomic_t>);

// SAFETY: The C helper accesses the initialization state only through native atomics.
unsafe impl Sync for Initialization {}

static DIRECTORY_INIT: Initialization =
    Initialization(Opaque::new(bindings::atomic_t { counter: 0 }));

extern "C" fn initialize() {
    // SAFETY: The shared atomic state permits exactly one non-sleeping initialization,
    // including when inline C helpers are emitted in more than one Rust object.
    unsafe { DIRECTORY.init() };
}

fn directory() -> Result<&'static Directory> {
    if let Some(directory) = DIRECTORY_REF.copy() {
        return Ok(directory);
    }
    // SAFETY: Every call supplies the same permanent atomic state and fixed initializer,
    // which neither allocates nor sleeps. The helper acquire-reads its release publication.
    unsafe { bindings::net_namespace_init_directory(DIRECTORY_INIT.0.get(), Some(initialize)) };
    let mut owner = DIRECTORY.lock();
    if owner.is_none() {
        let directory = KBox::pin_init(
            try_pin_init!(Directory {
                lifecycle <- crate::new_mutex!(()),
                entries <- crate::new_mutex!(Entries { types: RBTree::new(), generation: 0 }),
                readers <- crate::new_srcu!(),
                notifier: Opaque::new(bindings::notifier_block {
                    notifier_call: Some(Directory::module_notify),
                    next: core::ptr::null_mut(),
                    priority: 0,
                }),
            }),
            GFP_KERNEL,
        )?;
        // SAFETY: The initialized directory is pinned and becomes a permanent resident
        // owner. The callback recovers it directly, without taking DIRECTORY again.
        #[cfg(CONFIG_MODULES)]
        to_result(unsafe { bindings::register_module_notifier(directory.notifier.get()) })?;
        *owner = Some(directory);
    }
    let directory = core::ptr::from_ref(owner.as_ref().unwrap().as_ref().get_ref());
    // SAFETY: The private global owner is installed once and never removed. Its pinned
    // allocation and synchronization primitives remain live for the kernel's lifetime.
    let directory = unsafe { &*directory };
    // Native callbacks must not take the initialization mutex while a lifecycle operation
    // holds its lock. Publish the permanent reference before allowing any registration.
    DIRECTORY_REF.populate(directory);
    Ok(directory)
}

impl Directory {
    /// Reserves a type and its core identifier before registration.
    ///
    /// # Safety
    ///
    /// The caller must hold the lifecycle lock and keep `id` and `operations` pinned until
    /// removal, including rollback. `owner` must identify both callbacks and remain retained
    /// until registration finishes. Core callbacks must see the initialized ID.
    unsafe fn claim<T: State>(
        &self,
        id: NonNull<c_uint>,
        operations: NonNull<bindings::pernet_operations>,
        owner: *mut bindings::module,
    ) -> Result<Key<T>> {
        let reservation = RBTreeNodeReservation::new(GFP_KERNEL)?;
        let mut entries = self.entries.lock();
        let kind = TypeId::of::<T>();
        if entries.types.get(&kind).is_some() {
            return Err(EEXIST);
        }
        let generation = entries.generation.checked_add(1).ok_or(EOVERFLOW)?;
        entries.generation = generation;
        entries.types.insert(reservation.into_node(
            kind,
            Record {
                id,
                operations,
                owner,
                generation,
                active: false,
            },
        ));
        Ok(Key {
            generation,
            _type: PhantomData,
        })
    }

    fn set_active<T: State>(&self, active: bool) {
        self.entries
            .lock()
            .types
            .get_mut(&TypeId::of::<T>())
            .unwrap()
            .active = active;
    }

    fn remove<T: State>(&self) {
        let node = self.entries.lock().types.remove_node(&TypeId::of::<T>());
        drop(node);
    }

    /// Reads the identifier associated with a retained core callback.
    ///
    /// # Safety
    ///
    /// A paired core callback must retain the record and its initialized ID. This call must
    /// finish before register/unregister returns to the owner that can remove the record.
    unsafe fn callback_id<T: State>(&self) -> c_uint {
        let entries = self.entries.lock();
        let record = entries.types.get(&TypeId::of::<T>()).unwrap();
        // SAFETY: The core callback retains the pinned, initialized, immutable ID.
        unsafe { record.id.as_ptr().read() }
    }

    /// Closes one registration while the lifecycle mutex excludes its owner's destruction.
    fn close_locked(&self, kind: TypeId, generation: u64) {
        let operations = {
            let mut entries = self.entries.lock();
            let Some(record) = entries.types.get_mut(&kind) else {
                return;
            };
            if record.generation != generation {
                return;
            }
            record.active = false;
            record.operations
        };
        self.readers.synchronize();
        // SAFETY: The lifecycle mutex keeps the pinned owner alive. Revocation and SRCU
        // drainage exclude public readers; unregistration drains all native callbacks.
        unsafe { bindings::unregister_pernet_subsys(operations.as_ptr()) };
        let node = self.entries.lock().types.remove_node(&kind);
        drop(node);
    }

    fn close(&self, kind: TypeId, generation: u64) {
        let _lifecycle = self.lifecycle.lock();
        self.close_locked(kind, generation);
    }

    /// # Safety
    ///
    /// `block` must be this resident directory's notifier. GOING notifications retain the
    /// supplied module and its code until this callback returns.
    unsafe extern "C" fn module_notify(
        block: *mut bindings::notifier_block,
        event: c_ulong,
        module: *mut c_void,
    ) -> c_int {
        if event != bindings::module_state_MODULE_STATE_GOING as c_ulong {
            return bindings::NOTIFY_DONE as c_int;
        }
        // SAFETY: The notifier is embedded in the permanent, initialized directory.
        let directory = unsafe { &*crate::container_of!(Opaque::cast_from(block), Self, notifier) };
        let _lifecycle = directory.lifecycle.lock();
        loop {
            let next = directory
                .entries
                .lock()
                .types
                .iter()
                .filter(|(_, record)| record.owner == module.cast())
                .max_by_key(|(_, record)| record.generation)
                .map(|(kind, record)| (*kind, record.generation));
            let Some((kind, generation)) = next else {
                break;
            };
            directory.close_locked(kind, generation);
        }
        bindings::NOTIFY_DONE as c_int
    }
}

/// Resolves callback ownership in resident code, retaining it only during registration.
///
/// # Safety
///
/// `operations` must contain live callbacks. The caller must release the returned module
/// reference after publishing or rolling back registration.
unsafe fn callback_owner(
    operations: *const bindings::pernet_operations,
) -> Result<*mut bindings::module> {
    // SAFETY: The caller retains the callback addresses. The helper resolves them under RCU
    // and takes a temporary module reference, rejecting teardown already in progress.
    unsafe { from_err_ptr(bindings::net_namespace_callback_owner(operations)) }
}

/// A revocable capability to access one registration's typed namespace state.
///
/// Keys own no namespace or registration references. Once registration closes, access fails
/// with `ENODEV`, including after a new registration reuses the same state type or core ID.
pub struct Key<T: State> {
    generation: u64,
    _type: PhantomData<fn() -> T>,
}

impl<T: State> Copy for Key<T> {}

impl<T: State> Clone for Key<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: State> Key<T> {
    /// Borrows initialized state while retaining both the namespace and registration.
    ///
    /// The closure may sleep. Its borrows cannot escape. Namespace cleanup and registration
    /// destruction wait for the closure, so it must not wait for either of them or destroy the
    /// registration itself. The reader domain is shared by all registrations, so this also
    /// excludes indirect waits for another registration's destruction on a different thread.
    /// It must not register or unregister module notifiers: fallback cleanup holds that chain's
    /// read lock while waiting for these readers.
    /// Returns `ENODEV` if the namespace or registration is closing.
    pub fn with<R>(
        &self,
        namespace: &Namespace,
        access: impl FnOnce(Pin<&T>, &NamespaceRef) -> R,
    ) -> Result<R> {
        let namespace = namespace.try_to_ref().ok_or(ENODEV)?;
        let directory = directory()?;
        let _reader = directory.readers.read_lock();
        let id = {
            let entries = directory.entries.lock();
            let record = entries.types.get(&TypeId::of::<T>()).ok_or(ENODEV)?;
            if !record.active || record.generation != self.generation {
                return Err(ENODEV);
            }
            // SAFETY: Active publication follows core ID initialization under this mutex.
            // The SRCU guard prevents closing the registration and freeing its pinned ID.
            unsafe { record.id.as_ptr().read() }
        };
        // SAFETY: The initialized namespace has this active registration's pernet slot. The
        // active namespace reference excludes namespace exit; SRCU excludes unregistration.
        // Both remain held until the closure returns, before releasing the foreign-data borrow.
        let data = unsafe {
            let slot = bindings::net_generic(namespace.as_raw(), id).cast::<*mut c_void>();
            Pin::<KBox<T>>::borrow(slot.read())
        };
        Ok(access(data, &namespace))
    }
}

/// Owns per-namespace state registration until its readers and core callbacks have drained.
///
/// Creation and destruction may sleep and must run outside namespace callbacks, module notifier
/// callbacks and `Key::with` closures. Only one registration of each state type is allowed at a
/// time. First-time creation registers the directory's module notifier and therefore cannot
/// nest within that notifier chain.
/// Module teardown also revokes registrations whose owners were forgotten, before unloading
/// their callback code. This fallback does not release the forgotten owner's allocation.
///
/// # Invariants
///
/// While the directory record exists, the pinned operations and ID remain registered with
/// the core and indexed by T. `key` is initialized after successful registration. Closing
/// revokes keys before draining readers, unregistering callbacks and removing the record.
/// Module cleanup may close it first; a later drop recognizes the missing generation.
#[pin_data(PinnedDrop)]
pub struct Registration<T: State> {
    #[pin]
    operations: Opaque<bindings::pernet_operations>,
    #[pin]
    id: Opaque<c_uint>,
    key: Opaque<Key<T>>,
}

// SAFETY: Pinned core registration may be unregistered on another task; T permits transfer.
unsafe impl<T: State> Send for Registration<T> {}
// SAFETY: Sharing exposes only immutable keys. Core callbacks and directory access synchronize
// their own linkage, while T is Sync and its pinned owner lives through reader drainage.
unsafe impl<T: State> Sync for Registration<T> {}

impl<T: State> Registration<T> {
    /// Registers typed state for existing namespaces and for namespaces created later.
    pub fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(&this in Self {
            operations: Opaque::new(bindings::pernet_operations {
                init: Some(Self::initialize_namespace),
                exit: Some(Self::exit_namespace),
                size: size_of::<*mut c_void>(),
                ..Default::default()
            }),
            id: Opaque::new(0),
            key: Opaque::uninit(),
            _: {
                let directory = directory()?;
                // SAFETY: The initializer owns these fields at their final pinned addresses.
                let (operations, id, output) = unsafe {
                    (
                        Opaque::cast_into(&raw const (*this.as_ptr()).operations),
                        Opaque::cast_into(&raw const (*this.as_ptr()).id),
                        Opaque::cast_into(&raw const (*this.as_ptr()).key),
                    )
                };
                // SAFETY: The initialized operations contain this type's live callbacks.
                let owner = unsafe { callback_owner(operations)? };
                let _owner = ScopeGuard::new(|| {
                    // SAFETY: callback_owner returned this temporary module reference.
                    unsafe { bindings::net_namespace_put_callback_owner(owner) };
                });
                let _lifecycle = directory.lifecycle.lock();
                // SAFETY: This ID stays pinned through registration and its rollback. The
                // failure guard removes the record only after core callbacks have finished.
                let key = unsafe {
                    directory.claim::<T>(
                        NonNull::new(id).unwrap(),
                        NonNull::new(operations).unwrap(),
                        owner,
                    )?
                };
                let rollback = ScopeGuard::new(|| directory.remove::<T>());
                // SAFETY: Pinned operations and ID remain live throughout registration.
                // The inactive record lets paired core callbacks resolve their ID during init
                // and rollback, while preventing public access before all state is initialized.
                unsafe {
                    (*operations).id = id;
                    to_result(bindings::register_pernet_subsys(operations))?;
                    output.write(key);
                }
                // INVARIANT: Core registration and key initialization succeeded. No fallible
                // step follows activation; Drop or module cleanup owns unregistration.
                directory.set_active::<T>(true);
                rollback.dismiss();
            },
        })
    }

    /// Returns a key which can safely outlive registration and then reports `ENODEV`.
    #[inline]
    pub fn key(&self) -> Key<T> {
        // SAFETY: Successful initialization installs this immutable, Copy key.
        unsafe { self.key.get().read() }
    }

    /// Installs one namespace's state during the core's initialization callback.
    ///
    /// # Safety
    ///
    /// The core must retain `namespace`, its allocated generic slot, and this registration's
    /// initialized ID. No reader may access the slot until initialization succeeds.
    unsafe extern "C" fn initialize_namespace(namespace: *mut bindings::net) -> c_int {
        // Charge the task performing namespace creation, or the registering task when
        // initializing state for namespaces that already exist.
        let data = match KBox::pin_init(T::new(), GFP_KERNEL_ACCOUNT) {
            Ok(data) => data,
            Err(error) => return error.to_errno(),
        };
        // SAFETY: The core installed its ID and allocated the pointer-sized slot before this
        // callback. The registration retains its inactive or active directory entry. A failed
        // initializer returns before publishing ownership, so the core can free an empty slot.
        unsafe {
            let id = directory().unwrap().callback_id::<T>();
            let slot = bindings::net_generic(namespace, id).cast::<*mut c_void>();
            slot.write(data.into_foreign());
        }
        0
    }

    /// Removes state from a successfully initialized namespace.
    ///
    /// # Safety
    ///
    /// The core must retain the namespace, generic slot and registration record, call this
    /// exactly once after successful initialization, and exclude state readers until return.
    unsafe extern "C" fn exit_namespace(namespace: *mut bindings::net) {
        // SAFETY: Exit follows successful init. Namespace cleanup has drained active refs, or
        // registration closure has drained SRCU readers. The core retains the slot and directory
        // entry until this callback returns. Take back the single owner installed by init.
        unsafe {
            let id = directory().unwrap().callback_id::<T>();
            let slot = bindings::net_generic(namespace, id).cast::<*mut c_void>();
            drop(Pin::<KBox<T>>::from_foreign(slot.read()));
        }
    }
}

#[pinned_drop]
impl<T: State> PinnedDrop for Registration<T> {
    fn drop(self: Pin<&mut Self>) {
        let directory = directory().unwrap();
        directory.close(TypeId::of::<T>(), self.key().generation);
    }
}

#[cfg(CONFIG_RUST_NET_NAMESPACE_KUNIT_TEST)]
#[macros::kunit_tests(rust_namespace_registration)]
mod tests {
    use super::*;
    use crate::sync::atomic::{
        Acquire,
        Atomic,
        AtomicFlag,
        Relaxed,
        Release, //
    };

    #[pin_data]
    struct Data {
        value: Atomic<u32>,
    }

    impl State for Data {
        fn new() -> impl PinInit<Self, Error> {
            try_pin_init!(Self {
                value: Atomic::new(0)
            })
        }
    }

    #[test]
    fn stale_keys_cannot_access_replacement_state() -> Result {
        let namespace = Namespace::initial().try_to_ref().unwrap();
        let allocation = namespace.allocation_ref();
        let retained = allocation.clone();
        drop(namespace);
        drop(allocation);
        let registration = KBox::pin_init(Registration::<Data>::new(), GFP_KERNEL)?;
        let old = registration.key();
        old.with(&retained, |data, _namespace| data.value.store(37, Relaxed))?;
        assert_eq!(old.with(&retained, |data, _| data.value.load(Relaxed))?, 37);
        assert!(matches!(
            KBox::pin_init(Registration::<Data>::new(), GFP_KERNEL),
            Err(EEXIST)
        ));
        drop(registration);
        assert_eq!(old.with(&retained, |_, _| ()), Err(ENODEV));
        let replacement = KBox::pin_init(Registration::<Data>::new(), GFP_KERNEL)?;
        assert_eq!(old.with(&retained, |_, _| ()), Err(ENODEV));
        assert_eq!(
            replacement
                .key()
                .with(&retained, |data, _| data.value.load(Relaxed))?,
            0
        );
        drop(replacement);
        Ok(())
    }

    #[pin_data]
    struct Failing {}

    impl State for Failing {
        fn new() -> impl PinInit<Self, Error> {
            try_pin_init!(Self {
                _: { Err::<(), Error>(EINVAL)?; },
            })
        }
    }

    #[test]
    fn failed_initialization_releases_type_claim() {
        for _ in 0..2 {
            assert!(matches!(
                KBox::pin_init(Registration::<Failing>::new(), GFP_KERNEL),
                Err(EINVAL)
            ));
        }
    }

    #[pin_data]
    struct ConcurrentData {}

    impl State for ConcurrentData {
        fn new() -> impl PinInit<Self, Error> {
            try_pin_init!(Self {})
        }
    }

    fn wait_for(mut condition: impl FnMut() -> bool) -> Result {
        let start = crate::time::Instant::<crate::time::Monotonic>::now();
        while !condition() {
            if start.elapsed().as_millis() > 5000 {
                return Err(ETIMEDOUT);
            }
            // SAFETY: The test task holds no RCU guard or other non-sleepable protection.
            unsafe { crate::task::cond_resched() };
        }
        Ok(())
    }

    #[test]
    fn closing_rejects_new_access_and_waits_for_existing_reader() -> Result {
        static STARTED: AtomicFlag = AtomicFlag::new(false);
        static RELEASE: AtomicFlag = AtomicFlag::new(false);
        static READ_OK: AtomicFlag = AtomicFlag::new(false);
        static CLOSED: AtomicFlag = AtomicFlag::new(false);
        STARTED.store(false, Relaxed);
        RELEASE.store(false, Relaxed);
        READ_OK.store(false, Relaxed);
        CLOSED.store(false, Relaxed);

        let registration = KBox::pin_init(Registration::<ConcurrentData>::new(), GFP_KERNEL)?;
        let key = registration.key();
        let queue = crate::workqueue::OwnedQueue::new_unbound(c"rust_namespace_test", 2)?;
        let release = ScopeGuard::new(|| RELEASE.store(true, Release));
        queue.try_spawn(GFP_KERNEL, move || {
            let result = key.with(Namespace::initial(), |_, _| {
                STARTED.store(true, Release);
                while !RELEASE.load(Acquire) {
                    // SAFETY: This workqueue callback only retains sleepable SRCU protection.
                    unsafe { crate::task::cond_resched() };
                }
            });
            READ_OK.store(result.is_ok(), Release);
        })?;
        wait_for(|| STARTED.load(Acquire))?;
        // If allocating the closing work fails, unblock the reader before dropping the
        // captured registration. Otherwise its destructor would wait inside try_spawn().
        let closing = ScopeGuard::new_with_data(registration, |registration| {
            RELEASE.store(true, Release);
            drop(registration);
        });
        queue.try_spawn(GFP_KERNEL, move || {
            drop(closing.dismiss());
            CLOSED.store(true, Release);
        })?;
        wait_for(|| key.with(Namespace::initial(), |_, _| ()) == Err(ENODEV))?;
        assert!(!CLOSED.load(Acquire));
        RELEASE.store(true, Release);
        release.dismiss();
        drop(queue);
        assert!(READ_OK.load(Acquire));
        assert!(CLOSED.load(Acquire));
        Ok(())
    }
}
