// SPDX-License-Identifier: GPL-2.0

//! Ownership of RDMA link types and their creation callback state.

use super::Device;
use crate::{
    bindings,
    error::to_result,
    net,
    prelude::*,
    types::Opaque, //
};
use core::ptr::NonNull;

/// Operations for a dynamically registered RDMA link type.
pub trait Operations: Send + Sync + Sized + 'static {
    /// Provider type of devices associated with this link type.
    type Device;

    /// Creates a device while the core retains the link registration and network device.
    ///
    /// Called in sleepable context without RTNL held. Requests may run concurrently.
    fn new_link(self: Pin<&Self>, request: NewLink<'_, Self>) -> Result;

    /// Prepares a device for administrative deletion, before core unregistration.
    ///
    /// The core reference retains the device and its resources throughout this callback.
    /// This may run concurrently with [`Self::shutdown`].
    fn delete_link(self: Pin<&Self>, _device: &Device<Self::Device>) -> Result {
        Ok(())
    }

    /// Stops provider work and drops registration references before device unregistration.
    ///
    /// Creation callbacks have drained, but deletion callbacks can still run concurrently.
    /// A handler retaining [`super::DeviceRef`] values must release them here so the managed
    /// registration's device-unregistration fence can complete.
    fn quiesce(self: Pin<&Self>) {}

    /// Finishes shutdown after creation has stopped, before callback state is dropped.
    ///
    /// A managed registration drains its driver ID before this callback. A legacy registration
    /// which attaches C-owned devices requires their unregistration and pending deletion
    /// callbacks to finish here. No new creation callback can run at this point.
    fn shutdown(self: Pin<&Self>) {}
}

/// A creation request borrowed from the core's link-operations read-side critical section.
///
/// The request retains no additional references and cannot outlive its callback. Holding it
/// keeps the registration, name and network device alive, but does not freeze network settings.
///
/// # Invariants
///
/// The core retains all inputs for `'a`, and `ops` is the registration containing `_handler`.
pub struct NewLink<'a, T: Operations> {
    name: &'a CStr,
    net_device: &'a net::Device,
    ops: NonNull<bindings::rdma_link_ops>,
    driver_id: Option<bindings::rdma_driver_id>,
    _handler: Pin<&'a T>,
}

impl<'a, T: Operations> NewLink<'a, T> {
    /// Returns the requested RDMA device name.
    #[inline]
    pub fn name(&self) -> &'a CStr {
        self.name
    }

    /// Borrows the network device retained by the core during creation.
    #[inline]
    pub fn net_device(&self) -> &'a net::Device {
        self.net_device
    }

    /// Returns the driver ID which a managed registration fences during shutdown.
    #[inline]
    pub fn driver_id(&self) -> Option<bindings::rdma_driver_id> {
        self.driver_id
    }

    /// Associates an unpublished C-owned device with this link registration.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own initialization of `device` and its unused `link_ops`
    /// field. Before publication, the device must be fully initialized for `T::Device`, with
    /// stable DMA configuration and the storage guarantees required by [`Device::from_raw`].
    /// The association must remain unchanged while the device can receive deletion callbacks.
    /// If [`Self::driver_id`] returns an ID, the device must use that ID without changing it
    /// and must have a final deallocation callback installed.
    ///
    /// The device must be deallocated on failed creation. On success, `T::shutdown` must fully
    /// unregister it and drain concurrent deletion callbacks unless this is a managed
    /// registration, which supplies that fence. This includes pending queued unregistration.
    #[inline]
    pub unsafe fn attach(&self, device: *mut bindings::ib_device) {
        // SAFETY: The caller owns this unpublished field, and the request keeps the operations
        // live until creation completes. The shutdown contract retains them for later deletion.
        unsafe { (*device).link_ops = self.ops.as_ptr() };
    }
}

/// Owns a link type and its pinned callback state.
///
/// Destruction removes the link type, waits for creation callbacks, invokes
/// [`Operations::quiesce`], drains managed devices and invokes [`Operations::shutdown`]
/// before dropping the handler. Both construction and destruction
/// may sleep. They must run outside link callbacks and without locks needed by those callbacks.
///
/// # Invariants
///
/// `ops` is registered exactly once and its callbacks refer to the initialized, pinned handler.
/// Attached devices obey [`NewLink::attach`]'s shutdown and association requirements.
#[pin_data(PinnedDrop)]
pub struct Registration<T: Operations> {
    // The destructor must not create an exclusive borrow of callback-accessible state.
    state: Pin<KBox<State<T>>>,
}

#[pin_data]
struct State<T: Operations> {
    #[pin]
    handler: T,
    #[pin]
    ops: Opaque<bindings::rdma_link_ops>,
    driver_id: Option<bindings::rdma_driver_id>,
}

// SAFETY: The handler is Send and the core permits unregistration on another thread.
unsafe impl<T: Operations> Send for Registration<T> {}
// SAFETY: The handler is Sync and the core's link-operations semaphore serializes the C linkage.
unsafe impl<T: Operations> Sync for Registration<T> {}

impl<T: Operations> Registration<T> {
    /// Registers a link type, returning `EEXIST` when the name is already in use.
    ///
    /// Names must be nonempty and fit in the core's `IFNAMSIZ` bytes with the terminator.
    pub fn new(name: &'static CStr, handler: impl PinInit<T, Error>) -> impl PinInit<Self, Error> {
        Self::new_inner(name, handler, None)
    }

    /// Registers a link type whose device callbacks are drained automatically on removal.
    ///
    /// After stopping creation and invoking [`Operations::quiesce`], Drop unregisters every
    /// device with `driver_id` and waits for pending deletion callbacks before invoking
    /// [`Operations::shutdown`] and dropping state. Names must fit in `IFNAMSIZ` bytes.
    /// Choose the ID dedicated to this provider; devices with that ID are all affected.
    pub fn new_managed(
        name: &'static CStr,
        driver_id: bindings::rdma_driver_id,
        handler: impl PinInit<T, Error>,
    ) -> impl PinInit<Self, Error>
    where
        T::Device: super::DeviceOperations,
    {
        Self::new_inner(name, handler, Some(driver_id))
    }

    fn new_inner(
        name: &'static CStr,
        handler: impl PinInit<T, Error>,
        driver_id: Option<bindings::rdma_driver_id>,
    ) -> impl PinInit<Self, Error> {
        // INVARIANT: State registers its pinned operations only after initializing the
        // handler. This owner retains that state until removal drains every callback.
        try_pin_init!(Self {
            state: KBox::pin_init(State::new(name, handler, driver_id), GFP_KERNEL)?,
        })
    }
}

impl<T: Operations> State<T> {
    fn new(
        name: &'static CStr,
        handler: impl PinInit<T, Error>,
        driver_id: Option<bindings::rdma_driver_id>,
    ) -> impl PinInit<Self, Error> {
        try_pin_init!(&this in Self {
            _: {
                if name.to_bytes().is_empty()
                    || name.to_bytes().len() >= bindings::IFNAMSIZ as usize {
                    return Err(EINVAL);
                }
            },
            handler <- handler,
            driver_id,
            ops: Opaque::new(bindings::rdma_link_ops {
                type_: name.as_char_ptr(),
                newlink: Some(Self::new_link),
                dellink: Some(Self::delete_link),
                ..bindings::rdma_link_ops::default()
            }),
            _: {
                // SAFETY: All callback state is initialized at its final address. The name is
                // static and a failed registration retains nothing. On success, PinnedDrop
                // removes the table and drains its users before releasing the handler.
                // INVARIANT: Registration is the last fallible initialization step.
                to_result(unsafe {
                    bindings::rdma_link_register(
                        Opaque::cast_into(&raw const (*this.as_ptr()).ops),
                    )
                })?;
            },
        })
    }

    /// Borrows the pinned handler while a callback retains this operations table.
    ///
    /// # Safety
    ///
    /// `ops` must belong to this registration and keep its initialized handler alive for `'a`.
    #[inline]
    unsafe fn handler<'a>(ops: *const bindings::rdma_link_ops) -> Pin<&'a T> {
        // SAFETY: The caller identifies our embedded operations table. Borrow only the handler:
        // deletion callbacks can still run after removal from the core's registration list.
        let registration = unsafe { crate::container_of!(Opaque::cast_from(ops), Self, ops) };
        // SAFETY: The handler is structurally pinned and remains initialized for this borrow.
        unsafe { Pin::new_unchecked(&(*registration).handler) }
    }

    /// # Safety
    ///
    /// The core must retain this installed operations table, its pinned handler, the NUL-
    /// terminated name and the referenced netdev until the callback returns.
    unsafe extern "C" fn new_link(
        ops: *const bindings::rdma_link_ops,
        name: *const c_char,
        net_device: *mut bindings::net_device,
    ) -> c_int {
        // SAFETY: The core holds the link-operations read lock until this callback returns.
        let handler = unsafe { Self::handler(ops) };
        // SAFETY: The callback retains the registration. Copy only its immutable configuration,
        // without borrowing the operations linkage which the core manages independently.
        let driver_id = unsafe {
            let registration = crate::container_of!(Opaque::cast_from(ops), Self, ops);
            (*registration).driver_id
        };
        // INVARIANT: This callback borrows the name, held netdev and matching registration.
        let request = NewLink {
            // SAFETY: The core supplies a NUL-terminated name kept alive for the callback.
            name: unsafe { CStr::from_char_ptr(name) },
            // SAFETY: dev_get_by_name() acquired a reference which the core keeps until return.
            net_device: unsafe { net::Device::from_raw(net_device) },
            // SAFETY: The callback's operations pointer refers to our live embedded table.
            ops: unsafe { NonNull::new_unchecked(ops.cast_mut()) },
            driver_id,
            _handler: handler,
        };
        match handler.new_link(request) {
            Ok(()) => 0,
            Err(error) => error.to_errno(),
        }
    }

    /// # Safety
    ///
    /// The core must retain the attached device and its resources. Its unchanged link_ops
    /// must identify this registration, whose handler remains pinned until the callback
    /// returns.
    unsafe extern "C" fn delete_link(device: *mut bindings::ib_device) -> c_int {
        // SAFETY: The core retains this device across the callback. The attach contract keeps
        // the association unchanged and the handler alive until all deletion callbacks return.
        let handler = unsafe { Self::handler((*device).link_ops) };
        // SAFETY: The attach contract guarantees the provider type and stable DMA configuration;
        // the core's reference keeps the initialized device and its resources alive here.
        let device = unsafe { Device::from_raw(device) };
        match handler.delete_link(device) {
            Ok(()) => 0,
            Err(error) => error.to_errno(),
        }
    }
}

#[pinned_drop]
impl<T: Operations> PinnedDrop for Registration<T> {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: This owner registered the table. Removal prevents new creation and waits for
        // existing creation callbacks. Attached devices remain valid through shutdown below.
        unsafe { bindings::rdma_link_unregister(self.state.ops.get()) };
        // SAFETY: The handler remains pinned until both teardown phases finish. It may still
        // be shared with deletion callbacks, so neither phase receives an exclusive borrow.
        let handler = unsafe { Pin::new_unchecked(&self.state.handler) };
        handler.quiesce();
        if let Some(driver_id) = self.state.driver_id {
            // SAFETY: Creation has stopped and drained. Attached managed devices retain this
            // immutable driver ID and a deallocation callback. The core fence also waits for
            // queued removals before any handler or dependency can be dropped.
            unsafe { bindings::ib_unregister_driver(driver_id) };
        }
        handler.shutdown();
    }
}

#[cfg(all(CONFIG_RUST_KUNIT_TESTS, CONFIG_INFINIBAND = "y"))]
#[crate::macros::kunit_tests(rust_rdma_links)]
mod tests {
    use super::*;
    use crate::sync::atomic::{
        Atomic,
        Relaxed, //
    };

    static DROPS: Atomic<u32> = Atomic::new(0);
    static SHUTDOWNS: Atomic<u32> = Atomic::new(0);

    struct Handler;

    impl Operations for Handler {
        type Device = ();

        fn new_link(self: Pin<&Self>, _request: NewLink<'_, Self>) -> Result {
            Err(EOPNOTSUPP)
        }

        fn shutdown(self: Pin<&Self>) {
            SHUTDOWNS.fetch_add(1, Relaxed);
        }
    }

    impl Drop for Handler {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Relaxed);
        }
    }

    #[test]
    fn conflict_drops_state_without_unregistering_owner() -> Result {
        DROPS.store(0, Relaxed);
        SHUTDOWNS.store(0, Relaxed);
        let first = KBox::pin_init(
            Registration::new(c"rust_link_kunit", Ok(Handler)),
            GFP_KERNEL,
        )?;
        let duplicate = KBox::pin_init(
            Registration::new(c"rust_link_kunit", Ok(Handler)),
            GFP_KERNEL,
        );
        assert!(matches!(duplicate, Err(EEXIST)));
        assert_eq!(DROPS.load(Relaxed), 1);
        assert_eq!(SHUTDOWNS.load(Relaxed), 0);
        drop(first);
        assert_eq!(DROPS.load(Relaxed), 2);
        assert_eq!(SHUTDOWNS.load(Relaxed), 1);
        let next = KBox::pin_init(
            Registration::new(c"rust_link_kunit", Ok(Handler)),
            GFP_KERNEL,
        )?;
        drop(next);
        assert_eq!(DROPS.load(Relaxed), 3);
        assert_eq!(SHUTDOWNS.load(Relaxed), 2);
        Ok(())
    }
}
