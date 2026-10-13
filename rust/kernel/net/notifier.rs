// SPDX-License-Identifier: GPL-2.0

//! Owned registrations for network-device notifications.

use crate::{
    bindings,
    error::to_result,
    prelude::*,
    types::{
        NotThreadSafe,
        Opaque, //
    }, //
};

/// A network-device notification, including events not yet named by this abstraction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event(c_ulong);

impl Event {
    /// Returns the native event number, including notifications without a named constant.
    #[inline]
    pub fn as_raw(self) -> c_ulong {
        self.0
    }

    /// The device has been brought up.
    pub const UP: Self = Self(bindings::netdev_cmd_NETDEV_UP as c_ulong);
    /// The device has been brought down.
    pub const DOWN: Self = Self(bindings::netdev_cmd_NETDEV_DOWN as c_ulong);
    /// The device's operational state changed.
    pub const CHANGE: Self = Self(bindings::netdev_cmd_NETDEV_CHANGE as c_ulong);
    /// The device was registered, or registration is being replayed to a new listener.
    pub const REGISTER: Self = Self(bindings::netdev_cmd_NETDEV_REGISTER as c_ulong);
    /// The device is unregistering, or unregistration is being replayed to a departing listener.
    pub const UNREGISTER: Self = Self(bindings::netdev_cmd_NETDEV_UNREGISTER as c_ulong);
    /// The device's MTU changed.
    pub const CHANGE_MTU: Self = Self(bindings::netdev_cmd_NETDEV_CHANGEMTU as c_ulong);
    /// The device is about to be brought down.
    pub const GOING_DOWN: Self = Self(bindings::netdev_cmd_NETDEV_GOING_DOWN as c_ulong);
}

/// A successful notifier response.
pub enum Response {
    /// This listener has no interest in the event.
    Done,
    /// Continue notifying other listeners.
    Ok,
    /// Stop notifying other listeners, except during mandatory unregister cleanup.
    Stop,
}

impl Response {
    #[inline]
    fn into_raw(self) -> c_int {
        match self {
            Self::Done => bindings::NOTIFY_DONE as c_int,
            Self::Ok => bindings::NOTIFY_OK as c_int,
            Self::Stop => bindings::NOTIFY_STOP as c_int,
        }
    }
}

/// Information borrowed for a network-device notification under RTNL.
///
/// Some events precede registration. A typed device borrow is available while the device
/// is registered or unregistering, including repeated unregister notifications. The info
/// cannot be sent to another thread or kept beyond the callback.
///
/// # Invariants
///
/// The wrapped info and its device remain allocated for the borrow, with RTNL held.
pub struct Info<'a> {
    inner: &'a Opaque<bindings::netdev_notifier_info>,
    event: Event,
    _not_thread_safe: NotThreadSafe,
}

impl Info<'_> {
    /// Borrows the RTNL protection supplied by this notification.
    #[inline]
    pub fn rtnl(&self) -> super::RtnlGuard<'_> {
        // SAFETY: The notifier contract retains RTNL for the lifetime of this info borrow.
        unsafe { super::RtnlGuard::borrowed() }
    }

    /// Borrows the initialized device during registration and unregistration events.
    ///
    /// Returns `None` for early initialization and final release notifications. Taking a
    /// device reference retains its allocation, without preventing unregistration or a
    /// namespace move.
    #[inline]
    pub fn device(&self) -> Option<&super::Device> {
        let device = self.device_raw();
        // SAFETY: The callback retains the allocation. Sample the lifecycle field without
        // borrowing C storage that networking can modify.
        let state = unsafe { core::ptr::read_volatile(&raw const (*device).reg_state) };
        if !Self::admits_device(u32::from(state), self.event) {
            return None;
        }
        // SAFETY: The admitted states and authentic UNREGISTER rebroadcast initialized the
        // address lists and reference count, and teardown waits for acquired references.
        // Failed registration can also reach UNREGISTERED, but cannot emit this event.
        Some(unsafe { super::Device::from_raw(device) })
    }

    #[inline]
    fn admits_device(state: u32, event: Event) -> bool {
        matches!(
            state,
            bindings::netdev_reg_state_NETREG_REGISTERED
                | bindings::netdev_reg_state_NETREG_UNREGISTERING
        ) || (state == bindings::netdev_reg_state_NETREG_UNREGISTERED && event == Event::UNREGISTER)
    }

    /// Returns the MTU while the notification holds RTNL.
    #[inline]
    pub fn mtu(&self) -> u32 {
        // SAFETY: The notifier retains the device and RTNL serializes MTU changes.
        unsafe { (*self.device_raw()).mtu }
    }

    /// Returns the callback's device for interoperability with C networking interfaces.
    #[inline]
    pub fn device_raw(&self) -> *mut bindings::net_device {
        // SAFETY: The callback keeps the info live and its device pointer unchanged.
        unsafe { (*self.inner.get()).dev }
    }
}

/// Receives notifications about network devices in all namespaces.
///
/// Callbacks run with RTNL held. They must not acquire RTNL again or register/unregister
/// network-device notifiers. The information borrow lasts only for the callback.
pub trait Handler: Send + Sync + 'static {
    /// Handles an event. An error stops the chain and is returned to callers that permit vetoes.
    /// This registration ignores the response to [`Event::UNREGISTER`] and permits the chain
    /// to continue; it cannot control responses from other listeners.
    ///
    /// A callback rejecting [`Event::REGISTER`] must undo its partial external work before
    /// returning. Registration replay does not send a compensating unregister notification
    /// for the device whose callback rejected registration.
    fn notify(self: Pin<&Self>, event: Event, info: &Info<'_>) -> Result<Response>;
}

/// Owns a pinned notifier and its callback state until every callback has returned.
///
/// Registration replays register/up events for existing devices. Destruction first removes
/// the listener and then synthesizes down/unregister events before dropping its state.
/// Both operations may sleep and acquire RTNL and the namespace registration semaphore.
/// They must run outside callbacks and without locks needed by the callback.
///
/// # Invariants
///
/// `block` is registered exactly once, points back to this pinned allocation, and is removed
/// before `handler` is destroyed. The handler is initialized before any callback can run.
#[pin_data(PinnedDrop)]
pub struct Registration<T: Handler> {
    #[pin]
    handler: T,
    #[pin]
    block: Opaque<bindings::notifier_block>,
}

// SAFETY: The handler is Send, and notifier removal may run on any thread.
unsafe impl<T: Handler> Send for Registration<T> {}
// SAFETY: The handler is Sync. Networking serializes access to the opaque notifier linkage.
unsafe impl<T: Handler> Sync for Registration<T> {}

impl<T: Handler> Registration<T> {
    /// Registers initialized callback state, with higher priorities called first.
    pub fn new(handler: impl PinInit<T, Error>, priority: c_int) -> impl PinInit<Self, Error> {
        try_pin_init!(&this in Self {
            handler <- handler,
            block: Opaque::new(bindings::notifier_block {
                notifier_call: Some(Self::notify),
                next: core::ptr::null_mut(),
                priority,
            }),
            _: {
                // SAFETY: Both fields are initialized in their final pinned location before
                // registration can replay events. Success retains the block until PinnedDrop;
                // failure removes it and finishes rollback for previously accepted devices.
                // The rejecting callback must undo its own partial external work.
                // INVARIANT: No fallible initialization follows successful registration.
                to_result(unsafe {
                    bindings::register_netdevice_notifier(
                        Opaque::cast_into(&raw const (*this.as_ptr()).block),
                    )
                })?;
            },
        })
    }

    /// Dispatches a notification from this registration's embedded block.
    ///
    /// # Safety
    ///
    /// `block` must belong to a live, pinned `Registration<T>`. `info` must point to the
    /// event's initialized netdev notifier prefix and device, retained under RTNL for the call.
    unsafe extern "C" fn notify(
        block: *mut bindings::notifier_block,
        event: c_ulong,
        info: *mut c_void,
    ) -> c_int {
        // SAFETY: Only this registration installs the callback with its embedded block.
        let registration = unsafe { crate::container_of!(Opaque::cast_from(block), Self, block) };
        // SAFETY: The initialized handler remains pinned throughout registration, rollback,
        // and unregistration. Borrow only that field, including during partial initialization.
        let handler = unsafe { Pin::new_unchecked(&(*registration).handler) };
        let info = Info {
            // SAFETY: Every event supplies a live common info prefix under RTNL. This local
            // wrapper binds that prefix to the authentic event number for the borrow.
            inner: unsafe { &*info.cast::<Opaque<bindings::netdev_notifier_info>>() },
            event: Event(event),
            _not_thread_safe: NotThreadSafe,
        };
        let response = handler.notify(Event(event), &info);
        if info.event == Event::UNREGISTER {
            // Unregistration cannot be vetoed. Stopping here would prevent later listeners
            // from dropping device references and could strand the core's reference drain.
            return bindings::NOTIFY_DONE as c_int;
        }
        match response {
            Ok(response) => response.into_raw(),
            // Match notifier_from_errno(): preserve the errno and stop the chain.
            Err(error) => {
                bindings::NOTIFY_STOP_MASK as c_int
                    | (bindings::NOTIFY_OK as c_int - error.to_errno())
            }
        }
    }
}

#[pinned_drop]
impl<T: Handler> PinnedDrop for Registration<T> {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: The invariant gives us unique registration ownership. Removal serializes
        // with callbacks and completes synthetic notifications before the handler is dropped.
        unsafe { bindings::unregister_netdevice_notifier(self.block.get()) };
    }
}

#[cfg(CONFIG_RUST_KUNIT_TESTS)]
#[crate::macros::kunit_tests(rust_netdev_notifier)]
mod tests {
    use super::*;
    use crate::sync::atomic::{
        Atomic,
        Relaxed, //
    };

    static DROPS: Atomic<u32> = Atomic::new(0);
    static REGISTERS: Atomic<u32> = Atomic::new(0);
    static UNREGISTERS: Atomic<u32> = Atomic::new(0);
    static EARLY_DROPS: Atomic<u32> = Atomic::new(0);

    struct Observer {
        reject: bool,
    }

    impl Handler for Observer {
        fn notify(self: Pin<&Self>, event: Event, _info: &Info<'_>) -> Result<Response> {
            if DROPS.load(Relaxed) != u32::from(!self.reject) {
                EARLY_DROPS.fetch_add(1, Relaxed);
            }
            if event == Event::REGISTER {
                REGISTERS.fetch_add(1, Relaxed);
                if self.reject {
                    return Err(EINVAL);
                }
            } else if event == Event::UNREGISTER {
                UNREGISTERS.fetch_add(1, Relaxed);
            }
            Ok(Response::Ok)
        }
    }

    impl Drop for Observer {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Relaxed);
        }
    }

    #[test]
    fn failed_registration_does_not_lend_a_device() -> Result {
        let _rtnl = crate::net::RtnlGuard::lock();
        let mut device = KBox::new(bindings::net_device::default(), GFP_KERNEL)?;
        device.reg_state = bindings::netdev_reg_state_NETREG_UNREGISTERED as u8;
        let native = Opaque::new(bindings::netdev_notifier_info {
            dev: &mut *device,
            ..Default::default()
        });
        let info = Info {
            inner: &native,
            event: Event(bindings::netdev_cmd_NETDEV_PRE_UNINIT as c_ulong),
            _not_thread_safe: NotThreadSafe,
        };
        // A failed-registration PRE_UNINIT callback has allocated device storage but does
        // not promise to drain dev_hold references before freeing it.
        assert!(info.device().is_none());
        // A draining rebroadcast is the only UNREGISTERED event which lends a device.
        assert!(Info::admits_device(
            bindings::netdev_reg_state_NETREG_UNREGISTERED,
            Event::UNREGISTER,
        ));
        Ok(())
    }

    #[test]
    fn replay_rollback_and_release() -> Result {
        DROPS.store(0, Relaxed);
        REGISTERS.store(0, Relaxed);
        UNREGISTERS.store(0, Relaxed);
        EARLY_DROPS.store(0, Relaxed);

        // The initial namespace's loopback device causes registration replay. Reject it to
        // exercise the failure path, including dropping state after the core's rollback.
        let failed = KBox::pin_init(
            Registration::new(Ok(Observer { reject: true }), 0),
            GFP_KERNEL,
        );
        assert!(matches!(failed, Err(EINVAL)));
        assert_eq!(DROPS.load(Relaxed), 1);

        REGISTERS.store(0, Relaxed);
        let registration = KBox::pin_init(
            Registration::new(Ok(Observer { reject: false }), 0),
            GFP_KERNEL,
        )?;
        assert!(REGISTERS.load(Relaxed) > 0);
        assert_eq!(DROPS.load(Relaxed), 1);
        drop(registration);
        assert!(UNREGISTERS.load(Relaxed) > 0);
        assert_eq!(DROPS.load(Relaxed), 2);
        assert_eq!(EARLY_DROPS.load(Relaxed), 0);
        Ok(())
    }
}
