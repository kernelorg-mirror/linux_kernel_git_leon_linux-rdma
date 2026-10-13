// SPDX-License-Identifier: GPL-2.0

//! Owned references that keep RDMA device registration resources live.

use super::{
    Device,
    DeviceOperations,
    Operations, //
};
use crate::bindings;
use core::{
    mem::ManuallyDrop,
    ops::Deref,
    pin::Pin,
    ptr::NonNull, //
};

impl<T> Device<T> {
    /// Acquires a core registration reference, unless the reference count has reached zero.
    ///
    /// This does not sleep. The reference keeps device resources live across asynchronous
    /// processing, but does not prevent client removal or freeze port configuration.
    #[inline]
    pub fn try_to_ref(&self) -> Option<DeviceRef<T>> {
        // SAFETY: The borrow retains the initialized allocation while attempting acquisition.
        // Core unregistration waits for successful acquisitions before releasing resources.
        if unsafe { bindings::ib_device_try_get(self.as_raw()) } {
            // INVARIANT: The acquired core reference retains this initialized device.
            Some(DeviceRef {
                inner: NonNull::from(self),
            })
        } else {
            None
        }
    }
}

impl<T: DeviceOperations> Device<T> {
    /// Borrows the pinned provider data retained by this device.
    ///
    /// Core registration references keep this data initialized until they drain. Individual
    /// provider operations synchronize mutable state and may reject a retiring device.
    #[inline]
    pub fn provider(&self) -> Pin<&T> {
        // SAFETY: The device invariant retains the Operations<T> installation for this borrow.
        unsafe { Operations::<T>::data(self.as_raw()) }
    }
}

/// Owns one registration reference to an RDMA device belonging to provider `T`.
///
/// Cloning increments the existing core reference count without allocating storage. Dropping
/// the last reference signals the core's unregistering thread; it does not destroy the device
/// in the releasing context. References must be dropped before waiting for unregistration.
///
/// # Invariants
///
/// `inner` points to a live `Device<T>` and owns one reference acquired by `ib_device_try_get`
/// or an equivalent core lookup. Unregistration drains these references before resource cleanup.
pub struct DeviceRef<T> {
    inner: NonNull<Device<T>>,
}

// SAFETY: The core reference count and unregister completion permit release on any CPU.
// T identifies the provider. Data access requires DeviceOperations, which requires Send + Sync.
unsafe impl<T> Send for DeviceRef<T> {}
// SAFETY: Shared access exposes only the opaque device interface and its synchronized methods.
unsafe impl<T> Sync for DeviceRef<T> {}

impl<T> DeviceRef<T> {
    /// Takes ownership of a core registration reference acquired by C.
    ///
    /// # Safety
    ///
    /// `device` must satisfy [`Device::from_raw`] for provider T, with one live registration
    /// reference transferred to this owner. Its registration resources must remain valid until
    /// such references drain. The caller must not separately release the transferred reference.
    #[inline]
    pub unsafe fn from_raw(device: *mut bindings::ib_device) -> Self {
        // INVARIANT: The caller transfers a live core reference with the required provider type.
        Self {
            // SAFETY: The initialized core allocation is non-null and has Device<T>'s layout.
            inner: unsafe { NonNull::new_unchecked(device.cast()) },
        }
    }

    /// Transfers this core registration reference to a C caller responsible for releasing it.
    #[inline]
    pub fn into_raw(self) -> *mut bindings::ib_device {
        ManuallyDrop::new(self).inner.as_ptr().cast()
    }
}

impl<T: DeviceOperations> DeviceRef<T> {
    /// Queues unregistration without waiting for clients or registration references to drain.
    ///
    /// This may be called while holding RTNL. Release this reference and any clones before
    /// waiting for unregistration to finish. Repeated requests are coalesced by the core.
    #[inline]
    pub fn unregister_queued(&self) {
        // SAFETY: This owner keeps the registration count nonzero. Operations<T> installed
        // final deallocation and requires a driver fence before its module can unload. The
        // core workqueue acquires its own allocation reference before queueing the device.
        unsafe { bindings::ib_unregister_device_queued(self.as_raw()) };
    }

    /// Looks up a registered provider device associated with a network device.
    ///
    /// `driver` filters the core lookup; `RDMA_DRIVER_UNKNOWN` accepts any driver. The result
    /// is returned only if the Rust adapter installed provider type `T` on that device.
    /// Only the first core match is checked; a provider-type mismatch returns `None` rather
    /// than searching further. Use a driver ID dedicated to `T` when lookup must be complete.
    /// This does not sleep and may be used from network receive callbacks.
    #[inline]
    pub fn from_netdev(
        netdev: &crate::net::Device,
        driver: bindings::rdma_driver_id,
    ) -> Option<Self> {
        // SAFETY: The borrow keeps the initialized netdev allocation live. The core walks its
        // association table under RCU and takes a registration reference before returning.
        let device = unsafe { bindings::ib_device_get_by_netdev(netdev.as_raw(), driver) };
        if device.is_null() {
            return None;
        }
        if !super::registry::matches::<T>(device) {
            // SAFETY: Release the unmatched lookup reference, without accessing it afterwards.
            unsafe { bindings::ib_device_put(device) };
            return None;
        }
        // SAFETY: The private registry proves Operations<T> installed this provider. The core
        // reference excludes its final release and retains the initialized registration resources.
        Some(unsafe { Self::from_raw(device) })
    }
}

impl<T> Clone for DeviceRef<T> {
    #[inline]
    fn clone(&self) -> Self {
        // SAFETY: This owned reference keeps the count nonzero throughout acquisition.
        unsafe {
            bindings::refcount_inc(
                &raw mut (*self.inner.as_ptr().cast::<bindings::ib_device>()).refcount,
            )
        };
        // INVARIANT: The clone owns exactly the newly acquired reference.
        Self { inner: self.inner }
    }
}

impl<T> Deref for DeviceRef<T> {
    type Target = Device<T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: The reference retains the opaque device and its resources for this borrow.
        unsafe { self.inner.as_ref() }
    }
}

impl<T> Drop for DeviceRef<T> {
    fn drop(&mut self) {
        let device = self.inner.as_ptr().cast();
        // SAFETY: Release exactly the owned reference. This call may wake a waiter that frees
        // the allocation, so no device borrow spans it and no field is accessed afterwards.
        unsafe { bindings::ib_device_put(device) };
    }
}
