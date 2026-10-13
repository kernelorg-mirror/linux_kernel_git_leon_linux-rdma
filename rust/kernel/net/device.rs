// SPDX-License-Identifier: GPL-2.0

//! Borrowed network devices and ownership of existing core references.

use crate::{
    bindings,
    error::{
        code::{
            EINVAL,
            ENODEV, //
        },
        to_result,
        Result, //
    },
    sync::rcu,
    types::{
        NotThreadSafe,
        Opaque, //
    }, //
};
use core::{
    marker::PhantomData,
    ops::Deref,
    ptr::NonNull, //
};

/// Proof that the current task holds the network configuration lock.
///
/// An owned guard releases RTNL on drop. A notifier can lend a guard for its callback,
/// which does not release the caller's lock. Neither form can leave the current task.
pub struct RtnlGuard<'a> {
    unlock: bool,
    _borrow: PhantomData<&'a ()>,
    _not_thread_safe: NotThreadSafe,
}

impl RtnlGuard<'static> {
    /// Acquires RTNL in sleepable context. The current task must not already hold RTNL.
    pub fn lock() -> Self {
        // SAFETY: The caller supplies a sleepable context without recursively holding RTNL.
        unsafe { bindings::rtnl_lock() };
        Self {
            unlock: true,
            _borrow: PhantomData,
            _not_thread_safe: NotThreadSafe,
        }
    }
}

impl RtnlGuard<'_> {
    /// Borrows RTNL already held by the current task.
    ///
    /// # Safety
    ///
    /// The caller must hold RTNL throughout the returned guard's lifetime.
    pub(super) unsafe fn borrowed() -> Self {
        Self {
            unlock: false,
            _borrow: PhantomData,
            _not_thread_safe: NotThreadSafe,
        }
    }
}

impl Drop for RtnlGuard<'_> {
    fn drop(&mut self) {
        if self.unlock {
            // SAFETY: The owned, non-Send guard releases this task's acquisition exactly once.
            unsafe { bindings::rtnl_unlock() };
        }
    }
}

/// An owned snapshot of a network interface name.
///
/// Names contain arbitrary non-NUL bytes and need not be UTF-8.
#[derive(Clone, Copy, Debug)]
pub struct DeviceName {
    bytes: [u8; bindings::IFNAMSIZ as usize],
}

impl DeviceName {
    /// Returns the name bytes without the terminating NUL.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        let length = self
            .bytes
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(self.bytes.len());
        &self.bytes[..length]
    }
}

/// Link configuration copied while holding RTNL.
///
/// The snapshot owns its address bytes and grants no access to mutable device storage.
/// Its values may become stale after the lock is released.
///
/// # Invariants
///
/// `address_len` does not exceed the size of `address`.
#[derive(Clone, Copy, Debug)]
pub struct LinkInfo {
    /// Current maximum transmission unit in bytes.
    pub mtu: u32,
    /// Whether this interface is a VLAN device.
    pub is_vlan: bool,
    address: [u8; bindings::MAX_ADDR_LEN as usize],
    address_len: usize,
}

impl LinkInfo {
    /// Returns the copied link-layer address, which may be empty for some device types.
    #[inline]
    pub fn address(&self) -> &[u8] {
        &self.address[..self.address_len]
    }
}

/// A registered device's namespace and index sampled under RTNL or validated under RCU.
///
/// The namespace remains active while this value lives, but the device may subsequently move
/// or unregister. Keep this snapshot only for an operation, not in namespace-owned idle state.
pub struct DeviceLocation {
    device: DeviceRef,
    namespace: super::namespace::NamespaceRef,
    index: core::ffi::c_int,
}

impl DeviceLocation {
    /// Borrows the device whose identity was sampled.
    #[inline]
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// Borrows the active namespace reference retained by this snapshot.
    #[inline]
    pub fn namespace(&self) -> &super::namespace::NamespaceRef {
        &self.namespace
    }

    /// Returns the interface index observed in the retained namespace.
    #[inline]
    pub fn index(&self) -> core::ffi::c_int {
        self.index
    }
}

/// A borrowed, initialized network device.
///
/// This wrapper exposes no ordinary references to fields which networking may change.
/// Holding a borrow does not prevent device unregistration or namespace migration.
/// A borrow protected only by RCU cannot be used with methods that may sleep. Acquire an
/// independent [`DeviceRef`] with [`Self::to_ref`], leave the RCU read section, then call
/// those methods through the owned reference.
///
/// # Invariants
///
/// The wrapped network device is initialized and remains allocated throughout each borrow.
/// Its address lists and their lock remain initialized, and its address length does not exceed
/// `MAX_ADDR_LEN`.
#[repr(transparent)]
pub struct Device(Opaque<bindings::net_device>);

// SAFETY: The wrapper exposes only opaque C storage. Accessors use networking synchronization
// and do not borrow mutable fields; the reference provider retains the allocation.
unsafe impl Send for Device {}
// SAFETY: Shared accessors serialize mutable configuration or use the core's lockless readers.
unsafe impl Sync for Device {}

impl Device {
    /// Borrows a device retained by a core reference or an appropriate RCU read section.
    ///
    /// # Safety
    ///
    /// `device` must point to an initialized network device kept allocated for `'a`.
    /// Its lifetime protection must permit acquiring a reference with `dev_hold`.
    /// Destruction must wait for every independently acquired reference, including references
    /// that outlive this borrow. A never-registered device freed directly does not satisfy this.
    #[inline]
    pub unsafe fn from_raw<'a>(device: *mut bindings::net_device) -> &'a Self {
        // SAFETY: The caller guarantees the invariant for the borrow. The transparent wrapper
        // has the same layout and exposes only opaque access to the C allocation.
        unsafe { &*device.cast() }
    }

    /// Acquires an independent core reference without allocating Rust storage.
    #[inline]
    pub fn to_ref(&self) -> DeviceRef {
        // SAFETY: The borrow keeps the initialized reference count live during acquisition.
        unsafe { bindings::dev_hold(self.as_raw()) };
        // INVARIANT: The reference just acquired keeps this device allocated until release.
        DeviceRef {
            inner: NonNull::from(self),
        }
    }

    /// Snapshots the device's registered namespace and interface index.
    ///
    /// This may sleep and must run without RTNL held. Unregistered devices and namespaces
    /// which have not completed initialization or have begun cleanup return `ENODEV`.
    /// For an RCU-protected borrow, first acquire [`Self::to_ref`] and leave the read section.
    pub fn location(&self) -> Result<DeviceLocation> {
        self.location_locked(&RtnlGuard::lock())
    }

    /// Snapshots registered namespace membership while the caller keeps RTNL held.
    ///
    /// RTNL excludes concurrent registration and namespace migration. Callbacks can observe
    /// an unlisted device during either operation; such devices return `ENODEV`.
    pub fn location_locked(&self, _rtnl: &RtnlGuard<'_>) -> Result<DeviceLocation> {
        let device = self.as_raw();
        // SAFETY: The device borrow retains the allocation. Final unregistration updates this
        // field outside RTNL, so sample it without an ordinary shared-memory access.
        let state = unsafe { core::ptr::read_volatile(&raw const (*device).reg_state) };
        if u32::from(state) != bindings::netdev_reg_state_NETREG_REGISTERED {
            return Err(ENODEV);
        }
        // SAFETY: Registered devices retain their namespace allocation. RTNL excludes removal
        // and migration while reading the association and acquiring the independent reference.
        let net = unsafe { bindings::dev_net(device) };
        let _rcu = rcu::read_lock();
        // SAFETY: RTNL protects the sampled index, and RCU protects the index table. A
        // namespace-move callback can observe REGISTERED after the device was unlisted.
        let index = unsafe { (*device).ifindex };
        // SAFETY: Both the namespace and device remain allocated under this protection.
        if unsafe { bindings::dev_get_by_index_rcu(net, index) } != device {
            return Err(ENODEV);
        }
        // SAFETY: RCU protects the namespace tree lookup. Netdevs can be registered by pernet
        // initializers; namespace publication occurs only after every initializer has completed.
        if !unsafe { bindings::net_namespace_is_published(net) } {
            return Err(ENODEV);
        }
        // SAFETY: Publication establishes completed initialization. RTNL still retains the
        // namespace allocation; an active reference can fail if cleanup has become eligible.
        let namespace = unsafe { super::namespace::Namespace::from_raw(net) }
            .try_to_ref()
            .ok_or(ENODEV)?;
        Ok(DeviceLocation {
            device: self.to_ref(),
            namespace,
            index,
        })
    }

    /// Snapshots this device's index in an already active namespace without taking RTNL.
    ///
    /// The namespace must be published and the device must still belong to its index table.
    /// The returned snapshot can become stale; route lookup revalidates membership under RCU.
    pub fn location_in(
        &self,
        namespace: &super::namespace::NamespaceRef,
    ) -> Result<DeviceLocation> {
        let _guard = rcu::read_lock();
        // SAFETY: Both allocations remain live. Index lookup, rather than a plain dev_net
        // comparison, pairs with the RCU grace period preceding namespace migration.
        let index = unsafe {
            if !bindings::net_namespace_is_published(namespace.as_raw()) {
                return Err(ENODEV);
            }
            let index = core::ptr::read_volatile(&raw const (*self.as_raw()).ifindex);
            if bindings::dev_get_by_index_rcu(namespace.as_raw(), index) != self.as_raw() {
                return Err(ENODEV);
            }
            index
        };
        Ok(DeviceLocation {
            device: self.to_ref(),
            namespace: namespace.clone(),
            index,
        })
    }

    /// Returns the current link-layer headroom reservation.
    ///
    /// Networking may subsequently increase its headroom requirement. This is an allocation
    /// hint and does not grant access to packet storage or freeze device configuration.
    #[inline]
    pub fn reserved_space(&self) -> usize {
        // SAFETY: The device remains allocated. The helper samples both mutable reservation
        // fields with READ_ONCE without exposing a borrow of the device's fields.
        unsafe { bindings::ll_reserved_space(self.as_raw()) as usize }
    }

    /// Samples whether the device has been opened and remains administratively running.
    #[inline]
    pub fn is_running(&self) -> bool {
        // SAFETY: The borrow retains the allocation; the helper samples the core state bit.
        unsafe { bindings::netif_running(self.as_raw()) }
    }

    /// Samples whether the driver currently reports carrier availability.
    #[inline]
    pub fn has_carrier(&self) -> bool {
        // SAFETY: The borrow retains the allocation; the helper samples the core state bit.
        unsafe { bindings::netif_carrier_ok(self.as_raw()) }
    }

    /// Returns the VLAN identifier for an 802.1Q device, or `None` for other devices.
    #[inline]
    pub fn vlan_id(&self) -> Option<u16> {
        // SAFETY: The initialized allocation retains its private storage. The native VLAN
        // predicate reads the VLAN bit, which stays fixed after publication along with
        // the identifier, even while other feature bits change.
        unsafe {
            if bindings::is_vlan_dev(self.as_raw()) {
                Some(bindings::vlan_dev_vlan_id(self.as_raw()))
            } else {
                None
            }
        }
    }

    /// Adds a multicast address reference, updating the device's receive filter.
    ///
    /// RTNL keeps the address length stable and excludes the final multicast-list flush.
    /// Only registered devices admit new references. Each successful addition needs a
    /// matching removal unless networking flushes the list during device teardown.
    #[inline]
    pub fn add_multicast_address(&self, _rtnl: &RtnlGuard<'_>, address: &[u8]) -> Result {
        self.update_multicast_address(address, true)
    }

    /// Removes one multicast address reference, updating the device's receive filter.
    ///
    /// RTNL keeps the address length stable. Removal can fail if networking already flushed
    /// the list during unregistration or a namespace move.
    #[inline]
    pub fn remove_multicast_address(&self, _rtnl: &RtnlGuard<'_>, address: &[u8]) -> Result {
        self.update_multicast_address(address, false)
    }

    fn update_multicast_address(&self, address: &[u8], add: bool) -> Result {
        let mut bytes = [0u8; bindings::MAX_ADDR_LEN as usize];
        let output = bytes.get_mut(..address.len()).ok_or(EINVAL)?;
        output.copy_from_slice(address);
        let device = self.as_raw();
        // SAFETY: RTNL excludes registration changes which could admit an addition after
        // final multicast-list flushing. Later unregister-state updates use WRITE_ONCE.
        let state = unsafe { core::ptr::read_volatile(&raw const (*device).reg_state) };
        if add && u32::from(state) != bindings::netdev_reg_state_NETREG_REGISTERED {
            return Err(ENODEV);
        }
        // SAFETY: Every caller holds RTNL, which excludes link-layer address-length changes.
        let length = unsafe { (*device).addr_len };
        if address.len() != usize::from(length) {
            return Err(EINVAL);
        }
        // SAFETY: RTNL keeps the validated address length stable through the operation.
        // The core helpers additionally serialize their address-list access.
        to_result(unsafe {
            if add {
                bindings::dev_mc_add(device, bytes.as_ptr())
            } else {
                bindings::dev_mc_del(device, bytes.as_ptr())
            }
        })
    }

    /// Copies the current interface name under RTNL.
    ///
    /// This may sleep and must be called without RTNL held. The returned value remains valid
    /// after a rename or device removal, but may no longer match the device's current name.
    /// For an RCU-protected borrow, first acquire [`Self::to_ref`] and leave the read section.
    pub fn name(&self) -> DeviceName {
        let mut name = DeviceName {
            bytes: [0; bindings::IFNAMSIZ as usize],
        };
        // SAFETY: The borrow retains the initialized device. RTNL excludes both renames and
        // namespace migration. The arrays have the same size and no ordinary Rust reference
        // covers the C name storage while copying it into this independent value.
        unsafe {
            bindings::rtnl_lock();
            core::ptr::copy_nonoverlapping(
                (&raw const (*self.as_raw()).name).cast::<u8>(),
                name.bytes.as_mut_ptr(),
                name.bytes.len(),
            );
            bindings::rtnl_unlock();
        }
        name
    }

    /// Copies the address, MTU and VLAN indication under RTNL.
    ///
    /// This may sleep and must be called without RTNL held. The device borrow retains its
    /// allocation and address storage, including while unregistration waits for references.
    /// For an RCU-protected borrow, first acquire [`Self::to_ref`] and leave the read section.
    pub fn link_info(&self) -> LinkInfo {
        self.link_info_locked(&RtnlGuard::lock())
    }

    /// Copies link configuration while the caller keeps RTNL held.
    ///
    /// The guard permits publishing dependent state before a later configuration notifier
    /// can update it, avoiding replacement of a newer notification by an older snapshot.
    pub fn link_info_locked(&self, _rtnl: &RtnlGuard<'_>) -> LinkInfo {
        let device = self.as_raw();
        let mut address = [0; bindings::MAX_ADDR_LEN as usize];
        // SAFETY: The device borrow retains initialized storage. RTNL excludes concurrent
        // address and MTU changes. The bounded copy accesses only the core's MAX_ADDR_LEN
        // address buffer, and no ordinary reference covers the C device or its address.
        unsafe {
            let address_len = usize::from((*device).addr_len).min(address.len());
            if address_len != 0 {
                core::ptr::copy_nonoverlapping(
                    (*device).dev_addr,
                    address.as_mut_ptr(),
                    address_len,
                );
            }
            // INVARIANT: The copied length is bounded by the owned address array.
            LinkInfo {
                mtu: (*device).mtu,
                is_vlan: bindings::is_vlan_dev(device),
                address,
                address_len,
            }
        }
    }

    /// Returns the pointer for interoperability with C networking interfaces.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::net_device {
        self.0.get()
    }
}

/// Owns one network-device core reference.
///
/// The reference protects allocation lifetime, not registration state. Dropping it releases
/// exactly one core reference; [`Self::into_raw`] transfers that obligation to a C owner.
///
/// # Invariants
///
/// `inner` points to an initialized device and owns one reference acquired with `dev_hold`.
pub struct DeviceRef {
    inner: NonNull<Device>,
}

// SAFETY: Core device references may be acquired and released on different CPUs.
unsafe impl Send for DeviceRef {}
// SAFETY: Shared access exposes only the synchronized Device interface.
unsafe impl Sync for DeviceRef {}

impl Clone for DeviceRef {
    #[inline]
    fn clone(&self) -> Self {
        self.to_ref()
    }
}

impl DeviceRef {
    /// Takes ownership of a network-device reference acquired by C.
    ///
    /// # Safety
    ///
    /// `device` must point to an initialized network device with one owned core reference.
    /// The caller transfers that reference to the returned owner and must not release it.
    /// Destruction must wait for this reference and every reference cloned from it. A
    /// never-registered device freed without draining references does not satisfy this.
    #[inline]
    pub unsafe fn from_raw(device: *mut bindings::net_device) -> Self {
        // SAFETY: The transferred reference guarantees a non-null, live device. `Device`
        // transparently wraps the C allocation and exposes only opaque access.
        let inner = unsafe { NonNull::new_unchecked(device.cast()) };
        // INVARIANT: The owner holds the transferred reference until Drop or into_raw.
        Self { inner }
    }

    /// Transfers the owned reference to a caller responsible for eventually calling `dev_put`.
    #[inline]
    pub fn into_raw(self) -> *mut bindings::net_device {
        let device = self.as_raw();
        core::mem::forget(self);
        device
    }
}

impl Deref for DeviceRef {
    type Target = Device;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: The owned core reference pins the allocation throughout this borrow.
        unsafe { self.inner.as_ref() }
    }
}

impl Drop for DeviceRef {
    fn drop(&mut self) {
        // SAFETY: The invariant transfers exactly one live reference to the core release.
        unsafe { bindings::dev_put(self.as_raw()) };
    }
}
