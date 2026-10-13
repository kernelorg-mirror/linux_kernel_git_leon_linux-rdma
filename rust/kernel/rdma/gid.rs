// SPDX-License-Identifier: GPL-2.0

//! Scoped GID-cache access and ownership of acquired attributes.
//!
//! C header: [`include/rdma/ib_cache.h`](srctree/include/rdma/ib_cache.h)

use super::{
    Device,
    DeviceRef, //
};
use crate::{
    bindings,
    error::{
        from_err_ptr,
        Result, //
    },
    ffi::c_int,
    net,
    sync::rcu, //
};
use core::ptr::{
    self,
    NonNull, //
};

/// The link protocol associated with a GID-cache entry.
#[derive(Clone, Copy)]
pub enum Type {
    /// Native InfiniBand.
    InfiniBand,
    /// RoCE over Ethernet.
    Roce,
    /// RoCE over UDP.
    RoceUdpEncap,
}

impl Type {
    #[inline]
    fn as_raw(self) -> bindings::ib_gid_type {
        match self {
            Self::InfiniBand => bindings::ib_gid_type_IB_GID_TYPE_IB,
            Self::Roce => bindings::ib_gid_type_IB_GID_TYPE_ROCE,
            Self::RoceUdpEncap => bindings::ib_gid_type_IB_GID_TYPE_ROCE_UDP_ENCAP,
        }
    }
}

/// Borrows a device while its GID cache remains available.
///
/// This is a separate capability from a device allocation borrow: keeping an allocation alive
/// does not by itself prevent GID-cache teardown. Table updates and invalidation remain allowed.
///
/// # Invariants
///
/// The core's port data and GID cache are initialized and cannot be destroyed for `'a`.
pub struct Table<'a, T> {
    device: &'a Device<T>,
}

impl<'a, T> Table<'a, T> {
    /// Borrows the cache retained by an owned device registration reference.
    #[inline]
    pub fn from_reference(device: &'a DeviceRef<T>) -> Self {
        // INVARIANT: Registration initializes port data and caches before enabling reference
        // acquisition. Unregistration waits for this reference before destroying those caches.
        Self { device }
    }

    /// Borrows the cache during a callback or operation that excludes cache teardown.
    ///
    /// # Safety
    ///
    /// `device` must retain initialized port data and GID tables for `'a`. Merely retaining
    /// the device allocation is insufficient; unregistration must not destroy its cache.
    #[inline]
    pub unsafe fn from_device(device: &'a Device<T>) -> Self {
        // INVARIANT: The caller guarantees that the cache outlives this capability.
        Self { device }
    }

    /// Acquires a GID attribute by port and index. Invalid or absent entries return an error.
    #[inline]
    pub fn get(&self, port: u32, index: c_int) -> Result<Attribute<'_, T>> {
        // SAFETY: The table capability pins the device and cache. The core validates both
        // indices and acquires the entry reference while holding its cache lock.
        let attr = from_err_ptr(unsafe {
            bindings::rdma_get_gid_attr(self.device.as_raw(), port, index).cast_mut()
        })?;
        // INVARIANT: Successful lookup returned one reference and a non-null attribute. The
        // returned lifetime cannot outlive this cache borrow.
        Ok(Attribute {
            inner: NonNull::new(attr).unwrap(),
            _device: self.device,
        })
    }

    /// Acquires a matching GID, optionally restricted to one network device.
    #[inline]
    pub fn find(
        &self,
        port: u32,
        gid: [u8; 16],
        kind: Type,
        netdev: Option<&net::Device>,
    ) -> Result<Attribute<'_, T>> {
        let gid = bindings::ib_gid { raw: gid };
        // SAFETY: The table and optional device borrows pin lookup inputs. The core checks
        // the port and acquires any returned reference under the cache lock.
        let attr = from_err_ptr(unsafe {
            bindings::rdma_find_gid_by_port(
                self.device.as_raw(),
                &gid,
                kind.as_raw(),
                port,
                netdev.map_or(ptr::null_mut(), net::Device::as_raw),
            )
            .cast_mut()
        })?;
        // INVARIANT: The successful lookup owns one attribute reference for this cache borrow.
        Ok(Attribute {
            inner: NonNull::new(attr).unwrap(),
            _device: self.device,
        })
    }
}

/// Owns a GID-cache attribute reference within a live cache borrow.
///
/// The attribute may be invalidated while held. Operations that require a currently attached
/// network device can therefore fail. Dropping this owner releases its cache reference.
///
/// # Invariants
///
/// `inner` owns one acquired attribute reference. Its device and cache remain live for `'a`.
pub struct Attribute<'a, T> {
    inner: NonNull<bindings::ib_gid_attr>,
    _device: &'a Device<T>,
}

impl<T> Attribute<'_, T> {
    /// Acquires the associated network device while its RCU protection is held.
    ///
    /// The returned reference remains valid independently of the attribute. It protects
    /// allocation lifetime, without freezing network-device registration or configuration.
    #[inline]
    pub fn net_device(&self) -> Result<net::DeviceRef> {
        let _guard = rcu::read_lock();
        // SAFETY: The owner pins the attribute and cache; RCU protects the returned device
        // until an independent reference is acquired below.
        let device =
            from_err_ptr(unsafe { bindings::rdma_read_gid_attr_ndev_rcu(self.inner.as_ptr()) })?;
        // SAFETY: The initialized network device remains live in this RCU read section.
        Ok(unsafe { net::Device::from_raw(device) }.to_ref())
    }
}

impl<T> Drop for Attribute<'_, T> {
    fn drop(&mut self) {
        // SAFETY: This owner releases exactly the attribute reference acquired by lookup.
        // The cache capability keeps the core's table available during release.
        unsafe { bindings::rdma_put_gid_attr(self.inner.as_ptr()) };
    }
}
