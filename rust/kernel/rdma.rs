// SPDX-License-Identifier: GPL-2.0

//! RDMA provider interfaces.
//!
//! C header: [`include/rdma/ib_verbs.h`](srctree/include/rdma/ib_verbs.h)

use crate::{
    bindings,
    types::Opaque, //
};
use core::marker::PhantomData;

#[cfg(CONFIG_INFINIBAND_VIRT_DMA)]
pub mod virt_dma;

/// A borrowed RDMA core device belonging to provider `T`.
///
/// The provider parameter keeps operations in the provider's crate, allowing the RDMA core and
/// its Rust providers to be built as modules. The C object is opaque: a borrow does not confer
/// access to fields that the RDMA core may change concurrently.
///
/// # Invariants
///
/// This is a live, initialized `ib_device` belonging to `T`. Its allocation, DMA configuration
/// and any resources needed by the operations exposed here remain valid throughout a borrow.
/// Registered devices follow core unregistration, which drains queued cache events before
/// final deallocation. Acquired registration references keep the DMA configuration and
/// resources exposed by this interface valid until those references drain.
#[repr(transparent)]
pub struct Device<T> {
    inner: Opaque<bindings::ib_device>,
    _provider: PhantomData<T>,
}

impl<T> Device<T> {
    /// Borrows a device supplied by the RDMA core.
    ///
    /// # Safety
    ///
    /// `device` must be a live, initialized device belonging to `T`, kept alive for `'a`.
    /// DMA configuration, including whether virtual DMA tracking is enabled, must remain
    /// unchanged for `'a`. All mappings must obey the DMA API's storage lifetime and access
    /// requirements. In particular, storage in a tracked virtual DMA mapping cannot be borrowed
    /// through ordinary Rust references until that mapping has been unmapped, even if a captured
    /// mapping handle outlives the device borrow.
    /// After any successful registration, core unregistration must drain queued cache events
    /// before final deallocation, including events published during this borrow.
    /// While registration references can be acquired, their lifetime must also retain the DMA
    /// configuration and resources exposed by this interface.
    #[inline]
    pub unsafe fn from_raw<'a>(device: *mut bindings::ib_device) -> &'a Self {
        // SAFETY: The caller guarantees the invariant for 'a. The transparent wrapper exposes
        // only opaque access to the C object and adds no storage or alignment requirements.
        unsafe { &*device.cast() }
    }

    /// Returns the pointer for interoperability with C RDMA interfaces.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::ib_device {
        self.inner.get()
    }
}
