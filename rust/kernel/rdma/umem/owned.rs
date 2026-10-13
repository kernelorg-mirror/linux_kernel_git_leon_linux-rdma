// SPDX-License-Identifier: GPL-2.0

//! Ownership of CPU-accessible user registrations on virtual-DMA devices.

use super::PinnedMemory;
use crate::{
    bindings,
    error::{
        code::*,
        from_err_ptr,
        to_result,
        Result, //
    },
    ffi::c_int,
    rdma::{
        virt_dma::VirtualDma,
        AccessFlags, //
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

/// Owns a user registration and the core device needed to release it.
///
/// # Invariants
///
/// `inner` owns an ordinary or explicit ODP umem on a tracked virtual-DMA device, and one
/// reference to that device. Only core code is needed for release; no provider state is retained.
/// Metadata remains immutable. ODP registrations use the core CPU notifier. Contents are shared
/// user memory and are never exposed through ordinary Rust references.
struct Registration<T> {
    inner: NonNull<bindings::ib_umem>,
    _provider: PhantomData<fn() -> T>,
}

// SAFETY: Ownership and release are not thread-bound. The registration retains its mm and device.
unsafe impl<T> Send for Registration<T> {}
// SAFETY: Metadata is immutable and accessors copy shared data or hold the ODP invalidation lock.
unsafe impl<T> Sync for Registration<T> {}

impl<T> Registration<T> {
    /// Takes a newly created registration on a live tracked virtual-DMA device.
    ///
    /// # Safety
    ///
    /// The caller transfers sole ownership of an ordinary or explicit ODP umem. It must satisfy
    /// the registration invariant, except for the device reference which is acquired here.
    unsafe fn new(umem: *mut bindings::ib_umem) -> Self {
        // SAFETY: The caller retains the live device through acquisition of this reference.
        unsafe { bindings::get_device(&raw mut (*(*umem).ibdev).__bindgen_anon_1.dev) };
        // INVARIANT: The transferred registration and new device reference establish ownership.
        Self {
            // SAFETY: A successfully created registration is non-null.
            inner: unsafe { NonNull::new_unchecked(umem) },
            _provider: PhantomData,
        }
    }

    fn check_access(&self, access: AccessFlags) -> Result {
        // SAFETY: The registration owns immutable metadata. This check does not modify it.
        to_result(unsafe {
            bindings::ib_umem_check_rereg(
                self.inner.as_ptr(),
                bindings::ib_mr_rereg_flags_IB_MR_REREG_ACCESS as c_int,
                u32::from(access) as c_int,
            )
        })
    }
}

impl<T> Drop for Registration<T> {
    fn drop(&mut self) {
        // SAFETY: Exclusive ownership of this handle excludes Rust borrows. Release unpins
        // ordinary memory or drops the ODP backing reference, synchronizing notifiers on the
        // last release. Independent prefetch references retain their own device references.
        unsafe {
            let dev = (*self.inner.as_ptr()).ibdev;
            bindings::ib_umem_release(self.inner.as_ptr());
            bindings::put_device(&raw mut (*dev).__bindgen_anon_1.dev);
        }
    }
}

/// An owned pinned registration, created by [`VirtualDma::pin_user_memory`].
///
/// Dereferencing borrows bounded CPU access to the pinned memory. Dropping this owner releases
/// its page pins, memory-lock accounting and core device reference, and may sleep.
///
/// # Invariants
///
/// The owned registration is ordinary pinned memory, never ODP or dma-buf memory.
pub struct OwnedPinnedMemory<T>(Registration<T>);

impl<T> Deref for OwnedPinnedMemory<T> {
    type Target = PinnedMemory<T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: The invariant guarantees an ordinary registration with immutable metadata.
        // The transparent borrowed wrapper cannot outlive its owner.
        unsafe { &*self.0.inner.as_ptr().cast() }
    }
}

impl<T> OwnedPinnedMemory<T> {
    /// Checks whether existing pins permit new RDMA access rights.
    ///
    /// Call from process context: persistent access also checks the backing resources.
    #[inline]
    pub fn check_access(&self, access: AccessFlags) -> Result {
        if access.contains(crate::rdma::Access::FlushPersistent) && !self.is_persistent() {
            return Err(EOPNOTSUPP);
        }
        self.0.check_access(access)
    }
}

impl<T> VirtualDma<'_, T> {
    /// Pins a range in the current process for bounded CPU access.
    ///
    /// This operation may sleep. Addresses are userspace integers validated by the core pinning
    /// API. ODP and dma-buf registrations are not accepted by this interface. The returned owner
    /// retains the core device independently of this borrow.
    pub fn pin_user_memory(
        &self,
        address: u64,
        length: usize,
        access: AccessFlags,
    ) -> Result<OwnedPinnedMemory<T>> {
        let current = crate::current!();
        let _mm = current.mm().ok_or(EINVAL)?;
        // SAFETY: The virtual-DMA borrow pins the device. The core validates the user range,
        // rejects ODP and creates complete-page scatterlist entries with the requested pins.
        // A null attribute bundle selects only the ordinary userspace-address registration.
        let umem = from_err_ptr(unsafe {
            bindings::ib_umem_get_attr_or_va(
                self.device.as_raw(),
                ptr::null(),
                0,
                address,
                length,
                u32::from(access) as c_int,
            )
        })?;
        // INVARIANT: Registration succeeded through the ordinary-memory constructor.
        // SAFETY: The newly owned umem satisfies the pinning and shared-memory invariants.
        let memory = OwnedPinnedMemory(unsafe { Registration::new(umem) });
        memory.check_access(access)?;
        Ok(memory)
    }
}

#[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
mod odp {
    use super::*;
    use crate::rdma::odp::{
        OnDemandMemory,
        Prefetch,
        WRITE, //
    };

    /// An owned explicit ODP registration on a tracked virtual-DMA device.
    ///
    /// Its notifier excludes invalidation throughout every bounded CPU access. Dropping the
    /// last backing reference synchronizes notifier callbacks before release and may sleep.
    ///
    /// # Invariants
    ///
    /// The registration is explicit ODP and uses the core CPU-only invalidation callback.
    pub struct OwnedOnDemandMemory<T>(Registration<T>);

    impl<T> OwnedOnDemandMemory<T> {
        /// Queues a best-effort prefetch without retaining the provider or its MR.
        ///
        /// The core worker owns the backing registration and device until the fault finishes.
        /// Releasing this owner does not wait for the worker. No provider callback is invoked.
        /// The operation may allocate, and must be called from sleepable context.
        pub fn prefetch_async(&self, offset: usize, length: usize, mode: Prefetch) -> Result {
            let address = self.address(offset, length)?;
            let (write, fault) = match mode {
                Prefetch::Read => (false, true),
                Prefetch::Write => (true, true),
                Prefetch::Snapshot => (self.is_writable(), false),
            };
            if write && !self.is_writable() {
                return Err(EPERM);
            }
            if length == 0 {
                return Ok(());
            }
            // SAFETY: This owner retains an explicit registration with the core CPU notifier.
            // The checked range and access flags are valid. The helper acquires independent
            // backing and device references before scheduling its core-resident worker.
            to_result(unsafe {
                let odp = crate::container_of!(self.0.inner.as_ptr(), bindings::ib_umem_odp, umem);
                bindings::ib_umem_odp_queue_prefetch(
                    odp,
                    address as u64,
                    length as u64,
                    if write { WRITE as u64 } else { 0 },
                    fault,
                )
            })
        }

        /// Checks whether the registration permits new RDMA access rights.
        #[inline]
        pub fn check_access(&self, access: AccessFlags) -> Result {
            if access.contains(crate::rdma::Access::FlushPersistent) {
                return Err(EOPNOTSUPP);
            }
            self.0.check_access(access)
        }
    }

    impl<T> Deref for OwnedOnDemandMemory<T> {
        type Target = OnDemandMemory<T>;

        #[inline]
        fn deref(&self) -> &Self::Target {
            // SAFETY: The owner invariant supplies an explicit virtual-DMA ODP object with the
            // required notifier. Its immutable metadata and allocation outlive this borrow.
            unsafe {
                let odp = crate::container_of!(self.0.inner.as_ptr(), bindings::ib_umem_odp, umem);
                &*odp.cast()
            }
        }
    }

    impl<T> VirtualDma<'_, T> {
        /// Registers an explicit range in the current process for CPU-only on-demand access.
        ///
        /// Registration and accesses may sleep. The owner retains the device independently of
        /// this borrow. Invalidation, PFN publication and CPU access share the umem mutex.
        /// Persistent-flush access is unsupported because ODP backing has no persistence guarantee.
        pub fn register_on_demand(
            &self,
            address: usize,
            length: usize,
            access: AccessFlags,
        ) -> Result<OwnedOnDemandMemory<T>> {
            let current = crate::current!();
            let _mm = current.mm().ok_or(EINVAL)?;
            if !access.contains(crate::rdma::Access::OnDemand) {
                return Err(EINVAL);
            }
            if (address == 0 && length == usize::MAX)
                || access.contains(crate::rdma::Access::FlushPersistent)
            {
                return Err(EOPNOTSUPP);
            }
            // SAFETY: The device borrow retains the virtual-DMA configuration. The core checks
            // the user range, constructs explicit ODP metadata and installs its CPU-only notifier.
            let odp = from_err_ptr(unsafe {
                bindings::ib_umem_odp_get_cpu(
                    self.device.as_raw(),
                    address,
                    length,
                    u32::from(access) as c_int,
                )
            })?;
            // INVARIANT: The core created an explicit registration with the CPU-access notifier.
            // SAFETY: This transfers sole ownership of its embedded umem while the device is live.
            Ok(OwnedOnDemandMemory(unsafe {
                Registration::new(&raw mut (*odp).umem)
            }))
        }
    }
}

#[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
pub use odp::OwnedOnDemandMemory;
