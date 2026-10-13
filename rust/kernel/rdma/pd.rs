// SPDX-License-Identifier: GPL-2.0

//! Owned provider data for core-allocated protection domains.

use super::{
    DeviceOperations,
    Operations,
    UserData, //
};
use crate::{
    bindings,
    prelude::*,
    types::ForeignOwnable, //
};
use core::{
    marker::PhantomData,
    ptr, //
};

crate::impl_flags!(
    /// Flags selected by the protection-domain creator.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ProtectionDomainFlags(u32);

    /// One protection-domain creation flag.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ProtectionDomainFlag {
        /// The core requests a global remote key for kernel memory.
        GlobalRemoteKey = bindings::ib_pd_flags_IB_PD_UNSAFE_GLOBAL_RKEY,
    }
);

/// A failed release which returns the owner to the still-live core object.
///
/// The provider must preserve data needed for later operations when returning this error.
/// The adapter restores ownership before reporting the error to the core.
pub struct ReleaseError<T> {
    /// The failure reported to the caller.
    pub error: Error,
    /// Ownership retained by the core object after the failed release.
    pub owner: T,
}

/// Protection-domain operations implemented by the device's pinned provider data.
///
/// The core or kernel caller keeps a domain alive until its child resources have been
/// synchronously destroyed. Callbacks for different domains may run concurrently.
pub trait ProtectionDomainOperations: DeviceOperations {
    /// Private ownership transferred into a successfully created domain.
    type Domain: ForeignOwnable + Send + Sync + 'static;

    /// Creates private domain data in sleepable context.
    ///
    /// Failure leaves no domain published. The core retains its device throughout creation
    /// and through the lifetime of a successfully created domain.
    fn create_domain(
        self: Pin<&Self>,
        flags: ProtectionDomainFlags,
        data: Option<UserData<'_, Self>>,
    ) -> Result<Self::Domain>;

    /// Releases private data after child objects and domain users have drained.
    ///
    /// The callback runs in sleepable context with exclusive ownership. It must finish cleanup
    /// before returning: mandatory core cleanup does not retain a handle for another attempt.
    fn release_domain(self: Pin<&Self>, owner: Self::Domain, _data: Option<UserData<'_, Self>>) {
        drop(owner);
    }
}

#[repr(C)]
struct Domain {
    core: bindings::ib_pd,
    private_data: *mut c_void,
}

/// Installs protection-domain callbacks backed by a Rust foreign owner.
///
/// The core owns the header and allocation. Successful creation transfers one Rust owner
/// into private storage; successful release consumes it before the core frees that storage.
pub struct ProtectionDomains<T: ProtectionDomainOperations>(PhantomData<T>);

impl<T: ProtectionDomainOperations> ProtectionDomains<T> {
    /// Installs domain creation and release before publishing a device.
    ///
    /// # Safety
    ///
    /// `device` must be an exclusively owned, unpublished core device on which
    /// [`Operations::<T>::install`] has succeeded. Its `alloc_pd`, `dealloc_pd` and `size_ib_pd`
    /// slots must be unused. These slots and domain private storage must remain exclusively
    /// managed by this adapter. The device must eventually be deallocated through the core
    /// after its domains and their child objects have been destroyed.
    pub unsafe fn install(device: *mut bindings::ib_device) {
        // SAFETY: The caller exclusively owns the unpublished device and reserves these slots.
        unsafe {
            (*device).ops.size_ib_pd = size_of::<Domain>();
            (*device).ops.alloc_pd = Some(Self::create);
            (*device).ops.dealloc_pd = Some(Self::release);
        }
    }

    /// Borrows the private data of a successfully created domain.
    ///
    /// # Safety
    ///
    /// `domain` must belong to this installed adapter. The caller must keep the domain and
    /// its device alive and exclude release attempts, including unsuccessful ones, for `'a`.
    #[inline]
    pub unsafe fn data<'a>(
        domain: *mut bindings::ib_pd,
    ) -> <T::Domain as ForeignOwnable>::Borrowed<'a> {
        // SAFETY: The initialized slot owns the foreign value and the caller excludes release.
        unsafe { T::Domain::borrow((*domain.cast::<Domain>()).private_data) }
    }

    /// # Safety
    ///
    /// The core must provide unpublished storage of the installed size, retain this adapter's
    /// initialized device and parents, and supply stable selected attributes and original
    /// uverbs data with disassociation excluded.
    unsafe extern "C" fn create(
        domain: *mut bindings::ib_pd,
        data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core owns unpublished storage with our configured size and initialized
        // header. It retains the installed device and optional original uverbs bundle while
        // excluding disassociation. No fallible operation follows ownership transfer.
        unsafe {
            let flags = ProtectionDomainFlags((*domain).flags);
            match Operations::<T>::data((*domain).device)
                .create_domain(flags, UserData::from_raw(data))
            {
                Ok(owner) => {
                    (*domain.cast::<Domain>()).private_data = owner.into_foreign();
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The core must exclude further operations and release this adapter's initialized owner
    /// exactly once, while retaining its allocation and parents until this callback returns.
    unsafe extern "C" fn release(
        domain: *mut bindings::ib_pd,
        data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core or kernel caller has drained the domain's users and child objects
        // and grants exclusive ownership for this release attempt. The installed device stays
        // live. Optional driver data belongs to the original uverbs bundle. Cleanup consumes
        // the owner before the core releases the allocation.
        unsafe {
            let slot = &raw mut (*domain.cast::<Domain>()).private_data;
            let owner = T::Domain::from_foreign(ptr::replace(slot, ptr::null_mut()));
            Operations::<T>::data((*domain).device).release_domain(owner, UserData::from_raw(data));
            0
        }
    }
}
