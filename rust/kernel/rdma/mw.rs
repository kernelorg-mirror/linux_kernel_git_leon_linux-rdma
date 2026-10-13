// SPDX-License-Identifier: GPL-2.0

//! Owned provider data for core-allocated memory windows.

use super::{
    Operations,
    ProtectionDomainOperations,
    ProtectionDomains,
    ReleaseError,
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

/// Memory-window binding and invalidation semantics selected by the creator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryWindowType {
    /// A window rebound through a type 1 bind request.
    Type1,
    /// A window bound and invalidated through type 2 operations.
    Type2,
}

/// Private ownership and initial remote key returned by window creation.
pub struct WindowCreation<T> {
    /// The owner retained until successful release.
    pub owner: T,
    /// The initial remote key reported by the core to the creator.
    pub key: u32,
}

/// Memory-window operations implemented by pinned device data.
///
/// Creation and release run in sleepable context. The core retains the protection domain
/// through the window's lifetime. Provider-internal binding and transport users must be
/// synchronized with release by the provider; the core does not track those users.
pub trait MemoryWindowOperations: ProtectionDomainOperations {
    /// One private owner transferred into each successfully created window.
    type MemoryWindow: ForeignOwnable + Send + Sync + 'static;

    /// Creates private state and an initial remote key while the domain remains live.
    fn create_window(
        self: Pin<&Self>,
        domain: <Self::Domain as ForeignOwnable>::Borrowed<'_>,
        kind: MemoryWindowType,
        data: Option<UserData<'_, Self>>,
    ) -> Result<WindowCreation<Self::MemoryWindow>>;

    /// Consumes private state after excluding further core window operations.
    ///
    /// Before success the provider must unpublish the window and drain internal users of its
    /// private state. Failure returns a valid owner for later operations and release attempts.
    fn release_window(
        self: Pin<&Self>,
        owner: Self::MemoryWindow,
    ) -> Result<(), ReleaseError<Self::MemoryWindow>> {
        drop(owner);
        Ok(())
    }
}

#[repr(C)]
struct MemoryWindow {
    core: bindings::ib_mw,
    private_data: *mut c_void,
}

/// Installs memory-window callbacks while leaving header ownership with the RDMA core.
pub struct MemoryWindows<T: MemoryWindowOperations>(PhantomData<T>);

impl<T: MemoryWindowOperations> MemoryWindows<T> {
    /// Installs creation and release before device publication.
    ///
    /// # Safety
    ///
    /// `device` must be exclusively owned and unpublished, with [`Operations::<T>::install`]
    /// and [`ProtectionDomains::<T>::install`] completed. The `alloc_mw`, `dealloc_mw` and
    /// `size_ib_mw` slots must be unused and remain exclusively managed by this adapter.
    /// The device and domains must outlive their windows, which must be released by the core.
    #[inline]
    pub unsafe fn install(device: *mut bindings::ib_device) {
        // SAFETY: The caller exclusively owns the unpublished device and reserves these slots.
        unsafe {
            (*device).ops.size_ib_mw = size_of::<MemoryWindow>();
            (*device).ops.alloc_mw = Some(Self::create);
            (*device).ops.dealloc_mw = Some(Self::release);
        }
    }

    /// # Safety
    ///
    /// The core must supply an unpublished window with an initialized header and retain
    /// its domain/device and original optional uverbs bundle, excluding disassociation.
    unsafe extern "C" fn create(
        window: *mut bindings::ib_mw,
        data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core owns unpublished storage with an initialized header and retains
        // the domain and device. Optional userspace data belongs to the original live uverbs
        // bundle with disassociation excluded. Publication follows all fallible operations.
        unsafe {
            let kind = match (*window).type_ {
                bindings::ib_mw_type_IB_MW_TYPE_1 => MemoryWindowType::Type1,
                bindings::ib_mw_type_IB_MW_TYPE_2 => MemoryWindowType::Type2,
                _ => return EINVAL.to_errno(),
            };
            match Operations::<T>::data((*window).device).create_window(
                ProtectionDomains::<T>::data((*window).pd),
                kind,
                UserData::from_raw(data),
            ) {
                Ok(WindowCreation { owner, key }) => {
                    (*window).rkey = key;
                    (*window.cast::<MemoryWindow>()).private_data = owner.into_foreign();
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The core must retain the window, domain and device, exclude further core operations
    /// and reclaim the allocation only after successful release.
    unsafe extern "C" fn release(window: *mut bindings::ib_mw) -> c_int {
        // SAFETY: The core retains the allocation, domain and device and excludes further
        // core operations. Success consumes the owner before the core frees storage; failure
        // restores exactly the returned owner before operations or release attempts resume.
        unsafe {
            let slot = &raw mut (*window.cast::<MemoryWindow>()).private_data;
            let owner = T::MemoryWindow::from_foreign(ptr::replace(slot, ptr::null_mut()));
            match Operations::<T>::data((*window).device).release_window(owner) {
                Ok(()) => 0,
                Err(ReleaseError { error, owner }) => {
                    slot.write(owner.into_foreign());
                    error.to_errno()
                }
            }
        }
    }
}
