// SPDX-License-Identifier: GPL-2.0

//! Core-allocated address handles backed by owned provider data.

use super::{
    AddressAttributes,
    AddressRequest,
    Operations,
    ProtectionDomainOperations,
    ProtectionDomains,
    UserData, //
};
use crate::{
    bindings,
    net,
    prelude::*,
    types::ForeignOwnable, //
};
use core::{
    marker::PhantomData,
    ptr, //
};

crate::impl_flags!(
    /// Address-handle creation context supplied by the core.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct AddressCreateFlags(u32);

    /// An address-handle creation flag.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AddressCreateFlag {
        /// Allocation and other creation work may sleep.
        Sleepable = bindings::rdma_create_ah_flags_RDMA_CREATE_AH_SLEEPABLE,
        /// The handle will only be used with a subnet-management queue pair.
        Smi = bindings::rdma_create_ah_flags_RDMA_CREATE_AH_SMI,
    }
);

crate::impl_flags!(
    /// Address-handle release context supplied by the core.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct AddressReleaseFlags(u32);

    /// An address-handle release flag.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AddressReleaseFlag {
        /// Release work may sleep.
        Sleepable = bindings::rdma_destroy_ah_flags_RDMA_DESTROY_AH_SLEEPABLE,
    }
);

/// Address-handle operations implemented by pinned device data.
///
/// Callbacks may run concurrently; the provider synchronizes mutable private data. Creation
/// and release may sleep only when their flags permit it. Modification and query must not sleep.
#[vtable]
pub trait AddressHandleOperations: ProtectionDomainOperations {
    /// One owner transferred into each successfully created address handle.
    type AddressHandle: ForeignOwnable + Send + Sync + 'static;

    /// Whether the provider supports userspace address-handle creation.
    const USER_ADDRESS_HANDLES: bool = false;

    /// Creates private state while the core retains the domain and device.
    ///
    /// `transmit_slave` borrows the optional RoCE link-aggregation transmit device for this
    /// call only. Userspace buffers are present only for a sleepable userspace creation call.
    fn create_address(
        self: Pin<&Self>,
        domain: <Self::Domain as ForeignOwnable>::Borrowed<'_>,
        request: AddressRequest,
        flags: AddressCreateFlags,
        transmit_slave: Option<&net::Device>,
        data: Option<UserData<'_, Self>>,
    ) -> Result<Self::AddressHandle>;

    /// Changes a retained handle using copied core-validated attributes.
    fn modify_address(
        self: Pin<&Self>,
        _handle: <Self::AddressHandle as ForeignOwnable>::Borrowed<'_>,
        _request: AddressRequest,
    ) -> Result {
        Err(EOPNOTSUPP)
    }

    /// Returns address attributes without transferring a GID-cache reference.
    fn query_address(
        self: Pin<&Self>,
        _handle: <Self::AddressHandle as ForeignOwnable>::Borrowed<'_>,
    ) -> Result<AddressAttributes> {
        Err(EOPNOTSUPP)
    }

    /// Consumes private state after the caller has excluded further handle operations.
    ///
    /// Provider-internal users must drain before returning. Mandatory core cleanup does not
    /// retain a handle for another release attempt.
    fn release_address(self: Pin<&Self>, owner: Self::AddressHandle, _flags: AddressReleaseFlags) {
        drop(owner);
    }
}

#[repr(C)]
struct AddressHandle {
    core: bindings::ib_ah,
    private_data: *mut c_void,
}

/// Installs address-handle callbacks while leaving header ownership with the RDMA core.
pub struct AddressHandles<T: AddressHandleOperations>(PhantomData<T>);

impl<T: AddressHandleOperations> AddressHandles<T> {
    /// Installs supported operations before device publication.
    ///
    /// # Safety
    ///
    /// `device` must be exclusively owned and unpublished, with [`Operations::<T>::install`]
    /// and [`ProtectionDomains::<T>::install`] completed. All AH operation and size slots must
    /// be unused and must remain exclusively managed by this adapter. The device and domains
    /// must outlive their address handles, which must be released through the core.
    pub unsafe fn install(device: *mut bindings::ib_device) {
        // SAFETY: The caller exclusively owns the unpublished device and reserves these slots.
        unsafe {
            (*device).ops.size_ib_ah = size_of::<AddressHandle>();
            (*device).ops.create_ah = Some(Self::create);
            if T::USER_ADDRESS_HANDLES {
                (*device).ops.create_user_ah = Some(Self::create);
            }
            (*device).ops.destroy_ah = Some(Self::release);
            if T::HAS_MODIFY_ADDRESS {
                (*device).ops.modify_ah = Some(Self::modify);
            }
            if T::HAS_QUERY_ADDRESS {
                (*device).ops.query_ah = Some(Self::query);
            }
        }
    }

    /// Borrows private data while excluding release attempts.
    ///
    /// # Safety
    ///
    /// `handle` must be a successfully created handle belonging to this adapter. The caller
    /// must retain it, its domain and device for `'a`, and exclude all release attempts,
    /// including unsuccessful ones. Concurrent modification and query remain allowed.
    #[inline]
    pub unsafe fn data<'a>(
        handle: *mut bindings::ib_ah,
    ) -> <T::AddressHandle as ForeignOwnable>::Borrowed<'a> {
        // SAFETY: The initialized slot owns the foreign value; the caller excludes release.
        unsafe { T::AddressHandle::borrow((*handle.cast::<AddressHandle>()).private_data) }
    }

    /// # Safety
    ///
    /// The core must provide unpublished storage of the installed size, retain this adapter's
    /// initialized device and parents, and supply stable selected attributes and original
    /// uverbs data with disassociation excluded.
    unsafe extern "C" fn create(
        handle: *mut bindings::ib_ah,
        init: *mut bindings::rdma_ah_init_attr,
        data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core owns unpublished storage with an initialized header, retains its
        // domain and device, and supplies stable attributes and any GID/transmit-device refs.
        // Userspace data belongs to the original live uverbs bundle with disassociation excluded.
        unsafe {
            let request = match AddressRequest::from_raw((*init).ah_attr) {
                Ok(request) => request,
                Err(error) => return error.to_errno(),
            };
            let slave = if (*init).xmit_slave.is_null() {
                None
            } else {
                Some(net::Device::from_raw((*init).xmit_slave))
            };
            match Operations::<T>::data((*handle).device).create_address(
                ProtectionDomains::<T>::data((*handle).pd),
                request,
                AddressCreateFlags((*init).flags),
                slave,
                UserData::from_raw(data),
            ) {
                Ok(owner) => {
                    // Ownership transfer is the final, infallible step of creation.
                    (*handle.cast::<AddressHandle>()).private_data = owner.into_foreign();
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain this adapter's initialized object and parents, exclude release
    /// attempts, and supply stable initialized selected attributes and any original uverbs
    /// data.
    unsafe extern "C" fn modify(
        handle: *mut bindings::ib_ah,
        attr: *mut bindings::rdma_ah_attr,
    ) -> c_int {
        // SAFETY: The caller retains the handle and excludes release. The core retains stable
        // input attributes and any source GID reference for the duration of modification.
        unsafe {
            let request = match AddressRequest::from_raw(attr) {
                Ok(request) => request,
                Err(error) => return error.to_errno(),
            };
            Operations::<T>::data((*handle).device)
                .modify_address(Self::data(handle), request)
                .map_or_else(Error::to_errno, |()| 0)
        }
    }

    /// # Safety
    ///
    /// The caller must retain this adapter's initialized object and parents, exclude release
    /// attempts, and provide aligned, exclusively writable complete output storage.
    unsafe extern "C" fn query(
        handle: *mut bindings::ib_ah,
        attr: *mut bindings::rdma_ah_attr,
    ) -> c_int {
        // SAFETY: The caller retains the handle, excluding release, and provides exclusive
        // output storage without an owned GID reference. Output is written only after success.
        unsafe {
            match Operations::<T>::data((*handle).device).query_address(Self::data(handle)) {
                Ok(address) => {
                    if address.kind_raw() != (*handle).type_ {
                        return EINVAL.to_errno();
                    }
                    attr.write(address.to_raw());
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
    unsafe extern "C" fn release(handle: *mut bindings::ib_ah, flags: u32) -> c_int {
        // SAFETY: The core caller retains the allocation, domain and device while excluding
        // further handle operations. Cleanup consumes the owner before the core frees storage.
        unsafe {
            let slot = &raw mut (*handle.cast::<AddressHandle>()).private_data;
            let owner = T::AddressHandle::from_foreign(ptr::replace(slot, ptr::null_mut()));
            Operations::<T>::data((*handle).device)
                .release_address(owner, AddressReleaseFlags(flags));
            0
        }
    }
}
