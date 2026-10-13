// SPDX-License-Identifier: GPL-2.0

//! Rust-owned private data for core-allocated RDMA userspace contexts.

use super::{
    DeviceOperations,
    Operations,
    UserData, //
};
use crate::{
    bindings,
    mm::virt::VmaNew,
    prelude::*,
    types::ForeignOwnable, //
};
use core::{
    marker::PhantomData,
    ptr, //
};

/// User-context operations implemented by the device's pinned provider data.
///
/// The core allocates the context header, pins the device throughout its lifetime and calls
/// release exactly once after a successful allocation. Different contexts may run concurrently.
#[vtable]
pub trait UserContextOperations: DeviceOperations {
    /// Ownership transferred into the context, commonly a pinned box or `()`.
    type Context: ForeignOwnable + Send + Sync + 'static;

    /// Creates private context data in sleepable context.
    ///
    /// Failure leaves no context published. A successful return transfers the owner to the
    /// core, which eventually passes it to [`Self::release_context`].
    fn create_context(self: Pin<&Self>, data: Option<UserData<'_, Self>>) -> Result<Self::Context>;

    /// Releases private data after context operations and child objects have drained.
    ///
    /// The device remains live and sleeping is allowed. Driver removal calls disassociation
    /// before this method when implemented; closing a file does not require disassociation.
    fn release_context(self: Pin<&Self>, context: Self::Context) {
        drop(context);
    }

    /// Revokes driver-specific access during device removal, before releasing the context.
    ///
    /// Called in sleepable context after in-flight uverbs operations have drained. Implementing
    /// this method allows removal without waiting for userspace to close its files. Providers
    /// must revoke any remaining access to resources that will be released during removal.
    fn disassociate_context(
        self: Pin<&Self>,
        _context: <Self::Context as ForeignOwnable>::Borrowed<'_>,
    ) {
    }

    /// Initializes a userspace mapping while the core retains the context and device.
    ///
    /// The mmap write lock is held, disassociation is excluded and sleeping is allowed.
    /// Concurrent mapping and child-object operations remain possible. Return any mapping
    /// error so the memory manager removes partially installed pages.
    fn mmap(
        self: Pin<&Self>,
        _context: <Self::Context as ForeignOwnable>::Borrowed<'_>,
        _vma: &VmaNew,
    ) -> Result {
        Err(EOPNOTSUPP)
    }
}

// The core owns and initializes the header. Only the adapter accesses private_data, which
// contains a foreign owner after successful allocation and is cleared during final release.
#[repr(C)]
struct Context {
    core: bindings::ib_ucontext,
    private_data: *mut c_void,
}

/// Installs user-context callbacks for an already installed Rust device provider.
///
/// The adapter reserves private storage after the core header. A successful creation transfers
/// precisely one foreign owner into that storage; the core owns the surrounding allocation.
pub struct UserContexts<T: UserContextOperations>(PhantomData<T>);

impl<T: UserContextOperations> UserContexts<T> {
    /// Installs context allocation, release and optional disassociation callbacks.
    ///
    /// # Safety
    ///
    /// `device` must be an exclusively owned, unpublished core device on which
    /// [`Operations::<T>::install`] has succeeded. Its `alloc_ucontext`, `dealloc_ucontext`,
    /// `disassociate_ucontext` and `size_ib_ucontext` slots must be unused. After installation,
    /// those slots and context private storage must remain exclusively managed by this adapter.
    /// The device must eventually be deallocated through the core, which drains its contexts
    /// before releasing the installed provider data.
    /// If `T` implements `mmap`, that slot must also be unused and remain managed by this adapter.
    pub unsafe fn install(device: *mut bindings::ib_device) {
        // SAFETY: The caller exclusively owns the unpublished device and reserves these slots.
        unsafe {
            (*device).ops.size_ib_ucontext = size_of::<Context>();
            (*device).ops.alloc_ucontext = Some(Self::create);
            (*device).ops.dealloc_ucontext = Some(Self::release);
            if T::HAS_DISASSOCIATE_CONTEXT {
                (*device).ops.disassociate_ucontext = Some(Self::disassociate);
            }
            if T::HAS_MMAP {
                (*device).ops.mmap = Some(Self::mmap);
            }
        }
    }

    /// Borrows private data from a successfully initialized context.
    ///
    /// # Safety
    ///
    /// `context` must belong to this adapter. The caller must retain the context and its
    /// device and exclude release and disassociation for `'a`. Creation must have completed;
    /// the provisional context supplied during `create_context` does not satisfy this contract.
    #[inline]
    pub unsafe fn data<'a>(
        context: *mut bindings::ib_ucontext,
    ) -> <T::Context as ForeignOwnable>::Borrowed<'a> {
        // SAFETY: The initialized slot owns the foreign value and release is excluded.
        unsafe { T::Context::borrow((*context.cast::<Context>()).private_data) }
    }

    /// # Safety
    ///
    /// The uverbs mmap entry retains the initialized context and device while holding
    /// disassociation SRCU and hw_destroy_rwsem. The VMA is in initial mmap setup.
    unsafe extern "C" fn mmap(
        context: *mut bindings::ib_ucontext,
        vma: *mut bindings::vm_area_struct,
    ) -> c_int {
        // SAFETY: The uverbs mmap entry retains the initialized context and device while
        // holding disassociation SRCU and hw_destroy_rwsem. The VMA is in initial mmap setup.
        unsafe {
            Operations::<T>::data((*context).device)
                .mmap(Self::data(context), VmaNew::from_raw(vma))
                .map_or_else(Error::to_errno, |()| 0)
        }
    }

    /// # Safety
    ///
    /// The core must provide unpublished storage of the installed size, retain this adapter's
    /// initialized device and parents, and supply stable selected attributes and original
    /// uverbs data with disassociation excluded.
    unsafe extern "C" fn create(
        context: *mut bindings::ib_ucontext,
        data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core owns unpublished storage with our configured size and initialized
        // header. It retains the installed device and the original uverbs bundle, excluding
        // disassociation. No fallible operation follows transfer of the foreign owner.
        unsafe {
            match Operations::<T>::data((*context).device).create_context(UserData::from_raw(data))
            {
                Ok(owner) => {
                    (*context.cast::<Context>()).private_data = owner.into_foreign();
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
    unsafe extern "C" fn release(context: *mut bindings::ib_ucontext) {
        // SAFETY: The core calls release once after successful creation and drains other users
        // first. Take exactly the installed owner, leaving the core header to its allocator.
        // The provider data remains live until after context destruction completes.
        unsafe {
            let owner = ptr::replace(
                &raw mut (*context.cast::<Context>()).private_data,
                ptr::null_mut(),
            );
            Operations::<T>::data((*context).device)
                .release_context(T::Context::from_foreign(owner));
        }
    }

    /// # Safety
    ///
    /// The caller must retain a successfully initialized context and its device while
    /// excluding in-flight uverbs operations. Release occurs after this scoped borrow ends.
    unsafe extern "C" fn disassociate(context: *mut bindings::ib_ucontext) {
        // SAFETY: The core retains a successfully initialized context and its device while
        // excluding in-flight uverbs operations. Release occurs after this scoped borrow ends.
        unsafe {
            let owner = (*context.cast::<Context>()).private_data;
            Operations::<T>::data((*context).device)
                .disassociate_context(T::Context::borrow(owner));
        }
    }
}
