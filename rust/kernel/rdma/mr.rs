// SPDX-License-Identifier: GPL-2.0

//! Memory-region callbacks with provider references drained by deregistration.

use super::{
    AccessFlags,
    Device,
    Operations,
    ProtectionDomainOperations,
    ProtectionDomains,
    UserData, //
};
use crate::{
    bindings,
    prelude::*,
    sync::Refcount,
    types::{
        ForeignOwnable,
        Opaque, //
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

/// Process virtual memory and its registered I/O virtual address.
#[derive(Clone, Copy, Debug)]
pub struct UserMemoryRange {
    /// First process virtual address.
    pub start: u64,
    /// Number of bytes.
    pub length: u64,
    /// First I/O virtual address.
    pub iova: u64,
}

/// A supported memory-region creation request.
///
/// This adapter supports DMA regions, ordinary user registrations without a DMA handle,
/// and fast-registration regions of type `IB_MR_TYPE_MEM_REG`.
#[derive(Clone, Copy, Debug)]
pub enum RegionRequest {
    /// Access to the device's DMA address space.
    Dma(AccessFlags),
    /// A process virtual address range.
    User {
        /// Virtual addresses and length.
        range: UserMemoryRange,
        /// Requested access rights.
        access: AccessFlags,
    },
    /// Initially unregistered storage for a page translation table.
    Fast {
        /// Maximum number of registration pages.
        max_pages: u32,
    },
}

/// Native ownership, reserved publication storage and initial core attributes.
pub struct RegionCreation<O, P> {
    /// Private state owned until deregistration has drained provider references.
    pub owner: O,
    /// Provider-specific storage needed for infallible publication.
    pub publication: P,
    /// Initial local access key.
    pub local_key: u32,
    /// Initial remote access key.
    pub remote_key: u32,
    /// Initial registration page size.
    pub page_size: u32,
}

/// Native operations for DMA, user and fast-registration memory regions.
///
/// Creation and deregistration may sleep. Mapping runs in the kernel caller's context and
/// must not sleep. The core retains the device and current protection domain while a region
/// exists. Provider references extend deregistration, but do not retain a previous domain
/// after re-registration. Providers must synchronize their own registration and access state.
pub trait MemoryRegionOperations: ProtectionDomainOperations {
    /// Private ownership associated with each region.
    type MemoryRegion: ForeignOwnable + Send + Sync + 'static;
    /// Preallocated storage consumed when publishing the first provider reference.
    type RegionPublication;

    /// Builds private state before the core header or provider reference is published.
    ///
    /// The adapter allocates its header first. No fallible adapter operation follows success.
    fn create_region(
        self: Pin<&Self>,
        device: &Device<Self>,
        domain: <Self::Domain as ForeignOwnable>::Borrowed<'_>,
        request: RegionRequest,
        data: Option<UserData<'_, Self>>,
    ) -> Result<RegionCreation<Self::MemoryRegion, Self::RegionPublication>>;

    /// Publishes the first reference after all allocation and initialization have completed.
    ///
    /// Retain this reference in the provider's lookup structure until retirement. Publication
    /// cannot fail; any needed storage must be allocated during creation.
    fn publish_region(
        self: Pin<&Self>,
        region: MemoryRegionRef<Self>,
        publication: Self::RegionPublication,
    );

    /// Changes an existing user registration in place, or rejects the requested changes.
    ///
    /// The core excludes other core operations and retains a replacement domain, if supplied.
    /// Provider lookups and data operations may still run concurrently. The core updates its
    /// domain and translation fields only after success. Failure must preserve the old state.
    fn reregister_region(
        self: Pin<&Self>,
        region: &MemoryRegion<Self>,
        domain: Option<<Self::Domain as ForeignOwnable>::Borrowed<'_>>,
        translation: Option<UserMemoryRange>,
        access: Option<AccessFlags>,
        data: Option<UserData<'_, Self>>,
    ) -> Result;

    /// Begins replacing a fast region's translation table with the selected page size.
    fn begin_region_mapping(
        self: Pin<&Self>,
        region: &MemoryRegion<Self>,
        page_size: u32,
    ) -> Result;

    /// Appends one DMA page during the core's serialized scatterlist walk.
    ///
    /// The kernel caller maintains the DMA mappings according to the device's DMA contract.
    fn map_region_page(self: Pin<&Self>, region: &MemoryRegion<Self>, address: u64) -> Result;

    /// Ends the whole scatterlist walk, making its prepared translation available on success.
    ///
    /// A nonnegative walker result may describe a usable partial mapping. Failed walks must
    /// leave their unfinished replacement unavailable for a later registration.
    fn finish_region_mapping(self: Pin<&Self>, region: &MemoryRegion<Self>, success: bool);

    /// Stops new provider lookups and releases the published reference before returning success.
    ///
    /// Outstanding references are drained by the adapter after this returns. Failure must
    /// preserve publication and state needed for subsequent operations or retirement attempts.
    fn retire_region(self: Pin<&Self>, region: &MemoryRegion<Self>) -> Result;

    /// Stops lookups and releases publication for a protection domain's internal DMA region.
    ///
    /// This retirement cannot fail: the core discards the internal handle and destroys its
    /// domain after the callback. The adapter drains outstanding references before release.
    fn retire_internal_region(self: Pin<&Self>, region: &MemoryRegion<Self>);

    /// Releases native ownership after the last provider reference has been dropped.
    ///
    /// This runs in the deregistering task, which may sleep. The device and current domain
    /// remain live until this returns; the core header is freed immediately afterward.
    fn release_region(self: Pin<&Self>, owner: Self::MemoryRegion) {
        drop(owner);
    }
}

/// A borrowed region whose core header remains opaque to provider users.
///
/// # Invariants
///
/// Published instances are initialized by `MemoryRegions<T>` for a provider implementing
/// `MemoryRegionOperations`. The foreign owner is immutable until references drain. The
/// separate device pointer is immutable even while the core initializes or updates its header.
/// Deregistration owns destruction and retains the allocation, device and foreign owner until
/// `drained` is signaled. Borrows are protected by a core callback or provider reference.
#[pin_data]
#[repr(C)]
pub struct MemoryRegion<T> {
    core: Opaque<bindings::ib_mr>,
    device: *mut bindings::ib_device,
    private_data: Opaque<*mut c_void>,
    users: Refcount,
    #[pin]
    drained: Opaque<bindings::completion>,
    _provider: PhantomData<fn() -> T>,
}

// SAFETY: Instances are only published for providers with Send + Sync foreign ownership.
// Core fields are opaque, shared state is immutable or synchronized, and destruction waits
// for all references. The provider parameter is an identity, not an owned value.
unsafe impl<T> Send for MemoryRegion<T> {}
// SAFETY: The same invariant permits concurrent shared borrows of native data.
unsafe impl<T> Sync for MemoryRegion<T> {}

impl<T: MemoryRegionOperations> MemoryRegion<T> {
    /// Borrows the native owner while a core callback or provider reference retains it.
    #[inline]
    pub fn data(&self) -> <T::MemoryRegion as ForeignOwnable>::Borrowed<'_> {
        // SAFETY: The initialized foreign owner is retained throughout this borrow.
        unsafe { T::MemoryRegion::borrow(*self.private_data.get()) }
    }

    /// Borrows the device retained through region deregistration.
    #[inline]
    pub fn device(&self) -> &Device<T> {
        // SAFETY: The immutable shadow pointer names the device retained by the core owner.
        unsafe { Device::from_raw(self.device) }
    }
}

/// One provider reference which postpones region destruction until it is dropped.
///
/// Cloning and dropping do not allocate or sleep. The final drop only signals deregistration;
/// it does not destroy native data or release user memory from a transport context.
///
/// # Invariants
///
/// `region` names an initialized allocation and this handle owns one nonzero provider
/// reference. Deregistration retains the allocation and native owner until the last drop.
pub struct MemoryRegionRef<T> {
    region: NonNull<MemoryRegion<T>>,
}

// SAFETY: The owned reference retains a synchronized MemoryRegion until it is dropped.
unsafe impl<T> Send for MemoryRegionRef<T> {}
// SAFETY: Sharing the handle exposes only shared borrows and atomic reference operations.
unsafe impl<T> Sync for MemoryRegionRef<T> {}

impl<T> Deref for MemoryRegionRef<T> {
    type Target = MemoryRegion<T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: This counted reference excludes destruction throughout the borrow.
        unsafe { self.region.as_ref() }
    }
}

impl<T> Clone for MemoryRegionRef<T> {
    #[inline]
    fn clone(&self) -> Self {
        self.users.inc();
        // INVARIANT: The initialized region remains live through this new counted reference.
        Self {
            region: self.region,
        }
    }
}

impl<T> Drop for MemoryRegionRef<T> {
    fn drop(&mut self) {
        let drained = self.drained.get();
        if self.users.dec_and_test() {
            // SAFETY: Deregistration retains the allocation until this signal. No reference
            // to the region spans complete(), and no region field is accessed afterward:
            // the waiter may free storage as soon as complete() releases its internal lock.
            unsafe { bindings::complete(drained) };
        }
    }
}

/// Installs region callbacks and owns their core-header allocation through deregistration.
pub struct MemoryRegions<T: MemoryRegionOperations>(PhantomData<T>);

impl<T: MemoryRegionOperations> MemoryRegions<T> {
    /// Installs the supported region operations before publishing a device.
    ///
    /// # Safety
    ///
    /// `device` must be exclusively owned and unpublished, with `Operations<T>` and
    /// `ProtectionDomains<T>` installed. Its `get_dma_mr`, `reg_user_mr`, `rereg_user_mr`,
    /// `alloc_mr`, `map_mr_sg` and `dereg_mr` slots must be unused and exclusively managed by
    /// this adapter. Core or kernel callers must serialize mapping and re-registration and
    /// exclude other core operations during deregistration. All regions must be deregistered
    /// before their current domains and device are released.
    #[inline]
    pub unsafe fn install(device: *mut bindings::ib_device) {
        // SAFETY: The caller owns the unpublished device and reserves these operation slots.
        unsafe {
            (*device).ops.get_dma_mr = Some(Self::get_dma);
            (*device).ops.reg_user_mr = Some(Self::register_user);
            (*device).ops.rereg_user_mr = Some(Self::reregister);
            (*device).ops.alloc_mr = Some(Self::allocate_fast);
            (*device).ops.map_mr_sg = Some(Self::map);
            (*device).ops.dereg_mr = Some(Self::deregister);
        }
    }

    /// Borrows a successfully initialized region supplied by a core operation.
    ///
    /// # Safety
    ///
    /// `region` must belong to this adapter. The caller must retain its allocation, native
    /// owner and device and exclude successful deregistration throughout `'a`.
    #[inline]
    pub unsafe fn borrow<'a>(region: *mut bindings::ib_mr) -> &'a MemoryRegion<T> {
        // SAFETY: The core header is the leading field of the retained initialized allocation.
        unsafe { &*region.cast::<MemoryRegion<T>>() }
    }

    /// # Safety
    ///
    /// The caller retains the domain/device in sleepable context and supplies an original
    /// optional uverbs descriptor. Successful creation transfers ownership to deregistration.
    unsafe fn create(
        domain: *mut bindings::ib_pd,
        request: RegionRequest,
        data: *mut bindings::ib_udata,
    ) -> Result<*mut bindings::ib_mr> {
        // SAFETY: The caller retains the domain and its initialized device.
        let device = unsafe { (*domain).device };
        // INVARIANT: This unpublished allocation retains the callback-owned device and
        // initializes its reference count and drain completion before any borrow escapes.
        let region = KBox::pin_init(
            pin_init!(MemoryRegion::<T> {
                core: Opaque::new(bindings::ib_mr::default()),
                device,
                private_data: Opaque::new(ptr::null_mut()),
                users: Refcount::new(1),
                drained <- Opaque::ffi_init(|slot| {
                    // SAFETY: Pin initialization supplies stable uninitialized storage.
                    unsafe { bindings::init_completion(slot) };
                }),
                _provider: PhantomData,
            }),
            GFP_KERNEL,
        )?;
        // SAFETY: The caller retains the installed domain/device and original data bundle.
        let provider = unsafe { Operations::<T>::data(device) };
        let created = provider.create_region(
            // SAFETY: The core retains the initialized device throughout creation.
            unsafe { Device::from_raw(device) },
            // SAFETY: The initialized domain cannot be released during creation.
            unsafe { ProtectionDomains::<T>::data(domain) },
            request,
            // SAFETY: Optional data is the caller's original retained uverbs descriptor.
            unsafe { UserData::from_raw(data) },
        )?;
        let core = region.core.get();
        // SAFETY: The header and owner slot remain unpublished and exclusively writable.
        // No fallible operation follows creation, so native ownership cannot be abandoned.
        unsafe {
            (*core).device = device;
            (*core).pd = domain;
            (*core).lkey = created.local_key;
            (*core).rkey = created.remote_key;
            (*core).page_size = created.page_size;
            (*core).type_ = match request {
                RegionRequest::Dma(_) => bindings::ib_mr_type_IB_MR_TYPE_DMA,
                RegionRequest::User { range, .. } => {
                    (*core).iova = range.iova;
                    (*core).length = range.length;
                    bindings::ib_mr_type_IB_MR_TYPE_USER
                }
                RegionRequest::Fast { .. } => bindings::ib_mr_type_IB_MR_TYPE_MEM_REG,
            };
            region
                .private_data
                .get()
                .write(created.owner.into_foreign());
        }
        let raw = region.into_foreign().cast::<MemoryRegion<T>>();
        // INVARIANT: Initialization is complete, the core owns the pinned allocation, and
        // the initial reference prevents deregistration from consuming the native owner.
        provider.publish_region(
            MemoryRegionRef {
                // SAFETY: Foreign ownership always produces a non-null pointer.
                region: unsafe { NonNull::new_unchecked(raw) },
            },
            created.publication,
        );
        Ok(core)
    }

    /// # Safety
    ///
    /// The core must retain the initialized domain and device in sleepable context.
    unsafe extern "C" fn get_dma(
        domain: *mut bindings::ib_pd,
        access: c_int,
    ) -> *mut bindings::ib_mr {
        // SAFETY: The core retains the initialized domain/device in sleepable context.
        unsafe {
            Self::create(
                domain,
                RegionRequest::Dma(AccessFlags::from_bits(access as u32)),
                ptr::null_mut(),
            )
        }
        .unwrap_or_else(Error::to_ptr)
    }

    /// # Safety
    ///
    /// The core must retain the domain, device and original optional uverbs bundle
    /// in the registering process, with uverbs disassociation excluded.
    unsafe extern "C" fn register_user(
        domain: *mut bindings::ib_pd,
        start: u64,
        length: u64,
        iova: u64,
        access: c_int,
        dma_handle: *mut bindings::ib_dmah,
        data: *mut bindings::ib_udata,
    ) -> *mut bindings::ib_mr {
        if !dma_handle.is_null() {
            return EOPNOTSUPP.to_ptr();
        }
        let request = RegionRequest::User {
            range: UserMemoryRange {
                start,
                length,
                iova,
            },
            access: AccessFlags::from_bits(access as u32),
        };
        // SAFETY: The core retains the domain/device and optional original uverbs bundle in
        // the registering process's sleepable context. Addresses are values, not references.
        unsafe { Self::create(domain, request, data) }.unwrap_or_else(Error::to_ptr)
    }

    /// # Safety
    ///
    /// The core must retain the initialized domain and device in sleepable context.
    unsafe extern "C" fn allocate_fast(
        domain: *mut bindings::ib_pd,
        kind: bindings::ib_mr_type,
        max_pages: u32,
    ) -> *mut bindings::ib_mr {
        if kind != bindings::ib_mr_type_IB_MR_TYPE_MEM_REG {
            return EINVAL.to_ptr();
        }
        // SAFETY: The core retains the domain/device and permits sleeping allocation.
        unsafe { Self::create(domain, RegionRequest::Fast { max_pages }, ptr::null_mut()) }
            .unwrap_or_else(Error::to_ptr)
    }

    /// # Safety
    ///
    /// The core must retain the region, device, replacement domain and original
    /// optional uverbs bundle, and exclude concurrent core operations on the region.
    unsafe extern "C" fn reregister(
        core: *mut bindings::ib_mr,
        flags: c_int,
        start: u64,
        length: u64,
        iova: u64,
        access: c_int,
        domain: *mut bindings::ib_pd,
        data: *mut bindings::ib_udata,
    ) -> *mut bindings::ib_mr {
        let flags = flags as u32;
        if flags
            & !(bindings::ib_mr_rereg_flags_IB_MR_REREG_PD
                | bindings::ib_mr_rereg_flags_IB_MR_REREG_ACCESS
                | bindings::ib_mr_rereg_flags_IB_MR_REREG_TRANS)
            != 0
        {
            return EOPNOTSUPP.to_ptr();
        }
        // SAFETY: The core excludes other core operations and retains the initialized region,
        // device, requested replacement domain and original optional uverbs bundle.
        unsafe {
            let region = Self::borrow(core);
            let domain = if flags & bindings::ib_mr_rereg_flags_IB_MR_REREG_PD != 0 {
                Some(ProtectionDomains::<T>::data(domain))
            } else {
                None
            };
            let translation = (flags & bindings::ib_mr_rereg_flags_IB_MR_REREG_TRANS != 0)
                .then_some(UserMemoryRange {
                    start,
                    length,
                    iova,
                });
            let access = (flags & bindings::ib_mr_rereg_flags_IB_MR_REREG_ACCESS != 0)
                .then_some(AccessFlags::from_bits(access as u32));
            Operations::<T>::data(region.device)
                .reregister_region(
                    region,
                    domain,
                    translation,
                    access,
                    UserData::from_raw(data),
                )
                .map_or_else(Error::to_ptr, |()| ptr::null_mut())
        }
    }

    /// # Safety
    ///
    /// The synchronous core walker must retain the region/device, serialize mapping
    /// and supply a DMA page address satisfying the device mapping contract.
    unsafe extern "C" fn set_page(core: *mut bindings::ib_mr, address: u64) -> c_int {
        // SAFETY: The synchronous walker retains the region/device and serializes mapping.
        unsafe {
            let region = Self::borrow(core);
            Operations::<T>::data(region.device)
                .map_region_page(region, address)
                .map_or_else(Error::to_errno, |()| 0)
        }
    }

    /// # Safety
    ///
    /// The core must retain the region/device, serialize mapping and supply a valid
    /// DMA scatterlist and offset according to the ib_sg_to_pages contract.
    unsafe extern "C" fn map(
        core: *mut bindings::ib_mr,
        scatterlist: *mut bindings::scatterlist,
        entries: c_int,
        offset: *mut c_uint,
    ) -> c_int {
        // SAFETY: The kernel caller retains the region/device, serializes mapping and supplies
        // the core walker's DMA scatterlist/offset contract. Core fields remain opaque to Rust.
        unsafe {
            let region = Self::borrow(core);
            if let Err(error) =
                Operations::<T>::data(region.device).begin_region_mapping(region, (*core).page_size)
            {
                return error.to_errno();
            }
            let result =
                bindings::ib_sg_to_pages(core, scatterlist, entries, offset, Some(Self::set_page));
            Operations::<T>::data(region.device).finish_region_mapping(region, result >= 0);
            result
        }
    }

    /// # Safety
    ///
    /// The core must retain the region/device and original optional uverbs bundle,
    /// exclude concurrent core operations and free the header only after success.
    unsafe extern "C" fn deregister(
        core: *mut bindings::ib_mr,
        _data: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core excludes other core operations and retains the device/current
        // domain. Retirement removes publication before the wait; references retain native
        // data until they signal completion. The foreign borrow ends before ownership is
        // recovered. Only this successful callback reclaims the pinned allocation.
        unsafe {
            let raw = core.cast::<MemoryRegion<T>>();
            let provider = Operations::<T>::data((*raw).device);
            if (*(*core).pd).__internal_mr == core {
                provider.retire_internal_region(Self::borrow(core));
            } else if let Err(error) = provider.retire_region(Self::borrow(core)) {
                return error.to_errno();
            }
            bindings::wait_for_completion((*raw).drained.get());
            let owner = T::MemoryRegion::from_foreign(*(*raw).private_data.get());
            provider.release_region(owner);
            drop(Pin::<KBox<MemoryRegion<T>>>::from_foreign(raw.cast()));
        }
        0
    }
}
