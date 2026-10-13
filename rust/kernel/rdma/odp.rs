// SPDX-License-Identifier: GPL-2.0

//! CPU access to on-demand RDMA user memory under invalidation guards.
//!
//! C header: [`include/rdma/ib_umem_odp.h`](srctree/include/rdma/ib_umem_odp.h)

use crate::{
    bindings,
    error::{
        code::*,
        Result, //
    },
    page::{
        PAGE_SHIFT,
        PAGE_SIZE, //
    },
    types::Opaque, //
};
use core::{
    marker::PhantomData,
    mem::MaybeUninit,
    slice, //
};

#[allow(clippy::unnecessary_cast, reason = "hmm_pfn_flags is u32 on 32-bit")]
const VALID: usize = bindings::hmm_pfn_flags_HMM_PFN_VALID as usize;
#[allow(clippy::unnecessary_cast, reason = "hmm_pfn_flags is u32 on 32-bit")]
pub(super) const WRITE: usize = bindings::hmm_pfn_flags_HMM_PFN_WRITE as usize;

/// An explicit ODP registration on a virtual-DMA device, borrowed from its owner.
///
/// Operations may sleep to fault user pages. Each access holds the core umem mutex, excluding
/// invalidation and PFN publication, and exposes no reference into the externally mutable data.
/// Byte offsets are relative to the registered user address, independently of a provider's IOVA.
///
/// # Invariants
///
/// The opaque object is a live, explicit virtual-DMA `ib_umem_odp`. Registration metadata is
/// immutable during a borrow. Its notifier sets the invalidation sequence and unmaps PFNs under
/// `umem_mutex` before permitting invalidation. Faults publish PFNs under that same mutex.
/// Mapped contents are initialized and not accessed through ordinary Rust references.
#[repr(transparent)]
pub struct OnDemandMemory<T> {
    inner: Opaque<bindings::ib_umem_odp>,
    _provider: PhantomData<T>,
}

/// The requested prefetch operation.
#[derive(Clone, Copy)]
pub enum Prefetch {
    /// Fault readable pages into the registration.
    Read,
    /// Fault writable pages into a writable registration.
    Write,
    /// Snapshot existing mappings without faulting absent pages.
    Snapshot,
}

impl<T> OnDemandMemory<T> {
    /// Borrows an existing explicit registration.
    ///
    /// # Safety
    ///
    /// `umem` and its device must be live and initialized for `'a`, with stable registration
    /// metadata throughout the borrow.
    /// The caller must exclude deregistration and uphold the notifier and shared-memory
    /// requirements in the type invariant. Implicit and non-virtual-DMA objects are rejected.
    pub unsafe fn from_raw<'a>(umem: *mut bindings::ib_umem) -> Result<&'a Self> {
        // SAFETY: The caller pins initialized metadata. Only an ODP umem has the containing
        // allocation, and only a virtual-DMA explicit registration has the supported PFN layout.
        unsafe {
            if (*umem).is_odp() == 0 || !(*(*umem).ibdev).dma_device.is_null() {
                return Err(EOPNOTSUPP);
            }
            let odp = crate::container_of!(umem, bindings::ib_umem_odp, umem);
            if (*odp).is_implicit_odp {
                return Err(EOPNOTSUPP);
            }
            // INVARIANT: The checked kind and the caller's guarantees establish the invariant.
            Ok(&*odp.cast())
        }
    }

    /// Returns the registered byte length, excluding page padding.
    #[inline]
    pub fn len(&self) -> usize {
        // SAFETY: Registration metadata is immutable during the borrow.
        unsafe { (*self.inner.get()).umem.length }
    }

    /// Returns whether the registration is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether writes may be requested through this registration.
    #[inline]
    pub fn is_writable(&self) -> bool {
        // SAFETY: The access bit belongs to immutable registration metadata.
        unsafe { (*self.inner.get()).umem.writable() != 0 }
    }

    pub(super) fn address(&self, offset: usize, length: usize) -> Result<usize> {
        if offset > self.len() || length > self.len() - offset {
            return Err(EINVAL);
        }
        // SAFETY: The registered address is immutable and was validated by the core.
        unsafe { (*self.inner.get()).umem.address }
            .checked_add(offset)
            .ok_or(EINVAL)
    }

    fn fault(
        &self,
        address: usize,
        length: usize,
        write: bool,
        fault: bool,
    ) -> Result<Locked<'_, T>> {
        // SAFETY: The caller validated a nonempty user range and write permission. The core
        // faults into private storage, publishes PFNs under the mutex, and returns with that
        // mutex held on success only. The object borrow excludes deregistration.
        let result = unsafe {
            bindings::ib_umem_odp_map_dma_and_lock(
                self.inner.get(),
                address as u64,
                length as u64,
                if write { WRITE as u64 } else { 0 },
                fault,
            )
        };
        if result < 0 {
            return Err(crate::error::Error::from_errno(result));
        }
        // INVARIANT: The successful fault returns with this thread owning the umem mutex.
        Ok(Locked {
            memory: self,
            _not_send: PhantomData,
        })
    }

    fn lock(&self, address: usize, length: usize, write: bool) -> Result<Access<'_, T>> {
        if write && !self.is_writable() {
            return Err(EPERM);
        }
        // SAFETY: The borrow retains the initialized umem and its mutex. Operations may sleep.
        unsafe { bindings::mutex_lock(&raw mut (*self.inner.get()).umem_mutex) };
        // INVARIANT: This thread has acquired the mutex and retains the object borrow.
        let guard = Locked {
            memory: self,
            _not_send: PhantomData,
        };
        if guard.covers(address, length, write) {
            // INVARIANT: Every byte in the checked range has the requested PFN permissions.
            return Ok(Access {
                guard,
                address,
                length,
            });
        }
        drop(guard);
        let guard = self.fault(address, length, write, true)?;
        if !guard.covers(address, length, write) {
            return Err(EFAULT);
        }
        // INVARIANT: Fault completion supplied valid PFNs, rechecked under the retained mutex.
        Ok(Access {
            guard,
            address,
            length,
        })
    }

    /// Prefetches a bounded user range; snapshot mode permits absent pages.
    pub fn prefetch(&self, offset: usize, length: usize, mode: Prefetch) -> Result {
        let address = self.address(offset, length)?;
        let (write, fault) = match mode {
            Prefetch::Read => (false, true),
            Prefetch::Write => (true, true),
            Prefetch::Snapshot => (self.is_writable(), false),
        };
        if write && !self.is_writable() {
            return Err(EPERM);
        }
        if length != 0 {
            drop(self.fault(address, length, write, fault)?);
        }
        Ok(())
    }

    /// Copies into initialized private storage, faulting missing readable pages.
    #[inline]
    pub fn read(&self, offset: usize, output: &mut [u8]) -> Result {
        // SAFETY: The exclusive borrow is preserved, and read_uninit writes initialized bytes.
        let output = unsafe { slice::from_raw_parts_mut(output.as_mut_ptr().cast(), output.len()) };
        self.read_uninit(offset, output)
    }

    /// Copies into possibly uninitialized private storage.
    ///
    /// Success initializes the complete output. An error may leave a prefix initialized.
    pub fn read_uninit(&self, offset: usize, output: &mut [MaybeUninit<u8>]) -> Result {
        let mut address = self.address(offset, output.len())?;
        if output.is_empty() {
            return Ok(());
        }
        let guard = self.lock(address, output.len(), false)?;
        let mut copied = 0;
        while copied < output.len() {
            let mapping = guard.map(address)?;
            let bytes = (PAGE_SIZE - (address & (PAGE_SIZE - 1))).min(output.len() - copied);
            // SAFETY: The guard retains validated readable PFNs and the mapping borrows it.
            // The output is exclusively writable and disjoint from shared user memory.
            if unsafe {
                bindings::copy_mc_to_kernel_size(
                    output.as_mut_ptr().add(copied).cast(),
                    mapping.ptr,
                    bytes,
                )
            } != 0
            {
                return Err(EHWPOISON);
            }
            copied += bytes;
            address += bytes;
        }
        Ok(())
    }

    /// Copies private storage into a writable registration, faulting missing pages.
    pub fn write(&self, offset: usize, input: &[u8]) -> Result {
        let mut address = self.address(offset, input.len())?;
        if !self.is_writable() {
            return Err(EPERM);
        }
        if input.is_empty() {
            return Ok(());
        }
        let guard = self.lock(address, input.len(), true)?;
        let mut copied = 0;
        while copied < input.len() {
            let mapping = guard.map(address)?;
            let bytes = (PAGE_SIZE - (address & (PAGE_SIZE - 1))).min(input.len() - copied);
            // SAFETY: The guard retains validated writable PFNs. The input is stable readable
            // storage disjoint from the externally mutable user mapping.
            unsafe { bindings::memcpy(mapping.ptr, input.as_ptr().add(copied).cast(), bytes) };
            mapping.flush_dcache();
            copied += bytes;
            address += bytes;
        }
        Ok(())
    }

    /// Rejects persistent flushes for on-demand memory.
    ///
    /// ODP backing may change after registration and has no persistence guarantee. Global
    /// visibility ordering is independent of this operation and remains the provider's job.
    pub fn flush(&self, offset: usize, length: usize) -> Result {
        self.address(offset, length)?;
        Err(EOPNOTSUPP)
    }

    /// Compares and conditionally replaces an aligned word, returning its previous value.
    ///
    /// Returns [`EOPNOTSUPP`] when 64-bit atomics are emulated with kernel-private locks.
    #[inline]
    pub fn compare_exchange(&self, offset: usize, current: u64, new: u64) -> Result<u64> {
        self.atomic(offset, AtomicOp::CompareExchange(current, new))
    }

    /// Adds to an aligned word with wrapping arithmetic, returning its previous value.
    ///
    /// Returns [`EOPNOTSUPP`] when 64-bit atomics are emulated with kernel-private locks.
    #[inline]
    pub fn fetch_add(&self, offset: usize, value: u64) -> Result<u64> {
        self.atomic(offset, AtomicOp::Add(value))
    }

    /// Publishes an aligned word with release ordering.
    ///
    /// Returns [`EOPNOTSUPP`] when 64-bit atomics are emulated with kernel-private locks.
    #[inline]
    pub fn store_release(&self, offset: usize, value: u64) -> Result {
        self.atomic(offset, AtomicOp::Store(value)).map(|_| ())
    }

    fn atomic(&self, offset: usize, operation: AtomicOp) -> Result<u64> {
        let address = self.address(offset, size_of::<u64>())?;
        if address & 7 != 0 {
            return Err(EINVAL);
        }
        if !self.is_writable() {
            return Err(EPERM);
        }
        if cfg!(CONFIG_GENERIC_ATOMIC64) {
            return Err(EOPNOTSUPP);
        }
        let guard = self.lock(address, size_of::<u64>(), true)?;
        let mapping = guard.map(address)?;
        let ptr = mapping.ptr.cast();
        // SAFETY: The checked aligned word fits one page. The guard pins writable backing and
        // kernel atomic primitives serialize aliases without creating a Rust reference to it.
        let original = unsafe {
            match operation {
                AtomicOp::CompareExchange(current, new) => {
                    bindings::atomic64_cmpxchg(ptr, current as i64, new as i64) as u64
                }
                AtomicOp::Add(value) => bindings::atomic64_fetch_add(value as i64, ptr) as u64,
                AtomicOp::Store(value) => {
                    bindings::atomic64_set_release(ptr, value as i64);
                    0
                }
            }
        };
        mapping.flush_dcache();
        Ok(original)
    }
}

enum AtomicOp {
    CompareExchange(u64, u64),
    Add(u64),
    Store(u64),
}

/// Holds a borrowed registration's mutex on the current thread.
///
/// # Invariants
///
/// This thread owns `memory`'s initialized mutex, excluding PFN publication and invalidation.
struct Locked<'a, T> {
    memory: &'a OnDemandMemory<T>,
    _not_send: PhantomData<*mut ()>,
}

impl<'a, T> Locked<'a, T> {
    // The caller has checked a nonempty range against the user registration.
    fn covers(&self, address: usize, length: usize, write: bool) -> bool {
        // SAFETY: The invariant stabilizes all PFNs and notifier bounds under the mutex. Virtual
        // DMA stores one HMM PFN per system page even when page_shift describes huge pages.
        unsafe {
            let odp = self.memory.inner.get();
            let base = (*odp).notifier.interval_tree.start;
            let first = (address - base) >> PAGE_SHIFT;
            let last = (address + length - 1 - base) >> PAGE_SHIFT;
            let access = VALID | if write { WRITE } else { 0 };
            (first..=last).all(|i| *(*odp).map.pfn_list.add(i) & access == access)
        }
    }

    /// # Safety
    ///
    /// The address must have been validated by covers while this guard remains held.
    unsafe fn map_valid(&self, address: usize) -> Result<Mapping<'_, 'a, T>> {
        // SAFETY: The guard retains the validated system-page PFN against invalidation. HMM
        // supplies individual PFNs for compound subpages, so no compound-page arithmetic is used.
        let page = unsafe {
            let odp = self.memory.inner.get();
            let index = (address - (*odp).notifier.interval_tree.start) >> PAGE_SHIFT;
            let pfn = *(*odp).map.pfn_list.add(index);
            bindings::hmm_pfn_to_page(pfn)
        };
        // SAFETY: The guard retains this actual subpage. Poisoning can precede invalidation;
        // reject an already poisoned page even if its cached PFN still carries VALID.
        if unsafe { bindings::is_page_hwpoison(page) } {
            return Err(EHWPOISON);
        }
        // SAFETY: The guard retains the page until the local mapping is dropped.
        let base = unsafe { bindings::kmap_local_page(page) };
        // SAFETY: The offset is within the retained system page.
        let ptr = unsafe { base.byte_add(address & (PAGE_SIZE - 1)) };
        // INVARIANT: This local mapping borrows its PFN guard and cannot outlive it or be sent.
        Ok(Mapping {
            base,
            ptr,
            page,
            _guard: self,
        })
    }
}

impl<T> Drop for Locked<'_, T> {
    fn drop(&mut self) {
        // SAFETY: This thread owns the live mutex and every local mapping has been dropped.
        unsafe { bindings::mutex_unlock(&raw mut (*self.memory.inner.get()).umem_mutex) };
    }
}

/// Validated access permissions retained by a PFN guard.
///
/// # Invariants
///
/// The nonempty `address..address + length` range lies within the registration and has valid
/// PFNs with the permissions requested by `lock`. `guard` excludes changes to those PFNs.
struct Access<'a, T> {
    guard: Locked<'a, T>,
    address: usize,
    length: usize,
}

impl<'a, T> Access<'a, T> {
    fn map(&self, address: usize) -> Result<Mapping<'_, 'a, T>> {
        if address < self.address || address - self.address >= self.length {
            return Err(EFAULT);
        }
        // SAFETY: The access invariant retains a valid PFN at this checked address. The returned
        // mapping borrows the guard, so the PFN cannot be invalidated before it is unmapped.
        unsafe { self.guard.map_valid(address) }
    }
}

/// A thread-local mapping borrowing the guard that keeps its PFN valid.
///
/// # Invariants
///
/// `base` is an owned local mapping, `ptr` is within its page, and `_guard` retains that page.
struct Mapping<'guard, 'umem, T> {
    base: *mut crate::ffi::c_void,
    ptr: *mut crate::ffi::c_void,
    page: *mut bindings::page,
    _guard: &'guard Locked<'umem, T>,
}

impl<T> Mapping<'_, '_, T> {
    #[inline]
    fn flush_dcache(&self) {
        // SAFETY: The mapping retains this page through its PFN guard. CPU writes must invalidate
        // architecture clean-cache state before a later executable mapping is installed.
        unsafe { bindings::flush_dcache_page(self.page) };
    }
}

impl<T> Drop for Mapping<'_, '_, T> {
    fn drop(&mut self) {
        // SAFETY: We own this thread's local mapping and still borrow its PFN guard.
        unsafe { bindings::kunmap_local(self.base) };
    }
}

#[cfg(CONFIG_RUST_RDMA_ODP_KUNIT_TEST)]
#[macros::kunit_tests(rust_rdma_odp)]
mod tests {
    use super::*;
    use crate::{
        prelude::*,
        sync::static_lock_class, //
    };

    // Model already-faulted virtual-DMA PFNs with owned pages. No operation in these tests needs
    // an actual userspace mm; faults and notifier races are exercised by the verbs traffic suite.
    fn with_memory(writable: bool, callback: impl FnOnce(&OnDemandMemory<()>) -> Result) -> Result {
        let mut data = KBox::<[u8; 2 * PAGE_SIZE]>::zeroed(GFP_KERNEL)?;
        data[..PAGE_SIZE].fill(0x11);
        data[PAGE_SIZE..].fill(0x22);
        let mut dev = KBox::new(bindings::ib_device::default(), GFP_KERNEL)?;
        let mut odp = KBox::new(bindings::ib_umem_odp::default(), GFP_KERNEL)?;
        let mut pfns = [0usize; 2];
        // SAFETY: The initialized kmalloc allocation is page-aligned, physically contiguous and
        // remains owned through the callback. Convert only these known allocated addresses.
        unsafe {
            for (i, pfn) in pfns.iter_mut().enumerate() {
                let page =
                    bindings::ib_virt_dma_to_page(data.as_mut_ptr().add(i * PAGE_SIZE) as u64);
                *pfn = ((bindings::page_to_phys(page) >> PAGE_SHIFT) as usize)
                    | VALID
                    | if writable { WRITE } else { 0 };
            }
            bindings::__mutex_init(
                &raw mut odp.umem_mutex,
                c"rdma_odp_test".as_char_ptr(),
                static_lock_class!().as_ptr(),
            );
        }
        odp.umem.ibdev = &raw mut *dev;
        odp.umem.address = 2 * PAGE_SIZE + 3;
        odp.umem.length = 2 * PAGE_SIZE - 11;
        odp.umem.set_is_odp(1);
        odp.umem.set_writable(u32::from(writable));
        odp.notifier.interval_tree.start = 2 * PAGE_SIZE;
        odp.notifier.interval_tree.last = 4 * PAGE_SIZE - 1;
        // The PFN list uses system-page indices despite the larger registration page size.
        odp.page_shift = (PAGE_SHIFT + 1) as u32;
        odp.map.pfn_list = pfns.as_mut_ptr();
        // SAFETY: The fixture retains metadata, device and backing pages. No invalidation or
        // fault writer runs, so the initialized mutex stabilizes PFNs. There are no ordinary
        // Rust borrows of data during callback execution, only its allocation owner.
        callback(unsafe { OnDemandMemory::from_raw(&raw mut odp.umem)? })
    }

    #[test]
    fn system_page_indexing_and_bounds() -> Result {
        with_memory(true, |memory| {
            let mut output = [0; 8];
            memory.read(PAGE_SIZE - 3, &mut output)?;
            assert_eq!(output, [0x22; 8]);
            memory.read(PAGE_SIZE - 7, &mut output)?;
            assert_eq!(output, [0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22]);
            memory.write(PAGE_SIZE - 7, &[0x5a; 8])?;
            memory.read(PAGE_SIZE - 7, &mut output)?;
            assert_eq!(output, [0x5a; 8]);
            assert_eq!(memory.read(usize::MAX, &mut output), Err(EINVAL));
            assert_eq!(memory.read(memory.len() - 7, &mut output), Err(EINVAL));
            memory.read(memory.len(), &mut [])?;
            Ok(())
        })
    }

    #[test]
    #[cfg(not(CONFIG_GENERIC_ATOMIC64))]
    fn atomic_alignment_and_aliases() -> Result {
        with_memory(true, |memory| {
            assert_eq!(memory.fetch_add(0, 1), Err(EINVAL));
            memory.store_release(5, 7)?;
            assert_eq!(memory.compare_exchange(5, 7, 19)?, 7);
            assert_eq!(memory.compare_exchange(5, 7, 29)?, 19);
            assert_eq!(memory.fetch_add(5, u64::MAX)?, 19);
            let mut output = [0; 8];
            memory.read(5, &mut output)?;
            assert_eq!(u64::from_ne_bytes(output), 18);
            assert_eq!(memory.fetch_add(memory.len() - 7, 1), Err(EINVAL));
            Ok(())
        })
    }

    #[test]
    fn persistent_flush_is_unsupported() -> Result {
        with_memory(true, |memory| {
            assert_eq!(memory.flush(0, 8), Err(EOPNOTSUPP));
            Ok(())
        })
    }

    #[test]
    #[cfg(CONFIG_GENERIC_ATOMIC64)]
    fn emulated_atomics_are_unsupported() -> Result {
        with_memory(true, |memory| {
            assert_eq!(memory.fetch_add(5, 1), Err(EOPNOTSUPP));
            assert_eq!(memory.compare_exchange(5, 0, 1), Err(EOPNOTSUPP));
            assert_eq!(memory.store_release(5, 1), Err(EOPNOTSUPP));
            Ok(())
        })
    }

    #[test]
    #[cfg(CONFIG_MEMORY_FAILURE)]
    fn cached_poisoned_pfn_rejects_cpu_access() -> Result {
        with_memory(true, |memory| {
            // SAFETY: The fixture retains its two PFNs and no fault or invalidation runs.
            let page =
                unsafe { bindings::hmm_pfn_to_page(*(*memory.inner.get()).map.pfn_list.add(1)) };
            let mut output = [0xa5; 8];
            // SAFETY: Only this test owns the backing. Restore its flag before assertions.
            unsafe {
                bindings::set_bit(
                    bindings::pageflags_PG_hwpoison as crate::ffi::c_ulong,
                    &raw mut (*page).flags.f,
                );
            }
            let read = memory.read(PAGE_SIZE - 7, &mut output);
            let write = memory.write(PAGE_SIZE - 7, &[0x55; 8]);
            let atomic = memory.fetch_add(PAGE_SIZE - 3, 1);
            // SAFETY: Restore the flag before unwinding or releasing the test allocation.
            unsafe {
                bindings::clear_bit(
                    bindings::pageflags_PG_hwpoison as crate::ffi::c_ulong,
                    &raw mut (*page).flags.f,
                );
            }
            assert_eq!(read, Err(EHWPOISON));
            assert_eq!(output, [0x11, 0x11, 0x11, 0x11, 0xa5, 0xa5, 0xa5, 0xa5]);
            assert_eq!(write, Err(EHWPOISON));
            if !cfg!(CONFIG_GENERIC_ATOMIC64) {
                assert_eq!(atomic, Err(EHWPOISON));
            }
            Ok(())
        })
    }

    #[test]
    fn readonly_registration() -> Result {
        with_memory(false, |memory| {
            let mut output = [0; 8];
            memory.read(5, &mut output)?;
            assert_eq!(output, [0x11; 8]);
            assert_eq!(memory.write(5, &[1; 8]), Err(EPERM));
            assert_eq!(memory.fetch_add(5, 1), Err(EPERM));
            assert_eq!(memory.compare_exchange(5, 0, 1), Err(EPERM));
            assert_eq!(memory.store_release(5, 1), Err(EPERM));
            assert_eq!(memory.prefetch(0, 8, Prefetch::Write), Err(EPERM));
            Ok(())
        })
    }
}
