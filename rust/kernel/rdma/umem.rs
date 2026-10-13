// SPDX-License-Identifier: GPL-2.0

//! Bounded CPU access to pinned RDMA user memory.
//!
//! C header: [`include/rdma/ib_umem.h`](srctree/include/rdma/ib_umem.h)

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

#[cfg(CONFIG_INFINIBAND_VIRT_DMA)]
mod owned;
#[cfg(all(CONFIG_INFINIBAND_VIRT_DMA, CONFIG_INFINIBAND_ON_DEMAND_PAGING))]
pub use owned::OwnedOnDemandMemory;
#[cfg(CONFIG_INFINIBAND_VIRT_DMA)]
pub use owned::OwnedPinnedMemory;

/// A borrowed, pinned userspace registration belonging to provider `T`.
///
/// Memory contents may change concurrently through userspace mappings. Methods copy values
/// without exposing references into that storage. Registration metadata and backing pages must
/// remain stable throughout a borrow; ODP and dma-buf registrations require different interfaces.
/// Copies do not serialize with other accesses, including accesses through another registration
/// of the same pages. They can observe or produce a mixture of concurrent writes. Callers must
/// coordinate overlapping operations when they require a consistent transfer or snapshot;
/// native atomic methods do not make ordinary copies atomic.
///
/// # Invariants
///
/// The opaque object is a live, initialized, ordinary `ib_umem`. It owns pins on every page in
/// its immutable scatterlist. Its contents are initialized and externally mutable. Writable
/// registrations have writable page pins. No ordinary Rust references to the contents exist.
/// Scatterlist entries cover complete pages, as constructed by ordinary umem registration.
#[repr(transparent)]
pub struct PinnedMemory<T> {
    inner: Opaque<bindings::ib_umem>,
    _provider: PhantomData<T>,
}

impl<T> PinnedMemory<T> {
    /// Borrows a pinned registration from a core callback or an existing owner.
    ///
    /// # Safety
    ///
    /// `umem` must point to an initialized `ib_umem`, retained without metadata changes for
    /// `'a`. Its backing must follow the shared-memory requirements in the type invariant.
    /// The caller must exclude deregistration for `'a`. ODP and dma-buf objects are rejected.
    pub unsafe fn from_raw<'a>(umem: *mut bindings::ib_umem) -> Result<&'a Self> {
        // SAFETY: The caller supplies initialized, stable metadata. Checking the registration
        // kind before constructing the borrow excludes backing that can be revoked separately.
        if unsafe { (*umem).is_odp() != 0 || (*umem).is_dmabuf() != 0 } {
            return Err(EOPNOTSUPP);
        }
        // SAFETY: The transparent opaque wrapper has the same layout. The caller keeps the
        // registration and pinned pages valid for 'a, establishing the invariant.
        Ok(unsafe { &*umem.cast() })
    }

    /// Returns the length of the registered byte range, excluding page padding.
    #[inline]
    pub fn len(&self) -> usize {
        // SAFETY: Registration metadata is immutable during the borrow.
        unsafe { (*self.inner.get()).length }
    }

    /// Returns whether the registered byte range is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether the registration owns writable page pins.
    #[inline]
    pub fn is_writable(&self) -> bool {
        // SAFETY: The bitfield belongs to immutable registration metadata.
        unsafe { (*self.inner.get()).writable() != 0 }
    }

    fn check_range(&self, offset: usize, length: usize) -> Result<usize> {
        if offset
            .checked_add(length)
            .is_none_or(|end| end > self.len())
        {
            return Err(EINVAL);
        }
        // SAFETY: The address is immutable and was validated when the core pinned the pages.
        let page_offset = unsafe { (*self.inner.get()).address } & (PAGE_SIZE - 1);
        offset.checked_add(page_offset).ok_or(EINVAL)
    }

    /// Copies registered bytes into initialized private storage.
    #[inline]
    pub fn read(&self, offset: usize, output: &mut [u8]) -> Result {
        // SAFETY: Initialized bytes can be treated as MaybeUninit without changing their value.
        // The exclusive borrow is preserved; read_uninit never writes uninitialized bytes.
        let output = unsafe { slice::from_raw_parts_mut(output.as_mut_ptr().cast(), output.len()) };
        self.read_uninit(offset, output)
    }

    /// Copies registered bytes into possibly uninitialized private storage.
    ///
    /// Success initializes the entire output. On failure a prefix may have been initialized.
    pub fn read_uninit(&self, offset: usize, output: &mut [MaybeUninit<u8>]) -> Result {
        let start = self.check_range(offset, output.len())?;
        let mut offset = start & (PAGE_SIZE - 1);
        let mut pages = self.pages(start >> PAGE_SHIFT);
        let mut copied = 0;
        while copied < output.len() {
            // SAFETY: The iterator borrows the immutable, pinned scatterlist.
            if !unsafe { bindings::__sg_page_iter_next(&mut pages) } {
                return Err(EFAULT);
            }
            // SAFETY: The iterator supplies a page pinned until this borrow ends.
            let mapping = unsafe { LocalMapping::new(bindings::sg_page_iter_page(&mut pages))? };
            let bytes = (output.len() - copied).min(PAGE_SIZE - offset);
            // SAFETY: Both ranges are valid, disjoint, and bounded to this pinned page and
            // the output slice. User memory contains initialized bytes.
            if unsafe {
                bindings::copy_mc_to_kernel_size(
                    output.as_mut_ptr().add(copied).cast(),
                    mapping.ptr.add(offset).cast(),
                    bytes,
                )
            } != 0
            {
                return Err(EHWPOISON);
            }
            copied += bytes;
            offset = 0;
        }
        Ok(())
    }

    /// Copies private initialized bytes into a writable registration.
    pub fn write(&self, offset: usize, input: &[u8]) -> Result {
        if !self.is_writable() {
            return Err(EPERM);
        }
        let start = self.check_range(offset, input.len())?;
        let mut offset = start & (PAGE_SIZE - 1);
        let mut pages = self.pages(start >> PAGE_SHIFT);
        let mut copied = 0;
        while copied < input.len() {
            // SAFETY: The iterator borrows the immutable, pinned scatterlist.
            if !unsafe { bindings::__sg_page_iter_next(&mut pages) } {
                return Err(EFAULT);
            }
            // SAFETY: The iterator supplies a page pinned until this borrow ends.
            let mapping = unsafe { LocalMapping::new(bindings::sg_page_iter_page(&mut pages))? };
            let bytes = (input.len() - copied).min(PAGE_SIZE - offset);
            // SAFETY: The source is initialized and disjoint from the checked writable
            // user range, which remains mapped throughout the copy.
            unsafe {
                bindings::memcpy(
                    mapping.ptr.add(offset).cast(),
                    input.as_ptr().add(copied).cast(),
                    bytes,
                )
            };
            mapping.flush_dcache();
            copied += bytes;
            offset = 0;
        }
        Ok(())
    }

    /// Returns whether every backing page is persistent memory with cache writeback support.
    ///
    /// Call from process context because the resource lookup uses a non-IRQ-safe lock.
    pub fn is_persistent(&self) -> bool {
        let mut pages = self.pages(0);
        // SAFETY: The iterator's scatterlist remains pinned throughout this borrow.
        while unsafe { bindings::__sg_page_iter_next(&mut pages) } {
            // SAFETY: A successful iteration supplies a pinned page from the scatterlist.
            let page = unsafe { bindings::sg_page_iter_page(&mut pages) };
            #[allow(clippy::useless_conversion, reason = "phys_addr_t may be u32 or u64")]
            // SAFETY: The page is live. The resource lookup does not map or change its contents.
            let persistent = unsafe {
                bindings::ib_pmem_range(u64::from(bindings::page_to_phys(page)), PAGE_SIZE)
            };
            if !persistent {
                return false;
            }
        }
        true
    }

    /// Issues cache writeback for a bounded range.
    ///
    /// Providers must validate persistent backing with [`Self::is_persistent`] and execute a
    /// write memory barrier after the final writeback before reporting persistence completion.
    /// Nonempty ranges return [`EOPNOTSUPP`] without architecture cache writeback support.
    pub fn flush(&self, offset: usize, mut length: usize) -> Result {
        let start = self.check_range(offset, length)?;
        if length != 0 && !cfg!(CONFIG_ARCH_HAS_PMEM_API) {
            return Err(EOPNOTSUPP);
        }
        let mut offset = start & (PAGE_SIZE - 1);
        let mut pages = self.pages(start >> PAGE_SHIFT);
        while length != 0 {
            // SAFETY: The iterator borrows this pinned scatterlist.
            if !unsafe { bindings::__sg_page_iter_next(&mut pages) } {
                return Err(EFAULT);
            }
            let bytes = length.min(PAGE_SIZE - offset);
            // SAFETY: Iteration produced a pinned page. The mapping is dropped before any next
            // iteration and cannot escape this registration borrow.
            let mapping = unsafe { LocalMapping::new(bindings::sg_page_iter_page(&mut pages))? };
            // SAFETY: The checked range is contained in this one-page mapping.
            unsafe { bindings::arch_wb_cache_pmem(mapping.ptr.add(offset).cast(), bytes) };
            length -= bytes;
            offset = 0;
        }
        Ok(())
    }

    /// Compares and conditionally replaces an aligned word, returning its old value.
    ///
    /// Returns [`EOPNOTSUPP`] when 64-bit atomics are emulated with kernel-private locks.
    pub fn compare_exchange(&self, offset: usize, current: u64, new: u64) -> Result<u64> {
        let (mapping, offset) = self.atomic_mapping(offset)?;
        // SAFETY: atomic_mapping checks write permission, extent and alignment, and keeps the
        // page mapped. C atomics access externally mutable bytes without Rust references.
        let original = unsafe {
            bindings::atomic64_cmpxchg(mapping.ptr.add(offset).cast(), current as i64, new as i64)
        } as u64;
        mapping.flush_dcache();
        Ok(original)
    }

    /// Adds to an aligned word with wrapping arithmetic, returning its old value.
    ///
    /// Returns [`EOPNOTSUPP`] when 64-bit atomics are emulated with kernel-private locks.
    pub fn fetch_add(&self, offset: usize, value: u64) -> Result<u64> {
        let (mapping, offset) = self.atomic_mapping(offset)?;
        // SAFETY: The checked, writable word stays mapped through this C atomic operation.
        let original =
            unsafe { bindings::atomic64_fetch_add(value as i64, mapping.ptr.add(offset).cast()) }
                as u64;
        mapping.flush_dcache();
        Ok(original)
    }

    /// Publishes an aligned word with release ordering.
    ///
    /// Returns [`EOPNOTSUPP`] when 64-bit atomics are emulated with kernel-private locks.
    pub fn store_release(&self, offset: usize, value: u64) -> Result {
        let (mapping, offset) = self.atomic_mapping(offset)?;
        // SAFETY: The aligned writable word is in bounds and remains mapped through the store.
        unsafe { bindings::atomic64_set_release(mapping.ptr.add(offset).cast(), value as i64) };
        mapping.flush_dcache();
        Ok(())
    }

    fn pages(&self, offset: usize) -> bindings::sg_page_iter {
        let mut iter = bindings::sg_page_iter::default();
        // SAFETY: The invariant supplies an immutable, initialized scatterlist; the iterator
        // is private to this borrow and its page offset does not dereference any entry yet.
        unsafe {
            let table = &raw const (*self.inner.get()).sgt_append.sgt;
            bindings::__sg_page_iter_start(&mut iter, (*table).sgl, (*table).orig_nents, offset);
        }
        iter
    }

    fn atomic_mapping(&self, offset: usize) -> Result<(LocalMapping<'_>, usize)> {
        if !self.is_writable() {
            return Err(EPERM);
        }
        let start = self.check_range(offset, size_of::<u64>())?;
        let offset = start & (PAGE_SIZE - 1);
        if offset & (size_of::<u64>() - 1) != 0 {
            return Err(EINVAL);
        }
        if cfg!(CONFIG_GENERIC_ATOMIC64) {
            return Err(EOPNOTSUPP);
        }
        let mut pages = self.pages(start >> PAGE_SHIFT);
        // SAFETY: The iterator borrows a pinned scatterlist and bounds the page lookup.
        if !unsafe { bindings::__sg_page_iter_next(&mut pages) } {
            return Err(EFAULT);
        }
        // SAFETY: The successful iteration supplies a page pinned for the lifetime of self.
        // The returned mapping is tied to that borrow and is not sendable to another thread.
        let mapping = unsafe { LocalMapping::new(bindings::sg_page_iter_page(&mut pages))? };
        Ok((mapping, offset))
    }
}

/// A local page mapping, tied to its caller's page pin and current thread.
struct LocalMapping<'a> {
    ptr: *mut u8,
    page: *mut bindings::page,
    _pin: PhantomData<&'a ()>,
}

impl LocalMapping<'_> {
    /// # Safety
    ///
    /// The caller must pin the page until the returned mapping is dropped. Nested mappings
    /// must be dropped in reverse order on this thread.
    unsafe fn new(page: *mut bindings::page) -> Result<Self> {
        // SAFETY: The caller retains the page. A pin does not prevent hardware poisoning;
        // reject an already poisoned page before copying, flushing or performing atomics.
        if unsafe { bindings::is_page_hwpoison(page) } {
            return Err(EHWPOISON);
        }
        Ok(Self {
            // SAFETY: The caller keeps this page pinned for the mapping's lifetime.
            ptr: unsafe { bindings::kmap_local_page(page) }.cast(),
            page,
            _pin: PhantomData,
        })
    }
}

impl LocalMapping<'_> {
    #[inline]
    fn flush_dcache(&self) {
        // SAFETY: The registration pins this page until after the mapping is dropped. CPU writes
        // must invalidate architecture clean-cache state before a later executable mapping.
        unsafe { bindings::flush_dcache_page(self.page) };
    }
}

impl Drop for LocalMapping<'_> {
    fn drop(&mut self) {
        // SAFETY: We own this thread's local mapping, and its page remains pinned until drop.
        unsafe { bindings::kunmap_local(self.ptr.cast()) };
    }
}

#[cfg(CONFIG_RUST_RDMA_UMEM_KUNIT_TEST)]
#[macros::kunit_tests(rust_rdma_umem)]
mod tests {
    use super::*;
    use crate::prelude::*;

    // Stand in for an ordinary umem's stable, pinned backing without requiring a userspace mm.
    // The callback borrows only opaque metadata. The owner keeps two initialized, contiguous
    // pages alive, and there are no Rust borrows of their contents during callback execution.
    fn with_memory(writable: bool, callback: impl FnOnce(&PinnedMemory<()>) -> Result) -> Result {
        let mut data = KBox::<[u8; 2 * PAGE_SIZE]>::zeroed(GFP_KERNEL)?;
        let mut sg = bindings::scatterlist::default();
        let mut umem = bindings::ib_umem::default();
        // SAFETY: The kmalloc allocation is initialized and physically contiguous. Its
        // power-of-two size guarantees page alignment; it stays allocated through the callback.
        unsafe {
            bindings::sg_init_one(&mut sg, data.as_mut_ptr().cast(), (2 * PAGE_SIZE) as u32);
        }
        umem.address = 3;
        umem.length = 2 * PAGE_SIZE - 11;
        umem.set_writable(u32::from(writable));
        umem.sgt_append.sgt.sgl = &mut sg;
        umem.sgt_append.sgt.orig_nents = 1;
        // SAFETY: Metadata and backing stay initialized and unchanged through the callback.
        // The allocation owner retains the backing pages; no ordinary references to their
        // contents exist until this borrow ends. Only the shared-memory interface accesses them.
        callback(unsafe { PinnedMemory::from_raw(&mut umem)? })
    }

    #[test]
    fn unaligned_cross_page_copy() -> Result {
        with_memory(true, |memory| {
            let input = [0x5a; 16];
            let mut output = [0; 16];
            memory.write(PAGE_SIZE - 7, &input)?;
            memory.read(PAGE_SIZE - 7, &mut output)?;
            assert_eq!(input, output);
            assert_eq!(memory.read(usize::MAX, &mut output), Err(EINVAL));
            assert_eq!(memory.write(memory.len() - 15, &input), Err(EINVAL));
            memory.read(memory.len(), &mut [])?;
            memory.write(memory.len(), &[])?;
            Ok(())
        })
    }

    #[test]
    #[cfg(not(CONFIG_GENERIC_ATOMIC64))]
    fn aligned_atomic_access() -> Result {
        with_memory(true, |memory| {
            assert_eq!(memory.compare_exchange(0, 0, 7), Err(EINVAL));
            assert_eq!(memory.compare_exchange(5, 0, 7)?, 0);
            assert_eq!(memory.compare_exchange(5, 0, 19)?, 7);
            assert_eq!(memory.fetch_add(5, u64::MAX)?, 7);
            let mut output = [MaybeUninit::uninit(); 8];
            memory.read_uninit(5, &mut output)?;
            // SAFETY: A successful read_uninit initialized all eight output bytes.
            let output = output.map(|byte| unsafe { byte.assume_init() });
            assert_eq!(u64::from_ne_bytes(output), 6);
            memory.store_release(5, 29)?;
            let mut output = [0; 8];
            memory.read(5, &mut output)?;
            assert_eq!(u64::from_ne_bytes(output), 29);
            assert_eq!(memory.fetch_add(memory.len() - 7, 1), Err(EINVAL));
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
    #[cfg(not(CONFIG_ARCH_HAS_PMEM_API))]
    fn unsupported_cache_writeback_is_rejected() -> Result {
        with_memory(true, |memory| {
            assert!(!memory.is_persistent());
            assert_eq!(memory.flush(0, 1), Err(EOPNOTSUPP));
            memory.flush(0, 0)?;
            Ok(())
        })
    }

    #[test]
    #[cfg(CONFIG_MEMORY_FAILURE)]
    fn poisoned_page_rejects_cpu_access() -> Result {
        with_memory(true, |memory| {
            let mut pages = memory.pages(1);
            // SAFETY: The fixture owns the immutable scatterlist and both backing pages.
            assert!(unsafe { bindings::__sg_page_iter_next(&mut pages) });
            // SAFETY: Iteration returned the second page of the private test allocation.
            let page = unsafe { bindings::sg_page_iter_page(&mut pages) };
            let mut output = [0xa5; 8];
            // SAFETY: Only this test accesses the allocation. The bit is cleared before any
            // assertion can unwind or the allocation can be released.
            unsafe {
                bindings::set_bit(
                    bindings::pageflags_PG_hwpoison as crate::ffi::c_ulong,
                    &raw mut (*page).flags.f,
                );
            }
            let read = memory.read(PAGE_SIZE - 7, &mut output);
            let write = memory.write(PAGE_SIZE - 7, &[0x55; 8]);
            let flush = memory.flush(PAGE_SIZE - 3, 8);
            let atomic = memory.fetch_add(PAGE_SIZE - 3, 1);
            // SAFETY: Restore the test-only flag before assertions or freeing the backing.
            unsafe {
                bindings::clear_bit(
                    bindings::pageflags_PG_hwpoison as crate::ffi::c_ulong,
                    &raw mut (*page).flags.f,
                );
            }
            assert_eq!(read, Err(EHWPOISON));
            assert_eq!(output, [0, 0, 0, 0, 0xa5, 0xa5, 0xa5, 0xa5]);
            assert_eq!(write, Err(EHWPOISON));
            assert_eq!(
                flush,
                Err(if cfg!(CONFIG_ARCH_HAS_PMEM_API) {
                    EHWPOISON
                } else {
                    EOPNOTSUPP
                })
            );
            if !cfg!(CONFIG_GENERIC_ATOMIC64) {
                assert_eq!(atomic, Err(EHWPOISON));
            }
            memory.read(PAGE_SIZE - 7, &mut output)?;
            assert_eq!(output, [0x55, 0x55, 0x55, 0x55, 0, 0, 0, 0]);
            Ok(())
        })
    }

    #[test]
    fn readonly_registration() -> Result {
        with_memory(false, |memory| {
            let mut output = [1; 8];
            memory.read(5, &mut output)?;
            assert_eq!(output, [0; 8]);
            assert_eq!(memory.write(5, &[1; 8]), Err(EPERM));
            assert_eq!(memory.compare_exchange(5, 0, 7), Err(EPERM));
            assert_eq!(memory.fetch_add(5, 1), Err(EPERM));
            assert_eq!(memory.store_release(5, 1), Err(EPERM));
            Ok(())
        })
    }
}
