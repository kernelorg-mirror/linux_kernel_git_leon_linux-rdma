// SPDX-License-Identifier: GPL-2.0

//! Memory shared with userspace.
//!
//! [`SharedVmalloc`] owns zeroed, virtually contiguous memory suitable for user mappings. Unlike
//! ordinary Rust allocations, its contents may change without the kernel's cooperation. Accesses
//! use the kernel's [atomic primitives](crate::sync::atomic), and never expose ordinary references
//! to shared bytes. Copies can observe a mixture of concurrent writes: callers must validate the
//! private copy before interpreting it.
//!
//! C header: [`include/linux/vmalloc.h`](srctree/include/linux/vmalloc.h)

use crate::{
    alloc::{
        AllocError,
        KVec, //
    },
    bindings,
    error::{
        code::EINVAL,
        Result, //
    },
    page::{
        page_align,
        PAGE_SIZE, //
    },
    prelude::*,
    sync::atomic::{
        atomic_load,
        atomic_store,
        Atomic,
        Relaxed, //
    },
    workqueue::{
        self,
        Work,
        WorkItem, //
    }, //
};
use core::ptr::NonNull;

// SHMLBA is a power of two. Only the shared-memory colour matters, including when
// retained pages outlive the kernel virtual mapping which established that colour.
#[cfg(CONFIG_MMU)]
const fn matching_colour(source: usize, target: usize, offset: usize, alignment: usize) -> bool {
    (source.wrapping_add(offset) ^ target) & (alignment - 1) == 0
}

/// An owned, initialized allocation that can be shared with userspace.
///
/// The allocation cannot be resized. It can be mapped with
/// [`VmaNew::remap_vmalloc_range`](super::virt::VmaNew::remap_vmalloc_range); those mappings hold
/// their own page references and may outlive this object. Dropping this object releases the
/// kernel mapping and its page references through deferred work. Dropping the owner does not
/// allocate or sleep; private work linkage remains inaccessible to userspace.
///
/// # Invariants
///
/// - `allocation` is present until destruction and owns a `vmalloc_user` allocation of `len`
///   initialized bytes. Its private work item has not been queued.
/// - `len` is nonzero, page aligned, and at most `isize::MAX`.
/// - Kernel accesses to the contents are atomic, or serialized against all other kernel accesses.
///   Ordinary Rust references to the contents do not exist.
///
/// # Examples
///
/// ```
/// use kernel::{mm::shared::SharedVmalloc, sync::atomic::{Acquire, Release}};
///
/// let memory = SharedVmalloc::new(4096)?;
/// memory.write(4, b"message")?;
/// memory.atomic_u32(0)?.store(7, Release);
/// assert_eq!(memory.atomic_u32(0)?.load(Acquire), 7);
/// let mut copy = [0; 7];
/// memory.read(4, &mut copy)?;
/// assert_eq!(&copy, b"message");
/// # Ok::<(), kernel::error::Error>(())
/// ```
pub struct SharedVmalloc {
    allocation: Option<Pin<KBox<Allocation>>>,
    len: usize,
}

/// Private ownership and deferred-free linkage, never included in a user mapping.
#[pin_data]
struct Allocation {
    #[pin]
    work: Work<Self>,
    ptr: NonNull<u8>,
}

// SAFETY: The pointer owns its allocation, whose atomic accesses are governed by SharedVmalloc.
unsafe impl Send for Allocation {}
// SAFETY: The immutable pointer exposes no safe access to the allocation's shared bytes.
unsafe impl Sync for Allocation {}

crate::workqueue::impl_has_work! {
    impl HasWork<Self> for Allocation { self.work }
}

impl WorkItem for Allocation {
    type Pointer = Pin<KBox<Self>>;

    fn run(this: Self::Pointer) {
        // SAFETY: Queueing transferred the sole allocation owner. All Rust borrows have ended;
        // user mappings retain independent page references. Work runs in process context, so
        // vfree does not write deferred-free linkage into the user-writable allocation.
        unsafe { bindings::vfree(this.ptr.as_ptr().cast()) };
    }
}

// SAFETY: The allocation is owned, and `vfree` does not require the allocating task.
unsafe impl Send for SharedVmalloc {}
// SAFETY: All safe accesses to the shared contents use LKMM atomics. Bounds and lifetime are
// checked before returning atomic references, and the allocation cannot shrink while borrowed.
unsafe impl Sync for SharedVmalloc {}

impl SharedVmalloc {
    /// Returns the architecture's alignment for shared-memory mappings.
    ///
    /// `vmalloc_user` aligns the kernel mapping to this boundary. Drivers assigning file
    /// offsets to shared allocations can use it to preserve cache-alias alignment.
    #[inline]
    pub fn alignment() -> usize {
        // SAFETY: This returns the architecture's SHMLBA value without accessing an object.
        unsafe { bindings::shmlba() }
    }

    /// Allocates zeroed memory, rounding `size` up to a page boundary.
    ///
    /// Uses `GFP_KERNEL` and may sleep. Returns [`AllocError`] if the size is zero, cannot be
    /// represented after rounding, or the allocation fails.
    // Keep the work callback and its lock class in the kernel crate, even for module callers.
    #[inline(never)]
    pub fn new(size: usize) -> Result<Self, AllocError> {
        let len = page_align(size)
            .filter(|&len| len != 0 && len <= isize::MAX as usize)
            .ok_or(AllocError)?;
        let allocation = KBox::pin_init(
            try_pin_init!(Allocation {
                work <- workqueue::new_work!("SharedVmalloc::free"),
                // SAFETY: This nonzero size is representable. The helper charges the current
                // memory cgroup, initializes all bytes including padding, and permits user
                // mappings. This is the last fallible step, so a mapping always gains an owner.
                ptr: NonNull::new(unsafe { bindings::vmalloc_user_account(len) }.cast())
                    .ok_or(AllocError)?,
            }),
            GFP_KERNEL,
        )
        .map_err(|_| AllocError)?;
        // INVARIANT: The private, unqueued work item owns the zeroed vmalloc_user allocation.
        // No other kernel accesses or references to its contents exist yet.
        Ok(Self {
            allocation: Some(allocation),
            len,
        })
    }

    /// Returns the allocation size, including zero-initialized page padding.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the allocation is empty (always false).
    #[inline]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Retains the backing pages independently of this kernel mapping.
    ///
    /// Allocates the page-reference array with `GFP_KERNEL` and may sleep. The returned owner
    /// can initialize a userspace mapping after this allocation has been dropped. It does not
    /// retain the kernel virtual address or grant ordinary Rust references to shared contents.
    pub fn retain_pages(&self) -> Result<SharedPages, AllocError> {
        let count = self.len / PAGE_SIZE;
        let mut pages = KVec::with_capacity(count, GFP_KERNEL)?;
        for index in 0..count {
            // SAFETY: Each address is within this live vmalloc_user allocation. It uses order-0
            // pages without VM_ALLOW_HUGE_VMAP, and the allocation retains them during acquisition.
            let page = unsafe {
                let page = bindings::vmalloc_to_page(self.as_ptr().add(index * PAGE_SIZE).cast());
                bindings::get_page(page);
                NonNull::new_unchecked(page)
            };
            // INVARIANT: The acquired reference retains an initialized order-0 page whose
            // shared contents remain governed by SharedVmalloc's access rules.
            pages.push(SharedPage(page), GFP_KERNEL)?;
        }
        Ok(SharedPages {
            pages,
            #[cfg(CONFIG_MMU)]
            colour: self.as_ptr() as usize & (Self::alignment() - 1),
        })
    }

    /// Checks that a user alias has the same shared-memory colour as its backing.
    #[cfg(CONFIG_MMU)]
    pub(super) fn matches_colour(&self, address: usize, offset: usize) -> bool {
        matching_colour(self.as_ptr() as usize, address, offset, Self::alignment())
    }

    /// Returns the kernel address of the allocation.
    ///
    /// The pointer is page aligned and valid for [`Self::len`] bytes while `self` is alive.
    /// Accesses through it must uphold the type invariants: they must not create ordinary Rust
    /// references, free the allocation, or race non-atomic kernel accesses against other accesses.
    /// Userspace may change any byte at any time, including during an otherwise exclusive borrow.
    #[inline]
    pub fn as_ptr(&self) -> *mut u8 {
        self.allocation.as_ref().unwrap().ptr.as_ptr()
    }

    /// Checks that a byte range lies entirely within the allocation.
    #[inline]
    fn check_range(&self, offset: usize, len: usize) -> Result {
        if offset.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(EINVAL);
        }
        Ok(())
    }

    /// Copies shared bytes into `dst`, without promising a coherent snapshot.
    ///
    /// Returns [`EINVAL`] without modifying `dst` if the range is out of bounds.
    pub fn read(&self, offset: usize, dst: &mut [u8]) -> Result {
        self.check_range(offset, dst.len())?;
        for (i, byte) in dst.iter_mut().enumerate() {
            // SAFETY: The checked range is initialized and remains allocated through `self`.
            // Every bit pattern is a valid `u8`, and the type invariants exclude non-atomic
            // kernel accesses racing with this load. LKMM permits concurrent userspace writes.
            *byte = unsafe { atomic_load(self.as_ptr().add(offset + i), Relaxed) };
        }
        Ok(())
    }

    /// Copies `src` into shared memory.
    ///
    /// Returns [`EINVAL`] without modifying the allocation if the range is out of bounds.
    /// This does not publish the bytes as a unit; use a separate atomic index for publication.
    pub fn write(&self, offset: usize, src: &[u8]) -> Result {
        self.check_range(offset, src.len())?;
        for (i, &byte) in src.iter().enumerate() {
            // SAFETY: The checked range remains allocated through `self`, and the type invariants
            // exclude non-atomic kernel accesses racing with this store.
            unsafe { atomic_store(self.as_ptr().add(offset + i), byte, Relaxed) };
        }
        Ok(())
    }

    /// Fills a shared range with `value`.
    ///
    /// Returns [`EINVAL`] without modifying the allocation if the range is out of bounds.
    /// This does not publish the bytes as a unit.
    pub fn fill(&self, offset: usize, len: usize, value: u8) -> Result {
        self.check_range(offset, len)?;
        for i in 0..len {
            // SAFETY: The checked range remains allocated through `self`, and the type invariants
            // exclude non-atomic kernel accesses racing with this store.
            unsafe { atomic_store(self.as_ptr().add(offset + i), value, Relaxed) };
        }
        Ok(())
    }

    /// Borrows an aligned [`Atomic<u32>`] within the allocation.
    ///
    /// Returns [`EINVAL`] if the word is unaligned or out of bounds. The returned reference cannot
    /// outlive the allocation. It may overlap byte accesses: LKMM permits mixed-size atomic
    /// accesses. Acquire/release ordering only synchronizes with a cooperating publisher/observer;
    /// it cannot prevent userspace from changing a published value.
    #[inline]
    pub fn atomic_u32(&self, offset: usize) -> Result<&Atomic<u32>> {
        self.check_range(offset, size_of::<u32>())?;
        if !offset.is_multiple_of(align_of::<u32>()) {
            return Err(EINVAL);
        }
        // SAFETY: The allocation is page aligned and the complete word is in bounds and aligned.
        // It is initialized, all bit patterns are valid, and the type invariants exclude racing
        // non-atomic kernel accesses. The returned borrow is tied to the allocation's lifetime.
        Ok(unsafe { Atomic::from_ptr(self.as_ptr().add(offset).cast()) })
    }
}

impl Drop for SharedVmalloc {
    fn drop(&mut self) {
        // The preallocated private work item has never been queued. Ownership transfers to
        // the workqueue without allocation, including when the last owner drops in softirq.
        workqueue::system_dfl().enqueue(self.allocation.take().unwrap());
    }
}

/// One owned reference to an initialized order-0 page of shared memory.
///
/// # Invariants
///
/// The pointer owns a page reference acquired from a live `vmalloc_user` allocation. Shared
/// contents are never exposed as ordinary Rust references, even after that allocation is freed.
struct SharedPage(NonNull<bindings::page>);

// SAFETY: Page references may be released from any thread and expose no access to shared bytes.
unsafe impl Send for SharedPage {}
// SAFETY: The immutable owner retains its page and exposes no unsynchronized content access.
unsafe impl Sync for SharedPage {}

impl Drop for SharedPage {
    fn drop(&mut self) {
        // SAFETY: The invariant supplies exactly one owned reference to this initialized page.
        unsafe { bindings::put_page(self.0.as_ptr()) };
    }
}

/// Retained shared pages which may outlive their original kernel virtual mapping.
///
/// Created by [`SharedVmalloc::retain_pages`]. These references can initialize a VMA with
/// [`VmaNew::map_shared_pages`](super::virt::VmaNew::map_shared_pages), which acquires its own
/// page references. The original mapping's shared-memory colour is retained for those aliases.
/// Dropping this owner does not revoke any established userspace mappings.
pub struct SharedPages {
    pages: KVec<SharedPage>,
    #[cfg(CONFIG_MMU)]
    colour: usize,
}

impl SharedPages {
    /// Checks the colour retained from the original kernel mapping.
    #[cfg(CONFIG_MMU)]
    pub(super) fn matches_colour(&self, address: usize, pgoff: usize) -> bool {
        pgoff.checked_mul(PAGE_SIZE).is_some_and(|offset| {
            matching_colour(self.colour, address, offset, SharedVmalloc::alignment())
        })
    }

    /// Returns the number of retained pages.
    #[inline]
    pub fn len(&self) -> usize {
        self.pages.len()
    }

    /// Returns whether there are no retained pages.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }

    // Each pointer is valid only while this owner remains live. MM mapping code must not
    // transfer our reference or create ordinary references to the shared contents.
    #[inline]
    pub(super) fn page(&self, index: usize) -> *mut bindings::page {
        self.pages[index].0.as_ptr()
    }
}

#[cfg(CONFIG_RUST_SHARED_VMALLOC_KUNIT_TEST)]
#[macros::kunit_tests(rust_shared_vmalloc)]
mod tests {
    use super::*;
    use crate::{
        page::PAGE_SIZE,
        sync::atomic::{
            Acquire,
            Release, //
        }, //
    };

    #[test]
    #[cfg(CONFIG_MMU)]
    fn mappings_preserve_backing_colour() -> Result {
        let alignment = 4 * PAGE_SIZE;
        let source = 8 * PAGE_SIZE;
        assert!(matching_colour(source, 16 * PAGE_SIZE, 0, alignment));
        assert!(!matching_colour(source, 17 * PAGE_SIZE, 0, alignment));
        assert!(matching_colour(
            source,
            17 * PAGE_SIZE,
            PAGE_SIZE,
            alignment
        ));
        assert!(!matching_colour(
            source,
            16 * PAGE_SIZE,
            PAGE_SIZE,
            alignment
        ));
        assert!(matching_colour(
            source,
            16 * PAGE_SIZE,
            alignment,
            alignment
        ));

        let memory = SharedVmalloc::new(2 * PAGE_SIZE)?;
        let pages = memory.retain_pages()?;
        let address = memory.as_ptr() as usize;
        assert!(memory.matches_colour(address + PAGE_SIZE, PAGE_SIZE));
        drop(memory);
        assert!(pages.matches_colour(address, 0));
        assert!(pages.matches_colour(address + PAGE_SIZE, 1));
        assert!(!pages.matches_colour(address, usize::MAX));
        Ok(())
    }

    #[test]
    fn ranges_and_alignment() -> Result {
        assert!(SharedVmalloc::new(0).is_err());
        assert!(SharedVmalloc::new(usize::MAX).is_err());
        assert!(SharedVmalloc::new(isize::MAX as usize).is_err());
        let memory = SharedVmalloc::new(PAGE_SIZE + 1)?;
        assert_eq!(memory.len(), 2 * PAGE_SIZE);
        let end = memory.len();
        let mut byte = [0xff];
        memory.read(end - 1, &mut byte)?;
        assert_eq!(byte, [0]);
        memory.write(end - 1, &[0x80])?;
        memory.read(end - 1, &mut byte)?;
        assert_eq!(byte, [0x80]);
        assert!(memory.read(end, &mut byte).is_err());
        assert_eq!(byte, [0x80]);
        assert!(memory.write(end - 1, &[1, 2]).is_err());
        assert!(memory.fill(usize::MAX, 2, 0).is_err());
        memory.read(end - 1, &mut byte)?;
        assert_eq!(byte, [0x80]);
        memory.read(end, &mut [])?;
        memory.write(end, &[])?;
        memory.fill(end, 0, 0)?;
        assert!(memory.atomic_u32(1).is_err());
        assert!(memory.atomic_u32(end).is_err());
        assert!(memory.atomic_u32(usize::MAX - 3).is_err());
        memory.atomic_u32(end - 4)?.store(u32::MAX, Release);
        assert_eq!(memory.atomic_u32(end - 4)?.load(Acquire), u32::MAX);
        Ok(())
    }

    #[test]
    fn interrupt_drop_preserves_retained_page_contents() -> Result {
        use crate::time::{
            delay::fsleep,
            timer::{
                Context,
                Event,
                Timer, //
            },
            Delta, //
        };

        static RESULT: Atomic<u32> = Atomic::new(0);
        struct DropShared {
            memory: SharedVmalloc,
            pages: SharedPages,
        }
        impl Event for DropShared {
            fn expire(self, _context: Context<'_>) {
                drop(self.memory);
                // SAFETY: The independent page reference survives dropping the kernel mapping.
                // No user mapping or other writer exists; use atomic accesses as for shared data.
                let value = unsafe {
                    let mapping = bindings::kmap_local_page(self.pages.page(0));
                    let value = atomic_load(mapping.cast::<u32>(), Relaxed);
                    bindings::kunmap_local(mapping);
                    value
                };
                RESULT.store(if value == 0xa5a5_a5a5 { 1 } else { 2 }, Release);
            }
        }

        RESULT.store(0, Relaxed);
        let memory = SharedVmalloc::new(PAGE_SIZE)?;
        memory.fill(0, size_of::<usize>(), 0xa5)?;
        let pages = memory.retain_pages()?;
        let timer = Timer::new(
            c"shared vmalloc interrupt drop",
            crate::static_lock_class!(),
        )?;
        assert!(timer.arm(1, DropShared { memory, pages }).is_none());
        for _ in 0..1000 {
            if RESULT.load(Acquire) != 0 {
                break;
            }
            fsleep(Delta::from_millis(1));
        }
        drop(timer);
        assert_eq!(RESULT.load(Acquire), 1);
        Ok(())
    }

    #[test]
    fn overlapping_atomic_access() -> Result {
        let memory = SharedVmalloc::new(4)?;
        let word = memory.atomic_u32(0)?;
        word.store(0x80ff_01aa, Release);
        let mut bytes = [0; 4];
        memory.read(0, &mut bytes)?;
        assert_eq!(bytes, 0x80ff_01aa_u32.to_ne_bytes());
        memory.write(0, &0xfedc_9876_u32.to_ne_bytes())?;
        assert_eq!(word.load(Acquire), 0xfedc_9876);
        memory.fill(0, 4, 0xff)?;
        assert_eq!(word.load(Acquire), u32::MAX);
        Ok(())
    }
}
