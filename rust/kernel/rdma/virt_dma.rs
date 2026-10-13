// SPDX-License-Identifier: GPL-2.0

//! Bounded access to tracked virtual DMA mappings.
//!
//! C header: [`include/rdma/ib_virt_dma.h`](srctree/include/rdma/ib_virt_dma.h)

use super::Device;
use crate::{
    bindings,
    error::{
        code::*,
        to_result,
        Result, //
    },
    page::PAGE_SIZE, //
};
use core::{
    mem::MaybeUninit,
    slice, //
};

/// Access to the live virtual DMA mappings of a borrowed RDMA device.
///
/// Addresses are integers, including when supplied by an untrusted peer. Every access checks
/// coverage and DMA direction under the mapping lock, which excludes concurrent unmap until
/// the access completes. Mapped memory remains externally mutable; no Rust reference into it
/// is exposed. Unmapped addresses fail instead of being converted into pointers by a provider.
///
/// # Invariants
///
/// `device` has virtual DMA tracking enabled. Its borrow keeps that configuration and the
/// tracking registry alive.
pub struct VirtualDma<'a, T> {
    pub(super) device: &'a Device<T>,
}

impl<T> Device<T> {
    /// Borrows this device's tracked virtual DMA interface.
    ///
    /// Returns [`EOPNOTSUPP`] if the provider did not enable tracking before publication.
    #[inline]
    pub fn virtual_dma(&self) -> Result<VirtualDma<'_, T>> {
        // SAFETY: The device invariant keeps the core object and immutable DMA configuration
        // live. The tracking pointer is only installed before the device is published.
        if unsafe { (*self.as_raw()).virt_dma.is_null() } {
            return Err(EOPNOTSUPP);
        }
        // INVARIANT: The checked registry remains installed throughout this device borrow.
        Ok(VirtualDma { device: self })
    }
}

impl<T> VirtualDma<'_, T> {
    /// Copies bytes from mappings that permit device reads.
    ///
    /// The copy is split into at most page-sized accesses. A concurrent unmap may make a later
    /// access fail after an earlier one succeeded; the output remains initialized in all cases.
    #[inline]
    pub fn read(&self, address: u64, output: &mut [u8]) -> Result {
        // SAFETY: Every initialized byte is also a valid MaybeUninit<u8>. The exclusive borrow
        // is preserved, and read_uninit only writes initialized bytes, including on error.
        let output = unsafe { slice::from_raw_parts_mut(output.as_mut_ptr().cast(), output.len()) };
        self.read_uninit(address, output)
    }

    /// Copies mapped bytes into possibly uninitialized private storage.
    ///
    /// On success every output byte is initialized. On error a prefix may have been written;
    /// the remaining bytes retain their previous initialization state.
    #[inline]
    pub fn read_uninit(&self, mut address: u64, output: &mut [MaybeUninit<u8>]) -> Result {
        address.checked_add(output.len() as u64).ok_or(EFAULT)?;
        for chunk in output.chunks_mut(PAGE_SIZE) {
            // SAFETY: The invariant pins the registry. C validates and retains the mapping,
            // and materializes its object representation as initialized output bytes.
            // `chunk` is exclusively writable and cannot alias mapped
            // storage because that storage is not available for ordinary Rust borrows.
            to_result(unsafe {
                bindings::ib_virt_dma_read(
                    self.device.as_raw(),
                    address,
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                )
            })?;
            address += chunk.len() as u64;
        }
        Ok(())
    }

    /// Copies bytes to mappings that permit device writes.
    ///
    /// A later access may fail after a prefix has been written, as with [`Self::read`].
    #[inline]
    pub fn write(&self, mut address: u64, input: &[u8]) -> Result {
        address.checked_add(input.len() as u64).ok_or(EFAULT)?;
        for chunk in input.chunks(PAGE_SIZE) {
            // SAFETY: The registry is live, and C validates and retains the writable mapping
            // throughout the copy. `chunk` is readable and cannot alias mapped storage.
            to_result(unsafe {
                bindings::ib_virt_dma_write(
                    self.device.as_raw(),
                    address,
                    chunk.as_ptr().cast(),
                    chunk.len(),
                )
            })?;
            address += chunk.len() as u64;
        }
        Ok(())
    }

    /// Compares an aligned word with `current`, replacing it with `new` on equality.
    ///
    /// Returns the old value. The complete word must have a bidirectional DMA mapping.
    /// Kernel atomic primitives also serialize aliases used by other memory interfaces.
    #[inline]
    pub fn compare_exchange(&self, address: u64, current: u64, new: u64) -> Result<u64> {
        self.atomic(
            address,
            bindings::ib_virt_dma_atomic_op_IB_VIRT_DMA_CMP_SWAP,
            current,
            new,
        )
    }

    /// Adds `value` to an aligned word, returning the old value with wrapping arithmetic.
    ///
    /// Direction and serialization follow [`Self::compare_exchange`].
    #[inline]
    pub fn fetch_add(&self, address: u64, value: u64) -> Result<u64> {
        self.atomic(
            address,
            bindings::ib_virt_dma_atomic_op_IB_VIRT_DMA_FETCH_ADD,
            0,
            value,
        )
    }

    /// Publishes an aligned word with release ordering in a device-writable mapping.
    #[inline]
    pub fn store_release(&self, address: u64, value: u64) -> Result {
        self.atomic(
            address,
            bindings::ib_virt_dma_atomic_op_IB_VIRT_DMA_WRITE,
            0,
            value,
        )
        .map(|_| ())
    }

    #[inline]
    fn atomic(
        &self,
        address: u64,
        operation: bindings::ib_virt_dma_atomic_op,
        compare: u64,
        value: u64,
    ) -> Result<u64> {
        let mut original = 0;
        // SAFETY: The registry stays live, C validates alignment, direction and mapping coverage
        // and excludes unmap until the atomic access completes. `original` is private writable
        // storage and cannot alias a mapping.
        to_result(unsafe {
            bindings::ib_virt_dma_atomic(
                self.device.as_raw(),
                address,
                operation,
                compare,
                value,
                &mut original,
            )
        })?;
        Ok(original)
    }
}

/// An owned capture of the mappings intersecting a bounded DMA range.
///
/// The final unmap of an equivalent address/size/direction tuple revokes access without waiting
/// for this handle. A later mapping at the same address cannot revive it. Holes are permitted
/// when capturing a range; every operation checks that its requested bytes are still covered
/// by the original mappings with the required direction.
/// No reference into mapped memory escapes an operation.
///
/// The handle retains a core device reference and mapping metadata, without retaining provider
/// state or preventing the DMA caller from unmapping and freeing the backing storage.
///
/// Destruction requires process or softirq context compatible with regular kernel spinlocks
/// and memory deallocation, including on PREEMPT_RT. Hardirq and raw-spinlocked contexts are
/// unsupported. Dropping the last clone can also release the last core device reference and
/// run device teardown: this requires sleepable context unless another device reference is
/// retained throughout the drop to exclude final device destruction.
///
/// # Invariants
///
/// `inner` owns an `ib_virt_dma_range` and its core device reference. All captured mappings obey
/// the device's DMA storage contract until unmap, even after the original device borrow ends.
pub struct Range<T> {
    inner: core::ptr::NonNull<bindings::ib_virt_dma_range>,
    _provider: core::marker::PhantomData<fn() -> T>,
}

// SAFETY: The immutable handle is not thread-bound, and the core serializes revocation and access.
unsafe impl<T> Send for Range<T> {}
// SAFETY: Shared operations do not modify the handle; the core lock protects mapping state.
unsafe impl<T> Sync for Range<T> {}

impl<T> VirtualDma<'_, T> {
    /// Captures the identities of mappings intersecting `address..address + size`.
    ///
    /// `size` must be between one byte and [`PAGE_SIZE`]. The range may contain unmapped bytes.
    /// Allocation uses `GFP_ATOMIC`; no backing address is dereferenced during capture.
    /// Call from process or softirq context compatible with regular kernel spinlocks,
    /// including on PREEMPT_RT. Raw-spinlocked and hardirq contexts are not supported.
    /// More than 256 distinct intersecting mapping tuples returns `E2BIG`. Equivalent live DMA
    /// maps share one tuple. Concurrent map changes may exhaust bounded retries and return
    /// `EAGAIN`.
    #[inline]
    pub fn capture(&self, address: u64, size: usize) -> Result<Range<T>> {
        // SAFETY: The borrow pins the registry. C validates the range, retains its own device
        // reference and captures mapping metadata under the unmap lock.
        let inner = crate::error::from_err_ptr(unsafe {
            bindings::ib_virt_dma_range_alloc(self.device.as_raw(), address, size)
        })?;
        // INVARIANT: The successful allocation owns the range and its device reference. The
        // device contract applies to each captured mapping until it is unmapped.
        Ok(Range {
            // SAFETY: A successful allocation returns a non-null handle.
            inner: unsafe { core::ptr::NonNull::new_unchecked(inner) },
            _provider: core::marker::PhantomData,
        })
    }
}

impl<T> Range<T> {
    /// Copies live, device-readable bytes into initialized private storage.
    #[inline]
    pub fn read(&self, offset: usize, output: &mut [u8]) -> Result {
        // SAFETY: Exclusive access is preserved, and read_uninit only writes initialized bytes.
        let output = unsafe { slice::from_raw_parts_mut(output.as_mut_ptr().cast(), output.len()) };
        self.read_uninit(offset, output)
    }

    /// Copies live, device-readable bytes into possibly uninitialized private storage.
    ///
    /// Success initializes the entire output. Failure leaves it unchanged.
    #[inline]
    pub fn read_uninit(&self, offset: usize, output: &mut [MaybeUninit<u8>]) -> Result {
        // SAFETY: The owned handle pins the registry and metadata. C bounds and direction checks
        // retain the live backing and materialize initialized bytes during the copy.
        // The exclusive output cannot alias DMA storage,
        // which the device contract excludes from ordinary Rust borrows until unmap.
        to_result(unsafe {
            bindings::ib_virt_dma_range_read(
                self.inner.as_ptr(),
                offset,
                output.as_mut_ptr().cast(),
                output.len(),
            )
        })
    }

    /// Copies private storage into live, device-writable bytes.
    #[inline]
    pub fn write(&self, offset: usize, input: &[u8]) -> Result {
        // SAFETY: C checks bounds, direction and mapping liveness while excluding unmap. The
        // readable input cannot alias tracked storage under the device's DMA contract.
        to_result(unsafe {
            bindings::ib_virt_dma_range_write(
                self.inner.as_ptr(),
                offset,
                input.as_ptr().cast(),
                input.len(),
            )
        })
    }

    /// Compares and conditionally replaces an aligned, bidirectionally mapped word.
    #[inline]
    pub fn compare_exchange(&self, offset: usize, current: u64, new: u64) -> Result<u64> {
        self.atomic(
            offset,
            bindings::ib_virt_dma_atomic_op_IB_VIRT_DMA_CMP_SWAP,
            current,
            new,
        )
    }

    /// Adds to an aligned, bidirectionally mapped word, returning its old value.
    #[inline]
    pub fn fetch_add(&self, offset: usize, value: u64) -> Result<u64> {
        self.atomic(
            offset,
            bindings::ib_virt_dma_atomic_op_IB_VIRT_DMA_FETCH_ADD,
            0,
            value,
        )
    }

    /// Publishes an aligned, device-writable word with release ordering.
    #[inline]
    pub fn store_release(&self, offset: usize, value: u64) -> Result {
        self.atomic(
            offset,
            bindings::ib_virt_dma_atomic_op_IB_VIRT_DMA_WRITE,
            0,
            value,
        )
        .map(|_| ())
    }

    #[inline]
    fn atomic(
        &self,
        offset: usize,
        operation: bindings::ib_virt_dma_atomic_op,
        compare: u64,
        value: u64,
    ) -> Result<u64> {
        let mut original = 0;
        // SAFETY: C validates bounds, alignment, direction and mapping liveness, then performs a
        // kernel atomic operation under the unmap lock. The result is disjoint private storage.
        to_result(unsafe {
            bindings::ib_virt_dma_range_atomic(
                self.inner.as_ptr(),
                offset,
                operation,
                compare,
                value,
                &mut original,
            )
        })?;
        Ok(original)
    }

    /// Completes cache writeback for a still-mapped byte range.
    ///
    /// Unmap remains excluded until the writeback completion barrier has executed. Providers
    /// must separately validate that the backing is persistent with [`Self::is_persistent`].
    /// Nonempty live ranges return [`EOPNOTSUPP`] without architecture cache writeback support.
    #[inline]
    pub fn flush(&self, offset: usize, size: usize) -> Result {
        // SAFETY: C checks bounds and coverage and excludes unmap throughout the cache flush.
        to_result(unsafe { bindings::ib_virt_dma_range_flush(self.inner.as_ptr(), offset, size) })
    }

    /// Checks for live mappings, persistent backing and architecture cache writeback support.
    ///
    /// Unmapped bytes fail. Revoked identities do not matter when other captured mappings
    /// still cover the requested range. Bytes outside the requested range are ignored.
    /// Call from process context because the resource lookup uses a non-IRQ-safe lock.
    #[inline]
    pub fn is_persistent(&self, offset: usize, size: usize) -> bool {
        // SAFETY: The handle retains metadata; C inspects live backing under the unmap lock.
        unsafe { bindings::ib_virt_dma_range_is_persistent(self.inner.as_ptr(), offset, size) }
    }
}

impl<T> Clone for Range<T> {
    #[inline]
    fn clone(&self) -> Self {
        // SAFETY: This borrow retains the immutable range and its device. The new owner
        // releases its additional reference in Drop; backing revocation remains shared.
        unsafe { bindings::ib_virt_dma_range_get(self.inner.as_ptr()) };
        // INVARIANT: The new reference retains the same range, device and mapping identities;
        // backing storage remains subject to the original DMA contract until unmap.
        Self {
            inner: self.inner,
            _provider: core::marker::PhantomData,
        }
    }
}

impl<T> Drop for Range<T> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: Each owner releases one native range reference. The final release drops its
        // metadata and core device reference in the destruction context required by Range.
        // Mapped backing remains owned by the DMA caller.
        unsafe { bindings::ib_virt_dma_range_free(self.inner.as_ptr()) };
    }
}
