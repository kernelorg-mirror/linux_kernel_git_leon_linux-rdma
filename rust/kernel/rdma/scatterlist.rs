// SPDX-License-Identifier: GPL-2.0

//! Borrowed RDMA scatter/gather descriptors.
//!
//! C header: [`include/rdma/ib_verbs.h`](srctree/include/rdma/ib_verbs.h)

use crate::{
    bindings,
    error::{
        code::EINVAL,
        Result, //
    },
    prelude::c_int, //
};
use core::{
    mem::{
        align_of,
        offset_of,
        size_of, //
    },
    slice, //
};

/// One RDMA scatter/gather descriptor.
///
/// The address and key are identifiers, not permission to access memory. Their interpretation
/// depends on the work request: for example, inline send addresses refer to CPU memory while
/// ordinary sends use the local registration and its address space. Copying a descriptor does
/// not retain its registration or backing memory.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScatterGather {
    address: u64,
    length: u32,
    key: u32,
}

const _: () = assert!(size_of::<ScatterGather>() == size_of::<bindings::ib_sge>());
const _: () = assert!(align_of::<ScatterGather>() == align_of::<bindings::ib_sge>());
const _: () = assert!(offset_of!(ScatterGather, address) == offset_of!(bindings::ib_sge, addr));
const _: () = assert!(offset_of!(ScatterGather, length) == offset_of!(bindings::ib_sge, length));
const _: () = assert!(offset_of!(ScatterGather, key) == offset_of!(bindings::ib_sge, lkey));

impl ScatterGather {
    /// Creates a descriptor without acquiring its registration or memory.
    #[inline]
    pub const fn new(address: u64, length: u32, key: u32) -> Self {
        Self {
            address,
            length,
            key,
        }
    }

    /// Returns the address in the work request's address space.
    #[inline]
    pub const fn address(&self) -> u64 {
        self.address
    }

    /// Returns the described byte count.
    #[inline]
    pub const fn length(&self) -> u32 {
        self.length
    }

    /// Returns the local registration key.
    #[inline]
    pub const fn key(&self) -> u32 {
        self.key
    }

    /// Borrows the descriptor array of a kernel work request.
    ///
    /// Negative counts, nonempty null arrays and lengths exceeding Rust's slice limit fail.
    /// A zero count accepts a null pointer and returns an empty slice.
    ///
    /// # Safety
    ///
    /// If `entries` is non-null and the positive count fits the slice size limit, it must
    /// point to `count` initialized, aligned `ib_sge` values within one allocation.
    /// The array must remain live and unchanged for `'a`.
    /// These requirements apply to the descriptors only; this method does not access their
    /// described memory or require a live registration.
    #[inline]
    pub unsafe fn from_raw<'a>(
        entries: *const bindings::ib_sge,
        count: c_int,
    ) -> Result<&'a [Self]> {
        let count = usize::try_from(count).map_err(|_| EINVAL)?;
        if count == 0 {
            return Ok(&[]);
        }
        if entries.is_null()
            || count
                .checked_mul(size_of::<Self>())
                .is_none_or(|size| size > isize::MAX as usize)
        {
            return Err(EINVAL);
        }
        // SAFETY: The caller supplies a stable initialized array for 'a. Layout assertions
        // establish that each C descriptor is a valid ScatterGather, and the checked length
        // fits Rust's slice limit. No reference to the described memory is constructed.
        Ok(unsafe { slice::from_raw_parts(entries.cast(), count) })
    }
}
