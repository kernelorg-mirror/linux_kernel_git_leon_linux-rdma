// SPDX-License-Identifier: GPL-2.0

//! Static counter descriptions and core-owned RDMA statistics buffers.

use crate::{
    bindings,
    str::{
        as_char_ptr_in_const_context,
        CStr, //
    }, //
};
use core::ptr;

/// Descriptions of always-enabled counters exposed through the RDMA core.
///
/// The table must be static before it can describe an allocation. Counter names and order
/// form the provider's statistics ABI. Optional counters and private C data are not supported.
///
/// # Invariants
///
/// The table is nonempty, its length fits in a C `int`, and every name is an immutable static
/// string. Flags are zero and private pointers are null.
pub struct Statistics<const N: usize> {
    descriptors: [bindings::rdma_stat_desc; N],
}

// SAFETY: The private descriptors contain only immutable static names and null private pointers.
// Neither safe Rust nor the RDMA core can modify them through a shared reference.
unsafe impl<const N: usize> Sync for Statistics<N> {}

impl<const N: usize> Statistics<N> {
    /// Defines a nonempty table of static counter names.
    #[inline]
    pub const fn new(names: [&'static CStr; N]) -> Self {
        assert!(N > 0 && N <= i32::MAX as usize);
        let mut descriptors = [bindings::rdma_stat_desc {
            name: ptr::null(),
            flags: 0,
            priv_: ptr::null(),
        }; N];
        let mut index = 0;
        while index < N {
            assert!(super::sysfs::valid_name(names[index]));
            descriptors[index].name = as_char_ptr_in_const_context(names[index]);
            index += 1;
        }
        // INVARIANT: The checked length and static names satisfy the descriptor requirements.
        Self { descriptors }
    }

    /// Describes a core-owned allocation with the requested cache lifespan in milliseconds.
    #[inline]
    pub fn description(&'static self, lifespan_ms: u32) -> StatisticsDescription {
        // INVARIANT: The table's invariants and static borrow also cover this description.
        StatisticsDescription {
            descriptors: &self.descriptors,
            lifespan_ms,
        }
    }
}

/// Static descriptors and a cache lifespan for one device or port's statistics.
///
/// Returned from the provider's allocation callback. The adapter allocates the counter values,
/// and the RDMA core releases them during registration failure or device removal.
///
/// # Invariants
///
/// The descriptor slice comes from a static [`Statistics`] table and preserves its invariants.
pub struct StatisticsDescription {
    descriptors: &'static [bindings::rdma_stat_desc],
    lifespan_ms: u32,
}

impl StatisticsDescription {
    // Keep calls to the RDMA core in the provider's crate for modular providers.
    #[inline]
    pub(super) fn allocate<T>(self) -> *mut bindings::rdma_hw_stats {
        let _provider = core::marker::PhantomData::<T>;
        // SAFETY: Construction guarantees a nonempty table with an int-sized length. The
        // immutable descriptors and names are static; the core owns the returned allocation.
        unsafe {
            bindings::rdma_alloc_hw_stats_struct(
                self.descriptors.as_ptr(),
                self.descriptors.len() as i32,
                self.lifespan_ms as usize,
            )
        }
    }
}
