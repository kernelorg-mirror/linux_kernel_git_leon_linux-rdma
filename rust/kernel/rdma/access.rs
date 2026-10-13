// SPDX-License-Identifier: GPL-2.0

//! RDMA memory access flags.

use crate::bindings;

crate::impl_flags!(
    /// A set of RDMA memory access flags, including optional extension bits.
    ///
    /// The generated complement and XOR operators are restricted to named flags. Use
    /// [`Self::remove`] and [`Self::toggle`] when retaining unknown extension bits.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct AccessFlags(u32);

    /// One RDMA memory access flag.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Access {
        /// Permit local writes.
        LocalWrite = bindings::ib_access_flags_IB_ACCESS_LOCAL_WRITE,
        /// Permit remote writes.
        RemoteWrite = bindings::ib_access_flags_IB_ACCESS_REMOTE_WRITE,
        /// Permit remote reads.
        RemoteRead = bindings::ib_access_flags_IB_ACCESS_REMOTE_READ,
        /// Permit remote atomic operations.
        RemoteAtomic = bindings::ib_access_flags_IB_ACCESS_REMOTE_ATOMIC,
        /// Permit binding a memory window.
        WindowBind = bindings::ib_access_flags_IB_ACCESS_MW_BIND,
        /// Interpret addresses relative to zero.
        ZeroBased = bindings::ib_access_flags_IB_ZERO_BASED,
        /// Fault user pages on demand.
        OnDemand = bindings::ib_access_flags_IB_ACCESS_ON_DEMAND,
        /// Require huge-page backing.
        HugeTlb = bindings::ib_access_flags_IB_ACCESS_HUGETLB,
        /// Permit relaxed ordering.
        RelaxedOrdering = bindings::ib_access_flags_IB_ACCESS_RELAXED_ORDERING,
        /// Permit remote flush to global visibility.
        FlushGlobal = bindings::ib_access_flags_IB_ACCESS_FLUSH_GLOBAL,
        /// Permit remote flush to persistent storage.
        FlushPersistent = bindings::ib_access_flags_IB_ACCESS_FLUSH_PERSISTENT,
    }
);

impl AccessFlags {
    /// Retains flags from a core callback, including unknown optional bits.
    ///
    /// Providers must separately validate which flags their operations support.
    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Removes the supplied bits, preserving every other bit including unknown extensions.
    #[inline]
    pub fn remove(&mut self, flags: impl Into<Self>) {
        self.0 &= !flags.into().0;
    }

    /// Toggles the supplied bits, preserving every other bit including unknown extensions.
    #[inline]
    pub fn toggle(&mut self, flags: impl Into<Self>) {
        self.0 ^= flags.into().0;
    }
}

#[cfg(CONFIG_RUST_RDMA_UMEM_KUNIT_TEST)]
#[macros::kunit_tests(rust_rdma_access)]
mod tests {
    use super::*;

    #[test]
    fn preserve_extension_bits() {
        let unknown = 1 << 31;
        let mut access = AccessFlags::from_bits(unknown) | Access::LocalWrite;
        access.toggle(Access::RemoteRead);
        access.remove(Access::LocalWrite);
        assert_eq!(u32::from(access), unknown | Access::RemoteRead as u32);
    }
}
