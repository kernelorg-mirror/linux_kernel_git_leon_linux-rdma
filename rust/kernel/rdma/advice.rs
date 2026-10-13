// SPDX-License-Identifier: GPL-2.0

//! Bounded memory-advice callbacks for RDMA providers.

use super::{
    Operations,
    ProtectionDomainOperations,
    ProtectionDomains,
    ScatterGather, //
};
use crate::{
    bindings,
    prelude::*,
    types::ForeignOwnable, //
};
use core::marker::PhantomData;

/// The requested treatment of the supplied registration ranges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Advice {
    /// Prefetch pages for read access, faulting them in if necessary.
    Prefetch,
    /// Prefetch pages for write access, faulting them in if necessary.
    PrefetchWrite,
    /// Prefetch only pages already present, without faulting them in.
    PrefetchNoFault,
}

crate::impl_flags!(
    /// Memory-advice flags, including unknown bits for provider validation.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct AdviceFlags(u32);

    /// One memory-advice flag.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AdviceFlag {
        /// Complete the requested operation before returning.
        Flush = bindings::ib_uverbs_advise_mr_flag_IB_UVERBS_ADVISE_MR_FLAG_FLUSH,
    }
);

/// Memory advice implemented by the device's pinned native data.
pub trait MemoryAdviceOperations: ProtectionDomainOperations {
    /// Handles stable descriptors in the caller's sleepable context.
    ///
    /// The core retains the device and domain for this call. Descriptors confer no access
    /// rights or ownership of registered memory. The provider must validate them and retain
    /// any registrations needed by asynchronous work before returning.
    fn advise_memory(
        self: Pin<&Self>,
        domain: <Self::Domain as ForeignOwnable>::Borrowed<'_>,
        advice: Advice,
        flags: AdviceFlags,
        ranges: &[ScatterGather],
    ) -> Result;
}

/// Installs the core memory-advice callback for a native provider.
pub struct MemoryAdvice<T: MemoryAdviceOperations>(PhantomData<T>);

impl<T: MemoryAdviceOperations> MemoryAdvice<T> {
    /// Installs advice handling before publishing a device.
    ///
    /// # Safety
    ///
    /// `device` must be exclusively owned and unpublished, with `Operations<T>` and
    /// `ProtectionDomains<T>` installed. Its `advise_mr` slot must be unused and remain
    /// exclusively managed by this adapter. Core or kernel callers must retain the device,
    /// domain and a stable initialized descriptor array throughout each callback.
    #[inline]
    pub unsafe fn install(device: *mut bindings::ib_device) {
        // SAFETY: The caller owns the unpublished device and reserves this callback slot.
        unsafe { (*device).ops.advise_mr = Some(Self::advise) };
    }

    /// # Safety
    ///
    /// The caller must retain the installed domain/device and stable initialized array.
    /// ScatterGather checks the slice bounds and accepts a null array for a zero count. The
    /// returned slice only borrows descriptors, never the memory they describe.
    unsafe extern "C" fn advise(
        domain: *mut bindings::ib_pd,
        advice: bindings::ib_uverbs_advise_mr_advice,
        flags: u32,
        ranges: *mut bindings::ib_sge,
        count: u32,
        _attributes: *mut bindings::uverbs_attr_bundle,
    ) -> c_int {
        let advice = match advice {
            bindings::ib_uverbs_advise_mr_advice_IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH => {
                Advice::Prefetch
            }
            bindings::ib_uverbs_advise_mr_advice_IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE => {
                Advice::PrefetchWrite
            }
            bindings::ib_uverbs_advise_mr_advice_IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_NO_FAULT => {
                Advice::PrefetchNoFault
            }
            _ => return EOPNOTSUPP.to_errno(),
        };
        let Ok(count) = c_int::try_from(count) else {
            return EINVAL.to_errno();
        };
        // SAFETY: The core retains the installed domain/device and stable initialized array.
        // ScatterGather checks the slice bounds and accepts a null array for a zero count.
        // The returned slice only borrows descriptors, never the memory they describe.
        unsafe {
            let ranges = match ScatterGather::from_raw(ranges, count) {
                Ok(ranges) => ranges,
                Err(error) => return error.to_errno(),
            };
            Operations::<T>::data((*domain).device)
                .advise_memory(
                    ProtectionDomains::<T>::data(domain),
                    advice,
                    AdviceFlags(flags),
                    ranges,
                )
                .map_or_else(Error::to_errno, |()| 0)
        }
    }
}
