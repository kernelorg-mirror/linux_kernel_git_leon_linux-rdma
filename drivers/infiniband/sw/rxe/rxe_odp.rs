// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2022-2023 Fujitsu Ltd. All rights reserved.

//! Synchronous and asynchronous prefetch of owned ODP registrations.

#![forbid(unsafe_code)]

use crate::{
    rxe_device::DeviceData,
    rxe_mr::MrRef, //
};
use kernel::{
    prelude::*,
    rdma::{
        odp::Prefetch,
        Access,
        Advice,
        AdviceFlag,
        AdviceFlags,
        MemoryAdviceOperations,
        ScatterGather, //
    }, //
};

impl MemoryAdviceOperations for DeviceData {
    fn advise_memory(
        self: Pin<&Self>,
        domain: &super::rxe_pd::Domain,
        advice: Advice,
        flags: AdviceFlags,
        ranges: &[ScatterGather],
    ) -> Result {
        let mode = match advice {
            Advice::Prefetch => Prefetch::Read,
            Advice::PrefetchWrite => Prefetch::Write,
            Advice::PrefetchNoFault => Prefetch::Snapshot,
        };
        let access = if matches!(mode, Prefetch::Write) {
            Access::LocalWrite | Access::OnDemand
        } else {
            Access::OnDemand.into()
        };
        let fragments = ranges.iter().map(|range| {
            Ok(Fragment {
                address: range.address(),
                length: range.length() as usize,
                memory: self
                    .regions
                    .lookup(domain.index(), access, range.key())
                    .ok_or(EINVAL)?,
            })
        });
        advise(mode, flags.contains(AdviceFlag::Flush), fragments)
    }
}

pub(crate) struct Fragment {
    pub(crate) address: u64,
    pub(crate) length: usize,
    pub(crate) memory: MrRef,
}

impl Fragment {
    fn prefetch(&self, mode: Prefetch) -> Result {
        self.memory
            .access()
            .prefetch(self.address, self.length, mode)
    }
}

/// Validates all asynchronous lookups before handing backing-only references to core workers.
/// The temporary MR references are released before this returns, independently of fault progress.
pub(crate) fn advise(
    mode: Prefetch,
    sync: bool,
    fragments: impl ExactSizeIterator<Item = Result<Fragment>>,
) -> Result {
    if sync {
        for fragment in fragments {
            fragment?.prefetch(mode)?;
        }
        return Ok(());
    }
    let mut pending = KVVec::with_capacity(fragments.len(), GFP_KERNEL)?;
    for fragment in fragments {
        pending.push(fragment?, GFP_KERNEL)?;
    }
    for fragment in &pending {
        fragment
            .memory
            .access()
            .prefetch_async(fragment.address, fragment.length, mode)?;
    }
    Ok(())
}
