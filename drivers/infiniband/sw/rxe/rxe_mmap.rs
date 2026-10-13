// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Context-authorized, one-shot mappings with independent page ownership.

#![forbid(unsafe_code)]

use super::{
    rxe_context::Context,
    rxe_uapi::MappingDescriptor,
    rxe_version::Version, //
};
use kernel::{
    mm::{
        shared::{
            SharedPages,
            SharedVmalloc, //
        },
        virt::VmaNew, //
    },
    page::PAGE_SIZE,
    prelude::*,
    rbtree::{
        RBTree,
        RBTreeNode,
        RBTreeNodeReservation, //
    },
    sync::SpinLockIrq, //
};

struct Entry {
    context: Version,
    pages: SharedPages,
}

struct State {
    next: u64,
    entries: RBTree<u64, Entry>,
}

impl Drop for State {
    fn drop(&mut self) {
        kernel::warn_on!(!self.entries.is_empty());
    }
}

/// A queue's cancellation token; established mappings have already consumed its entry.
pub(super) struct Mapping {
    offset: u64,
}

/// An unpublished descriptor owning all allocations required for publication.
pub(super) struct Pending {
    descriptor: MappingDescriptor,
    node: RBTreeNode<u64, Entry>,
}

impl Pending {
    pub(super) fn descriptor(&self) -> &MappingDescriptor {
        &self.descriptor
    }
}

/// Owns pending mappings independently of queue storage and in-flight mmap calls.
///
/// The registry lock covers lookup, authorization and removal. Mapping removes its entry
/// before installing pages, so neither queue teardown nor resize can release those pages.
/// No allocation, userspace copy, mapping or page release runs under the registry lock.
#[pin_data]
pub(crate) struct Mappings {
    #[pin]
    state: SpinLockIrq<State>,
}

impl Mappings {
    pub(crate) fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            state <- kernel::new_spinlock_irq!(State {
                next: SharedVmalloc::alignment() as u64,
                entries: RBTree::new(),
            }),
        })
    }

    pub(super) fn prepare(&self, context: &Context, memory: &SharedVmalloc) -> Result<Pending> {
        let size = u32::try_from(memory.len())?;
        let pages = memory.retain_pages()?;
        let node = RBTreeNodeReservation::new(GFP_KERNEL)?;
        let alignment = SharedVmalloc::alignment() as u64;
        let span = (u64::from(size) + alignment - 1) & !(alignment - 1);
        let offset = {
            let mut state = self.state.lock();
            let offset = state.next;
            // Never wrap an offset onto an older pending descriptor or cancellation token.
            state.next = offset.checked_add(span).ok_or(EOVERFLOW)?;
            offset
        };
        Ok(Pending {
            descriptor: MappingDescriptor { offset, size },
            node: node.into_node(
                offset,
                Entry {
                    context: context.identity(),
                    pages,
                },
            ),
        })
    }

    /// Publishes after the complete userspace descriptor has been written successfully.
    pub(super) fn publish(&self, pending: Pending) -> Mapping {
        let offset = pending.descriptor.offset;
        self.state.lock().entries.insert(pending.node);
        Mapping { offset }
    }

    /// Cancels a descriptor which has not yet been acquired by mmap.
    pub(super) fn cancel(&self, mapping: Mapping) {
        let removed = self.state.lock().entries.remove_node(&mapping.offset);
        drop(removed);
    }

    fn take(&self, context: &Context, offset: u64, size: usize) -> Result<SharedPages> {
        let removed = {
            let mut state = self.state.lock();
            let entry = state.entries.get(&offset).ok_or(EINVAL)?;
            if entry.context != context.identity() || size > entry.pages.len() * PAGE_SIZE {
                return Err(EINVAL);
            }
            state.entries.remove_node(&offset).unwrap()
        };
        Ok(removed.to_key_value().1.pages)
    }

    pub(crate) fn map(&self, context: &Context, vma: &VmaNew) -> Result {
        let offset = vma
            .file_offset_pages()
            .checked_mul(PAGE_SIZE)
            .ok_or(EINVAL)?;
        let pages = self.take(context, offset as u64, vma.end() - vma.start())?;
        vma.map_shared_pages(&pages, 0)
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_mmap)]
mod tests {
    use super::*;

    #[test]
    fn authorization_size_and_one_shot() -> Result {
        let mappings = KBox::pin_init(Mappings::new(), GFP_KERNEL)?;
        let first = Context::new()?;
        let other = Context::new()?;
        let memory = SharedVmalloc::new(2 * PAGE_SIZE)?;
        let pending = mappings.prepare(&first, &memory)?;
        let offset = pending.descriptor().offset;
        assert!(offset >= PAGE_SIZE as u64);
        assert_eq!(offset % SharedVmalloc::alignment() as u64, 0);
        assert!(matches!(
            mappings.take(&first, offset, PAGE_SIZE),
            Err(EINVAL)
        ));
        let mapping = mappings.publish(pending);
        assert!(matches!(
            mappings.take(&other, offset, PAGE_SIZE),
            Err(EINVAL)
        ));
        assert!(matches!(
            mappings.take(&first, offset, 3 * PAGE_SIZE),
            Err(EINVAL)
        ));
        // Queue storage may disappear before mmap takes its independently retained pages.
        drop(memory);
        let pages = mappings.take(&first, offset, PAGE_SIZE)?;
        assert_eq!(pages.len(), 2);
        assert!(matches!(
            mappings.take(&first, offset, PAGE_SIZE),
            Err(EINVAL)
        ));
        mappings.cancel(mapping);
        assert_eq!(pages.len(), 2);
        drop(pages);
        Ok(())
    }

    #[test]
    fn cancellation_abandonment_and_exhaustion() -> Result {
        let mappings = KBox::pin_init(Mappings::new(), GFP_KERNEL)?;
        let context = Context::new()?;
        let memory = SharedVmalloc::new(PAGE_SIZE)?;
        let abandoned = mappings.prepare(&context, &memory)?;
        let old_offset = abandoned.descriptor().offset;
        drop(abandoned);
        assert!(mappings.state.lock().entries.is_empty());
        let pending = mappings.prepare(&context, &memory)?;
        let offset = pending.descriptor().offset;
        assert!(offset > old_offset);
        let mapping = mappings.publish(pending);
        mappings.cancel(mapping);
        assert!(matches!(
            mappings.take(&context, offset, PAGE_SIZE),
            Err(EINVAL)
        ));
        mappings.state.lock().next = u64::MAX - SharedVmalloc::alignment() as u64 + 1;
        assert!(matches!(
            mappings.prepare(&context, &memory),
            Err(EOVERFLOW)
        ));
        assert!(mappings.state.lock().entries.is_empty());
        Ok(())
    }
}
