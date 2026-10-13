// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2020 Hewlett Packard Enterprise, Inc. All rights reserved.

//! Native memory-window ownership and synchronized binding lookup.

#![forbid(unsafe_code)]

use super::{
    rxe_id::Identities,
    rxe_mr::MrRef,
    rxe_mw_state::{
        Bind,
        Window,
        WindowState, //
    },
    rxe_param::{
        RXE_MAX_MW,
        RXE_MAX_MW_INDEX,
        RXE_MIN_MW_INDEX, //
    },
    rxe_qp::QpRef, //
};
use kernel::{
    prelude::*,
    rbtree::{
        RBTree,
        RBTreeNodeReservation, //
    },
    rdma::{
        AccessFlags,
        MemoryWindowType,
        WindowCreation, //
    },
    sync::{
        Arc,
        Mutex,
        SpinLockIrq, //
    }, //
};

/// Immutable identity retained by the core until successful window release.
pub(crate) struct Handle {
    index: u32,
}

/// Owns every window and serializes binding, invalidation, snapshots and removal.
///
/// The registry lock only protects membership and reference acquisition. Per-window mutexes
/// serialize bindings outside that lock, and a separate access mutex drains revoked accesses.
/// Identity allocation may sleep. Released IDs become reusable after revocation.
#[pin_data]
pub(crate) struct Windows {
    #[pin]
    identities: Mutex<Identities>,
    #[pin]
    entries: SpinLockIrq<RBTree<u32, Arc<Mutex<WindowState>>>>,
}

impl Windows {
    pub(crate) fn new() -> impl PinInit<Self, Error> {
        Self::with_range(RXE_MIN_MW_INDEX, RXE_MAX_MW_INDEX, RXE_MAX_MW)
    }

    fn with_range(first: u32, last: u32, limit: u32) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            identities <- kernel::new_mutex!(Identities::new(first, last, limit)),
            entries <- kernel::new_spinlock_irq!(RBTree::new()),
        })
    }

    pub(crate) fn create(
        &self,
        pd: u32,
        kind: MemoryWindowType,
    ) -> Result<WindowCreation<KBox<Handle>>> {
        let mut owner = KBox::new(Handle { index: 0 }, GFP_KERNEL)?;
        let node = RBTreeNodeReservation::new(GFP_KERNEL)?;
        let window = Arc::pin_init(kernel::new_mutex!(WindowState::new(kind, pd)?), GFP_KERNEL)?;
        let suffix = super::rxe_mr::rxe_get_next_key(u32::MAX);
        // All fallible allocations precede reservation; publication cannot abandon an ID.
        let index = self.identities.lock().allocate()?;
        let key = (index << 8) | u32::from(suffix);
        owner.index = index;
        window.lock().initialize(key);
        self.entries.lock().insert(node.into_node(index, window));
        Ok(WindowCreation { owner, key })
    }

    pub(crate) fn bind(
        &self,
        qp: QpRef,
        memory: Option<MrRef>,
        request: super::rxe_send::Window,
    ) -> Result {
        self.get(request.window_key).ok_or(EINVAL)?.lock().bind(
            qp,
            memory,
            Bind {
                window_key: request.window_key,
                region_key: request.region_key,
                new_key: request.new_key,
                access: AccessFlags::from_bits(request.access),
                address: request.address,
                length: request.length,
            },
        )
    }

    fn get(&self, key: u32) -> Option<Arc<Mutex<WindowState>>> {
        self.entries.lock().get(&(key >> 8)).cloned()
    }

    pub(crate) fn invalidate(&self, pd: u32, key: u32) -> Result {
        self.get(key).ok_or(EINVAL)?.lock().invalidate(pd, key)
    }

    pub(crate) fn lookup(&self, pd: u32, qp: u32, key: u32, access: AccessFlags) -> Option<Window> {
        self.get(key)?.lock().lookup(pd, qp, key, access)
    }

    /// Releases type-2 bindings after the QP's send task has permanently stopped.
    pub(crate) fn unbind_qp(&self, qp: u32) {
        let mut next = 0;
        loop {
            let mut entries = self.entries.lock();
            let Some(mut cursor) = entries.cursor_lower_bound_mut(&next) else {
                break;
            };
            let (index, window) = cursor.current_mut();
            next = *index + 1;
            let window = window.clone();
            drop(entries);
            window.lock().unbind_qp(qp);
            // QP send retirement excludes new bindings. Other windows remain accessible
            // while this window waits for already admitted memory operations.
        }
    }

    pub(crate) fn release(&self, owner: KBox<Handle>) {
        let removed = self.entries.lock().remove_node(&owner.index).unwrap();
        // Revoke access outside the registry lock before allowing this identity to be reused.
        let (_, window) = removed.to_key_value();
        window.lock().release();
        drop(window);
        self.identities.lock().release(owner.index);
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_mw)]
mod tests {
    use super::*;

    #[test]
    fn grow_limit_wrap_and_remove() -> Result {
        let first = RXE_MIN_MW_INDEX;
        let windows = KBox::pin_init(Windows::with_range(first, first + 66, 66), GFP_KERNEL)?;
        let mut owners = KVec::with_capacity(66, GFP_KERNEL)?;
        for offset in 0..66 {
            let created = match windows.create(7, MemoryWindowType::Type2) {
                Ok(created) => created,
                Err(error) => {
                    while let Some(owner) = owners.pop() {
                        windows.release(owner);
                    }
                    return Err(error);
                }
            };
            assert_eq!(created.key >> 8, first + offset);
            assert!(windows
                .lookup(7, 1, created.key, AccessFlags::default())
                .is_none());
            assert!(matches!(windows.invalidate(7, created.key), Err(EINVAL)));
            owners.push(created.owner, GFP_KERNEL)?;
        }
        assert!(matches!(
            windows.create(7, MemoryWindowType::Type1),
            Err(EINVAL)
        ));
        windows.release(owners.pop().unwrap());
        let final_id = windows.create(7, MemoryWindowType::Type1)?;
        assert_eq!(final_id.key >> 8, first + 66);
        windows.release(final_id.owner);
        while let Some(owner) = owners.pop() {
            windows.release(owner);
        }
        assert!(windows.entries.lock().is_empty());
        let wrapped = windows.create(8, MemoryWindowType::Type2)?;
        assert_eq!(wrapped.key >> 8, first);
        windows.release(wrapped.owner);
        assert!(windows.entries.lock().is_empty());
        Ok(())
    }
}
