// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Native address-handle ownership and synchronized transport snapshots.

#![forbid(unsafe_code)]

use super::{
    rxe_av::AddressVector,
    rxe_uapi::{
        self,
        UserData, //
    }, //
};
use kernel::{
    alloc::Flags,
    id_pool::IdPool,
    prelude::*,
    rbtree::{
        RBTree,
        RBTreeNodeReservation, //
    },
    sync::SpinLockIrq, //
};

/// Core-owned identity; zero `number` selects the legacy userspace address-vector ABI.
pub(crate) struct Handle {
    index: u32,
    number: u32,
}

impl Handle {
    pub(crate) fn number(&self) -> u32 {
        self.number
    }
}

struct Entry {
    pd: u32,
    vector: AddressVector,
    published: bool,
}

struct State {
    entries: RBTree<u32, Entry>,
    ids: IdPool,
    next: u32,
    count: u32,
    limit: u32,
}

impl State {
    fn new(limit: u32) -> Result<Self> {
        Ok(Self {
            entries: RBTree::new(),
            // The full AH range needs 4 KiB. Allocate it during device initialization so
            // atomic creation never has to resize the bitmap under the registry lock.
            ids: IdPool::with_capacity(limit as usize + 1, GFP_KERNEL)?,
            next: 1,
            count: 0,
            limit,
        })
    }

    fn allocate(&mut self) -> Result<u32> {
        if self.count == self.limit {
            return Err(EINVAL);
        }
        let candidate = self
            .ids
            .find_unused_id(self.next as usize)
            .filter(|id| id.as_u32() <= self.limit)
            .map(|id| id.acquire() as u32);
        let index = match candidate {
            Some(index) => index,
            None => self
                .ids
                .find_unused_id(1)
                .filter(|id| id.as_u32() <= self.limit)
                .ok_or(ENOSPC)?
                .acquire() as u32,
        };
        self.next = if index == self.limit { 1 } else { index + 1 };
        self.count += 1;
        Ok(index)
    }
}

impl Drop for State {
    fn drop(&mut self) {
        kernel::warn_on!(self.count != 0);
    }
}

/// Owns all address data; readers copy values under the IRQ-safe lock.
///
/// No entry reference leaves the lock. Removing an entry therefore drains every reader
/// before releasing its storage, including when destruction cannot sleep.
#[pin_data]
pub(crate) struct Addresses {
    #[pin]
    state: SpinLockIrq<State>,
}

impl Addresses {
    pub(crate) fn new(limit: u32) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            state <- kernel::new_spinlock_irq!(State::new(limit)?),
        })
    }

    fn reserve(&self, pd: u32, vector: AddressVector, flags: Flags) -> Result<KBox<Handle>> {
        let mut handle = KBox::new(
            Handle {
                index: 0,
                number: 0,
            },
            flags,
        )?;
        let node = RBTreeNodeReservation::new(flags)?;
        let mut state = self.state.lock();
        let index = state.allocate()?;
        state.entries.insert(node.into_node(
            index,
            Entry {
                pd,
                vector,
                published: false,
            },
        ));
        handle.index = index;
        handle.number = index;
        Ok(handle)
    }

    fn publish(&self, handle: &Handle) {
        self.state
            .lock()
            .entries
            .get_mut(&handle.index)
            .unwrap()
            .published = true;
    }

    pub(crate) fn create(
        &self,
        pd: u32,
        vector: AddressVector,
        flags: Flags,
        data: Option<UserData<'_>>,
    ) -> Result<KBox<Handle>> {
        let mut handle = self.reserve(pd, vector, flags)?;
        // A guessed ID must not expose an entry before the userspace response succeeds.
        handle.number = match rxe_uapi::create_ah(data, handle.index) {
            Ok(number) => number,
            Err(error) => {
                self.release(handle);
                return Err(error);
            }
        };
        self.publish(&handle);
        Ok(handle)
    }

    pub(crate) fn modify(&self, handle: &Handle, vector: AddressVector) {
        self.state
            .lock()
            .entries
            .get_mut(&handle.index)
            .unwrap()
            .vector = vector;
    }

    pub(crate) fn query(&self, handle: &Handle) -> AddressVector {
        self.state.lock().entries.get(&handle.index).unwrap().vector
    }

    pub(crate) fn lookup(&self, pd: u32, number: u32) -> Option<AddressVector> {
        let state = self.state.lock();
        let entry = state.entries.get(&number)?;
        (entry.published && entry.pd == pd).then_some(entry.vector)
    }

    pub(crate) fn release(&self, handle: KBox<Handle>) {
        let removed = {
            let mut state = self.state.lock();
            let removed = state.entries.remove_node(&handle.index).unwrap();
            state.ids.release_id(handle.index as usize);
            state.count -= 1;
            removed
        };
        // Readers retained only copied bytes, so both allocations can be freed immediately.
        drop(removed);
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_ah)]
mod tests {
    use super::*;

    #[test]
    fn abandoned_reservation() -> Result {
        let addresses = KBox::pin_init(Addresses::new(1), GFP_KERNEL)?;
        let pending = addresses.reserve(7, AddressVector::zeroed(), GFP_KERNEL)?;
        assert!(addresses.lookup(7, 1).is_none());
        addresses.release(pending);
        let handle = addresses.create(8, AddressVector::zeroed(), GFP_KERNEL, None)?;
        assert_eq!(handle.number(), 1);
        assert!(addresses.lookup(7, 1).is_none());
        assert!(addresses.lookup(8, 1).is_some());
        addresses.release(handle);
        Ok(())
    }

    #[test]
    fn publication_domain_and_reuse() -> Result {
        let addresses = KBox::pin_init(Addresses::new(2), GFP_KERNEL)?;
        let mut vector = AddressVector::zeroed();
        vector.port_num = 1;
        let first = addresses.reserve(7, vector, GFP_KERNEL)?;
        assert_eq!(first.number(), 1);
        assert!(addresses.lookup(7, first.number()).is_none());
        addresses.publish(&first);
        assert!(addresses.lookup(8, first.number()).is_none());
        assert_eq!(addresses.lookup(7, first.number()).unwrap().port_num, 1);
        let second = match addresses.create(8, vector, GFP_KERNEL, None) {
            Ok(handle) => handle,
            Err(error) => {
                addresses.release(first);
                return Err(error);
            }
        };
        assert_eq!(second.number(), 2);
        assert!(matches!(
            addresses.create(7, vector, GFP_KERNEL, None),
            Err(EINVAL)
        ));
        let snapshot = addresses.query(&first);
        vector.port_num = 2;
        addresses.modify(&first, vector);
        assert_eq!(snapshot.port_num, 1);
        assert_eq!(addresses.query(&first).port_num, 2);
        addresses.release(first);
        assert!(addresses.lookup(7, 1).is_none());
        let reused = match addresses.create(8, vector, GFP_KERNEL, None) {
            Ok(handle) => handle,
            Err(error) => {
                addresses.release(second);
                return Err(error);
            }
        };
        assert_eq!(reused.number(), 1);
        assert!(addresses.lookup(7, 1).is_none());
        assert_eq!(addresses.lookup(8, 1).unwrap().port_num, 2);
        addresses.release(second);
        addresses.release(reused);
        Ok(())
    }
}
