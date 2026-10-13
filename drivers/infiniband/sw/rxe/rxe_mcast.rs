// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Native multicast membership ownership and serialized filter transactions.

#![forbid(unsafe_code)]

use super::{
    rxe_param as params,
    rxe_qp::QpRef, //
};
use kernel::{
    prelude::*,
    rbtree::{
        RBTree,
        RBTreeNode, //
    },
    sync::{
        Mutex,
        SpinLockIrq, //
    }, //
};

/// Maps IPv4-mapped and IPv6 multicast GIDs to their Ethernet filter addresses.
pub(crate) fn address(gid: [u8; 16]) -> [u8; 6] {
    if gid[..10] == [0; 10] && gid[10..12] == [0xff; 2] {
        [0x01, 0x00, 0x5e, gid[13] & 0x7f, gid[14], gid[15]]
    } else {
        [0x33, 0x33, gid[12], gid[13], gid[14], gid[15]]
    }
}

struct Group {
    members: RBTree<u32, QpRef>,
    count: u32,
    filter: bool,
}

struct State {
    groups: RBTree<[u8; 16], Group>,
    group_count: u32,
    attachments: u32,
}

impl Drop for State {
    fn drop(&mut self) {
        kernel::warn_on!(self.group_count != 0 || self.attachments != 0);
    }
}

/// Owns membership references while packets visit the published group under its IRQ-safe lock.
///
/// The control mutex serializes sleepable attach, detach and filter shutdown transactions.
/// Control transactions allocate and program filters without holding the state lock.
#[pin_data]
pub(crate) struct Groups {
    #[pin]
    enabled: Mutex<bool>,
    #[pin]
    state: SpinLockIrq<State>,
}

impl Groups {
    pub(crate) fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            enabled <- kernel::new_mutex!(true),
            state <- kernel::new_spinlock_irq!(State {
                groups: RBTree::new(),
                group_count: 0,
                attachments: 0,
            }),
        })
    }

    /// Publishes one attachment, rejecting duplicates before the core counts a success.
    pub(crate) fn attach(
        &self,
        gid: [u8; 16],
        qp: QpRef,
        program: impl FnOnce() -> Result,
    ) -> Result {
        let enabled = self.enabled.lock();
        if !*enabled {
            return Err(ENODEV);
        }
        let index = qp.index();
        let new_group = {
            let state = self.state.lock();
            if let Some(group) = state.groups.get(&gid) {
                if group.members.get(&index).is_some() {
                    return Err(EEXIST);
                }
                if group.count == params::RXE_MAX_MCAST_QP_ATTACH {
                    return Err(ENOMEM);
                }
            } else if state.group_count == params::RXE_MAX_MCAST_GRP {
                return Err(ENOMEM);
            }
            if state.attachments == params::RXE_MAX_TOT_MCAST_QP_ATTACH {
                return Err(ENOMEM);
            }
            state.groups.get(&gid).is_none()
        };
        let member = RBTreeNode::new(index, qp, GFP_KERNEL)?;
        if new_group {
            let mut group = Group {
                members: RBTree::new(),
                count: 1,
                filter: true,
            };
            group.members.insert(member);
            let node = RBTreeNode::new(gid, group, GFP_KERNEL)?;
            // Nothing can fail after acquiring the filter. The control guard prevents an
            // overlapping attach, last-member detach or netdevice shutdown from intervening.
            program()?;
            let mut state = self.state.lock();
            state.groups.insert(node);
            state.group_count += 1;
            state.attachments += 1;
        } else {
            let mut state = self.state.lock();
            let group = state.groups.get_mut(&gid).unwrap();
            group.members.insert(member);
            group.count += 1;
            state.attachments += 1;
        }
        Ok(())
    }

    /// Removes one membership and deletes the filter when the last member leaves.
    pub(crate) fn detach(&self, gid: [u8; 16], index: u32, remove: impl FnOnce()) -> Result {
        let _control = self.enabled.lock();
        let (member, removed, filter) = {
            let mut state = self.state.lock();
            let group = state.groups.get_mut(&gid).ok_or(EINVAL)?;
            let member = group.members.remove_node(&index).ok_or(EINVAL)?;
            group.count -= 1;
            let last = group.count == 0;
            let filter = last && group.filter;
            state.attachments -= 1;
            let removed = if last {
                state.group_count -= 1;
                state.groups.remove_node(&gid)
            } else {
                None
            };
            (member, removed, filter)
        };
        drop(member);
        drop(removed);
        if filter {
            remove();
        }
        Ok(())
    }

    /// Visits retained QP indices; the callback may stop fan-out and must not sleep.
    ///
    /// The final-member flag allows the caller to transfer the original packet instead of
    /// allocating one more clone. The registry lock remains held throughout each visit;
    /// callbacks must not reenter this registry.
    pub(crate) fn visit(&self, gid: [u8; 16], mut visit: impl FnMut(u32, bool) -> bool) {
        let state = self.state.lock();
        if let Some(group) = state.groups.get(&gid) {
            let mut members = group.members.keys().peekable();
            while let Some(index) = members.next() {
                if !visit(*index, members.peek().is_none()) {
                    break;
                }
            }
        }
    }

    /// Closes admission and removes filters before the netdevice flushes its multicast list.
    ///
    /// Memberships remain retained until the core detaches them. Later detach must not delete
    /// an address which a different namespace may have subscribed after the network flush.
    /// The callback runs without the state lock and must not acquire RTNL.
    pub(crate) fn disable(&self, mut remove: impl FnMut([u8; 16])) {
        let mut enabled = self.enabled.lock();
        *enabled = false;
        let mut next = self
            .state
            .lock()
            .groups
            .cursor_front()
            .map(|cursor| *cursor.current().0);
        while let Some(gid) = next {
            let filter = {
                let mut state = self.state.lock();
                next = state
                    .groups
                    .cursor_lower_bound(&gid)
                    .and_then(|cursor| cursor.peek_next().map(|(key, _)| *key));
                let group = state.groups.get_mut(&gid).unwrap();
                core::mem::replace(&mut group.filter, false)
            };
            if filter {
                remove(gid);
            }
        }
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_multicast_address)]
mod address_tests {
    use super::*;

    #[test]
    fn ethernet_multicast_mapping() {
        let mut gid = [0; 16];
        gid[10..12].copy_from_slice(&[0xff; 2]);
        gid[12..].copy_from_slice(&[239, 129, 2, 3]);
        assert_eq!(address(gid), [0x01, 0x00, 0x5e, 1, 2, 3]);
        gid[0] = 0xff;
        assert_eq!(address(gid), [0x33, 0x33, 239, 129, 2, 3]);
    }
}
