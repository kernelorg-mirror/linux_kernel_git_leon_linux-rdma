// SPDX-License-Identifier: GPL-2.0

//! Provider type identities for devices installed through the Rust adapter.

use crate::{
    bindings,
    prelude::*,
    rbtree::{
        RBTree,
        RBTreeNode, //
    },
    types::Opaque, //
};
use core::any::TypeId;

crate::sync::global_lock! {
    // SAFETY: Every access first completes the shared once initializer.
    unsafe(uninit) static PROVIDERS: SpinLockIrq<Option<RBTree<usize, TypeId>>> = None;
}

struct Initialization(Opaque<bindings::atomic_t>);

// SAFETY: The C helper accesses the initialization state only through native atomics.
unsafe impl Sync for Initialization {}

static PROVIDERS_INIT: Initialization =
    Initialization(Opaque::new(bindings::atomic_t { counter: 0 }));

extern "C" fn initialize() {
    // SAFETY: The shared atomic state permits exactly one initialization, including when
    // inline C helpers are emitted in more than one Rust object.
    unsafe { PROVIDERS.init() };
}

fn ensure_initialized() {
    // SAFETY: Every invocation supplies the same permanent atomic state and initializer,
    // which neither sleeps nor allocates. The helper also excludes same-CPU softirq reentry.
    unsafe { bindings::rust_rdma_init_provider_registry(PROVIDERS_INIT.0.get(), Some(initialize)) };
}

/// Allocates a type record before installation changes the core allocation.
pub(super) fn prepare<T: super::DeviceOperations>(
    device: *mut bindings::ib_device,
) -> Result<RBTreeNode<usize, TypeId>> {
    RBTreeNode::new(device as usize, TypeId::of::<T>(), GFP_KERNEL)
}

/// Publishes a record after its provider owner and operations have been installed.
pub(super) fn insert(node: RBTreeNode<usize, TypeId>) {
    ensure_initialized();
    let previous = PROVIDERS
        .lock()
        .get_or_insert_with(RBTree::new)
        .insert(node);
    // Device installation exclusively owns an unpublished allocation, so no entry is replaced.
    drop(previous);
}

/// Removes the identity before releasing its provider owner at final device deallocation.
pub(super) fn remove(device: *mut bindings::ib_device) {
    ensure_initialized();
    let node = PROVIDERS
        .lock()
        .as_mut()
        .and_then(|providers| providers.remove_node(&(device as usize)));
    // Release the node after restoring interrupts. Records own no device references.
    drop(node);
}
