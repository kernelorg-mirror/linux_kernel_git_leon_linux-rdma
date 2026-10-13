// SPDX-License-Identifier: GPL-2.0

//! Network namespace borrows, active references and allocation references.

use crate::{
    bindings,
    types::Opaque, //
};
use core::{
    ops::Deref,
    ptr::NonNull, //
};

pub mod registration;

/// A borrowed network namespace whose allocation remains live.
///
/// The borrow alone need not exclude namespace cleanup. Acquiring an active reference fails
/// once its active reference count reaches zero.
///
/// # Invariants
///
/// The opaque C namespace is initialized and retained throughout every borrow.
#[repr(transparent)]
pub struct Namespace(Opaque<bindings::net>);

// SAFETY: Shared methods expose only opaque storage and synchronized core reference operations.
unsafe impl Send for Namespace {}
// SAFETY: The networking core serializes reference acquisition against namespace cleanup.
unsafe impl Sync for Namespace {}

impl Namespace {
    /// Borrows the permanently allocated initial network namespace.
    #[inline]
    pub fn initial() -> &'static Self {
        // SAFETY: init_net remains initialized and allocated throughout kernel execution.
        unsafe { Self::from_raw(&raw mut bindings::init_net) }
    }

    /// Borrows a namespace allocation retained by the caller.
    ///
    /// # Safety
    ///
    /// `net` must identify a namespace that has completed its per-namespace initialization,
    /// kept allocated for `'a`. The lifetime protection must permit attempting an active
    /// reference with `maybe_get_net`.
    #[inline]
    pub unsafe fn from_raw<'a>(net: *mut bindings::net) -> &'a Self {
        // SAFETY: The caller establishes the invariant; the wrapper is transparent and opaque.
        unsafe { &*net.cast() }
    }

    /// Acquires an active reference unless namespace cleanup has already become eligible.
    #[inline]
    pub fn try_to_ref(&self) -> Option<NamespaceRef> {
        // SAFETY: This borrow retains the initialized counter. The core operation never
        // resurrects a namespace whose active references have drained.
        let net = unsafe { bindings::maybe_get_net(self.as_raw()) };
        // INVARIANT: A non-null result transfers one active reference to this owner.
        NonNull::new(net.cast()).map(|inner| NamespaceRef { inner })
    }

    /// Returns the opaque pointer for C interoperability without transferring ownership.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::net {
        self.0.get()
    }

    /// Returns the immutable core namespace identifier, suitable for cache identity checks.
    #[inline]
    pub fn cookie(&self) -> u64 {
        // SAFETY: Namespace setup assigns the cookie before publication and never changes it.
        unsafe { (*self.as_raw()).net_cookie }
    }
}

/// An active core reference which postpones network namespace cleanup.
///
/// # Invariants
///
/// `inner` names an initialized namespace and owns one active reference released by Drop.
pub struct NamespaceRef {
    inner: NonNull<Namespace>,
}

impl NamespaceRef {
    /// Retains the namespace allocation without postponing namespace cleanup.
    ///
    /// This is suitable for records owned by a namespace subsystem: an active reference in
    /// such a record could prevent the cleanup responsible for destroying that same record.
    #[inline]
    pub fn allocation_ref(&self) -> NamespaceAllocationRef {
        // SAFETY: The active reference excludes cleanup, retaining the base passive reference.
        unsafe { bindings::net_namespace_get_passive(self.as_raw()) };
        // INVARIANT: The new owner holds the additional passive reference.
        NamespaceAllocationRef { inner: self.inner }
    }
}

// SAFETY: Active references may be released on any thread; put_net defers cleanup as needed.
unsafe impl Send for NamespaceRef {}
// SAFETY: Shared access exposes only an opaque namespace and atomic core references.
unsafe impl Sync for NamespaceRef {}

impl Deref for NamespaceRef {
    type Target = Namespace;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: The owned active reference retains the namespace throughout this borrow.
        unsafe { self.inner.as_ref() }
    }
}

impl Clone for NamespaceRef {
    #[inline]
    fn clone(&self) -> Self {
        // SAFETY: This owner already retains a nonzero active reference.
        unsafe { bindings::get_net(self.as_raw()) };
        // INVARIANT: get_net acquired the additional reference transferred to this clone.
        Self { inner: self.inner }
    }
}

impl Drop for NamespaceRef {
    fn drop(&mut self) {
        // SAFETY: This handle transfers exactly one active reference; no access follows put.
        unsafe { bindings::put_net(self.as_raw()) };
    }
}

/// Retains only the namespace allocation, allowing its subsystem cleanup to run.
///
/// This reference does not retain per-namespace storage or make routing operations available.
/// Use [`Namespace::try_to_ref`] to acquire an active reference before accessing live namespace
/// resources. That acquisition fails once cleanup becomes eligible.
///
/// # Invariants
///
/// `inner` identifies an initialized namespace allocation and owns one passive core reference.
pub struct NamespaceAllocationRef {
    inner: NonNull<Namespace>,
}

// SAFETY: The core permits passive reference acquisition and release on any CPU.
unsafe impl Send for NamespaceAllocationRef {}
// SAFETY: Shared access only exposes the opaque allocation and synchronized reference operations.
unsafe impl Sync for NamespaceAllocationRef {}

impl Deref for NamespaceAllocationRef {
    type Target = Namespace;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: The owned passive reference retains the allocation for this borrow.
        unsafe { self.inner.as_ref() }
    }
}

impl Clone for NamespaceAllocationRef {
    #[inline]
    fn clone(&self) -> Self {
        // SAFETY: This owner retains a nonzero passive reference throughout acquisition.
        unsafe { bindings::net_namespace_get_passive(self.as_raw()) };
        // INVARIANT: The clone owns the newly acquired passive reference.
        Self { inner: self.inner }
    }
}

impl Drop for NamespaceAllocationRef {
    fn drop(&mut self) {
        let net = self.inner.as_ptr().cast();
        // SAFETY: Release exactly the owned passive reference. The core defers final allocation
        // reclamation as needed; no namespace borrow or access spans or follows this release.
        unsafe { bindings::net_namespace_put_passive(net) };
    }
}
