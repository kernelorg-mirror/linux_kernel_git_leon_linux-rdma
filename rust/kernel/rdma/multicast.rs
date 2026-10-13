// SPDX-License-Identifier: GPL-2.0

//! Multicast membership callbacks for native queue-pair providers.

use super::{
    QueuePair,
    QueuePairOperations,
    QueuePairs, //
};
use crate::{
    bindings,
    prelude::*, //
};
use core::marker::PhantomData;

/// Multicast membership implemented by pinned provider data.
///
/// Callbacks run in sleepable context while the core retains the QP and excludes its
/// destruction. Implementations synchronize membership changes against packet delivery.
pub trait MulticastOperations: QueuePairOperations {
    /// Attaches a QP to the group identified by its GID and multicast LID.
    fn attach_multicast(self: Pin<&Self>, qp: &QueuePair<Self>, gid: [u8; 16], lid: u16) -> Result;

    /// Detaches a QP and releases any provider reference retained by membership.
    fn detach_multicast(self: Pin<&Self>, qp: &QueuePair<Self>, gid: [u8; 16], lid: u16) -> Result;
}

/// Installs multicast callbacks for QPs owned by the native core adapter.
pub struct MulticastGroups<T: MulticastOperations>(PhantomData<T>);

impl<T: MulticastOperations> MulticastGroups<T> {
    /// Installs membership callbacks before device publication.
    ///
    /// # Safety
    ///
    /// The caller exclusively owns an unpublished device with [`QueuePairs<T>`] installed.
    /// Its multicast callbacks must be unused and remain managed by this adapter. Core and
    /// kernel callers must retain each QP and exclude destruction throughout a callback.
    pub unsafe fn install(device: *mut bindings::ib_device) {
        // SAFETY: The caller reserves both callback slots in the unpublished device.
        unsafe {
            (*device).ops.attach_mcast = Some(Self::attach);
            (*device).ops.detach_mcast = Some(Self::detach);
        }
    }

    /// # Safety
    ///
    /// Installation ensures this initialized QP belongs to the matching adapter; the core
    /// retains it and its parents throughout this callback.
    unsafe extern "C" fn attach(
        qp: *mut bindings::ib_qp,
        gid: *mut bindings::ib_gid,
        lid: u16,
    ) -> c_int {
        // SAFETY: Installation ensures this initialized QP belongs to the matching adapter;
        // the core retains it and its parents throughout this callback.
        let qp = unsafe { QueuePairs::<T>::borrow(qp) };
        // SAFETY: The core supplies a retained, initialized GID. Copy it before provider use.
        let gid = unsafe { (*gid).raw };
        match qp.provider().attach_multicast(qp, gid, lid) {
            Ok(()) => 0,
            Err(error) => error.to_errno(),
        }
    }

    /// # Safety
    ///
    /// Installation ensures this initialized QP belongs to the matching adapter; the core
    /// retains it and its parents throughout this callback.
    unsafe extern "C" fn detach(
        qp: *mut bindings::ib_qp,
        gid: *mut bindings::ib_gid,
        lid: u16,
    ) -> c_int {
        // SAFETY: Installation ensures this initialized QP belongs to the matching adapter;
        // the core retains it and its parents throughout this callback.
        let qp = unsafe { QueuePairs::<T>::borrow(qp) };
        // SAFETY: The core supplies a retained, initialized GID. Copy it before provider use.
        let gid = unsafe { (*gid).raw };
        match qp.provider().detach_multicast(qp, gid, lid) {
            Ok(()) => 0,
            Err(error) => error.to_errno(),
        }
    }
}
