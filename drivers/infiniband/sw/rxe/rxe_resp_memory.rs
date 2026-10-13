// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Request memory state with owned registrations and receive work.

#![forbid(unsafe_code)]

use super::{
    rxe_mr::MrRef,
    rxe_mr_data::Buffer,
    rxe_version::Version,
    rxe_wqe::ReceiveWqe, //
};
use kernel::prelude::*;

/// The MR publication and optional window binding which admitted an operation.
///
/// This record retains no object. A later segment must reacquire an owned MR reference and match
/// both versions before accessing memory; retaining this record cannot delay deregistration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Authorization {
    region: Version,
    window: Option<Version>,
}

impl Authorization {
    pub(super) fn new(region: Version, window: Option<Version>) -> Self {
        Self { region, window }
    }

    pub(super) fn is_window(self) -> bool {
        self.window.is_some()
    }
}

/// Memory state exclusively owned by a QP's serialized receive task.
///
/// The registration reference moves into a read reply or is dropped when the request finishes.
/// Queue-pair teardown drops any remaining reference after quiescing the receive task.
#[derive(Default)]
pub(super) struct RequestMemory {
    pub(super) region: Option<MrRef>,
    authorization: Option<Authorization>,
    pub(super) receive: Option<ReceiveWqe>,
    pub(super) address: u64,
    pub(super) offset: u64,
    pub(super) residual: u32,
    pub(super) key: u32,
    pub(super) length: u32,
}

impl RequestMemory {
    pub(super) fn new() -> Result<KBox<Self>> {
        Ok(KBox::new(Self::default(), GFP_KERNEL)?)
    }

    pub(super) fn start(&mut self, address: u64, length: u32, key: u32) {
        self.address = address;
        self.offset = 0;
        self.residual = length;
        self.length = length;
        self.key = key;
        self.region = None;
        self.authorization = None;
    }

    pub(super) fn reset(&mut self) {
        *self = Self::default();
    }

    pub(super) fn authorization(&self) -> Option<Authorization> {
        self.authorization
    }

    /// Retains a newly acquired reference only if it belongs to the original admission.
    pub(super) fn admit(&mut self, memory: MrRef, window: Option<Version>) -> Result {
        let authorization = Authorization::new(memory.version(), window);
        if self
            .authorization
            .is_some_and(|original| original != authorization)
        {
            return Err(EINVAL);
        }
        self.authorization = Some(authorization);
        self.region = Some(memory);
        Ok(())
    }

    pub(super) fn registration(&self) -> Result<&MrRef> {
        self.region.as_ref().ok_or(EINVAL)
    }

    pub(super) fn translated_address(&self) -> Result<u64> {
        self.address.checked_add(self.offset).ok_or(EINVAL)
    }

    pub(super) fn write(&mut self, bytes: &[u8]) -> Result {
        if bytes.is_empty() {
            return Ok(());
        }
        let length = u32::try_from(bytes.len()).map_err(|_| EINVAL)?;
        let residual = self.residual.checked_sub(length).ok_or(EINVAL)?;
        let next = self.address.checked_add(bytes.len() as u64).ok_or(EINVAL)?;
        let memory = self.registration()?;
        memory
            .access()
            .write(memory.device(), self.translated_address()?, bytes)?;
        self.address = next;
        self.residual = residual;
        Ok(())
    }

    pub(super) fn write_receive(
        &mut self,
        bytes: &[u8],
        lookup: impl FnMut(u32) -> Option<MrRef>,
    ) -> Result {
        let receive = self.receive.as_mut().ok_or(EINVAL)?;
        if bytes.len() > receive.remaining() as usize {
            return Err(ENOSPC);
        }
        receive.dma()?.copy(Buffer::Write(bytes), lookup)
    }
}
