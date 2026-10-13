// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Owned user registrations and checked IOVA translation.

#![forbid(unsafe_code)]

use crate::rxe_device::DeviceData;
#[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
use kernel::rdma::{
    odp::Prefetch,
    umem::OwnedOnDemandMemory, //
};
use kernel::{
    prelude::*,
    rdma::{
        umem::OwnedPinnedMemory,
        AccessFlags,
        Device as RdmaDevice, //
    }, //
};

enum Backing {
    Pinned(OwnedPinnedMemory<DeviceData>),
    #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
    OnDemand(OwnedOnDemandMemory<DeviceData>),
}

/// Owns the registration independently of the core MR's mutable attributes.
pub(crate) struct UserMemory {
    backing: Backing,
    iova: u64,
}

impl UserMemory {
    pub(crate) fn pin(
        device: &RdmaDevice<DeviceData>,
        start: u64,
        length: u64,
        iova: u64,
        access: c_int,
        persistent: bool,
    ) -> Result<Self> {
        iova.checked_add(length).ok_or(EINVAL)?;
        let memory = device.virtual_dma()?.pin_user_memory(
            start,
            usize::try_from(length)?,
            AccessFlags::from_bits(access as u32),
        )?;
        if persistent && !memory.is_persistent() {
            return Err(EINVAL);
        }
        Ok(Self {
            backing: Backing::Pinned(memory),
            iova,
        })
    }

    #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
    pub(crate) fn on_demand(
        device: &RdmaDevice<DeviceData>,
        start: u64,
        length: u64,
        iova: u64,
        access: c_int,
    ) -> Result<Self> {
        iova.checked_add(length).ok_or(EINVAL)?;
        let memory = device.virtual_dma()?.register_on_demand(
            usize::try_from(start)?,
            usize::try_from(length)?,
            AccessFlags::from_bits(access as u32),
        )?;
        memory.prefetch(0, memory.len(), Prefetch::Snapshot)?;
        Ok(Self {
            backing: Backing::OnDemand(memory),
            iova,
        })
    }

    fn offset(&self, address: u64, length: usize) -> Result<usize> {
        let offset = usize::try_from(address.checked_sub(self.iova).ok_or(EINVAL)?)?;
        let size = match &self.backing {
            Backing::Pinned(memory) => memory.len(),
            #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
            Backing::OnDemand(memory) => memory.len(),
        };
        if offset > size || length > size - offset {
            return Err(EINVAL);
        }
        Ok(offset)
    }

    pub(crate) fn check_access(&self, access: c_int) -> Result {
        match &self.backing {
            Backing::Pinned(memory) => memory.check_access(AccessFlags::from_bits(access as u32)),
            #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
            Backing::OnDemand(memory) => memory.check_access(AccessFlags::from_bits(access as u32)),
        }
    }

    pub(crate) fn read(&self, address: u64, output: &mut [u8]) -> Result {
        let offset = self.offset(address, output.len())?;
        match &self.backing {
            Backing::Pinned(memory) => memory.read(offset, output),
            #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
            Backing::OnDemand(memory) => memory.read(offset, output),
        }
    }

    pub(crate) fn write(&self, address: u64, input: &[u8]) -> Result {
        let offset = self.offset(address, input.len())?;
        match &self.backing {
            Backing::Pinned(memory) => memory.write(offset, input),
            #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
            Backing::OnDemand(memory) => memory.write(offset, input),
        }
    }

    pub(crate) fn flush(&self, address: u64, length: usize) -> Result {
        let offset = self.offset(address, length)?;
        match &self.backing {
            Backing::Pinned(memory) => memory.flush(offset, length),
            #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
            Backing::OnDemand(memory) => memory.flush(offset, length),
        }
    }

    pub(crate) fn compare_exchange(&self, address: u64, compare: u64, value: u64) -> Result<u64> {
        let offset = self.offset(address, size_of::<u64>())?;
        match &self.backing {
            Backing::Pinned(memory) => memory.compare_exchange(offset, compare, value),
            #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
            Backing::OnDemand(memory) => memory.compare_exchange(offset, compare, value),
        }
    }

    pub(crate) fn fetch_add(&self, address: u64, value: u64) -> Result<u64> {
        let offset = self.offset(address, size_of::<u64>())?;
        match &self.backing {
            Backing::Pinned(memory) => memory.fetch_add(offset, value),
            #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
            Backing::OnDemand(memory) => memory.fetch_add(offset, value),
        }
    }

    pub(crate) fn store_release(&self, address: u64, value: u64) -> Result {
        let offset = self.offset(address, size_of::<u64>())?;
        match &self.backing {
            Backing::Pinned(memory) => memory.store_release(offset, value),
            #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
            Backing::OnDemand(memory) => memory.store_release(offset, value),
        }
    }

    #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
    pub(crate) fn prefetch_async(&self, address: u64, length: usize, mode: Prefetch) -> Result {
        let offset = self.offset(address, length)?;
        match &self.backing {
            Backing::OnDemand(memory) => memory.prefetch_async(offset, length, mode),
            Backing::Pinned(_) => Err(EINVAL),
        }
    }

    #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
    pub(crate) fn prefetch(&self, address: u64, length: usize, mode: Prefetch) -> Result {
        let offset = self.offset(address, length)?;
        match &self.backing {
            Backing::OnDemand(memory) => memory.prefetch(offset, length, mode),
            Backing::Pinned(_) => Err(EINVAL),
        }
    }
}
