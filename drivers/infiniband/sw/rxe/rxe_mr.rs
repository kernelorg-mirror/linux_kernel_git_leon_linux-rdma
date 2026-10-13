// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Native memory-region ownership, registration and retained lookups.

#![forbid(unsafe_code)]

use super::{
    rxe_device::DeviceData,
    rxe_id::Identities,
    rxe_mr_region::{
        Attributes,
        Region,
        RegisteredAccess,
        Registration, //
    },
    rxe_mr_user::UserMemory,
    rxe_param as params, //
};
use kernel::{
    page::PAGE_SIZE,
    prelude::*,
    random,
    rbtree::{
        RBTree,
        RBTreeNodeReservation, //
    },
    rdma::{
        Access,
        AccessFlags,
        Device,
        MemoryRegion,
        MemoryRegionOperations,
        MemoryRegionRef,
        RegionCreation,
        RegionRequest,
        UserData,
        UserMemoryRange, //
    },
    sync::{
        Mutex,
        SpinLockIrq, //
    },
    types::ScopeGuard, //
};

/// Generates a random key byte different from the previous value.
pub(crate) fn rxe_get_next_key(last_key: u32) -> u8 {
    loop {
        let mut key = [0u8];
        random::get_bytes(&mut key);
        if u32::from(key[0]) != last_key {
            return key[0];
        }
    }
}

/// Native ownership consumed by deregistration after every transport reference drains.
pub(crate) struct Entry {
    index: u32,
    pub(crate) region: Region,
}

pub(crate) type Publication = RBTreeNodeReservation<u32, MemoryRegionRef<DeviceData>>;
type Creation = RegionCreation<KBox<Entry>, Publication>;

/// Owns the published references and prevents identity reuse before deregistration completes.
///
/// Lookup clones a reference under the IRQ lock and releases the lock before accessing region
/// state. Creation allocates before publication; retirement removes the lookup reference
/// before the core adapter waits for users. Identity allocation and backing release may sleep.
#[pin_data]
pub(crate) struct Regions {
    #[pin]
    identities: Mutex<Identities>,
    #[pin]
    entries: SpinLockIrq<RBTree<u32, MemoryRegionRef<DeviceData>>>,
}

impl Regions {
    pub(crate) fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            identities <- kernel::new_mutex!(Identities::new(
                params::RXE_MIN_MR_INDEX, params::RXE_MAX_MR_INDEX, params::RXE_MAX_MR,
            )),
            entries <- kernel::new_spinlock_irq!(RBTree::new()),
        })
    }

    fn create(
        &self,
        device: &Device<DeviceData>,
        pd: u32,
        request: RegionRequest,
    ) -> Result<Creation> {
        if let RegionRequest::User { access, .. } = request {
            if u32::from(access) & !params::RXE_ACCESS_SUPPORTED_MR != 0 {
                return Err(EOPNOTSUPP);
            }
        }
        let publication = Publication::new(GFP_KERNEL)?;
        let index = self.identities.lock().allocate()?;
        let reserved = ScopeGuard::new(|| self.identities.lock().release(index));
        let key = (index << 8) | u32::from(rxe_get_next_key(u32::MAX));
        let region = match request {
            RegionRequest::Dma(access) => Region::dma(pd, key, access)?,
            RegionRequest::User { range, access } => {
                let flags = u32::from(access) as c_int;
                let memory = if access.contains(Access::OnDemand) {
                    #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
                    {
                        UserMemory::on_demand(device, range.start, range.length, range.iova, flags)?
                    }
                    #[cfg(not(CONFIG_INFINIBAND_ON_DEMAND_PAGING))]
                    {
                        return Err(EOPNOTSUPP);
                    }
                } else {
                    UserMemory::pin(
                        device,
                        range.start,
                        range.length,
                        range.iova,
                        flags,
                        access.contains(Access::FlushPersistent),
                    )?
                };
                Region::user(pd, key, access, range.iova, range.length, memory)?
            }
            RegionRequest::Fast { max_pages } => {
                if max_pages > c_int::MAX as u32 {
                    return Err(EINVAL);
                }
                Region::fast(pd, key, max_pages as usize)?
            }
        };
        let owner = KBox::new(Entry { index, region }, GFP_KERNEL)?;
        reserved.dismiss();
        Ok(RegionCreation {
            owner,
            publication,
            local_key: key,
            remote_key: key,
            page_size: PAGE_SIZE as u32,
        })
    }

    fn publish(&self, region: MemoryRegionRef<DeviceData>, publication: Publication) {
        let index = region.data().index;
        self.entries
            .lock()
            .insert(publication.into_node(index, region));
    }

    pub(crate) fn lookup(&self, pd: u32, access: AccessFlags, key: u32) -> Option<MrRef> {
        let region = self.entries.lock().get(&(key >> 8))?.clone();
        let reference = MrRef::new(region);
        reference
            .access()
            .matches(pd, key, access)
            .then_some(reference)
    }

    pub(crate) fn invalidate(&self, pd: u32, key: u32) -> Result {
        let region = self.entries.lock().get(&(key >> 8)).ok_or(EINVAL)?.clone();
        region.data().region.invalidate(pd, key)
    }

    /// Retains the exact region named by kernel registration work before it is queued.
    pub(crate) fn prepare_registration(
        &self,
        region: &MemoryRegion<DeviceData>,
        key: u32,
        access: AccessFlags,
        address: u64,
        length: u64,
    ) -> Result<FastRegistration> {
        let retained = self
            .entries
            .lock()
            .get(&region.data().index)
            .ok_or(EINVAL)?
            .clone();
        if !core::ptr::eq(&*retained, region) {
            return Err(EINVAL);
        }
        Ok(FastRegistration {
            region: retained,
            key,
            access,
            address,
            length,
        })
    }

    fn retire(&self, region: &MemoryRegion<DeviceData>) -> Result {
        let entry = region.data();
        entry.region.retire()?;
        let removed = self.entries.lock().remove_node(&entry.index).unwrap();
        // Drop the published reference outside the registry lock; the adapter then drains users.
        drop(removed);
        Ok(())
    }

    fn release(&self, owner: KBox<Entry>) {
        let index = owner.index;
        drop(owner);
        self.identities.lock().release(index);
    }
}

/// A kernel registration request retaining native MR ownership until completion or flush.
///
/// Copied translation attributes belong to this request. Transport execution never reads
/// the core header, and deregistration cannot release the region while this value exists.
#[derive(Clone)]
pub(crate) struct FastRegistration {
    region: MemoryRegionRef<DeviceData>,
    key: u32,
    access: AccessFlags,
    address: u64,
    length: u64,
}

impl FastRegistration {
    pub(crate) fn execute(&self, pd: u32) -> Result {
        self.region.data().region.register_fast(
            pd,
            self.key,
            self.access,
            self.address,
            self.length,
        )
    }
}

/// Retains native region storage and the registration observed by one successful lookup.
///
/// Clones preserve the captured version. Every access revalidates it under the region's lock,
/// so re-registration cannot grant an old lookup the authority of a newer publication.
#[derive(Clone)]
pub(crate) struct MrRef {
    region: MemoryRegionRef<DeviceData>,
    registration: Registration,
    window: Option<super::rxe_mw_state::Permission>,
}

impl MrRef {
    fn new(region: MemoryRegionRef<DeviceData>) -> Self {
        let registration = region.data().region.registration();
        Self {
            region,
            registration,
            window: None,
        }
    }

    pub(crate) fn access(&self) -> RegisteredAccess<'_> {
        self.region
            .data()
            .region
            .access(self.registration)
            .with_window(self.window.as_ref())
    }

    pub(crate) fn with_window(mut self, permission: super::rxe_mw_state::Permission) -> Self {
        self.window = Some(permission);
        self
    }

    pub(crate) fn version(&self) -> super::rxe_version::Version {
        self.registration.version()
    }

    pub(crate) fn attributes(&self) -> Attributes {
        self.registration.attributes()
    }

    pub(crate) fn unbind_window(&self) {
        self.region.data().region.unbind_window();
    }

    pub(crate) fn device(&self) -> &Device<DeviceData> {
        self.region.device()
    }
}

impl MemoryRegionOperations for DeviceData {
    type MemoryRegion = KBox<Entry>;
    type RegionPublication = Publication;

    fn create_region(
        self: Pin<&Self>,
        device: &Device<Self>,
        domain: &super::rxe_pd::Domain,
        request: RegionRequest,
        _data: Option<UserData<'_, Self>>,
    ) -> Result<Creation> {
        self.regions.create(device, domain.index(), request)
    }

    fn publish_region(self: Pin<&Self>, region: MemoryRegionRef<Self>, publication: Publication) {
        self.regions.publish(region, publication);
    }

    fn reregister_region(
        self: Pin<&Self>,
        region: &MemoryRegion<Self>,
        domain: Option<&super::rxe_pd::Domain>,
        translation: Option<UserMemoryRange>,
        access: Option<AccessFlags>,
        _data: Option<UserData<'_, Self>>,
    ) -> Result {
        if translation.is_some() {
            return Err(EOPNOTSUPP);
        }
        region
            .data()
            .region
            .reregister(domain.map(|pd| pd.index()), access)
    }

    fn begin_region_mapping(
        self: Pin<&Self>,
        region: &MemoryRegion<Self>,
        page_size: u32,
    ) -> Result {
        region.data().region.begin_map(page_size as usize)
    }

    fn map_region_page(self: Pin<&Self>, region: &MemoryRegion<Self>, address: u64) -> Result {
        region.data().region.push_page(region.device(), address)
    }

    fn finish_region_mapping(self: Pin<&Self>, region: &MemoryRegion<Self>, success: bool) {
        region.data().region.finish_map(success);
    }

    fn retire_region(self: Pin<&Self>, region: &MemoryRegion<Self>) -> Result {
        self.regions.retire(region)
    }

    fn retire_internal_region(self: Pin<&Self>, region: &MemoryRegion<Self>) {
        // The core creates internal DMA regions without window-binding access. Retirement
        // can only fail for bound windows, which cannot exist for these registrations.
        self.regions
            .retire(region)
            .expect("internal DMA regions cannot have bound windows");
    }

    fn release_region(self: Pin<&Self>, owner: KBox<Entry>) {
        self.regions.release(owner);
    }
}
