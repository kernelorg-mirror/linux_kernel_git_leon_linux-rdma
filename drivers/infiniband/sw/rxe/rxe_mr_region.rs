// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Memory-region ownership, registration state and bounded access.

#![forbid(unsafe_code)]

use crate::{
    rxe_device::DeviceData,
    rxe_mr_fast::{
        persistent_segments,
        FastMemory, //
    },
    rxe_mr_user::UserMemory,
    rxe_param::RXE_ACCESS_SUPPORTED_MR,
    rxe_version::Version, //
};
use core::pin::Pin;
use kernel::{
    page::PAGE_SIZE,
    prelude::*,
    rdma::{
        Access,
        AccessFlags,
        Device as RdmaDevice, //
    },
    sync::{
        lock::spinlock::SpinLockIrqGuard,
        SpinLockIrq, //
    }, //
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Dma,
    User,
    Fast,
}

/// A consistent snapshot of attributes published by registration.
#[derive(Clone, Copy)]
pub(crate) struct Attributes {
    pub(crate) kind: Kind,
    pub(crate) key: u32,
    pub(crate) pd: u32,
    pub(crate) access: AccessFlags,
    pub(crate) address: u64,
    pub(crate) length: u64,
    pub(crate) valid: bool,
}

impl Attributes {
    pub(crate) fn contains(&self, address: u64, length: u64) -> bool {
        address >= self.address
            && length <= self.length
            && address - self.address <= self.length - length
    }

    fn matches(&self, pd: u32, key: u32, access: AccessFlags) -> bool {
        self.valid && self.pd == pd && self.key == key && self.access.contains_all(access)
    }
}

struct State {
    attributes: Attributes,
    version: Version,
    mapping_version: u64,
    windows: u32,
    retired: bool,
    fast: Option<FastMemory>,
}

impl State {
    fn matches(&self, registration: Registration, pd: u32, key: u32, access: AccessFlags) -> bool {
        self.version == registration.version && self.attributes.matches(pd, key, access)
    }
}

/// Immutable identity and attributes of one registration publication.
#[derive(Clone, Copy)]
pub(crate) struct Registration {
    version: Version,
    attributes: Attributes,
}

impl Registration {
    pub(crate) fn version(self) -> Version {
        self.version
    }

    pub(crate) fn attributes(self) -> Attributes {
        self.attributes
    }
}

/// A borrowed registration capability, revalidated under the state lock for each access.
///
/// Fast translations remain locked throughout data access. User backing is immutable, so
/// an operation admitted before re-registration may finish after dropping the state lock.
pub(crate) struct RegisteredAccess<'a> {
    region: &'a Region,
    registration: Registration,
    window: Option<&'a super::rxe_mw_state::Permission>,
}

/// Owns the backing and serializes publication of keys and translations.
///
/// User backing is immutable after construction and survives all registration changes. Its
/// operations run without the state lock. Fast translations remain under the state lock for
/// both modification and access, so no access can borrow a table while another call replaces it.
pub(crate) struct Region {
    state: Pin<KBox<SpinLockIrq<State>>>,
    user: Option<UserMemory>,
}

enum Memory<'a> {
    Dma,
    User(&'a UserMemory),
    Fast(SpinLockIrqGuard<'a, State>),
}

impl Region {
    fn new(
        attributes: Attributes,
        user: Option<UserMemory>,
        fast: Option<FastMemory>,
    ) -> Result<Self> {
        Ok(Self {
            state: KBox::pin_init(
                kernel::new_spinlock_irq!(State {
                    attributes,
                    version: Version::new()?,
                    mapping_version: 0,
                    windows: 0,
                    retired: false,
                    fast,
                }),
                GFP_KERNEL,
            )?,
            user,
        })
    }

    pub(crate) fn dma(pd: u32, key: u32, access: AccessFlags) -> Result<Self> {
        Self::new(
            Attributes {
                kind: Kind::Dma,
                pd,
                key,
                access,
                address: 0,
                length: 0,
                valid: true,
            },
            None,
            None,
        )
    }

    pub(crate) fn user(
        pd: u32,
        key: u32,
        access: AccessFlags,
        address: u64,
        length: u64,
        memory: UserMemory,
    ) -> Result<Self> {
        Self::new(
            Attributes {
                kind: Kind::User,
                pd,
                key,
                access,
                address,
                length,
                valid: true,
            },
            Some(memory),
            None,
        )
    }

    pub(crate) fn fast(pd: u32, key: u32, max_pages: usize) -> Result<Self> {
        Self::new(
            Attributes {
                kind: Kind::Fast,
                pd,
                key,
                access: AccessFlags::empty(),
                address: 0,
                length: 0,
                valid: false,
            },
            None,
            Some(FastMemory::new(max_pages)?),
        )
    }

    pub(crate) fn registration(&self) -> Registration {
        let state = self.state.lock();
        Registration {
            version: state.version,
            attributes: state.attributes,
        }
    }

    pub(crate) fn access(&self, registration: Registration) -> RegisteredAccess<'_> {
        RegisteredAccess {
            region: self,
            registration,
            window: None,
        }
    }

    /// Stops new lookup and window binding before the owner drains references.
    pub(crate) fn retire(&self) -> Result {
        let mut state = self.state.lock();
        if state.windows != 0 {
            return Err(EINVAL);
        }
        state.retired = true;
        state.attributes.valid = false;
        Ok(())
    }

    pub(crate) fn invalidate(&self, pd: u32, key: u32) -> Result {
        let mut state = self.state.lock();
        if state.retired
            || state.attributes.kind != Kind::Fast
            || state.attributes.pd != pd
            || state.attributes.key != key
            || state.windows != 0
        {
            return Err(EINVAL);
        }
        state.attributes.valid = false;
        Ok(())
    }

    pub(crate) fn register_fast(
        &self,
        pd: u32,
        key: u32,
        access: AccessFlags,
        address: u64,
        length: u64,
    ) -> Result {
        let mut state = self.state.lock();
        if state.retired
            || state.attributes.valid
            || state.attributes.kind != Kind::Fast
            || state.attributes.pd != pd
            || state.attributes.key & !0xff != key & !0xff
            || access.contains(Access::OnDemand)
        {
            return Err(EINVAL);
        }
        if !state.fast.as_ref().ok_or(EINVAL)?.mapping_available() {
            return Err(EBUSY);
        }
        address.checked_add(length).ok_or(EINVAL)?;
        if access.contains(Access::FlushPersistent) {
            let version = state.version;
            let mapping_version = state.mapping_version;
            let page_size = state.fast.as_ref().ok_or(EINVAL)?.pending_page_size();
            drop(state);
            let persistent =
                persistent_segments(page_size, address, length, |index, offset, size| {
                    let range = {
                        let state = self.state.lock();
                        if state.retired
                            || state.version != version
                            || state.mapping_version != mapping_version
                        {
                            return false;
                        }
                        state
                            .fast
                            .as_ref()
                            .and_then(|fast| fast.pending_range(index))
                    };
                    range.is_some_and(|range| range.is_persistent(offset, size))
                });
            state = self.state.lock();
            if !persistent
                || state.retired
                || state.version != version
                || state.mapping_version != mapping_version
            {
                return Err(EINVAL);
            }
        }
        let version = state.version.next()?;
        state.fast.as_mut().ok_or(EINVAL)?.publish();
        state.version = version;
        state.attributes.key = key;
        state.attributes.access = access;
        state.attributes.address = address;
        state.attributes.length = length;
        state.attributes.valid = true;
        Ok(())
    }

    pub(crate) fn begin_map(&self, page_size: usize) -> Result {
        self.prepare_mapping(false, |table, max_pages| table.begin(max_pages, page_size))
    }

    pub(crate) fn push_page(&self, device: &RdmaDevice<DeviceData>, address: u64) -> Result {
        self.prepare_mapping(true, |table, _| table.push(device, address))
    }

    pub(crate) fn finish_map(&self, success: bool) {
        if let Some(fast) = self.state.lock().fast.as_mut() {
            fast.finish_mapping(success);
        }
    }

    /// The core serializes map callbacks. The mapping transaction excludes registration
    /// until the whole page walk finishes, without blocking active accesses.
    fn prepare_mapping(
        &self,
        require_mapping: bool,
        prepare: impl FnOnce(&mut super::rxe_mr_fast::Table, usize) -> Result,
    ) -> Result {
        let (mut table, max_pages) = {
            let mut state = self.state.lock();
            if state.retired {
                return Err(EINVAL);
            }
            let version = state.mapping_version.checked_add(1).ok_or(EOVERFLOW)?;
            let pending = state
                .fast
                .as_mut()
                .ok_or(EINVAL)?
                .take_pending(require_mapping)?;
            state.mapping_version = version;
            pending
        };
        // Allocation, capture, rollback and old-table destruction retain the caller's IRQ
        // state rather than extending our state-lock critical section across the page walk.
        let result = prepare(&mut table, max_pages);
        let mut state = self.state.lock();
        let fast = state.fast.as_mut().unwrap();
        fast.restore_pending(table, result.is_ok());
        if !require_mapping && result.is_err() {
            fast.finish_mapping(false);
        }
        if state.retired {
            return Err(EINVAL);
        }
        result
    }

    pub(crate) fn reregister(&self, pd: Option<u32>, access: Option<AccessFlags>) -> Result {
        // Immutable user backing can be validated before acquiring the publication lock.
        if let (Some(user), Some(access)) = (&self.user, access) {
            user.check_access(u32::from(access) as c_int)?;
        }
        let mut state = self.state.lock();
        if state.retired {
            return Err(EINVAL);
        }
        let version = state.version.next()?;
        if let Some(access) = access {
            if u32::from(access) & !RXE_ACCESS_SUPPORTED_MR != 0
                || access.contains(Access::OnDemand)
                    != state.attributes.access.contains(Access::OnDemand)
            {
                return Err(EOPNOTSUPP);
            }
            state.attributes.access = access;
        }
        if let Some(pd) = pd {
            state.attributes.pd = pd;
        }
        state.version = version;
        Ok(())
    }

    pub(crate) fn unbind_window(&self) {
        let mut state = self.state.lock();
        if !kernel::warn_on!(state.windows == 0) {
            state.windows -= 1;
        }
    }

    fn memory(
        &self,
        registration: Registration,
        address: u64,
        length: usize,
    ) -> Result<Memory<'_>> {
        let state = self.state.lock();
        if state.version != registration.version || !state.attributes.valid {
            return Err(EINVAL);
        }
        if state.attributes.kind == Kind::Dma {
            return Ok(Memory::Dma);
        }
        if !state.attributes.contains(address, length as u64) {
            return Err(EINVAL);
        }
        if state.attributes.kind == Kind::Fast {
            return Ok(Memory::Fast(state));
        }
        // User backing and its IOVA are immutable; faults must run without the spinlock.
        drop(state);
        Ok(Memory::User(self.user.as_ref().ok_or(EINVAL)?))
    }
}

impl<'a> RegisteredAccess<'a> {
    pub(crate) fn with_window(
        mut self,
        permission: Option<&'a super::rxe_mw_state::Permission>,
    ) -> Self {
        self.window = permission;
        self
    }

    pub(crate) fn is_valid(&self) -> bool {
        let state = self.region.state.lock();
        state.version == self.registration.version && state.attributes.valid
    }

    pub(crate) fn matches(&self, pd: u32, key: u32, access: AccessFlags) -> bool {
        self.region
            .state
            .lock()
            .matches(self.registration, pd, key, access)
    }

    pub(crate) fn check_range(&self, address: u64, length: u64) -> Result {
        let state = self.region.state.lock();
        if state.version != self.registration.version
            || !state.attributes.valid
            || (state.attributes.kind != Kind::Dma && !state.attributes.contains(address, length))
        {
            return Err(EINVAL);
        }
        Ok(())
    }

    /// Validates and counts a window binding under the same lock as invalidation.
    pub(crate) fn bind_window(
        &self,
        pd: u32,
        key: u32,
        access: AccessFlags,
        address: u64,
        length: u64,
    ) -> Result {
        let mut state = self.region.state.lock();
        let attributes = state.attributes;
        if state.version != self.registration.version
            || !attributes.matches(pd, key, Access::WindowBind.into())
            || attributes.access.contains(Access::ZeroBased)
            || (access.contains_any(Access::RemoteWrite | Access::RemoteAtomic)
                && !attributes.access.contains(Access::LocalWrite))
            || address.checked_add(length).is_none()
            || (attributes.kind != Kind::Dma && !attributes.contains(address, length))
        {
            return Err(EINVAL);
        }
        state.windows = state.windows.checked_add(1).ok_or(EOVERFLOW)?;
        Ok(())
    }

    pub(crate) fn read(
        &self,
        device: &RdmaDevice<DeviceData>,
        mut address: u64,
        output: &mut [u8],
    ) -> Result {
        self.check_range(address, output.len() as u64)?;
        address.checked_add(output.len() as u64).ok_or(EINVAL)?;
        for chunk in output.chunks_mut(PAGE_SIZE) {
            self.read_chunk(device, address, chunk)?;
            address += chunk.len() as u64;
        }
        Ok(())
    }

    pub(crate) fn write(
        &self,
        device: &RdmaDevice<DeviceData>,
        mut address: u64,
        input: &[u8],
    ) -> Result {
        self.check_range(address, input.len() as u64)?;
        address.checked_add(input.len() as u64).ok_or(EINVAL)?;
        for chunk in input.chunks(PAGE_SIZE) {
            self.write_chunk(device, address, chunk)?;
            address += chunk.len() as u64;
        }
        Ok(())
    }

    pub(crate) fn flush(&self, mut address: u64, mut length: usize) -> Result {
        self.check_range(address, length as u64)?;
        address.checked_add(length as u64).ok_or(EINVAL)?;
        if length == 0 {
            return self.flush_chunk(address, 0);
        }
        while length != 0 {
            let bytes = length.min(PAGE_SIZE);
            self.flush_chunk(address, bytes)?;
            address += bytes as u64;
            length -= bytes;
        }
        Ok(())
    }

    fn read_chunk(
        &self,
        device: &RdmaDevice<DeviceData>,
        address: u64,
        output: &mut [u8],
    ) -> Result {
        let _window = self
            .window
            .map(|permission| permission.lock())
            .transpose()?;
        match self
            .region
            .memory(self.registration, address, output.len())?
        {
            Memory::Dma => device.virtual_dma()?.read(address, output),
            Memory::User(memory) => memory.read(address, output),
            Memory::Fast(state) => {
                state
                    .fast
                    .as_ref()
                    .ok_or(EINVAL)?
                    .read(state.attributes.address, address, output)
            }
        }
    }

    fn write_chunk(&self, device: &RdmaDevice<DeviceData>, address: u64, input: &[u8]) -> Result {
        let _window = self
            .window
            .map(|permission| permission.lock())
            .transpose()?;
        match self
            .region
            .memory(self.registration, address, input.len())?
        {
            Memory::Dma => device.virtual_dma()?.write(address, input),
            Memory::User(memory) => memory.write(address, input),
            Memory::Fast(state) => {
                state
                    .fast
                    .as_ref()
                    .ok_or(EINVAL)?
                    .write(state.attributes.address, address, input)
            }
        }
    }

    fn flush_chunk(&self, address: u64, length: usize) -> Result {
        let _window = self
            .window
            .map(|permission| permission.lock())
            .transpose()?;
        let memory = self.region.memory(self.registration, address, length)?;
        if length == 0 {
            return Ok(());
        }
        match memory {
            Memory::Dma => Err(EFAULT),
            Memory::User(memory) => memory.flush(address, length),
            Memory::Fast(state) => {
                state
                    .fast
                    .as_ref()
                    .ok_or(EINVAL)?
                    .flush(state.attributes.address, address, length)
            }
        }
    }

    pub(crate) fn compare_exchange(
        &self,
        device: &RdmaDevice<DeviceData>,
        address: u64,
        compare: u64,
        value: u64,
    ) -> Result<u64> {
        let _window = self
            .window
            .map(|permission| permission.lock())
            .transpose()?;
        match self
            .region
            .memory(self.registration, address, size_of::<u64>())?
        {
            Memory::Dma => device
                .virtual_dma()?
                .compare_exchange(address, compare, value),
            Memory::User(memory) => memory.compare_exchange(address, compare, value),
            Memory::Fast(state) => state.fast.as_ref().ok_or(EINVAL)?.compare_exchange(
                state.attributes.address,
                address,
                compare,
                value,
            ),
        }
    }

    pub(crate) fn fetch_add(
        &self,
        device: &RdmaDevice<DeviceData>,
        address: u64,
        value: u64,
    ) -> Result<u64> {
        let _window = self
            .window
            .map(|permission| permission.lock())
            .transpose()?;
        match self
            .region
            .memory(self.registration, address, size_of::<u64>())?
        {
            Memory::Dma => device.virtual_dma()?.fetch_add(address, value),
            Memory::User(memory) => memory.fetch_add(address, value),
            Memory::Fast(state) => state.fast.as_ref().ok_or(EINVAL)?.fetch_add(
                state.attributes.address,
                address,
                value,
            ),
        }
    }

    pub(crate) fn store_release(
        &self,
        device: &RdmaDevice<DeviceData>,
        address: u64,
        value: u64,
    ) -> Result {
        let _window = self
            .window
            .map(|permission| permission.lock())
            .transpose()?;
        match self
            .region
            .memory(self.registration, address, size_of::<u64>())?
        {
            Memory::Dma => device.virtual_dma()?.store_release(address, value),
            Memory::User(memory) => memory.store_release(address, value),
            Memory::Fast(state) => state.fast.as_ref().ok_or(EINVAL)?.store_release(
                state.attributes.address,
                address,
                value,
            ),
        }
    }

    #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
    pub(crate) fn prefetch_async(
        &self,
        address: u64,
        length: usize,
        mode: kernel::rdma::odp::Prefetch,
    ) -> Result {
        self.check_range(address, length as u64)?;
        self.region
            .user
            .as_ref()
            .ok_or(EINVAL)?
            .prefetch_async(address, length, mode)
    }

    #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
    pub(crate) fn prefetch(
        &self,
        address: u64,
        length: usize,
        mode: kernel::rdma::odp::Prefetch,
    ) -> Result {
        self.check_range(address, length as u64)?;
        self.region
            .user
            .as_ref()
            .ok_or(EINVAL)?
            .prefetch(address, length, mode)
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_mr_region)]
mod tests {
    use super::*;

    fn current(region: &Region) -> RegisteredAccess<'_> {
        region.access(region.registration())
    }

    #[test]
    fn empty_dma_flush_checks_admission_without_touching_backing() -> Result {
        let region = Region::dma(7, 0x1201, Access::FlushPersistent.into())?;
        let access = current(&region);
        assert_eq!(access.flush(0, 0), Ok(()));
        assert_eq!(access.flush(u64::MAX, 0), Ok(()));
        assert_eq!(access.flush(0, 1), Err(EFAULT));
        region.retire()?;
        assert_eq!(access.flush(0, 0), Err(EINVAL));
        Ok(())
    }

    #[test]
    fn stale_capability_cannot_follow_reused_key_or_translation() -> Result {
        let region = Region::fast(7, 0x1200, 0)?;
        let rights = Access::LocalWrite | Access::RemoteRead | Access::WindowBind;
        region.register_fast(7, 0x1201, rights, 0x1000, 128)?;
        let registration = region.registration();
        let old = region.access(registration);
        assert!(old.is_valid());
        region.invalidate(7, 0x1201)?;
        assert!(!old.is_valid());
        region.register_fast(7, 0x1201, rights, 0x2000, 128)?;
        assert!(!old.matches(7, 0x1201, rights));
        assert_eq!(old.check_range(0x2000, 8), Err(EINVAL));
        assert!(region.memory(registration, 0x2000, 8).is_err());
        assert_eq!(
            old.bind_window(7, 0x1201, Access::RemoteRead.into(), 0x2000, 8),
            Err(EINVAL)
        );
        assert_eq!(current(&region).check_range(0x2000, 8), Ok(()));
        assert_eq!(registration.attributes().address, 0x1000);
        Ok(())
    }

    #[test]
    fn matching_key_and_generation_do_not_identify_another_region() -> Result {
        let first = Region::fast(7, 0x1200, 0)?;
        let second = Region::fast(7, 0x1200, 0)?;
        first.register_fast(7, 0x1201, AccessFlags::empty(), 0x1000, 128)?;
        second.register_fast(7, 0x1201, AccessFlags::empty(), 0x1000, 128)?;
        let old = first.registration();
        assert!(first.access(old).is_valid());
        assert!(!second.access(old).is_valid());
        assert!(!second.access(old).matches(7, 0x1201, AccessFlags::empty()));
        assert_eq!(second.access(old).check_range(0x1000, 8), Err(EINVAL));
        assert!(second.memory(old, 0x1000, 8).is_err());
        Ok(())
    }

    #[test]
    fn mapping_walk_excludes_registration_until_finish() -> Result {
        let region = Region::fast(7, 0x1200, 0)?;
        let rights = Access::LocalWrite | Access::RemoteRead;
        region.begin_map(PAGE_SIZE)?;
        assert_eq!(
            region.register_fast(7, 0x1201, rights, 0x1000, 0),
            Err(EBUSY)
        );
        region.finish_map(true);
        region.register_fast(7, 0x1201, rights, 0x1000, 0)?;
        region.invalidate(7, 0x1201)?;
        region.begin_map(PAGE_SIZE * 2)?;
        assert_eq!(
            region.register_fast(7, 0x1202, rights, 0x2000, 0),
            Err(EBUSY)
        );
        region.finish_map(false);
        region.register_fast(7, 0x1202, rights, 0x2000, 0)?;
        Ok(())
    }

    #[test]
    fn mapping_next_registration_keeps_the_current_capability_live() -> Result {
        let region = Region::fast(7, 0x1200, 0)?;
        let rights = Access::LocalWrite | Access::RemoteRead;
        region.begin_map(kernel::page::PAGE_SIZE)?;
        region.finish_map(true);
        region.register_fast(7, 0x1201, rights, 0x1000, 128)?;
        let registration = region.registration();
        let old = region.access(registration);

        // Core RDMA RW and iSER map the replacement before posting LOCAL_INV and REG_MR.
        region.begin_map(kernel::page::PAGE_SIZE * 2)?;
        region.finish_map(true);
        assert!(old.matches(7, 0x1201, rights));
        assert_eq!(old.check_range(0x1000, 128), Ok(()));
        assert_eq!(region.registration().version(), registration.version());
        assert_eq!(
            region.register_fast(7, 0x1202, rights, 0x2000, 128),
            Err(EINVAL)
        );
        assert!(old.is_valid());
        region.invalidate(7, 0x1201)?;
        assert!(!old.is_valid());

        // A rejected registration must not consume the pending table or publish attributes.
        assert_eq!(
            region.register_fast(7, 0x1202, rights, u64::MAX, 128),
            Err(EINVAL)
        );
        assert_eq!(region.registration().version(), registration.version());
        assert_eq!(region.registration().attributes().key, 0x1201);
        region.register_fast(7, 0x1202, rights, 0x2000, 128)?;
        assert_ne!(region.registration().version(), registration.version());
        assert!(!old.is_valid());
        assert!(current(&region).matches(7, 0x1202, rights));
        assert_eq!(current(&region).check_range(0x2000, 128), Ok(()));
        Ok(())
    }

    #[test]
    fn fast_keys_and_bounds_publish_together() -> Result {
        let region = Region::fast(7, 0x1200, 0)?;
        let access = Access::LocalWrite | Access::RemoteRead;
        assert!(!current(&region).matches(7, 0x1200, access));
        region.register_fast(7, 0x1201, access, 0x100000000, 127)?;
        assert!(current(&region).matches(7, 0x1201, access));
        assert!(!current(&region).matches(7, 0x1200, access));
        assert_eq!(current(&region).check_range(0x100000000 + 126, 1), Ok(()));
        assert_eq!(
            current(&region).check_range(0x100000000 + 126, 2),
            Err(EINVAL)
        );
        region.begin_map(4096)?;
        region.finish_map(true);
        assert_eq!(region.invalidate(8, 0x1201), Err(EINVAL));
        region.invalidate(7, 0x1201)?;
        assert_eq!(current(&region).check_range(0x100000000, 1), Err(EINVAL));
        assert_eq!(region.register_fast(7, 0x1300, access, 0, 1), Err(EINVAL));
        assert_eq!(
            region.register_fast(7, 0x1202, access, u64::MAX, 2),
            Err(EINVAL)
        );
        assert!(!current(&region).matches(7, 0x1202, access));
        region.register_fast(7, 0x1202, access, 0x200000000, 127)?;
        assert_eq!(current(&region).check_range(0x100000000, 1), Err(EINVAL));
        assert_eq!(current(&region).check_range(0x200000000, 127), Ok(()));
        Ok(())
    }

    #[test]
    fn dma_windows_validate_overflow_without_a_registered_extent() -> Result {
        let region = Region::dma(7, 0x1201, Access::WindowBind | Access::LocalWrite)?;
        for access in [
            Access::RemoteWrite.into(),
            Access::ZeroBased | Access::RemoteWrite,
        ] {
            assert_eq!(
                current(&region).bind_window(7, 0x1201, access, u64::MAX, 2),
                Err(EINVAL)
            );
            current(&region).bind_window(7, 0x1201, access, 0x1000, 128)?;
            assert_eq!(region.retire(), Err(EINVAL));
            region.unbind_window();
        }
        region.retire()?;
        Ok(())
    }

    #[test]
    fn zero_based_windows_validate_the_translated_extent() -> Result {
        let region = Region::fast(7, 0x1200, 0)?;
        let access = Access::WindowBind | Access::LocalWrite | Access::RemoteRead;
        region.register_fast(7, 0x1201, access, 0x1000, 128)?;
        let window = Access::ZeroBased | Access::RemoteRead;
        for (address, length) in [(0x2000, 16), (0x107f, 2), (u64::MAX, 2)] {
            assert_eq!(
                current(&region).bind_window(7, 0x1201, window, address, length),
                Err(EINVAL)
            );
        }
        current(&region).bind_window(7, 0x1201, window, 0x1040, 64)?;
        region.unbind_window();
        region.retire()?;
        Ok(())
    }

    #[test]
    fn bound_windows_exclude_retirement_and_invalidation() -> Result {
        let region = Region::fast(7, 0x1200, 0)?;
        let access = Access::WindowBind | Access::LocalWrite | Access::RemoteRead;
        region.register_fast(7, 0x1201, access, 0x1000, 128)?;
        assert_eq!(
            current(&region).bind_window(7, 0x1201, Access::RemoteRead.into(), u64::MAX, 2),
            Err(EINVAL)
        );
        current(&region).bind_window(7, 0x1201, Access::RemoteRead.into(), 0x1040, 64)?;
        assert_eq!(region.retire(), Err(EINVAL));
        assert_eq!(region.invalidate(7, 0x1201), Err(EINVAL));
        region.unbind_window();
        region.retire()?;
        assert_eq!(
            current(&region).bind_window(7, 0x1201, Access::RemoteRead.into(), 0x1040, 64),
            Err(EINVAL)
        );
        assert_eq!(region.register_fast(7, 0x1202, access, 0, 128), Err(EINVAL));
        assert_eq!(region.begin_map(4096), Err(EINVAL));
        Ok(())
    }

    #[test]
    fn failed_reregistration_preserves_pd_and_access() -> Result {
        let access = Access::LocalWrite | Access::RemoteRead;
        let region = Region::dma(7, 0x1200, access)?;
        let old = current(&region);
        assert_eq!(
            region.reregister(Some(8), Some(access | Access::OnDemand)),
            Err(EOPNOTSUPP)
        );
        assert!(old.matches(7, 0x1200, access));
        assert!(current(&region).matches(7, 0x1200, access));
        assert!(!current(&region).matches(8, 0x1200, access));
        region.reregister(Some(8), Some(Access::LocalWrite.into()))?;
        assert!(!old.is_valid());
        assert!(!current(&region).matches(7, 0x1200, AccessFlags::empty()));
        assert!(!current(&region).matches(8, 0x1200, Access::RemoteRead.into()));
        assert!(current(&region).matches(8, 0x1200, Access::LocalWrite.into()));
        region.retire()?;
        assert_eq!(region.reregister(Some(7), Some(access)), Err(EINVAL));
        Ok(())
    }
}
