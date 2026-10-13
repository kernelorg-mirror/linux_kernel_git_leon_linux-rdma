// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Owned fast-registration translations and bounded memory operations.

#![forbid(unsafe_code)]

use crate::rxe_device::DeviceData;
use kernel::{
    page::PAGE_SIZE,
    prelude::*,
    rdma::{
        virt_dma::Range,
        Device as RdmaDevice, //
    }, //
};

/// Active and pending translations retaining revocable DMA mapping identities.
///
/// Mapping prepares the next registration while data operations use the active table. The owner
/// publishes the pending table with the registration attributes under its state lock. Both tables
/// own metadata only: unmap revokes access even while an entry remains in either table.
pub(crate) struct FastMemory {
    active: Table,
    pending: Option<Table>,
    mapped: bool,
    mapping: bool,
    max_pages: usize,
}

pub(super) struct Table {
    pages: KVec<Range<DeviceData>>,
    page_size: usize,
    max_entries: usize,
}

impl FastMemory {
    pub(crate) fn new(max_pages: usize) -> Result<Self> {
        Ok(Self {
            active: Table {
                pages: KVec::with_capacity(max_pages, GFP_KERNEL)?,
                page_size: PAGE_SIZE,
                max_entries: max_pages,
            },
            pending: Some(Table {
                pages: KVec::with_capacity(max_pages, GFP_KERNEL)?,
                page_size: PAGE_SIZE,
                max_entries: max_pages,
            }),
            mapped: false,
            mapping: false,
            max_pages,
        })
    }

    /// Detaches only unpublished translations for work outside the region IRQ lock.
    pub(crate) fn take_pending(&mut self, require_mapping: bool) -> Result<(Table, usize)> {
        if require_mapping && (!self.mapping || !self.mapped) {
            return Err(EINVAL);
        }
        if !require_mapping && self.mapping {
            return Err(EBUSY);
        }
        let pending = self.pending.take().ok_or(EBUSY)?;
        if !require_mapping {
            self.mapping = true;
            self.mapped = false;
        }
        Ok((pending, self.max_pages))
    }

    /// Restores a checked-out table without walking or dropping its captures.
    pub(crate) fn restore_pending(&mut self, table: Table, mapped: bool) {
        self.pending = Some(table);
        self.mapped |= mapped;
    }

    pub(crate) fn mapping_available(&self) -> bool {
        !self.mapping && self.pending.is_some()
    }

    pub(crate) fn finish_mapping(&mut self, success: bool) {
        self.mapped &= success;
        self.mapping = false;
    }

    /// Publishes a prepared mapping, retaining the current one if no new map was requested.
    pub(crate) fn publish(&mut self) {
        if self.mapped {
            core::mem::swap(&mut self.active, self.pending.as_mut().unwrap());
            // Retire the old captures when the next map detaches this table, or at MR drop.
            self.mapped = false;
        }
    }

    /// Translates an IOVA using the current registration's virtual base.
    fn locate(&self, base: u64, address: u64) -> Result<(&Range<DeviceData>, usize, usize)> {
        let offset = address
            .checked_sub(base & !(self.active.page_size as u64 - 1))
            .ok_or(EFAULT)?;
        let size = self.active.page_size.min(PAGE_SIZE);
        let index = usize::try_from(offset / size as u64).map_err(|_| EFAULT)?;
        let offset = (offset % size as u64) as usize;
        Ok((
            self.active.pages.get(index).ok_or(EFAULT)?,
            offset,
            size - offset,
        ))
    }

    pub(crate) fn read(&self, base: u64, mut address: u64, mut output: &mut [u8]) -> Result {
        address.checked_add(output.len() as u64).ok_or(EFAULT)?;
        while !output.is_empty() {
            let (range, offset, remaining) = self.locate(base, address)?;
            let bytes = remaining.min(output.len());
            let (chunk, rest) = output.split_at_mut(bytes);
            range.read(offset, chunk)?;
            output = rest;
            address += bytes as u64;
        }
        Ok(())
    }

    pub(crate) fn write(&self, base: u64, mut address: u64, mut input: &[u8]) -> Result {
        address.checked_add(input.len() as u64).ok_or(EFAULT)?;
        while !input.is_empty() {
            let (range, offset, remaining) = self.locate(base, address)?;
            let bytes = remaining.min(input.len());
            range.write(offset, &input[..bytes])?;
            input = &input[bytes..];
            address += bytes as u64;
        }
        Ok(())
    }

    pub(crate) fn flush(&self, base: u64, mut address: u64, mut length: usize) -> Result {
        address.checked_add(length as u64).ok_or(EFAULT)?;
        while length != 0 {
            let (range, offset, remaining) = self.locate(base, address)?;
            let bytes = remaining.min(length);
            range.flush(offset, bytes)?;
            length -= bytes;
            address += bytes as u64;
        }
        Ok(())
    }

    pub(crate) fn compare_exchange(
        &self,
        base: u64,
        address: u64,
        current: u64,
        new: u64,
    ) -> Result<u64> {
        let (range, offset, _) = self.locate(base, address)?;
        range.compare_exchange(offset, current, new)
    }

    pub(crate) fn fetch_add(&self, base: u64, address: u64, value: u64) -> Result<u64> {
        let (range, offset, _) = self.locate(base, address)?;
        range.fetch_add(offset, value)
    }

    pub(crate) fn store_release(&self, base: u64, address: u64, value: u64) -> Result {
        let (range, offset, _) = self.locate(base, address)?;
        range.store_release(offset, value)
    }

    /// Returns the granularity of the next published translation.
    pub(crate) fn pending_page_size(&self) -> usize {
        if self.mapped {
            self.pending.as_ref().unwrap().page_size
        } else {
            self.active.page_size
        }
    }

    /// Retains one immutable capture for validation outside the region lock.
    pub(crate) fn pending_range(&self, index: usize) -> Option<Range<DeviceData>> {
        let table = if self.mapped {
            self.pending.as_ref()?
        } else {
            &self.active
        };
        table.pages.get(index).cloned()
    }
}

impl Table {
    /// Starts a pending replacement without changing the active translation.
    pub(crate) fn begin(&mut self, max_pages: usize, page_size: usize) -> Result {
        if !page_size.is_power_of_two() {
            return Err(EINVAL);
        }
        let max_entries = max_pages
            .checked_mul((page_size / PAGE_SIZE).max(1))
            .ok_or(ENOMEM)?;
        self.pages
            .reserve(max_entries.saturating_sub(self.pages.len()), GFP_ATOMIC)?;
        self.pages.clear();
        self.page_size = page_size;
        self.max_entries = max_entries;
        Ok(())
    }

    /// Captures one registration page, splitting large pages into bounded handles.
    ///
    /// Failure drops every handle added for this page. Earlier pages remain available for the
    /// partial mapping result returned by the core's scatterlist walker.
    pub(crate) fn push(&mut self, device: &RdmaDevice<DeviceData>, address: u64) -> Result {
        let count = (self.page_size / PAGE_SIZE).max(1);
        let size = self.page_size.min(PAGE_SIZE);
        let first = self.pages.len();
        if count > self.max_entries - first {
            return Err(ENOMEM);
        }
        address
            .checked_add(self.page_size as u64 - 1)
            .ok_or(EFAULT)?;
        let dma = device.virtual_dma()?;
        for i in 0..count {
            let result = dma
                .capture(address + (i * PAGE_SIZE) as u64, size)
                .and_then(|range| self.pages.push_within_capacity(range).map_err(|_| ENOMEM));
            if let Err(error) = result {
                self.pages.truncate(first);
                return Err(error);
            }
        }
        Ok(())
    }
}

// Registration starts inside its first translation page. Only its actual bytes need backing.
pub(super) fn persistent_segments(
    page_size: usize,
    address: u64,
    mut length: u64,
    mut check: impl FnMut(usize, usize, usize) -> bool,
) -> bool {
    let size = page_size.min(PAGE_SIZE);
    let mut position = address & (page_size as u64 - 1);
    while length != 0 {
        let Ok(index) = usize::try_from(position / size as u64) else {
            return false;
        };
        let offset = (position % size as u64) as usize;
        let bytes = length.min((size - offset) as u64) as usize;
        if !check(index, offset, bytes) {
            return false;
        }
        length -= bytes as u64;
        let Some(next) = position.checked_add(bytes as u64) else {
            return false;
        };
        position = next;
    }
    true
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_mr_fast)]
mod tests {
    use super::*;

    #[test]
    fn persistent_registration_excludes_page_padding() {
        let mut checked = 0;
        assert!(persistent_segments(
            PAGE_SIZE,
            3,
            (PAGE_SIZE - 5) as u64,
            |index, offset, size| {
                checked += 1;
                (index, offset, size) == (0, 3, PAGE_SIZE - 5)
            }
        ));
        assert_eq!(checked, 1);
        let mut checked = 0;
        assert!(persistent_segments(
            2 * PAGE_SIZE,
            (PAGE_SIZE - 3) as u64,
            8,
            |index, offset, size| {
                checked += 1;
                match index {
                    0 => (offset, size) == (PAGE_SIZE - 3, 3),
                    1 => (offset, size) == (0, 5),
                    _ => false,
                }
            }
        ));
        assert_eq!(checked, 2);
        assert!(!persistent_segments(
            PAGE_SIZE,
            0,
            (2 * PAGE_SIZE) as u64,
            |index, _, _| index == 0
        ));
    }

    #[test]
    fn pending_mapping_does_not_change_active_translation_geometry() -> Result {
        let mut memory = FastMemory::new(1)?;
        let (mut pending, max_pages) = memory.take_pending(false)?;
        pending.begin(max_pages, PAGE_SIZE / 2)?;
        memory.restore_pending(pending, true);
        memory.finish_mapping(true);
        memory.publish();
        assert_eq!(memory.active.page_size, PAGE_SIZE / 2);

        let (mut pending, max_pages) = memory.take_pending(false)?;
        pending.begin(max_pages, PAGE_SIZE * 2)?;
        assert_eq!(pending.begin(max_pages, 3), Err(EINVAL));
        memory.restore_pending(pending, true);
        assert_eq!(memory.active.page_size, PAGE_SIZE / 2);
        assert_eq!(memory.pending.as_ref().unwrap().page_size, PAGE_SIZE * 2);
        assert_eq!(memory.active.page_size, PAGE_SIZE / 2);
        assert_eq!(memory.pending.as_ref().unwrap().page_size, PAGE_SIZE * 2);

        memory.finish_mapping(true);
        memory.publish();
        assert_eq!(memory.active.page_size, PAGE_SIZE * 2);
        // Invalidating and registering again without another map preserves the translation.
        memory.finish_mapping(true);
        memory.publish();
        assert_eq!(memory.active.page_size, PAGE_SIZE * 2);
        Ok(())
    }
}
