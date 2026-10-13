// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Queue layout and shared storage, independent of core callback pointers.

#![forbid(unsafe_code)]

use kernel::{
    alloc::KVVec,
    mm::shared::SharedVmalloc,
    prelude::*,
    rdma::CompletionId,
    sync::atomic::{
        Acquire,
        Release, //
    }, //
    sync::SpinLockIrq,
};

// The userspace queue ABI reserves three 128-byte regions before the slots.
pub(super) const HEADER_SIZE: usize = 384;
pub(super) const PRODUCER_OFFSET: usize = 128;
pub(super) const CONSUMER_OFFSET: usize = 256;

type CompletionSlots = SpinLockIrq<KVVec<Option<CompletionId>>>;

pub(super) struct Storage {
    memory: SharedVmalloc,
    completions: Option<Pin<KBox<CompletionSlots>>>,
    elem_size: usize,
    shift: u32,
    mask: u32,
    size: usize,
}

impl Storage {
    pub(super) fn new(count: u32, elem_size: u32, cache_line: u32) -> Result<Self> {
        let stride = elem_size
            .max(cache_line)
            .checked_next_power_of_two()
            .ok_or(EINVAL)?;
        let slots = count
            .checked_add(1)
            .and_then(u32::checked_next_power_of_two)
            .ok_or(EINVAL)?;
        let size = (slots as usize)
            .checked_mul(stride as usize)
            .and_then(|n| n.checked_add(HEADER_SIZE))
            .ok_or(EINVAL)?;
        let memory = SharedVmalloc::new(size)?;
        memory
            .atomic_u32(0)?
            .store(stride.trailing_zeros(), Release);
        memory.atomic_u32(4)?.store(slots - 1, Release);
        Ok(Self {
            memory,
            completions: None,
            elem_size: elem_size as usize,
            shift: stride.trailing_zeros(),
            mask: slots - 1,
            size,
        })
    }

    /// Preallocates private completion capabilities for a kernel work queue.
    pub(super) fn prepare_native(&mut self) -> Result {
        let slots = KVVec::from_elem(None, self.mask as usize + 1, GFP_KERNEL)?;
        self.completions = Some(KBox::pin_init(
            kernel::new_spinlock_irq!(slots),
            GFP_KERNEL,
        )?);
        Ok(())
    }

    /// Publishes the accepted request's capability before its producer index.
    pub(super) fn publish_id(&self, index: u32, id: CompletionId) {
        if let Some(slots) = &self.completions {
            slots.lock()[(index & self.mask) as usize] = Some(id);
        }
    }

    /// Captures private provenance, or an untrusted userspace scalar identifier.
    pub(super) fn completion_id(&self, index: u32, value: u64) -> CompletionId {
        self.completions
            .as_ref()
            .and_then(|slots| slots.lock()[(index & self.mask) as usize].clone())
            .unwrap_or_else(|| CompletionId::user(value))
    }

    pub(super) fn memory(&self) -> &SharedVmalloc {
        &self.memory
    }

    pub(super) fn mask(&self) -> u32 {
        self.mask
    }

    pub(super) fn producer(&self) -> u32 {
        // The allocation includes the complete ABI header and cannot shrink.
        self.memory
            .atomic_u32(PRODUCER_OFFSET)
            .expect("queue header")
            .load(Acquire)
    }

    pub(super) fn consumer(&self) -> u32 {
        self.memory
            .atomic_u32(CONSUMER_OFFSET)
            .expect("queue header")
            .load(Acquire)
    }

    pub(super) fn publish_producer(&self, index: u32) {
        self.memory
            .atomic_u32(PRODUCER_OFFSET)
            .expect("queue header")
            .store(index & self.mask, Release);
    }

    pub(super) fn publish_consumer(&self, index: u32) {
        self.memory
            .atomic_u32(CONSUMER_OFFSET)
            .expect("queue header")
            .store(index & self.mask, Release);
    }

    pub(super) fn offset(&self, index: u32) -> usize {
        HEADER_SIZE + (((index & self.mask) as usize) << self.shift)
    }

    pub(super) fn reset(&self) -> Result {
        self.memory.fill(HEADER_SIZE, self.size - HEADER_SIZE, 0)?;
        if let Some(slots) = &self.completions {
            slots.lock().fill(None);
        }
        Ok(())
    }

    /// Copies part of a slot without crossing its configured element size.
    pub(super) fn read(&self, index: u32, offset: usize, dst: &mut [u8]) -> Result {
        if offset
            .checked_add(dst.len())
            .is_none_or(|end| end > self.elem_size)
        {
            return Err(EINVAL);
        }
        self.memory.read(self.offset(index) + offset, dst)
    }

    /// Writes part of a slot without crossing its configured element size.
    pub(super) fn write(&self, index: u32, offset: usize, src: &[u8]) -> Result {
        if offset
            .checked_add(src.len())
            .is_none_or(|end| end > self.elem_size)
        {
            return Err(EINVAL);
        }
        self.memory.write(self.offset(index) + offset, src)
    }

    /// Copies one slot during resize without borrowing either shared allocation.
    pub(super) fn copy_slot(&self, index: u32, target: &Self, target_index: u32) -> Result {
        if target.elem_size > 1usize << self.shift {
            return Err(EINVAL);
        }
        let mut chunk = [0u8; 128];
        let mut copied = 0;
        while copied < target.elem_size {
            let len = chunk.len().min(target.elem_size - copied);
            self.memory
                .read(self.offset(index) + copied, &mut chunk[..len])?;
            target
                .memory
                .write(target.offset(target_index) + copied, &chunk[..len])?;
            copied += len;
        }
        if let Some(slots) = &self.completions {
            let id = slots.lock()[(index & self.mask) as usize].clone();
            if let Some(target_slots) = &target.completions {
                target_slots.lock()[(target_index & target.mask) as usize] = id;
            }
        }
        Ok(())
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_ring_completion)]
mod tests {
    use super::*;

    #[test]
    fn private_identifiers_ignore_slot_bytes_and_survive_copy() -> Result {
        let mut source = Storage::new(3, 8, 64)?;
        let mut target = Storage::new(7, 8, 64)?;
        source.prepare_native()?;
        target.prepare_native()?;
        source.write(3, 0, &7u64.to_ne_bytes())?;
        source.publish_id(3, CompletionId::user(41));
        assert_eq!(source.completion_id(3, 7).value(), 41);
        source.copy_slot(3, &target, 0)?;
        source.publish_id(3, CompletionId::user(42));
        assert_eq!(target.completion_id(0, 7).value(), 41);
        source.reset()?;
        assert_eq!(source.completion_id(3, 7).value(), 7);
        assert_eq!(target.completion_id(0, 7).value(), 41);
        Ok(())
    }
}
