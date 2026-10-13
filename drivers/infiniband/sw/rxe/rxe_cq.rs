// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Owned completion storage and one-shot notification policy.

#![forbid(unsafe_code)]

use crate::{
    rxe_completion::{
        Record,
        USER_BYTES, //
    },
    rxe_context::Context,
    rxe_device::DeviceData,
    rxe_id::Identities,
    rxe_mmap::{
        Mappings,
        Pending, //
    },
    rxe_param as params,
    rxe_queue::Queue as UserRing,
    rxe_types::QueueType,
    rxe_uapi, //
};
use kernel::{
    prelude::*,
    ratelimit::RateLimiter,
    rdma::{
        Completion,
        CompletionAttributes,
        CompletionCapacity,
        CompletionCreation,
        CompletionNotify,
        CompletionOutput,
        CompletionQueue as CoreQueue,
        ContextData,
        QueuePairIdentity, //
    },
    sync::{
        Mutex,
        SpinLockIrq, //
    },
    types::ScopeGuard,
    uaccess::UserSliceWriter, //
};

#[derive(Default)]
struct Notification {
    next: bool,
    solicited: bool,
}

impl Notification {
    fn arm(&mut self, next: bool, solicited: bool) {
        self.next |= next;
        self.solicited |= solicited;
    }

    fn publish(&mut self, solicited: bool) -> bool {
        if !self.next && !(self.solicited && solicited) {
            return false;
        }
        self.next = false;
        self.solicited = false;
        true
    }
}

/// Private kernel entries, moved without byte copies or references into mapped storage.
struct KernelRing<T> {
    slots: VVec<Option<T>>,
    producer: u32,
    consumer: u32,
    mask: u32,
}

impl<T> KernelRing<T> {
    fn new(count: u32) -> Result<Self> {
        let slots = count
            .checked_add(1)
            .and_then(u32::checked_next_power_of_two)
            .ok_or(EINVAL)?;
        let mut entries = VVec::with_capacity(slots as usize, GFP_KERNEL)?;
        for _ in 0..slots {
            entries.push(None, GFP_KERNEL)?;
        }
        Ok(Self {
            slots: entries,
            producer: 0,
            consumer: 0,
            mask: slots - 1,
        })
    }

    fn queued(&self) -> u32 {
        self.producer.wrapping_sub(self.consumer) & self.mask
    }

    fn push(&mut self, entry: T) -> Result {
        if self.queued() == self.mask {
            return Err(EBUSY);
        }
        self.slots[self.producer as usize] = Some(entry);
        self.producer = self.producer.wrapping_add(1) & self.mask;
        Ok(())
    }

    fn pop(&mut self) -> Option<T> {
        if self.queued() == 0 {
            return None;
        }
        let entry = self.slots[self.consumer as usize].take();
        self.consumer = self.consumer.wrapping_add(1) & self.mask;
        entry
    }

    #[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
    fn resize(&mut self, replacement: &mut Self) -> Result {
        let count = self.queued();
        if count > replacement.mask {
            return Err(EINVAL);
        }
        for index in 0..count {
            replacement.slots[index as usize] = self.slots[self.consumer as usize].take();
            self.consumer = self.consumer.wrapping_add(1) & self.mask;
        }
        replacement.producer = count;
        core::mem::swap(self, replacement);
        Ok(())
    }
}

enum Storage {
    Kernel(KernelRing<Completion>),
    User(KBox<UserRing>),
}

impl Storage {
    fn new(entries: u32, user: bool) -> Result<Self> {
        if entries > params::RXE_MAX_CQE {
            return Err(EINVAL);
        }
        if user {
            Ok(Self::User(UserRing::new(
                entries,
                Completion::CORE_SIZE as u32,
                QueueType::ToClient,
                kernel::cpu::cache_line_size(),
            )?))
        } else {
            Ok(Self::Kernel(KernelRing::new(entries)?))
        }
    }

    fn capacity(&self) -> Result<CompletionCapacity> {
        CompletionCapacity::new(match self {
            Self::Kernel(ring) => ring.mask,
            Self::User(ring) => ring.index_mask,
        })
    }

    fn queued(&self) -> u32 {
        match self {
            Self::Kernel(ring) => ring.queued(),
            Self::User(ring) => {
                ring.index.wrapping_sub(ring.storage().consumer()) & ring.index_mask
            }
        }
    }

    fn prepare_mapping(
        &self,
        mappings: &Mappings,
        context: Option<&Context>,
        output: Option<UserSliceWriter>,
    ) -> Result<Option<Pending>> {
        let Some(mut output) = output else {
            return Ok(None);
        };
        let Self::User(ring) = self else {
            return Err(EINVAL);
        };
        let pending = mappings.prepare(context.ok_or(EINVAL)?, ring.storage().memory())?;
        pending.descriptor().write(&mut output)?;
        Ok(Some(pending))
    }

    fn publish_mapping(&mut self, mappings: &Mappings, pending: Option<Pending>) {
        if let (Self::User(ring), Some(pending)) = (self, pending) {
            ring.mapping = Some(mappings.publish(pending));
        }
    }

    fn cancel_mapping(&mut self, mappings: &Mappings) {
        if let Self::User(ring) = self {
            ring.cancel_mapping(mappings);
        }
    }

    fn mask(&self) -> u32 {
        match self {
            Self::Kernel(ring) => ring.mask,
            Self::User(ring) => ring.index_mask,
        }
    }

    fn producer(&self) -> u32 {
        match self {
            Self::Kernel(ring) => ring.producer,
            Self::User(ring) => ring.index,
        }
    }

    fn consumer(&self) -> u32 {
        match self {
            Self::Kernel(ring) => ring.consumer,
            Self::User(ring) => ring.storage().consumer() & ring.index_mask,
        }
    }

    fn copy_slot(&self, index: u32, target: &mut Self, position: u32) -> Result {
        match (self, target) {
            (Self::Kernel(ring), Self::Kernel(target)) => {
                target.slots[(position & target.mask) as usize] =
                    ring.slots[(index & ring.mask) as usize].clone();
                Ok(())
            }
            (Self::User(ring), Self::User(target)) => {
                ring.storage().copy_slot(index, target.storage(), position)
            }
            _ => Err(EINVAL),
        }
    }

    fn set_indices(&mut self, consumer: u32, producer: u32) {
        match self {
            Self::Kernel(ring) => {
                ring.consumer = consumer & ring.mask;
                ring.producer = producer & ring.mask;
            }
            Self::User(ring) => {
                ring.index = producer & ring.index_mask;
                ring.storage().publish_consumer(consumer);
                ring.storage().publish_producer(producer);
            }
        }
    }

    fn write_slot(&mut self, index: u32, qp: QueuePairIdentity, record: &Record) -> Result {
        match self {
            Self::Kernel(ring) => {
                ring.slots[(index & ring.mask) as usize] =
                    Some(Completion::new(qp, record.kernel_data()));
                Ok(())
            }
            Self::User(ring) => {
                let mut bytes = [0; Completion::CORE_SIZE];
                bytes[..USER_BYTES].copy_from_slice(&record.user_bytes(qp.number()));
                ring.storage().write(index, 0, &bytes)
            }
        }
    }

    fn post(&mut self, qp: QueuePairIdentity, record: &Record) -> Result {
        match self {
            Self::Kernel(ring) => ring.push(Completion::new(qp, record.kernel_data())),
            Self::User(ring) => {
                let next = ring.index.wrapping_add(1) & ring.index_mask;
                if next == ring.storage().consumer() & ring.index_mask {
                    return Err(EBUSY);
                }
                // Keep the established slot stride, but initialize only scalar ABI bytes.
                let mut bytes = [0; Completion::CORE_SIZE];
                bytes[..USER_BYTES].copy_from_slice(&record.user_bytes(qp.number()));
                ring.storage().write(ring.index, 0, &bytes)?;
                ring.index = next;
                ring.storage().publish_producer(next);
                Ok(())
            }
        }
    }
}

/// An unpublished replacement mirroring arrivals while the original ring remains usable.
///
/// Positions count forward from the original consumer. Only entries present at the start
/// need copying; later posts are mirrored directly. The original ring remains authoritative
/// until commit, so a failed shrink cannot lose a completion or interrupt polling.
struct Migration {
    replacement: Storage,
    origin: u32,
    initial: u64,
    copied: u64,
    producer: u64,
    failure: Option<Error>,
}

impl Migration {
    const BATCH: u64 = 32;

    fn new(replacement: Storage, original: &Storage) -> Self {
        let origin = original.consumer();
        let count = u64::from(original.producer().wrapping_sub(origin) & original.mask());
        Self {
            replacement,
            origin,
            initial: count,
            copied: 0,
            producer: count,
            failure: None,
        }
    }

    fn consumer(&self, original: &Storage) -> Result<u64> {
        let queued = original.queued();
        if queued > self.replacement.mask() {
            return Err(EINVAL);
        }
        self.producer.checked_sub(u64::from(queued)).ok_or(EINVAL)
    }

    fn posted(&mut self, original: &Storage, write: impl FnOnce(&mut Storage, u32) -> Result) {
        if self.failure.is_some() {
            return;
        }
        let result = (|| {
            let position = self.producer;
            self.producer = self.producer.checked_add(1).ok_or(EOVERFLOW)?;
            self.consumer(original)?;
            write(&mut self.replacement, position as u32)
        })();
        self.failure = result.err();
    }

    /// Drops a copied entry while polling still owns the original completion.
    fn polled(&mut self, remaining: u32) {
        if self.failure.is_some() {
            return;
        }
        // Successful migration tracks every post, including ones after the initial batch.
        // The just-consumed position precedes the remaining live range by one entry.
        let position = self.producer - u64::from(remaining) - 1;
        if let Storage::Kernel(ring) = &mut self.replacement {
            ring.slots[(position as u32 & ring.mask) as usize] = None;
        }
    }

    fn step(&mut self, original: &Storage) -> Result<bool> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        // Consumed initial entries need not be copied and may already have been overwritten.
        self.copied = self.copied.max(self.consumer(original)?).min(self.initial);
        let end = (self.copied + Self::BATCH).min(self.initial);
        while self.copied < end {
            original.copy_slot(
                self.origin.wrapping_add(self.copied as u32),
                &mut self.replacement,
                self.copied as u32,
            )?;
            self.copied += 1;
        }
        Ok(self.copied == self.initial)
    }

    fn commit(&mut self, original: &mut Storage) -> Result {
        let consumer = self.consumer(original)?;
        self.replacement
            .set_indices(consumer as u32, self.producer as u32);
        if let Storage::User(ring) = original {
            ring.storage().publish_consumer(ring.index);
        }
        core::mem::swap(original, &mut self.replacement);
        Ok(())
    }
}

fn response<'a>(
    data: Option<ContextData<'a, DeviceData>>,
) -> Result<(Option<&'a Context>, Option<UserSliceWriter>)> {
    let Some(data) = data else {
        return Ok((None, None));
    };
    let (context, data) = data.split();
    let present = data.has_output_buffer();
    let (_, output) = data.split();
    if output.len() < rxe_uapi::MAPPING_SIZE {
        return Err(EINVAL);
    }
    Ok((Some(context), present.then_some(output)))
}

#[pin_data]
pub(crate) struct Queues {
    #[pin]
    numbers: Mutex<Identities>,
}

impl Queues {
    pub(crate) fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            numbers <- kernel::new_mutex!(Identities::new(
                1, params::RXE_MAX_CQ, params::RXE_MAX_CQ,
            )),
        })
    }

    pub(crate) fn create(
        &self,
        mappings: &Mappings,
        attributes: CompletionAttributes,
        data: Option<ContextData<'_, DeviceData>>,
    ) -> Result<CompletionCreation<Pin<KBox<Queue>>>> {
        let (context, output) = response(data)?;
        let user = output.is_some();
        if attributes.flags != 0 {
            return Err(EOPNOTSUPP);
        }
        let storage = Storage::new(attributes.entries, user)?;
        let capacity = storage.capacity()?;
        let pending = storage.prepare_mapping(mappings, context, output)?;
        let number = self.numbers.lock().allocate()?;
        let reservation = ScopeGuard::new(|| self.numbers.lock().release(number));
        let queue = KBox::pin_init(
            try_pin_init!(Queue {
                number,
                user,
                log_limit <- RateLimiter::new(),
                state <- kernel::new_spinlock_irq!(State {
                    storage,
                    notification: Notification::default(),
                    migration: None,
                }),
            }),
            GFP_KERNEL,
        )?;
        queue
            .state
            .lock()
            .storage
            .publish_mapping(mappings, pending);
        reservation.dismiss();
        Ok(CompletionCreation {
            owner: queue,
            capacity,
        })
    }

    pub(crate) fn release(&self, mappings: &Mappings, queue: Pin<KBox<Queue>>) {
        let number = queue.number;
        let mapping = match &mut queue.state.lock().storage {
            Storage::User(ring) => ring.mapping.take(),
            Storage::Kernel(_) => None,
        };
        if let Some(mapping) = mapping {
            mappings.cancel(mapping);
        }
        // Core QPs and the adapter's dispatcher have drained. Neither storage disposal nor
        // identity release runs while interrupts are disabled by the queue lock.
        drop(queue);
        self.numbers.lock().release(number);
    }
}

struct State {
    storage: Storage,
    notification: Notification,
    migration: Option<Migration>,
}

/// Core-owned CQ state. Resize allocation and disposal happen outside its queue lock.
#[pin_data]
pub(crate) struct Queue {
    number: u32,
    user: bool,
    #[pin]
    log_limit: RateLimiter,
    #[pin]
    state: SpinLockIrq<State>,
}

impl Queue {
    pub(crate) fn is_user(&self) -> bool {
        self.user
    }

    pub(crate) fn resize(
        &self,
        mappings: &Mappings,
        entries: u32,
        data: Option<ContextData<'_, DeviceData>>,
    ) -> Result<CompletionCapacity> {
        let (context, output) = response(data)?;
        let replacement = Storage::new(entries, self.user)?;
        let capacity = replacement.capacity()?;
        let pending = replacement.prepare_mapping(mappings, context, output)?;
        {
            let mut state = self.state.lock();
            if state.storage.queued() > replacement.mask() {
                return Err(EINVAL);
            }
            // The core adapter serializes resize calls through capacity publication.
            state.migration = Some(Migration::new(replacement, &state.storage));
        }
        let (mut replacement, result) = loop {
            let mut state = self.state.lock();
            let State {
                storage, migration, ..
            } = &mut *state;
            // Dropping the guard between bounded batches admits polling and posting.
            match migration.as_mut().unwrap().step(storage) {
                Ok(false) => continue,
                status => {
                    let mut migration = migration.take().unwrap();
                    let result = status.and_then(|_| migration.commit(storage));
                    if result.is_ok() {
                        // Mmap cannot acquire the replacement until every live slot is ready.
                        storage.publish_mapping(mappings, pending);
                    }
                    break (migration.replacement, result);
                }
            }
        };
        // Success returns the old storage; failure keeps the unused replacement.
        replacement.cancel_mapping(mappings);
        drop(replacement);
        result?;
        Ok(capacity)
    }

    pub(crate) fn poll(&self, output: &mut CompletionOutput<'_>) -> Result {
        let mut state = self.state.lock();
        let State {
            storage, migration, ..
        } = &mut *state;
        let Storage::Kernel(ring) = storage else {
            return Err(EINVAL);
        };
        while output.remaining() != 0 {
            let Some(completion) = ring.pop() else { break };
            if let Some(migration) = migration {
                migration.polled(ring.queued());
            }
            // Revoked or duplicate capabilities cannot reach the native callback. Discard
            // them without hiding later valid entries or completions already returned.
            let _ = output.push(completion);
        }
        Ok(())
    }

    pub(crate) fn peek(&self, maximum: u32) -> u32 {
        self.state.lock().storage.queued().min(maximum)
    }

    pub(crate) fn arm(&self, flags: CompletionNotify) -> bool {
        let mut state = self.state.lock();
        state.notification.arm(flags.next, flags.solicited);
        flags.report_missed && state.storage.queued() != 0
    }

    pub(crate) fn post(
        &self,
        core: &CoreQueue<DeviceData>,
        qp: QueuePairIdentity,
        record: &Record,
        solicited: bool,
    ) -> Result {
        let result = {
            let mut state = self.state.lock();
            let result = state.storage.post(qp.clone(), record);
            if result.is_ok() {
                let State {
                    storage, migration, ..
                } = &mut *state;
                if let Some(migration) = migration {
                    migration.posted(storage, |target, index| {
                        target.write_slot(index, qp, record)
                    });
                }
            }
            result.map(|()| state.notification.publish(solicited))
        };
        match result {
            Ok(notify) => {
                if notify {
                    let _ = core.notify();
                }
                Ok(())
            }
            Err(error) => {
                if error == EBUSY {
                    if self.log_limit.allow(c"rxe_cq_post") {
                        kernel::dev_err!(
                            core.device(),
                            "cq#{} rxe_cq_post: queue full\n",
                            self.number
                        );
                    }
                    let _ = core.error();
                }
                Err(error)
            }
        }
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_cq)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_kernel_entries_move_in_order_and_failed_shrink_preserves_them() -> Result {
        let mut ring = KernelRing::new(3)?;
        for id in 0..3 {
            ring.push(id)?;
        }
        assert_eq!(ring.push(99), Err(EBUSY));
        assert_eq!(ring.pop(), Some(0));
        assert_eq!(ring.pop(), Some(1));
        ring.push(3)?;
        ring.push(4)?;
        let mut small = KernelRing::new(1)?;
        assert_eq!(ring.resize(&mut small), Err(EINVAL));
        assert_eq!(ring.queued(), 3);
        let mut large = KernelRing::new(7)?;
        ring.resize(&mut large)?;
        for id in 2..5 {
            assert_eq!(ring.pop(), Some(id));
        }
        assert_eq!(ring.pop(), None);
        ring.resize(&mut small)?;
        ring.push(5)?;
        assert_eq!(ring.push(6), Err(EBUSY));
        assert_eq!(ring.pop(), Some(5));
        let mut zero = KernelRing::new(0)?;
        assert_eq!(zero.push(1), Err(EBUSY));
        assert_eq!(zero.pop(), None);
        Ok(())
    }

    fn write_user(storage: &mut Storage, index: u32, value: u64) -> Result {
        let Storage::User(ring) = storage else {
            return Err(EINVAL);
        };
        ring.storage().write(index, 0, &value.to_ne_bytes())
    }

    fn push_user(storage: &mut Storage, migration: Option<&mut Migration>, value: u64) -> Result {
        if storage.queued() == storage.mask() {
            return Err(EBUSY);
        }
        let producer = storage.producer();
        write_user(storage, producer, value)?;
        storage.set_indices(storage.consumer(), producer.wrapping_add(1));
        if let Some(migration) = migration {
            migration.posted(storage, |target, position| {
                write_user(target, position, value)
            });
        }
        Ok(())
    }

    fn pop_user(storage: &mut Storage) -> Result<Option<u64>> {
        if storage.queued() == 0 {
            return Ok(None);
        }
        let Storage::User(ring) = storage else {
            return Err(EINVAL);
        };
        let consumer = ring.storage().consumer();
        let mut bytes = [0; 8];
        ring.storage().read(consumer, 0, &mut bytes)?;
        ring.storage().publish_consumer(consumer.wrapping_add(1));
        Ok(Some(u64::from_ne_bytes(bytes)))
    }

    #[test]
    fn resize_copies_wrapped_entries_while_polling_and_posting_continue() -> Result {
        let mut original = Storage::new(127, true)?;
        for value in 0..100 {
            push_user(&mut original, None, value)?;
        }
        for value in 0..80 {
            assert_eq!(pop_user(&mut original)?, Some(value));
        }
        for value in 100..180 {
            push_user(&mut original, None, value)?;
        }
        let mut migration = Migration::new(Storage::new(255, true)?, &original);
        assert!(!migration.step(&original)?);
        for value in 80..130 {
            assert_eq!(pop_user(&mut original)?, Some(value));
        }
        for value in 180..240 {
            push_user(&mut original, Some(&mut migration), value)?;
        }
        // Userspace cannot redefine the kernel producer by changing its mapped copy.
        if let Storage::User(ring) = &original {
            ring.storage().publish_producer(u32::MAX);
        }
        while !migration.step(&original)? {}
        migration.commit(&mut original)?;
        for value in 130..240 {
            assert_eq!(pop_user(&mut original)?, Some(value));
        }
        assert_eq!(pop_user(&mut original)?, None);
        Ok(())
    }

    #[test]
    fn failed_shrink_keeps_every_completion_in_original_queue() -> Result {
        let mut original = Storage::new(127, true)?;
        for value in 0..40 {
            push_user(&mut original, None, value)?;
        }
        let mut migration = Migration::new(Storage::new(63, true)?, &original);
        assert!(!migration.step(&original)?);
        for value in 40..70 {
            push_user(&mut original, Some(&mut migration), value)?;
        }
        assert_eq!(migration.step(&original), Err(EINVAL));
        drop(migration);
        for value in 0..70 {
            assert_eq!(pop_user(&mut original)?, Some(value));
        }
        assert_eq!(pop_user(&mut original)?, None);
        Ok(())
    }

    #[test]
    fn resize_skips_consumed_slots_after_original_ring_reuse() -> Result {
        let mut original = Storage::new(127, true)?;
        for value in 0..70 {
            push_user(&mut original, None, value)?;
        }
        let mut migration = Migration::new(Storage::new(127, true)?, &original);
        assert!(!migration.step(&original)?);
        for value in 0..70 {
            assert_eq!(pop_user(&mut original)?, Some(value));
        }
        for value in 70..300 {
            push_user(&mut original, Some(&mut migration), value)?;
            if value < 280 {
                assert_eq!(pop_user(&mut original)?, Some(value));
            }
        }
        assert!(migration.step(&original)?);
        migration.commit(&mut original)?;
        for value in 280..300 {
            assert_eq!(pop_user(&mut original)?, Some(value));
        }
        assert_eq!(pop_user(&mut original)?, None);
        Ok(())
    }

    #[test]
    fn notification_is_one_shot_and_next_dominates_solicited() {
        let mut notification = Notification::default();
        notification.arm(false, true);
        assert!(!notification.publish(false));
        assert!(notification.publish(true));
        assert!(!notification.publish(true));
        notification.arm(true, false);
        notification.arm(false, true);
        assert!(notification.publish(false));
        assert!(!notification.publish(true));
    }
}
