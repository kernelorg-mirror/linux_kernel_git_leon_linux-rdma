// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Shared receive queue attributes and backing storage.

#![forbid(unsafe_code)]

use crate::{
    rxe_device::DeviceData,
    rxe_id::Identities,
    rxe_mmap::Mappings,
    rxe_param as params,
    rxe_queue::Queue as Ring,
    rxe_submission::Submission,
    rxe_types::QueueType,
    rxe_uapi,
    rxe_wqe::{
        ReceiveFailure,
        ReceiveWqe,
        RECV_HEADER_SIZE,
        SGE_SIZE, //
    }, //
};
use kernel::{
    prelude::*,
    rdma::{
        ContextData,
        ReceiveRequests,
        SharedReceiveAttributes,
        SharedReceiveChange, //
    },
    sync::{
        CondVar,
        Mutex,
        SpinLockIrq, //
    },
    types::ScopeGuard, //
};

const MIN_WR: u32 = params::RXE_MIN_SRQ_WR;
const MIN_SGE: u32 = params::RXE_MIN_SRQ_SGE;

/// Immutable device limits used to validate SRQ requests.
struct Limits {
    max_wr: u32,
    max_sge: u32,
}

/// Queue capacity copied from creation attributes.
struct Capacity {
    max_wr: u32,
    max_sge: u32,
}

/// Requested changes; absent fields are neither read nor validated.
struct Change {
    max_wr: Option<u32>,
    limit: Option<u32>,
}

/// Checks and rounds requested capacity before allocating backing storage.
fn check_init(limits: Limits, attr: &mut Capacity) -> Result {
    if attr.max_wr == 0 || attr.max_wr > limits.max_wr {
        return Err(EINVAL);
    }
    attr.max_wr = attr.max_wr.max(MIN_WR);
    if attr.max_sge > limits.max_sge {
        return Err(EINVAL);
    }
    attr.max_sge = attr.max_sge.max(MIN_SGE);
    Ok(())
}

/// Values sampled while the caller serializes SRQ attribute changes.
struct Attributes {
    max_wr: u32,
    limit: u32,
    capacity: u32,
}

impl Attributes {
    /// Checks capacity and notification changes against the existing queue.
    fn check(&self, change: &mut Change) -> Result {
        let mut capacity = self.capacity;
        if let Some(count) = &mut change.max_wr {
            if *count == 0 || *count > self.max_wr {
                return Err(EINVAL);
            }
            *count = (*count).max(MIN_WR);
            capacity = count
                .checked_add(1)
                .and_then(u32::checked_next_power_of_two)
                .ok_or(EINVAL)?
                - 1;
        }
        let limit = change.limit.unwrap_or(self.limit);
        if limit > self.max_wr || limit > capacity {
            return Err(EINVAL);
        }
        Ok(())
    }
}

/// One-shot notification state, borrowed only while the SRQ consumer lock is held.
#[derive(Zeroable)]
struct Notification {
    limit: u32,
}

impl Notification {
    fn limit(&self) -> u32 {
        self.limit
    }

    fn arm(&mut self, limit: u32) {
        self.limit = limit;
    }

    /// Consumes the armed threshold only when a callback will be delivered.
    fn take(&mut self, remaining: u32, has_handler: bool) -> bool {
        if self.limit == 0 || !has_handler || remaining >= self.limit {
            return false;
        }
        self.limit = 0;
        true
    }
}

/// Allocates identities while the RDMA core owns each queue's pinned state.
#[pin_data]
pub(crate) struct Queues {
    #[pin]
    numbers: Mutex<Identities>,
}

impl Queues {
    pub(crate) fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            numbers <- kernel::new_mutex!(Identities::new(
                params::RXE_MIN_SRQ_INDEX,
                params::RXE_MAX_SRQ_INDEX,
                params::RXE_MAX_SRQ,
            )),
        })
    }

    pub(crate) fn create(
        &self,
        mappings: &Mappings,
        attr: &mut SharedReceiveAttributes,
        data: Option<ContextData<'_, DeviceData>>,
    ) -> Result<Pin<KBox<SharedReceive>>> {
        let (context, output) = if let Some(data) = data {
            let (context, data) = data.split();
            let present = data.has_output_buffer();
            let (_, output) = data.split();
            if output.len() < rxe_uapi::SRQ_RESPONSE_SIZE {
                return Err(EINVAL);
            }
            (Some(context), present.then_some(output))
        } else {
            (None, None)
        };
        let mut capacity = Capacity {
            max_wr: attr.max_wr,
            max_sge: attr.max_sge,
        };
        check_init(
            Limits {
                max_wr: params::RXE_MAX_SRQ_WR,
                max_sge: params::RXE_MAX_SRQ_SGE,
            },
            &mut capacity,
        )?;
        let native = context.is_none();
        let mut ring = new_ring(capacity.max_wr, capacity.max_sge)?;
        if native {
            ring.storage.prepare_native()?;
        }
        let count = ring.index_mask;
        if attr.limit > count || attr.limit > params::RXE_MAX_SRQ_WR {
            return Err(EINVAL);
        }
        let (mut mapping_output, number_output) = rxe_uapi::split_mapping(output)?;
        let pending = if mapping_output.is_some() {
            Some(mappings.prepare(context.ok_or(EINVAL)?, ring.storage().memory())?)
        } else {
            None
        };
        let number = self.numbers.lock().allocate()?;
        let reservation = ScopeGuard::new(|| self.numbers.lock().release(number));
        let mut notification = Notification::zeroed();
        notification.arm(attr.limit);
        let queue = KBox::pin_init(
            try_pin_init!(SharedReceive {
                number,
                native,
                max_sge: capacity.max_sge,
                control <- kernel::new_mutex!(()),
                ready <- kernel::new_condvar!("rxe_srq_resize"),
                state <- kernel::new_spinlock_irq!(QueueState {
                    ring: Some(ring),
                    resizing: false,
                    notification,
                }),
            }),
            GFP_KERNEL,
        )?;
        if let (Some(pending), Some(output)) = (&pending, &mut mapping_output) {
            pending.descriptor().write(output)?;
        }
        rxe_uapi::write_srq_number(number_output, number)?;
        // Every fallible allocation and response copy precedes publication. Failure drops
        // unpublished page owners and queue storage before returning the reserved identity.
        if let Some(pending) = pending {
            queue.state.lock().ring.as_mut().unwrap().mapping = Some(mappings.publish(pending));
        }
        attr.max_wr = count;
        attr.max_sge = capacity.max_sge;
        reservation.dismiss();
        Ok(queue)
    }

    pub(crate) fn release(&self, mappings: &Mappings, queue: Pin<KBox<SharedReceive>>) {
        let number = queue.number;
        let mapping = queue.state.lock().ring.as_mut().unwrap().mapping.take();
        if let Some(mapping) = mapping {
            mappings.cancel(mapping);
        }
        // Core QP references and callback borrows have drained. Release storage outside the
        // queue lock and make the number reusable only after its native owner is gone.
        drop(queue);
        self.numbers.lock().release(number);
    }
}

fn new_ring(count: u32, max_sge: u32) -> Result<KBox<Ring>> {
    Ring::new(
        count,
        (RECV_HEADER_SIZE + max_sge as usize * SGE_SIZE) as u32,
        QueueType::FromClient,
        kernel::cpu::cache_line_size(),
    )
}

struct QueueState {
    ring: Option<KBox<Ring>>,
    resizing: bool,
    notification: Notification,
}

/// Copies a stable consumer prefix while posters can append between bounded batches.
struct Migration {
    copied: u32,
}

impl Migration {
    fn step(&mut self, ring: &Ring, replacement: &Ring) -> Result<Option<u32>> {
        let queued = ring.storage().producer().wrapping_sub(ring.index) & ring.index_mask;
        if queued > replacement.index_mask {
            return Err(EINVAL);
        }
        let end = queued.min(self.copied.saturating_add(32));
        while self.copied < end {
            ring.storage().copy_slot(
                ring.index.wrapping_add(self.copied),
                replacement.storage(),
                self.copied,
            )?;
            self.copied += 1;
        }
        Ok((self.copied >= queued).then_some(queued))
    }
}

/// Owns queue storage and one-shot notification state behind an IRQ-safe lock.
///
/// The control mutex serializes resize and query. Allocation, userspace copies and disposal
/// occur outside the queue lock. The core retains this owner through attached QP destruction;
/// no additional reference-counted allocation or raw queue pointer is needed.
#[pin_data]
pub(crate) struct SharedReceive {
    number: u32,
    native: bool,
    max_sge: u32,
    #[pin]
    control: Mutex<()>,
    #[pin]
    ready: CondVar,
    #[pin]
    state: SpinLockIrq<QueueState>,
}

impl SharedReceive {
    pub(crate) fn query(&self) -> SharedReceiveAttributes {
        let _control = self.control.lock();
        let state = self.state.lock();
        SharedReceiveAttributes {
            max_wr: state.ring.as_ref().unwrap().index_mask,
            max_sge: self.max_sge,
            limit: state.notification.limit(),
        }
    }

    pub(crate) fn modify(
        &self,
        mappings: &Mappings,
        change: &mut SharedReceiveChange,
        data: Option<ContextData<'_, DeviceData>>,
    ) -> Result {
        let (context, data) = match data {
            Some(data) => {
                let (context, data) = data.split();
                (Some(context), Some(data))
            }
            None => (None, None),
        };
        let address = rxe_uapi::modify_srq(data)?;
        let _control = self.control.lock();
        let attributes = {
            let state = self.state.lock();
            Attributes {
                max_wr: params::RXE_MAX_SRQ_WR,
                limit: state.notification.limit(),
                capacity: state.ring.as_ref().unwrap().index_mask,
            }
        };
        let mut checked = Change {
            max_wr: change.max_wr,
            limit: change.limit,
        };
        attributes.check(&mut checked)?;
        if let Some(count) = checked.max_wr {
            let mut replacement = new_ring(count, self.max_sge)?;
            if self.native {
                replacement.storage.prepare_native()?;
            }
            let count = replacement.index_mask;
            let pending = if let Some(mut output) = rxe_uapi::srq_mapping(address) {
                let pending =
                    mappings.prepare(context.ok_or(EINVAL)?, replacement.storage().memory())?;
                pending.descriptor().write(&mut output)?;
                Some(pending)
            } else {
                None
            };
            // Receivers wait while migration fixes the consumer position. Atomic posters
            // keep appending to the original ring between bounded copy batches.
            self.state.lock().resizing = true;
            let mut migration = Migration { copied: 0 };
            let result = loop {
                let mut state = self.state.lock();
                let ring = state.ring.as_mut().unwrap();
                let result = migration.step(ring, &replacement);
                match result {
                    Ok(None) => continue,
                    Ok(Some(queued)) => {
                        replacement.storage().publish_consumer(0);
                        replacement.storage().publish_producer(queued);
                        replacement.index = 0;
                        ring.storage()
                            .publish_consumer(ring.index.wrapping_add(queued));
                        core::mem::swap(ring, &mut replacement);
                        if let Some(pending) = pending {
                            ring.mapping = Some(mappings.publish(pending));
                        }
                        if let Some(limit) = checked.limit.take() {
                            state.notification.arm(limit);
                        }
                    }
                    Err(_) => (),
                }
                state.resizing = false;
                self.ready.notify_all();
                break result.map(|_| ());
            };
            // Success leaves the old storage in replacement; failure leaves the unused new
            // storage there. Both cases cancel its pending map and free it outside the lock.
            replacement.cancel_mapping(mappings);
            drop(replacement);
            result?;
            change.max_wr = Some(count);
        }
        if let Some(limit) = checked.limit {
            self.state.lock().notification.arm(limit);
        }
        Ok(())
    }

    pub(crate) fn post(&self, requests: ReceiveRequests<'_>) -> Result {
        let state = self.state.lock();
        requests.try_for_each(|request| {
            let ring = state.ring.as_ref().unwrap();
            let producer = ring.storage().producer();
            let next = producer.wrapping_add(1) & ring.index_mask;
            if next == ring.storage().consumer() & ring.index_mask {
                return Err(ENOMEM);
            }
            if request.scatter_gather_count() > self.max_sge as c_int {
                return Err(EINVAL);
            }
            let submission = Submission::receive(
                request.id(),
                request.scatter_gather()?,
                self.max_sge as usize,
            )?;
            ring.storage().write(producer, 0, submission.bytes())?;
            // Acceptance follows every fallible step and precedes producer publication.
            ring.storage().publish_id(producer, request.completion_id());
            ring.storage().publish_producer(next);
            Ok(())
        })
    }

    /// Removes one request and reports its decode result and a notification after unlocking.
    ///
    /// Called from a transport worker; it may sleep until an in-progress resize completes.
    pub(crate) fn receive(
        &self,
        has_handler: bool,
    ) -> Option<(Result<ReceiveWqe, ReceiveFailure>, bool)> {
        let mut state = self.state.lock();
        while state.resizing {
            self.ready.wait(&mut state);
        }
        let ring = state.ring.as_mut().unwrap();
        let consumer = ring.index;
        if ring.storage().producer().wrapping_sub(consumer) & ring.index_mask == 0 {
            return None;
        }
        let work = ReceiveWqe::capture(ring.storage(), consumer, self.max_sge);
        // A malformed request belongs to this receiver. Retiring it prevents other QPs
        // from repeatedly selecting the same bad entry and lets later requests progress.
        ring.index = consumer.wrapping_add(1) & ring.index_mask;
        ring.storage().publish_consumer(ring.index);
        let remaining = ring.storage().producer().wrapping_sub(ring.index) & ring.index_mask;
        let notify = state.notification.take(remaining, has_handler);
        Some((work, notify))
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_srq)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_resize_preserves_requests_and_one_shot_notification() -> Result {
        let queues = KBox::pin_init(Queues::new(), GFP_KERNEL)?;
        let mappings = KBox::pin_init(Mappings::new(), GFP_KERNEL)?;
        let mut attr = SharedReceiveAttributes {
            max_wr: 3,
            max_sge: 1,
            limit: 2,
        };
        let queue = queues.create(&mappings, &mut attr, None)?;
        let queue = ScopeGuard::new_with_data(queue, |queue| queues.release(&mappings, queue));
        {
            let mut state = queue.state.lock();
            let ring = state.ring.as_mut().unwrap();
            ring.index = 2;
            for (index, id) in [(2, 101), (3, 102), (0, 103)] {
                let submission = Submission::receive(id, &[], 1)?;
                ring.storage().write(index, 0, submission.bytes())?;
                ring.storage()
                    .publish_id(index, kernel::rdma::CompletionId::user(id + 1000));
            }
            ring.storage().publish_consumer(2);
            ring.storage().publish_producer(1);
        }
        let mut change = SharedReceiveChange {
            max_wr: Some(7),
            limit: None,
            unknown_mask: 0,
        };
        queue.modify(&mappings, &mut change, None)?;
        assert_eq!(queue.query().max_wr, 7);
        for (id, notify) in [(101, false), (102, true), (103, false)] {
            let (work, actual) = queue.receive(true).unwrap();
            assert_eq!(work.map_err(|_| EINVAL)?.id().value(), id + 1000);
            assert_eq!(actual, notify);
        }
        assert!(queue.receive(true).is_none());
        assert_eq!(queue.query().limit, 0);
        Ok(())
    }

    #[test]
    fn malformed_requests_are_retired_and_preserve_limit_notifications() -> Result {
        let queues = KBox::pin_init(Queues::new(), GFP_KERNEL)?;
        let mappings = KBox::pin_init(Mappings::new(), GFP_KERNEL)?;
        let mut attr = SharedReceiveAttributes {
            max_wr: 3,
            max_sge: 1,
            limit: 2,
        };
        let queue = queues.create(&mappings, &mut attr, None)?;
        let queue = ScopeGuard::new_with_data(queue, |queue| queues.release(&mappings, queue));
        {
            let state = queue.state.lock();
            let ring = state.ring.as_ref().unwrap();
            for index in 0..3 {
                let id = u64::from(index) + 100;
                let submission = Submission::receive(id, &[], 1)?;
                ring.storage().write(index, 0, submission.bytes())?;
                ring.storage()
                    .publish_id(index, kernel::rdma::CompletionId::user(id + 1000));
            }
            // Reject an excessive SGE count, then an inconsistent aggregate length.
            ring.storage().write(0, 28, &2u32.to_ne_bytes())?;
            ring.storage().write(1, 16, &1u32.to_ne_bytes())?;
            ring.storage().publish_producer(3);
        }
        for (id, expected_notification) in [(100, false), (101, true)] {
            let (work, notify) = queue.receive(true).unwrap();
            let failure = work.err().unwrap();
            let completion = failure.completion().unwrap();
            assert_eq!(completion.id().value(), id + 1000);
            assert_eq!(completion.capacity(), 0);
            assert_eq!(completion.received(), 0);
            assert_eq!(notify, expected_notification);
        }
        let (work, notify) = queue.receive(true).unwrap();
        assert_eq!(work.map_err(|_| EINVAL)?.id().value(), 1102);
        assert!(!notify);
        assert!(queue.receive(true).is_none());
        assert_eq!(queue.query().limit, 0);
        assert_eq!(queue.state.lock().ring.as_ref().unwrap().index, 3);
        Ok(())
    }

    #[test]
    fn resize_captures_posts_between_batches_and_preserves_failed_shrinks() -> Result {
        let mut ring = new_ring(127, 1)?;
        let mut replacement = new_ring(255, 1)?;
        ring.storage.prepare_native()?;
        replacement.storage.prepare_native()?;
        let append = |id: u64| -> Result {
            let index = ring.storage().producer();
            let submission = Submission::receive(id, &[], 1)?;
            ring.storage().write(index, 0, submission.bytes())?;
            ring.storage()
                .publish_id(index, kernel::rdma::CompletionId::user(id + 1000));
            ring.storage().publish_producer(index + 1);
            Ok(())
        };
        for id in 0..50 {
            append(id)?;
        }
        let mut migration = Migration { copied: 0 };
        assert_eq!(migration.step(&ring, &replacement)?, None);
        for id in 50..75 {
            append(id)?;
        }
        assert_eq!(migration.step(&ring, &replacement)?, None);
        assert_eq!(migration.step(&ring, &replacement)?, Some(75));
        for id in 0..75 {
            assert_eq!(
                ReceiveWqe::read(replacement.storage(), id, 1)?.id().value(),
                u64::from(id) + 1000
            );
        }
        let small = new_ring(63, 1)?;
        assert_eq!(Migration { copied: 0 }.step(&ring, &small), Err(EINVAL));
        assert_eq!(ring.storage().producer(), 75);
        assert_eq!(ring.index, 0);
        for id in 0..75 {
            assert_eq!(
                ReceiveWqe::read(ring.storage(), id, 1)?.id().value(),
                u64::from(id) + 1000
            );
        }
        Ok(())
    }

    #[test]
    fn capacity_and_notification_limits() {
        let current = Attributes {
            max_wr: 1024,
            limit: 8,
            capacity: 31,
        };
        let mut change = Change {
            max_wr: Some(7),
            limit: None,
        };
        assert_eq!(current.check(&mut change), Err(EINVAL));
        change.max_wr = None;
        change.limit = Some(32);
        assert_eq!(current.check(&mut change), Err(EINVAL));
        change.max_wr = Some(8);
        change.limit = Some(31);
        assert_eq!(current.check(&mut change), Err(EINVAL));
        change.max_wr = Some(63);
        change.limit = Some(63);
        assert_eq!(current.check(&mut change), Ok(()));
        change.max_wr = Some(7);
        change.limit = Some(7);
        assert_eq!(current.check(&mut change), Ok(()));
        change.max_wr = Some(1025);
        assert_eq!(current.check(&mut change), Err(EINVAL));
        let mut capacity = Capacity {
            max_wr: 0,
            max_sge: 1,
        };
        let limits = || Limits {
            max_wr: 1024,
            max_sge: 32,
        };
        assert_eq!(check_init(limits(), &mut capacity), Err(EINVAL));
        capacity.max_wr = 1;
        capacity.max_sge = 33;
        assert_eq!(check_init(limits(), &mut capacity), Err(EINVAL));
    }

    #[test]
    fn notifications_are_one_shot_and_require_a_handler() {
        let mut notify = Notification::zeroed();
        assert!(!notify.take(0, true));
        notify.arm(4);
        assert!(!notify.take(4, true));
        assert!(!notify.take(3, false));
        assert_eq!(notify.limit(), 4);
        assert!(notify.take(3, true));
        assert_eq!(notify.limit(), 0);
        assert!(!notify.take(0, true));
        notify.arm(2);
        assert!(notify.take(1, true));
        notify.arm(0);
        assert!(!notify.take(0, true));
    }
}
