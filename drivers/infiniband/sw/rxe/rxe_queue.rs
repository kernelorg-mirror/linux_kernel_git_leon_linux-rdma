// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! RXE queue storage, user mappings and resizing.

#![forbid(unsafe_code)]

use crate::{
    rxe_context::Context,
    rxe_device::DeviceData,
    rxe_mmap::{
        Mapping,
        Mappings, //
    },
    rxe_mr::{
        FastRegistration,
        Regions, //
    },
    rxe_net_tx::TransmitCompletion,
    rxe_packet::{
        Packet,
        PacketQueue, //
    },
    rxe_qp_config::Capacity,
    rxe_resp_state::Responder,
    rxe_ring::Storage,
    rxe_send::{
        SendSnapshots,
        SendState, //
    },
    rxe_submission::{
        Limits,
        Request,
        Submission, //
    },
    rxe_types::QueueType,
    rxe_wqe::{
        RECV_HEADER_SIZE,
        SEND_HEADER_SIZE,
        SGE_SIZE, //
    }, //
};
use kernel::{
    alloc::KVVec,
    net::skbuff::completion::Completions,
    prelude::*,
    rdma::{
        CompletionId,
        ReceiveRequest,
        SendRequest, //
    },
    sync::{
        Mutex,
        SpinLockIrq, //
    },
    uaccess::UserSliceWriter, //
};

/// A completely constructed send queue and its serialized private progress.
pub(crate) struct SendQueue {
    pub(crate) max_wr: c_int,
    pub(crate) max_sge: c_int,
    pub(crate) max_inline: c_int,
    queue: KBox<WorkQueue>,
    pub(crate) state: Pin<KBox<Mutex<SendState>>>,
    pub(crate) packets: Pin<KBox<PacketQueue>>,
    pub(crate) completions: Completions<TransmitCompletion>,
}

impl SendQueue {
    pub(crate) fn queue(&self) -> &WorkQueue {
        &self.queue
    }

    pub(crate) fn new(
        mappings: &Mappings,
        capacity: &mut Capacity,
        user: bool,
        context: Option<&Context>,
        output: Option<UserSliceWriter>,
    ) -> Result<Self> {
        let extra =
            (capacity.send.scatter_gather as usize * SGE_SIZE).max(capacity.inline as usize);
        let size = extra + SEND_HEADER_SIZE;
        let mut queue = WorkQueue::new(capacity.send.work_requests, size as u32)?;
        if !user {
            queue.prepare_kernel_send()?;
        }
        let snapshots = SendSnapshots::new(queue.storage(), size)?;
        let state = KBox::pin_init(kernel::new_mutex!(SendState::new(snapshots)), GFP_KERNEL)?;
        let packets = KBox::pin_init(PacketQueue::new(), GFP_KERNEL)?;
        let completions = Completions::new()?;
        // Publication is the final fallible operation, so every published mapping transfers
        // to a complete owner whose release cancels its pending descriptor.
        queue.publish_mapping(mappings, context, output)?;
        capacity.send.work_requests = queue.mask();
        capacity.send.scatter_gather = (extra / SGE_SIZE) as u32;
        capacity.inline = extra as u32;
        Ok(Self {
            max_wr: queue.mask() as c_int,
            max_sge: (extra / SGE_SIZE) as c_int,
            max_inline: extra as c_int,
            queue,
            state,
            packets,
            completions,
        })
    }

    /// Resets queue bytes and private progress after the send task has been drained.
    pub(crate) fn reset(&self) {
        let _ = self.queue.storage().reset();
        self.state.lock().reset();
    }

    /// Drains transmit callbacks before releasing snapshots and the pending queue mapping.
    pub(crate) fn release(self, mappings: &Mappings) {
        drop(self.completions);
        drop(self.state);
        WorkQueue::release(self.queue, mappings);
    }
}

/// The receive worker owns its current packet between read-response segments.
pub(crate) struct ReceiveState {
    pub(crate) progress: Responder,
    pub(crate) packet: Option<Packet>,
}

/// Completely constructed receive progress with an optional private work queue.
pub(crate) struct ReceiveQueue {
    pub(crate) max_wr: c_int,
    pub(crate) max_sge: c_int,
    pub(crate) queue: Option<KBox<WorkQueue>>,
    pub(crate) state: Pin<KBox<Mutex<ReceiveState>>>,
    pub(crate) packets: Pin<KBox<PacketQueue>>,
}

impl ReceiveQueue {
    pub(crate) fn new(
        mappings: &Mappings,
        capacity: &mut Capacity,
        context: Option<&Context>,
        output: Option<UserSliceWriter>,
    ) -> Result<Self> {
        let state = KBox::pin_init(
            kernel::new_mutex!(ReceiveState {
                progress: Responder::new()?,
                packet: None,
            }),
            GFP_KERNEL,
        )?;
        let packets = KBox::pin_init(PacketQueue::new(), GFP_KERNEL)?;
        let Some(receive) = &mut capacity.receive else {
            return Ok(Self {
                max_wr: 0,
                max_sge: 0,
                queue: None,
                state,
                packets,
            });
        };
        let size = RECV_HEADER_SIZE + receive.scatter_gather as usize * SGE_SIZE;
        let mut queue = WorkQueue::new(receive.work_requests, size as u32)?;
        if context.is_none() {
            queue.storage.prepare_native()?;
        }
        // No fallible operation follows descriptor publication. Partial creation before
        // this point releases only local owners and cannot leave a pending mapping behind.
        queue.publish_mapping(mappings, context, output)?;
        receive.work_requests = queue.mask();
        Ok(Self {
            max_wr: queue.mask() as c_int,
            max_sge: receive.scatter_gather as c_int,
            queue: Some(queue),
            state,
            packets,
        })
    }

    /// Resets private receive bytes and progress after the receive task has been drained.
    pub(crate) fn reset(&self) {
        if let Some(queue) = &self.queue {
            let _ = queue.storage().reset();
        }
        let mut state = self.state.lock();
        drop(state.packet.take());
        state.progress.reset();
    }

    /// Releases receive snapshots before cancelling the optional private queue mapping.
    pub(crate) fn release(self, mappings: &Mappings) {
        drop(self.state);
        if let Some(queue) = self.queue {
            WorkQueue::release(queue, mappings);
        }
    }
}

type Registrations = SpinLockIrq<KVVec<Option<FastRegistration>>>;

/// A QP work queue whose storage owner is immutable after publication.
///
/// Producers and consumers may borrow this owner concurrently. Private consumer progress
/// lives in a separate [`Consumer`], which the transport task borrows exclusively.
pub(crate) struct WorkQueue {
    storage: Storage,
    mapping: Option<Mapping>,
    registrations: Option<Pin<KBox<Registrations>>>,
}

impl WorkQueue {
    pub(super) fn new(count: u32, elem_size: u32) -> Result<KBox<Self>> {
        Ok(KBox::new(
            Self {
                storage: Storage::new(count, elem_size, kernel::cpu::cache_line_size())?,
                mapping: None,
                registrations: None,
            },
            GFP_KERNEL,
        )?)
    }

    pub(super) fn storage(&self) -> &Storage {
        &self.storage
    }

    pub(super) fn mask(&self) -> u32 {
        self.storage.mask()
    }

    /// Preallocates native registration ownership for a private kernel send queue.
    pub(super) fn prepare_kernel_send(&mut self) -> Result {
        self.storage.prepare_native()?;
        let slots = KVVec::from_elem(None, self.mask() as usize + 1, GFP_KERNEL)?;
        self.registrations = Some(KBox::pin_init(
            kernel::new_spinlock_irq!(slots),
            GFP_KERNEL,
        )?);
        Ok(())
    }

    fn retain_registration(&self, index: u32, registration: Option<FastRegistration>) -> Result {
        if let Some(slots) = &self.registrations {
            slots.lock()[(index & self.mask()) as usize] = registration;
        } else if registration.is_some() {
            return Err(EINVAL);
        }
        Ok(())
    }

    /// Transfers published ownership to the transport's private send snapshot.
    pub(super) fn take_registration(&self, index: u32) -> Option<FastRegistration> {
        self.registrations.as_ref()?.lock()[(index & self.mask()) as usize].take()
    }

    /// Publishes a mapping only after its descriptor has been copied successfully.
    pub(super) fn publish_mapping(
        &mut self,
        mappings: &Mappings,
        context: Option<&Context>,
        output: Option<UserSliceWriter>,
    ) -> Result {
        let Some(mut output) = output else {
            return Ok(());
        };
        let pending = mappings.prepare(context.ok_or(EINVAL)?, self.storage.memory())?;
        pending.descriptor().write(&mut output)?;
        self.mapping = Some(mappings.publish(pending));
        Ok(())
    }

    /// Cancels an unclaimed descriptor before dropping the queue's storage ownership.
    pub(super) fn release(mut queue: KBox<Self>, mappings: &Mappings) {
        if let Some(mapping) = queue.mapping.take() {
            mappings.cancel(mapping);
        }
    }
}

/// Kernel producer progress owned by the QP's native IRQ lock.
///
/// Each queue retains its cursor across reset, just as its consumer does. Userspace queues
/// publish their own producer and never enter the kernel posting path.
#[derive(Zeroable)]
pub(crate) struct Producer {
    index: u32,
}

impl Producer {
    /// Validates send metadata before checking capacity or copying inline memory.
    pub(super) fn post_send(
        &mut self,
        queue: &WorkQueue,
        regions: &Regions,
        request: SendRequest<'_, DeviceData>,
        limits: &Limits,
    ) -> Result {
        if usize::try_from(request.scatter_gather_count()).map_err(|_| EINVAL)? > limits.max_sge {
            return Err(EINVAL);
        }
        let list = request.scatter_gather()?;
        super::rxe_submission::validate(limits, request.opcode(), request.flags(), list)?;
        let (captured, registration) = Request::capture(&request, regions)?;
        super::rxe_submission::validate_request(&captured, list, limits)?;
        let next = self.prepare(queue, || {
            Submission::send(&captured, list, limits, |address, output| {
                request.read_inline(address, output)
            })
            .map(|submission| (submission, registration))
        })?;
        self.publish(queue, next, request.completion_id());
        Ok(())
    }

    /// Checks receive capacity before reading the bounded descriptor array.
    pub(super) fn post_receive(
        &mut self,
        queue: &WorkQueue,
        request: ReceiveRequest<'_>,
        max_sge: usize,
    ) -> Result {
        let next = self.prepare(queue, || {
            if usize::try_from(request.scatter_gather_count()).map_err(|_| EINVAL)? > max_sge {
                return Err(EINVAL);
            }
            Submission::receive(request.id(), request.scatter_gather()?, max_sge)
                .map(|submission| (submission, None))
        })?;
        self.publish(queue, next, request.completion_id());
        Ok(())
    }

    fn prepare(
        &mut self,
        queue: &WorkQueue,
        capture: impl FnOnce() -> Result<(Submission, Option<FastRegistration>)>,
    ) -> Result<u32> {
        let next = self.index.wrapping_add(1) & queue.mask();
        if next == queue.storage.consumer() & queue.mask() {
            return Err(ENOMEM);
        }
        let (submission, registration) = capture()?;
        queue.storage.write(self.index, 0, submission.bytes())?;
        queue.retain_registration(self.index, registration)?;
        Ok(next)
    }

    fn publish(&mut self, queue: &WorkQueue, next: u32, completion: CompletionId) {
        // Capturing the capability accepts the WR irreversibly. All remaining work is
        // infallible and completes before producer publication can expose the request.
        queue.storage.publish_id(self.index, completion);
        self.index = next;
        queue.storage.publish_producer(next);
    }
}

/// Private consumer progress owned by one serialized transport task.
#[derive(Zeroable)]
pub(crate) struct Consumer {
    index: u32,
}

impl Consumer {
    pub(super) fn position(&self) -> u32 {
        self.index
    }

    pub(super) fn is_empty(&self, queue: &WorkQueue) -> bool {
        queue.storage.producer().wrapping_sub(self.index) & queue.mask() == 0
    }

    /// Publishes completion after the caller finishes accessing the consumed request.
    pub(super) fn advance(&mut self, queue: &WorkQueue) {
        self.index = self.index.wrapping_add(1) & queue.mask();
        queue.storage.publish_consumer(self.index);
    }

    /// Captures receive work through bounded shared-memory reads.
    pub(super) fn receive(
        &self,
        queue: &WorkQueue,
        max_sge: u32,
    ) -> Result<Option<super::rxe_wqe::ReceiveWqe>, super::rxe_wqe::ReceiveFailure> {
        if self.is_empty(queue) {
            return Ok(None);
        }
        super::rxe_wqe::ReceiveWqe::capture(queue.storage(), self.index, max_sge).map(Some)
    }

    /// Captures the identifier of the oldest request for an error completion.
    pub(super) fn receive_id(&self, queue: &WorkQueue) -> Option<CompletionId> {
        if self.is_empty(queue) {
            return None;
        }
        let mut bytes = [0; size_of::<u64>()];
        queue
            .storage
            .read(self.index, 0, &mut bytes)
            .expect("receive queue header");
        Some(
            queue
                .storage
                .completion_id(self.index, u64::from_ne_bytes(bytes)),
        )
    }
}

/// A ring owning its kernel storage and any pending mapping identity.
///
/// Pending mappings retain their own pages. Queue teardown cancels the pending identity;
/// a mapping already acquired by mmap or established in userspace has independent ownership.
pub(crate) struct Queue {
    pub(super) storage: Storage,
    pub(super) mapping: Option<Mapping>,
    pub(crate) index_mask: u32,
    #[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
    type_: QueueType,
    pub(crate) index: u32,
}

impl Queue {
    /// Constructs an unpublished ring with its storage owned by the returned box.
    pub(super) fn new(
        count: u32,
        elem_size: u32,
        _type: QueueType,
        line: u32,
    ) -> Result<KBox<Self>> {
        let storage = Storage::new(count, elem_size, line)?;
        Ok(KBox::new(
            Self {
                #[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
                type_: _type,
                index_mask: storage.mask(),
                index: 0,
                storage,
                mapping: None,
            },
            GFP_KERNEL,
        )?)
    }
}

impl Queue {
    pub(super) fn storage(&self) -> &Storage {
        &self.storage
    }

    pub(super) fn cancel_mapping(&mut self, mappings: &Mappings) {
        if let Some(mapping) = self.mapping.take() {
            mappings.cancel(mapping);
        }
    }

    /// Copies published entries and swaps storage only after every copy succeeds.
    ///
    /// Exclusive borrows cover both kernel producers and consumers. Storage
    /// operations tolerate concurrent access through existing userspace mappings.
    #[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
    pub(super) fn resize(&mut self, replacement: &mut Self) -> Result {
        let prod = self.producer();
        let mut cons = self.consumer();
        if replacement.index_mask < prod.wrapping_sub(cons) & self.index_mask {
            return Err(EINVAL);
        }
        // Replacement storage starts at a private origin, regardless of mapped cursor bytes.
        let mut new_prod = 0;
        while prod.wrapping_sub(cons) & self.index_mask != 0 {
            self.storage()
                .copy_slot(cons, replacement.storage(), new_prod)?;
            new_prod = new_prod.wrapping_add(1) & replacement.index_mask;
            cons = cons.wrapping_add(1) & self.index_mask;
        }
        replacement.storage().publish_consumer(0);
        replacement.storage().publish_producer(new_prod);
        replacement.index = 0;
        self.storage().publish_consumer(cons);
        if self.type_ == QueueType::ToClient {
            replacement.index = new_prod;
        } else {
            self.index = cons;
        }
        core::mem::swap(self, replacement);
        Ok(())
    }

    #[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
    fn producer(&self) -> u32 {
        if self.type_ == QueueType::ToClient {
            self.index
        } else {
            self.storage().producer()
        }
    }

    #[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
    fn consumer(&self) -> u32 {
        if self.type_ == QueueType::FromClient {
            self.index
        } else {
            self.storage().consumer()
        }
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_queue)]
mod tests {
    use super::*;

    #[test]
    fn work_consumer_ignores_mapped_cursor_and_layout() -> Result {
        let queue = WorkQueue::new(3, super::super::rxe_wqe::RECV_HEADER_SIZE as u32)?;
        let mut consumer = Consumer::zeroed();
        for round in 0..8u32 {
            let first = consumer.position();
            for offset in 0..2 {
                let id = u64::from(round * 2 + offset);
                queue
                    .storage()
                    .write(first + offset, 0, &id.to_ne_bytes())?;
            }
            queue.storage().publish_producer(first + 2);
            // Userspace can forge both the advertised layout and consumer position. The
            // task retains its own cursor and continues using the allocation's real bounds.
            queue.storage().memory().write(0, &[0xff; 8])?;
            queue.storage().publish_consumer(first + 1);
            for offset in 0..2 {
                let id = u64::from(round * 2 + offset);
                assert_eq!(consumer.receive_id(&queue).map(|id| id.value()), Some(id));
                assert_eq!(
                    consumer
                        .receive(&queue, 0)
                        .map_err(|_| EINVAL)?
                        .unwrap()
                        .id()
                        .value(),
                    id
                );
                consumer.advance(&queue);
            }
            assert!(consumer.is_empty(&queue));
            assert!(consumer.receive_id(&queue).is_none());
            assert!(consumer.receive(&queue, 0).map_err(|_| EINVAL)?.is_none());
            assert_eq!(consumer.position(), (first + 2) & queue.mask());
        }
        Ok(())
    }

    #[test]
    fn wrapped_resize_ignores_mapped_layout() -> Result {
        for type_ in [QueueType::ToClient, QueueType::FromClient] {
            let mut queue = Queue::new(7, 8, type_, 64)?;
            queue.storage().publish_consumer(6);
            queue.storage().publish_producer(2);
            queue.index = if type_ == QueueType::ToClient { 2 } else { 6 };
            for (index, value) in [(6, 1u64), (7, 2), (0, 3), (1, 4)] {
                let storage = queue.storage();
                storage
                    .memory()
                    .write(storage.offset(index), &value.to_ne_bytes())?;
            }
            // A userspace writer cannot change the allocation's real layout.
            queue.storage().memory().write(0, &[0xff; 8])?;
            let mut small = Queue::new(3, 8, type_, 64)?;
            assert_eq!(queue.resize(&mut small), Err(EINVAL));
            assert_eq!(queue.consumer(), 6);
            assert_eq!(queue.producer(), 2);
            let mut larger = Queue::new(15, 8, type_, 64)?;
            larger.storage().publish_producer(13);
            larger.storage().publish_consumer(9);
            queue.resize(&mut larger)?;
            assert_eq!(queue.consumer(), 0);
            assert_eq!(queue.producer(), 4);
            assert_eq!(queue.index_mask, 15);
            for index in 0..4 {
                let mut bytes = [0; 8];
                queue.storage().read(index, 0, &mut bytes)?;
                assert_eq!(u64::from_ne_bytes(bytes), u64::from(index) + 1);
            }
        }
        Ok(())
    }
}
