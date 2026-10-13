// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Native send requests and progress retained by the serialized send task.

#![forbid(unsafe_code)]

use super::{
    rxe_mr::FastRegistration,
    rxe_mr_data::{
        Cursor,
        Dma, //
    },
    rxe_queue::{
        Consumer,
        WorkQueue, //
    },
    rxe_ring::Storage,
    rxe_wqe::{
        SEND_DMA_OFFSET,
        SEND_HEADER_SIZE,
        SEND_WR_SIZE,
        SGE_SIZE, //
    }, //
};
use kernel::{
    alloc::KVVec,
    prelude::*, //
};

/// Native send progress and captured requests owned by the same mutex.
pub(crate) struct SendState {
    pub(crate) progress: Progress,
    pub(crate) snapshots: KBox<SendSnapshots>,
}

impl SendState {
    pub(crate) fn new(snapshots: KBox<SendSnapshots>) -> Self {
        Self {
            progress: Progress::new(),
            snapshots,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.snapshots.reset();
        self.progress.reset();
    }
}

/// Requester and completer progress, accessed under the QP's send-state mutex.
pub(crate) struct Progress {
    pub(crate) req: super::rxe_req_state::Requester,
    pub(crate) comp: super::rxe_comp_state::Completer,
}

impl Progress {
    pub(crate) fn new() -> Self {
        let mut req = super::rxe_req_state::Requester::zeroed();
        let mut comp = super::rxe_comp_state::Completer::zeroed();
        req.opcode = -1;
        comp.opcode = -1;
        Self { req, comp }
    }

    pub(crate) fn reset(&mut self) {
        self.req.opcode = -1;
        self.req.need_retry = false;
        self.req.wait_for_rnr_timer = false;
        self.req.noack_pkts = 0;
        self.comp.opcode = -1;
        self.comp.timeout_retry = false;
        self.comp.started_retry = false;
    }

    /// Returns the next ACK state after releasing a completed read or atomic credit.
    pub(crate) fn acknowledge(
        &mut self,
        wqe: &mut SendWqe<'_>,
        credits: &super::rxe_req_state::ReadCredits,
        psn: u32,
    ) -> super::rxe_comp_state::State {
        self.release_credit(wqe, credits);
        if super::rxe_wire::psn_compare(psn, self.comp.psn) >= 0 {
            super::rxe_comp_state::State::Update
        } else {
            super::rxe_comp_state::State::Done
        }
    }

    /// Releases a request's credit before any success, error or flush consumes it.
    pub(crate) fn release_credit(
        &mut self,
        wqe: &mut SendWqe<'_>,
        credits: &super::rxe_req_state::ReadCredits,
    ) {
        if wqe.has_rd_atomic != 0 {
            wqe.has_rd_atomic = 0;
            if self.req.release_read_credit(credits) {
                self.comp.timeout_retry = false;
            }
        }
    }

    /// Advances completion progress past a pending request before publishing its completion.
    pub(crate) fn complete_pending(&mut self, wqe: &SendWqe<'_>, has_packet: bool) {
        if has_packet && wqe.state == super::rxe_param::WQE_STATE_PENDING {
            if super::rxe_wire::psn_compare(wqe.last_psn, self.comp.psn) >= 0 {
                self.comp.psn = wqe.last_psn.wrapping_add(1) & 0xffffff;
                self.comp.opcode = -1;
            }
            self.req.wake_psn();
        }
    }
}

/// Copied request metadata. No reference to the shared submission survives capture.
#[derive(Clone)]
pub(super) struct Request {
    pub(super) wr_id: kernel::rdma::CompletionId,
    pub(super) opcode: u32,
    pub(super) send_flags: u32,
    immediate: [u8; 4],
    parameters: [u8; SEND_WR_SIZE - 24],
}

impl Request {
    fn decode(header: &[u8; SEND_HEADER_SIZE]) -> Self {
        Self {
            wr_id: kernel::rdma::CompletionId::user(u64::from_ne_bytes(
                header[..8].try_into().unwrap(),
            )),
            opcode: u32::from_ne_bytes(header[12..16].try_into().unwrap()),
            send_flags: u32::from_ne_bytes(header[16..20].try_into().unwrap()),
            immediate: header[20..24].try_into().unwrap(),
            parameters: header[24..SEND_WR_SIZE].try_into().unwrap(),
        }
    }

    fn word(&self, offset: usize) -> u32 {
        u32::from_ne_bytes(self.parameters[offset..offset + 4].try_into().unwrap())
    }

    fn doubleword(&self, offset: usize) -> u64 {
        u64::from_ne_bytes(self.parameters[offset..offset + 8].try_into().unwrap())
    }

    pub(super) fn immediate(&self) -> [u8; 4] {
        self.immediate
    }

    pub(super) fn invalidate_key(&self) -> u32 {
        u32::from_ne_bytes(self.immediate)
    }

    pub(super) fn address(&self) -> u64 {
        self.doubleword(0)
    }

    pub(super) fn remote_key(&self) -> u32 {
        self.word(8)
    }

    pub(super) fn atomic_key(&self) -> u32 {
        self.word(24)
    }

    pub(super) fn compare_add(&self) -> u64 {
        self.doubleword(8)
    }

    pub(super) fn swap(&self) -> u64 {
        self.doubleword(16)
    }

    pub(super) fn destination(&self) -> u32 {
        self.word(0)
    }

    pub(super) fn datagram_key(&self) -> u32 {
        self.word(4)
    }

    pub(super) fn address_handle(&self) -> u32 {
        self.word(12)
    }

    pub(super) fn legacy_address_vector(&self) -> &[u8; 88] {
        self.parameters[32..].try_into().unwrap()
    }

    pub(super) fn window(&self) -> Window {
        Window {
            address: self.doubleword(0),
            length: self.doubleword(8),
            region_key: self.word(16),
            window_key: self.word(20),
            new_key: self.word(24),
            access: self.word(28),
        }
    }

    pub(super) fn flush(&self) -> Flush {
        Flush {
            key: self.word(12),
            kind: self.parameters[16],
            level: self.parameters[17],
        }
    }
}

pub(super) struct Window {
    pub(super) address: u64,
    pub(super) length: u64,
    pub(super) region_key: u32,
    pub(super) window_key: u32,
    pub(super) new_key: u32,
    pub(super) access: u32,
}

pub(super) struct Flush {
    pub(super) key: u32,
    pub(super) kind: u8,
    pub(super) level: u8,
}

/// Driver-owned progress. The client supplies none of these protocol fields.
#[derive(Clone)]
pub(super) struct State {
    pub(super) wr: Request,
    pub(super) registration: Option<FastRegistration>,
    pub(super) status: u32,
    pub(super) state: u32,
    // Retained work waiting for retransmission remains distinct from new posts.
    pub(super) replaying: bool,
    pub(super) iova: u64,
    pub(super) mask: u32,
    pub(super) first_psn: u32,
    pub(super) last_psn: u32,
    pub(super) has_rd_atomic: u32,
    pub(super) dma: Cursor,
}

impl State {
    fn capture(header: &[u8; SEND_HEADER_SIZE]) -> Self {
        let wr = Request::decode(header);
        let length = u32::from_ne_bytes(
            header[SEND_DMA_OFFSET..SEND_DMA_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        let count = u32::from_ne_bytes(
            header[SEND_DMA_OFFSET + 12..SEND_DMA_OFFSET + 16]
                .try_into()
                .unwrap(),
        );
        Self {
            iova: wr.address(),
            wr,
            registration: None,
            status: 0,
            state: 0,
            replaying: false,
            mask: 0,
            first_psn: 0,
            last_psn: 0,
            has_rd_atomic: 0,
            dma: Cursor::new(length, count),
        }
    }
}

/// A single exclusive borrow of a native request and its retained data.
///
/// Completion must end this borrow before returning the slot to the producer.
pub(super) struct SendWqe<'a> {
    work: &'a mut State,
    data: &'a [u8],
}

impl core::ops::Deref for SendWqe<'_> {
    type Target = State;

    fn deref(&self) -> &State {
        self.work
    }
}

impl core::ops::DerefMut for SendWqe<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.work
    }
}

impl SendWqe<'_> {
    pub(super) fn dma(&mut self) -> Result<Dma<'_>> {
        Dma::from_cursor(&mut self.work.dma, self.data)
    }

    pub(super) fn copy_inline(&mut self, output: &mut [u8], limit: usize) -> Result {
        let cursor = &mut self.work.dma;
        let start = cursor.sge_offset as usize;
        let end = start.checked_add(output.len()).ok_or(EINVAL)?;
        if end > limit || output.len() > cursor.resid as usize {
            return Err(EINVAL);
        }
        output.copy_from_slice(self.data.get(start..end).ok_or(EINVAL)?);
        cursor.resid -= output.len() as u32;
        cursor.sge_offset = u32::try_from(end).map_err(|_| EINVAL)?;
        Ok(())
    }

    pub(super) fn copy_atomic_write(&mut self, output: &mut [u8]) -> Result {
        if output.len() != 8 || self.work.dma.resid != 8 {
            return Err(EINVAL);
        }
        output.copy_from_slice(self.data.get(..8).ok_or(EINVAL)?);
        self.work.dma.resid = 0;
        Ok(())
    }
}

#[derive(Clone)]
struct Slot {
    state: State,
    loaded: bool,
}

/// Preallocated requests and data, retained across retries until completion.
pub(super) struct SendSnapshots {
    slots: KVVec<Slot>,
    data: KVVec<u8>,
    data_per_slot: usize,
    mask: u32,
    consumer: Consumer,
}

impl SendSnapshots {
    pub(super) fn new(storage: &Storage, slot_size: usize) -> Result<KBox<Self>> {
        if !(SEND_HEADER_SIZE..=SEND_HEADER_SIZE + 32 * SGE_SIZE).contains(&slot_size) {
            return Err(EINVAL);
        }
        let count = storage.mask() as usize + 1;
        let data_per_slot = slot_size - SEND_HEADER_SIZE;
        let size = count.checked_mul(data_per_slot).ok_or(EOVERFLOW)?;
        Ok(KBox::new(
            Self {
                slots: KVVec::from_elem(
                    Slot {
                        state: State::capture(&[0; SEND_HEADER_SIZE]),
                        loaded: false,
                    },
                    count,
                    GFP_KERNEL_ACCOUNT,
                )?,
                data: KVVec::from_elem(0, size, GFP_KERNEL_ACCOUNT)?,
                data_per_slot,
                mask: storage.mask(),
                consumer: Consumer::zeroed(),
            },
            GFP_KERNEL_ACCOUNT,
        )?)
    }

    pub(super) fn position(&self) -> u32 {
        self.consumer.position()
    }

    /// Borrows a published request, retaining its captured bytes throughout retries.
    pub(super) fn slot(&mut self, queue: &WorkQueue, index: u32) -> SendWqe<'_> {
        let capture = !self.slots[(index & self.mask) as usize].loaded;
        let mut work = self
            .get(queue.storage(), index)
            .expect("send queue dimensions");
        if capture {
            work.registration = queue.take_registration(index);
        }
        work
    }

    /// Borrows the oldest pending request after observing producer publication.
    pub(super) fn head(&mut self, queue: &WorkQueue) -> Option<SendWqe<'_>> {
        self.pending(queue).map(|index| self.slot(queue, index))
    }

    /// Selects the current consumer without lending its captured request bytes.
    pub(super) fn pending(&self, queue: &WorkQueue) -> Option<u32> {
        if !self.slots[self.position() as usize].loaded && self.consumer.is_empty(queue) {
            None
        } else {
            Some(self.position())
        }
    }

    /// Borrows the next requester slot after observing producer publication.
    pub(super) fn request(&mut self, queue: &WorkQueue, index: u32) -> Option<SendWqe<'_>> {
        if !self.slots[(index & self.mask) as usize].loaded
            && index == queue.storage().producer() & queue.mask()
        {
            None
        } else {
            Some(self.slot(queue, index))
        }
    }

    /// Forgets completed work before publishing that its slot can be reused.
    ///
    /// The exclusive borrow prevents consumption while a request borrow remains live.
    pub(super) fn consume(&mut self, queue: &WorkQueue) {
        self.release(self.position());
        self.consumer.advance(queue);
    }

    pub(super) fn get(&mut self, storage: &Storage, index: u32) -> Result<SendWqe<'_>> {
        let index = (index & self.mask) as usize;
        let slot = &mut self.slots[index];
        let offset = index * self.data_per_slot;
        let data = &mut self.data[offset..offset + self.data_per_slot];
        if !slot.loaded {
            let mut header = [0; SEND_HEADER_SIZE];
            storage.read(index as u32, 0, &mut header)?;
            storage.read(index as u32, SEND_HEADER_SIZE, data)?;
            slot.state = State::capture(&header);
            slot.state.wr.wr_id = storage.completion_id(index as u32, slot.state.wr.wr_id.value());
            slot.loaded = true;
        }
        Ok(SendWqe {
            work: &mut slot.state,
            data,
        })
    }

    pub(super) fn release(&mut self, index: u32) {
        let slot = &mut self.slots[(index & self.mask) as usize];
        slot.state.registration = None;
        slot.loaded = false;
    }

    pub(super) fn reset(&mut self) {
        for slot in &mut self.slots {
            slot.state.registration = None;
            slot.loaded = false;
        }
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_send)]
mod tests {
    use super::*;

    #[test]
    fn reset_ends_partial_read_before_a_new_atomic_response() -> Result {
        use crate::{
            rxe_comp_state as comp,
            rxe_wire::{
                bth,
                Transport, //
            }, //
        };

        let storage = Storage::new(1, SEND_HEADER_SIZE as u32, 64)?;
        let mut snapshots = SendSnapshots::new(&storage, SEND_HEADER_SIZE)?;
        let mut work = snapshots.get(&storage, 0)?;
        work.wr.opcode = kernel::bindings::ib_wr_opcode_IB_WR_ATOMIC_FETCH_AND_ADD;
        work.first_psn = 7;
        work.last_psn = 7;
        let mut bytes = [0; 24];
        bytes[..12].copy_from_slice(&bth(0x12, 7, false, 0, 1, false));
        let wire = Transport::parse(&bytes)?;
        let limits = comp::Limits { retry: 3, rnr: 2 };
        for previous in [0x0d, 0x0e] {
            let mut progress = Progress::new();
            progress.comp.opcode = previous;
            progress.comp.timeout_retry = true;
            progress.comp.started_retry = true;
            assert_eq!(
                comp::check_ack(&mut progress.comp, limits, &wire, &mut work).state,
                comp::State::Error
            );
            progress.reset();
            assert!(!progress.comp.timeout_retry);
            assert!(!progress.comp.started_retry);
            assert_eq!(
                comp::check_ack(&mut progress.comp, limits, &wire, &mut work).state,
                comp::State::Atomic
            );
        }
        Ok(())
    }

    #[test]
    fn failed_work_releases_its_credit_exactly_once() -> Result {
        let queue = WorkQueue::new(1, SEND_HEADER_SIZE as u32)?;
        let mut snapshots = SendSnapshots::new(queue.storage(), SEND_HEADER_SIZE)?;
        let credits = super::super::rxe_req_state::ReadCredits::zeroed();
        credits.set(1);
        let mut progress = Progress::new();
        assert!(progress.req.take_read_credit(&credits));
        assert!(!progress.req.take_read_credit(&credits));
        let mut work = snapshots.get(queue.storage(), 0)?;
        work.has_rd_atomic = 1;
        progress.release_credit(&mut work, &credits);
        assert_eq!(credits.outstanding(), 0);
        assert_eq!(work.has_rd_atomic, 0);
        assert!(!progress.req.need_rd_atomic);
        progress.release_credit(&mut work, &credits);
        assert_eq!(credits.outstanding(), 0);
        Ok(())
    }

    #[test]
    fn captured_send_keeps_private_identifier_across_slot_reuse() -> Result {
        let mut queue = WorkQueue::new(1, SEND_HEADER_SIZE as u32)?;
        queue.prepare_kernel_send()?;
        let mut snapshots = SendSnapshots::new(queue.storage(), SEND_HEADER_SIZE)?;
        queue.storage().write(0, 0, &7u64.to_ne_bytes())?;
        queue
            .storage()
            .publish_id(0, kernel::rdma::CompletionId::user(41));
        queue.storage().publish_producer(1);
        assert_eq!(snapshots.slot(&queue, 0).wr.wr_id.value(), 41);
        queue.storage().write(0, 0, &8u64.to_ne_bytes())?;
        queue
            .storage()
            .publish_id(0, kernel::rdma::CompletionId::user(42));
        let completed =
            super::super::rxe_completion::SendCompletion::new(snapshots.slot(&queue, 0), true);
        snapshots.consume(&queue);
        assert_eq!(completed.record.unwrap().id.value(), 41);
        assert_eq!(snapshots.slot(&queue, 0).wr.wr_id.value(), 42);
        Ok(())
    }

    #[test]
    fn selected_work_survives_withdrawn_publication_and_slot_reuse() -> Result {
        let queue = WorkQueue::new(1, SEND_HEADER_SIZE as u32)?;
        let mut snapshots = SendSnapshots::new(queue.storage(), SEND_HEADER_SIZE)?;
        queue.storage().write(0, 0, &17u64.to_ne_bytes())?;
        queue.storage().publish_producer(1);
        let selected = snapshots.pending(&queue).unwrap();
        assert_eq!(snapshots.slot(&queue, selected).wr.wr_id.value(), 17);

        // Userspace can withdraw publication and overwrite shared bytes between protocol
        // states. The selected private request remains authoritative until completion.
        queue.storage().publish_producer(0);
        queue.storage().write(0, 0, &99u64.to_ne_bytes())?;
        assert_eq!(snapshots.pending(&queue), Some(selected));
        let completed = super::super::rxe_completion::SendCompletion::new(
            snapshots.slot(&queue, selected),
            true,
        );
        snapshots.consume(&queue);
        assert_eq!(completed.record.unwrap().id.value(), 17);
        assert_eq!(snapshots.slot(&queue, selected).wr.wr_id.value(), 99);
        Ok(())
    }

    #[test]
    fn completion_forgets_snapshot_before_reusing_wrapped_slot() -> Result {
        let queue = WorkQueue::new(1, SEND_HEADER_SIZE as u32)?;
        let mut snapshots = SendSnapshots::new(queue.storage(), SEND_HEADER_SIZE)?;
        for id in 0..16u64 {
            let index = snapshots.position();
            queue.storage().write(index, 0, &id.to_ne_bytes())?;
            queue.storage().publish_producer(index + 1);
            assert_eq!(snapshots.head(&queue).unwrap().wr.wr_id.value(), id);
            // Retry keeps the captured request even if the producer rewrites its slot.
            queue.storage().write(index, 0, &u64::MAX.to_ne_bytes())?;
            assert_eq!(snapshots.slot(&queue, index).wr.wr_id.value(), id);
            snapshots.consume(&queue);
            assert!(snapshots.head(&queue).is_none());
            assert_eq!(queue.storage().consumer(), snapshots.position());
        }
        Ok(())
    }

    #[test]
    fn native_snapshot_ignores_client_progress_and_survives_reuse() -> Result {
        let storage = Storage::new(1, (SEND_HEADER_SIZE + SGE_SIZE) as u32, 64)?;
        let mut snapshots = SendSnapshots::new(&storage, SEND_HEADER_SIZE + SGE_SIZE)?;
        let mut request = [0xff; SEND_HEADER_SIZE + SGE_SIZE];
        request[24..32].copy_from_slice(&0x12345678u64.to_ne_bytes());
        request[184..188].copy_from_slice(&32u32.to_ne_bytes());
        storage.memory().write(storage.offset(0), &request)?;
        {
            let mut work = snapshots.get(&storage, 0)?;
            assert_eq!(work.wr.wr_id.value(), u64::MAX);
            assert_eq!(work.iova, 0x12345678);
            assert_eq!(
                (work.status, work.state, work.mask, work.has_rd_atomic),
                (0, 0, 0, 0)
            );
            assert_eq!((work.first_psn, work.last_psn), (0, 0));
            assert_eq!(work.dma, Cursor::new(32, u32::MAX));
            assert!(work.dma().is_err());
            work.state = 2;
            work.dma.resid = 16;
        }
        storage.memory().fill(storage.offset(0), request.len(), 0)?;
        {
            let work = snapshots.get(&storage, 0)?;
            assert_eq!(work.wr.wr_id.value(), u64::MAX);
            assert_eq!((work.state, work.dma.resid), (2, 16));
        }
        snapshots.release(0);
        {
            let work = snapshots.get(&storage, 2)?;
            assert_eq!(work.wr.wr_id.value(), 0);
            assert_eq!((work.state, work.dma.resid), (0, 0));
        }
        storage.memory().write(storage.offset(0), &request)?;
        snapshots.reset();
        assert_eq!(snapshots.get(&storage, 0)?.wr.wr_id.value(), u64::MAX);
        Ok(())
    }

    #[test]
    fn inline_and_atomic_data_stay_inside_the_captured_slot() -> Result {
        let storage = Storage::new(1, (SEND_HEADER_SIZE + SGE_SIZE) as u32, 64)?;
        let mut snapshots = SendSnapshots::new(&storage, SEND_HEADER_SIZE + SGE_SIZE)?;
        let mut request = [0; SEND_HEADER_SIZE + SGE_SIZE];
        request[184..188].copy_from_slice(&8u32.to_ne_bytes());
        request[SEND_HEADER_SIZE..SEND_HEADER_SIZE + 8].copy_from_slice(b"abcdefgh");
        storage.memory().write(storage.offset(0), &request)?;
        let mut work = snapshots.get(&storage, 0)?;
        let mut first = [0; 3];
        work.copy_inline(&mut first, 8)?;
        assert_eq!(&first, b"abc");
        let progress = work.dma;
        let mut last = [0x55; 5];
        assert_eq!(work.copy_inline(&mut last, 7), Err(EINVAL));
        assert_eq!(last, [0x55; 5]);
        assert_eq!(work.dma, progress);
        work.copy_inline(&mut last, 8)?;
        assert_eq!(&last, b"defgh");
        assert_eq!(work.dma.resid, 0);
        work.dma.reset();
        let mut atomic = [0; 8];
        assert_eq!(work.copy_atomic_write(&mut atomic[..7]), Err(EINVAL));
        assert_eq!(work.dma.resid, 8);
        work.copy_atomic_write(&mut atomic)?;
        assert_eq!(&atomic, b"abcdefgh");
        assert_eq!(work.dma.resid, 0);
        work.dma.reset();
        work.dma.sge_offset = u32::MAX;
        assert_eq!(work.copy_inline(&mut first, usize::MAX), Err(EINVAL));
        assert_eq!(work.dma.resid, 8);
        Ok(())
    }

    #[test]
    fn request_fields_keep_abi_offsets() {
        let mut bytes = [0; SEND_HEADER_SIZE];
        bytes[..8].copy_from_slice(&0x0102030405060708u64.to_ne_bytes());
        bytes[12..16].copy_from_slice(&0x1234u32.to_ne_bytes());
        bytes[16..20].copy_from_slice(&0x5678u32.to_ne_bytes());
        bytes[20..24].copy_from_slice(&[1, 2, 3, 4]);
        for (offset, value) in [
            (24, 1u32),
            (28, 2),
            (32, 3),
            (36, 4),
            (40, 5),
            (44, 6),
            (48, 7),
            (52, 8),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        bytes[56..144].fill(0xa5);
        let request = Request::decode(&bytes);
        assert_eq!(request.wr_id.value(), 0x0102030405060708);
        assert_eq!(request.opcode, 0x1234);
        assert_eq!(request.send_flags, 0x5678);
        assert_eq!(request.immediate(), [1, 2, 3, 4]);
        assert_eq!(request.invalidate_key(), u32::from_ne_bytes([1, 2, 3, 4]));
        assert_eq!(request.remote_key(), 3);
        assert_eq!(request.atomic_key(), 7);
        assert_eq!(request.destination(), 1);
        assert_eq!(request.datagram_key(), 2);
        assert_eq!(request.address_handle(), 4);
        assert_eq!(request.window().region_key, 5);
        assert_eq!(request.window().window_key, 6);
        assert_eq!(request.window().new_key, 7);
        assert_eq!(request.window().access, 8);
        assert_eq!(request.legacy_address_vector(), &[0xa5; 88]);
    }
}
