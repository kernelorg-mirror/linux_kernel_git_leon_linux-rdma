// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Private snapshots of client-owned work requests.

#![forbid(unsafe_code)]

use kernel::{
    prelude::*,
    rdma::CompletionId, //
};

use super::{
    rxe_mr_data::{
        Cursor,
        Dma, //
    },
    rxe_ring::Storage, //
};

pub(super) const RECV_HEADER_SIZE: usize = 40;
pub(super) const SGE_SIZE: usize = 16;
pub(super) const NUM_SGE_OFFSET: usize = 28;
const MAX_SGE: usize = 32;

pub(super) const SEND_WR_SIZE: usize = 144;
pub(super) const SEND_DMA_OFFSET: usize = 184;
pub(super) const SEND_HEADER_SIZE: usize = 208;

/// A bounded receive request copied from one queue slot.
///
/// The header is read once before its SGE count is decoded. Later client writes cannot alter
/// either that count or the private descriptors. Cursor fields are initialized locally;
/// memory keys and lengths are validated by the operation that consumes the request.
pub(super) struct ReceiveWqe {
    id: CompletionId,
    cursor: Cursor,
    descriptors: [u8; MAX_SGE * SGE_SIZE],
}

/// A failed decode retains readable identity for a selected receive.
pub(super) struct ReceiveFailure {
    id: Option<CompletionId>,
}

impl ReceiveFailure {
    /// Produces only the retained identity, without malformed cursor or descriptor state.
    pub(super) fn completion(self) -> Option<ReceiveWqe> {
        self.id.map(|id| ReceiveWqe {
            id,
            cursor: Cursor::new(0, 0),
            descriptors: [0; MAX_SGE * SGE_SIZE],
        })
    }
}

impl ReceiveWqe {
    #[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
    pub(super) fn read(storage: &Storage, index: u32, max_sge: u32) -> Result<Self> {
        Self::capture(storage, index, max_sge).map_err(|_| EINVAL)
    }

    /// Preserves an error-only snapshot when a readable request has invalid descriptors.
    pub(super) fn capture(
        storage: &Storage,
        index: u32,
        max_sge: u32,
    ) -> Result<Self, ReceiveFailure> {
        let mut header = [0; RECV_HEADER_SIZE];
        storage
            .read(index, 0, &mut header)
            .map_err(|_| ReceiveFailure { id: None })?;
        let mut snapshot = Self {
            id: storage.completion_id(index, u64::from_ne_bytes(header[..8].try_into().unwrap())),
            cursor: Cursor::new(0, 0),
            descriptors: [0; MAX_SGE * SGE_SIZE],
        };
        if snapshot
            .read_descriptors(storage, index, max_sge, &header)
            .is_err()
        {
            return Err(ReceiveFailure {
                id: Some(snapshot.id),
            });
        }
        Ok(snapshot)
    }

    fn read_descriptors(
        &mut self,
        storage: &Storage,
        index: u32,
        max_sge: u32,
        header: &[u8; RECV_HEADER_SIZE],
    ) -> Result {
        let count = u32::from_ne_bytes(
            header[NUM_SGE_OFFSET..NUM_SGE_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        if count > max_sge || count as usize > MAX_SGE {
            return Err(EINVAL);
        }
        self.cursor = Cursor::new(
            u32::from_ne_bytes(header[16..20].try_into().unwrap()),
            count,
        );
        storage.read(
            index,
            RECV_HEADER_SIZE,
            &mut self.descriptors[..count as usize * SGE_SIZE],
        )?;
        if self.capacity() != u64::from(self.cursor.length) {
            return Err(EINVAL);
        }
        Ok(())
    }

    pub(super) fn id(&self) -> CompletionId {
        self.id.clone()
    }

    pub(super) fn received(&self) -> u32 {
        self.cursor.length - self.cursor.resid
    }

    pub(super) fn remaining(&self) -> u32 {
        self.cursor.resid
    }

    pub(super) fn capacity(&self) -> u64 {
        self.descriptors[..self.cursor.num_sge as usize * SGE_SIZE]
            .chunks_exact(SGE_SIZE)
            .map(|sge| u64::from(u32::from_ne_bytes(sge[8..12].try_into().unwrap())))
            .sum()
    }

    pub(super) fn dma(&mut self) -> Result<Dma<'_>> {
        Dma::from_cursor(&mut self.cursor, &self.descriptors)
    }

    pub(super) fn reset(&mut self) {
        self.cursor.reset();
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_wqe)]
mod tests {
    use super::*;

    #[test]
    fn receive_snapshot_rejects_inconsistent_capacity() -> Result {
        let storage = Storage::new(1, (RECV_HEADER_SIZE + SGE_SIZE) as u32, 64)?;
        let mut request = [0u8; RECV_HEADER_SIZE + SGE_SIZE];
        request[..8].copy_from_slice(&0x12345678u64.to_ne_bytes());
        request[28..32].copy_from_slice(&1u32.to_ne_bytes());
        for (aggregate, capacity) in [(8u32, 4u32), (40, 41)] {
            request[16..20].copy_from_slice(&aggregate.to_ne_bytes());
            request[48..52].copy_from_slice(&capacity.to_ne_bytes());
            storage.memory().write(storage.offset(0), &request)?;
            assert!(matches!(ReceiveWqe::read(&storage, 0, 1), Err(EINVAL)));
            let failure = ReceiveWqe::capture(&storage, 0, 1).err().unwrap();
            let completion = failure.completion().unwrap();
            storage.memory().fill(storage.offset(0), request.len(), 0)?;
            assert_eq!(completion.id().value(), 0x12345678);
            assert_eq!(completion.capacity(), 0);
            assert_eq!(completion.remaining(), 0);
        }
        Ok(())
    }

    #[test]
    fn receive_snapshot_owns_descriptors_and_initializes_progress() -> Result {
        let storage = Storage::new(1, (RECV_HEADER_SIZE + SGE_SIZE) as u32, 64)?;
        let mut request = [0xff; RECV_HEADER_SIZE + SGE_SIZE];
        request[16..20].copy_from_slice(&8u32.to_ne_bytes());
        request[28..32].copy_from_slice(&1u32.to_ne_bytes());
        request[40..48].copy_from_slice(&0x1000u64.to_ne_bytes());
        request[48..52].copy_from_slice(&8u32.to_ne_bytes());
        storage.memory().write(storage.offset(0), &request)?;
        let mut receive = ReceiveWqe::read(&storage, 0, 1)?;
        storage.memory().fill(storage.offset(0), request.len(), 0)?;
        assert_eq!(receive.id().value(), u64::MAX);
        assert_eq!(receive.capacity(), 8);
        assert_eq!(receive.received(), 0);
        receive.dma()?.advance(3)?;
        assert_eq!(receive.received(), 3);
        receive.reset();
        assert_eq!(receive.received(), 0);
        receive.dma()?.advance(8)?;
        assert_eq!(receive.received(), 8);
        Ok(())
    }
}
