// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Bounded scatter/gather transfers through private work requests.

#![forbid(unsafe_code)]

use super::rxe_mr::MrRef;
use kernel::prelude::*;

pub(super) const DMA_HEADER_SIZE: usize = 24;
const SGE_SIZE: usize = 16;

/// A private packet buffer and its direction relative to registered memory.
pub(super) enum Buffer<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

/// Transfer progress initialized by the driver, independent of the shared-memory ABI.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Cursor {
    pub(super) length: u32,
    pub(super) resid: u32,
    pub(super) cur_sge: u32,
    pub(super) num_sge: u32,
    pub(super) sge_offset: u32,
}

impl Cursor {
    pub(super) fn new(length: u32, num_sge: u32) -> Self {
        Self {
            length,
            resid: length,
            num_sge,
            ..Self::default()
        }
    }

    pub(super) fn reset(&mut self) {
        self.resid = self.length;
        self.cur_sge = 0;
        self.sge_offset = 0;
    }
}

/// A checked view of private descriptors and transfer progress.
///
/// Descriptors cannot change while this view exists. Each successful chunk updates the borrowed
/// cursor before attempting the next callback. A failing callback may have copied a prefix
/// which is not reflected in the cursor; callers must fail the request instead of resuming it.
/// Descriptor offsets and transfer lengths are bounded by slices.
pub(super) struct Dma<'a> {
    descriptors: &'a [u8],
    cursor: &'a mut Cursor,
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

impl<'a> Dma<'a> {
    pub(super) fn from_cursor(cursor: &'a mut Cursor, descriptors: &'a [u8]) -> Result<Self> {
        let size = (cursor.num_sge as usize)
            .checked_mul(SGE_SIZE)
            .ok_or(EINVAL)?;
        let descriptors = descriptors.get(..size).ok_or(EINVAL)?;
        if cursor.resid > cursor.length {
            return Err(EINVAL);
        }
        Ok(Self {
            cursor,
            descriptors,
        })
    }

    fn transfer(
        &mut self,
        length: usize,
        mut copy: impl FnMut(u32, u64, usize, usize) -> Result,
    ) -> Result {
        if length > self.cursor.resid as usize {
            return Err(EINVAL);
        }
        let mut done = 0;
        while done < length {
            let offset = (self.cursor.cur_sge as usize)
                .checked_mul(SGE_SIZE)
                .ok_or(ENOSPC)?;
            let sge = self.descriptors.get(offset..).ok_or(ENOSPC)?;
            let sge = sge.get(..SGE_SIZE).ok_or(ENOSPC)?;
            let size = word(sge, 8);
            if self.cursor.sge_offset >= size {
                self.cursor.cur_sge += 1;
                self.cursor.sge_offset = 0;
                continue;
            }
            let bytes = (length - done).min((size - self.cursor.sge_offset) as usize);
            let address = u64::from_ne_bytes(sge[..8].try_into().unwrap())
                .checked_add(u64::from(self.cursor.sge_offset))
                .ok_or(EINVAL)?;
            address.checked_add(bytes as u64).ok_or(EINVAL)?;
            copy(word(sge, 12), address, done, bytes)?;
            self.cursor.sge_offset += bytes as u32;
            self.cursor.resid -= bytes as u32;
            done += bytes;
        }
        Ok(())
    }

    pub(super) fn copy(
        &mut self,
        mut buffer: Buffer<'_>,
        mut lookup: impl FnMut(u32) -> Option<MrRef>,
    ) -> Result {
        let length = match &buffer {
            Buffer::Read(bytes) => bytes.len(),
            Buffer::Write(bytes) => bytes.len(),
        };
        self.transfer(length, |key, address, offset, length| {
            let memory = lookup(key).ok_or(EINVAL)?;
            match &mut buffer {
                Buffer::Read(bytes) => memory.access().read(
                    memory.device(),
                    address,
                    &mut bytes[offset..offset + length],
                ),
                Buffer::Write(bytes) => {
                    memory
                        .access()
                        .write(memory.device(), address, &bytes[offset..offset + length])
                }
            }
        })
    }

    pub(super) fn advance(&mut self, length: usize) -> Result {
        self.transfer(length, |_, _, _, _| Ok(()))
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_mr_data)]
mod tests {
    use super::*;

    #[test]
    fn native_cursor_retains_progress_and_rejects_short_descriptors() -> Result {
        let mut cursor = Cursor::new(8, 2);
        let mut descriptors = [0u8; SGE_SIZE * 2];
        descriptors[8..12].copy_from_slice(&3u32.to_ne_bytes());
        descriptors[24..28].copy_from_slice(&5u32.to_ne_bytes());
        let initial = cursor;
        assert!(Dma::from_cursor(&mut cursor, &descriptors[..SGE_SIZE]).is_err());
        assert_eq!(cursor, initial);
        {
            let mut dma = Dma::from_cursor(&mut cursor, &descriptors)?;
            assert_eq!(
                dma.transfer(6, |_, _, offset, _| {
                    if offset == 0 {
                        Ok(())
                    } else {
                        Err(EFAULT)
                    }
                }),
                Err(EFAULT)
            );
        }
        assert_eq!(cursor.resid, 5);
        assert_eq!(cursor.cur_sge, 1);
        assert_eq!(cursor.sge_offset, 0);
        Dma::from_cursor(&mut cursor, &descriptors)?.advance(5)?;
        assert_eq!(cursor.resid, 0);
        cursor.reset();
        assert_eq!(cursor, initial);
        Dma::from_cursor(&mut cursor, &descriptors)?.advance(8)?;
        assert_eq!(cursor.resid, 0);
        Ok(())
    }

    #[test]
    fn scatter_cursor_skips_empty_entries_and_retains_partial_progress() -> Result {
        let mut cursor = Cursor::new(7, 3);
        let mut bytes = [0u8; 3 * SGE_SIZE];
        bytes[16..24].copy_from_slice(&0x1000u64.to_ne_bytes());
        bytes[24..28].copy_from_slice(&3u32.to_ne_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_ne_bytes());
        bytes[32..40].copy_from_slice(&0x2000u64.to_ne_bytes());
        bytes[40..44].copy_from_slice(&4u32.to_ne_bytes());
        bytes[44..48].copy_from_slice(&2u32.to_ne_bytes());
        {
            let mut dma = Dma::from_cursor(&mut cursor, &bytes)?;
            let mut calls = 0;
            assert_eq!(
                dma.transfer(5, |key, address, offset, length| {
                    calls += 1;
                    if key == 1 {
                        assert_eq!((address, offset, length), (0x1000, 0, 3));
                        Ok(())
                    } else {
                        assert_eq!((key, address, offset, length), (2, 0x2000, 3, 2));
                        Err(EFAULT)
                    }
                }),
                Err(EFAULT)
            );
            assert_eq!(calls, 2);
        }
        assert_eq!(cursor.resid, 4);
        assert_eq!(cursor.cur_sge, 2);
        assert_eq!(cursor.sge_offset, 0);
        Dma::from_cursor(&mut cursor, &bytes)?.advance(4)?;
        assert_eq!(cursor.resid, 0);
        assert_eq!(cursor.sge_offset, 4);
        Ok(())
    }

    #[test]
    fn malformed_scatter_lengths_and_wrapping_addresses_are_rejected() -> Result {
        let mut bytes = [0u8; SGE_SIZE];
        let mut cursor = Cursor::new(8, u32::MAX);
        assert!(Dma::from_cursor(&mut cursor, &bytes).is_err());
        cursor.num_sge = 1;
        bytes[..8].copy_from_slice(&u64::MAX.to_ne_bytes());
        bytes[8..12].copy_from_slice(&8u32.to_ne_bytes());
        assert_eq!(
            Dma::from_cursor(&mut cursor, &bytes)?.advance(9),
            Err(EINVAL)
        );
        assert_eq!(
            Dma::from_cursor(&mut cursor, &bytes)?.advance(1),
            Err(EINVAL)
        );
        bytes[..8].copy_from_slice(&0x1000u64.to_ne_bytes());
        cursor.cur_sge = u32::MAX;
        assert_eq!(
            Dma::from_cursor(&mut cursor, &bytes)?.advance(1),
            Err(ENOSPC)
        );
        assert_eq!(cursor.resid, 8);
        cursor.resid = 9;
        assert!(Dma::from_cursor(&mut cursor, &bytes).is_err());
        Ok(())
    }
}
