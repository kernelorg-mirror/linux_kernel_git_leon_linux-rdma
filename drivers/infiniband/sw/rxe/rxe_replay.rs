// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Owned responder replay slots with typed operation state.

#![forbid(unsafe_code)]

use super::{
    rxe_resp_memory::Authorization,
    rxe_wire::psn_compare, //
};
use kernel::prelude::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    Read,
    Atomic,
    AtomicWrite,
    Flush,
}

#[derive(Clone, Copy)]
pub(super) enum Request {
    Read {
        address: u64,
        key: u32,
        length: u32,
        authorization: Option<Authorization>,
    },
    Atomic,
    AtomicWrite,
    Flush {
        address: u64,
        length: u32,
        kind: u8,
        level: u8,
    },
}

#[derive(Clone, Copy)]
pub(super) enum Duplicate {
    Read { address: u64, key: u32, length: u32 },
    Atomic,
    AtomicWrite,
    Flush,
}

impl Duplicate {
    fn kind(self) -> Kind {
        match self {
            Self::Read { .. } => Kind::Read,
            Self::Atomic => Kind::Atomic,
            Self::AtomicWrite => Kind::AtomicWrite,
            Self::Flush => Kind::Flush,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Read {
    pub(super) address: u64,
    pub(super) residual: u32,
    pub(super) key: u32,
    pub(super) first: bool,
    pub(super) psn: u32,
    pub(super) replay: bool,
    pub(super) authorization: Option<Authorization>,
}

#[derive(Clone, Copy)]
pub(super) struct Flush {
    pub(super) address: u64,
    pub(super) length: u32,
    pub(super) kind: u8,
    pub(super) level: u8,
}

enum Data {
    Read {
        original: u64,
        offset: u64,
        length: u32,
        end: u64,
        mtu: u32,
        complete: bool,
        current: Read,
    },
    Atomic {
        original: u64,
    },
    AtomicWrite,
    Flush(Flush),
}

struct Resource {
    first: u32,
    last: u32,
    replay: bool,
    data: Data,
}

impl Resource {
    fn new(request: Request, psn: u32, mtu: u32, offset: u64) -> Result<Self> {
        let psn = psn & 0xffffff;
        let mut last = psn;
        let data = match request {
            Request::Read {
                address,
                key,
                length,
                authorization,
            } => {
                if mtu == 0 {
                    return Err(EINVAL);
                }
                let translated = address.checked_add(offset).ok_or(EINVAL)?;
                let end = translated.checked_add(u64::from(length)).ok_or(EINVAL)?;
                let packets = length.div_ceil(mtu).max(1);
                if packets > 0x800000 {
                    return Err(EINVAL);
                }
                last = psn.wrapping_add(packets - 1) & 0xffffff;
                Data::Read {
                    original: address,
                    offset,
                    length,
                    end,
                    mtu,
                    complete: false,
                    current: Read {
                        address: translated,
                        residual: length,
                        key,
                        first: true,
                        psn,
                        replay: false,
                        authorization,
                    },
                }
            }
            Request::Atomic => Data::Atomic { original: 0 },
            Request::AtomicWrite => Data::AtomicWrite,
            Request::Flush {
                address,
                length,
                kind,
                level,
            } => Data::Flush(Flush {
                address: address.checked_add(offset).ok_or(EINVAL)?,
                length,
                kind,
                level,
            }),
        };
        Ok(Self {
            first: psn,
            last,
            replay: false,
            data,
        })
    }

    fn kind(&self) -> Kind {
        match self.data {
            Data::Read { .. } => Kind::Read,
            Data::Atomic { .. } => Kind::Atomic,
            Data::AtomicWrite => Kind::AtomicWrite,
            Data::Flush(_) => Kind::Flush,
        }
    }

    fn replaceable(&self) -> bool {
        !matches!(
            self.data,
            Data::Read {
                complete: false,
                ..
            }
        )
    }
}

/// A fixed-capacity replay cache owned by the serialized responder task.
///
/// The active slot is an index into this allocation. Reset and replacement clear it before
/// discarding entries. Interrupted READ replies remain reserved until transmission finishes
/// or their entire response range leaves the half-space duplicate window.
pub(super) struct Cache {
    slots: KVec<Option<Resource>>,
    next: usize,
    active: Option<usize>,
}

impl Cache {
    pub(super) fn new(count: usize) -> Result<KBox<Self>> {
        let mut slots = KVec::with_capacity(count, GFP_KERNEL)?;
        for _ in 0..count {
            slots.push(None, GFP_KERNEL)?;
        }
        Ok(KBox::new(
            Self {
                slots,
                next: 0,
                active: None,
            },
            GFP_KERNEL,
        )?)
    }

    pub(super) fn reset(&mut self) {
        self.active = None;
        self.next = 0;
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
    }

    pub(super) fn active(&self) -> bool {
        self.active.is_some()
    }

    pub(super) fn finish(&mut self) {
        self.active = None;
    }

    /// Expires reservations after every advance of the expected request PSN.
    ///
    /// Advances may cover at most half the sequence space, including a READ's reserved
    /// response range. An older retained entry is less than half a space behind, so adding
    /// such an advance cannot wrap its age. Measuring from the last PSN preserves still-valid
    /// suffix retries even when the first PSN has become ambiguous.
    pub(super) fn expire(&mut self, expected: u32) {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot
                .as_ref()
                .is_some_and(|resource| expected.wrapping_sub(resource.last) & 0xffffff >= 0x800000)
            {
                if self.active == Some(index) {
                    self.active = None;
                }
                *slot = None;
            }
        }
    }

    /// Returns `EAGAIN` when unfinished READs temporarily reserve every allocated slot.
    pub(super) fn start(&mut self, request: Request, psn: u32, mtu: u32, offset: u64) -> Result {
        if self.active() {
            return Err(EBUSY);
        }
        let resource = Resource::new(request, psn, mtu, offset)?;
        let count = self.slots.len();
        let index = (0..count)
            .map(|offset| (self.next + offset) % count)
            .find(|&index| self.slots[index].as_ref().is_none_or(Resource::replaceable))
            .ok_or(if count == 0 { ENOSPC } else { EAGAIN })?;
        self.slots[index] = Some(resource);
        self.active = Some(index);
        self.next = (index + 1) % count;
        Ok(())
    }

    fn current(&self) -> Result<&Resource> {
        self.slots
            .get(self.active.ok_or(EINVAL)?)
            .and_then(Option::as_ref)
            .ok_or(EINVAL)
    }

    fn current_mut(&mut self) -> Result<&mut Resource> {
        self.slots
            .get_mut(self.active.ok_or(EINVAL)?)
            .and_then(Option::as_mut)
            .ok_or(EINVAL)
    }

    pub(super) fn replaying(&self, kind: Kind) -> Result<bool> {
        let resource = self.current()?;
        if resource.kind() != kind {
            return Err(EINVAL);
        }
        Ok(resource.replay)
    }

    pub(super) fn read(&self) -> Result<Read> {
        match self.current()?.data {
            Data::Read { current, .. } => Ok(current),
            _ => Err(EINVAL),
        }
    }

    pub(super) fn read_end(&self) -> Result<u32> {
        let resource = self.current()?;
        if resource.kind() != Kind::Read {
            return Err(EINVAL);
        }
        Ok(resource.last.wrapping_add(1) & 0xffffff)
    }

    pub(super) fn flush(&self) -> Result<Flush> {
        match self.current()?.data {
            Data::Flush(flush) => Ok(flush),
            _ => Err(EINVAL),
        }
    }

    pub(super) fn atomic_original(&self) -> Result<u64> {
        match self.current()?.data {
            Data::Atomic { original } => Ok(original),
            _ => Err(EINVAL),
        }
    }

    pub(super) fn record_atomic(&mut self, value: u64) -> Result {
        match &mut self.current_mut()?.data {
            Data::Atomic { original } => *original = value,
            _ => return Err(EINVAL),
        }
        Ok(())
    }

    /// Advances only the successfully transmitted part of a read reply.
    pub(super) fn advance_read(&mut self, bytes: u32) -> Result<Read> {
        let Data::Read {
            current,
            end,
            complete,
            ..
        } = &mut self.current_mut()?.data
        else {
            return Err(EINVAL);
        };
        if bytes > current.residual {
            return Err(EINVAL);
        }
        current.address = current
            .address
            .checked_add(u64::from(bytes))
            .ok_or(EINVAL)?;
        current.residual -= bytes;
        current.psn = current.psn.wrapping_add(1) & 0xffffff;
        current.first = false;
        // A contained retry may finish before the original response's end. Only successful
        // transmission through that end releases the reservation; replay cannot undo it.
        *complete |= current.residual == 0 && current.address == *end;
        Ok(*current)
    }

    /// Selects a matching retained operation without reinterpreting another operation's state.
    pub(super) fn replay(&mut self, request: Duplicate, psn: u32) -> Option<Kind> {
        if self.active() {
            return None;
        }
        let psn = psn & 0xffffff;
        let (index, resource) = self
            .slots
            .iter_mut()
            .enumerate()
            .find_map(|(index, slot)| {
                let resource = slot.as_mut()?;
                (psn_compare(psn, resource.first) >= 0 && psn_compare(psn, resource.last) <= 0)
                    .then_some((index, resource))
            })?;
        if resource.kind() != request.kind() {
            return None;
        }
        if let Duplicate::Read {
            address,
            key,
            length,
        } = request
        {
            let Data::Read {
                original,
                offset,
                length: total,
                mtu,
                current,
                ..
            } = &mut resource.data
            else {
                return None;
            };
            if address < *original
                || length > *total
                || address - *original > u64::from(*total - length)
                || key != current.key
                || address - *original
                    != u64::from(psn.wrapping_sub(resource.first) & 0xffffff) * u64::from(*mtu)
            {
                return None;
            }
            current.address = address.checked_add(*offset)?;
            current.residual = length;
            current.psn = psn;
            current.first = psn == resource.first;
            current.replay = true;
        }
        resource.replay = true;
        self.active = Some(index);
        Some(resource.kind())
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_replay)]
mod tests {
    use super::*;

    #[test]
    fn read_reservations_expire_only_after_the_last_psn_ages_out() -> Result {
        let mut cache = Cache::new(1)?;
        cache.start(
            Request::Read {
                address: 0x1000,
                key: 7,
                length: 768,
                authorization: None,
            },
            0xfffffe,
            256,
            0,
        )?;
        cache.advance_read(256)?;
        cache.finish();
        cache.expire(1);
        // The first PSN is half a space old, but the final response PSN is still usable.
        cache.expire(0x7ffffe);
        assert_eq!(
            cache.replay(
                Duplicate::Read {
                    address: 0x1200,
                    key: 7,
                    length: 256
                },
                0,
            ),
            Some(Kind::Read)
        );
        cache.finish();
        cache.expire(0x7fffff);
        assert_eq!(cache.start(Request::Atomic, 0x7fffff, 256, 0), Err(EAGAIN));
        cache.expire(0x800000);
        assert_eq!(
            cache.replay(
                Duplicate::Read {
                    address: 0x1200,
                    key: 7,
                    length: 256
                },
                0,
            ),
            None
        );
        cache.start(Request::Atomic, 0x800000, 256, 0)?;
        Ok(())
    }

    #[test]
    fn a_large_read_advance_expires_older_reservations() -> Result {
        let mut cache = Cache::new(2)?;
        let read = |length| Request::Read {
            address: 0,
            key: 7,
            length,
            authorization: None,
        };
        cache.start(read(256), 0, 256, 0)?;
        cache.finish();
        cache.expire(1);
        cache.start(read(0x800000 * 256), 1, 256, 0)?;
        let end = cache.read_end()?;
        assert_eq!(end, 0x800001);
        cache.expire(end);
        assert!(cache.active());
        cache.finish();
        // The older unfinished entry expired, but the new READ remains reserved.
        cache.start(Request::Atomic, 0x800001, 256, 0)?;
        cache.finish();
        assert_eq!(
            cache.replay(
                Duplicate::Read {
                    address: 0,
                    key: 7,
                    length: 256
                },
                0
            ),
            None
        );
        assert_eq!(
            cache.replay(
                Duplicate::Read {
                    address: 0x7fffff * 256,
                    key: 7,
                    length: 256
                },
                0x800000,
            ),
            Some(Kind::Read)
        );
        Ok(())
    }

    #[test]
    fn shortened_retries_do_not_complete_the_original_read() -> Result {
        for length in [0, 256] {
            let mut cache = Cache::new(1)?;
            cache.start(
                Request::Read {
                    address: 0x1000,
                    key: 7,
                    length: 512,
                    authorization: None,
                },
                1,
                256,
                0x2000,
            )?;
            cache.advance_read(256)?;
            cache.finish();
            assert_eq!(
                cache.replay(
                    Duplicate::Read {
                        address: 0x1000,
                        key: 7,
                        length
                    },
                    1
                ),
                Some(Kind::Read)
            );
            cache.advance_read(length)?;
            cache.finish();
            assert_eq!(cache.start(Request::Atomic, 3, 256, 0), Err(EAGAIN));
            assert_eq!(
                cache.replay(
                    Duplicate::Read {
                        address: 0x1100,
                        key: 7,
                        length: 256
                    },
                    2,
                ),
                Some(Kind::Read)
            );
            cache.advance_read(256)?;
            cache.finish();
            cache.start(Request::Atomic, 3, 256, 0)?;
        }
        Ok(())
    }

    #[test]
    fn completed_read_stays_replaceable_after_replay() -> Result {
        for replay_bytes in [0, 128] {
            let mut cache = Cache::new(1)?;
            cache.start(
                Request::Read {
                    address: 0x1000,
                    key: 7,
                    length: 512,
                    authorization: None,
                },
                1,
                256,
                0,
            )?;
            cache.advance_read(256)?;
            cache.advance_read(256)?;
            cache.finish();
            assert_eq!(
                cache.replay(
                    Duplicate::Read {
                        address: 0x1000,
                        key: 7,
                        length: 128
                    },
                    1,
                ),
                Some(Kind::Read)
            );
            if replay_bytes != 0 {
                cache.advance_read(replay_bytes)?;
            }
            // Both an interrupted replay and a finished subset preserve original completion.
            cache.finish();
            cache.start(Request::Atomic, 3, 256, 0)?;
        }
        Ok(())
    }

    #[test]
    fn interrupted_reads_survive_replacement_until_the_reply_finishes() -> Result {
        let mut cache = Cache::new(2)?;
        let request = Request::Read {
            address: 0x1000,
            key: 7,
            length: 512,
            authorization: None,
        };
        cache.start(request, 1, 256, 0)?;
        cache.advance_read(256)?;
        // A packet failure suspends this reply while another request is accepted.
        cache.finish();
        cache.start(Request::Atomic, 3, 256, 0)?;
        cache.record_atomic(17)?;
        cache.finish();
        cache.start(Request::AtomicWrite, 4, 256, 0)?;
        cache.finish();
        assert_eq!(cache.replay(Duplicate::Atomic, 3), None);
        assert_eq!(
            cache.replay(
                Duplicate::Read {
                    address: 0x1100,
                    key: 7,
                    length: 256,
                },
                2,
            ),
            Some(Kind::Read)
        );
        cache.advance_read(256)?;
        cache.finish();
        cache.start(Request::Atomic, 5, 256, 0)?;
        cache.finish();
        assert_eq!(
            cache.replay(
                Duplicate::Read {
                    address: 0x1100,
                    key: 7,
                    length: 256,
                },
                2,
            ),
            None
        );
        Ok(())
    }

    #[test]
    fn empty_read_reservation_requires_a_successful_reply() -> Result {
        let mut cache = Cache::new(1)?;
        cache.start(
            Request::Read {
                address: 0,
                key: 7,
                length: 0,
                authorization: None,
            },
            0xffffff,
            256,
            0,
        )?;
        cache.finish();
        assert_eq!(cache.start(Request::Atomic, 0, 256, 0), Err(EAGAIN));
        assert_eq!(
            cache.replay(
                Duplicate::Read {
                    address: 0,
                    key: 7,
                    length: 0,
                },
                0xffffff,
            ),
            Some(Kind::Read)
        );
        cache.advance_read(0)?;
        cache.finish();
        cache.start(Request::Atomic, 0, 256, 0)?;
        Ok(())
    }

    #[test]
    fn typed_replay_eviction_and_reset() -> Result {
        let mut cache = Cache::new(2)?;
        cache.start(Request::Atomic, 1, 1024, 0)?;
        cache.record_atomic(17)?;
        assert_eq!(cache.start(Request::AtomicWrite, 2, 1024, 0), Err(EBUSY));
        assert_eq!(cache.atomic_original()?, 17);
        cache.finish();
        assert_eq!(cache.replay(Duplicate::AtomicWrite, 1), None);
        assert!(!cache.active());
        assert_eq!(cache.replay(Duplicate::Atomic, 1), Some(Kind::Atomic));
        assert!(cache.replaying(Kind::Atomic)?);
        assert_eq!(cache.atomic_original()?, 17);
        cache.finish();
        let flush = Request::Flush {
            address: 4,
            length: 8,
            kind: 1,
            level: 0,
        };
        cache.start(flush, 2, 1024, 0x1000)?;
        cache.finish();
        cache.start(Request::AtomicWrite, 3, 1024, 0)?;
        cache.finish();
        assert_eq!(cache.replay(Duplicate::Atomic, 1), None);
        assert_eq!(cache.replay(Duplicate::Flush, 2), Some(Kind::Flush));
        assert_eq!(cache.flush()?.address, 0x1004);
        assert_eq!(cache.flush()?.length, 8);
        assert!(cache.read().is_err());
        assert!(cache.atomic_original().is_err());
        cache.reset();
        assert!(!cache.active());
        assert_eq!(cache.replay(Duplicate::Flush, 2), None);
        cache.start(Request::Atomic, 4, 1024, 0)?;
        assert_eq!(cache.atomic_original()?, 0);
        let mut empty = Cache::new(0)?;
        assert_eq!(empty.start(Request::Atomic, 1, 1024, 0), Err(ENOSPC));
        assert!(!empty.active());
        Ok(())
    }

    #[test]
    fn empty_reads_replay_with_their_original_key() -> Result {
        let mut cache = Cache::new(1)?;
        cache.start(
            Request::Read {
                address: u64::MAX,
                key: 0x1234,
                length: 0,
                authorization: None,
            },
            7,
            256,
            0,
        )?;
        cache.finish();
        for (key, expected) in [(0, None), (0x1234, Some(Kind::Read))] {
            assert_eq!(
                cache.replay(
                    Duplicate::Read {
                        address: u64::MAX,
                        key,
                        length: 0,
                    },
                    7,
                ),
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn read_ranges_allow_exactly_half_the_psn_space() {
        for (length, valid) in [
            ((1 << 31) + 1, false),
            (1 << 31, true),
            ((1 << 31) - 256, true),
        ] {
            let resource = Resource::new(
                Request::Read {
                    address: 0,
                    key: 7,
                    length,
                    authorization: None,
                },
                0xffffff,
                256,
                0,
            );
            assert_eq!(resource.is_ok(), valid);
        }
    }

    #[test]
    fn maximum_reads_replay_both_ends_across_psn_wrap() -> Result {
        let length = 1 << 31;
        for first in [0, 0x7fffff, 0xffffff] {
            let mut cache = Cache::new(1)?;
            cache.start(
                Request::Read {
                    address: 0,
                    key: 7,
                    length,
                    authorization: None,
                },
                first,
                256,
                0,
            )?;
            let end = first.wrapping_add(0x800000) & 0xffffff;
            assert_eq!(cache.read_end()?, end);
            cache.expire(end);
            cache.finish();
            for (psn, address, bytes) in [
                (first, 0, length),
                (end.wrapping_sub(1) & 0xffffff, u64::from(length - 256), 256),
            ] {
                assert_eq!(
                    cache.replay(
                        Duplicate::Read {
                            address,
                            key: 7,
                            length: bytes
                        },
                        psn
                    ),
                    Some(Kind::Read)
                );
                cache.finish();
            }
            cache.expire(first.wrapping_sub(1) & 0xffffff);
            assert_eq!(
                cache.replay(
                    Duplicate::Read {
                        address: 0,
                        key: 7,
                        length
                    },
                    first
                ),
                None
            );
        }
        Ok(())
    }

    #[test]
    fn read_replay_keeps_original_bounds_and_window_translation() -> Result {
        let mut cache = Cache::new(1)?;
        let authorization = Authorization::new(
            super::super::rxe_version::Version::new()?,
            Some(super::super::rxe_version::Version::new()?),
        );
        let request = Request::Read {
            address: 0,
            key: 7,
            length: 10,
            authorization: Some(authorization),
        };
        cache.start(request, 0xfffffe, 4, 0x1000)?;
        let first = cache.read()?;
        assert_eq!(first.address, 0x1000);
        assert_eq!(first.authorization, Some(authorization));
        assert!(first.first);
        assert_eq!(cache.advance_read(11), Err(EINVAL));
        assert_eq!(cache.read()?, first);
        assert_eq!(cache.advance_read(4)?.psn, 0xffffff);
        assert_eq!(cache.advance_read(4)?.psn, 0);
        assert_eq!(cache.advance_read(2)?.psn, 1);
        cache.finish();
        let suffix = Duplicate::Read {
            address: 4,
            key: 7,
            length: 6,
        };
        // PSN and address must identify the same original segment, even if the
        // requested memory range and PSN would each be valid independently.
        assert_eq!(cache.replay(suffix, 0xfffffe), None);
        assert_eq!(
            cache.replay(
                Duplicate::Read {
                    address: 0,
                    key: 7,
                    length: 10,
                },
                0xffffff
            ),
            None
        );
        assert_eq!(cache.replay(suffix, 0xffffff), Some(Kind::Read));
        let read = cache.read()?;
        assert_eq!(read.address, 0x1004);
        assert_eq!(read.residual, 6);
        assert!(!read.first);
        assert!(read.replay);
        assert_eq!(read.authorization, Some(authorization));
        cache.finish();
        assert_eq!(
            cache.replay(
                Duplicate::Read {
                    address: 0,
                    key: 7,
                    length: 10
                },
                0xfffffe
            ),
            Some(Kind::Read)
        );
        assert_eq!(cache.read()?.address, 0x1000);
        assert_eq!(cache.read()?.residual, 10);
        assert!(cache.read()?.first);
        assert_eq!(cache.read()?.authorization, Some(authorization));
        cache.finish();
        for invalid in [
            Duplicate::Read {
                address: 0,
                key: 8,
                length: 10,
            },
            Duplicate::Read {
                address: 5,
                key: 7,
                length: 6,
            },
            Duplicate::Read {
                address: u64::MAX,
                key: 7,
                length: 1,
            },
        ] {
            assert_eq!(cache.replay(invalid, 0xfffffe), None);
            assert!(!cache.active());
        }
        assert!(cache.start(request, 0, 0, 0).is_err());
        assert!(cache.start(request, 0, 4, u64::MAX).is_err());
        assert!(!cache.active());
        Ok(())
    }
}
