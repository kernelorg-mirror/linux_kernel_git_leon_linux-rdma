// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Checked RoCE transport views over initialized packet bytes.

#![forbid(unsafe_code)]

use super::rxe_opcode::{
    self,
    Opcode, //
};
use super::rxe_param::*;
use kernel::error::{
    code::EINVAL,
    Result, //
};

pub(super) const BTH_BYTES: usize = 12;
pub(super) const ICRC_BYTES: usize = 4;
const PAYLOAD_INDEX: usize = 12;

/// A validated transport header and payload, excluding the ICRC.
///
/// # Invariants
///
/// The complete opcode-specific header and padding fit in `bytes`. The
/// immutable opcode layout has a nonzero mask and a header of at least BTH_BYTES.
/// `payload` is a bounded opcode-specific offset no later than `data_end`.
/// Opcodes without a data payload start padding immediately after the header.
pub(super) struct Transport<'a> {
    bytes: &'a [u8],
    layout: &'static Opcode,
    payload: usize,
    data_end: usize,
}

impl<'a> Transport<'a> {
    /// Rejects unknown opcodes and truncated headers or padding.
    pub(super) fn parse(bytes: &'a [u8]) -> Result<Self> {
        let opcode = *bytes.first().ok_or(EINVAL)?;
        let layout = rxe_opcode::info(opcode);
        let header = usize::try_from(layout.length).map_err(|_| EINVAL)?;
        if layout.mask == 0 || header < BTH_BYTES || header > bytes.len() || bytes.len() % 4 != 0 {
            return Err(EINVAL);
        }
        let pad = usize::from((bytes[1] >> 4) & 3);
        let data_end = bytes.len().checked_sub(pad).ok_or(EINVAL)?;
        let payload = if layout.mask & RXE_PAYLOAD_MASK == 0 {
            if bytes.len() != header || pad != 0 {
                return Err(EINVAL);
            }
            header
        } else {
            usize::try_from(layout.offset[PAYLOAD_INDEX]).map_err(|_| EINVAL)?
        };
        if header > data_end || payload > data_end {
            return Err(EINVAL);
        }
        // INVARIANT: The checked layout, payload boundary and padding all fit.
        Ok(Self {
            bytes,
            layout,
            payload,
            data_end,
        })
    }

    pub(super) fn opcode(&self) -> u8 {
        self.bytes[0]
    }

    pub(super) fn psn(&self) -> u32 {
        u32::from_be_bytes([0, self.bytes[9], self.bytes[10], self.bytes[11]])
    }

    pub(super) fn mask(&self) -> u32 {
        self.layout.mask
    }

    pub(super) fn payload_len(&self) -> usize {
        self.data_end - self.payload
    }

    pub(super) fn qpn(&self) -> u32 {
        u32::from_be_bytes([0, self.bytes[5], self.bytes[6], self.bytes[7]])
    }

    pub(super) fn pkey(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    pub(super) fn version(&self) -> u8 {
        self.bytes[1] & 0xf
    }

    pub(super) fn pad(&self) -> u8 {
        (self.bytes[1] >> 4) & 3
    }

    pub(super) fn solicited(&self) -> bool {
        self.bytes[1] & 0x80 != 0
    }

    pub(super) fn ack_requested(&self) -> bool {
        self.bytes[8] & 0x80 != 0
    }

    /// Borrows data without exposing transport headers, padding or ICRC.
    pub(super) fn payload(&self) -> Result<&'a [u8]> {
        if self.mask() & RXE_PAYLOAD_MASK == 0 || self.payload < self.layout.length as usize {
            return Err(EINVAL);
        }
        Ok(&self.bytes[self.payload..self.data_end])
    }

    fn extension<const N: usize>(&self, kind: u32) -> Result<&'a [u8; N]> {
        if self.mask() & (1 << kind) == 0 {
            return Err(EINVAL);
        }
        let start = usize::try_from(self.layout.offset[kind as usize]).map_err(|_| EINVAL)?;
        let end = start.checked_add(N).ok_or(EINVAL)?;
        self.bytes[..self.layout.length as usize]
            .get(start..end)
            .ok_or(EINVAL)?
            .try_into()
            .map_err(|_| EINVAL)
    }

    pub(super) fn remote(&self) -> Result<Remote> {
        let bytes = self.extension::<16>(RXE_RETH)?;
        Ok(Remote {
            address: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
            key: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            length: u32::from_be_bytes(bytes[12..].try_into().unwrap()),
        })
    }

    pub(super) fn syndrome(&self) -> Result<u8> {
        Ok(self.extension::<4>(RXE_AETH)?[0])
    }

    pub(super) fn atomic(&self) -> Result<Atomic> {
        let bytes = self.extension::<28>(RXE_ATMETH)?;
        Ok(Atomic {
            address: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
            key: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            swap: u64::from_be_bytes(bytes[12..20].try_into().unwrap()),
            compare: u64::from_be_bytes(bytes[20..].try_into().unwrap()),
        })
    }

    pub(super) fn atomic_reply(&self) -> Result<u64> {
        Ok(u64::from_be_bytes(*self.extension(RXE_ATMACK)?))
    }

    pub(super) fn invalidate(&self) -> Result<u32> {
        Ok(u32::from_be_bytes(*self.extension(RXE_IETH)?))
    }

    pub(super) fn immediate(&self) -> Result<[u8; 4]> {
        Ok(*self.extension(RXE_IMMDT)?)
    }

    pub(super) fn datagram(&self) -> Result<Datagram> {
        let bytes = self.extension::<8>(RXE_DETH)?;
        Ok(Datagram {
            key: u32::from_be_bytes(bytes[..4].try_into().unwrap()),
            source: u32::from_be_bytes([0, bytes[5], bytes[6], bytes[7]]),
        })
    }

    pub(super) fn flush(&self) -> Result<Flush> {
        let bits = u32::from_be_bytes(*self.extension(RXE_FETH)?);
        Ok(Flush {
            kind: (bits & 0xf) as u8,
            level: ((bits >> 4) & 3) as u8,
        })
    }

    /// Returns the base transport header as a bounded byte array.
    pub(super) fn bth(&self) -> &[u8] {
        &self.bytes[..BTH_BYTES]
    }

    /// Returns transport headers beyond the base transport header.
    pub(super) fn extended_headers(&self) -> &[u8] {
        &self.bytes[BTH_BYTES..self.layout.length as usize]
    }

    /// Returns data and pad bytes, both of which participate in ICRC.
    pub(super) fn padded_payload(&self) -> &[u8] {
        &self.bytes[self.payload..]
    }
}

/// Copied remote-memory fields, independent of packet alignment and storage.
pub(super) struct Remote {
    pub(super) address: u64,
    pub(super) key: u32,
    pub(super) length: u32,
}

pub(super) struct Atomic {
    pub(super) address: u64,
    pub(super) key: u32,
    pub(super) swap: u64,
    pub(super) compare: u64,
}

pub(super) struct Datagram {
    pub(super) key: u32,
    pub(super) source: u32,
}

pub(super) struct Flush {
    pub(super) kind: u8,
    pub(super) level: u8,
}

/// Constructs a base transport header without casting packet memory.
pub(super) fn bth(opcode: u8, psn: u32, solicited: bool, pad: u8, qpn: u32, ack: bool) -> [u8; 12] {
    let mut header = [0u8; BTH_BYTES];
    header[0] = opcode;
    header[1] = ((pad & 3) << 4) | if solicited { 0x80 } else { 0 };
    header[2..4].copy_from_slice(&0xffffu16.to_be_bytes());
    header[4..8].copy_from_slice(&(qpn & 0x00ff_ffff).to_be_bytes());
    let apsn = (psn & 0x00ff_ffff) | if ack { 0x8000_0000 } else { 0 };
    header[8..12].copy_from_slice(&apsn.to_be_bytes());
    header
}

/// Compares wrapping 24-bit packet sequence numbers.
pub(super) fn psn_compare(a: u32, b: u32) -> i32 {
    (a.wrapping_sub(b) << 8) as i32
}

/// Values for the base transport header of an outgoing packet.
pub(super) struct Base {
    pub(super) opcode: u8,
    pub(super) psn: u32,
    pub(super) qpn: u32,
    pub(super) solicited: bool,
    pub(super) ack: bool,
}

/// An opcode-specific extension, represented independently of packet storage.
pub(super) enum Extension {
    Remote {
        address: u64,
        key: u32,
        length: u32,
    },
    Acknowledge {
        syndrome: u8,
        sequence: u32,
    },
    Atomic {
        address: u64,
        key: u32,
        swap: u64,
        compare: u64,
    },
    AtomicReply(u64),
    Invalidate(u32),
    Datagram {
        key: u32,
        source: u32,
    },
    Immediate([u8; 4]),
    Flush {
        kind: u8,
        level: u8,
    },
}

/// Returns the complete transport allocation size, including padding and ICRC.
pub(super) fn packet_len(opcode: u8, payload: usize) -> Result<usize> {
    let layout = rxe_opcode::info(opcode);
    let header = usize::try_from(layout.length).map_err(|_| EINVAL)?;
    if layout.mask == 0
        || header < BTH_BYTES
        || (layout.mask & RXE_PAYLOAD_MASK == 0 && payload != 0)
    {
        return Err(EINVAL);
    }
    header
        .checked_add(payload)
        .and_then(|length| length.checked_add((4 - (payload & 3)) & 3))
        .and_then(|length| length.checked_add(ICRC_BYTES))
        .ok_or(EINVAL)
}

/// A writable transport view whose fields and payload stay inside the packet.
///
/// Includes the ICRC in its backing storage but never exposes it as payload. Header writes are
/// selected by typed extensions, and reject extensions absent from the packet's immutable opcode.
pub(super) struct TransportMut<'a> {
    bytes: &'a mut [u8],
    layout: &'static Opcode,
    payload: usize,
    data_end: usize,
}

impl<'a> TransportMut<'a> {
    pub(super) fn opcode(&self) -> u8 {
        self.bytes[0]
    }

    pub(super) fn mask(&self) -> u32 {
        self.layout.mask
    }

    pub(super) fn initialize(bytes: &'a mut [u8], base: Base, payload: usize) -> Result<Self> {
        if bytes.len() != packet_len(base.opcode, payload)? {
            return Err(EINVAL);
        }
        bytes.fill(0);
        let pad = ((4 - (payload & 3)) & 3) as u8;
        bytes[..BTH_BYTES].copy_from_slice(&bth(
            base.opcode,
            base.psn,
            base.solicited,
            pad,
            base.qpn,
            base.ack,
        ));
        Self::parse(bytes)
    }

    pub(super) fn parse(bytes: &'a mut [u8]) -> Result<Self> {
        let length = bytes.len().checked_sub(ICRC_BYTES).ok_or(EINVAL)?;
        let wire = Transport::parse(&bytes[..length])?;
        let (layout, payload, data_end) = (wire.layout, wire.payload, wire.data_end);
        Ok(Self {
            bytes,
            layout,
            payload,
            data_end,
        })
    }

    pub(super) fn payload(&mut self) -> Result<&mut [u8]> {
        if self.layout.mask & super::rxe_param::RXE_PAYLOAD_MASK == 0
            || self.payload < self.layout.length as usize
        {
            return Err(EINVAL);
        }
        Ok(&mut self.bytes[self.payload..self.data_end])
    }

    pub(super) fn set(&mut self, extension: Extension) -> Result {
        use super::rxe_param::*;
        let mut bytes = [0u8; RXE_ATMETH_BYTES as usize];
        let (kind, length) = match extension {
            Extension::Remote {
                address,
                key,
                length,
            } => {
                bytes[..8].copy_from_slice(&address.to_be_bytes());
                bytes[8..12].copy_from_slice(&key.to_be_bytes());
                bytes[12..16].copy_from_slice(&length.to_be_bytes());
                (RXE_RETH, RXE_RETH_BYTES)
            }
            Extension::Acknowledge { syndrome, sequence } => {
                let word = (u32::from(syndrome) << 24) | (sequence & 0xffffff);
                bytes[..4].copy_from_slice(&word.to_be_bytes());
                (RXE_AETH, RXE_AETH_BYTES)
            }
            Extension::Atomic {
                address,
                key,
                swap,
                compare,
            } => {
                bytes[..8].copy_from_slice(&address.to_be_bytes());
                bytes[8..12].copy_from_slice(&key.to_be_bytes());
                bytes[12..20].copy_from_slice(&swap.to_be_bytes());
                bytes[20..28].copy_from_slice(&compare.to_be_bytes());
                (RXE_ATMETH, RXE_ATMETH_BYTES)
            }
            Extension::AtomicReply(value) => {
                bytes[..8].copy_from_slice(&value.to_be_bytes());
                (RXE_ATMACK, RXE_ATMACK_BYTES)
            }
            Extension::Invalidate(key) => {
                bytes[..4].copy_from_slice(&key.to_be_bytes());
                (RXE_IETH, RXE_IETH_BYTES)
            }
            Extension::Datagram { key, source } => {
                bytes[..4].copy_from_slice(&key.to_be_bytes());
                bytes[4..8].copy_from_slice(&(source & 0xffffff).to_be_bytes());
                (RXE_DETH, RXE_DETH_BYTES)
            }
            Extension::Immediate(value) => {
                bytes[..4].copy_from_slice(&value);
                (RXE_IMMDT, RXE_IMMDT_BYTES)
            }
            Extension::Flush { kind, level } => {
                let word = (u32::from(level & 3) << 4) | u32::from(kind & 0xf);
                bytes[..4].copy_from_slice(&word.to_be_bytes());
                (RXE_FETH, RXE_FETH_BYTES)
            }
        };
        if self.layout.mask & (1 << kind) == 0 {
            return Err(EINVAL);
        }
        let start = usize::try_from(self.layout.offset[kind as usize]).map_err(|_| EINVAL)?;
        let end = start.checked_add(length as usize).ok_or(EINVAL)?;
        let headers = &mut self.bytes[..self.layout.length as usize];
        headers
            .get_mut(start..end)
            .ok_or(EINVAL)?
            .copy_from_slice(&bytes[..length as usize]);
        Ok(())
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_wire)]
mod tests {
    use super::*;

    fn base(opcode: u8) -> Base {
        Base {
            opcode,
            psn: 0x123456,
            qpn: 0x010203,
            solicited: false,
            ack: true,
        }
    }

    #[test]
    fn opcode_bounds_and_padding() -> Result {
        for opcode in 0..=u8::MAX {
            let layout = rxe_opcode::info(opcode);
            let mut bytes = [0xa5; 128];
            if layout.mask == 0 {
                assert!(packet_len(opcode, 0).is_err());
                assert!(TransportMut::initialize(&mut bytes, base(opcode), 0).is_err());
                assert_eq!(bytes, [0xa5; 128]);
                continue;
            }
            let has_payload = layout.mask & super::super::rxe_param::RXE_PAYLOAD_MASK != 0;
            let payload = if has_payload { 7 } else { 0 };
            let length = packet_len(opcode, payload)?;
            assert!(
                TransportMut::initialize(&mut bytes[..length - 1], base(opcode), payload).is_err()
            );
            assert_eq!(bytes, [0xa5; 128]);
            let mut wire = TransportMut::initialize(&mut bytes[..length], base(opcode), payload)?;
            if has_payload {
                let data = wire.payload()?;
                assert_eq!(data.len(), payload);
                data.fill(0xcc);
            } else {
                assert!(wire.payload().is_err());
            }
            let wire = Transport::parse(&bytes[..length - ICRC_BYTES])?;
            assert_eq!(wire.opcode(), opcode);
            assert_eq!(wire.psn(), 0x123456);
            assert_eq!(wire.remote().is_ok(), layout.mask & RXE_RETH_MASK != 0);
            assert_eq!(wire.syndrome().is_ok(), layout.mask & RXE_AETH_MASK != 0);
            assert_eq!(wire.atomic().is_ok(), layout.mask & RXE_ATMETH_MASK != 0);
            assert_eq!(
                wire.atomic_reply().is_ok(),
                layout.mask & RXE_ATMACK_MASK != 0
            );
            assert_eq!(wire.invalidate().is_ok(), layout.mask & RXE_IETH_MASK != 0);
            assert_eq!(wire.immediate().is_ok(), layout.mask & RXE_IMMDT_MASK != 0);
            assert_eq!(wire.datagram().is_ok(), layout.mask & RXE_DETH_MASK != 0);
            assert_eq!(wire.flush().is_ok(), layout.mask & RXE_FETH_MASK != 0);
            assert_eq!(wire.payload().is_ok(), has_payload);
            for truncated in 0..layout.length as usize {
                assert!(Transport::parse(&bytes[..truncated]).is_err());
            }
            assert_eq!(wire.payload_len(), payload);
            if has_payload {
                assert_eq!(bytes[length - ICRC_BYTES - 1], 0);
            } else {
                // A header-only opcode must not hash its headers again as ICRC payload.
                assert!(wire.padded_payload().is_empty());
            }
            assert_eq!(bytes[length..], [0xa5; 128][length..]);
        }
        assert!(packet_len(0x0a, usize::MAX).is_err());
        Ok(())
    }

    #[test]
    fn reject_misaligned_packets_and_data_on_header_only_opcodes() -> Result {
        let mut send = [0; 16];
        send[0] = 0x04; // RC SEND ONLY.
        assert!(Transport::parse(&send[..13]).is_err());
        send[1] = 3 << 4;
        assert_eq!(Transport::parse(&send)?.payload_len(), 1);
        for opcode in [0x0c, 0x11, 0x1c] {
            // READ, ACK and FLUSH.
            let length = packet_len(opcode, 0)?;
            let mut bytes = [0; 40];
            TransportMut::initialize(&mut bytes[..length], base(opcode), 0)?;
            assert!(Transport::parse(&bytes[..length - ICRC_BYTES]).is_ok());
            assert!(Transport::parse(&bytes[..length]).is_err());
            bytes[1] |= 1 << 4;
            assert!(Transport::parse(&bytes[..length - ICRC_BYTES]).is_err());
            assert!(packet_len(opcode, 1).is_err());
        }
        Ok(())
    }

    #[test]
    fn receive_fields_decode_wire_values_and_padding() -> Result {
        // RC WRITE ONLY WITH IMMEDIATE, three payload bytes and one pad byte.
        let bytes = [
            0x0b, 0x90, 0x80, 0x01, 0xa5, 0x12, 0x34, 0x56, 0x80, 0xfe, 0xdc, 0xba, 1, 2, 3, 4, 5,
            6, 7, 8, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 3, 0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc,
            0x55,
        ];
        let wire = Transport::parse(&bytes)?;
        assert_eq!(wire.qpn(), 0x123456);
        assert_eq!(wire.psn(), 0xfedcba);
        assert_eq!(wire.pkey(), 0x8001);
        assert_eq!(wire.version(), 0);
        assert!(wire.solicited());
        assert!(wire.ack_requested());
        assert_eq!(wire.pad(), 1);
        let remote = wire.remote()?;
        assert_eq!(remote.address, 0x0102030405060708);
        assert_eq!(remote.key, 0x11223344);
        assert_eq!(remote.length, 3);
        assert_eq!(wire.immediate()?, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(wire.payload()?, [0xaa, 0xbb, 0xcc]);
        assert_eq!(wire.padded_payload(), [0xaa, 0xbb, 0xcc, 0x55]);
        assert!(wire.atomic().is_err());

        // COMPARE SWAP has two distinct, unaligned eight-byte operands.
        let bytes = [
            0x13, 0, 0xff, 0xff, 0, 0, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x22, 0x33,
            0x44, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x91, 0x92, 0x93, 0x94, 0x95,
            0x96, 0x97, 0x98,
        ];
        let wire = Transport::parse(&bytes)?;
        let atomic = wire.atomic()?;
        assert_eq!(atomic.address, 0x0102030405060708);
        assert_eq!(atomic.key, 0x11223344);
        assert_eq!(atomic.swap, 0x8182838485868788);
        assert_eq!(atomic.compare, 0x9192939495969798);
        assert!(wire.payload().is_err());

        // UD SEND ONLY: the high source-QP byte is reserved, not part of the QPN.
        let bytes = [
            0x64, 0, 0xff, 0xff, 0, 0, 0, 1, 0, 0, 0, 1, 0x11, 0x22, 0x33, 0x44, 0xff, 0x55, 0x66,
            0x77,
        ];
        let datagram = Transport::parse(&bytes)?.datagram()?;
        assert_eq!(datagram.key, 0x11223344);
        assert_eq!(datagram.source, 0x556677);

        // FLUSH places FETH before RETH and masks the reserved FETH bits.
        let bytes = [
            0x1c, 0, 0xff, 0xff, 0, 0, 0, 1, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xe3, 1, 2, 3, 4, 5, 6,
            7, 8, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 8,
        ];
        let wire = Transport::parse(&bytes)?;
        assert_eq!(wire.flush()?.kind, 3);
        assert_eq!(wire.flush()?.level, 2);
        assert_eq!(wire.remote()?.address, 0x0102030405060708);
        assert!(wire.payload().is_err());
        Ok(())
    }

    #[test]
    fn extensions_preserve_payload_and_reject_wrong_opcode() -> Result {
        let mut bytes = [0; 36];
        let mut wire = TransportMut::initialize(&mut bytes, base(0x0a), 3)?;
        wire.set(Extension::Remote {
            address: 0x0102030405060708,
            key: 0x11223344,
            length: 3,
        })?;
        wire.payload()?.copy_from_slice(&[0xaa, 0xbb, 0xcc]);
        assert!(wire.set(Extension::AtomicReply(u64::MAX)).is_err());
        assert!(wire.set(Extension::Immediate([0xff; 4])).is_err());
        assert_eq!(
            bytes[..12],
            [0x0a, 0x10, 0xff, 0xff, 0, 1, 2, 3, 0x80, 0x12, 0x34, 0x56]
        );
        assert_eq!(
            bytes[12..28],
            [1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 3]
        );
        assert_eq!(bytes[28..], [0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0]);
        Ok(())
    }
}
