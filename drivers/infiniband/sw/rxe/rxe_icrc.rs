// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! RoCE invariant CRC generation and verification.

#![forbid(unsafe_code)]

use super::rxe_wire::{
    Transport,
    BTH_BYTES, //
};
use kernel::{
    crc32::le,
    error::{
        code::EINVAL,
        Result, //
    }, //
};

const IPV4_BYTES: usize = 20;
const IPV6_BYTES: usize = 40;
const UDP_BYTES: usize = 8;

/// Calculates the CRC, masking fields that can change in transit.
pub(super) fn icrc(network: &[u8], transport: &Transport<'_>) -> Result<u32> {
    match network.len() {
        28 if network[0] == 0x45 && network[9] == 17 => (),
        48 if network[0] >> 4 == 6 && network[6] == 17 => (),
        _ => return Err(EINVAL),
    }
    let mut pseudo = [0u8; IPV6_BYTES + UDP_BYTES + BTH_BYTES];
    let network_len = network.len();
    pseudo[..network_len].copy_from_slice(network);
    if network_len == IPV4_BYTES + UDP_BYTES {
        pseudo[1] = 0xff; // Type of service.
        pseudo[8] = 0xff; // Time to live.
        pseudo[10..12].fill(0xff); // IPv4 checksum.
    } else {
        pseudo[0] |= 0x0f; // Traffic class and flow label.
        pseudo[1..4].fill(0xff);
        pseudo[7] = 0xff; // Hop limit.
    }
    pseudo[network_len - 2..network_len].fill(0xff); // UDP checksum.
    pseudo[network_len..network_len + BTH_BYTES].copy_from_slice(transport.bth());
    pseudo[network_len + 4] = 0xff; // BTH reserved byte before the QPN.

    // CRC of eight 0xff bytes representing the masked LRH, seeded with !0.
    let crc = le(0xdebb20e3, &pseudo[..network_len + BTH_BYTES]);
    let crc = le(crc, transport.extended_headers());
    Ok(!le(crc, transport.padded_payload()))
}

/// Calculates and stores ICRC within an exclusively borrowed transmit packet.
pub(super) fn generate(network: &[u8], packet: &mut [u8]) -> Result {
    let length = packet
        .len()
        .checked_sub(super::rxe_wire::ICRC_BYTES)
        .ok_or(EINVAL)?;
    let (body, checksum) = packet.split_at_mut(length);
    let crc = icrc(network, &Transport::parse(body)?)?;
    checksum.copy_from_slice(&crc.to_le_bytes());
    Ok(())
}

/// Validates a received ICRC and returns the checked transport view.
pub(super) fn check<'a>(network: &[u8], packet: &'a [u8]) -> Result<Transport<'a>> {
    let (ip_length, ip_header) = match network.len() {
        28 => (
            u16::from_be_bytes([network[2], network[3]]) as usize,
            IPV4_BYTES,
        ),
        48 => (u16::from_be_bytes([network[4], network[5]]) as usize, 0),
        _ => return Err(EINVAL),
    };
    let offset = network.len() - 4;
    let udp_length = u16::from_be_bytes([network[offset], network[offset + 1]]) as usize;
    if ip_length != ip_header + udp_length
        || packet.len().checked_add(UDP_BYTES) != Some(udp_length)
    {
        return Err(EINVAL);
    }
    let length = packet
        .len()
        .checked_sub(super::rxe_wire::ICRC_BYTES)
        .ok_or(EINVAL)?;
    let (body, checksum) = packet.split_at(length);
    let transport = Transport::parse(body)?;
    let received = u32::from_le_bytes(checksum.try_into().map_err(|_| EINVAL)?);
    if icrc(network, &transport)? != received {
        return Err(EINVAL);
    }
    Ok(transport)
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_icrc)]
mod tests {
    use super::super::rxe_wire::{
        Base,
        Extension,
        TransportMut, //
    };
    use super::*;

    #[test]
    fn bounded_generation_matches_wire_vector() -> Result {
        let mut network = [0u8; 28];
        network[0] = 0x45;
        network[8] = 64;
        network[9] = 17;
        network[12..20].copy_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        network[20..28].copy_from_slice(&[0x12, 0xb6, 0x12, 0xb7, 0, 44, 0, 0]);
        let mut bytes = [0; 36];
        let mut wire = TransportMut::initialize(
            &mut bytes,
            Base {
                opcode: 0x0a,
                psn: 0x123456,
                qpn: 0x010203,
                solicited: false,
                ack: true,
            },
            3,
        )?;
        wire.set(Extension::Remote {
            address: 0x0102030405060708,
            key: 0x11223344,
            length: 3,
        })?;
        wire.payload()?.copy_from_slice(&[0xaa, 0xbb, 0xcc]);
        let original = bytes;
        generate(&network, &mut bytes)?;
        assert_eq!(&bytes[..32], &original[..32]);
        // Independent IEEE CRC-32 of the masked LRH, network and transport bytes.
        assert_eq!(&bytes[32..], &[0x84, 0xf7, 0x07, 0x73]);
        let checksum: [u8; 4] = bytes[32..].try_into().unwrap();
        network[1] = 17;
        network[8] = 3;
        generate(&network, &mut bytes)?;
        assert_eq!(&bytes[32..], &checksum);
        network[2..4].copy_from_slice(&64u16.to_be_bytes());
        generate(&network, &mut bytes)?;
        assert_eq!(check(&network, &bytes)?.psn(), 0x123456);
        // UDP trimming leaves the original IP length untouched, even with a valid ICRC.
        network[2..4].copy_from_slice(&68u16.to_be_bytes());
        generate(&network, &mut bytes)?;
        assert!(check(&network, &bytes).is_err());
        network[2..4].copy_from_slice(&64u16.to_be_bytes());
        generate(&network, &mut bytes)?;
        bytes[20] ^= 1;
        assert!(check(&network, &bytes).is_err());
        bytes[20] ^= 1;
        bytes[35] ^= 1;
        assert!(check(&network, &bytes).is_err());
        assert!(check(&network, &bytes[..3]).is_err());
        assert!(check(&network, &bytes[..16]).is_err());
        assert!(generate(&network, &mut [0; 3]).is_err());
        assert!(generate(&network[..27], &mut bytes).is_err());
        Ok(())
    }
    #[test]
    fn crc_rejects_ip_options_and_extension_headers() -> Result {
        let mut bytes = [0; 16];
        TransportMut::initialize(
            &mut bytes,
            Base {
                opcode: 0x04,
                psn: 0,
                qpn: 1,
                solicited: false,
                ack: false,
            },
            0,
        )?;
        let mut ipv4 = [0; 28];
        ipv4[0] = 0x46;
        ipv4[9] = 17;
        assert_eq!(generate(&ipv4, &mut bytes), Err(EINVAL));
        ipv4[0] = 0x45;
        generate(&ipv4, &mut bytes)?;
        let mut ipv6 = [0; 48];
        ipv6[0] = 0x60;
        ipv6[6] = 60;
        assert_eq!(generate(&ipv6, &mut bytes), Err(EINVAL));
        ipv6[6] = 17;
        ipv6[4..6].copy_from_slice(&24u16.to_be_bytes());
        ipv6[44..46].copy_from_slice(&24u16.to_be_bytes());
        generate(&ipv6, &mut bytes)?;
        assert!(check(&ipv6, &bytes).is_ok());
        ipv6[4..6].copy_from_slice(&28u16.to_be_bytes());
        generate(&ipv6, &mut bytes)?;
        assert!(check(&ipv6, &bytes).is_err());
        ipv6[44..46].copy_from_slice(&28u16.to_be_bytes());
        generate(&ipv6, &mut bytes)?;
        assert!(check(&ipv6, &bytes).is_err());
        Ok(())
    }
}
