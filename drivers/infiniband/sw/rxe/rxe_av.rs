// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Native address vectors and legacy userspace decoding.

#![forbid(unsafe_code)]

use super::rxe_network::Address;
use kernel::{
    prelude::*, //
};

/// An owned global route, independent of the core's GID attribute lifetime.
#[derive(Clone, Copy, Eq, PartialEq, Zeroable)]
pub(crate) struct GlobalRoute {
    pub(crate) dgid: [u8; 16],
    pub(crate) flow_label: u32,
    pub(crate) sgid_index: u8,
    pub(crate) hop_limit: u8,
    pub(crate) traffic_class: u8,
}

/// Copied routing metadata with no socket-address union or core-owned pointers.
///
/// IPv4 addresses occupy the first four bytes of each address array. The family tag is
/// validated before exposing addresses; zero-initialized, unpublished vectors have no family.
#[derive(Clone, Copy, Eq, PartialEq, Zeroable)]
pub(crate) struct AddressVector {
    pub(crate) port_num: u8,
    pub(crate) dmac: [u8; 6],
    pub(crate) grh: GlobalRoute,
    family: u8,
    source: [u8; 16],
    destination: [u8; 16],
}

impl GlobalRoute {
    pub(crate) fn check(&self, gid_table_len: c_int) -> Result {
        if c_int::from(self.sgid_index) >= gid_table_len {
            return Err(EINVAL);
        }
        Ok(())
    }

    pub(crate) fn address_vector(
        self,
        port: u8,
        sgid: [u8; 16],
        dmac: [u8; 6],
        ipv4: bool,
    ) -> AddressVector {
        fn address(gid: [u8; 16], ipv4: bool) -> [u8; 16] {
            let mapped = gid[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
            if ipv4 {
                let mut address = [0; 16];
                if mapped {
                    address[..4].copy_from_slice(&gid[12..]);
                }
                address
            } else if mapped {
                [0; 16]
            } else {
                gid
            }
        }
        AddressVector {
            port_num: port,
            dmac,
            grh: self,
            family: if ipv4 { 1 } else { 2 },
            source: address(sgid, ipv4),
            destination: address(self.dgid, ipv4),
        }
    }
}

impl AddressVector {
    pub(crate) fn from_request(request: kernel::rdma::AddressRequest) -> Result<Self> {
        use kernel::rdma::{
            AddressKind,
            NetworkType, //
        };
        let AddressKind::Roce { destination_mac } = request.attributes.kind else {
            return Err(EINVAL);
        };
        let route = request.attributes.route.ok_or(EINVAL)?;
        let source = request.source.ok_or(EINVAL)?;
        let ipv4 = match source.network {
            NetworkType::Ipv4 => true,
            NetworkType::Ipv6 => false,
            _ => return Err(EINVAL),
        };
        let mapped = |gid: &[u8; 16]| gid[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
        if mapped(&source.gid) != ipv4 || mapped(&route.dgid) != ipv4 {
            return Err(EINVAL);
        }
        let route = GlobalRoute {
            dgid: route.dgid,
            flow_label: route.flow_label,
            sgid_index: route.sgid_index,
            hop_limit: route.hop_limit,
            traffic_class: route.traffic_class,
        };
        route.check(super::rxe_param::RXE_PORT_GID_TBL_LEN as i32)?;
        Ok(route.address_vector(
            request.attributes.port as u8,
            source.gid,
            destination_mac,
            ipv4,
        ))
    }

    pub(crate) fn attributes(&self) -> kernel::rdma::AddressAttributes {
        kernel::rdma::AddressAttributes {
            // Preserve RXE's query ABI: only the global route and port are reported.
            kind: kernel::rdma::AddressKind::Roce {
                destination_mac: [0; 6],
            },
            port: self.port_num.into(),
            service_level: 0,
            static_rate: 0,
            route: Some(kernel::rdma::GlobalRoute {
                dgid: self.grh.dgid,
                flow_label: self.grh.flow_label,
                sgid_index: self.grh.sgid_index,
                hop_limit: self.grh.hop_limit,
                traffic_class: self.grh.traffic_class,
            }),
        }
    }

    pub(crate) fn addresses(&self) -> Result<Address> {
        match self.family {
            1 => Ok(Address::V4 {
                source: self.source[..4].try_into().unwrap(),
                destination: self.destination[..4].try_into().unwrap(),
            }),
            2 => Ok(Address::V6 {
                source: self.source,
                destination: self.destination,
            }),
            _ => Err(EAFNOSUPPORT),
        }
    }

    /// Checks an incoming fixed IPv4 or IPv6 header against this connected peer.
    pub(crate) fn accepts(&self, header: &[u8]) -> bool {
        match (self.addresses(), header.len()) {
            (
                Ok(Address::V4 {
                    source,
                    destination,
                }),
                20,
            ) => header[12..16] == destination && header[16..20] == source,
            (
                Ok(Address::V6 {
                    source,
                    destination,
                }),
                40,
            ) => header[8..24] == destination && header[24..40] == source,
            _ => false,
        }
    }

    pub(crate) fn ipv4(&self) -> Result<bool> {
        match self.family {
            1 => Ok(true),
            2 => Ok(false),
            _ => Err(EAFNOSUPPORT),
        }
    }
}

/// Decodes the legacy userspace representation without casting or retaining its bytes.
pub(super) fn decode(bytes: &[u8; 88]) -> Result<AddressVector> {
    let mut source = [0; 16];
    let mut destination = [0; 16];
    match bytes[1] {
        1 => {
            source[..4].copy_from_slice(&bytes[36..40]);
            destination[..4].copy_from_slice(&bytes[64..68]);
        }
        2 => {
            source.copy_from_slice(&bytes[40..56]);
            destination.copy_from_slice(&bytes[68..84]);
        }
        _ => return Err(EAFNOSUPPORT),
    }
    Ok(AddressVector {
        port_num: bytes[0],
        dmac: bytes[2..8].try_into().unwrap(),
        grh: GlobalRoute {
            dgid: bytes[8..24].try_into().unwrap(),
            flow_label: u32::from_ne_bytes(bytes[24..28].try_into().unwrap()),
            sgid_index: bytes[28],
            hop_limit: bytes[29],
            traffic_class: bytes[30],
        },
        family: bytes[1],
        source,
        destination,
    })
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_av)]
mod tests {
    use super::*;

    fn gid(ipv4: bool, host: u8) -> [u8; 16] {
        let mut gid = [0; 16];
        if ipv4 {
            gid[10..12].fill(0xff);
            gid[12..].copy_from_slice(&[192, 0, 2, host]);
        } else {
            gid[0] = 0xfd;
            gid[15] = host;
        }
        gid
    }

    #[test]
    fn native_vectors_check_both_peer_addresses_and_network_family() -> Result {
        for ipv4 in [true, false] {
            let route = GlobalRoute {
                dgid: gid(ipv4, 2),
                flow_label: 17,
                sgid_index: 3,
                hop_limit: 64,
                traffic_class: 5,
            };
            let vector = route.address_vector(1, gid(ipv4, 1), [0x12; 6], ipv4);
            assert_eq!(vector.ipv4()?, ipv4);
            let mut header = [0; 40];
            let length = match vector.addresses()? {
                Address::V4 {
                    source,
                    destination,
                } => {
                    assert_eq!(source, [192, 0, 2, 1]);
                    assert_eq!(destination, [192, 0, 2, 2]);
                    header[12..16].copy_from_slice(&destination);
                    header[16..20].copy_from_slice(&source);
                    20
                }
                Address::V6 {
                    source,
                    destination,
                } => {
                    assert_eq!(source, gid(false, 1));
                    assert_eq!(destination, gid(false, 2));
                    header[8..24].copy_from_slice(&destination);
                    header[24..40].copy_from_slice(&source);
                    40
                }
            };
            assert!(vector.accepts(&header[..length]));
            header[length - 1] ^= 1;
            assert!(!vector.accepts(&header[..length]));
            header[length - 1] ^= 1;
            header[if ipv4 { 15 } else { 23 }] ^= 1;
            assert!(!vector.accepts(&header[..length]));
            assert!(!vector.accepts(&header[..length - 1]));
        }
        let empty = AddressVector::zeroed();
        assert_eq!(empty.ipv4(), Err(EAFNOSUPPORT));
        assert!(!empty.accepts(&[0; 40]));
        Ok(())
    }

    #[test]
    fn legacy_vectors_decode_socket_fields_without_union_borrows() -> Result {
        for ipv4 in [true, false] {
            let route = GlobalRoute {
                dgid: gid(ipv4, 2),
                flow_label: 0x12345,
                sgid_index: 3,
                hop_limit: 64,
                traffic_class: 5,
            };
            let native = route.address_vector(1, gid(ipv4, 1), [0x12; 6], ipv4);
            let mut bytes = [0; 88];
            bytes[0] = 1;
            bytes[1] = if ipv4 { 1 } else { 2 };
            bytes[2..8].fill(0x12);
            bytes[8..24].copy_from_slice(&route.dgid);
            bytes[24..28].copy_from_slice(&route.flow_label.to_ne_bytes());
            bytes[28] = route.sgid_index;
            bytes[29] = route.hop_limit;
            bytes[30] = route.traffic_class;
            if ipv4 {
                bytes[36..40].copy_from_slice(&[192, 0, 2, 1]);
                bytes[64..68].copy_from_slice(&[192, 0, 2, 2]);
            } else {
                bytes[40..56].copy_from_slice(&gid(false, 1));
                bytes[68..84].copy_from_slice(&gid(false, 2));
            }
            assert!(decode(&bytes)? == native);
            bytes[1] = 0;
            assert!(decode(&bytes).is_err());
        }
        Ok(())
    }
}
