// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Receive admission over copied QP attributes and bounded packet headers.

#![forbid(unsafe_code)]

use super::{
    rxe_av::AddressVector,
    rxe_param::{
        GSI_QKEY,
        RXE_REQ_MASK, //
    },
    rxe_resp_check::Protocol,
    rxe_wire::Transport, //
};
use kernel::error::{
    code::EINVAL,
    Result, //
};

pub(super) const MULTICAST_QPN: u32 = 0xffffff;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Rejection {
    Invalid,
    PartitionKey,
    DatagramKey,
}

/// Header fields copied before multicast recipients share the packet data.
pub(super) struct Admission {
    opcode: u8,
    mask: u32,
    pkey: u16,
    qpn: u32,
    qkey: Option<u32>,
}

impl Admission {
    pub(super) fn new(wire: &Transport<'_>) -> Self {
        Self {
            opcode: wire.opcode(),
            mask: wire.mask(),
            pkey: wire.pkey(),
            qpn: wire.qpn(),
            qkey: wire.datagram().ok().map(|datagram| datagram.key),
        }
    }
}

/// One coherent capture of the attributes used to admit a received packet.
pub(super) struct Snapshot {
    pub(super) protocol: Protocol,
    pub(super) valid: bool,
    pub(super) request_ready: bool,
    pub(super) response_ready: bool,
    pub(super) port: u32,
    pub(super) address: AddressVector,
    pub(super) qkey: u32,
}

impl Snapshot {
    /// A multicast membership supplies the QP without a connected peer-address check.
    pub(super) fn check(
        &self,
        wire: &Admission,
        incoming: Option<(u8, &[u8])>,
    ) -> core::result::Result<(), Rejection> {
        let transport = match self.protocol {
            Protocol::Reliable => 0,
            Protocol::Unreliable => 0x20,
            Protocol::Datagram => 0x60,
        };
        let ready = if wire.mask & RXE_REQ_MASK != 0 {
            self.request_ready
        } else {
            self.response_ready
        };
        if !self.valid || !ready || wire.opcode & 0xe0 != transport {
            return Err(Rejection::Invalid);
        }
        if self.protocol != Protocol::Datagram {
            if let Some((port, header)) = incoming {
                if u32::from(port) != self.port || !self.address.accepts(header) {
                    return Err(Rejection::Invalid);
                }
            }
        }
        if wire.pkey & 0x7fff != 0x7fff {
            return Err(Rejection::PartitionKey);
        }
        if self.protocol == Protocol::Datagram {
            let expected = if wire.qpn == 1 { GSI_QKEY } else { self.qkey };
            if wire.qkey.ok_or(Rejection::Invalid)? != expected {
                return Err(Rejection::DatagramKey);
            }
        }
        Ok(())
    }
}

/// Checks the transport version and destination before looking up a QP or group.
pub(super) fn destination(wire: &Transport<'_>, has_grh: bool) -> Result<u32> {
    let number = wire.qpn();
    if wire.version() != 0 || number == 0 || (number == MULTICAST_QPN && !has_grh) {
        return Err(EINVAL);
    }
    Ok(number)
}

/// Copies the destination GID from a fixed IP header already checked by the network stack.
pub(super) fn destination_gid(header: &[u8]) -> Result<[u8; 16]> {
    match header.len() {
        20 => {
            let mut gid = [0; 16];
            gid[10..12].fill(0xff);
            gid[12..].copy_from_slice(&header[16..20]);
            Ok(gid)
        }
        40 => Ok(header[24..40].try_into().unwrap()),
        _ => Err(EINVAL),
    }
}

pub(super) fn multicast_gid(gid: &[u8; 16]) -> bool {
    gid[0] == 0xff || (gid[..10] == [0; 10] && gid[10..12] == [0xff; 2] && gid[12] & 0xf0 == 0xe0)
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_recv_check)]
mod tests {
    use super::*;
    use crate::rxe_av::GlobalRoute;

    fn snapshot(protocol: Protocol) -> Snapshot {
        let mut source = [0; 16];
        source[10..12].fill(0xff);
        source[12..].copy_from_slice(&[192, 0, 2, 1]);
        let mut destination = source;
        destination[15] = 2;
        Snapshot {
            protocol,
            valid: true,
            request_ready: true,
            response_ready: false,
            port: 1,
            address: GlobalRoute {
                dgid: destination,
                flow_label: 0,
                sgid_index: 0,
                hop_limit: 64,
                traffic_class: 0,
            }
            .address_vector(1, source, [0; 6], true),
            qkey: 0x12345678,
        }
    }

    fn packet(opcode: u8, qpn: u32, pkey: u16, qkey: u32) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..12].copy_from_slice(&crate::rxe_wire::bth(opcode, 0, false, 0, qpn, false));
        bytes[2..4].copy_from_slice(&pkey.to_be_bytes());
        bytes[12..16].copy_from_slice(&qkey.to_be_bytes());
        bytes
    }

    #[test]
    fn connected_admission_checks_state_protocol_and_both_addresses() -> Result {
        let mut header = [0; 20];
        header[12..16].copy_from_slice(&[192, 0, 2, 2]);
        header[16..20].copy_from_slice(&[192, 0, 2, 1]);
        for (protocol, opcode) in [(Protocol::Reliable, 0x04), (Protocol::Unreliable, 0x24)] {
            let mut qp = snapshot(protocol);
            let bytes = packet(opcode, 5, 0xffff, 0);
            let wire = Admission::new(&Transport::parse(&bytes)?);
            assert_eq!(qp.check(&wire, Some((1, &header))), Ok(()));
            assert_eq!(qp.check(&wire, Some((2, &header))), Err(Rejection::Invalid));
            header[15] ^= 1;
            assert_eq!(qp.check(&wire, Some((1, &header))), Err(Rejection::Invalid));
            header[15] ^= 1;
            header[19] ^= 1;
            assert_eq!(qp.check(&wire, Some((1, &header))), Err(Rejection::Invalid));
            header[19] ^= 1;
            qp.request_ready = false;
            assert_eq!(qp.check(&wire, None), Err(Rejection::Invalid));
            qp.request_ready = true;
            qp.valid = false;
            assert_eq!(qp.check(&wire, None), Err(Rejection::Invalid));
            qp.valid = true;
            qp.protocol = Protocol::Datagram;
            assert_eq!(qp.check(&wire, None), Err(Rejection::Invalid));
        }
        let bytes = packet(0x11, 5, 0x7fff, 0);
        // ACK contains only its BTH and AETH.
        let wire = Admission::new(&Transport::parse(&bytes[..16])?);
        let mut qp = snapshot(Protocol::Reliable);
        assert_eq!(qp.check(&wire, None), Err(Rejection::Invalid));
        qp.response_ready = true;
        assert_eq!(qp.check(&wire, None), Ok(()));
        Ok(())
    }

    #[test]
    fn key_rejections_preserve_partition_precedence_and_management_key() -> Result {
        let qp = snapshot(Protocol::Datagram);
        for qpn in [1, 5, MULTICAST_QPN] {
            let key = if qpn == 1 { GSI_QKEY } else { qp.qkey };
            for pkey in [0x7fff, 0xffff] {
                let bytes = packet(0x64, qpn, pkey, key);
                assert_eq!(
                    qp.check(&Admission::new(&Transport::parse(&bytes)?), Some((2, &[]))),
                    Ok(())
                );
            }
            let bytes = packet(0x64, qpn, 0xffff, key ^ 1);
            assert_eq!(
                qp.check(&Admission::new(&Transport::parse(&bytes)?), None),
                Err(Rejection::DatagramKey)
            );
            let bytes = packet(0x64, qpn, 0x1234, key ^ 1);
            assert_eq!(
                qp.check(&Admission::new(&Transport::parse(&bytes)?), None),
                Err(Rejection::PartitionKey)
            );
        }
        Ok(())
    }

    #[test]
    fn multicast_admission_outlives_packet_data_and_checks_each_qp() -> Result {
        let mut qp = snapshot(Protocol::Datagram);
        let mut bytes = packet(0x64, MULTICAST_QPN, 0xffff, qp.qkey);
        let admission = Admission::new(&Transport::parse(&bytes)?);

        // Admission retains only header values, so dispatch can share or release the data.
        bytes.fill(0);
        assert_eq!(qp.check(&admission, None), Ok(()));
        qp.qkey ^= 1;
        assert_eq!(qp.check(&admission, None), Err(Rejection::DatagramKey));
        qp.request_ready = false;
        assert_eq!(qp.check(&admission, None), Err(Rejection::Invalid));
        Ok(())
    }

    #[test]
    fn destinations_reject_reserved_transport_and_require_multicast_grh() -> Result {
        let mut bytes = packet(0x64, 0, 0xffff, 0);
        assert_eq!(destination(&Transport::parse(&bytes)?, true), Err(EINVAL));
        bytes = packet(0x64, MULTICAST_QPN, 0xffff, 0);
        assert_eq!(destination(&Transport::parse(&bytes)?, false), Err(EINVAL));
        assert_eq!(
            destination(&Transport::parse(&bytes)?, true),
            Ok(MULTICAST_QPN)
        );
        bytes = packet(0x64, 1, 0xffff, GSI_QKEY);
        assert_eq!(destination(&Transport::parse(&bytes)?, false), Ok(1));
        bytes[1] |= 1;
        assert_eq!(destination(&Transport::parse(&bytes)?, true), Err(EINVAL));

        let mut ipv4 = [0; 20];
        ipv4[16..].copy_from_slice(&[239, 1, 2, 3]);
        let gid = destination_gid(&ipv4)?;
        assert_eq!(
            gid,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 239, 1, 2, 3]
        );
        assert!(multicast_gid(&gid));
        for prefix in [223, 240] {
            ipv4[16] = prefix;
            assert!(!multicast_gid(&destination_gid(&ipv4)?));
        }
        let mut ipv6 = [0; 40];
        ipv6[24] = 0xff;
        ipv6[39] = 1;
        assert_eq!(&destination_gid(&ipv6)?[..], &ipv6[24..]);
        assert!(multicast_gid(&destination_gid(&ipv6)?));
        ipv6[24] = 0xfe;
        assert!(!multicast_gid(&destination_gid(&ipv6)?));
        assert_eq!(destination_gid(&ipv6[..39]), Err(EINVAL));
        assert_eq!(destination_gid(&[]), Err(EINVAL));
        Ok(())
    }
}
