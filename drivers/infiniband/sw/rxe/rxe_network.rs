// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Initialized RoCEv2 network headers with checked wire lengths.

#![forbid(unsafe_code)]

use kernel::{
    error::Result,
    net::{
        ip::UdpFlow,
        udp::{
            Configuration,
            Headers, //
        }, //
    }, //
};

const ROCE_PORT: u16 = 4791;

pub(super) use kernel::net::ip::AddressPair as Address;

pub(super) struct Network {
    pub(super) address: Address,
    pub(super) traffic_class: u8,
    pub(super) hop_limit: u8,
    pub(super) source_port: u16,
}

impl Network {
    fn configuration(&self) -> Configuration {
        Configuration {
            addresses: self.address,
            traffic_class: self.traffic_class,
            hop_limit: self.hop_limit,
            source_port: self.source_port,
            destination_port: ROCE_PORT,
        }
    }

    pub(super) fn flow(&self) -> UdpFlow {
        self.configuration().flow()
    }

    pub(super) fn headers(&self, transport_length: usize) -> Result<Headers> {
        self.configuration().headers(transport_length)
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_network)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_lengths_and_addresses() -> Result {
        let network = Network {
            address: Address::V4 {
                source: [192, 0, 2, 1],
                destination: [192, 0, 2, 2],
            },
            traffic_class: 0x2a,
            hop_limit: 64,
            source_port: 4790,
        };
        let header = network.headers(36)?;
        assert_eq!(
            header.ip(),
            &[0x45, 0x2a, 0, 64, 0, 0, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,]
        );
        assert_eq!(header.udp(), &[0x12, 0xb6, 0x12, 0xb7, 0, 44, 0, 0]);
        assert!(network.headers(usize::MAX).is_err());
        assert!(network.headers(65508).is_err());
        assert!(network.headers(65507).is_ok());
        Ok(())
    }

    #[test]
    fn ipv6_lengths_and_addresses() -> Result {
        let network = Network {
            address: Address::V6 {
                source: [1; 16],
                destination: [2; 16],
            },
            traffic_class: 0xab,
            hop_limit: 63,
            source_port: 4790,
        };
        let header = network.headers(36)?;
        assert_eq!(&header.ip()[..8], &[0x6a, 0xb0, 0, 0, 0, 44, 17, 63]);
        assert_eq!(&header.ip()[8..24], &[1; 16]);
        assert_eq!(&header.ip()[24..40], &[2; 16]);
        assert_eq!(header.udp(), &[0x12, 0xb6, 0x12, 0xb7, 0, 44, 0, 0]);
        assert!(network.headers(65528).is_err());
        assert!(network.headers(65527).is_ok());
        Ok(())
    }
}
