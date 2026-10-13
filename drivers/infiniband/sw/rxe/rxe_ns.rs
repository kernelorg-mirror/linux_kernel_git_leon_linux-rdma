// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Device leases on namespace-owned UDP tunnels.

#![forbid(unsafe_code)]

use super::rxe_tunnel::Receive;
use kernel::{
    bindings,
    net::{
        namespace::Namespace,
        socket::Family,
        udp_tunnel, //
    },
    prelude::*, //
};

pub(crate) type Registration = udp_tunnel::Registration<Receive>;
pub(crate) type Key = udp_tunnel::Key<Receive>;

/// Owns one device's interest in each supported address family's receive port.
pub(crate) struct Tunnels {
    ipv4: udp_tunnel::Lease<Receive>,
    #[cfg(CONFIG_IPV6)]
    ipv6: Option<udp_tunnel::Lease<Receive>>,
}

impl Tunnels {
    pub(crate) fn new(key: Key, namespace: &Namespace) -> Result<Self> {
        let port = bindings::ROCE_V2_UDP_DPORT as u16;
        let ipv4 = key.bind(namespace, Family::Ipv4, port)?;
        #[cfg(CONFIG_IPV6)]
        let ipv6 = match key.bind(namespace, Family::Ipv6, port) {
            Ok(lease) => Some(lease),
            Err(EAFNOSUPPORT) => None,
            Err(error) => return Err(error),
        };
        Ok(Self {
            ipv4,
            #[cfg(CONFIG_IPV6)]
            ipv6,
        })
    }

    pub(crate) fn socket(&self, ipv4: bool) -> Option<udp_tunnel::SocketRef> {
        if ipv4 {
            return Some(self.ipv4.socket().clone());
        }
        #[cfg(CONFIG_IPV6)]
        {
            self.ipv6.as_ref().map(|lease| lease.socket().clone())
        }
        #[cfg(not(CONFIG_IPV6))]
        {
            None
        }
    }
}
