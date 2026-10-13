// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! IP route ownership and RoCEv2 UDP/IP header construction.

#![forbid(unsafe_code)]

use crate::rxe_av::AddressVector;
use crate::rxe_types::{
    PacketInfo,
    QueuePair, //
};
use kernel::{
    net::ip::{
        AddressPair,
        Route,
        UdpFlow, //
    },
    prelude::*, //
};

fn find_route(ndev: &kernel::net::Device, qp: &QueuePair, flow: UdpFlow) -> Result<Route> {
    let tunnel = qp
        .provider()
        .tunnel(matches!(flow.addresses, AddressPair::V4 { .. }))?;
    let namespace = tunnel.namespace().try_to_ref().ok_or(ENODEV)?;
    let location = ndev.location_in(&namespace)?;
    // Native destinations require active namespace services until their final release.
    // Look up each transmission instead of retaining a namespace-dependent idle QP cache.
    Route::lookup_udp(&location, &tunnel, flow)
}

/// Finds a route and transfers a packet with complete RoCEv2 UDP/IP headers.
pub(crate) fn rxe_prepare(
    qp: &QueuePair,
    av: &AddressVector,
    _pkt: &mut PacketInfo,
    packet: super::rxe_net_tx::TransmitPacket,
) -> Result<super::rxe_net_tx::PreparedPacket> {
    use super::rxe_network::Network;
    let mut network = Network {
        address: av.addresses()?,
        traffic_class: av.grh.traffic_class,
        hop_limit: av.grh.hop_limit,
        source_port: packet.source_port(),
    };
    let route = find_route(packet.net_device(), qp, network.flow()).map_err(|_| EHOSTUNREACH)?;
    network.address = route.flow().addresses;
    let headers = network.headers(packet.len())?;
    packet.prepare(&route, headers)
}
