// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Handoff of owned UDP datagrams to the RXE transport.

#![forbid(unsafe_code)]

use super::{
    rxe_net_control::get_device,
    rxe_param as params,
    rxe_recv::rxe_rcv, //
};
use kernel::net::udp_tunnel::{
    Datagram,
    Handler, //
};

pub(crate) struct Receive;

impl Handler for Receive {
    fn receive(datagram: Datagram) {
        let device =
            get_device(datagram.device()).or_else(|| datagram.lower_device().and_then(get_device));
        let Some(device) = device else {
            return;
        };
        let length = datagram.payload_length();
        rxe_rcv(datagram.into_packet(), device, params::RXE_GRH_MASK, length);
    }
}
