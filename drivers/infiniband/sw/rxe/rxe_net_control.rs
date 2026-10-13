// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Network device notifications and owned device lookup.

#![forbid(unsafe_code)]

use super::{
    rxe_device::{
        mtu_from_netdev,
        DeviceData, //
    },
    rxe_hw_counters::Counter,
    rxe_qp::rxe_qp_error, //
};
use kernel::{
    bindings,
    net::notifier::{
        Event,
        Handler,
        Info,
        Response, //
    },
    prelude::*, //
};

/// Finds the RXE device for a netdev and acquires its core reference.
pub(super) fn get_device(
    ndev: &kernel::net::Device,
) -> Option<kernel::rdma::DeviceRef<DeviceData>> {
    kernel::rdma::DeviceRef::from_netdev(ndev, bindings::rdma_driver_id_RDMA_DRIVER_RXE)
}

fn flush_qps(provider: &DeviceData) {
    provider.pairs.visit(rxe_qp_error);
}

/// RXE's listener, retained by the module's owned notifier registration.
pub(crate) struct Events;

impl Handler for Events {
    fn notify(self: Pin<&Self>, event: Event, info: &Info<'_>) -> Result<Response> {
        if !matches!(
            event,
            Event::GOING_DOWN | Event::UNREGISTER | Event::CHANGE_MTU | Event::DOWN | Event::CHANGE
        ) {
            return Ok(Response::Ok);
        }
        let Some(ndev) = info.device() else {
            return Ok(Response::Ok);
        };
        let Some(rxe) = get_device(ndev) else {
            return Ok(Response::Ok);
        };
        let provider = rxe.provider();
        match event {
            Event::GOING_DOWN => flush_qps(provider.get_ref()),
            Event::UNREGISTER => {
                // Remove old filter references before networking flushes the list or moves
                // this netdevice to another namespace. Queued RDMA teardown runs later.
                super::rxe_mcast_control::disable(provider.get_ref(), ndev, &info.rtnl());
                flush_qps(provider.get_ref());
                rxe.unregister_queued();
                provider.close_tunnels();
            }
            Event::CHANGE_MTU => {
                let mtu = mtu_from_netdev(info.mtu());
                provider.port.set_mtu(mtu);
            }
            Event::DOWN | Event::CHANGE => {
                if !ndev.is_running() || !ndev.has_carrier() {
                    provider.counters.increment(Counter::LinkDown);
                }
            }
            _ => {}
        }
        Ok(Response::Ok)
    }
}
