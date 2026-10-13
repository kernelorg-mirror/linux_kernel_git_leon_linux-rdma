// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Native multicast membership and network-device filter programming.

#![forbid(unsafe_code)]

use super::{
    rxe_device::DeviceData,
    rxe_mcast::address,
    rxe_qp::QpRef,
    rxe_types::QueuePair, //
};
use kernel::{
    net::RtnlGuard,
    prelude::*,
    rdma::Device,
    sync::atomic::Relaxed, //
};

fn program(device: &Device<DeviceData>, rtnl: &RtnlGuard<'_>, gid: [u8; 16], add: bool) -> Result {
    let ndev = device.net_device(1).ok_or(ENODEV)?;
    let address = address(gid);
    if add {
        ndev.add_multicast_address(rtnl, &address)
    } else {
        ndev.remove_multicast_address(rtnl, &address)
    }
}

/// Retains the QP in a group after programming its first network-device filter reference.
pub(crate) fn attach(qp: &QueuePair, gid: [u8; 16]) -> Result {
    // Notifier shutdown holds RTNL before the group control lock. Use the same order.
    let rtnl = RtnlGuard::lock();
    qp.provider().groups.attach(gid, QpRef::acquire(qp), || {
        program(qp.device(), &rtnl, gid, true)
    })?;
    qp.data().control.multicast.fetch_add(1, Relaxed);
    Ok(())
}

/// Removes membership before releasing its retained QP reference.
pub(crate) fn detach(qp: &QueuePair, gid: [u8; 16]) -> Result {
    let rtnl = RtnlGuard::lock();
    qp.provider().groups.detach(gid, qp.data().index, || {
        // Networking may already have flushed this device's address list during teardown.
        let _ = program(qp.device(), &rtnl, gid, false);
    })?;
    qp.data().control.multicast.fetch_sub(1, Relaxed);
    Ok(())
}

/// Closes admission before networking flushes the old device's address list or namespace.
pub(crate) fn disable(provider: &DeviceData, ndev: &kernel::net::Device, rtnl: &RtnlGuard<'_>) {
    provider.groups.disable(|gid| {
        let _ = ndev.remove_multicast_address(rtnl, &address(gid));
    });
}
