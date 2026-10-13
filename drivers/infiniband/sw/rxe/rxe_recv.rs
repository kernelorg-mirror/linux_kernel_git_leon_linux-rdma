// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Receive validation and dispatch, transferring packet ownership to a QP.

#![forbid(unsafe_code)]

use super::{
    rxe_completion::Network,
    rxe_hw_counters::Counter,
    rxe_packet::{
        transport,
        Packet,
        ReceiveInfo, //
    },
    rxe_recv_check::{
        self,
        Admission,
        Rejection,
        Snapshot, //
    },
    rxe_resp_check::Protocol, //
};
use crate::{
    rxe_param as params,
    rxe_types::{
        QueuePair, //
    }, //
};
use kernel::{
    bindings,
    net::skbuff::packet,
    prelude::*,
    rdma::{
        gid,
        DeviceRef, //
    }, //
};

const REQUEST: u32 = params::RXE_REQ_MASK;

// The caller retains the QP through a native reference; the packet owns its bytes and device.
fn check_qp(
    packet: &mut Packet,
    qp: &QueuePair,
    wire: &Admission,
    network: Option<&[u8]>,
) -> Result {
    // Capture admission attributes together under their lock. The packet owner keeps
    // the device live; port locking serializes violation counters.
    let (snapshot, generation) = {
        let shared = qp.data().control.state.lock();
        (
            Snapshot {
                protocol: match qp.kind().encoding() {
                    bindings::ib_qp_type_IB_QPT_RC => Protocol::Reliable,
                    bindings::ib_qp_type_IB_QPT_UC => Protocol::Unreliable,
                    bindings::ib_qp_type_IB_QPT_UD | bindings::ib_qp_type_IB_QPT_GSI => {
                        Protocol::Datagram
                    }
                    _ => return Err(EINVAL),
                },
                valid: shared.valid && !shared.resetting,
                request_ready: shared.attributes.qp_state >= bindings::ib_qp_state_IB_QPS_RTR,
                response_ready: shared.attributes.qp_state >= bindings::ib_qp_state_IB_QPS_RTS,
                port: shared.attributes.port_num,
                address: shared.primary,
                qkey: shared.attributes.qkey,
            },
            shared.generation,
        )
    };
    let port = packet.context().port_num;
    if let Err(rejection) = snapshot.check(wire, network.map(|header| (port, header))) {
        if rejection != Rejection::Invalid {
            packet.context().device.provider().port.reject(rejection);
        }
        return Err(EINVAL);
    }
    packet.context_mut().generation = generation;
    Ok(())
}

fn check_gid(packet: &Packet, destination: [u8; 16]) -> Result {
    if packet.context().mask & params::RXE_LOOPBACK_MASK != 0
        || rxe_recv_check::multicast_gid(&destination)
    {
        return Ok(());
    }
    let table = gid::Table::from_reference(&packet.context().device);
    let _attr = table.find(1, destination, gid::Type::RoceUdpEncap, packet.device())?;
    Ok(())
}

// The packet retains an RXE device whose QP registry remains initialized.
fn check_header(packet: &mut Packet, network: &[u8]) -> Result {
    // The device owner retains the provider and its registry. Successful lookup transfers
    // its QP reference into the packet; every rejection drops the locally acquired owner.
    let has_grh = packet.context().mask & params::RXE_GRH_MASK != 0;
    let wire = transport(packet)?;
    let number = rxe_recv_check::destination(&wire, has_grh)?;
    if number == rxe_recv_check::MULTICAST_QPN {
        return Ok(());
    }
    let admission = Admission::new(&wire);
    let provider = packet.context().device.provider();
    let qp = if number == 1 {
        provider
            .port
            .lookup_gsi(|index| provider.pairs.lookup(index.get()))
            .flatten()
    } else {
        provider.pairs.lookup(number)
    }
    .ok_or(EINVAL)?;
    check_qp(packet, &qp, &admission, Some(network))?;
    packet.context_mut().qp = Some(qp);
    Ok(())
}

// The packet owns a validated QP reference and its matching device.
fn dispatch(packet: Packet) {
    // The native reference retains the initialized QP and its queue owners. Each enqueue
    // transfers the complete packet owner, including both references, or drops it on retirement.
    let qp = packet.context().qp.as_ref().unwrap().clone();
    if packet.context().mask & REQUEST != 0 {
        crate::rxe_resp::rxe_resp_queue_pkt(&qp, packet);
    } else {
        crate::rxe_comp::rxe_comp_queue_pkt(&qp, packet);
    }
}

// The packet's device reference retains both registries throughout delivery.
fn multicast(mut packet: Packet, destination: [u8; 16]) {
    // Copy admission fields before cloning. Checking later recipients must not
    // request mutable packet data and copy the shared payload under the group lock.
    let Ok(wire) = transport(&mut packet) else {
        return;
    };
    let admission = Admission::new(&wire);
    // The last dispatch transfers the original packet. Keep the registry's device alive
    // independently until visit returns and releases its own locks and borrows.
    let device = packet.context().device.clone();
    let provider = device.provider();
    let mut packet = Some(packet);
    provider.groups.visit(destination, |index, last| {
        let Some(qp) = provider.pairs.lookup(index) else {
            return true;
        };
        if check_qp(packet.as_mut().unwrap(), &qp, &admission, None).is_err() {
            return true;
        }
        let mut queued = if last {
            packet.take().unwrap()
        } else {
            let Ok(cloned) = packet.as_mut().unwrap().try_clone(GFP_ATOMIC) else {
                return true;
            };
            cloned
        };
        queued.context_mut().qp = Some(qp);
        dispatch(queued);
        true
    });
}

// The packet retains an RXE device with initialized admission resources.
fn validate(packet: &mut Packet) -> Result<(u32, [u8; 16])> {
    let network_len = if u32::from(packet.context().network.kind)
        == bindings::rdma_network_type_RDMA_NETWORK_IPV4
    {
        28
    } else {
        48
    };
    if packet.network_header_len() != network_len {
        return Err(EINVAL);
    }
    let mut network = [0; 48];
    packet.copy_network_header(&mut network[..network_len])?;
    let (info, body) = packet.parts()?;
    let body = body.get_mut(..usize::from(info.paylen)).ok_or(EINVAL)?;
    let wire = super::rxe_icrc::check(&network[..network_len], body)?;
    info.opcode = wire.opcode();
    info.psn = wire.psn();
    info.mask |= wire.mask();
    let number = wire.qpn();
    let header = &network[..network_len - 8];
    let destination = rxe_recv_check::destination_gid(header)?;
    check_gid(packet, destination)?;
    check_header(packet, header)?;
    Ok((number, destination))
}

/// Validates and consumes an incoming RXE packet.
pub(crate) fn rxe_rcv(
    buffer: packet::Packet<()>,
    device: DeviceRef<super::rxe_device::DeviceData>,
    mask: u32,
    paylen: u16,
) {
    let kind = match u32::from(buffer.protocol()) {
        bindings::ETH_P_IP => bindings::rdma_network_type_RDMA_NETWORK_IPV4,
        bindings::ETH_P_IPV6 => bindings::rdma_network_type_RDMA_NETWORK_IPV6,
        _ => return,
    } as u8;
    let vlan = buffer.device().and_then(kernel::net::Device::vlan_id);
    let length = buffer.len() as u64 + buffer.network_header_len() as u64;
    let mut packet = buffer.map_context(|()| ReceiveInfo {
        qp: None,
        generation: 0,
        device,
        mask,
        psn: 0,
        paylen,
        port_num: 1,
        opcode: 0,
        network: Network { kind, vlan },
    });
    let Ok((number, destination)) = validate(&mut packet) else {
        return;
    };
    let data = packet.context().device.provider();
    data.counters.add(Counter::ReceivedBytes, length as i64);
    data.counters.increment(Counter::ReceivedPackets);
    if number == rxe_recv_check::MULTICAST_QPN {
        multicast(packet, destination);
    } else {
        dispatch(packet);
    }
}
