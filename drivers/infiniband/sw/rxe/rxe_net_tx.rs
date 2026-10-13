// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Transmit packet allocation and network output.

#![forbid(unsafe_code)]

use super::rxe_hw_counters::Counter;
use crate::rxe_param as params;
use crate::rxe_types::{
    PacketInfo,
    QueuePair, //
};
use kernel::{
    bindings,
    net::{
        ip::Route,
        skbuff::completion::Event,
        socket::Family,
        udp::{
            Headers,
            Payload,
            Prepared, //
        }, //
    },
    prelude::*,
    rdma::gid, //
};

/// Retains a transmitted packet's QP until completion or retirement cancels the event.
pub(super) struct TransmitCompletion {
    qp: super::rxe_types::QueuePairRef,
}

impl Event for TransmitCompletion {
    fn complete(self) {
        if self.qp.data().inflight.finish() {
            super::rxe_task_ffi::schedule_send(&self.qp);
        }
    }
}

/// A transport payload retaining its network device until preparation or drop.
pub(super) struct TransmitPacket {
    payload: Payload,
    source_port: u16,
}

impl TransmitPacket {
    pub(super) fn net_device(&self) -> &kernel::net::Device {
        self.payload.device()
    }

    pub(super) fn source_port(&self) -> u16 {
        self.source_port
    }

    pub(super) fn len(&self) -> usize {
        self.payload.len()
    }

    pub(super) fn initialize(
        &mut self,
        base: super::rxe_wire::Base,
        payload: usize,
    ) -> Result<super::rxe_wire::TransportMut<'_>> {
        super::rxe_wire::TransportMut::initialize(self.payload.data_mut()?, base, payload)
    }

    pub(super) fn prepare(self, route: &Route, headers: Headers) -> Result<PreparedPacket> {
        Ok(PreparedPacket {
            packet: self.payload.prepare(route, headers)?,
        })
    }
}

/// A transport packet with immutable network headers and native route ownership.
pub(super) struct PreparedPacket {
    packet: Prepared,
}

impl PreparedPacket {
    /// Borrows only the bounded transport bytes, preserving routing and network headers.
    pub(super) fn transport(&mut self) -> Result<super::rxe_wire::TransportMut<'_>> {
        super::rxe_wire::TransportMut::parse(self.packet.data_mut()?)
    }

    fn generate_crc(&mut self) -> Result {
        let (network, transport) = self.packet.parts_mut()?;
        super::rxe_icrc::generate(network, transport)
    }
}

// Caller transfers a prepared skb, pins pkt/QP/device, and has generated ICRC.
// This function consumes the skb on both success and error.
fn transmit(qp: &QueuePair, prepared: PreparedPacket) -> c_int {
    let PreparedPacket { mut packet } = prepared;
    let completion = TransmitCompletion {
        qp: qp.try_ref().unwrap(),
    };
    // Keep the unsent packet's own netdev reference through every fallible step. Installing
    // an event cannot complete it until this owner releases or hands off the buffer.
    if let Err(error) = packet.attach_completion(&qp.data().sq.completions, completion, GFP_ATOMIC)
    {
        return error.to_errno();
    }
    qp.data().inflight.start();
    packet.output()
}

/// Generates ICRC and consumes a packet whose network headers and route are prepared.
pub(crate) fn rxe_xmit_packet(
    qp: &QueuePair,
    pkt: &PacketInfo,
    mut prepared: PreparedPacket,
) -> c_int {
    // The native borrow retains the QP and the owner keeps network headers and routing intact.
    let len = prepared.packet.len();
    let ready = {
        let shared = qp.data().control.state.lock();
        let minimum = if pkt.mask & params::RXE_REQ_MASK != 0 {
            bindings::ib_qp_state_IB_QPS_RTS
        } else {
            bindings::ib_qp_state_IB_QPS_RTR
        };
        shared.attributes.qp_state >= minimum
            && shared.attributes.qp_state <= bindings::ib_qp_state_IB_QPS_SQD
    };
    if !ready {
        return 0;
    }
    if let Err(error) = prepared.generate_crc() {
        return error.to_errno();
    }
    let err = transmit(qp, prepared);
    if err != 0 {
        qp.provider().counters.increment(Counter::SendError);
        return err;
    }
    qp.provider().counters.increment(Counter::SentPackets);
    qp.provider().counters.add(Counter::SentBytes, len as i64);
    0
}

/// Allocates a payload and reserves room for Ethernet, IP and UDP headers.
///
/// The QP retains its device while the returned allocation acquires its network-device
/// reference. The returned owner keeps that reference until drop or transmission.
pub(crate) fn rxe_init_packet(
    qp: &QueuePair,
    av: &super::rxe_av::AddressVector,
    source_port: u16,
    paylen: usize,
    pkt: &mut PacketInfo,
) -> Result<TransmitPacket> {
    let device = qp.device().try_to_ref().ok_or(ENODEV)?;
    let table = gid::Table::from_reference(&device);
    let attr = table.get(1, av.grh.sgid_index.into())?;
    let netdev = attr.net_device()?;
    let family = if av.ipv4()? {
        Family::Ipv4
    } else {
        Family::Ipv6
    };
    let payload = Payload::new(netdev, family, paylen, GFP_ATOMIC)?;
    pkt.mask |= params::RXE_GRH_MASK;
    Ok(TransmitPacket {
        payload,
        source_port,
    })
}
