// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Owned receive metadata and bounded transport views.

#![forbid(unsafe_code)]

use super::{
    rxe_completion::Network,
    rxe_device::DeviceData,
    rxe_types::QueuePairRef,
    rxe_wire::{
        Transport,
        ICRC_BYTES, //
    }, //
};
use kernel::{
    bindings,
    net::skbuff::packet,
    prelude::*,
    rdma::DeviceRef, //
};

pub(super) use super::rxe_wire::psn_compare;

/// Ownership follows a received packet through validation, cloning and worker dispatch.
#[derive(Clone)]
pub(super) struct ReceiveInfo {
    pub(super) qp: Option<QueuePairRef>,
    pub(super) generation: u32,
    pub(super) device: DeviceRef<DeviceData>,
    pub(super) mask: u32,
    pub(super) psn: u32,
    pub(super) paylen: u16,
    pub(super) port_num: u8,
    pub(super) opcode: u8,
    pub(super) network: Network,
}

pub(super) type Packet = packet::Packet<ReceiveInfo>;
pub(super) type PacketQueue = packet::Queue<ReceiveInfo>;

/// Borrows validated transport bytes after making cloned storage private.
pub(super) fn transport(packet: &mut Packet) -> Result<Transport<'_>> {
    let (info, bytes) = packet.parts()?;
    let length = usize::from(info.paylen)
        .checked_sub(ICRC_BYTES)
        .ok_or(EINVAL)?;
    Transport::parse(bytes.get(..length).ok_or(EINVAL)?)
}

/// Copies the network header into the 40-byte receive prefix required by verbs.
pub(super) fn grh(packet: &Packet) -> Result<[u8; 40]> {
    let mut header = [0; 40];
    if u32::from(packet.context().network.kind) == bindings::rdma_network_type_RDMA_NETWORK_IPV4 {
        packet.copy_network_header(&mut header[20..])?;
    } else {
        packet.copy_network_header(&mut header)?;
    }
    Ok(header)
}
