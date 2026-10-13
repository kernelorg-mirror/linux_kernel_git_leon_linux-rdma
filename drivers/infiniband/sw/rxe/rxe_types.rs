// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Native RXE objects and metadata. Core devices and queue pairs use typed kernel owners.

#![forbid(unsafe_code)]

use kernel::prelude::*;

pub(crate) use super::rxe_resp_state::State as ResponderState;

/// Which side owns each producer and consumer index.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueueType {
    ToClient = 0,
    FromClient = 1,
}

/// The RDMA core owns the allocation and drains native provider references.
pub(crate) type QueuePair = kernel::rdma::QueuePair<super::rxe_device::DeviceData>;
pub(crate) type QueuePairRef = kernel::rdma::QueuePairRef<super::rxe_device::DeviceData>;

/// Transmit metadata kept separately from packet storage.
#[repr(C)]
#[derive(Zeroable, Clone, Copy)]
pub(crate) struct PacketInfo {
    pub(crate) mask: u32,
    pub(crate) psn: u32,
    pub(crate) paylen: u16,
    pub(crate) opcode: u8,
}
