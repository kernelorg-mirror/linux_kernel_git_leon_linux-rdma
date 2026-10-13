// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Immutable work request and transport opcode metadata.

#![forbid(unsafe_code)]

use crate::rxe_param::{
    NUM_HDR_TYPES,
    RXE_ACK_MASK,
    RXE_AETH,
    RXE_AETH_BYTES,
    RXE_AETH_MASK,
    RXE_ATMACK,
    RXE_ATMACK_BYTES,
    RXE_ATMACK_MASK,
    RXE_ATMETH,
    RXE_ATMETH_BYTES,
    RXE_ATMETH_MASK,
    RXE_ATOMIC_MASK,
    RXE_ATOMIC_WRITE_MASK,
    RXE_BTH,
    RXE_BTH_BYTES,
    RXE_COMP_MASK,
    RXE_DETH,
    RXE_DETH_BYTES,
    RXE_DETH_MASK,
    RXE_END_MASK,
    RXE_FETH,
    RXE_FETH_BYTES,
    RXE_FETH_MASK,
    RXE_FLUSH_MASK,
    RXE_IETH,
    RXE_IETH_BYTES,
    RXE_IETH_MASK,
    RXE_IMMDT,
    RXE_IMMDT_BYTES,
    RXE_IMMDT_MASK,
    RXE_MIDDLE_MASK,
    RXE_NUM_OPCODE,
    RXE_PAYLOAD,
    RXE_PAYLOAD_MASK,
    RXE_RDETH,
    RXE_RDETH_BYTES,
    RXE_RDETH_MASK,
    RXE_READ_MASK,
    RXE_REQ_MASK,
    RXE_RETH,
    RXE_RETH_BYTES,
    RXE_RETH_MASK,
    RXE_RWR_MASK,
    RXE_SEND_MASK,
    RXE_START_MASK,
    RXE_WRITE_MASK,
    WR_ATOMIC_MASK,
    WR_ATOMIC_WRITE_MASK,
    WR_FLUSH_MASK,
    WR_INLINE_MASK,
    WR_LOCAL_OP_MASK,
    WR_MAX_QPT,
    WR_READ_MASK,
    WR_SEND_MASK,
    WR_WRITE_MASK, //
};
use kernel::{
    bindings::{
        ib_qp_type_IB_QPT_GSI as IB_QPT_GSI,
        ib_qp_type_IB_QPT_RC as IB_QPT_RC,
        ib_qp_type_IB_QPT_UC as IB_QPT_UC,
        ib_qp_type_IB_QPT_UD as IB_QPT_UD,
        ib_wr_opcode_IB_WR_ATOMIC_CMP_AND_SWP as IB_WR_ATOMIC_CMP_AND_SWP,
        ib_wr_opcode_IB_WR_ATOMIC_FETCH_AND_ADD as IB_WR_ATOMIC_FETCH_AND_ADD,
        ib_wr_opcode_IB_WR_ATOMIC_WRITE as IB_WR_ATOMIC_WRITE,
        ib_wr_opcode_IB_WR_BIND_MW as IB_WR_BIND_MW,
        ib_wr_opcode_IB_WR_FLUSH as IB_WR_FLUSH,
        ib_wr_opcode_IB_WR_LOCAL_INV as IB_WR_LOCAL_INV,
        ib_wr_opcode_IB_WR_RDMA_READ as IB_WR_RDMA_READ,
        ib_wr_opcode_IB_WR_RDMA_READ_WITH_INV as IB_WR_RDMA_READ_WITH_INV,
        ib_wr_opcode_IB_WR_RDMA_WRITE as IB_WR_RDMA_WRITE,
        ib_wr_opcode_IB_WR_RDMA_WRITE_WITH_IMM as IB_WR_RDMA_WRITE_WITH_IMM,
        ib_wr_opcode_IB_WR_REG_MR as IB_WR_REG_MR,
        ib_wr_opcode_IB_WR_SEND as IB_WR_SEND,
        ib_wr_opcode_IB_WR_SEND_WITH_IMM as IB_WR_SEND_WITH_IMM,
        ib_wr_opcode_IB_WR_SEND_WITH_INV as IB_WR_SEND_WITH_INV,
        IB_OPCODE_RC_ACKNOWLEDGE,
        IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE,
        IB_OPCODE_RC_ATOMIC_WRITE,
        IB_OPCODE_RC_COMPARE_SWAP,
        IB_OPCODE_RC_FETCH_ADD,
        IB_OPCODE_RC_FLUSH,
        IB_OPCODE_RC_RDMA_READ_REQUEST,
        IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST,
        IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST,
        IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE,
        IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY,
        IB_OPCODE_RC_RDMA_WRITE_FIRST,
        IB_OPCODE_RC_RDMA_WRITE_LAST,
        IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE,
        IB_OPCODE_RC_RDMA_WRITE_MIDDLE,
        IB_OPCODE_RC_RDMA_WRITE_ONLY,
        IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE,
        IB_OPCODE_RC_SEND_FIRST,
        IB_OPCODE_RC_SEND_LAST,
        IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE,
        IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE,
        IB_OPCODE_RC_SEND_MIDDLE,
        IB_OPCODE_RC_SEND_ONLY,
        IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE,
        IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE,
        IB_OPCODE_RD_ACKNOWLEDGE,
        IB_OPCODE_RD_ATOMIC_ACKNOWLEDGE,
        IB_OPCODE_RD_COMPARE_SWAP,
        IB_OPCODE_RD_FETCH_ADD,
        IB_OPCODE_RD_RDMA_READ_REQUEST,
        IB_OPCODE_RD_RDMA_READ_RESPONSE_FIRST,
        IB_OPCODE_RD_RDMA_READ_RESPONSE_LAST,
        IB_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE,
        IB_OPCODE_RD_RDMA_READ_RESPONSE_ONLY,
        IB_OPCODE_RD_RDMA_WRITE_FIRST,
        IB_OPCODE_RD_RDMA_WRITE_LAST,
        IB_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE,
        IB_OPCODE_RD_RDMA_WRITE_MIDDLE,
        IB_OPCODE_RD_RDMA_WRITE_ONLY,
        IB_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE,
        IB_OPCODE_RD_SEND_FIRST,
        IB_OPCODE_RD_SEND_LAST,
        IB_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE,
        IB_OPCODE_RD_SEND_MIDDLE,
        IB_OPCODE_RD_SEND_ONLY,
        IB_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE,
        IB_OPCODE_UC_RDMA_WRITE_FIRST,
        IB_OPCODE_UC_RDMA_WRITE_LAST,
        IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE,
        IB_OPCODE_UC_RDMA_WRITE_MIDDLE,
        IB_OPCODE_UC_RDMA_WRITE_ONLY,
        IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE,
        IB_OPCODE_UC_SEND_FIRST,
        IB_OPCODE_UC_SEND_LAST,
        IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE,
        IB_OPCODE_UC_SEND_MIDDLE,
        IB_OPCODE_UC_SEND_ONLY,
        IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE,
        IB_OPCODE_UD_SEND_ONLY,
        IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE, //
    },
    ffi::c_int, //
};

#[derive(Clone, Copy)]
struct WorkOpcode {
    mask: [u32; WR_MAX_QPT as usize],
}

/// Transport layout for one wire opcode.
#[derive(Clone, Copy)]
pub(super) struct Opcode {
    pub(super) mask: u32,
    pub(super) length: i32,
    pub(super) offset: [i32; NUM_HDR_TYPES as usize],
}

static WORK_OPCODES: [WorkOpcode; 33] = wr_opcodes();

/// Looks up a work request without trusting either caller-supplied index.
pub(super) fn work_mask(opcode: u32, qp_type: u32) -> u32 {
    WORK_OPCODES
        .get(opcode as usize)
        .and_then(|entry| entry.mask.get(qp_type as usize))
        .copied()
        .unwrap_or(0)
}

/// Returns the immutable layout of an eight-bit wire opcode.
pub(super) fn info(opcode: u8) -> &'static Opcode {
    &OPCODES[usize::from(opcode)]
}

const fn wr_opcodes() -> [WorkOpcode; 33] {
    let mut table = [WorkOpcode {
        mask: [0; WR_MAX_QPT as usize],
    }; 33];
    table[IB_WR_RDMA_WRITE as usize].mask[IB_QPT_RC as usize] = WR_INLINE_MASK | WR_WRITE_MASK;
    table[IB_WR_RDMA_WRITE as usize].mask[IB_QPT_UC as usize] = WR_INLINE_MASK | WR_WRITE_MASK;
    table[IB_WR_RDMA_WRITE_WITH_IMM as usize].mask[IB_QPT_RC as usize] =
        WR_INLINE_MASK | WR_WRITE_MASK;
    table[IB_WR_RDMA_WRITE_WITH_IMM as usize].mask[IB_QPT_UC as usize] =
        WR_INLINE_MASK | WR_WRITE_MASK;
    table[IB_WR_SEND as usize].mask[IB_QPT_GSI as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    table[IB_WR_SEND as usize].mask[IB_QPT_RC as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    table[IB_WR_SEND as usize].mask[IB_QPT_UC as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    table[IB_WR_SEND as usize].mask[IB_QPT_UD as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    table[IB_WR_SEND_WITH_IMM as usize].mask[IB_QPT_GSI as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    table[IB_WR_SEND_WITH_IMM as usize].mask[IB_QPT_RC as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    table[IB_WR_SEND_WITH_IMM as usize].mask[IB_QPT_UC as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    table[IB_WR_SEND_WITH_IMM as usize].mask[IB_QPT_UD as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    table[IB_WR_RDMA_READ as usize].mask[IB_QPT_RC as usize] = WR_READ_MASK;
    table[IB_WR_ATOMIC_CMP_AND_SWP as usize].mask[IB_QPT_RC as usize] = WR_ATOMIC_MASK;
    table[IB_WR_ATOMIC_FETCH_AND_ADD as usize].mask[IB_QPT_RC as usize] = WR_ATOMIC_MASK;
    table[IB_WR_SEND_WITH_INV as usize].mask[IB_QPT_RC as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    table[IB_WR_SEND_WITH_INV as usize].mask[IB_QPT_UC as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    table[IB_WR_SEND_WITH_INV as usize].mask[IB_QPT_UD as usize] = WR_INLINE_MASK | WR_SEND_MASK;
    table[IB_WR_RDMA_READ_WITH_INV as usize].mask[IB_QPT_RC as usize] = WR_READ_MASK;
    table[IB_WR_LOCAL_INV as usize].mask[IB_QPT_RC as usize] = WR_LOCAL_OP_MASK;
    table[IB_WR_REG_MR as usize].mask[IB_QPT_RC as usize] = WR_LOCAL_OP_MASK;
    table[IB_WR_BIND_MW as usize].mask[IB_QPT_RC as usize] = WR_LOCAL_OP_MASK;
    table[IB_WR_BIND_MW as usize].mask[IB_QPT_UC as usize] = WR_LOCAL_OP_MASK;
    table[IB_WR_FLUSH as usize].mask[IB_QPT_RC as usize] = WR_FLUSH_MASK;
    table[IB_WR_ATOMIC_WRITE as usize].mask[IB_QPT_RC as usize] = WR_ATOMIC_WRITE_MASK;
    table
}

/// Transport header layout and request classification for every wire opcode.
// Unsupported opcodes retain a zero mask and length for the receive validator.
static OPCODES: [Opcode; RXE_NUM_OPCODE as usize] = opcodes();

const fn opcodes() -> [Opcode; RXE_NUM_OPCODE as usize] {
    let mut table = [Opcode {
        mask: 0,
        length: 0,
        offset: [0; NUM_HDR_TYPES as usize],
    }; RXE_NUM_OPCODE as usize];
    table[IB_OPCODE_RC_SEND_FIRST as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_RWR_MASK | RXE_SEND_MASK | RXE_START_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_SEND_MIDDLE as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_SEND_MASK | RXE_MIDDLE_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_SEND_LAST as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_COMP_MASK | RXE_SEND_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_SEND_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IMMDT_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_IMMDT as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_SEND_ONLY as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_SEND_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_SEND_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IMMDT_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_IMMDT as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_RDMA_WRITE_FIRST as usize] = Opcode {
        mask: RXE_RETH_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK | RXE_START_MASK,
        length: (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_RDMA_WRITE_MIDDLE as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK | RXE_MIDDLE_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_RDMA_WRITE_LAST as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_WRITE_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IMMDT_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_IMMDT as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_RDMA_WRITE_ONLY as usize] = Opcode {
        mask: RXE_RETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_WRITE_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_RETH_MASK
            | RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_WRITE_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_RETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_IMMDT as usize] = (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_RDMA_READ_REQUEST as usize] = Opcode {
        mask: RXE_RETH_MASK | RXE_REQ_MASK | RXE_READ_MASK | RXE_START_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST as usize] = Opcode {
        mask: RXE_AETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_START_MASK,
        length: (RXE_BTH_BYTES + RXE_AETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_AETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_AETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_MIDDLE_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST as usize] = Opcode {
        mask: RXE_AETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_AETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_AETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_AETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY as usize] = Opcode {
        mask: RXE_AETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_START_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_AETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_AETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_AETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_ACKNOWLEDGE as usize] = Opcode {
        mask: RXE_AETH_MASK | RXE_ACK_MASK | RXE_START_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_AETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_AETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_AETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE as usize] = Opcode {
        mask: RXE_AETH_MASK | RXE_ATMACK_MASK | RXE_ACK_MASK | RXE_START_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_ATMACK_BYTES + RXE_AETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_AETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_ATMACK as usize] = (RXE_BTH_BYTES + RXE_AETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_ATMACK_BYTES + RXE_AETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_COMPARE_SWAP as usize] = Opcode {
        mask: RXE_ATMETH_MASK | RXE_REQ_MASK | RXE_ATOMIC_MASK | RXE_START_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_ATMETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_ATMETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_ATMETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_FETCH_ADD as usize] = Opcode {
        mask: RXE_ATMETH_MASK | RXE_REQ_MASK | RXE_ATOMIC_MASK | RXE_START_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_ATMETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_ATMETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_ATMETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE as usize] = Opcode {
        mask: RXE_IETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_SEND_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_IETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_IETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE as usize] = Opcode {
        mask: RXE_IETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_SEND_MASK
            | RXE_END_MASK
            | RXE_START_MASK,
        length: (RXE_BTH_BYTES + RXE_IETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_IETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_IETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_FLUSH as usize] = Opcode {
        mask: RXE_FETH_MASK
            | RXE_RETH_MASK
            | RXE_FLUSH_MASK
            | RXE_START_MASK
            | RXE_END_MASK
            | RXE_REQ_MASK,
        length: (RXE_BTH_BYTES + RXE_FETH_BYTES + RXE_RETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_FETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES + RXE_FETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RC_ATOMIC_WRITE as usize] = Opcode {
        mask: RXE_RETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_ATOMIC_WRITE_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UC_SEND_FIRST as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_RWR_MASK | RXE_SEND_MASK | RXE_START_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UC_SEND_MIDDLE as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_SEND_MASK | RXE_MIDDLE_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UC_SEND_LAST as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_COMP_MASK | RXE_SEND_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_SEND_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IMMDT_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_IMMDT as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UC_SEND_ONLY as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_SEND_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_SEND_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IMMDT_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_IMMDT as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UC_RDMA_WRITE_FIRST as usize] = Opcode {
        mask: RXE_RETH_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK | RXE_START_MASK,
        length: (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UC_RDMA_WRITE_MIDDLE as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK | RXE_MIDDLE_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UC_RDMA_WRITE_LAST as usize] = Opcode {
        mask: RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_WRITE_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IMMDT_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_IMMDT as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UC_RDMA_WRITE_ONLY as usize] = Opcode {
        mask: RXE_RETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_WRITE_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_RETH_MASK
            | RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_WRITE_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_RETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_IMMDT as usize] = (RXE_BTH_BYTES + RXE_RETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_SEND_FIRST as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_RWR_MASK
            | RXE_SEND_MASK
            | RXE_START_MASK,
        length: (RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_SEND_MIDDLE as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_SEND_MASK
            | RXE_MIDDLE_MASK,
        length: (RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_SEND_LAST as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_SEND_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_SEND_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_IMMDT as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_SEND_ONLY as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_SEND_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_SEND_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_IMMDT as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_RDMA_WRITE_FIRST as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_RETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_WRITE_MASK
            | RXE_START_MASK,
        length: (RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_RETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_RDMA_WRITE_MIDDLE as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_WRITE_MASK
            | RXE_MIDDLE_MASK,
        length: (RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_RDMA_WRITE_LAST as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_WRITE_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_WRITE_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_IMMDT as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_RDMA_WRITE_ONLY as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_RETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_WRITE_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_RETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_RETH_MASK
            | RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_WRITE_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES
            + RXE_IMMDT_BYTES
            + RXE_RETH_BYTES
            + RXE_DETH_BYTES
            + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset[RXE_IMMDT as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES + RXE_RETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES
                + RXE_RDETH_BYTES
                + RXE_DETH_BYTES
                + RXE_RETH_BYTES
                + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_RDMA_READ_REQUEST as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_RETH_MASK
            | RXE_REQ_MASK
            | RXE_READ_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_RETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_RDMA_READ_RESPONSE_FIRST as usize] = Opcode {
        mask: RXE_RDETH_MASK | RXE_AETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_START_MASK,
        length: (RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_AETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_AETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE as usize] = Opcode {
        mask: RXE_RDETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_MIDDLE_MASK,
        length: (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_RDMA_READ_RESPONSE_LAST as usize] = Opcode {
        mask: RXE_RDETH_MASK | RXE_AETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_AETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_AETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_RDMA_READ_RESPONSE_ONLY as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_AETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_ACK_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_AETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_AETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_ACKNOWLEDGE as usize] = Opcode {
        mask: RXE_RDETH_MASK | RXE_AETH_MASK | RXE_ACK_MASK | RXE_START_MASK | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_AETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_ATOMIC_ACKNOWLEDGE as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_AETH_MASK
            | RXE_ATMACK_MASK
            | RXE_ACK_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_ATMACK_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_AETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_ATMACK as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_AETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_COMPARE_SWAP as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_ATMETH_MASK
            | RXE_REQ_MASK
            | RXE_ATOMIC_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_ATMETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_ATMETH as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_ATMETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_RD_FETCH_ADD as usize] = Opcode {
        mask: RXE_RDETH_MASK
            | RXE_DETH_MASK
            | RXE_ATMETH_MASK
            | RXE_REQ_MASK
            | RXE_ATOMIC_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_ATMETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_RDETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset[RXE_ATMETH as usize] =
                (RXE_BTH_BYTES + RXE_RDETH_BYTES + RXE_DETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_ATMETH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UD_SEND_ONLY as usize] = Opcode {
        mask: RXE_DETH_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_SEND_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_DETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] = (RXE_BTH_BYTES + RXE_DETH_BYTES) as c_int;
            offset
        },
    };
    table[IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE as usize] = Opcode {
        mask: RXE_DETH_MASK
            | RXE_IMMDT_MASK
            | RXE_PAYLOAD_MASK
            | RXE_REQ_MASK
            | RXE_COMP_MASK
            | RXE_RWR_MASK
            | RXE_SEND_MASK
            | RXE_START_MASK
            | RXE_END_MASK,
        length: (RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES) as c_int,
        offset: {
            let mut offset = [0; NUM_HDR_TYPES as usize];
            offset[RXE_BTH as usize] = (0) as c_int;
            offset[RXE_DETH as usize] = (RXE_BTH_BYTES) as c_int;
            offset[RXE_IMMDT as usize] = (RXE_BTH_BYTES + RXE_DETH_BYTES) as c_int;
            offset[RXE_PAYLOAD as usize] =
                (RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_IMMDT_BYTES) as c_int;
            offset
        },
    };
    table
}
