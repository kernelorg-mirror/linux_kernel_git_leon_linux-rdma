// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Transport limits, capabilities and wire constants.

#![forbid(unsafe_code)]

use kernel::bindings;

const DEFAULT_MAX_VALUE: u32 = 1 << 20;

pub(crate) const WR_MAX_QPT: u32 = 8;
pub(crate) const RXE_NUM_OPCODE: u32 = 256;
pub(crate) const RXE_MAX_HDR_LENGTH: u32 = 80;
pub(crate) const GSI_QKEY: u32 = 0x80010000;
pub(crate) const RXE_UVERBS_ABI_VERSION: u32 = 2;
pub(crate) const RXE_ROCE_V2_SPORT: u32 = 0xc000;
pub(crate) const WR_INLINE_MASK: u32 = 1 << 0;
pub(crate) const WR_ATOMIC_MASK: u32 = 1 << 1;
pub(crate) const WR_SEND_MASK: u32 = 1 << 2;
pub(crate) const WR_READ_MASK: u32 = 1 << 3;
pub(crate) const WR_WRITE_MASK: u32 = 1 << 4;
pub(crate) const WR_LOCAL_OP_MASK: u32 = 1 << 5;
pub(crate) const WR_FLUSH_MASK: u32 = 1 << 6;
pub(crate) const WR_ATOMIC_WRITE_MASK: u32 = 1 << 7;
pub(crate) const WR_READ_OR_WRITE_MASK: u32 = WR_READ_MASK | WR_WRITE_MASK;
pub(crate) const WR_WRITE_OR_SEND_MASK: u32 = WR_WRITE_MASK | WR_SEND_MASK;
pub(crate) const WR_ATOMIC_OR_READ_MASK: u32 = WR_ATOMIC_MASK | WR_READ_MASK;
pub(crate) const RXE_BTH: u32 = 2;
pub(crate) const RXE_RETH: u32 = 3;
pub(crate) const RXE_AETH: u32 = 4;
pub(crate) const RXE_ATMETH: u32 = 5;
pub(crate) const RXE_ATMACK: u32 = 6;
pub(crate) const RXE_IETH: u32 = 7;
pub(crate) const RXE_RDETH: u32 = 8;
pub(crate) const RXE_DETH: u32 = 9;
pub(crate) const RXE_IMMDT: u32 = 10;
pub(crate) const RXE_FETH: u32 = 11;
pub(crate) const RXE_PAYLOAD: u32 = 12;
pub(crate) const NUM_HDR_TYPES: u32 = 13;
pub(crate) const RXE_GRH_MASK: u32 = 1 << 1;
pub(crate) const RXE_IMMDT_MASK: u32 = 1 << RXE_IMMDT;
pub(crate) const RXE_RETH_MASK: u32 = 1 << RXE_RETH;
pub(crate) const RXE_AETH_MASK: u32 = 1 << RXE_AETH;
pub(crate) const RXE_ATMETH_MASK: u32 = 1 << RXE_ATMETH;
pub(crate) const RXE_ATMACK_MASK: u32 = 1 << RXE_ATMACK;
pub(crate) const RXE_IETH_MASK: u32 = 1 << RXE_IETH;
pub(crate) const RXE_RDETH_MASK: u32 = 1 << RXE_RDETH;
pub(crate) const RXE_DETH_MASK: u32 = 1 << RXE_DETH;
pub(crate) const RXE_FETH_MASK: u32 = 1 << RXE_FETH;
pub(crate) const RXE_PAYLOAD_MASK: u32 = 1 << RXE_PAYLOAD;
pub(crate) const RXE_REQ_MASK: u32 = 1 << NUM_HDR_TYPES;
pub(crate) const RXE_ACK_MASK: u32 = 1 << (NUM_HDR_TYPES + 1);
pub(crate) const RXE_SEND_MASK: u32 = 1 << (NUM_HDR_TYPES + 2);
pub(crate) const RXE_WRITE_MASK: u32 = 1 << (NUM_HDR_TYPES + 3);
pub(crate) const RXE_READ_MASK: u32 = 1 << (NUM_HDR_TYPES + 4);
pub(crate) const RXE_ATOMIC_MASK: u32 = 1 << (NUM_HDR_TYPES + 5);
pub(crate) const RXE_FLUSH_MASK: u32 = 1 << (NUM_HDR_TYPES + 6);
pub(crate) const RXE_RWR_MASK: u32 = 1 << (NUM_HDR_TYPES + 7);
pub(crate) const RXE_COMP_MASK: u32 = 1 << (NUM_HDR_TYPES + 8);
pub(crate) const RXE_START_MASK: u32 = 1 << (NUM_HDR_TYPES + 9);
pub(crate) const RXE_MIDDLE_MASK: u32 = 1 << (NUM_HDR_TYPES + 10);
pub(crate) const RXE_END_MASK: u32 = 1 << (NUM_HDR_TYPES + 11);
pub(crate) const RXE_LOOPBACK_MASK: u32 = 1 << (NUM_HDR_TYPES + 12);
pub(crate) const RXE_ATOMIC_WRITE_MASK: u32 = 1 << (NUM_HDR_TYPES + 14);
pub(crate) const RXE_READ_OR_ATOMIC_MASK: u32 = RXE_READ_MASK | RXE_ATOMIC_MASK;
pub(crate) const RXE_WRITE_OR_SEND_MASK: u32 = RXE_WRITE_MASK | RXE_SEND_MASK;
pub(crate) const RXE_READ_OR_WRITE_MASK: u32 = RXE_READ_MASK | RXE_WRITE_MASK;
pub(crate) const RXE_RDMA_OP_MASK: u32 =
    RXE_READ_MASK | RXE_WRITE_MASK | RXE_ATOMIC_WRITE_MASK | RXE_FLUSH_MASK | RXE_ATOMIC_MASK;
pub(crate) const AETH_TYPE_MASK: u32 = 0xe0;
pub(crate) const AETH_ACK: u32 = 0x00;
pub(crate) const AETH_RNR_NAK: u32 = 0x20;
pub(crate) const AETH_NAK: u32 = 0x60;
pub(crate) const AETH_ACK_UNLIMITED: u32 = 0x1f;
pub(crate) const AETH_NAK_PSN_SEQ_ERROR: u32 = 0x60;
pub(crate) const AETH_NAK_INVALID_REQ: u32 = 0x61;
pub(crate) const AETH_NAK_REM_ACC_ERR: u32 = 0x62;
pub(crate) const AETH_NAK_REM_OP_ERR: u32 = 0x63;
pub(crate) const RXE_BTH_BYTES: u32 = 12;
pub(crate) const RXE_DETH_BYTES: u32 = 8;
pub(crate) const RXE_IMMDT_BYTES: u32 = 4;
pub(crate) const RXE_RETH_BYTES: u32 = 16;
pub(crate) const RXE_AETH_BYTES: u32 = 4;
pub(crate) const RXE_ATMACK_BYTES: u32 = 8;
pub(crate) const RXE_ATMETH_BYTES: u32 = 28;
pub(crate) const RXE_IETH_BYTES: u32 = 4;
pub(crate) const RXE_RDETH_BYTES: u32 = 4;
pub(crate) const RXE_FETH_BYTES: u32 = 4;
pub(crate) const RXE_MAX_MR_SIZE: u64 = u64::MAX;
pub(crate) const RXE_PAGE_SIZE_CAP: u32 = 0xfffff000;
pub(crate) const RXE_MAX_QP_WR: u32 = DEFAULT_MAX_VALUE;
pub(crate) const RXE_MAX_SGE: u32 = 32;
pub(crate) const RXE_MAX_INLINE_DATA: usize = super::rxe_wqe::SGE_SIZE * RXE_MAX_SGE as usize;
pub(crate) const RXE_MAX_SGE_RD: u32 = 32;
pub(crate) const RXE_MAX_CQ: u32 = DEFAULT_MAX_VALUE;
pub(crate) const RXE_MAX_LOG_CQE: u32 = 15;
pub(crate) const RXE_MAX_CQE: u32 = (1 << RXE_MAX_LOG_CQE) - 1;
pub(crate) const RXE_MAX_PD: u32 = DEFAULT_MAX_VALUE;
pub(crate) const RXE_MAX_QP_RD_ATOM: u32 = 128;
pub(crate) const RXE_MAX_RES_RD_ATOM: u32 = 0x3f000;
pub(crate) const RXE_MAX_QP_INIT_RD_ATOM: u32 = 128;
pub(crate) const RXE_MAX_MCAST_GRP: u32 = 8192;
pub(crate) const RXE_MAX_MCAST_QP_ATTACH: u32 = 56;
pub(crate) const RXE_MAX_TOT_MCAST_QP_ATTACH: u32 = 0x70000;
pub(crate) const RXE_MAX_AH: u32 = (1 << 15) - 1;
pub(crate) const RXE_MAX_SRQ_WR: u32 = DEFAULT_MAX_VALUE;
pub(crate) const RXE_MIN_SRQ_WR: u32 = 1;
pub(crate) const RXE_MAX_SRQ_SGE: u32 = 27;
pub(crate) const RXE_MIN_SRQ_SGE: u32 = 1;
pub(crate) const RXE_MAX_FMR_PAGE_LIST_LEN: u32 = 512;
pub(crate) const RXE_MAX_PKEYS: u32 = 64;
pub(crate) const RXE_LOCAL_CA_ACK_DELAY: u32 = 15;
pub(crate) const RXE_MAX_UCONTEXT: u32 = DEFAULT_MAX_VALUE;
pub(crate) const RXE_MIN_QP_INDEX: u32 = 16;
pub(crate) const RXE_MAX_QP_INDEX: u32 = DEFAULT_MAX_VALUE;
pub(crate) const RXE_MAX_QP: u32 = DEFAULT_MAX_VALUE - RXE_MIN_QP_INDEX;
pub(crate) const RXE_MIN_SRQ_INDEX: u32 = 0x00020001;
pub(crate) const RXE_MAX_SRQ_INDEX: u32 = DEFAULT_MAX_VALUE;
pub(crate) const RXE_MAX_SRQ: u32 = DEFAULT_MAX_VALUE - RXE_MIN_SRQ_INDEX;
pub(crate) const RXE_MIN_MR_INDEX: u32 = 0x00000001;
pub(crate) const RXE_MAX_MR_INDEX: u32 = DEFAULT_MAX_VALUE >> 1;
pub(crate) const RXE_MAX_MR: u32 = RXE_MAX_MR_INDEX - RXE_MIN_MR_INDEX;
pub(crate) const RXE_MIN_MW_INDEX: u32 = RXE_MAX_MR_INDEX + 1;
pub(crate) const RXE_MAX_MW_INDEX: u32 = DEFAULT_MAX_VALUE;
pub(crate) const RXE_MAX_MW: u32 = RXE_MAX_MW_INDEX - RXE_MIN_MW_INDEX;
pub(crate) const RXE_MAX_PKT_PER_ACK: u32 = 64;
pub(crate) const RXE_MAX_UNACKED_PSNS: u32 = 128;
pub(crate) const RXE_INFLIGHT_SKBS_PER_QP_HIGH: u32 = 64;
pub(crate) const RXE_INFLIGHT_SKBS_PER_QP_LOW: u32 = 16;
pub(crate) const RXE_MAX_ITERATIONS: u32 = 1024;
pub(crate) const RXE_VENDOR_ID: u32 = 0xffffff;
pub(crate) const RXE_PORT_GID_TBL_LEN: u32 = 1024;
pub(crate) const RXE_PORT_PORT_CAP_FLAGS: u32 =
    bindings::ib_port_capability_mask_bits_IB_PORT_CM_SUP;
pub(crate) const RXE_PORT_MAX_MSG_SZ: u32 = 1 << 31;
pub(crate) const RXE_PORT_LID: u32 = 0;
pub(crate) const RXE_PORT_SM_LID: u32 = 0;
pub(crate) const RXE_PORT_SM_SL: u32 = 0;
pub(crate) const RXE_PORT_LMC: u32 = 0;
pub(crate) const RXE_PORT_MAX_VL_NUM: u32 = 1;
pub(crate) const RXE_PORT_SUBNET_TIMEOUT: u32 = 0;
pub(crate) const RXE_PORT_INIT_TYPE_REPLY: u32 = 0;
pub(crate) const RXE_PORT_PKEY_TBL_LEN: u32 = 1;
pub(crate) const RXE_CNT_SENT_PKTS: u32 = 0;
pub(crate) const RXE_CNT_RCVD_PKTS: u32 = 1;
pub(crate) const RXE_CNT_DUP_REQ: u32 = 2;
pub(crate) const RXE_CNT_OUT_OF_SEQ_REQ: u32 = 3;
pub(crate) const RXE_CNT_RCV_RNR: u32 = 4;
pub(crate) const RXE_CNT_SND_RNR: u32 = 5;
pub(crate) const RXE_CNT_RCV_SEQ_ERR: u32 = 6;
pub(crate) const RXE_CNT_SENDER_SCHED: u32 = 7;
pub(crate) const RXE_CNT_RETRY_EXCEEDED: u32 = 8;
pub(crate) const RXE_CNT_RNR_RETRY_EXCEEDED: u32 = 9;
pub(crate) const RXE_CNT_COMP_RETRY: u32 = 10;
pub(crate) const RXE_CNT_SEND_ERR: u32 = 11;
pub(crate) const RXE_CNT_LINK_DOWNED: u32 = 12;
pub(crate) const RXE_CNT_RDMA_SEND: u32 = 13;
pub(crate) const RXE_CNT_RDMA_RECV: u32 = 14;
pub(crate) const RXE_CNT_SENT_BYTES: u32 = 15;
pub(crate) const RXE_CNT_RCVD_BYTES: u32 = 16;
pub(crate) const RXE_NUM_OF_COUNTERS: u32 = 17;
pub(crate) const WQE_STATE_POSTED: u32 = 0;
pub(crate) const WQE_STATE_PROCESSING: u32 = 1;
pub(crate) const WQE_STATE_PENDING: u32 = 2;
pub(crate) const WQE_STATE_DONE: u32 = 3;
pub(crate) const WQE_STATE_ERROR: u32 = 4;
pub(crate) const RXE_ACCESS_REMOTE: u32 = bindings::ib_access_flags_IB_ACCESS_REMOTE_READ
    | bindings::ib_access_flags_IB_ACCESS_REMOTE_WRITE
    | bindings::ib_access_flags_IB_ACCESS_REMOTE_ATOMIC;
pub(crate) const RXE_ACCESS_SUPPORTED_MR: u32 = RXE_ACCESS_REMOTE
    | bindings::ib_access_flags_IB_ACCESS_LOCAL_WRITE
    | bindings::ib_access_flags_IB_ACCESS_MW_BIND
    | bindings::ib_access_flags_IB_ACCESS_ON_DEMAND
    | bindings::ib_access_flags_IB_ACCESS_FLUSH_GLOBAL
    | bindings::ib_access_flags_IB_ACCESS_FLUSH_PERSISTENT
    | bindings::ib_access_flags_IB_ACCESS_OPTIONAL;
pub(crate) const RXE_ACCESS_SUPPORTED_QP: u32 = RXE_ACCESS_SUPPORTED_MR;
pub(crate) const RXE_ACCESS_SUPPORTED_MW: u32 =
    RXE_ACCESS_SUPPORTED_MR | bindings::ib_access_flags_IB_ZERO_BASED;
