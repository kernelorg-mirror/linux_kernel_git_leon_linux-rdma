// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Software RDMA over Ethernet (RoCEv2).

#![forbid(unsafe_code)]

use kernel::prelude::*;

mod rxe_ah;
mod rxe_av;
mod rxe_comp;
mod rxe_comp_state;
mod rxe_completion;
mod rxe_context;
mod rxe_cq;
mod rxe_device;
mod rxe_hw_counters;
mod rxe_icrc;
mod rxe_id;
mod rxe_inflight;
mod rxe_mad;
mod rxe_mcast;
mod rxe_mcast_control;
mod rxe_mmap;
mod rxe_mr;
mod rxe_mr_data;
mod rxe_mr_fast;
mod rxe_mr_region;
mod rxe_mr_user;
mod rxe_mw;
mod rxe_mw_state;
mod rxe_net_control;
mod rxe_net_tx;
mod rxe_network;
mod rxe_ns;
mod rxe_objects;
#[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
mod rxe_odp;
mod rxe_opcode;
mod rxe_packet;
mod rxe_param;
mod rxe_pd;
mod rxe_port;
mod rxe_post;
mod rxe_qp;
mod rxe_qp_config;
mod rxe_queue;
mod rxe_recv;
mod rxe_recv_check;
mod rxe_register;
mod rxe_replay;
mod rxe_req;
mod rxe_req_state;
mod rxe_resp;
mod rxe_resp_check;
mod rxe_resp_data;
mod rxe_resp_memory;
mod rxe_resp_state;
mod rxe_ring;
mod rxe_route;
mod rxe_send;
mod rxe_srq;
mod rxe_submission;
mod rxe_task;
mod rxe_task_ffi;
mod rxe_tunnel;
mod rxe_types;
mod rxe_uapi;
mod rxe_version;
mod rxe_wire;
mod rxe_wqe;

module! {
    type: rxe_device::RxeModule,
    name: "rdma_rxe",
    authors: ["Leon Romanovsky"],
    description: "Soft RoCEv2 transport (RXE)",
    license: "Dual BSD/GPL",
    alias: ["rdma-link-rxe"],
    initcall: "late",
}
