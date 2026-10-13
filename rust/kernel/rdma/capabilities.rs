// SPDX-License-Identifier: GPL-2.0

//! Native RDMA device capabilities and query results.

use crate::bindings;

// Bindgen uses usize for the 64-bit unsigned-long enum and u64 for its 32-bit ABI.
#[allow(clippy::unnecessary_cast)]
const fn device_capability_bits(value: bindings::ib_device_cap_flags) -> u64 {
    value as u64
}

/// The scope in which atomic operations are supported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u32)]
pub enum AtomicCapability {
    /// Atomic operations are unsupported.
    #[default]
    None = bindings::ib_atomic_cap_IB_ATOMIC_NONE,
    /// Atomic operations are coherent within the adapter.
    Hca = bindings::ib_atomic_cap_IB_ATOMIC_HCA,
    /// Atomic operations are globally coherent.
    Global = bindings::ib_atomic_cap_IB_ATOMIC_GLOB,
}

crate::impl_flags!(
    /// Device capabilities exposed through userspace verbs.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct DeviceCapabilities(u64);

    /// One capability in [`DeviceCapabilities`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DeviceCapability {
        /// Resize work-request capacity.
        ResizeMaxWr = device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_RESIZE_MAX_WR),
        /// Report partition-key violations.
        BadPkeyCounter =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_BAD_PKEY_CNTR),
        /// Report datagram-key violations.
        BadQkeyCounter =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_BAD_QKEY_CNTR),
        /// Support raw multicast.
        RawMulticast = device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_RAW_MULTI),
        /// Support automatic path migration.
        AutoPathMigration =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_AUTO_PATH_MIG),
        /// Change the physical port of a queue pair.
        ChangePhysicalPort =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_CHANGE_PHY_PORT),
        /// Enforce the address-handle port for UD traffic.
        UdAvPortEnforcement =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_UD_AV_PORT_ENFORCE),
        /// Validate the current QP state during modification.
        CurrentQpStateModification =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_CURR_QP_STATE_MOD),
        /// Shut down a port.
        ShutdownPort =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_SHUTDOWN_PORT),
        /// Deliver port-active events.
        PortActiveEvent =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_PORT_ACTIVE_EVENT),
        /// Report a system-image GUID.
        SystemImageGuid =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_SYS_IMAGE_GUID),
        /// Generate receiver-not-ready NAKs for RC traffic.
        RcRnrNakGeneration =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_RC_RNR_NAK_GEN),
        /// Resize shared receive queues.
        SrqResize = device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_SRQ_RESIZE),
        /// Request notification after a completion count.
        NNotifyCq = device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_N_NOTIFY_CQ),
        /// Support memory windows.
        MemoryWindow = device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_MEM_WINDOW),
        /// Support UD IP checksums.
        UdIpChecksum = device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_UD_IP_CSUM),
        /// Support extended reliable connections.
        Xrc = device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_XRC),
        /// Support fast registration and invalidation.
        MemoryManagementExtensions =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_MEM_MGT_EXTENSIONS),
        /// Support type 2A memory windows.
        MemoryWindowType2A =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_MEM_WINDOW_TYPE_2A),
        /// Support type 2B memory windows.
        MemoryWindowType2B =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_MEM_WINDOW_TYPE_2B),
        /// Support RC IP checksums.
        RcIpChecksum = device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_RC_IP_CSUM),
        /// Legacy raw-packet IP checksum capability.
        RawIpChecksum = device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_RAW_IP_CSUM),
        /// Support managed flow steering.
        ManagedFlowSteering =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_MANAGED_FLOW_STEERING),
        /// Legacy raw-packet FCS scattering capability.
        RawScatterFcs =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_RAW_SCATTER_FCS),
        /// Pad incoming writes to a cache-line boundary.
        PciWriteEndPadding =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_PCI_WRITE_END_PADDING),
        /// Flush to global visibility.
        FlushGlobal = device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_FLUSH_GLOBAL),
        /// Flush to persistent storage.
        FlushPersistent =
            device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_FLUSH_PERSISTENT),
        /// Support atomic writes.
        AtomicWrite = device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_ATOMIC_WRITE),
        /// Use DMA bounce buffers for confidential computing.
        CcDmaBounce = device_capability_bits(bindings::ib_device_cap_flags_IB_DEVICE_CC_DMA_BOUNCE),
    }
);

crate::impl_flags!(
    /// Device capabilities used by kernel RDMA clients.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct KernelCapabilities(u64);

    /// One capability in [`KernelCapabilities`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum KernelCapability {
        /// Provide a local DMA key.
        LocalDmaLkey = bindings::ib_kernel_cap_flags_IBK_LOCAL_DMA_LKEY as u64,
        /// Support integrity-enabled queue pairs.
        IntegrityHandover = bindings::ib_kernel_cap_flags_IBK_INTEGRITY_HANDOVER as u64,
        /// Support on-demand user memory registration.
        OnDemandPaging = bindings::ib_kernel_cap_flags_IBK_ON_DEMAND_PAGING as u64,
        /// Support scatter/gather registrations with gaps.
        SgGapsRegistration = bindings::ib_kernel_cap_flags_IBK_SG_GAPS_REG as u64,
        /// Allow userspace to remove this device.
        AllowUserUnregister = bindings::ib_kernel_cap_flags_IBK_ALLOW_USER_UNREG as u64,
        /// Support disabling multicast loopback.
        BlockMulticastLoopback = bindings::ib_kernel_cap_flags_IBK_BLOCK_MULTICAST_LOOPBACK as u64,
        /// Support UD TCP segmentation offload.
        UdTso = bindings::ib_kernel_cap_flags_IBK_UD_TSO as u64,
        /// Provide virtual-function management operations.
        VirtualFunction = bindings::ib_kernel_cap_flags_IBK_VIRTUAL_FUNCTION as u64,
        /// Support Omni-Path RDMA network devices.
        RdmaNetdevOpa = bindings::ib_kernel_cap_flags_IBK_RDMA_NETDEV_OPA as u64,
    }
);

crate::impl_flags!(
    /// General on-demand paging capabilities.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct OdpSupportFlags(u64);

    /// One capability in [`OdpSupportFlags`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum OdpSupport {
        /// Support explicit on-demand memory registration.
        Supported = bindings::ib_odp_general_cap_bits_IB_ODP_SUPPORT as u64,
        /// Support implicit on-demand memory registration.
        Implicit = bindings::ib_odp_general_cap_bits_IB_ODP_SUPPORT_IMPLICIT as u64,
    }
);

crate::impl_flags!(
    /// On-demand operations supported by a transport.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct OdpTransportFlags(u32);

    /// One capability in [`OdpTransportFlags`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum OdpTransportCapability {
        /// Support sends.
        Send = bindings::ib_odp_transport_cap_bits_IB_ODP_SUPPORT_SEND,
        /// Support receives.
        Receive = bindings::ib_odp_transport_cap_bits_IB_ODP_SUPPORT_RECV,
        /// Support RDMA writes.
        Write = bindings::ib_odp_transport_cap_bits_IB_ODP_SUPPORT_WRITE,
        /// Support RDMA reads.
        Read = bindings::ib_odp_transport_cap_bits_IB_ODP_SUPPORT_READ,
        /// Support atomic operations.
        Atomic = bindings::ib_odp_transport_cap_bits_IB_ODP_SUPPORT_ATOMIC,
        /// Support shared receive queues.
        SrqReceive = bindings::ib_odp_transport_cap_bits_IB_ODP_SUPPORT_SRQ_RECV,
        /// Support flush operations.
        Flush = bindings::ib_odp_transport_cap_bits_IB_ODP_SUPPORT_FLUSH,
        /// Support atomic writes.
        AtomicWrite = bindings::ib_odp_transport_cap_bits_IB_ODP_SUPPORT_ATOMIC_WRITE,
    }
);

/// On-demand paging support for each transport.
#[derive(Clone, Copy, Debug, Default)]
pub struct OdpCapabilities {
    /// General registration capabilities.
    pub general: OdpSupportFlags,
    /// Reliable connected transport.
    pub rc: OdpTransportFlags,
    /// Unreliable connected transport.
    pub uc: OdpTransportFlags,
    /// Unreliable datagram transport.
    pub ud: OdpTransportFlags,
    /// Extended reliable connected transport.
    pub xrc: OdpTransportFlags,
}

/// Receive-side scaling limits.
#[derive(Clone, Copy, Debug, Default)]
pub struct RssCapabilities {
    /// Bit mask indexed by the core QP type encoding.
    pub supported_qpts: u32,
    /// Maximum number of receive indirection tables.
    pub max_rwq_indirection_tables: u32,
    /// Maximum entries in one receive indirection table.
    pub max_rwq_indirection_table_size: u32,
}

/// Tag-matching offload capabilities.
#[derive(Clone, Copy, Debug, Default)]
pub struct TagMatchingCapabilities {
    /// Maximum rendezvous header size.
    pub max_rndv_hdr_size: u32,
    /// Maximum entries in a tag-matching list.
    pub max_num_tags: u32,
    /// Support rendezvous offload for RC transport.
    pub rendezvous_rc: bool,
    /// Maximum outstanding list operations.
    pub max_ops: u32,
    /// Maximum scatter/gather entries in a tag-matching entry.
    pub max_sge: u32,
}

/// Completion queue moderation limits.
#[derive(Clone, Copy, Debug, Default)]
pub struct CqCapabilities {
    /// Maximum completion moderation count.
    pub max_cq_moderation_count: u16,
    /// Maximum completion moderation period in microseconds.
    pub max_cq_moderation_period: u16,
}

/// A copied device query result, independent of the core output buffer.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceAttributes {
    /// Firmware version.
    pub fw_ver: u64,
    /// System-image GUID in host byte order.
    pub sys_image_guid: u64,
    /// Maximum memory region size in bytes.
    pub max_mr_size: u64,
    /// Bit mask of supported page sizes.
    pub page_size_cap: u64,
    /// Vendor identifier.
    pub vendor_id: u32,
    /// Vendor part identifier.
    pub vendor_part_id: u32,
    /// Hardware version.
    pub hw_ver: u32,
    /// Maximum queue pairs.
    pub max_qp: u32,
    /// Maximum work requests in a queue pair.
    pub max_qp_wr: u32,
    /// Userspace-visible capabilities.
    pub device_cap_flags: DeviceCapabilities,
    /// Kernel-client capabilities.
    pub kernel_cap_flags: KernelCapabilities,
    /// Maximum scatter/gather entries in a send request.
    pub max_send_sge: u32,
    /// Maximum scatter/gather entries in a receive request.
    pub max_recv_sge: u32,
    /// Maximum scatter/gather entries in an RDMA read.
    pub max_sge_rd: u32,
    /// Maximum completion queues.
    pub max_cq: u32,
    /// Maximum entries in a completion queue.
    pub max_cqe: u32,
    /// Maximum memory regions.
    pub max_mr: u32,
    /// Maximum protection domains.
    pub max_pd: u32,
    /// Maximum outstanding read/atomic responses per QP.
    pub max_qp_rd_atom: u32,
    /// Maximum outstanding read/atomic responses per EE context.
    pub max_ee_rd_atom: u32,
    /// Maximum outstanding read/atomic responses on the device.
    pub max_res_rd_atom: u32,
    /// Maximum outstanding read/atomic requests per QP.
    pub max_qp_init_rd_atom: u32,
    /// Maximum outstanding read/atomic requests per EE context.
    pub max_ee_init_rd_atom: u32,
    /// Atomic operation scope.
    pub atomic_cap: AtomicCapability,
    /// Masked atomic operation scope.
    pub masked_atomic_cap: AtomicCapability,
    /// Maximum end-to-end contexts.
    pub max_ee: u32,
    /// Maximum reliable datagram domains.
    pub max_rdd: u32,
    /// Maximum memory windows.
    pub max_mw: u32,
    /// Maximum raw IPv6 queue pairs.
    pub max_raw_ipv6_qp: u32,
    /// Maximum raw EtherType queue pairs.
    pub max_raw_ethy_qp: u32,
    /// Maximum multicast groups.
    pub max_mcast_grp: u32,
    /// Maximum QP attachments per multicast group.
    pub max_mcast_qp_attach: u32,
    /// Maximum multicast QP attachments on the device.
    pub max_total_mcast_qp_attach: u32,
    /// Maximum address handles.
    pub max_ah: u32,
    /// Maximum shared receive queues.
    pub max_srq: u32,
    /// Maximum work requests in a shared receive queue.
    pub max_srq_wr: u32,
    /// Maximum scatter/gather entries in an SRQ receive request.
    pub max_srq_sge: u32,
    /// Maximum pages in a fast registration.
    pub max_fast_reg_page_list_len: u32,
    /// Maximum pages in a protection-information fast registration.
    pub max_pi_fast_reg_page_list_len: u32,
    /// Maximum partition keys.
    pub max_pkeys: u16,
    /// Local acknowledgment delay encoding.
    pub local_ca_ack_delay: u8,
    /// Supported signature protection types in the core encoding.
    pub sig_prot_cap: i32,
    /// Supported signature guard types in the core encoding.
    pub sig_guard_cap: i32,
    /// On-demand paging support.
    pub odp_caps: OdpCapabilities,
    /// Valid completion timestamp bits.
    pub timestamp_mask: u64,
    /// Adapter core clock in kHz.
    pub hca_core_clock: u64,
    /// Receive-side scaling support.
    pub rss_caps: RssCapabilities,
    /// Maximum standalone receive work queues.
    pub max_wq_type_rq: u32,
    /// Raw-packet capabilities in the core encoding.
    pub raw_packet_caps: u32,
    /// Tag-matching support.
    pub tm_caps: TagMatchingCapabilities,
    /// Completion moderation support.
    pub cq_caps: CqCapabilities,
    /// Maximum device memory size in bytes.
    pub max_dm_size: u64,
    /// Maximum scatter/gather entries for optimized RDMA read performance.
    pub max_sgl_rd: u32,
}

impl DeviceAttributes {
    pub(super) fn into_raw(self) -> bindings::ib_device_attr {
        let mut attr = bindings::ib_device_attr {
            fw_ver: self.fw_ver,
            sys_image_guid: self.sys_image_guid.to_be(),
            max_mr_size: self.max_mr_size,
            page_size_cap: self.page_size_cap,
            vendor_id: self.vendor_id,
            vendor_part_id: self.vendor_part_id,
            hw_ver: self.hw_ver,
            max_qp: self.max_qp,
            max_qp_wr: self.max_qp_wr,
            device_cap_flags: self.device_cap_flags.into(),
            kernel_cap_flags: self.kernel_cap_flags.into(),
            max_send_sge: self.max_send_sge,
            max_recv_sge: self.max_recv_sge,
            max_sge_rd: self.max_sge_rd,
            max_cq: self.max_cq,
            max_cqe: self.max_cqe,
            max_mr: self.max_mr,
            max_pd: self.max_pd,
            max_qp_rd_atom: self.max_qp_rd_atom,
            max_ee_rd_atom: self.max_ee_rd_atom,
            max_res_rd_atom: self.max_res_rd_atom,
            max_qp_init_rd_atom: self.max_qp_init_rd_atom,
            max_ee_init_rd_atom: self.max_ee_init_rd_atom,
            atomic_cap: self.atomic_cap as bindings::ib_atomic_cap,
            masked_atomic_cap: self.masked_atomic_cap as bindings::ib_atomic_cap,
            max_ee: self.max_ee,
            max_rdd: self.max_rdd,
            max_mw: self.max_mw,
            max_raw_ipv6_qp: self.max_raw_ipv6_qp,
            max_raw_ethy_qp: self.max_raw_ethy_qp,
            max_mcast_grp: self.max_mcast_grp,
            max_mcast_qp_attach: self.max_mcast_qp_attach,
            max_total_mcast_qp_attach: self.max_total_mcast_qp_attach,
            max_ah: self.max_ah,
            max_srq: self.max_srq,
            max_srq_wr: self.max_srq_wr,
            max_srq_sge: self.max_srq_sge,
            max_fast_reg_page_list_len: self.max_fast_reg_page_list_len,
            max_pi_fast_reg_page_list_len: self.max_pi_fast_reg_page_list_len,
            max_pkeys: self.max_pkeys,
            local_ca_ack_delay: self.local_ca_ack_delay,
            sig_prot_cap: self.sig_prot_cap,
            sig_guard_cap: self.sig_guard_cap,
            timestamp_mask: self.timestamp_mask,
            hca_core_clock: self.hca_core_clock,
            max_wq_type_rq: self.max_wq_type_rq,
            raw_packet_caps: self.raw_packet_caps,
            max_dm_size: self.max_dm_size,
            max_sgl_rd: self.max_sgl_rd,
            rss_caps: bindings::ib_rss_caps {
                supported_qpts: self.rss_caps.supported_qpts,
                max_rwq_indirection_tables: self.rss_caps.max_rwq_indirection_tables,
                max_rwq_indirection_table_size: self.rss_caps.max_rwq_indirection_table_size,
            },
            tm_caps: bindings::ib_tm_caps {
                max_rndv_hdr_size: self.tm_caps.max_rndv_hdr_size,
                max_num_tags: self.tm_caps.max_num_tags,
                flags: if self.tm_caps.rendezvous_rc {
                    bindings::ib_tm_cap_flags_IB_TM_CAP_RNDV_RC
                } else {
                    0
                },
                max_ops: self.tm_caps.max_ops,
                max_sge: self.tm_caps.max_sge,
            },
            cq_caps: bindings::ib_cq_caps {
                max_cq_moderation_count: self.cq_caps.max_cq_moderation_count,
                max_cq_moderation_period: self.cq_caps.max_cq_moderation_period,
            },
            ..Default::default()
        };
        attr.odp_caps.general_caps = self.odp_caps.general.into();
        attr.odp_caps.per_transport_caps.rc_odp_caps = self.odp_caps.rc.into();
        attr.odp_caps.per_transport_caps.uc_odp_caps = self.odp_caps.uc.into();
        attr.odp_caps.per_transport_caps.ud_odp_caps = self.odp_caps.ud.into();
        attr.odp_caps.per_transport_caps.xrc_odp_caps = self.odp_caps.xrc.into();
        attr
    }
}
