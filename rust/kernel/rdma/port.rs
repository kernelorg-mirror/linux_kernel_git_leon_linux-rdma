// SPDX-License-Identifier: GPL-2.0

//! Native RDMA port query and modification values.

use crate::bindings;

/// An InfiniBand payload MTU.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u32)]
pub enum Mtu {
    /// 256 bytes.
    #[default]
    Mtu256 = bindings::ib_mtu_IB_MTU_256,
    /// 512 bytes.
    Mtu512 = bindings::ib_mtu_IB_MTU_512,
    /// 1024 bytes.
    Mtu1024 = bindings::ib_mtu_IB_MTU_1024,
    /// 2048 bytes.
    Mtu2048 = bindings::ib_mtu_IB_MTU_2048,
    /// 4096 bytes.
    Mtu4096 = bindings::ib_mtu_IB_MTU_4096,
}

impl Mtu {
    /// Returns the payload size in bytes.
    #[inline]
    pub const fn bytes(self) -> u32 {
        128 << self as u32
    }

    /// Returns the InfiniBand MTU encoding.
    #[inline]
    pub const fn encoding(self) -> u32 {
        self as u32
    }
}

/// The logical state of a port.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u32)]
pub enum PortState {
    /// No state transition is requested.
    Nop = bindings::ib_port_state_IB_PORT_NOP,
    /// Link is down.
    #[default]
    Down = bindings::ib_port_state_IB_PORT_DOWN,
    /// Link initialization is complete.
    Init = bindings::ib_port_state_IB_PORT_INIT,
    /// Ready to become active.
    Armed = bindings::ib_port_state_IB_PORT_ARMED,
    /// Link is active.
    Active = bindings::ib_port_state_IB_PORT_ACTIVE,
    /// Link activation is deferred.
    ActiveDefer = bindings::ib_port_state_IB_PORT_ACTIVE_DEFER,
}

/// The physical state of a port.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum PhysicalState {
    /// The physical layer is asleep.
    Sleep = bindings::ib_port_phys_state_IB_PORT_PHYS_STATE_SLEEP as u8,
    /// Polling for a link.
    #[default]
    Polling = bindings::ib_port_phys_state_IB_PORT_PHYS_STATE_POLLING as u8,
    /// Administratively disabled.
    Disabled = bindings::ib_port_phys_state_IB_PORT_PHYS_STATE_DISABLED as u8,
    /// Configuring and training the link.
    Training = bindings::ib_port_phys_state_IB_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING as u8,
    /// Link is up.
    LinkUp = bindings::ib_port_phys_state_IB_PORT_PHYS_STATE_LINK_UP as u8,
    /// Recovering from a link error.
    Recovery = bindings::ib_port_phys_state_IB_PORT_PHYS_STATE_LINK_ERROR_RECOVERY as u8,
    /// Physical-layer testing.
    Test = bindings::ib_port_phys_state_IB_PORT_PHYS_STATE_PHY_TEST as u8,
}

/// A copied port query result, independent of the core's output buffer.
#[derive(Clone, Copy, Default)]
pub struct PortAttributes {
    /// Subnet prefix.
    pub subnet_prefix: u64,
    /// Logical link state.
    pub state: PortState,
    /// Maximum supported payload MTU.
    pub max_mtu: Mtu,
    /// Current payload MTU.
    pub active_mtu: Mtu,
    /// Physical link MTU in bytes.
    pub phys_mtu: u32,
    /// Number of GID entries.
    pub gid_tbl_len: i32,
    /// Whether GIDs use IP addressing.
    pub ip_gids: bool,
    /// InfiniBand PortInfo CapabilityMask.
    pub port_cap_flags: u32,
    /// Maximum message size in bytes.
    pub max_msg_sz: u32,
    /// Partition-key violation count.
    pub bad_pkey_cntr: u32,
    /// Datagram-key violation count.
    pub qkey_viol_cntr: u32,
    /// Number of partition-key entries.
    pub pkey_tbl_len: u16,
    /// Subnet manager local identifier.
    pub sm_lid: u32,
    /// Port local identifier.
    pub lid: u32,
    /// Local identifier mask control.
    pub lmc: u8,
    /// Maximum virtual-lane encoding.
    pub max_vl_num: u8,
    /// Subnet manager service level.
    pub sm_sl: u8,
    /// Subnet timeout encoding.
    pub subnet_timeout: u8,
    /// Initialization type reply.
    pub init_type_reply: u8,
    /// Active width in the RDMA core encoding.
    pub active_width: u8,
    /// Active speed in the RDMA core encoding.
    pub active_speed: u16,
    /// Physical link state.
    pub phys_state: PhysicalState,
    /// Extended port capability mask.
    pub port_cap_flags2: u16,
}

impl PortAttributes {
    pub(super) fn into_raw(self) -> bindings::ib_port_attr {
        let mut attr = bindings::ib_port_attr {
            subnet_prefix: self.subnet_prefix,
            state: self.state as bindings::ib_port_state,
            max_mtu: self.max_mtu as bindings::ib_mtu,
            active_mtu: self.active_mtu as bindings::ib_mtu,
            phys_mtu: self.phys_mtu,
            gid_tbl_len: self.gid_tbl_len,
            port_cap_flags: self.port_cap_flags,
            max_msg_sz: self.max_msg_sz,
            bad_pkey_cntr: self.bad_pkey_cntr,
            qkey_viol_cntr: self.qkey_viol_cntr,
            pkey_tbl_len: self.pkey_tbl_len,
            sm_lid: self.sm_lid,
            lid: self.lid,
            lmc: self.lmc,
            max_vl_num: self.max_vl_num,
            sm_sl: self.sm_sl,
            subnet_timeout: self.subnet_timeout,
            init_type_reply: self.init_type_reply,
            active_width: self.active_width,
            active_speed: self.active_speed,
            phys_state: self.phys_state as u8,
            port_cap_flags2: self.port_cap_flags2,
            ..Default::default()
        };
        attr.set_ip_gids(self.ip_gids.into());
        attr
    }
}

crate::impl_flags!(
    /// Core services and protocols required by a port.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct PortCapabilities(u32);

    /// One port capability understood by the RDMA core.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PortCapability {
        /// InfiniBand management datagrams.
        IbMad = bindings::RDMA_CORE_CAP_IB_MAD,
        /// InfiniBand subnet management interface.
        IbSmi = bindings::RDMA_CORE_CAP_IB_SMI,
        /// InfiniBand connection management.
        IbCm = bindings::RDMA_CORE_CAP_IB_CM,
        /// iWARP connection management.
        IwCm = bindings::RDMA_CORE_CAP_IW_CM,
        /// InfiniBand subnet administration.
        IbSa = bindings::RDMA_CORE_CAP_IB_SA,
        /// Omni-Path management datagrams.
        OpaMad = bindings::RDMA_CORE_CAP_OPA_MAD,
        /// InfiniBand address family.
        IbAddress = bindings::RDMA_CORE_CAP_AF_IB,
        /// Ethernet address handles.
        EthernetAh = bindings::RDMA_CORE_CAP_ETH_AH,
        /// Omni-Path address handles.
        OpaAh = bindings::RDMA_CORE_CAP_OPA_AH,
        /// Global routing headers are required.
        GrhRequired = bindings::RDMA_CORE_CAP_IB_GRH_REQUIRED,
        /// Native InfiniBand transport.
        InfiniBand = bindings::RDMA_CORE_CAP_PROT_IB,
        /// RoCE over Ethernet.
        Roce = bindings::RDMA_CORE_CAP_PROT_ROCE,
        /// iWARP transport.
        Iwarp = bindings::RDMA_CORE_CAP_PROT_IWARP,
        /// RoCE over UDP.
        RoceUdp = bindings::RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP,
        /// Raw packet transport.
        RawPacket = bindings::RDMA_CORE_CAP_PROT_RAW_PACKET,
        /// USNIC transport.
        Usnic = bindings::RDMA_CORE_CAP_PROT_USNIC,
    }
);

/// Port properties established during registration and unchanged thereafter.
#[derive(Clone, Copy, Default)]
pub struct PortImmutable {
    /// Number of partition-key entries.
    pub pkey_tbl_len: i32,
    /// Number of GID entries.
    pub gid_tbl_len: i32,
    /// Required core services and supported transport protocols.
    pub capabilities: PortCapabilities,
    /// Maximum management datagram size in bytes.
    pub max_mad_size: u32,
}

impl PortImmutable {
    pub(super) fn into_raw(self) -> bindings::ib_port_immutable {
        bindings::ib_port_immutable {
            pkey_tbl_len: self.pkey_tbl_len,
            gid_tbl_len: self.gid_tbl_len,
            core_cap_flags: self.capabilities.into(),
            max_mad_size: self.max_mad_size,
        }
    }
}

crate::impl_flags!(
    /// Requested port modifications, retaining unknown extension bits.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct PortModifyFlags(u32);

    /// One requested port modification.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PortModify {
        /// Shut down the port.
        Shutdown = bindings::ib_port_modify_flags_IB_PORT_SHUTDOWN,
        /// Change initialization type.
        InitType = bindings::ib_port_modify_flags_IB_PORT_INIT_TYPE,
        /// Reset the datagram-key violation counter.
        ResetQkey = bindings::ib_port_modify_flags_IB_PORT_RESET_QKEY_CNTR,
        /// Change the Omni-Path capability mask.
        OpaMask = bindings::ib_port_modify_flags_IB_PORT_OPA_MASK_CHG,
    }
);

/// Copied input to a port modification callback.
#[derive(Clone, Copy)]
pub struct PortModification {
    /// Requested changes; providers must reject unsupported flags.
    pub flags: PortModifyFlags,
    /// Capability bits to set.
    pub set_capabilities: u32,
    /// Capability bits to clear.
    pub clear_capabilities: u32,
    /// Requested initialization type.
    pub init_type: u8,
}

impl PortModification {
    // The caller provides stable capability masks and an initialization type only when requested.
    /// # Safety
    ///
    /// The attribute pointer must be live and aligned, with stable capability masks and an
    /// initialized init_type when selected by flags.
    pub(super) unsafe fn from_raw(flags: u32, attr: *const bindings::ib_port_modify) -> Self {
        // SAFETY: Read only fields required by the core API for the supplied modification flags.
        // In particular, callers need not initialize init_type when they do not modify it.
        unsafe {
            Self {
                flags: PortModifyFlags(flags),
                set_capabilities: (*attr).set_port_cap_mask,
                clear_capabilities: (*attr).clr_port_cap_mask,
                init_type: if flags & bindings::ib_port_modify_flags_IB_PORT_INIT_TYPE != 0 {
                    (*attr).init_type
                } else {
                    0
                },
            }
        }
    }
}
