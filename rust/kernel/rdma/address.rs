// SPDX-License-Identifier: GPL-2.0

//! Owned address attributes at the RDMA provider boundary.

use crate::{
    bindings,
    prelude::*, //
};
use core::ptr;

/// Global-route fields, with GIDs represented in network byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalRoute {
    /// Destination GID.
    pub dgid: [u8; 16],
    /// IPv6 flow label in host byte order.
    pub flow_label: u32,
    /// Source GID table index.
    pub sgid_index: u8,
    /// Hop limit.
    pub hop_limit: u8,
    /// Traffic class.
    pub traffic_class: u8,
}

/// Link-specific address fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    /// Native InfiniBand routing.
    InfiniBand {
        /// Destination local identifier.
        dlid: u16,
        /// Source path bits.
        source_path_bits: u8,
    },
    /// RoCE Ethernet routing.
    Roce {
        /// Destination Ethernet address.
        destination_mac: [u8; 6],
    },
    /// Omni-Path routing.
    Opa {
        /// Destination local identifier.
        dlid: u32,
        /// Source path bits.
        source_path_bits: u8,
        /// Request a global route header.
        make_grd: bool,
    },
}

/// Address metadata without core-owned GID pointers or a C union.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressAttributes {
    /// Link-specific address.
    pub kind: AddressKind,
    /// Port number.
    pub port: u32,
    /// Service level.
    pub service_level: u8,
    /// Encoded static rate.
    pub static_rate: u8,
    /// Global route, when requested.
    pub route: Option<GlobalRoute>,
}

impl AddressAttributes {
    /// Copies initialized address fields without retaining any core pointer.
    ///
    /// # Safety
    ///
    /// `attr` must remain readable and unchanged for the call. Common fields and the union
    /// member selected by its type must be initialized, as must the global route when enabled.
    pub unsafe fn from_raw(attr: *const bindings::rdma_ah_attr) -> Result<Self> {
        // SAFETY: The caller supplies stable fields; only the selected union member and
        // enabled global route are read. Unknown types are rejected without reading the union.
        unsafe {
            let kind = match (*attr).type_ {
                bindings::rdma_ah_attr_type_RDMA_AH_ATTR_TYPE_IB => {
                    let ib = (*attr).__bindgen_anon_1.ib;
                    AddressKind::InfiniBand {
                        dlid: ib.dlid,
                        source_path_bits: ib.src_path_bits,
                    }
                }
                bindings::rdma_ah_attr_type_RDMA_AH_ATTR_TYPE_ROCE => AddressKind::Roce {
                    destination_mac: (*attr).__bindgen_anon_1.roce.dmac,
                },
                bindings::rdma_ah_attr_type_RDMA_AH_ATTR_TYPE_OPA => {
                    let opa = (*attr).__bindgen_anon_1.opa;
                    AddressKind::Opa {
                        dlid: opa.dlid,
                        source_path_bits: opa.src_path_bits,
                        make_grd: opa.make_grd,
                    }
                }
                _ => return Err(EINVAL),
            };
            let route = if (*attr).ah_flags & bindings::ib_ah_flags_IB_AH_GRH as u8 != 0 {
                Some(GlobalRoute {
                    dgid: (*attr).grh.dgid.raw,
                    flow_label: (*attr).grh.flow_label,
                    sgid_index: (*attr).grh.sgid_index,
                    hop_limit: (*attr).grh.hop_limit,
                    traffic_class: (*attr).grh.traffic_class,
                })
            } else {
                None
            };
            Ok(Self {
                kind,
                route,
                port: (*attr).port_num,
                service_level: (*attr).sl,
                static_rate: (*attr).static_rate,
            })
        }
    }

    #[inline]
    pub(super) fn kind_raw(&self) -> bindings::rdma_ah_attr_type {
        match self.kind {
            AddressKind::InfiniBand { .. } => bindings::rdma_ah_attr_type_RDMA_AH_ATTR_TYPE_IB,
            AddressKind::Roce { .. } => bindings::rdma_ah_attr_type_RDMA_AH_ATTR_TYPE_ROCE,
            AddressKind::Opa { .. } => bindings::rdma_ah_attr_type_RDMA_AH_ATTR_TYPE_OPA,
        }
    }

    pub(super) fn to_raw(self) -> bindings::rdma_ah_attr {
        // SAFETY: Zero initializes scalar fields, padding and the absent GID pointer. The
        // selected union member and type are set below before the value is returned.
        let mut attr: bindings::rdma_ah_attr = unsafe { core::mem::zeroed() };
        attr.type_ = self.kind_raw();
        attr.port_num = self.port;
        attr.sl = self.service_level;
        attr.static_rate = self.static_rate;
        match self.kind {
            AddressKind::InfiniBand {
                dlid,
                source_path_bits,
            } => {
                attr.__bindgen_anon_1.ib = bindings::ib_ah_attr {
                    dlid,
                    src_path_bits: source_path_bits,
                };
            }
            AddressKind::Roce { destination_mac } => {
                attr.__bindgen_anon_1.roce = bindings::roce_ah_attr {
                    dmac: destination_mac,
                };
            }
            AddressKind::Opa {
                dlid,
                source_path_bits,
                make_grd,
            } => {
                attr.__bindgen_anon_1.opa = bindings::opa_ah_attr {
                    dlid,
                    src_path_bits: source_path_bits,
                    make_grd,
                };
            }
        }
        if let Some(route) = self.route {
            attr.ah_flags = bindings::ib_ah_flags_IB_AH_GRH as u8;
            attr.grh = bindings::ib_global_route {
                sgid_attr: ptr::null(),
                dgid: bindings::ib_gid { raw: route.dgid },
                flow_label: route.flow_label,
                sgid_index: route.sgid_index,
                hop_limit: route.hop_limit,
                traffic_class: route.traffic_class,
            };
        }
        attr
    }
}

/// Network protocol selected by a source GID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkType {
    /// Native InfiniBand.
    InfiniBand,
    /// RoCE over Ethernet without UDP encapsulation.
    RoceV1,
    /// RoCE over IPv4 and UDP.
    Ipv4,
    /// RoCE over IPv6 and UDP.
    Ipv6,
}

/// Immutable source information copied while the core retains its GID reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceGid {
    /// GID bytes in network byte order.
    pub gid: [u8; 16],
    /// Network protocol.
    pub network: NetworkType,
    /// Port and table index of the retained source entry.
    pub port: u32,
    /// Source entry's table index, even if it has since been invalidated.
    pub index: u16,
    /// Selected Ethernet source metadata; absent for native InfiniBand.
    pub ethernet: Option<([u8; 6], u16)>,
}

/// Creation or modification attributes with a snapshot of the selected source GID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRequest {
    /// Requested address attributes.
    pub attributes: AddressAttributes,
    /// Source GID, present when a global route is requested.
    pub source: Option<SourceGid>,
}

impl AddressRequest {
    /// Copies core-validated address attributes and their retained source GID.
    ///
    /// # Safety
    ///
    /// The requirements of [`AddressAttributes::from_raw`] apply. When a global route is
    /// enabled, its non-null source attribute must remain initialized and retained throughout
    /// this call. A missing source attribute is rejected.
    #[inline]
    pub unsafe fn from_raw(attr: *const bindings::rdma_ah_attr) -> Result<Self> {
        // SAFETY: The caller retains stable attributes, including their source GID reference.
        unsafe {
            let attributes = AddressAttributes::from_raw(attr)?;
            let source = if attributes.route.is_some() {
                let source = (*attr).grh.sgid_attr;
                if source.is_null() {
                    return Err(EINVAL);
                }
                let network = match bindings::rdma_gid_attr_network_type(source) {
                    bindings::rdma_network_type_RDMA_NETWORK_IB => NetworkType::InfiniBand,
                    bindings::rdma_network_type_RDMA_NETWORK_ROCE_V1 => NetworkType::RoceV1,
                    bindings::rdma_network_type_RDMA_NETWORK_IPV4 => NetworkType::Ipv4,
                    bindings::rdma_network_type_RDMA_NETWORK_IPV6 => NetworkType::Ipv6,
                    _ => return Err(EINVAL),
                };
                let ethernet = if network == NetworkType::InfiniBand {
                    None
                } else {
                    let mut mac = [0; 6];
                    let mut vlan = 0;
                    crate::error::to_result(bindings::rdma_read_gid_l2_fields(
                        source,
                        &mut vlan,
                        mac.as_mut_ptr(),
                    ))?;
                    Some((mac, vlan))
                };
                Some(SourceGid {
                    gid: (*source).gid.raw,
                    network,
                    port: (*source).port_num,
                    index: (*source).index,
                    ethernet,
                })
            } else {
                None
            };
            Ok(Self { attributes, source })
        }
    }
}
