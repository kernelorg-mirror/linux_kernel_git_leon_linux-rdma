// SPDX-License-Identifier: GPL-2.0

//! Owned IP routes with namespace and interface identity.

#[cfg(CONFIG_NET_UDP_TUNNEL)]
use super::DeviceLocation;
use super::{
    namespace::NamespaceRef,
    Device,
    DeviceRef, //
};
#[cfg(CONFIG_NET_UDP_TUNNEL)]
use crate::prelude::*;
use crate::{
    bindings,
    sync::rcu, //
};
use core::ptr::NonNull;

/// Source and destination IP addresses in network byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressPair {
    /// An IPv4 path.
    V4 {
        /// Source address.
        source: [u8; 4],
        /// Destination address.
        destination: [u8; 4],
    },
    /// An IPv6 path.
    V6 {
        /// Source address.
        source: [u8; 16],
        /// Destination address.
        destination: [u8; 16],
    },
}

/// UDP policy-routing selectors, in addition to the output interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpFlow {
    /// Source and destination IP addresses.
    pub addresses: AddressPair,
    /// IPv4 TOS or IPv6 traffic class, including ECN bits.
    pub traffic_class: u8,
    /// UDP source port in host byte order.
    pub source_port: u16,
    /// UDP destination port in host byte order.
    pub destination_port: u16,
}

/// A native destination reference and an active namespace for one transmission.
///
/// Native IPv6 destinations can depend on namespace resources until their final release.
/// Keep routes only during transmission: storing one in namespace-owned idle state can
/// prevent the namespace cleanup which would release that state.
///
/// # Invariants
///
/// `destination` owns one reference returned by an IP route lookup in `namespace` for the
/// retained `device` and `flow`. Its family matches the address pair, and `cookie` records
/// the IPv6 generation when applicable. Namespace services remain live through Drop.
pub struct Route {
    destination: NonNull<bindings::dst_entry>,
    namespace: NamespaceRef,
    device: DeviceRef,
    index: core::ffi::c_int,
    flow: UdpFlow,
    cookie: u32,
}

// SAFETY: Native destination, device and active namespace references may move between tasks.
// No method exposes ordinary references to fields changed by the networking core.
unsafe impl Send for Route {}
// SAFETY: Shared access only uses core-synchronized validation and reference operations.
unsafe impl Sync for Route {}

impl Route {
    /// Finds a UDP route in the registered device's sampled namespace and interface.
    ///
    /// The socket must have the same family and namespace as the path. A retained tunnel
    /// socket remains suitable for lookup after its receive port closes: lookup only uses
    /// allocation-resident preferences and the core's synchronized policy lookup.
    /// A stale device location returns `ENODEV`. An RCU membership check keeps its namespace
    /// and index association stable throughout lookup without acquiring RTNL.
    /// An unspecified IPv6 source is selected first, then used for the policy lookup.
    #[cfg(CONFIG_NET_UDP_TUNNEL)]
    pub fn lookup_udp(
        location: &DeviceLocation,
        socket: &super::udp_tunnel::SocketRef,
        mut selectors: UdpFlow,
    ) -> Result<Self> {
        use super::socket::Family;
        use crate::error::from_err_ptr;

        let namespace = location.namespace();
        if socket.namespace().as_raw() != namespace.as_raw() {
            return Err(ENODEV);
        }
        if !matches!(
            (selectors.addresses, socket.family()),
            (AddressPair::V4 { .. }, Family::Ipv4) | (AddressPair::V6 { .. }, Family::Ipv6)
        ) {
            return Err(EAFNOSUPPORT);
        }
        // This guard also retains output devices sampled beyond nested native RCU guards.
        let _rcu = location.read_lock()?;
        // SAFETY: RCU stabilizes the validated namespace membership and retains devices
        // sampled by the route and XFRM helpers. The snapshot retains an active namespace. The
        // socket retains its initialized allocation, with matching immutable namespace/family.
        // Each flow is fully initialized, and successful lookup transfers a destination ref.
        let (destination, cookie, addresses) = unsafe {
            match selectors.addresses {
                AddressPair::V4 {
                    source,
                    destination,
                } => {
                    let mut flow = bindings::flowi4::default();
                    flow.__fl_common.flowic_oif = location.index();
                    flow.__fl_common.flowic_proto = bindings::IPPROTO_UDP as u8;
                    flow.__fl_common.flowic_dscp = selectors.traffic_class & 0xfc;
                    flow.uli.ports.sport = selectors.source_port.to_be();
                    flow.uli.ports.dport = selectors.destination_port.to_be();
                    flow.saddr = u32::from_ne_bytes(source);
                    flow.daddr = u32::from_ne_bytes(destination);
                    bindings::sock_flow_init(socket.as_raw(), &mut flow.__fl_common);
                    let table = from_err_ptr(bindings::ip_route_output_flow(
                        namespace.as_raw(),
                        &mut flow,
                        socket.as_raw(),
                    ))?;
                    (
                        &raw mut (*table).dst,
                        0,
                        AddressPair::V4 {
                            source: flow.saddr.to_ne_bytes(),
                            destination: flow.daddr.to_ne_bytes(),
                        },
                    )
                }
                #[cfg(CONFIG_IPV6)]
                AddressPair::V6 {
                    source,
                    destination,
                } => {
                    let mut flow = bindings::flowi6::default();
                    flow.__fl_common.flowic_oif = location.index();
                    flow.__fl_common.flowic_proto = bindings::IPPROTO_UDP as u8;
                    flow.flowlabel = (u32::from(selectors.traffic_class) << 20).to_be();
                    flow.uli.ports.sport = selectors.source_port.to_be();
                    flow.uli.ports.dport = selectors.destination_port.to_be();
                    flow.saddr = bindings::in6_addr {
                        in6_u: bindings::in6_addr__bindgen_ty_1 { u6_addr8: source },
                    };
                    flow.daddr = bindings::in6_addr {
                        in6_u: bindings::in6_addr__bindgen_ty_1 {
                            u6_addr8: destination,
                        },
                    };
                    bindings::sock_flow_init(socket.as_raw(), &mut flow.__fl_common);
                    if source == [0; 16] {
                        // Native source selection can retain a route which skipped source
                        // policy rules. Select the source before the final routing and XFRM
                        // policy lookup, which must use the selectors sent on wire.
                        let mut selected = core::ptr::null_mut();
                        crate::error::to_result(bindings::ip6_dst_lookup(
                            namespace.as_raw(),
                            socket.as_raw(),
                            &mut selected,
                            &mut flow,
                        ))?;
                        bindings::dst_release(selected);
                    }
                    let destination = from_err_ptr(bindings::ip6_dst_lookup_flow(
                        namespace.as_raw(),
                        socket.as_raw(),
                        &mut flow,
                        core::ptr::null(),
                    ))?;
                    // IPv6 routes, including XFRM destinations, begin with rt6_info storage.
                    // The owned reference retains it; rt6_get_cookie protects fib data by RCU.
                    let cookie = bindings::rt6_get_cookie(destination.cast());
                    (
                        destination,
                        cookie,
                        AddressPair::V6 {
                            source: flow.saddr.in6_u.u6_addr8,
                            destination: flow.daddr.in6_u.u6_addr8,
                        },
                    )
                }
                #[cfg(not(CONFIG_IPV6))]
                AddressPair::V6 { .. } => return Err(EAFNOSUPPORT),
            }
        };
        // INVARIANT: Lookup transferred a non-null destination reference for these inputs.
        // SAFETY: Successful IP lookup returns a destination, never a null pointer.
        let destination = unsafe { NonNull::new_unchecked(destination) };
        selectors.addresses = addresses;
        Ok(Self {
            destination,
            namespace: namespace.clone(),
            device: location.device().to_ref(),
            index: location.index(),
            flow: selectors,
            cookie,
        })
    }

    /// Checks the originating device, all wire selectors and current destination validity.
    pub(super) fn matches(&self, device: &Device, flow: UdpFlow) -> bool {
        if self.device.as_raw() != device.as_raw() || self.flow != flow {
            return false;
        }
        let _rcu = rcu::read_lock();
        // SAFETY: The destination and its active namespace are retained. RCU additionally
        // retains devices/fib entries sampled by check callbacks, which do not consume it.
        unsafe {
            bindings::dev_get_by_index_rcu(self.namespace.as_raw(), self.index)
                == self.device.as_raw()
                && !bindings::dst_check(self.as_raw(), self.cookie).is_null()
        }
    }

    /// Returns the originating interface index in the retained namespace.
    #[inline]
    pub(super) fn index(&self) -> core::ffi::c_int {
        self.index
    }

    /// Returns the routing generation captured with this destination.
    #[inline]
    pub(super) fn cookie(&self) -> u32 {
        self.cookie
    }

    /// Returns the selected flow, including source and destination addresses resolved by IP.
    #[inline]
    pub fn flow(&self) -> UdpFlow {
        self.flow
    }

    /// Borrows the active namespace retained until the destination is released.
    #[inline]
    pub fn namespace(&self) -> &NamespaceRef {
        &self.namespace
    }

    /// Returns the destination pointer without transferring its reference.
    ///
    /// C callers must retain this owner or acquire another destination reference, and must
    /// not mutate fields directly. Packet output additionally requires the matching namespace.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::dst_entry {
        self.destination.as_ptr()
    }
}

impl Clone for Route {
    #[inline]
    fn clone(&self) -> Self {
        // SAFETY: The current owner retains a nonzero destination reference during acquisition.
        unsafe { bindings::dst_hold(self.as_raw()) };
        // INVARIANT: The new handle owns the additional reference and the same path identity.
        Self {
            destination: self.destination,
            namespace: self.namespace.clone(),
            device: self.device.clone(),
            index: self.index,
            flow: self.flow,
            cookie: self.cookie,
        }
    }
}

impl Drop for Route {
    fn drop(&mut self) {
        // SAFETY: Release exactly this owned reference before releasing the active
        // namespace reference.
        unsafe { bindings::dst_release(self.as_raw()) };
    }
}
