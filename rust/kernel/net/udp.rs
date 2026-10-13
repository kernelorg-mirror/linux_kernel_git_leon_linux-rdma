// SPDX-License-Identifier: GPL-2.0

//! Owned UDP encapsulation packets with immutable prepared network headers.

use super::{
    ip::{
        AddressPair,
        Route,
        UdpFlow, //
    },
    namespace::NamespaceRef,
    skbuff::{
        completion::{
            Completions,
            Event, //
        },
        SkBuff, //
    },
    socket::Family,
    Device,
    DeviceRef, //
};
use crate::{
    alloc::Flags,
    bindings,
    prelude::*,
    sync::rcu, //
};

const UDP_LENGTH: usize = 8;

/// Network settings for UDP encapsulations which carry their own integrity check.
///
/// The UDP checksum is zero. The receiving protocol must support this mode, including
/// explicitly permitting zero UDP checksums for IPv6 encapsulations.
pub struct Configuration {
    /// Source and destination IP addresses.
    pub addresses: AddressPair,
    /// IPv4 TOS or IPv6 traffic class.
    pub traffic_class: u8,
    /// IPv4 TTL or IPv6 hop limit.
    pub hop_limit: u8,
    /// UDP source port in host byte order.
    pub source_port: u16,
    /// UDP destination port in host byte order.
    pub destination_port: u16,
}

enum Bytes {
    V4([u8; 28]),
    V6([u8; 48]),
}

/// Complete, initialized IP/UDP headers whose shape and lengths cannot be modified.
///
/// IPv4 uses a fixed header with DF set; IPv6 has no extension headers. The IPv4
/// identification and checksum are filled by packet preparation and output, respectively.
///
/// # Invariants
///
/// The byte variant, encoded addresses and IP/UDP length fields agree with the addresses
/// in `flow` and `payload_length`. Both headers have their fixed protocol sizes and UDP
/// next protocol.
pub struct Headers {
    bytes: Bytes,
    flow: UdpFlow,
    payload_length: usize,
}

impl Configuration {
    /// Returns the complete selectors to use for policy routing.
    #[inline]
    pub fn flow(&self) -> UdpFlow {
        UdpFlow {
            addresses: self.addresses,
            traffic_class: self.traffic_class,
            source_port: self.source_port,
            destination_port: self.destination_port,
        }
    }

    /// Builds headers after checking the IP and UDP wire-length limits.
    pub fn headers(&self, payload_length: usize) -> Result<Headers> {
        let udp_length = u16::try_from(payload_length.checked_add(UDP_LENGTH).ok_or(EINVAL)?)?;
        let mut bytes = match self.addresses {
            AddressPair::V4 {
                source,
                destination,
            } => {
                let length = udp_length.checked_add(20).ok_or(EINVAL)?;
                let mut bytes = [0; 28];
                bytes[0] = 0x45;
                bytes[1] = self.traffic_class;
                bytes[2..4].copy_from_slice(&length.to_be_bytes());
                bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
                bytes[8] = self.hop_limit;
                bytes[9] = bindings::IPPROTO_UDP as u8;
                bytes[12..16].copy_from_slice(&source);
                bytes[16..20].copy_from_slice(&destination);
                Bytes::V4(bytes)
            }
            AddressPair::V6 {
                source,
                destination,
            } => {
                let mut bytes = [0; 48];
                let version = (6u32 << 28) | (u32::from(self.traffic_class) << 20);
                bytes[..4].copy_from_slice(&version.to_be_bytes());
                bytes[4..6].copy_from_slice(&udp_length.to_be_bytes());
                bytes[6] = bindings::IPPROTO_UDP as u8;
                bytes[7] = self.hop_limit;
                bytes[8..24].copy_from_slice(&source);
                bytes[24..40].copy_from_slice(&destination);
                Bytes::V6(bytes)
            }
        };
        let udp = match &mut bytes {
            Bytes::V4(bytes) => &mut bytes[20..],
            Bytes::V6(bytes) => &mut bytes[40..],
        };
        udp[..2].copy_from_slice(&self.source_port.to_be_bytes());
        udp[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        udp[4..6].copy_from_slice(&udp_length.to_be_bytes());
        // INVARIANT: Checked lengths and the selected address pair populate every wire field;
        // the private byte variants prevent modifying their shape after construction.
        Ok(Headers {
            bytes,
            flow: self.flow(),
            payload_length,
        })
    }
}

impl Headers {
    /// Borrows the complete IP header.
    #[inline]
    pub fn ip(&self) -> &[u8] {
        match &self.bytes {
            Bytes::V4(bytes) => &bytes[..20],
            Bytes::V6(bytes) => &bytes[..40],
        }
    }

    /// Borrows the complete UDP header.
    #[inline]
    pub fn udp(&self) -> &[u8] {
        match &self.bytes {
            Bytes::V4(bytes) => &bytes[20..],
            Bytes::V6(bytes) => &bytes[40..],
        }
    }

    fn family(&self) -> Family {
        match &self.bytes {
            Bytes::V4(_) => Family::Ipv4,
            Bytes::V6(_) => Family::Ipv6,
        }
    }
}

/// An initialized payload with reserved header space and a retained original device.
///
/// # Invariants
///
/// The buffer is a fresh, exclusively owned allocation with no destination or callback.
/// Its data contains only initialized payload. `device` retains `skb->dev`, and `family`
/// matches its protocol. Buffer field order keeps the device alive while freeing the skb.
pub struct Payload {
    buffer: SkBuff,
    device: DeviceRef,
    family: Family,
}

impl Payload {
    /// Allocates zeroed payload with aligned space for link, IP and UDP headers.
    pub fn new(device: DeviceRef, family: Family, length: usize, flags: Flags) -> Result<Self> {
        let ip_length = match family {
            Family::Ipv4 => 20usize,
            Family::Ipv6 if cfg!(CONFIG_IPV6) => 40,
            Family::Ipv6 => return Err(EAFNOSUPPORT),
        };
        let udp_length = u16::try_from(length.checked_add(UDP_LENGTH).ok_or(EINVAL)?)?;
        if family == Family::Ipv4 {
            udp_length.checked_add(ip_length as u16).ok_or(EINVAL)?;
        }
        // LL_RESERVED_SPACE already includes the link header and its alignment padding.
        let headroom = device
            .reserved_space()
            .checked_add(ip_length + UDP_LENGTH)
            .ok_or(EINVAL)?;
        let buffer = SkBuff::new(length, headroom, flags)?;
        let raw = buffer.as_raw();
        // SAFETY: This fresh header is exclusive. The owned device outlives every access to
        // its non-owning pointer, and no callback or destination is installed yet.
        unsafe {
            (*raw).__bindgen_anon_2.tstamp = bindings::ktime_get();
            (*raw)
                .__bindgen_anon_1
                .__bindgen_anon_1
                .__bindgen_anon_1
                .dev = device.as_raw();
            let protocol = match family {
                Family::Ipv4 => bindings::ETH_P_IP,
                Family::Ipv6 => bindings::ETH_P_IPV6,
            };
            bindings::skb_set_protocol(raw, (protocol as u16).to_be());
        }
        // INVARIANT: The new allocation has initialized payload and the retained device/family.
        Ok(Self {
            buffer,
            device,
            family,
        })
    }

    /// Borrows the original network device.
    #[inline]
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// Returns the payload length.
    #[inline]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns whether the payload is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Borrows the initialized payload without exposing header or ownership metadata.
    #[inline]
    pub fn data_mut(&mut self) -> Result<&mut [u8]> {
        self.buffer.data_mut()
    }

    /// Prepends matching headers and retains a route and active namespace for output.
    ///
    /// Consumes this allocation on error as well as success. Header lengths and addresses
    /// must match the payload and route. All routing selectors and the originating device
    /// must agree, and the routing core must still consider the destination valid.
    pub fn prepare(mut self, route: &Route, headers: Headers) -> Result<Prepared> {
        if headers.family() != self.family {
            return Err(EAFNOSUPPORT);
        }
        if headers.payload_length != self.len() || !route.matches(&self.device, headers.flow) {
            return Err(EINVAL);
        }
        let namespace = route.namespace().clone();
        self.buffer.prepend(headers.udp())?;
        let raw = self.buffer.as_raw();
        // SAFETY: The exclusive buffer now starts at its initialized UDP header. Fresh packet
        // state has no external cb users or completion callbacks. Scrubbing cannot drop owners.
        unsafe {
            bindings::skb_reset_transport_header(raw);
            if self.family == Family::Ipv4 {
                bindings::skb_scrub_packet(raw, false);
                bindings::skb_clear_hash(raw);
            }
            (*raw).cb.fill(0);
        }
        self.buffer.prepend(headers.ip())?;
        // SAFETY: The matching fixed IP header is initialized and aligned after reserved link
        // headroom. Route ownership and the active namespace span every C access. The fresh skb
        // has no existing destination; acquiring a reference transfers it to skb destruction.
        unsafe {
            bindings::skb_reset_network_header(raw);
            bindings::dst_hold(route.as_raw());
            bindings::skb_dst_set(raw, route.as_raw());
            if self.family == Family::Ipv4 {
                bindings::__ip_select_ident(
                    namespace.as_raw(),
                    bindings::skb_network_header(raw).cast(),
                    1,
                );
            }
        }
        let Self {
            buffer,
            device,
            family,
        } = self;
        // INVARIANT: The sealed headers establish every offset and length, and owned references
        // retain the destination, device and active namespace without exposing mutable metadata.
        Ok(Prepared {
            buffer,
            device,
            namespace,
            family,
            header_length: headers.ip().len() + UDP_LENGTH,
            origin_index: route.index(),
            route_cookie: route.cookie(),
        })
    }
}

/// An owned UDP packet with initialized, immutable network headers and a retained route.
///
/// # Invariants
///
/// The buffer owns a destination in the retained active namespace. Its complete IP/UDP
/// prefix matches `family`; network and transport offsets point to those headers. Only
/// payload bytes are mutable. The retained device equals `skb->dev` until handoff, and
/// completion ownership leaves the packet socket-free. Field order frees the buffer before
/// releasing its device and namespace.
pub struct Prepared {
    buffer: SkBuff,
    device: DeviceRef,
    namespace: NamespaceRef,
    family: Family,
    header_length: usize,
    origin_index: c_int,
    route_cookie: u32,
}

impl Prepared {
    /// Borrows the original network device.
    #[inline]
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// Returns the packet's immutable IP family.
    #[inline]
    pub fn family(&self) -> Family {
        self.family
    }

    /// Returns the complete IP/UDP packet length.
    #[inline]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns whether the complete packet is empty (always false for prepared headers).
    #[inline]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Borrows immutable network headers and mutable payload for integrity calculations.
    pub fn parts_mut(&mut self) -> Result<(&[u8], &mut [u8])> {
        let (headers, payload) = self.buffer.data_mut()?.split_at_mut(self.header_length);
        Ok((headers, payload))
    }

    /// Borrows only the initialized payload, preserving network headers and offsets.
    #[inline]
    pub fn data_mut(&mut self) -> Result<&mut [u8]> {
        self.parts_mut().map(|(_, payload)| payload)
    }

    /// Installs a socket-free completion for the prepared packet.
    ///
    /// Native IP transforms can charge write memory to an attached socket. Completion
    /// ownership does not implement that accounting, so this handoff leaves `skb->sk` unset.
    /// The prepared owner retains the original device until output clears `skb->dev`.
    /// Queued output then owns only its destination's device; completion storage must not
    /// retain an unrelated original device that native teardown cannot identify.
    ///
    /// Failure retains the packet and drops the uninstalled event without completing it.
    /// Completion can run as soon as the packet is dropped or handed off.
    pub fn attach_completion<T: Event>(
        &mut self,
        completions: &Completions<T>,
        event: T,
        flags: Flags,
    ) -> Result {
        completions.attach(&mut self.buffer, None, None, event, flags)
    }

    /// Transfers the packet to native IP output, consuming it on success and error.
    pub fn output(self) -> c_int {
        // Destination teardown can replace dst.dev and release its old reference. Keep
        // output-device pointers alive before IP samples them for its netfilter arguments.
        let _rcu = rcu::read_lock();
        // SAFETY: RCU lookup validates the retained original device in this namespace and
        // excludes migration until the synchronous handoff ends. Queued output uses only dst.
        if unsafe { bindings::dev_get_by_index_rcu(self.namespace.as_raw(), self.origin_index) }
            != self.device.as_raw()
        {
            return ENODEV.to_errno();
        }
        // SAFETY: The buffer owns its immutable destination and retains its namespace.
        // RCU protects route and policy objects sampled while checking the saved generation.
        // Preparation may precede output by an arbitrary interval, so revalidate at handoff.
        if unsafe {
            bindings::dst_check(bindings::skb_dst(self.buffer.as_raw()), self.route_cookie)
                .is_null()
        } {
            return EHOSTUNREACH.to_errno();
        }
        // Keep self intact through fallible validation so its field order releases the
        // buffer and destination before the final device and active namespace references.
        let Self {
            buffer,
            device: _device,
            namespace,
            family,
            ..
        } = self;
        let raw = buffer.into_raw();
        // SAFETY: Prepared headers, protocol, offsets and destination agree. The packet has no
        // socket ownership. Namespace and original device remain retained through output,
        // which consumes the header reference.
        unsafe {
            // A locally generated packet has no input interface. In particular, an original
            // device reference must not supply cross-namespace provenance after migration.
            (*raw)
                .__bindgen_anon_1
                .__bindgen_anon_1
                .__bindgen_anon_1
                .dev = core::ptr::null_mut();
            match family {
                Family::Ipv4 => bindings::ip_local_out(namespace.as_raw(), (*raw).sk, raw),
                #[cfg(CONFIG_IPV6)]
                Family::Ipv6 => bindings::ip6_local_out(namespace.as_raw(), (*raw).sk, raw),
                #[cfg(not(CONFIG_IPV6))]
                Family::Ipv6 => {
                    bindings::kfree_skb(raw);
                    EAFNOSUPPORT.to_errno()
                }
            }
        }
    }
}

#[cfg(CONFIG_RUST_UDP_PACKET_KUNIT_TEST)]
#[macros::kunit_tests(rust_udp_packets)]
mod tests {
    use super::*;

    #[test]
    fn encapsulation_wire_length_boundaries() -> Result {
        let mut config = Configuration {
            addresses: AddressPair::V4 {
                source: [192, 0, 2, 1],
                destination: [192, 0, 2, 2],
            },
            traffic_class: 0x2a,
            hop_limit: 64,
            source_port: 4790,
            destination_port: 4791,
        };
        let headers = config.headers(65507)?;
        assert_eq!(&headers.ip()[2..4], &[0xff, 0xff]);
        assert_eq!(&headers.ip()[12..], &[192, 0, 2, 1, 192, 0, 2, 2]);
        assert_eq!(headers.udp(), &[0x12, 0xb6, 0x12, 0xb7, 0xff, 0xeb, 0, 0]);
        assert!(matches!(config.headers(65508), Err(EINVAL)));
        assert!(matches!(config.headers(usize::MAX), Err(EINVAL)));
        config.addresses = AddressPair::V6 {
            source: [1; 16],
            destination: [2; 16],
        };
        let headers = config.headers(65527)?;
        assert_eq!(&headers.ip()[..8], &[0x62, 0xa0, 0, 0, 0xff, 0xff, 17, 64]);
        assert_eq!(headers.udp(), &[0x12, 0xb6, 0x12, 0xb7, 0xff, 0xff, 0, 0]);
        assert!(config.headers(65528).is_err());
        assert!(matches!(config.headers(usize::MAX), Err(EINVAL)));
        Ok(())
    }

    #[cfg(CONFIG_NET_UDP_TUNNEL = "y")]
    #[test]
    fn lookup_resolves_addresses_and_preparation_checks_selectors() -> Result {
        use super::super::{namespace::Namespace, udp_tunnel, RtnlGuard};
        use crate::{error::to_result, types::ScopeGuard};

        struct Receiver;
        impl udp_tunnel::Handler for Receiver {
            fn receive(_datagram: udp_tunnel::Datagram) {}
        }

        let registration = KBox::pin_init(udp_tunnel::Registration::<Receiver>::new(), GFP_KERNEL)?;
        let lease = registration
            .key()
            .bind(Namespace::initial(), Family::Ipv4, 47914)?;
        // SAFETY: The initial namespace's loopback device is registered before KUnit runs.
        let device = unsafe { Device::from_raw((*Namespace::initial().as_raw()).loopback_dev) };
        // KUnit can run before userspace brings loopback up and installs its local route.
        let opened = {
            let _rtnl = RtnlGuard::lock();
            if device.is_running() {
                false
            } else {
                // SAFETY: The registered loopback device remains live and RTNL is held.
                to_result(unsafe { bindings::dev_open(device.as_raw(), core::ptr::null_mut()) })?;
                true
            }
        };
        let _close = ScopeGuard::new(|| {
            if opened {
                let _rtnl = RtnlGuard::lock();
                // SAFETY: Restore only the state changed by this fixture, under RTNL.
                unsafe { bindings::dev_close(device.as_raw()) };
            }
        });
        let location = device.location()?;
        let mut configuration = Configuration {
            addresses: AddressPair::V4 {
                source: [0; 4],
                destination: [127, 0, 0, 1],
            },
            traffic_class: 0x2a,
            hop_limit: 64,
            source_port: 4790,
            destination_port: 47914,
        };
        let route = Route::lookup_udp(&location, lease.socket(), configuration.flow())?;
        assert_eq!(
            route.flow().addresses,
            AddressPair::V4 {
                source: [127, 0, 0, 1],
                destination: [127, 0, 0, 1],
            }
        );
        configuration.addresses = route.flow().addresses;
        configuration.destination_port += 1;
        let payload = Payload::new(device.to_ref(), Family::Ipv4, 4, GFP_KERNEL)?;
        assert!(matches!(
            payload.prepare(&route, configuration.headers(4)?),
            Err(EINVAL)
        ));
        configuration.destination_port -= 1;
        let payload = Payload::new(device.to_ref(), Family::Ipv4, 4, GFP_KERNEL)?;
        let packet = payload.prepare(&route, configuration.headers(4)?)?;
        assert_eq!(packet.output(), 0);
        // Model a saved interface index which no longer identifies the retained device.
        let payload = Payload::new(device.to_ref(), Family::Ipv4, 4, GFP_KERNEL)?;
        let mut stale = payload.prepare(&route, configuration.headers(4)?)?;
        stale.origin_index = c_int::MAX;
        assert_eq!(stale.output(), ENODEV.to_errno());
        let payload = Payload::new(device.to_ref(), Family::Ipv4, 4, GFP_KERNEL)?;
        let stale = payload.prepare(&route, configuration.headers(4)?)?;
        // SAFETY: Flushing the active namespace's route cache invalidates the saved route
        // without consuming its references; this models a routing change before handoff.
        unsafe { bindings::rt_cache_flush(Namespace::initial().as_raw()) };
        assert_eq!(stale.output(), EHOSTUNREACH.to_errno());
        Ok(())
    }

    #[test]
    fn payload_bounds_and_network_alignment() -> Result {
        // SAFETY: The initial namespace's loopback device is registered before KUnit runs
        // and remains allocated. Acquiring an independent device reference is permitted.
        let device = unsafe {
            Device::from_raw((*super::super::namespace::Namespace::initial().as_raw()).loopback_dev)
        };
        let mut payload = Payload::new(device.to_ref(), Family::Ipv4, 32, GFP_KERNEL)?;
        assert_eq!(payload.len(), 32);
        assert_eq!(payload.data_mut()?, &[0; 32]);
        payload.data_mut()?[31] = 0xa5;
        assert_eq!(payload.data_mut()?[31], 0xa5);
        assert_eq!(payload.device().as_raw(), device.as_raw());
        let link_space = payload.buffer.headroom() - 28;
        assert!(link_space >= device.reserved_space());
        assert_eq!(link_space % core::mem::align_of::<bindings::iphdr>(), 0);
        assert!(matches!(
            Payload::new(device.to_ref(), Family::Ipv4, 65508, GFP_KERNEL),
            Err(EINVAL)
        ));
        assert!(matches!(
            Payload::new(device.to_ref(), Family::Ipv4, usize::MAX, GFP_KERNEL),
            Err(EINVAL)
        ));
        #[cfg(not(CONFIG_IPV6))]
        assert!(matches!(
            Payload::new(device.to_ref(), Family::Ipv6, 32, GFP_KERNEL),
            Err(EAFNOSUPPORT)
        ));
        #[cfg(CONFIG_IPV6)]
        {
            let payload = Payload::new(device.to_ref(), Family::Ipv6, 32, GFP_KERNEL)?;
            assert_eq!(payload.buffer.headroom() - 48, link_space);
        }
        Ok(())
    }
}
