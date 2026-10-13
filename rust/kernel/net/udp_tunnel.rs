// SPDX-License-Identifier: GPL-2.0

//! Namespace-owned UDP tunnel sockets with separately retained protocol-socket references.

use super::{
    namespace::{
        registration,
        Namespace,
        NamespaceAllocationRef,
        NamespaceRef, //
    },
    skbuff::packet::Packet,
    socket::Family,
    Device,
    DeviceRef, //
};
use crate::{
    bindings,
    error::to_result,
    prelude::*,
    rbtree::{
        RBTree,
        RBTreeNodeReservation, //
    },
    str::CStr,
    sync::{
        LockClassKey,
        Mutex, //
    },
    types::ScopeGuard, //
};
use core::{
    marker::PhantomData,
    ptr::{
        self,
        NonNull, //
    }, //
};

/// A stateless receiver for bounded UDP datagrams.
///
/// Callbacks run in network receive context under RCU and must not sleep. Taking ownership
/// of the datagram permits deferring its processing; dropping it discards the packet.
/// Deferred packets retain network-device references. Their owner must stop admission and
/// drain them on NETDEV_UNREGISTER, before networking waits for device references. Waiting
/// for an ordinary per-namespace exit callback is too late to release those references.
///
/// Encapsulation errors are not delivered to handlers. Native IP route exception processing
/// still runs, but this receive-only interface does not report per-datagram ICMP errors.
pub trait Handler: Send + Sync + 'static {
    /// Consumes a datagram whose UDP length and payload position have been validated.
    fn receive(datagram: Datagram);
}

/// Owns a received UDP payload and the device references needed to classify it.
///
/// The complete IP/UDP prefix remains available through the owned packet. IPv6 jumbograms
/// are not supported. The payload length excludes the eight-byte UDP header.
///
/// # Invariants
///
/// The packet retains its non-null receiving device and begins at UDP payload. The UDP length
/// is between eight and the original packet length. `lower` independently retains the ultimate
/// lower device when the receiving device is a VLAN device.
pub struct Datagram {
    packet: Packet<()>,
    lower: Option<DeviceRef>,
    payload_length: u16,
}

impl Datagram {
    /// Borrows the device on which networking delivered the packet.
    ///
    /// For loopback traffic, this is the interface owning the local destination address.
    #[inline]
    pub fn device(&self) -> &Device {
        self.packet.device().unwrap()
    }

    /// Borrows the retained underlying device for a VLAN packet, including stacked VLANs.
    #[inline]
    pub fn lower_device(&self) -> Option<&Device> {
        self.lower.as_deref()
    }

    /// Returns the UDP payload length declared by the validated header.
    #[inline]
    pub fn payload_length(&self) -> u16 {
        self.payload_length
    }

    /// Transfers the payload packet, retaining its network prefix and receiving device.
    #[inline]
    pub fn into_packet(self) -> Packet<()> {
        self.packet
    }

    /// Imports a packet handed off by the UDP encapsulation callback.
    ///
    /// # Safety
    ///
    /// The caller must transfer an exclusive skb under RCU with initialized received bytes
    /// in its linear data and fragments, data at the UDP header, and an initialized network
    /// prefix. Its callbacks must ignore cb and permit release on another CPU. Its device
    /// and any VLAN lower device must permit reference acquisition throughout the call.
    unsafe fn from_raw(skb: *mut bindings::sk_buff) -> Result<Self> {
        // Keep a retained lower device through packet destruction on validation failure too.
        let mut lower = None;
        // SAFETY: UDP has validated the IP prefix and retains the receiving device under RCU.
        // Resolve local delivery before discarding the receive route. The helper's selected
        // device remains RCU-protected until Packet acquires its independent reference.
        unsafe { bindings::udp_tunnel_resolve_loopback(skb) };
        // SAFETY: The UDP receive context supplies the packet and device/destination protection
        // required by Packet::from_raw. The owner upgrades their lifetimes before leaving RCU.
        let mut packet = unsafe { Packet::from_raw(skb, ()) };
        let device = packet.device().ok_or(EINVAL)?;
        if device.vlan_id().is_some() {
            // SAFETY: Netdev unregistration drains network RCU readers before ndo_uninit can
            // release VLAN lower-device references. Capture an independent reference here;
            // retaining only the upper allocation would not suffice after leaving receive.
            lower = Some(unsafe {
                Device::from_raw(bindings::vlan_dev_real_dev(device.as_raw())).to_ref()
            });
        }
        let mut header = [0; 8];
        packet.copy_bits(0, &mut header)?;
        let length = u16::from_be_bytes([header[4], header[5]]);
        if usize::from(length) < header.len() || usize::from(length) > packet.len() {
            return Err(EINVAL);
        }
        packet.pull(header.len())?;
        // INVARIANT: Validation bounded the declared length; pull preserves the initialized
        // prefix and positions data at payload. Both device references remain independently held.
        Ok(Self {
            packet,
            lower,
            payload_length: length - 8,
        })
    }
}

/// Retains a UDP protocol socket and its namespace allocation, even after the port is closed.
///
/// This does not keep the namespace active or keep the tunnel bound. Protocol operations need
/// appropriate namespace and socket synchronization in addition to this allocation reference.
///
/// # Invariants
///
/// `socket` owns one native sock reference. Its family and namespace association are immutable;
/// `namespace` retains that namespace allocation and `family` records the socket's address family.
pub struct SocketRef {
    socket: NonNull<bindings::sock>,
    namespace: NamespaceAllocationRef,
    family: Family,
}

// SAFETY: Native protocol-socket and passive namespace references may be released on any CPU.
unsafe impl Send for SocketRef {}
// SAFETY: Shared methods expose immutable values and synchronized reference acquisition only.
unsafe impl Sync for SocketRef {}

impl SocketRef {
    /// Borrows the retained namespace allocation without keeping its subsystems active.
    #[inline]
    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// Returns the immutable address family of the protocol socket.
    #[inline]
    pub fn family(&self) -> Family {
        self.family
    }

    /// Borrows the protocol socket for interoperability without transferring a reference.
    ///
    /// C users must preserve its configuration, namespace and ownership, and must not close
    /// it or perform native receive operations. Closure purges receive queues after draining
    /// network callbacks; it does not serialize with native socket readers.
    /// Allocation lifetime alone does not guarantee that the tunnel remains bound.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::sock {
        self.socket.as_ptr()
    }
}

impl Clone for SocketRef {
    #[inline]
    fn clone(&self) -> Self {
        // SAFETY: This owner retains a nonzero native reference throughout acquisition.
        unsafe { bindings::sock_hold(self.as_raw()) };
        // INVARIANT: The new handle owns the acquired reference and the same immutable identity.
        Self {
            socket: self.socket,
            namespace: self.namespace.clone(),
            family: self.family,
        }
    }
}

impl Drop for SocketRef {
    fn drop(&mut self) {
        // SAFETY: Release exactly the owned reference. The namespace field outlives this call;
        // delayed socket destruction invokes only core callbacks after tunnel receive is fenced.
        unsafe { bindings::sock_put(self.socket.as_ptr()) };
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SocketKey {
    ipv6: bool,
    port: u16,
}

// This owner never escapes Bank or a scope retaining an active namespace reference. Bank's
// pernet exit closes it before dependent namespace subsystems are destroyed. Keeping it generic
// also places UDP-tunnel module references in the consuming driver's code, not kernel.o.
struct SocketOwner<H: Handler> {
    socket: SocketRef,
    close_state: CloseState,
    _handler: PhantomData<fn() -> H>,
}

enum CloseState {
    Open,
    Closing,
    Closed,
}

impl<H: Handler> SocketOwner<H> {
    fn new(namespace: &NamespaceRef, key: SocketKey) -> Result<Self> {
        let family = if key.ipv6 { Family::Ipv6 } else { Family::Ipv4 };
        let address_family = if key.ipv6 {
            bindings::AF_INET6
        } else {
            bindings::AF_INET
        };
        let mut socket = ptr::null_mut();
        // SAFETY: The active namespace spans creation. Output storage is exclusive and the
        // selected UDP protocol retains no borrowed arguments.
        to_result(unsafe {
            bindings::sock_create_kern(
                namespace.as_raw(),
                address_family as c_int,
                bindings::sock_type_SOCK_DGRAM as c_int,
                0,
                &mut socket,
            )
        })?;
        let cleanup = ScopeGuard::new(|| {
            // SAFETY: Creation transferred the unique close obligation, which this guard
            // retains until successful setup transfers it to SocketOwner.
            unsafe {
                bindings::kernel_sock_shutdown(socket, bindings::sock_shutdown_cmd_SHUT_RDWR);
                bindings::sock_release(socket);
            }
        });
        // SAFETY: The initialized socket remains unpublished until kernel_bind below.
        let sock = unsafe { (*socket).sk };
        #[cfg(CONFIG_DEBUG_LOCK_ALLOC)]
        // SAFETY: Reclassify before binding publishes the socket to UDP lookups.
        unsafe {
            reclassify(sock, key.ipv6)
        };
        let mut callbacks = bindings::udp_tunnel_sock_cfg {
            encap_type: 1,
            encap_rcv: Some(Self::receive),
            ..Default::default()
        };
        // SAFETY: The socket is private. Configure all receive state before binding publishes
        // it to UDP lookup. No GRO callback is installed and wildcard lookup is still deferred.
        unsafe { bindings::udp_tunnel_sock_configure(sock, &mut callbacks) };
        // Binding can publish the socket before a post-bind hook rejects it. Establish
        // the fenced close obligation before either family enters that error path.
        // SAFETY: The newly created socket retains this initialized sock. A separate protocol
        // reference keeps it alive through callback drainage after socket closure.
        unsafe { bindings::sock_hold(sock) };
        let owner = Self {
            // INVARIANT: sock_hold acquired this reference; the passive namespace owner and
            // recorded family match the newly created socket's immutable association.
            socket: SocketRef {
                // SAFETY: Successful kernel socket creation returned a non-null sock.
                socket: unsafe { NonNull::new_unchecked(sock) },
                namespace: namespace.allocation_ref(),
                family,
            },
            close_state: CloseState::Open,
            _handler: PhantomData,
        };
        cleanup.dismiss();
        if key.ipv6 {
            #[cfg(CONFIG_IPV6)]
            {
                // SAFETY: This private IPv6 socket is not bound yet.
                to_result(unsafe { bindings::ip6_sock_set_v6only(sock) })?;
                // SAFETY: Set checksum policy while the socket remains unpublished.
                unsafe {
                    bindings::udp_set_no_check6_tx(sock, true);
                    bindings::udp_set_no_check6_rx(sock, true);
                }
                let mut address = bindings::sockaddr_in6 {
                    sin6_family: address_family as u16,
                    sin6_port: key.port.to_be(),
                    ..Default::default()
                };
                // SAFETY: The initialized IPv6 address is valid for its complete length.
                to_result(unsafe {
                    bindings::kernel_bind(
                        socket,
                        (&raw mut address).cast(),
                        size_of_val(&address) as c_int,
                    )
                })?;
            }
            #[cfg(not(CONFIG_IPV6))]
            return Err(EAFNOSUPPORT);
        } else {
            // SAFETY: The socket is private until binding; no other task can access its
            // packed checksum policy bits while this setter updates them.
            unsafe { (*sock).set_sk_no_check_tx(1) };
            let mut address = bindings::sockaddr_in {
                sin_family: address_family as u16,
                sin_port: key.port.to_be(),
                ..Default::default()
            };
            // SAFETY: The initialized IPv4 address is valid for its complete length.
            to_result(unsafe {
                bindings::kernel_bind(
                    socket,
                    (&raw mut address).cast(),
                    size_of_val(&address) as c_int,
                )
            })?;
        }
        // SAFETY: Binding has completed and no configuration-changing handle has escaped.
        // Bind hooks may have rewritten the requested identity. A mismatch drops the owner,
        // draining callbacks already admitted by binding before releasing receive resources.
        if !unsafe {
            bindings::udp_tunnel_sock_matches(sock, address_family as u16, key.port.to_be())
        } {
            return Err(EADDRNOTAVAIL);
        }
        // SAFETY: This bound kernel socket has wildcard source, no peer and no bound device.
        // Its receive state is initialized, the namespace is active and this owner closes it.
        unsafe { bindings::udp_tunnel_update_gro_lookup(namespace.as_raw(), sock, true) };
        Ok(owner)
    }

    /// Removes the receive hook and releases the uniquely owned socket binding.
    fn close(&mut self) {
        if !matches!(self.close_state, CloseState::Open) {
            return;
        }
        // SAFETY: The bank or an active namespace scope retains resources needed to close
        // this uniquely owned socket. SocketRef retains its allocation through completion.
        unsafe {
            bindings::udp_tunnel_clear_receive(self.socket.as_raw());
            bindings::udp_tunnel_sock_release(self.socket.as_raw());
        }
        self.close_state = CloseState::Closing;
    }

    /// Releases resources which receive readers could still have populated during closure.
    ///
    /// # Safety
    ///
    /// A network receive grace period must have completed since `close` returned.
    unsafe fn finish_close(&mut self) {
        if !matches!(self.close_state, CloseState::Closing) {
            return;
        }
        // SAFETY: Closure and the caller's receive fence exclude cache and queue producers.
        // These kernel sockets have no userspace readers, and SocketRef retains allocation.
        unsafe {
            bindings::udp_tunnel_clear_dst(self.socket.as_raw());
            bindings::udp_flush_receive_queue(self.socket.as_raw());
        }
        self.close_state = CloseState::Closed;
    }

    /// Consumes a UDP packet on behalf of this owner.
    ///
    /// # Safety
    ///
    /// The UDP core must transfer the exclusive skb to the callback installed by this
    /// owner, with the receive-side RCU and packet guarantees of `Datagram::from_raw`.
    unsafe extern "C" fn receive(
        socket: *mut bindings::sock,
        skb: *mut bindings::sk_buff,
    ) -> c_int {
        // SAFETY: UDP retains the socket and transfers this exclusive packet. The helper
        // consumes it and passes each individual, unlinked datagram to receive_one while
        // retaining the original receive context, including RCU and device protection.
        unsafe { bindings::udp_tunnel_receive_segments(socket, skb, Some(Self::receive_one)) };
        0
    }

    /// Imports one UDP datagram while the receive callback's protections remain held.
    ///
    /// # Safety
    ///
    /// The caller transfers an exclusive, unlinked packet under the same receive-side
    /// protections as `receive`, with data positioned at the UDP header after segmentation.
    unsafe extern "C" fn receive_one(skb: *mut bindings::sk_buff) {
        // SAFETY: Only setup_udp_tunnel_sock installs this hook. IPv4/IPv6 UDP delivery retains
        // the packet's devices and unreferenced destination under network RCU protection.
        if let Ok(datagram) = unsafe { Datagram::from_raw(skb) } {
            H::receive(datagram);
        }
    }
}

// Both the function and its class keys reside in kernel Rust, independently of H's module.
// Delayed sock destruction may retain these keys after tunnel/module teardown.
/// Reclassifies an unpublished tunnel socket with resident lock keys.
///
/// # Safety
///
/// `socket` must be initialized, unpublished and exclusively accessible. `ipv6` must match
/// its family, and no other user may acquire its locks during this call.
#[cfg(CONFIG_DEBUG_LOCK_ALLOC)]
#[inline(never)]
unsafe fn reclassify(socket: *mut bindings::sock, ipv6: bool) {
    // SAFETY: The socket has not been bound or otherwise published. No UDP lookup or
    // receive-side user can access its ownership lock before initialization finishes.
    unsafe {
        let (spin_name, spin_key, name, key) = if ipv6 {
            (
                c"rust UDP6 tunnel slock",
                crate::sync::static_lock_class!(),
                c"rust UDP6 tunnel lock",
                crate::sync::static_lock_class!(),
            )
        } else {
            (
                c"rust UDP4 tunnel slock",
                crate::sync::static_lock_class!(),
                c"rust UDP4 tunnel lock",
                crate::sync::static_lock_class!(),
            )
        };
        bindings::sock_lock_init_class_and_name(
            socket,
            spin_name.as_char_ptr(),
            spin_key.as_ptr(),
            name.as_char_ptr(),
            key.as_ptr(),
        );
    }
}

impl<H: Handler> Drop for SocketOwner<H> {
    fn drop(&mut self) {
        self.close();
        if matches!(self.close_state, CloseState::Closing) {
            // SAFETY: Close removed this hook and binding; the fence drains receive readers
            // before their caches and queues are released. Bank teardown can batch this work.
            unsafe {
                bindings::synchronize_net();
                self.finish_close();
            }
        }
    }
}

struct Entry<H: Handler> {
    owner: SocketOwner<H>,
    users: usize,
}

#[pin_data(PinnedDrop)]
struct Bank<H: Handler> {
    #[pin]
    sockets: Mutex<RBTree<SocketKey, Entry<H>>>,
}

#[pinned_drop]
impl<H: Handler> PinnedDrop for Bank<H> {
    fn drop(self: Pin<&mut Self>) {
        let mut sockets = self.sockets.lock();
        if sockets.is_empty() {
            return;
        }
        // Namespace state teardown has excluded all lease acquisition and release callbacks.
        // Close every binding before waiting, so the number of sockets adds no grace periods.
        for entry in sockets.values_mut() {
            entry.owner.close();
        }
        // SAFETY: Every hook is cleared and every socket is closed. Their independent
        // SocketRefs retain allocation until all callbacks finish and cleanup completes.
        unsafe { bindings::synchronize_net() };
        for entry in sockets.values_mut() {
            // SAFETY: The shared receive fence follows this socket's close above.
            unsafe { entry.owner.finish_close() };
        }
    }
}

// Both built-in and modular handlers must use the same name pointer for this static class.
#[inline(never)]
fn bank_lock_class() -> (&'static CStr, Pin<&'static LockClassKey>) {
    (c"rust UDP tunnel bank", crate::sync::static_lock_class!())
}

impl<H: Handler> registration::State for Bank<H> {
    fn new() -> impl PinInit<Self, Error> {
        let (name, class) = bank_lock_class();
        try_pin_init!(Self { sockets <- Mutex::new(RBTree::new(), name, class) })
    }
}

/// Owns a handler's tunnel registration across network namespaces.
///
/// Destruction closes sockets even if leases or protocol references remain, and waits for
/// receive callbacks. Creation and destruction may sleep and must run outside receive callbacks.
#[pin_data]
pub struct Registration<H: Handler> {
    #[pin]
    namespaces: registration::Registration<Bank<H>>,
}

impl<H: Handler> Registration<H> {
    /// Registers namespace-owned socket storage, deferring binding until the first lease.
    pub fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self { namespaces <- registration::Registration::new() })
    }

    /// Returns a revocable key for acquiring tunnel leases.
    #[inline]
    pub fn key(&self) -> Key<H> {
        Key {
            namespaces: self.namespaces.key(),
        }
    }
}

/// A copyable key which stops admitting new leases when its registration closes.
pub struct Key<H: Handler> {
    namespaces: registration::Key<Bank<H>>,
}

impl<H: Handler> Copy for Key<H> {}

impl<H: Handler> Clone for Key<H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H: Handler> Key<H> {
    /// Binds or shares a tunnel port in a live namespace, in sleepable context.
    ///
    /// The port must be nonzero. IPv6 sockets are IPv6-only so both families can share a port
    /// number. These tunnels accept and emit zero UDP checksums, including IPv6; the
    /// encapsulated protocol must supply its own integrity check. The returned lease retains
    /// allocations without postponing namespace cleanup.
    /// Receive callbacks are configured before binding publishes the socket. Wildcard GRO
    /// lookup registration follows a successful bind, so receive configuration is complete
    /// before either publication. A bind hook that changes the requested port or wildcard
    /// binding causes acquisition to fail after draining any admitted receive callbacks.
    pub fn bind(&self, namespace: &Namespace, family: Family, port: u16) -> Result<Lease<H>> {
        if port == 0 {
            return Err(EINVAL);
        }
        let key = SocketKey {
            ipv6: matches!(family, Family::Ipv6),
            port,
        };
        let reservation = RBTreeNodeReservation::new(GFP_KERNEL)?;
        self.namespaces.with(namespace, |bank, active| {
            let mut sockets = bank.sockets.lock();
            let socket = if let Some(entry) = sockets.get_mut(&key) {
                entry.users = entry.users.checked_add(1).ok_or(EOVERFLOW)?;
                entry.owner.socket.clone()
            } else {
                let owner = SocketOwner::<H>::new(active, key)?;
                let socket = owner.socket.clone();
                sockets.insert(reservation.into_node(key, Entry { owner, users: 1 }));
                socket
            };
            // INVARIANT: The matching bank entry counts this lease. No fallible step follows.
            Ok(Lease {
                namespaces: self.namespaces,
                key,
                socket,
            })
        })?
    }
}

/// Owns one device user's interest in a namespace's shared tunnel port.
///
/// Drop may sleep. The last lease closes the port even if separate SocketRefs remain.
/// Namespace or registration teardown can close it earlier. Leases never keep namespaces active.
///
/// # Invariants
///
/// While its registration and namespace remain active, the matching bank entry counts this
/// lease exactly once. Otherwise bank teardown owns closure. `socket` independently retains
/// the original protocol socket and namespace allocation, so stale keys can fail safely.
pub struct Lease<H: Handler> {
    namespaces: registration::Key<Bank<H>>,
    key: SocketKey,
    socket: SocketRef,
}

impl<H: Handler> Lease<H> {
    /// Borrows a protocol reference which can be cloned without extending the port's binding.
    #[inline]
    pub fn socket(&self) -> &SocketRef {
        &self.socket
    }
}

impl<H: Handler> Drop for Lease<H> {
    fn drop(&mut self) {
        let _ = self
            .namespaces
            .with(self.socket.namespace(), |bank, _active| {
                let mut sockets = bank.sockets.lock();
                let entry = sockets.get_mut(&self.key).unwrap();
                entry.users -= 1;
                if entry.users == 0 {
                    // Keep acquisition excluded until closing releases the bound port.
                    // Receive callbacks cannot take this sleepable bank lock.
                    drop(sockets.remove(&self.key));
                }
            });
    }
}

#[cfg(CONFIG_RUST_UDP_TUNNEL_KUNIT_TEST)]
#[macros::kunit_tests(rust_udp_tunnel)]
mod tests {
    use super::*;

    struct Shared;

    impl Handler for Shared {
        fn receive(_datagram: Datagram) {}
    }

    #[test]
    fn tunnel_gso_is_split_before_datagram_delivery() -> Result {
        let registration = KBox::pin_init(Registration::<Shared>::new(), GFP_KERNEL)?;
        let lease = registration
            .key()
            .bind(Namespace::initial(), Family::Ipv4, 47916)?;
        // SAFETY: The live tunnel socket supplies initialized UDP state. The fixture owns
        // its synthetic aggregate and synchronously verifies every resulting datagram.
        to_result(unsafe { bindings::udp_tunnel_test_segments(lease.socket().as_raw()) })
    }

    #[test]
    fn retained_protocol_references_do_not_keep_ports_bound() -> Result {
        let registration = KBox::pin_init(Registration::<Shared>::new(), GFP_KERNEL)?;
        let key = registration.key();
        let first = key.bind(Namespace::initial(), Family::Ipv4, 47912)?;
        let second = key.bind(Namespace::initial(), Family::Ipv4, 47912)?;
        assert_eq!(first.socket().as_raw(), second.socket().as_raw());
        let retained = first.socket().clone();
        drop(first);
        let third = key.bind(Namespace::initial(), Family::Ipv4, 47912)?;
        assert_eq!(retained.as_raw(), third.socket().as_raw());
        drop(second);
        drop(third);
        let replacement = key.bind(Namespace::initial(), Family::Ipv4, 47912)?;
        assert_ne!(retained.as_raw(), replacement.socket().as_raw());
        drop(retained);
        Ok(())
    }

    #[test]
    fn closure_purges_queued_datagrams_before_retained_socket_release() -> Result {
        let registration = KBox::pin_init(Registration::<Shared>::new(), GFP_KERNEL)?;
        let lease = registration
            .key()
            .bind(Namespace::initial(), Family::Ipv4, 47915)?;
        let retained = lease.socket().clone();
        // SAFETY: This live UDP socket has initialized receive queues and no user reader.
        // Inject an ordinary queued datagram to exercise receive-state reclamation.
        to_result(unsafe { bindings::udp_tunnel_test_queue(retained.as_raw()) })?;
        // SAFETY: The socket remains live and the fixture has finished its only producer.
        assert!(!unsafe { bindings::udp_tunnel_test_receive_empty(retained.as_raw()) });
        drop(lease);
        // SAFETY: Closing drained network producers. The reference retains inert queues.
        assert!(unsafe { bindings::udp_tunnel_test_receive_empty(retained.as_raw()) });
        drop(retained);
        Ok(())
    }

    #[test]
    fn bank_closure_purges_all_retained_sockets() -> Result {
        let registration = KBox::pin_init(Registration::<Shared>::new(), GFP_KERNEL)?;
        let key = registration.key();
        let first = key.bind(Namespace::initial(), Family::Ipv4, 47917)?;
        let second = key.bind(Namespace::initial(), Family::Ipv4, 47918)?;
        for socket in [first.socket(), second.socket()] {
            // SAFETY: Both live UDP sockets have initialized queues and no userspace reader.
            to_result(unsafe { bindings::udp_tunnel_test_queue(socket.as_raw()) })?;
            // SAFETY: The fixture has finished its only producer; the lease retains storage.
            assert!(!unsafe { bindings::udp_tunnel_test_receive_empty(socket.as_raw()) });
        }
        drop(registration);
        for socket in [first.socket(), second.socket()] {
            // SAFETY: Bank closure fenced all producers; the leases retain inert sockets.
            assert!(unsafe { bindings::udp_tunnel_test_receive_empty(socket.as_raw()) });
        }
        let replacement = KBox::pin_init(Registration::<Shared>::new(), GFP_KERNEL)?;
        let key = replacement.key();
        let rebound_first = key.bind(Namespace::initial(), Family::Ipv4, 47917)?;
        let rebound_second = key.bind(Namespace::initial(), Family::Ipv4, 47918)?;
        assert_ne!(first.socket().as_raw(), rebound_first.socket().as_raw());
        assert_ne!(second.socket().as_raw(), rebound_second.socket().as_raw());
        Ok(())
    }

    struct Replaced;

    impl Handler for Replaced {
        fn receive(_datagram: Datagram) {}
    }

    #[test]
    fn failed_bind_releases_preconfigured_tunnel_state() -> Result {
        let first = KBox::pin_init(Registration::<Shared>::new(), GFP_KERNEL)?;
        let second = KBox::pin_init(Registration::<Replaced>::new(), GFP_KERNEL)?;
        for family in [Family::Ipv4, Family::Ipv6] {
            if family == Family::Ipv6 && !cfg!(CONFIG_IPV6) {
                continue;
            }
            let lease = first.key().bind(Namespace::initial(), family, 47919)?;
            assert!(matches!(
                second.key().bind(Namespace::initial(), family, 47919),
                Err(EADDRINUSE)
            ));
            drop(lease);
            let rebound = second.key().bind(Namespace::initial(), family, 47919)?;
            drop(rebound);
        }
        Ok(())
    }

    #[test]
    fn stale_leases_cannot_close_replacement_registrations() -> Result {
        let registration = KBox::pin_init(Registration::<Replaced>::new(), GFP_KERNEL)?;
        let old_key = registration.key();
        let old = old_key.bind(Namespace::initial(), Family::Ipv4, 47913)?;
        let retained = old.socket().clone();
        drop(registration);
        let replacement = KBox::pin_init(Registration::<Replaced>::new(), GFP_KERNEL)?;
        let key = replacement.key();
        let lease = key.bind(Namespace::initial(), Family::Ipv4, 47913)?;
        assert_ne!(retained.as_raw(), lease.socket().as_raw());
        assert!(matches!(
            old_key.bind(Namespace::initial(), Family::Ipv4, 47913),
            Err(ENODEV)
        ));
        drop(old);
        drop(retained);
        let another = key.bind(Namespace::initial(), Family::Ipv4, 47913)?;
        assert_eq!(lease.socket().as_raw(), another.socket().as_raw());
        Ok(())
    }
}
