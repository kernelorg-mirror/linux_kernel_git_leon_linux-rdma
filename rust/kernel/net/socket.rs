// SPDX-License-Identifier: GPL-2.0

//! Owned kernel datagram sockets with retained network namespaces.

use super::namespace::Namespace;
use crate::{
    bindings,
    error::to_result,
    prelude::*, //
};
use core::ptr::{
    self,
    NonNull, //
};

/// IP address family selected when creating a datagram socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// IPv4 datagrams.
    Ipv4,
    /// IPv6 datagrams, if the protocol is available.
    Ipv6,
}

/// Owns one kernel UDP socket and closes it on drop.
///
/// Creation and drop require sleepable context. The underlying sock holds an active namespace
/// reference until its final release, including when C users retain sock references after close.
/// A namespace-owned subsystem must avoid retaining such a socket in a cycle with its namespace.
///
/// # Invariants
///
/// `socket` owns an initialized kernel datagram socket. `sock` is its initialized, immutable
/// protocol-socket association, retained until socket release. No other owner may close it.
/// `family` matches the immutable protocol address family. The sock's namespace reference
/// has been upgraded before publication.
pub struct DatagramSocket {
    socket: NonNull<bindings::socket>,
    sock: NonNull<bindings::sock>,
    family: Family,
    namespace: NonNull<bindings::net>,
}

// SAFETY: Socket ownership may move between tasks. Shared methods use synchronized C socket
// operations, and exclusive destruction closes the socket only after Rust borrows have ended.
unsafe impl Send for DatagramSocket {}
// SAFETY: Sharing exposes only synchronized operations and opaque interoperability pointers.
unsafe impl Sync for DatagramSocket {}

impl DatagramSocket {
    /// Creates a UDP socket with lock classes owned by the kernel crate.
    ///
    /// Returns ENODEV if the namespace can no longer acquire active references.
    pub fn new(namespace: &Namespace, family: Family) -> Result<Self> {
        let namespace = namespace.try_to_ref().ok_or(ENODEV)?;
        let address_family = match family {
            Family::Ipv4 => bindings::AF_INET,
            Family::Ipv6 => bindings::AF_INET6,
        };
        let mut socket = ptr::null_mut();
        // SAFETY: The active namespace reference spans creation and upgrade. The socket
        // output is exclusive, and the selected datagram protocol has no borrowed arguments.
        to_result(unsafe {
            bindings::sock_create_kern(
                namespace.as_raw(),
                address_family as c_int,
                bindings::sock_type_SOCK_DGRAM as c_int,
                0,
                &mut socket,
            )
        })?;
        // SAFETY: Successful datagram creation returns a non-null socket and initialized sock.
        // Both remain private. Upgrading replaces the kernel socket's passive namespace
        // reference with an active one, which the socket core releases at final sock destruction.
        unsafe {
            let sock = (*socket).sk;
            bindings::sk_net_refcnt_upgrade(sock);
            #[cfg(CONFIG_DEBUG_LOCK_ALLOC)]
            reclassify(sock, family == Family::Ipv6);
            // INVARIANT: The private initialized socket now retains its namespace through
            // final sock release. Ownership transfers into this handle with no fallible step.
            Ok(Self {
                socket: NonNull::new_unchecked(socket),
                sock: NonNull::new_unchecked(sock),
                family,
                namespace: NonNull::new_unchecked(namespace.as_raw()),
            })
        }
    }

    /// Borrows the namespace kept active by the protocol socket.
    #[inline]
    pub fn namespace(&self) -> &Namespace {
        // SAFETY: Creation upgraded the socket's immutable namespace association to an
        // active reference, retained until the socket's final release.
        unsafe { Namespace::from_raw(self.namespace.as_ptr()) }
    }

    /// Returns the immutable address family selected at creation.
    #[inline]
    pub fn family(&self) -> Family {
        self.family
    }

    /// Invalidates the socket's cached route, releasing the cache's destination reference.
    #[inline]
    pub fn clear_route(&self) {
        // SAFETY: This borrow retains the sock; the C helper synchronizes cache replacement.
        unsafe { bindings::sk_dst_reset(self.sock.as_ptr()) };
    }

    /// Retains the protocol socket and its namespace independently of this socket owner.
    #[inline]
    pub fn to_ref(&self) -> SockRef {
        // SAFETY: The socket owner retains the initialized sock throughout acquisition.
        unsafe { bindings::sock_hold(self.sock.as_ptr()) };
        // INVARIANT: The new handle owns the reference acquired above.
        SockRef { sock: self.sock }
    }

    /// Borrows the protocol-socket pointer without transferring a reference.
    ///
    /// C users must retain their own sock reference before using it beyond this borrow, and
    /// must preserve the owner's invariant, including exclusive socket-release ownership.
    #[inline]
    pub fn as_sock(&self) -> *mut bindings::sock {
        self.sock.as_ptr()
    }
}

// Socket references can outlive their creator. Keep both names and keys in resident code,
// avoiding a module reference that would prevent the creator from closing its own sockets.
/// Reclassifies the unpublished socket's locks with resident keys.
///
/// # Safety
///
/// `sock` must be initialized, unpublished and exclusively accessible; `ipv6` must match
/// its address family. No other user may acquire its locks during this call.
#[cfg(CONFIG_DEBUG_LOCK_ALLOC)]
#[inline(never)]
unsafe fn reclassify(sock: *mut bindings::sock, ipv6: bool) {
    let (spin_name, spin_key, name, key) = if ipv6 {
        (
            c"rust UDP6 datagram slock",
            crate::sync::static_lock_class!(),
            c"rust UDP6 datagram lock",
            crate::sync::static_lock_class!(),
        )
    } else {
        (
            c"rust UDP4 datagram slock",
            crate::sync::static_lock_class!(),
            c"rust UDP4 datagram lock",
            crate::sync::static_lock_class!(),
        )
    };
    // SAFETY: Creation retains exclusive access to this initialized, unpublished socket.
    // The names and keys reside in the kernel crate and need no module lifetime reference.
    unsafe {
        bindings::sock_lock_init_class_and_name(
            sock,
            spin_name.as_char_ptr(),
            spin_key.as_ptr(),
            name.as_char_ptr(),
            key.as_ptr(),
        );
    }
}

/// Owns a protocol-socket reference acquired from a kernel datagram socket.
///
/// Closing the originating socket does not release this reference or its active namespace
/// reference. This handle cannot close the socket and exposes no ordinary borrows of C fields.
///
/// # Invariants
///
/// `sock` owns one reference acquired with sock_hold. Its active namespace reference remains
/// installed until final sock destruction, including after the originating socket is closed.
pub struct SockRef {
    sock: NonNull<bindings::sock>,
}

// SAFETY: Core socket references permit acquisition and release on different CPUs.
unsafe impl Send for SockRef {}
// SAFETY: Shared methods only acquire references or return an opaque interoperability pointer.
unsafe impl Sync for SockRef {}

impl SockRef {
    /// Borrows the sock pointer without transferring its owned reference.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::sock {
        self.sock.as_ptr()
    }
}

impl Clone for SockRef {
    #[inline]
    fn clone(&self) -> Self {
        // SAFETY: This owned reference keeps the sock live during acquisition.
        unsafe { bindings::sock_hold(self.sock.as_ptr()) };
        // INVARIANT: The clone owns exactly the acquired reference.
        Self { sock: self.sock }
    }
}

impl Drop for SockRef {
    fn drop(&mut self) {
        // SAFETY: Release exactly this handle's core reference, without accessing it afterwards.
        unsafe { bindings::sock_put(self.sock.as_ptr()) };
    }
}

impl Drop for DatagramSocket {
    fn drop(&mut self) {
        // SAFETY: The handle owns the socket's only release obligation. Shutdown does not
        // consume it; sock_release closes it and retains protocol state for outstanding users.
        unsafe {
            bindings::kernel_sock_shutdown(
                self.socket.as_ptr(),
                bindings::sock_shutdown_cmd_SHUT_RDWR,
            );
            bindings::sock_release(self.socket.as_ptr());
        }
    }
}
