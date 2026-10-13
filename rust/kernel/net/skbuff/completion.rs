// SPDX-License-Identifier: GPL-2.0

//! Revocable packet completion events with resident networking callbacks.

use super::SkBuff;
use crate::{
    alloc::Flags,
    bindings,
    net::{
        socket::{
            DatagramSocket,
            SockRef, //
        },
        Device,
        DeviceRef, //
    },
    prelude::*,
    rbtree::{
        RBTree,
        RBTreeNodeReservation, //
    },
    sync::{
        Arc,
        Refcount,
        SpinLockIrq, //
    },
    types::Opaque, //
};
use core::{
    marker::PhantomData,
    ptr::{
        self,
        NonNull, //
    }, //
};

/// An event consumed when networking releases a packet's socket ownership.
///
/// Completion and cancellation must not sleep, including when dropping fields. Completion
/// may precede transmission, for example when C orphans the packet. Registration shutdown
/// cancels outstanding events by dropping them without calling `complete`.
pub trait Event: Send + 'static {
    /// Completes one event, with no internal registration lock held.
    fn complete(self);
}

/// One uniquely owned event whose type is known by its consuming function.
///
/// # Invariants
///
/// `event` owns an allocation accepted by `finish`, which consumes it exactly once.
struct Pending {
    event: NonNull<c_void>,
    finish: unsafe fn(NonNull<c_void>, bool),
}

// SAFETY: The erased allocation contains a Send event and transfers unique ownership.
unsafe impl Send for Pending {}

impl Pending {
    fn new<T: Event>(event: T, flags: Flags) -> Result<Self> {
        let event = KBox::new(event, flags)?;
        // INVARIANT: The allocation and consuming function use the same event type.
        Ok(Self {
            event: NonNull::new(KBox::into_raw(event).cast()).unwrap(),
            finish: Self::finish::<T>,
        })
    }

    /// # Safety
    ///
    /// `event` must transfer the live KBox<T> allocated by `new` exactly once.
    unsafe fn finish<T: Event>(event: NonNull<c_void>, complete: bool) {
        // SAFETY: The caller transfers the unique allocation of the matching type.
        let event = unsafe { KBox::<T>::from_raw(event.as_ptr().cast()) };
        if complete {
            KBox::into_inner(event).complete();
        }
    }

    fn complete(self) {
        let event = self.event;
        let finish = self.finish;
        core::mem::forget(self);
        // SAFETY: Unique ownership and the invariant transfer the matching allocation.
        unsafe { finish(event, true) };
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        // SAFETY: Drop consumes the unique event without invoking its completion method.
        unsafe { (self.finish)(self.event, false) };
    }
}

/// Resident storage shared with packet headers after provider events have been revoked.
///
/// # Invariants
///
/// The count includes the registration and every pending or executing event. Closing removes
/// all pending events before releasing the registration count. No provider code runs after
/// the zero-count signal; packet headers retain only this nongeneric, resident allocation.
#[pin_data]
struct Inner {
    #[pin]
    pending: SpinLockIrq<Option<RBTree<usize, Pending>>>,
    users: Refcount,
    #[pin]
    drained: Opaque<bindings::completion>,
}

// SAFETY: Pending events are Send and serialized by the lock. The completion and reference
// count support concurrent operations, and Arc owners retain their pinned allocation.
unsafe impl Send for Inner {}
// SAFETY: All mutable accesses use the lock, atomic count or native completion operations.
unsafe impl Sync for Inner {}

impl Inner {
    fn put(&self) {
        if self.users.dec_and_test() {
            // SAFETY: Arc owners retain this initialized completion through signaling.
            unsafe { bindings::complete_all(self.drained.get()) };
        }
    }

    fn complete(&self, key: usize) {
        let event = Option::as_mut(&mut self.pending.lock()).and_then(|tree| tree.remove(&key));
        if let Some(event) = event {
            event.complete();
            self.put();
        }
    }

    fn shutdown(&self) {
        let pending = self.pending.lock().take();
        if let Some(mut pending) = pending {
            // Removal excludes new callbacks. Drop provider events outside the lock.
            while let Some(cursor) = pending.cursor_front_mut() {
                let (_, node) = cursor.remove_current();
                drop(node);
                self.put();
            }
            self.put();
        }
        // SAFETY: The Arc retains the initialized completion. Only callbacks which already
        // took an event can delay this wait; packets retained by networking cannot do so.
        unsafe { bindings::wait_for_completion(self.drained.get()) };
    }
}

/// Packet-owned resident storage, independent of provider code and event allocations.
struct Header {
    owner: Arc<Inner>,
    socket: Option<SockRef>,
    _device: Option<DeviceRef>,
}

/// Consumes the packet header's resident ownership exactly once.
///
/// # Safety
///
/// The caller transfers the destructor installed by `Completions::attach`, with a live,
/// exclusive skb header and its original shared-info completion argument.
unsafe extern "C" fn complete(skb: *mut bindings::sk_buff) {
    // SAFETY: attach installed a uniquely owned Header. Clones have no header destructor.
    unsafe {
        let shared = bindings::skb_shinfo(skb);
        let raw = (*shared).__bindgen_anon_2.destructor_arg.cast::<Header>();
        let header = KBox::<Header>::from_raw(raw);
        // Clones may still copy the inert shared-info argument, but cannot consume it.
        (*skb).__bindgen_anon_3.__bindgen_anon_1.destructor = None;
        (*skb).sk = ptr::null_mut();
        header.owner.complete(raw as usize);
        // The independent socket reference remains live throughout event completion.
    }
}

/// Owns revocable packet events and drains callbacks already executing provider code.
///
/// Destruction cancels pending events even when networking retains their packets. It requires
/// sleepable context without locks needed by an event, and must not run from its own event.
/// Packet destruction after shutdown invokes only resident code and releases resident storage.
///
/// Packet release and orphaning acquire a native `spinlock_t`. Their execution context must
/// permit that lock acquisition. Release while holding a raw spinlock is unsupported, including
/// on non-RT kernels with raw-lock nesting checks. On PREEMPT_RT, direct release from hardirq
/// or with interrupts disabled is also unsupported. Native owners must defer release to a
/// permitted context, as the networking IRQ-safe release helpers do.
pub struct Completions<T: Event> {
    inner: Arc<Inner>,
    _event: PhantomData<fn(T)>,
}

impl<T: Event> Completions<T> {
    /// Allocates an idle completion registration.
    pub fn new() -> Result<Self> {
        // INVARIANT: The registration owns the initial count, and publishes no event until
        // both the pending registry and completion have been initialized at pinned addresses.
        let inner = Arc::pin_init(
            pin_init!(Inner {
                pending <- crate::new_spinlock_irq!(Some(RBTree::new())),
                users: Refcount::new(1),
                drained <- Opaque::ffi_init(|raw| {
                    // SAFETY: The initializer owns uninitialized pinned completion storage.
                    unsafe { bindings::init_completion(raw) };
                }),
            }),
            GFP_KERNEL,
        )?;
        Ok(Self {
            inner,
            _event: PhantomData,
        })
    }

    /// Prevents new events, cancels pending events and waits for executing callbacks.
    ///
    /// This may sleep and has the same context restrictions as destruction. Repeated calls
    /// are allowed. A later packet release does not invoke a cancelled event.
    #[inline]
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    /// Installs an event and optional independent socket and device references on a packet.
    ///
    /// Socket and device references survive event cancellation until packet release or
    /// orphaning. They protect native packet ownership independently of provider callbacks.
    /// This does not set `skb->dev` or retain its target for clones or an orphaned packet;
    /// native owners must independently protect any device pointer those headers still use.
    /// A socket reference is not write-memory ownership: native consumers must not charge
    /// `sk_wmem_alloc` for this packet as they do for normal socket output.
    ///
    /// Returns EINVAL if the packet already has socket ownership, a header destructor or
    /// zero-copy state, and ENODEV after shutdown. Failure retains the packet and drops the
    /// event without completing it. Packet data is made private and linear before reusing its
    /// shared-info argument, which may allocate with GFP_ATOMIC in addition to `flags`.
    /// Cloning does not duplicate the event. Release or orphaning completes an installed
    /// event unless registration shutdown has already cancelled it.
    ///
    /// Native consumers must preserve the installed destructor and shared-info argument until
    /// release or orphaning. They must orphan the packet before replacing that argument with
    /// zero-copy ownership or handing it to GRO without `skb_prepare_for_gro`. These operations
    /// are not exposed by the safe [`SkBuff`] methods.
    pub fn attach(
        &self,
        packet: &mut SkBuff,
        socket: Option<&DatagramSocket>,
        device: Option<&Device>,
        event: T,
        flags: Flags,
    ) -> Result {
        let skb = packet.as_raw();
        // SAFETY: The packet owns initialized header and shared-info storage.
        let occupied = unsafe {
            !(*skb).sk.is_null()
                || (*skb)
                    .__bindgen_anon_3
                    .__bindgen_anon_1
                    .destructor
                    .is_some()
                || u32::from((*bindings::skb_shinfo(skb)).flags) & bindings::SKBFL_ZEROCOPY_ENABLE
                    != 0
        };
        if occupied {
            return Err(EINVAL);
        }
        packet.data_mut()?;
        let node = RBTreeNodeReservation::new(flags)?;
        let event = Pending::new(event, flags)?;
        let header = KBox::new(
            Header {
                owner: self.inner.clone(),
                socket: socket.map(DatagramSocket::to_ref),
                _device: device.map(Device::to_ref),
            },
            flags,
        )?;
        let key = ptr::from_ref(&*header) as usize;
        let mut pending = self.inner.pending.lock();
        let tree = Option::as_mut(&mut pending).ok_or(ENODEV)?;
        self.inner.users.inc();
        tree.insert(node.into_node(key, event));
        // SAFETY: Exclusive packet ownership and COW provide private shared-info storage.
        // The header and event are initialized before publishing the resident destructor.
        unsafe {
            (*skb).sk = header
                .socket
                .as_ref()
                .map_or(ptr::null_mut(), SockRef::as_raw);
            (*bindings::skb_shinfo(skb)).__bindgen_anon_2.destructor_arg =
                KBox::into_raw(header).cast();
            (*skb).__bindgen_anon_3.__bindgen_anon_1.destructor = Some(complete);
        }
        Ok(())
    }
}

impl<T: Event> Drop for Completions<T> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(all(CONFIG_RUST_SKBUFF_KUNIT_TEST, CONFIG_INET))]
#[macros::kunit_tests(rust_packet_completions)]
mod tests {
    use super::*;
    use crate::{
        net::namespace::Namespace,
        net::socket::Family,
        sync::atomic::{
            Atomic,
            Relaxed, //
        }, //
    };

    static COMPLETED: Atomic<u32> = Atomic::new(0);
    static DROPPED: Atomic<u32> = Atomic::new(0);

    struct Finished;

    impl Event for Finished {
        fn complete(self) {
            COMPLETED.fetch_add(1, Relaxed);
        }
    }

    impl Drop for Finished {
        fn drop(&mut self) {
            DROPPED.fetch_add(1, Relaxed);
        }
    }

    #[test]
    fn socket_free_events_complete_on_orphaning() -> Result {
        struct Orphaned;
        impl Event for Orphaned {
            fn complete(self) {
                ORPHANED.fetch_add(1, Relaxed);
            }
        }
        static ORPHANED: Atomic<u32> = Atomic::new(0);
        ORPHANED.store(0, Relaxed);
        let completions = Completions::new()?;
        let mut packet = SkBuff::new(4, 0, GFP_KERNEL)?;
        completions.attach(&mut packet, None, None, Orphaned, GFP_KERNEL)?;
        // SAFETY: The exclusive packet has initialized header ownership; orphaning consumes
        // only its registered event, leaving the buffer owned by this test.
        unsafe { bindings::skb_orphan(packet.as_raw()) };
        assert_eq!(ORPHANED.load(Relaxed), 1);
        drop(packet);
        drop(completions);
        assert_eq!(ORPHANED.load(Relaxed), 1);
        Ok(())
    }

    #[test]
    fn shutdown_revokes_events_while_packets_and_clones_remain_alive() -> Result {
        COMPLETED.store(0, Relaxed);
        DROPPED.store(0, Relaxed);
        let socket = DatagramSocket::new(Namespace::initial(), Family::Ipv4)?;
        let completions = Completions::new()?;
        let mut packet = SkBuff::new(4, 0, GFP_KERNEL)?;
        completions.attach(&mut packet, Some(&socket), None, Finished, GFP_KERNEL)?;
        assert!(completions
            .attach(&mut packet, Some(&socket), None, Finished, GFP_KERNEL)
            .is_err());
        drop(socket);
        // SAFETY: Exclusive access excludes packet borrows. The registered event and socket
        // own their resources, and C clones clear the socket and header destructor fields.
        let raw = unsafe { bindings::skb_clone(packet.as_raw(), GFP_KERNEL.as_raw()) };
        let raw = NonNull::new(raw).ok_or(ENOMEM)?;
        // SAFETY: The clone owns one header reference and independently releasable data.
        let clone = unsafe { SkBuff::from_raw(raw.as_ptr()) };
        assert_eq!(COMPLETED.load(Relaxed), 0);
        completions.shutdown();
        let mut another = SkBuff::new(4, 0, GFP_KERNEL)?;
        assert!(completions
            .attach(&mut another, None, None, Finished, GFP_KERNEL)
            .is_err());
        assert_eq!(DROPPED.load(Relaxed), 3);
        drop(completions);
        drop(packet);
        drop(clone);
        assert_eq!(COMPLETED.load(Relaxed), 0);
        assert_eq!(DROPPED.load(Relaxed), 3);
        Ok(())
    }
}
