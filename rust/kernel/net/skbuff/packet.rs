// SPDX-License-Identifier: GPL-2.0

//! Packets with owned control metadata and allocation-free queue transfers.

use super::SkBuff;
use crate::{
    alloc::{
        AllocError,
        Flags, //
    },
    bindings,
    error::{
        code::EINVAL,
        Result, //
    },
    net::{
        Device,
        DeviceRef, //
    },
    prelude::*,
    types::Opaque, //
};
use core::{
    marker::PhantomData,
    mem::{
        align_of,
        offset_of,
        size_of,
        ManuallyDrop, //
    },
    ptr::NonNull, //
};

/// Metadata stored in an exclusively owned skb control buffer.
///
/// The device reference is separate from user metadata so replacing that metadata cannot
/// invalidate the non-owning `skb->dev` pointer.
#[derive(Clone)]
struct Control<T> {
    context: T,
    device: Option<DeviceRef>,
}

/// An exclusively owned socket buffer carrying a Rust value in its control buffer.
///
/// The metadata follows the packet through queue transfers. Cloning a packet clones its
/// metadata and network-device reference; shared packet bytes are made private before a Rust
/// borrow. Metadata must fit alongside one device reference in the 48-byte control buffer.
///
/// # Invariants
///
/// - `buffer` exclusively owns its header and an initialized `Control<T>` in `cb`.
/// - No C callback accesses `cb`. Header and fragment resources can be accessed and released
///   on another CPU without retaining the original caller's execution context.
/// - The packet has no destination attached; import releases its receive route.
/// - `Control::device` retains `skb->dev`, when non-null, until after the skb is freed.
/// - The range from the network header to `data` is within the linear allocation and initialized.
pub struct Packet<T> {
    buffer: ManuallyDrop<SkBuff>,
    _context: PhantomData<T>,
}

// SAFETY: The invariant makes C resources independent of the originating CPU or RCU section.
// Ownership transfers the exclusively accessible header and Send metadata together.
unsafe impl<T: Send> Send for Packet<T> {}
// SAFETY: Shared methods only read the private header and Sync metadata or copy packet bytes.
// Cloning, mutable metadata access and borrowing data all require exclusive access.
unsafe impl<T: Sync> Sync for Packet<T> {}

impl<T> Packet<T> {
    /// Allocates a zeroed packet without reserved headroom and installs its owned metadata.
    pub fn new(length: usize, context: T, flags: Flags) -> Result<Self> {
        let buffer = SkBuff::new(length, 0, flags)?;
        // SAFETY: This new packet has no headroom, so its network header starts at initialized
        // packet data. There are no device, destination or callback resources to retain.
        unsafe { bindings::skb_reset_network_header(buffer.as_raw()) };
        Ok(Self::install(
            buffer,
            Control {
                context,
                device: None,
            },
        ))
    }

    /// Takes ownership of a packet and installs new metadata in its control buffer.
    ///
    /// The receive destination is discarded while the caller's protection remains live.
    /// The network device is independently retained until the buffer has been freed. This
    /// packet owner provides payload and metadata access, not forwarding through its old route.
    ///
    /// # Safety
    ///
    /// - `skb` must satisfy [`SkBuff::from_raw`], transferring exclusive ownership to this call.
    /// - The entire range from the network header through `data` must be initialized and lie
    ///   within the linear allocation, with the network header at or before `data`.
    /// - The caller must retain any unreferenced destination under RCU during this call, and
    ///   retain a non-null `skb->dev` with protection that permits acquiring a device reference.
    /// - All other resources and callbacks must permit access, cloning and release from another
    ///   CPU, without requiring the original execution context or any external borrowed storage.
    /// - C callbacks must not access `cb`, and its previous contents must not own unreleased
    ///   Rust values. No ordinary Rust references may cover shared packet data.
    pub unsafe fn from_raw(skb: *mut bindings::sk_buff, context: T) -> Self {
        // SAFETY: The caller transfers the single header reference, initialized readable
        // packet bytes (including fragments), and required context.
        let buffer = unsafe { SkBuff::from_raw(skb) };
        // SAFETY: The caller retains the initialized header and any non-null device long
        // enough to acquire a reference. This reference outlives all access through this skb.
        let device = unsafe {
            let raw = (*skb)
                .__bindgen_anon_1
                .__bindgen_anon_1
                .__bindgen_anon_1
                .dev;
            NonNull::new(raw).map(|raw| Device::from_raw(raw.as_ptr()).to_ref())
        };
        // SAFETY: The caller retains the destination's required context through this call.
        // Drop the unused route now: a device reference does not keep its old namespace
        // services alive if the device subsequently moves to a different namespace.
        unsafe { bindings::skb_drop_receive_dst(skb) };
        // INVARIANT: Device lifetime is independently owned and no destination remains. The caller
        // supplies the remaining callback, initialization and CPU-independence guarantees.
        Self::install(buffer, Control { context, device })
    }

    /// Installs metadata after the caller has established the packet resource invariants.
    fn install(buffer: SkBuff, control: Control<T>) -> Self {
        const {
            assert!(size_of::<Control<T>>() <= 48);
            assert!(align_of::<Control<T>>() <= align_of::<bindings::sk_buff>());
            assert!(offset_of!(bindings::sk_buff, cb) % align_of::<Control<T>>() == 0);
        }
        // SAFETY: The caller owns this header and its cb, which is large and aligned enough.
        // The previous bytes do not own any Rust value, including a cloned bit-copy of cb.
        unsafe { Self::control_raw(buffer.as_raw()).write(control) };
        // INVARIANT: The caller has established the C resource invariants; cb now owns control.
        Self {
            buffer: ManuallyDrop::new(buffer),
            _context: PhantomData,
        }
    }

    #[inline]
    fn control_raw(skb: *mut bindings::sk_buff) -> *mut Control<T> {
        // SAFETY: All callers pass an exclusively owned live skb header. Forming this address
        // neither accesses its bytes nor creates a reference to the surrounding C header.
        unsafe { (&raw mut (*skb).cb).cast() }
    }

    /// Borrows the packet's owned metadata.
    #[inline]
    pub fn context(&self) -> &T {
        // SAFETY: The invariant initializes cb as Control<T>; the owner retains it for this
        // borrow and shared access cannot mutate or remove the value.
        unsafe { &(*Self::control_raw(self.buffer.as_raw())).context }
    }

    /// Mutably borrows the packet's owned metadata.
    #[inline]
    pub fn context_mut(&mut self) -> &mut T {
        // SAFETY: Exclusive access to the packet excludes every other access to its metadata.
        unsafe { &mut (*Self::control_raw(self.buffer.as_raw())).context }
    }

    /// Transfers the packet and its retained resources into a new metadata type.
    ///
    /// This neither allocates nor copies packet data. The closure owns the old metadata and
    /// returns its replacement, whose size must also fit the packet's control buffer.
    pub fn map_context<U>(self, map: impl FnOnce(T) -> U) -> Packet<U> {
        let mut old = ManuallyDrop::new(self);
        // SAFETY: Exclusive ownership permits moving the initialized control value once.
        // ManuallyDrop prevents the old packet from reading or destroying it again.
        let control = unsafe { Self::control_raw(old.buffer.as_raw()).read() };
        // SAFETY: Transfer the sole buffer owner. Its local drops before control.device on
        // an unwinding exit, preserving the retained device through buffer destruction.
        let buffer = unsafe { ManuallyDrop::take(&mut old.buffer) };
        let context = map(control.context);
        // INVARIANT: Packet resources and header positions are unchanged. Installation checks
        // the replacement metadata's size and alignment before overwriting the moved value.
        Packet::install(
            buffer,
            Control {
                context,
                device: control.device,
            },
        )
    }

    /// Borrows the independently retained network device, if present.
    #[inline]
    pub fn device(&self) -> Option<&Device> {
        // SAFETY: The invariant keeps the initialized control buffer and its device owner live.
        unsafe { (*Self::control_raw(self.buffer.as_raw())).device.as_deref() }
    }

    /// Returns the data length, including any non-linear fragments.
    #[inline]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns the packet's Ethernet protocol number in host byte order.
    #[inline]
    pub fn protocol(&self) -> u16 {
        // SAFETY: The header is exclusively owned, and shared methods never modify its protocol.
        u16::from_be(unsafe { bindings::skb_protocol_field(self.buffer.as_raw()) })
    }

    /// Returns the initialized prefix length from the network header to packet data.
    #[inline]
    pub fn network_header_len(&self) -> usize {
        let skb = self.buffer.as_raw();
        // SAFETY: Both pointers belong to the retained linear allocation, and the invariant
        // places the network header at or before data. The difference is nonnegative.
        unsafe { (*skb).data.offset_from(bindings::skb_network_header(skb)) as usize }
    }

    /// Returns whether the packet contains no data.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Copies a range of packet data without requiring exclusive access or linearization.
    #[inline]
    pub fn copy_bits(&self, offset: usize, output: &mut [u8]) -> Result {
        self.buffer.copy_bits(offset, output)
    }

    /// Consumes leading data while retaining it in the initialized network-header prefix.
    ///
    /// This may allocate with `GFP_ATOMIC` to pull fragment bytes into the linear allocation.
    /// Failure leaves the data position unchanged and retains ownership of every resource.
    pub fn pull(&mut self, length: usize) -> Result {
        if length > self.len() || length > c_int::MAX as usize {
            return Err(EINVAL);
        }
        c_int::try_from(self.len())?;
        let skb = self.buffer.as_raw();
        // SAFETY: Exclusive header ownership stabilizes both lengths. Header-only pulls do
        // not write bytes, so retain shared storage when the requested prefix is linear.
        let head_length = unsafe { (*skb).len - (*skb).data_len } as usize;
        if length > head_length {
            // Pulling fragments writes into the head; first detach independent page aliases.
            self.buffer.linearize()?;
        }
        // SAFETY: The requested bytes are now linear. Moving data forward preserves the
        // initialized prefix from the network header, without modifying owned cb metadata.
        unsafe { bindings::skb_pull(skb, length as u32) };
        Ok(())
    }

    /// Copies initialized bytes preceding packet data, starting at the network header.
    ///
    /// Returns [`EINVAL`] if the requested bytes extend past the current data pointer.
    pub fn copy_network_header(&self, output: &mut [u8]) -> Result {
        let skb = self.buffer.as_raw();
        // SAFETY: The invariant keeps the network header and data within one allocation, with
        // the network header at or before data. Both pointers are retained by this owner.
        let (header, length) = unsafe {
            let header = bindings::skb_network_header(skb);
            (header, (*skb).data.offset_from(header) as usize)
        };
        if output.len() > length {
            return Err(EINVAL);
        }
        // SAFETY: The checked range is initialized and within the owned linear allocation.
        // Copying allows COW data sharing without exposing an ordinary Rust reference.
        unsafe {
            output
                .as_mut_ptr()
                .copy_from_nonoverlapping(header, output.len())
        };
        Ok(())
    }

    /// Makes packet data private and linear, then borrows it alongside the owned metadata.
    ///
    /// This may allocate with `GFP_ATOMIC`. Failure retains the packet and its metadata.
    pub fn parts(&mut self) -> Result<(&mut T, &mut [u8])> {
        let control = Self::control_raw(self.buffer.as_raw());
        let data = self.buffer.data_mut()?;
        // SAFETY: cb is in the exclusive skb header, disjoint from packet data. Copy-on-write
        // may move data but never moves or modifies the header's initialized Rust metadata.
        Ok((unsafe { &mut (*control).context }, data))
    }

    /// Clones metadata and core references into a new header sharing the packet's data.
    ///
    /// Exclusive access is required because `skb_clone` may orphan fragments and updates the
    /// original header's cloned indication. Failure retains the original packet unchanged in
    /// ownership, though the networking core may have copied fragment storage.
    pub fn try_clone(&mut self, flags: Flags) -> Result<Self>
    where
        T: Clone,
    {
        // SAFETY: The owned metadata is initialized and stable for the duration of this clone.
        let control = unsafe { (&*Self::control_raw(self.buffer.as_raw())).clone() };
        // SAFETY: The invariant permits cloning all resources. Exclusive access excludes data
        // and metadata borrows while C updates the original header and copies the new header.
        let raw = unsafe { bindings::skb_clone(self.buffer.as_raw(), flags.as_raw()) };
        let raw = NonNull::new(raw).ok_or(AllocError)?;
        // SAFETY: The clone owns its header and independent core references. It inherits the
        // original packet's CPU-independent resources and initialized network header range.
        let buffer = unsafe { SkBuff::from_raw(raw.as_ptr()) };
        // Replace C's cb bit-copy without dropping it: only the original owns those references.
        Ok(Self::install(buffer, control))
    }

    /// Transfers both the skb and initialized control metadata to a private packet queue.
    #[inline]
    fn into_queued(self) -> *mut bindings::sk_buff {
        ManuallyDrop::new(self).buffer.as_raw()
    }

    /// Reconstructs an owner transferred by into_queued, without touching its control metadata.
    ///
    /// # Safety
    ///
    /// `skb` must be a packet of this type removed from its queue, with ownership transferred
    /// to the returned value and no other access to its header or metadata.
    #[inline]
    unsafe fn from_queued(skb: *mut bindings::sk_buff) -> Self {
        // INVARIANT: The queue preserves the packet's resources and initialized metadata.
        Self {
            // SAFETY: The caller transfers exclusive ownership of the dequeued header.
            buffer: ManuallyDrop::new(unsafe { SkBuff::from_raw(skb) }),
            _context: PhantomData,
        }
    }
}

impl<T> Drop for Packet<T> {
    fn drop(&mut self) {
        // SAFETY: This owner has exclusive access to initialized control metadata. Move it out
        // exactly once, keeping its resources alive through the C buffer destructor. No C
        // callback accesses cb, so leaving the moved value's old bytes there is harmless.
        let control = unsafe { Self::control_raw(self.buffer.as_raw()).read() };
        // SAFETY: The sole skb owner is released once, before dropping its retained device.
        unsafe { ManuallyDrop::drop(&mut self.buffer) };
        drop(control);
    }
}

/// A pinned, internally locked FIFO of owned packets.
///
/// Enqueue and dequeue allocate no additional storage. Removing a packet transfers its entire
/// ownership; no reference into a queued packet is exposed. Dropping the queue releases all
/// remaining packets outside its internal lock, in the context of the queue's destructor.
///
/// # Invariants
///
/// `queue` is initialized at its final address and owns every linked `Packet<T>`. Only the
/// networking core's locking queue functions access its links and length after initialization.
#[pin_data(PinnedDrop)]
pub struct Queue<T> {
    #[pin]
    queue: Opaque<bindings::sk_buff_head>,
    // Shared access can insert and remove T, so its lifetime must remain invariant.
    // Retain ownership tracking as well as the contravariant function argument.
    _context: PhantomData<(T, fn(T))>,
}

// SAFETY: Moving ownership preserves the pinned queue and transfers only Send packets.
unsafe impl<T: Send> Send for Queue<T> {}
// SAFETY: The C IRQ-safe queue lock serializes ownership transfers. No shared metadata borrow
// escapes that lock, so T only needs to be Send, not Sync.
unsafe impl<T: Send> Sync for Queue<T> {}

impl<T> Queue<T> {
    /// Initializes an empty queue at its final address.
    #[inline]
    pub fn new() -> impl PinInit<Self> {
        // INVARIANT: Initialization creates an empty queue before publication at a stable address.
        pin_init!(Self {
            queue <- Opaque::ffi_init(|raw| {
                // SAFETY: The initializer owns uninitialized, pinned queue storage.
                unsafe { bindings::skb_queue_head_init(raw) };
            }),
            _context: PhantomData,
        })
    }

    /// Transfers a packet and its metadata to the tail of this queue.
    #[inline]
    pub fn push(&self, packet: Packet<T>) {
        // SAFETY: The initialized queue remains pinned. The packet transfers its exclusive
        // header and metadata, is not already queued, and C holds the queue lock while linking.
        unsafe { bindings::skb_queue_tail(self.queue.get(), packet.into_queued()) };
    }

    /// Removes the oldest packet, transferring its ownership to the caller.
    #[inline]
    pub fn pop(&self) -> Option<Packet<T>> {
        // SAFETY: The queue is initialized and pinned; C serializes removal under its lock.
        let raw = unsafe { bindings::skb_dequeue(self.queue.get()) };
        NonNull::new(raw).map(|raw| {
            // SAFETY: Only packets of this type are enqueued. Removal transfers ownership,
            // and no other caller can borrow or remove this now-unlinked packet.
            unsafe { Packet::from_queued(raw.as_ptr()) }
        })
    }
}

#[pinned_drop]
impl<T> PinnedDrop for Queue<T> {
    fn drop(self: Pin<&mut Self>) {
        while let Some(packet) = self.pop() {
            drop(packet);
        }
    }
}

#[cfg(CONFIG_RUST_SKBUFF_KUNIT_TEST)]
#[macros::kunit_tests(rust_owned_packets)]
mod tests {
    use super::*;
    use crate::sync::atomic::{
        Atomic,
        Relaxed, //
    };

    static DROPPED: Atomic<u32> = Atomic::new(0);

    #[derive(Clone)]
    struct Context(u32);

    impl Drop for Context {
        fn drop(&mut self) {
            DROPPED.fetch_add(self.0, Relaxed);
        }
    }

    #[test]
    fn clones_and_queue_transfers_preserve_owned_metadata() -> Result {
        DROPPED.store(0, Relaxed);
        let queue = KBox::pin_init(Queue::new(), GFP_KERNEL)?;
        let mut first = Packet::new(4, Context(1), GFP_KERNEL)?;
        first.parts()?.1.copy_from_slice(b"body");
        let mut second = first.try_clone(GFP_KERNEL)?;
        second.context_mut().0 = 2;
        second.parts()?.1.copy_from_slice(b"copy");
        assert_eq!(first.parts()?.1, b"body");
        assert_eq!(second.parts()?.1, b"copy");
        assert!(first.copy_network_header(&mut [0]).is_err());
        queue.push(first);
        queue.push(second);
        assert_eq!(DROPPED.load(Relaxed), 0);
        let mut first = queue.pop().unwrap();
        assert_eq!(first.context().0, 1);
        assert_eq!(first.parts()?.1, b"body");
        drop(queue);
        assert_eq!(DROPPED.load(Relaxed), 2);
        drop(first);
        assert_eq!(DROPPED.load(Relaxed), 3);
        Ok(())
    }

    #[test]
    fn metadata_conversion_preserves_clone_and_drop_ownership() -> Result {
        struct Tracked<'a>(&'a Atomic<u32>);
        impl Drop for Tracked<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Relaxed);
            }
        }
        let dropped = Atomic::new(0);
        let mut original = Packet::new(4, (), GFP_KERNEL)?;
        original.parts()?.1.copy_from_slice(b"body");
        let clone = original.try_clone(GFP_KERNEL)?;
        let tracked = clone.map_context(|()| Tracked(&dropped));
        let mut converted = tracked.map_context(|context| {
            drop(context);
            7u64
        });
        assert_eq!(dropped.load(Relaxed), 1);
        assert_eq!(*converted.context(), 7);
        assert_eq!(converted.network_header_len(), 0);
        converted.parts()?.1.copy_from_slice(b"copy");
        assert_eq!(original.parts()?.1, b"body");
        assert_eq!(converted.parts()?.1, b"copy");
        drop(converted);
        drop(original);
        assert_eq!(dropped.load(Relaxed), 1);
        Ok(())
    }

    #[test]
    fn consuming_headers_preserves_prefix_and_cloned_data() -> Result {
        let mut packet = Packet::new(8, 17u32, GFP_KERNEL)?;
        packet.parts()?.1.copy_from_slice(b"headbody");
        let mut clone = packet.try_clone(GFP_KERNEL)?;
        packet.pull(4)?;
        assert_eq!(packet.network_header_len(), 4);
        assert_eq!(*packet.context(), 17);
        let mut header = [0; 4];
        packet.copy_network_header(&mut header)?;
        assert_eq!(&header, b"head");
        assert_eq!(packet.pull(usize::MAX), Err(EINVAL));
        assert_eq!(packet.network_header_len(), 4);
        packet.parts()?.1.copy_from_slice(b"copy");
        assert_eq!(packet.parts()?.1, b"copy");
        assert_eq!(clone.parts()?.1, b"headbody");
        packet.copy_network_header(&mut header)?;
        assert_eq!(&header, b"head");
        Ok(())
    }
}
