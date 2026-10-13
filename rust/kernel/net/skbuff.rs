// SPDX-License-Identifier: GPL-2.0

//! Owned socket buffers with bounded copy access.
//!
//! C header: [`include/linux/skbuff.h`](srctree/include/linux/skbuff.h)

use crate::{
    alloc::{
        AllocError,
        Flags, //
    },
    bindings,
    error::{
        code::EINVAL,
        to_result,
        Result, //
    },
    ffi::c_int, //
};
use core::{
    mem::ManuallyDrop,
    ptr::NonNull,
    slice, //
};

/// Owns a socket buffer whose header is not shared with other owners.
///
/// Its data may be cloned or stored in non-linear fragments. This interface copies bytes instead
/// of exposing references to shared data. [`Self::data_mut`] first makes the data private and
/// linear. Dropping the owner releases the header and its data references; [`Self::into_raw`]
/// transfers that responsibility back to C.
///
/// # Invariants
///
/// - `skb` owns the sole reference to a valid, initialized `struct sk_buff`.
/// - The header is exclusively accessible through this owner.
/// - All `skb->len` packet bytes, including non-linear fragments, are initialized and readable.
/// - Shared data and fragments follow the networking core's copy-on-write rules. They may be
///   accessed by C but must be made private before borrowing through ordinary Rust references.
/// - Any context needed to access or release the packet (e.g. an RCU read-side critical section
///   protecting an unreferenced destination) remains valid until ownership is returned or dropped.
pub struct SkBuff {
    skb: NonNull<bindings::sk_buff>,
}

impl SkBuff {
    /// Allocates a zeroed packet with space reserved before its data.
    ///
    /// The reserved headroom is not part of the packet data. Returns [`EINVAL`] if the total
    /// allocation cannot be represented by a C `int`.
    pub fn new(length: usize, headroom: usize, flags: Flags) -> Result<Self> {
        let total = length.checked_add(headroom).ok_or(EINVAL)?;
        let total = c_int::try_from(total)?;
        // SAFETY: The checked size also leaves room for the allocator's alignment and skb
        // shared-info overhead within the unsigned allocation size.
        let skb = unsafe { bindings::alloc_skb(total as u32, flags.as_raw()) };
        let skb = NonNull::new(skb).ok_or(AllocError)?;
        // SAFETY: The newly allocated header and storage are exclusively owned. Both lengths
        // fit the allocation and C arguments. Initialize all bytes before publishing ownership.
        unsafe {
            bindings::skb_reserve(skb.as_ptr(), headroom as c_int);
            bindings::skb_put(skb.as_ptr(), length as u32)
                .cast::<u8>()
                .write_bytes(0, length);
        }
        // INVARIANT: The allocation owns its header and initialized data, with no external
        // resources or context requirements.
        Ok(Self { skb })
    }

    /// Takes ownership of a packet delivered by the networking core.
    ///
    /// # Safety
    ///
    /// - `skb` must point to a valid, initialized `struct sk_buff` with a single reference.
    ///   The caller transfers that reference and exclusive access to the header to the returned
    ///   owner. This includes excluding access through a queue containing the header.
    /// - Every byte represented by `skb->len`, including non-linear fragments, must be
    ///   initialized and readable. Initializing the header alone does not establish this.
    /// - Shared data and fragments must obey the networking core's copy-on-write rules and must
    ///   not be borrowed through ordinary Rust references while this owner exists.
    /// - Any context required to access or free the packet must remain valid until the owner is
    ///   dropped or consumed by [`Self::into_raw`].
    #[inline]
    pub unsafe fn from_raw(skb: *mut bindings::sk_buff) -> Self {
        // SAFETY: The caller guarantees that `skb` points to a valid header, so it is non-null.
        let skb = unsafe { NonNull::new_unchecked(skb) };
        // INVARIANT: The caller transfers exclusive ownership and guarantees the data and context
        // requirements for the duration of that ownership.
        Self { skb }
    }

    /// Returns the packet length, including any non-linear fragments.
    #[inline]
    pub fn len(&self) -> usize {
        // SAFETY: The invariant keeps the skb header live and exclusively owned.
        unsafe { (*self.skb.as_ptr()).len as usize }
    }

    /// Returns whether the packet contains no data.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies a range of packet data, including non-linear fragments, into `output`.
    ///
    /// The output may have been partially changed if the network core reports
    /// an error. Its storage remains initialized on both success and failure.
    /// Returns [`EINVAL`] if the range is outside the packet or cannot be represented by C `int`.
    #[inline]
    pub fn copy_bits(&self, offset: usize, output: &mut [u8]) -> Result {
        c_int::try_from(self.len())?;
        let end = offset.checked_add(output.len()).ok_or(EINVAL)?;
        if end > self.len() {
            return Err(EINVAL);
        }
        let offset = c_int::try_from(offset)?;
        let length = c_int::try_from(output.len())?;
        // SAFETY: By the type invariants, the header and its fragments are valid. The checked
        // range is within the packet, and `output` is writable for `length` bytes. C handles
        // non-linear or externally shared data without exposing a Rust reference to it.
        to_result(unsafe {
            bindings::skb_copy_bits(
                self.skb.as_ptr(),
                offset,
                output.as_mut_ptr().cast(),
                length,
            )
        })
    }

    /// Pulls all packet data into the linear area, retaining ownership on error.
    ///
    /// This may allocate with `GFP_ATOMIC`. Success makes all packet bytes private, including
    /// page-backed heads shared independently of skb cloning.
    #[inline]
    pub fn linearize(&mut self) -> Result {
        c_int::try_from(self.len())?;
        // SAFETY: The owner has exclusive header access and bounds native signed lengths.
        // The helper detaches page aliases before copying fragments into the linear head.
        to_result(unsafe { bindings::skb_linearize_private(self.skb.as_ptr()) })
    }

    /// Makes all data private and linear, then lends its initialized bytes.
    ///
    /// This may allocate with `GFP_ATOMIC`; on failure this owner still holds the packet.
    /// The returned borrow prevents cloning, reallocation or transfer until it ends.
    /// Modifying bytes does not update protocol checksums or other packet metadata.
    #[inline]
    pub fn data_mut(&mut self) -> Result<&mut [u8]> {
        c_int::try_from(self.len())?;
        // SAFETY: The invariant provides sole header ownership and initialized packet bytes.
        // The helper also replaces page-backed heads, which can have independent page aliases
        // not recorded by skb_cloned(), before pulling fragments into private linear storage.
        to_result(unsafe { bindings::skb_linearize_private(self.skb.as_ptr()) })?;
        // SAFETY: Success leaves all initialized packet data in exclusive linear storage.
        // The borrow of this owner excludes any other access or operation that could move it.
        Ok(unsafe { slice::from_raw_parts_mut((*self.skb.as_ptr()).data, self.len()) })
    }

    /// Returns the reserved space before the packet's current data.
    #[inline]
    pub fn headroom(&self) -> usize {
        // SAFETY: Both pointers belong to the owned linear allocation, and data is at or after
        // head. The networking core keeps their difference within that allocation.
        unsafe {
            (*self.skb.as_ptr())
                .data
                .offset_from((*self.skb.as_ptr()).head) as usize
        }
    }

    /// Prepends initialized bytes using the packet's reserved headroom.
    ///
    /// Returns [`EINVAL`] without changing packet data if the header would overlap headroom
    /// metadata, does not fit, or the total length cannot be represented by C `int`.
    /// Making shared data private may allocate with
    /// `GFP_ATOMIC`; allocation failure retains ownership. Existing header offsets are preserved.
    /// The caller remains responsible for updating protocol lengths and checksums.
    pub fn prepend(&mut self, header: &[u8]) -> Result {
        if header.len() > self.headroom() {
            return Err(EINVAL);
        }
        c_int::try_from(self.len().checked_add(header.len()).ok_or(EINVAL)?)?;
        // SAFETY: The owned header and its shared-info metadata are valid. The checked headroom
        // keeps the proposed start in the allocation. Only integer addresses are compared.
        let overlaps_metadata = unsafe {
            let skb = self.skb.as_ptr();
            let length = usize::from(bindings::skb_metadata_len(skb));
            if length == 0 || header.is_empty() {
                false
            } else {
                let end = bindings::skb_metadata_end(skb) as usize;
                let data = (*skb).data as usize;
                data - header.len() < end && data > end - length
            }
        };
        if overlaps_metadata {
            return Err(EINVAL);
        }
        // The temporary borrow ends before extending the data range. Copy-on-write retains the
        // reserved headroom, and no part of the new header is exposed before initialization.
        self.data_mut()?;
        // SAFETY: The checked headroom covers the entire header, whose length fits C unsigned
        // int. The data is private, with no live Rust borrows. The input cannot alias the packet.
        unsafe {
            bindings::skb_push(self.skb.as_ptr(), header.len() as u32)
                .cast::<u8>()
                .copy_from_nonoverlapping(header.as_ptr(), header.len());
        }
        Ok(())
    }

    /// Returns the header pointer for interoperability with networking interfaces.
    ///
    /// The caller must preserve this owner's invariants. In particular, the header cannot be
    /// consumed or queued, and packet data cannot be accessed while a Rust data borrow is live.
    /// Use [`Self::into_raw`] to transfer ownership instead.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::sk_buff {
        self.skb.as_ptr()
    }

    /// Transfers the sole header reference back to the networking interface.
    ///
    /// The receiver must eventually consume or free the returned buffer.
    #[inline]
    pub fn into_raw(self) -> *mut bindings::sk_buff {
        ManuallyDrop::new(self).skb.as_ptr()
    }
}

impl Drop for SkBuff {
    fn drop(&mut self) {
        // SAFETY: The invariant owns the sole header reference and its fragment
        // references. There are no outstanding Rust borrows into packet data.
        unsafe { bindings::kfree_skb(self.skb.as_ptr()) };
    }
}

#[cfg(CONFIG_RUST_SKBUFF_KUNIT_TEST)]
#[macros::kunit_tests(rust_skbuff)]
mod tests {
    use super::*;
    use crate::{
        alloc::{
            flags::GFP_KERNEL,
            AllocError, //
        }, //
    };

    #[test]
    fn prepend_checks_headroom_and_unshares_data() -> Result {
        let mut packet = SkBuff::new(4, 4, GFP_KERNEL)?;
        packet.data_mut()?.copy_from_slice(b"body");
        // SAFETY: The packet is privately owned without context resources or live data borrows.
        let raw = unsafe { bindings::skb_clone(packet.as_raw(), GFP_KERNEL.as_raw()) };
        let raw = NonNull::new(raw).ok_or(AllocError)?;
        // SAFETY: The new header has a single reference and shares data under C's COW rules.
        let mut cloned = unsafe { SkBuff::from_raw(raw.as_ptr()) };
        assert!(cloned.prepend(b"large").is_err());
        assert_eq!(cloned.len(), 4);
        assert_eq!(cloned.headroom(), 4);
        cloned.prepend(b"head")?;
        assert_eq!(cloned.headroom(), 0);
        assert_eq!(cloned.data_mut()?, b"headbody");
        assert_eq!(packet.headroom(), 4);
        assert_eq!(packet.data_mut()?, b"body");
        packet.prepend(b"keep")?;
        assert_eq!(packet.data_mut()?, b"keepbody");
        assert_eq!(cloned.data_mut()?, b"headbody");
        Ok(())
    }

    #[test]
    fn prepend_preserves_live_headroom_metadata() -> Result {
        let mut packet = SkBuff::new(4, 8, GFP_KERNEL)?;
        packet.data_mut()?.copy_from_slice(b"body");
        // SAFETY: This fresh packet has exclusive initialized storage and eight headroom bytes.
        // Place metadata before a MAC header four bytes behind the current data pointer.
        unsafe {
            let raw = packet.as_raw();
            bindings::skb_set_mac_header(raw, -4);
            (*bindings::skb_shinfo(raw)).meta_len = 4;
            (*raw).head.copy_from_nonoverlapping(b"meta".as_ptr(), 4);
        }
        assert_eq!(packet.prepend(b"large"), Err(EINVAL));
        assert_eq!(packet.data_mut()?, b"body");
        packet.prepend(b"head")?;
        assert_eq!(packet.data_mut()?, b"headbody");
        assert_eq!(packet.prepend(b"x"), Err(EINVAL));
        // SAFETY: The metadata lies within the live exclusively owned head allocation.
        let length = unsafe { bindings::skb_metadata_len(packet.as_raw()) };
        assert_eq!(length, 4);
        // SAFETY: The metadata lies within the live exclusively owned head allocation.
        let metadata = unsafe { slice::from_raw_parts((*packet.as_raw()).head, 4) };
        assert_eq!(metadata, b"meta");
        Ok(())
    }

    #[test]
    fn allocation_and_private_clones() -> Result {
        assert!(SkBuff::new(usize::MAX, 1, GFP_KERNEL).is_err());
        assert!(SkBuff::new(c_int::MAX as usize, 1, GFP_KERNEL).is_err());
        let mut packet = SkBuff::new(11, 32, GFP_KERNEL)?;
        assert_eq!(packet.data_mut()?, &[0; 11]);
        packet.data_mut()?.copy_from_slice(b"packet data");
        // SAFETY: This exclusively owned header has no context-dependent resources or live
        // data borrows. The new header owns a reference to its shared, initialized data.
        let raw = unsafe { bindings::skb_clone(packet.skb.as_ptr(), GFP_KERNEL.as_raw()) };
        let raw = NonNull::new(raw).ok_or(AllocError)?;
        // SAFETY: The clone has a sole header reference and observes the copy-on-write rules.
        let mut cloned = unsafe { SkBuff::from_raw(raw.as_ptr()) };
        cloned.data_mut()?[..6].copy_from_slice(b"cloned");
        let mut original = [0; 11];
        packet.copy_bits(0, &mut original)?;
        assert_eq!(&original, b"packet data");
        assert_eq!(cloned.data_mut()?, b"cloned data");
        drop(packet);
        assert_eq!(cloned.data_mut()?, b"cloned data");
        assert!(SkBuff::new(0, 0, GFP_KERNEL)?.data_mut()?.is_empty());
        Ok(())
    }

    #[test]
    fn page_head_alias_is_detached_before_mutation() -> Result {
        use crate::page::PAGE_SIZE;

        // SAFETY: This test runs in process context and may allocate with GFP_KERNEL.
        let raw = unsafe { bindings::skb_test_page() };
        let raw = NonNull::new(raw).ok_or(AllocError)?;
        let length = PAGE_SIZE / 2;
        // SAFETY: Half a page fits before shared-info; initialize every packet byte.
        unsafe {
            bindings::skb_put(raw.as_ptr(), length as u32)
                .cast::<u8>()
                .write_bytes(b'a', length);
        }
        // SAFETY: The header and initialized page-backed data are exclusively owned.
        let mut source = unsafe { SkBuff::from_raw(raw.as_ptr()) };
        let alias = SkBuff::new(0, 0, GFP_KERNEL)?;
        // SAFETY: Both headers are exclusive with no data borrows. The destination has less
        // tailroom than the source length, so zero-copy retains the source head as a fragment.
        to_result(unsafe {
            bindings::skb_zerocopy(alias.as_raw(), source.as_raw(), length as c_int, 0)
        })?;
        // SAFETY: Only C page references were shared; the source is not an skb clone.
        assert_eq!(unsafe { (*source.as_raw()).cloned() }, 0);
        source.data_mut()?[0] = b'b';
        let mut original = [0; 1];
        alias.copy_bits(0, &mut original)?;
        assert_eq!(&original, b"a");
        assert_eq!(source.data_mut()?[0], b'b');
        Ok(())
    }

    #[test]
    fn linearization_preserves_independent_head_page_alias() -> Result {
        use crate::page::PAGE_SIZE;

        // SAFETY: The fixture returns exclusive page-backed storage in process context.
        let raw = NonNull::new(unsafe { bindings::skb_test_page() }).ok_or(AllocError)?;
        let length = PAGE_SIZE / 2;
        // SAFETY: Half the page fits before shared-info; initialize all visible bytes.
        unsafe {
            bindings::skb_put(raw.as_ptr(), length as u32)
                .cast::<u8>()
                .write_bytes(b'a', length);
        }
        // SAFETY: This header exclusively owns its initialized page-backed data.
        let mut source = unsafe { SkBuff::from_raw(raw.as_ptr()) };
        let alias = SkBuff::new(0, 0, GFP_KERNEL)?;
        // SAFETY: Both headers are exclusive. Export the head through independent page refs.
        to_result(unsafe {
            bindings::skb_zerocopy(alias.as_raw(), source.as_raw(), length as c_int, 0)
        })?;
        let mut fragment = SkBuff::new(4, 0, GFP_KERNEL)?;
        fragment.data_mut()?.copy_from_slice(b"tail");
        let fragment = fragment.into_raw();
        // SAFETY: Trim changes only header geometry, preserving the exported bytes. Attach
        // an exclusively owned initialized fragment without writing the shared head page.
        unsafe {
            bindings::skb_test_trim(source.as_raw(), 4);
            (*bindings::skb_shinfo(source.as_raw())).frag_list = fragment;
            (*source.as_raw()).len += (*fragment).len;
            (*source.as_raw()).data_len = (*fragment).len;
            (*source.as_raw()).truesize += (*fragment).truesize;
        }
        source.linearize()?;
        assert_eq!(source.data_mut()?, b"aaaatail");
        let mut original = [0; 8];
        alias.copy_bits(0, &mut original)?;
        assert_eq!(&original, b"aaaaaaaa");
        Ok(())
    }

    #[test]
    fn fragmented_clone_becomes_private() -> Result {
        let mut packet = SkBuff::new(4, 0, GFP_KERNEL)?;
        packet.data_mut()?.copy_from_slice(b"head");
        let mut fragment = SkBuff::new(4, 0, GFP_KERNEL)?;
        fragment.data_mut()?.copy_from_slice(b"tail");
        let fragment = fragment.into_raw();
        // SAFETY: Both headers and their data are exclusively owned and have no resources or
        // existing fragments. Transfer the second header to the first's frag_list and account
        // for its length and allocation. The skb destructor now owns both headers.
        unsafe {
            (*bindings::skb_shinfo(packet.skb.as_ptr())).frag_list = fragment;
            (*packet.skb.as_ptr()).len += (*fragment).len;
            (*packet.skb.as_ptr()).data_len = (*fragment).len;
            (*packet.skb.as_ptr()).truesize += (*fragment).truesize;
        }
        // SAFETY: No Rust data references exist. The clone shares the head and frag_list under
        // the networking core's reference counts and copy-on-write rules.
        let raw = unsafe { bindings::skb_clone(packet.skb.as_ptr(), GFP_KERNEL.as_raw()) };
        let raw = NonNull::new(raw).ok_or(AllocError)?;
        // SAFETY: The newly created clone owns its sole header reference, with no context needs.
        let mut cloned = unsafe { SkBuff::from_raw(raw.as_ptr()) };
        assert_eq!(cloned.data_mut()?, b"headtail");
        cloned.data_mut()?.fill(b'x');
        let mut original = [0; 8];
        packet.copy_bits(0, &mut original)?;
        assert_eq!(&original, b"headtail");
        drop(packet);
        assert_eq!(cloned.data_mut()?, b"xxxxxxxx");
        Ok(())
    }

    #[test]
    fn cloned_packet_ownership() -> Result {
        let data = b"packet data";
        // SAFETY: `alloc_skb` accepts this length and allocation flags.
        let raw = unsafe { bindings::alloc_skb(data.len() as u32, GFP_KERNEL.as_raw()) };
        let raw = NonNull::new(raw).ok_or(AllocError)?;
        // SAFETY: This is a newly allocated, uniquely owned header with no data or external
        // references. It does not carry context-dependent resources.
        let packet = unsafe { SkBuff::from_raw(raw.as_ptr()) };
        // SAFETY: The allocation has sufficient tailroom for `data`. We own the header, and the
        // destination is disjoint from `data` and writable for the whole copy.
        unsafe {
            let tail = bindings::skb_put(packet.skb.as_ptr(), data.len() as u32);
            tail.cast::<u8>()
                .copy_from_nonoverlapping(data.as_ptr(), data.len());
        }
        // SAFETY: We own this valid packet. Cloning only shares its data; no Rust references to
        // the data exist. No borrow of the Rust owner is live across the C call.
        let cloned = unsafe { bindings::skb_clone(packet.skb.as_ptr(), GFP_KERNEL.as_raw()) };
        let cloned = NonNull::new(cloned).ok_or(AllocError)?;
        // SAFETY: The clone is a separate, uniquely owned header. Both owners follow the C
        // copy-on-write rules for their shared data and have no context-dependent resources.
        let mut cloned = unsafe { SkBuff::from_raw(cloned.as_ptr()) };
        drop(packet);
        cloned.linearize()?;
        let mut copy = [0; 11];
        cloned.copy_bits(0, &mut copy)?;
        assert_eq!(&copy, data);
        assert!(cloned.copy_bits(1, &mut copy).is_err());
        assert_eq!(&copy, data);
        assert!(cloned.copy_bits(usize::MAX, &mut copy).is_err());
        cloned.copy_bits(cloned.len(), &mut [])?;
        let raw = cloned.into_raw();
        // SAFETY: `into_raw` transferred the live header and its last data reference to us.
        unsafe { bindings::kfree_skb(raw) };
        Ok(())
    }
}
