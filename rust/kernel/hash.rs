// SPDX-License-Identifier: GPL-2.0

//! Non-cryptographic integer hashing.
//!
//! C header: [`include/linux/hash.h`](srctree/include/linux/hash.h)

/// Hashes a 32-bit integer to `BITS` bits using the architecture's kernel implementation.
///
/// `BITS` must be in `1..=32`; an invalid width fails to compile.
#[inline]
pub fn hash_32<const BITS: u32>(value: u32) -> u32 {
    crate::const_assert!(BITS > 0 && BITS <= u32::BITS);
    // SAFETY: The compile-time width check keeps the helper's shift within 0..32.
    unsafe { crate::bindings::hash_32(value, BITS) }
}
