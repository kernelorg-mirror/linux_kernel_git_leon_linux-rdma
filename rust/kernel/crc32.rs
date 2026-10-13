// SPDX-License-Identifier: GPL-2.0

//! IEEE CRC-32 over initialized byte slices.
//!
//! C header: [`include/linux/crc32.h`](srctree/include/linux/crc32.h)

use crate::bindings;

/// Updates a least-significant-bit-first IEEE CRC-32 accumulator.
///
/// Neither the input accumulator nor the result is complemented. Callers
/// select the seed and final complement required by their wire format.
///
/// # Examples
///
/// ```
/// # #[cfg(CONFIG_CRC32 = "y")]
/// # {
/// use kernel::crc32;
///
/// assert_eq!(!crc32::le(!0, b"123456789"), 0xcbf4_3926);
/// assert_eq!(crc32::le(0x1234_5678, b""), 0x1234_5678);
/// # }
/// ```
// Inline into the caller so modular CRC support does not create a built-in dependency.
#[inline(always)]
#[doc(alias = "crc32_le")]
pub fn le(crc: u32, bytes: &[u8]) -> u32 {
    // SAFETY: The slice is initialized and readable for its complete length.
    // `crc32_le` only reads these bytes and does not retain the pointer.
    unsafe { bindings::crc32_le(crc, bytes.as_ptr().cast(), bytes.len()) }
}
