// SPDX-License-Identifier: GPL-2.0

//! Kernel random-byte generation.

use crate::bindings;

/// Fills a byte slice from the kernel random-number generator.
///
/// This does not wait for the generator to be initialized. Callers that require seeded
/// cryptographic randomness must arrange for initialization before using this function.
#[inline]
pub fn get_bytes(bytes: &mut [u8]) {
    // SAFETY: The exclusive slice is writable for exactly the requested number of bytes.
    // The C function retains no pointer and accepts a zero length.
    unsafe { bindings::get_random_bytes(bytes.as_mut_ptr().cast(), bytes.len()) };
}
