// SPDX-License-Identifier: GPL-2.0

//! Per-object rate limiting using the kernel's default interval and burst.
//!
//! C header: [`include/linux/ratelimit.h`](srctree/include/linux/ratelimit.h)

use crate::{
    bindings,
    str::{
        CStr,
        CStrExt as _, //
    },
    types::Opaque, //
};

use pin_init::{
    pin_data,
    pin_init,
    PinInit, //
};

/// A pinned rate limiter shared by callers of one logging site.
///
/// The kernel's default policy permits ten messages per five-second interval. Contention
/// may suppress additional messages. Suppression counts are reported by the C implementation
/// at the start of a later interval; this object does not request a report when dropped.
///
/// # Invariants
///
/// `inner` is initialized and pinned. Its interval and burst remain at their defaults, and
/// its release-reporting flag is never set. All runtime accesses use the C synchronization.
#[pin_data]
pub struct RateLimiter {
    #[pin]
    inner: Opaque<bindings::ratelimit_state>,
}

// SAFETY: The C state owns no thread-affine resource and all accesses use its synchronization.
unsafe impl Send for RateLimiter {}
// SAFETY: The C implementation serializes shared access using its raw spinlock and atomics.
unsafe impl Sync for RateLimiter {}

impl RateLimiter {
    /// Initializes a rate limiter at its final address using the kernel's default policy.
    pub fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            // INVARIANT: Initialization installs the raw lock, immutable defaults and zero flags.
            inner <- Opaque::ffi_init(|slot| {
                // SAFETY: The initializer exclusively owns the pinned, unpublished storage.
                unsafe { bindings::ratelimit_default_init(slot) };
            }),
        })
    }

    /// Returns whether the current message may be emitted.
    ///
    /// `site` identifies suppression reports. This operation may be called concurrently and
    /// with interrupts disabled; it does not sleep or retain the supplied string.
    #[inline]
    pub fn allow(&self, site: &CStr) -> bool {
        // SAFETY: The invariant retains initialized pinned state. The C implementation uses
        // internal synchronization and reads the valid, terminated site string only here.
        unsafe { bindings::___ratelimit(self.inner.get(), site.as_char_ptr()) != 0 }
    }
}
