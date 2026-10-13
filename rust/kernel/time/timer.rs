// SPDX-License-Identifier: GPL-2.0

//! Owned jiffy timers which transfer an event to each expiration.

use super::Jiffies;
use crate::{
    bindings,
    prelude::*,
    str::CStr,
    sync::{
        LockClassKey,
        SpinLockIrq, //
    },
    types::Opaque, //
};

/// An owned event consumed by a timer expiration.
///
/// Expiration runs in timer softirq context and must not sleep, including when dropping
/// event fields. An event may retain asynchronous resources until expiry or cancellation.
pub trait Event: Send + 'static {
    /// Handles one expiration, after the timer's event lock has been released.
    fn expire(self, context: Context<'_>);
}

/// A timer retained throughout the current expiration callback.
pub struct Context<'a> {
    timer: &'a Opaque<bindings::timer_list>,
}

impl Context<'_> {
    /// Returns whether a new expiration has been queued.
    ///
    /// This is an observation, not synchronization with another CPU's rearm operation.
    /// Callers needing a stable result must serialize their rearm and expiry decisions.
    #[inline]
    pub fn is_pending(&self) -> bool {
        // SAFETY: The timer owner synchronizes destruction with this callback. The C helper
        // uses a lockless read and does not require exclusive access to the timer.
        unsafe { bindings::timer_pending(self.timer.get()) }
    }
}

struct State<T> {
    event: Option<T>,
    closed: bool,
}

// Events move into callbacks or back to the owner; the slot never structurally pins them.
impl<T> Unpin for State<T> {}

/// Pinned storage kept allocated until the C timer callback has returned.
///
/// # Invariants
///
/// The timer is initialized before publication. Only `Timer<T>` owns this storage, and its
/// destructor synchronously shuts the timer down before dropping the box. Arming, event
/// replacement and callback admission are serialized by `state`.
#[pin_data]
struct Inner<T: Event> {
    #[pin]
    timer: Opaque<bindings::timer_list>,
    #[pin]
    state: SpinLockIrq<State<T>>,
}

// SAFETY: The timer API serializes its opaque fields, and the IRQ lock protects the Send event.
// Moving ownership moves only a pinned allocation's handle; callbacks retain its storage.
unsafe impl<T: Event> Send for Inner<T> {}
// SAFETY: Shared methods serialize event access and never expose a mutable timer reference.
unsafe impl<T: Event> Sync for Inner<T> {}

impl<T: Event> Inner<T> {
    /// Consumes the event admitted by the timer core.
    ///
    /// # Safety
    ///
    /// `raw` must point to the initialized timer field of a live, pinned `Self`.
    /// The caller must follow the timer core callback serialization rules.
    unsafe extern "C" fn expire(raw: *mut bindings::timer_list) {
        // SAFETY: The timer is the pinned field installed by Timer::new. Its owner waits for
        // this callback before freeing the allocation or starting destruction of its fields.
        let inner = unsafe { &*crate::container_of!(raw.cast::<Opaque<_>>(), Self, timer) };
        let event = {
            let mut state = inner.state.lock();
            // An old callback may begin after another CPU has rearmed the timer. In that case
            // the new event belongs to the pending expiration and must remain in the slot.
            // SAFETY: The timer is live; all rearming holds this same state lock.
            if state.closed || unsafe { bindings::timer_pending(inner.timer.get()) } {
                None
            } else {
                state.event.take()
            }
        };
        if let Some(event) = event {
            event.expire(Context {
                timer: &inner.timer,
            });
        }
    }
}

/// One independently owned jiffy timer, without shared ownership of its allocation.
///
/// Arming replaces the pending event and returns the displaced owner. Expiration consumes
/// the event outside the internal lock. Cancellation and shutdown return any unconsumed event
/// so the caller controls where it is released.
///
/// Shutdown and drop wait for a running callback and require sleepable context without locks
/// needed by that callback. They must not run from the timer's own callback. In particular,
/// an event must not release the last owner of its own timer during expiration.
pub struct Timer<T: Event> {
    inner: Pin<KBox<Inner<T>>>,
}

// Generic callers may live in modules. Keep the name beside its class in the kernel crate:
// lockdep compares name pointers, so identical literals in separate images are insufficient.
#[inline(never)]
fn state_lock_class() -> (&'static CStr, Pin<&'static LockClassKey>) {
    (c"rust timer state", crate::sync::static_lock_class!())
}

impl<T: Event> Timer<T> {
    /// Allocates and initializes an idle timer with a static lockdep name and class.
    pub fn new(name: &'static CStr, class: Pin<&'static LockClassKey>) -> Result<Self> {
        let (state_name, state_class) = state_lock_class();
        // INVARIANT: The initializer installs the callback at a stable address before this
        // owner is published. No fallible step follows C initialization, and Drop drains it.
        let inner = KBox::pin_init(
            pin_init!(Inner {
                state <- SpinLockIrq::new(State { event: None, closed: false },
                                         state_name, state_class),
                timer <- Opaque::ffi_init(|raw| {
                    // SAFETY: The initializer owns pinned, uninitialized timer storage. The
                    // callback, name and class remain live while the initialized timer exists.
                    unsafe {
                        bindings::timer_init_key(raw, Some(Inner::<T>::expire), 0,
                                                name.as_char_ptr(), class.as_ptr())
                    };
                }),
            }),
            GFP_KERNEL,
        )?;
        Ok(Self { inner })
    }

    /// Arms an expiration after `delay` jiffies and returns the displaced pending event.
    ///
    /// Delays are capped at `MAX_JIFFY_OFFSET` to leave headroom for signed deadline comparisons.
    /// The timer wheel may further round or shorten long delays.
    /// Once shutdown starts, the supplied event is returned without arming the timer.
    /// A callback already admitted may finish concurrently with replacement.
    pub fn arm(&self, delay: Jiffies, event: T) -> Option<T> {
        let mut state = self.inner.state.lock();
        if state.closed {
            return Some(event);
        }
        let previous = state.event.replace(event);
        // SAFETY: The initialized timer remains pinned. The state lock serializes rearming
        // with event replacement and callback admission; wrapping arithmetic matches jiffies.
        // Delete first so mod_timer cannot use a stale pending same-bucket fast path after
        // the timer core has detached an old expiration. A running old callback waits for
        // this lock, then observes the newly pending timer and leaves its event untouched.
        unsafe {
            bindings::timer_delete(self.inner.timer.get());
            bindings::mod_timer(
                self.inner.timer.get(),
                bindings::read_jiffies().wrapping_add(delay.min(bindings::MAX_JIFFY_OFFSET)),
            );
        }
        previous
    }

    /// Returns whether an expiration is queued, without waiting for a running callback.
    #[inline]
    pub fn is_pending(&self) -> bool {
        Context {
            timer: &self.inner.timer,
        }
        .is_pending()
    }

    /// Removes the queued expiration and returns its event without waiting for a callback.
    ///
    /// A callback already admitted continues running; the timer can be armed again.
    #[inline]
    pub fn cancel(&self) -> Option<T> {
        let mut state = self.inner.state.lock();
        // SAFETY: The timer is initialized and retained, and rearming holds the state lock.
        // Non-synchronous deletion does not wait for a callback which may need that lock.
        unsafe { bindings::timer_delete(self.inner.timer.get()) };
        state.event.take()
    }

    /// Permanently stops arming, drains the callback and returns any unconsumed event.
    ///
    /// The caller must be able to sleep and must not hold locks needed by the callback.
    #[inline]
    pub fn shutdown(&self) -> Option<T> {
        let event = {
            let mut state = self.inner.state.lock();
            state.closed = true;
            state.event.take()
        };
        // SAFETY: The owner retains initialized storage. Arming is now excluded, and the
        // callback can acquire state while synchronous shutdown waits for its return.
        unsafe { bindings::timer_shutdown_sync(self.inner.timer.get()) };
        event
    }
}

impl<T: Event> Drop for Timer<T> {
    fn drop(&mut self) {
        // Synchronize before the inner Box's destructor begins: callbacks borrow Inner,
        // whereas this exclusive borrow covers only the outer owner and its pointer field.
        drop(self.shutdown());
    }
}

#[cfg(CONFIG_RUST_KUNIT_TESTS)]
#[crate::macros::kunit_tests(rust_owned_timer)]
mod tests {
    use super::*;
    use crate::{
        sync::atomic::{
            Atomic,
            Relaxed, //
        },
        time::{
            delay::fsleep,
            msecs_to_jiffies,
            Delta, //
        }, //
    };

    static FIRED: Atomic<u32> = Atomic::new(0);
    static DROPPED: Atomic<u32> = Atomic::new(0);

    struct Recorded(u32);

    impl Event for Recorded {
        fn expire(self, _context: Context<'_>) {
            FIRED.fetch_add(1 << self.0, Relaxed);
        }
    }

    impl Drop for Recorded {
        fn drop(&mut self) {
            DROPPED.fetch_add(1 << self.0, Relaxed);
        }
    }

    #[test]
    fn replacement_expiry_cancel_and_shutdown_release_ownership() -> Result {
        FIRED.store(0, Relaxed);
        DROPPED.store(0, Relaxed);
        let timer = Timer::new(c"owned timer test", crate::static_lock_class!())?;
        let later = msecs_to_jiffies(10_000);
        assert!(timer.arm(later, Recorded(0)).is_none());
        assert!(timer.is_pending());
        let previous = timer.arm(later, Recorded(1)).unwrap();
        assert_eq!(previous.0, 0);
        assert_eq!(DROPPED.load(Relaxed), 0);
        drop(previous);
        let cancelled = timer.cancel().unwrap();
        assert_eq!(cancelled.0, 1);
        assert!(!timer.is_pending());
        drop(cancelled);

        assert!(timer.arm(1, Recorded(2)).is_none());
        for _ in 0..1000 {
            if FIRED.load(Relaxed) != 0 {
                break;
            }
            fsleep(Delta::from_millis(1));
        }
        assert!(timer.shutdown().is_none());
        assert_eq!(FIRED.load(Relaxed), 1 << 2);
        assert_eq!(DROPPED.load(Relaxed), 0b111);
        let rejected = timer.arm(1, Recorded(3)).unwrap();
        assert_eq!(rejected.0, 3);
        assert!(!timer.is_pending());
        drop(rejected);
        drop(timer);

        let timer = Timer::new(c"owned pending timer test", crate::static_lock_class!())?;
        assert!(timer.arm(later, Recorded(4)).is_none());
        drop(timer);
        assert_eq!(FIRED.load(Relaxed), 1 << 2);
        assert_eq!(DROPPED.load(Relaxed), 0b11111);
        Ok(())
    }
}
