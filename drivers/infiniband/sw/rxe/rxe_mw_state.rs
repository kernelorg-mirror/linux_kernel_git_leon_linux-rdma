// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Memory-window binding policy and ownership.

#![forbid(unsafe_code)]

use super::{
    rxe_mr::MrRef,
    rxe_param::RXE_ACCESS_SUPPORTED_MW,
    rxe_qp::QpRef,
    rxe_version::Version, //
};
use kernel::{
    prelude::*,
    rdma::{
        Access,
        AccessFlags,
        MemoryWindowType as Kind, //
    },
    sync::{
        Arc,
        Mutex,
        MutexGuard, //
    },
};

pub(super) struct Bind {
    pub(super) window_key: u32,
    pub(super) region_key: u32,
    pub(super) new_key: u32,
    pub(super) access: AccessFlags,
    pub(super) address: u64,
    pub(super) length: u64,
}

/// One counted binding, retaining its region until the count is released.
struct BoundRegion {
    memory: MrRef,
}

impl Drop for BoundRegion {
    fn drop(&mut self) {
        self.memory.unbind_window();
    }
}

struct Binding {
    region: BoundRegion,
    qp: Option<QpRef>,
    access: AccessFlags,
    address: u64,
    length: u64,
}

struct State {
    key: u32,
    version: Version,
    binding: Option<Binding>,
}

/// A window owns every reference required by its current binding.
///
/// The per-window mutex serializes validation, replacement and snapshot acquisition. A
/// snapshot owns its region and revocation authority without borrowing the binding.
pub(super) struct WindowState {
    kind: Kind,
    pd: u32,
    state: State,
    active: Arc<Mutex<Option<Version>>>,
    retired: bool,
}

/// Retains the exclusion domain and publication of one window binding.
///
/// Memory operations hold this mutex through their actual access. Replacement and revocation
/// take the same mutex before returning, so completed revocation excludes every old access.
#[derive(Clone)]
pub(crate) struct Permission {
    active: Arc<Mutex<Option<Version>>>,
    version: Version,
}

impl Permission {
    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Option<Version>>> {
        let guard = self.active.lock();
        if *guard != Some(self.version) {
            return Err(EINVAL);
        }
        Ok(guard)
    }
}

/// A binding snapshot whose region remains live independently of the window.
pub(crate) struct Window {
    pub(crate) memory: MrRef,
    pub(crate) offset: u64,
    pub(crate) version: Version,
    address: u64,
    length: u64,
}

impl Window {
    /// Checks a translated virtual address against this binding's extent.
    pub(crate) fn check_range(&self, address: u64, length: u64) -> Result {
        if address < self.address
            || length > self.length
            || address - self.address > self.length - length
        {
            return Err(EINVAL);
        }
        Ok(())
    }
}

impl WindowState {
    pub(super) fn new(kind: Kind, pd: u32) -> Result<Self> {
        Ok(Self {
            kind,
            pd,
            active: Arc::pin_init(kernel::new_mutex!(None), GFP_KERNEL)?,
            retired: false,
            state: State {
                key: 0,
                version: Version::new()?,
                binding: None,
            },
        })
    }

    /// Assigns the reserved key before this uniquely owned window is published.
    pub(super) fn initialize(&mut self, key: u32) {
        self.state.key = key;
    }

    pub(super) fn bind(&mut self, qp: QpRef, memory: Option<MrRef>, request: Bind) -> Result {
        if u32::from(request.access) & !RXE_ACCESS_SUPPORTED_MW != 0 {
            return Err(EOPNOTSUPP);
        }
        let state = &mut self.state;
        if self.retired || state.key != request.window_key || qp.pd() != self.pd {
            return Err(EINVAL);
        }
        match self.kind {
            Kind::Type1 if request.access.contains(Access::ZeroBased) => return Err(EINVAL),
            Kind::Type2 if state.binding.is_some() || request.length == 0 => return Err(EINVAL),
            _ => (),
        }
        let version = if request.length == 0 {
            state.version
        } else {
            state.version.next()?
        };
        let binding = if request.length == 0 {
            None
        } else {
            let memory = memory.ok_or(EINVAL)?;
            memory.access().bind_window(
                self.pd,
                request.region_key,
                request.access,
                request.address,
                request.length,
            )?;
            Some(Binding {
                region: BoundRegion { memory },
                qp: if self.kind == Kind::Type2 {
                    Some(qp)
                } else {
                    None
                },
                access: request.access,
                address: request.address,
                length: request.length,
            })
        };
        // No new authorization becomes visible until old accesses have finished. The
        // registry IRQ lock is not held while this sleepable exclusion is acquired.
        let mut active = self.active.lock();
        *active = binding.as_ref().map(|_| version);
        state.key = (state.key & !0xff) | (request.new_key & 0xff);
        state.binding = binding;
        state.version = version;
        Ok(())
    }

    pub(super) fn invalidate(&mut self, pd: u32, key: u32) -> Result {
        let state = &mut self.state;
        if self.retired
            || self.kind != Kind::Type2
            || self.pd != pd
            || state.key != key
            || state.binding.is_none()
        {
            return Err(EINVAL);
        }
        let mut active = self.active.lock();
        *active = None;
        state.binding = None;
        Ok(())
    }

    pub(super) fn unbind_qp(&mut self, qp: u32) {
        if self
            .state
            .binding
            .as_ref()
            .and_then(|binding| binding.qp.as_ref())
            .is_some_and(|bound| bound.index() == qp)
        {
            self.revoke();
        }
    }

    fn revoke(&mut self) {
        let mut active = self.active.lock();
        *active = None;
        self.state.binding = None;
    }

    pub(super) fn release(&mut self) {
        self.retired = true;
        self.revoke();
    }

    pub(super) fn lookup(&self, pd: u32, qp: u32, key: u32, access: AccessFlags) -> Option<Window> {
        let state = &self.state;
        let binding = state.binding.as_ref()?;
        if self.retired
            || state.key != key
            || self.pd != pd
            || !binding.access.contains_all(access)
            || binding.qp.as_ref().is_some_and(|bound| bound.index() != qp)
            || !binding.region.memory.access().is_valid()
        {
            return None;
        }
        Some(Window {
            version: state.version,
            memory: binding.region.memory.clone().with_window(Permission {
                active: self.active.clone(),
                version: state.version,
            }),
            offset: if binding.access.contains(Access::ZeroBased) {
                binding.address
            } else {
                0
            },
            address: binding.address,
            length: binding.length,
        })
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_mw_access)]
mod tests {
    use super::*;
    use kernel::{
        sync::{
            atomic::{
                Atomic,
                Relaxed, //
            },
            Completion, //
        },
        workqueue::OwnedQueue, //
    };

    #[test]
    fn changed_binding_rejects_captured_authority() -> Result {
        let window = WindowState::new(Kind::Type1, 7)?;
        let old = Permission {
            active: window.active.clone(),
            version: window.state.version,
        };
        *window.active.lock() = Some(old.version);
        assert!(old.lock().is_ok());
        *window.active.lock() = Some(old.version.next()?);
        assert!(matches!(old.lock(), Err(EINVAL)));
        Ok(())
    }

    #[test]
    fn revocation_waits_for_memory_access_and_rejects_late_access() -> Result {
        let window = Arc::pin_init(
            kernel::new_mutex!(WindowState::new(Kind::Type1, 7)?),
            GFP_KERNEL,
        )?;
        let permission = {
            let state = window.lock();
            *state.active.lock() = Some(state.state.version);
            Permission {
                active: state.active.clone(),
                version: state.state.version,
            }
        };
        let queue = OwnedQueue::new_unbound(c"rxe_mw_access", 1)?;
        let started = Arc::pin_init(Completion::new(), GFP_KERNEL)?;
        let finished = Arc::new(Atomic::new(false), GFP_KERNEL)?;
        let access = permission.lock()?;
        let worker_started = started.clone();
        let worker_finished = finished.clone();
        queue.try_spawn(GFP_KERNEL, move || {
            worker_started.complete_all();
            window.lock().release();
            worker_finished.store(true, Relaxed);
        })?;
        started.wait_for_completion();
        assert!(!finished.load(Relaxed));
        drop(access);
        // Draining also keeps this module's worker code live through its final return.
        drop(queue);
        assert!(finished.load(Relaxed));
        assert!(matches!(permission.lock(), Err(EINVAL)));
        Ok(())
    }
}
