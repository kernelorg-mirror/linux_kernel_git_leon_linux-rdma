// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Native protection-domain identities retained by the RDMA core.

#![forbid(unsafe_code)]

use super::rxe_id::Identities;
use kernel::{
    prelude::*,
    sync::Mutex, //
};

/// Immutable identity used by MR, MW, QP and AH authorization checks.
///
/// The core owns this value until it destroys the domain after its child resources drain.
/// The identity is private to RXE and is never exposed as a userspace object handle.
pub(crate) struct Domain {
    index: u32,
}

impl Domain {
    pub(crate) fn index(&self) -> u32 {
        self.index
    }
}

/// Serializes identity allocation and release independently of transport lookups.
#[pin_data]
pub(crate) struct Domains {
    #[pin]
    state: Mutex<Identities>,
}

impl Domains {
    pub(crate) fn new(limit: u32) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            state <- kernel::new_mutex!(Identities::new(1, limit, limit)),
        })
    }

    pub(crate) fn allocate(&self) -> Result<KBox<Domain>> {
        // Allocate private storage first so failure cannot leak an acquired identity.
        let mut domain = KBox::new(Domain { index: 0 }, GFP_KERNEL)?;
        domain.index = self.state.lock().allocate()?;
        Ok(domain)
    }

    pub(crate) fn release(&self, domain: KBox<Domain>) {
        self.state.lock().release(domain.index);
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_pd)]
mod tests {
    use super::*;

    #[test]
    fn grow_wrap_and_reuse() -> Result {
        let domains = KBox::pin_init(Domains::new(66), GFP_KERNEL)?;
        let mut owners = KVec::with_capacity(66, GFP_KERNEL)?;
        for expected in 1..=66 {
            let domain = match domains.allocate() {
                Ok(domain) => domain,
                Err(error) => {
                    while let Some(domain) = owners.pop() {
                        domains.release(domain);
                    }
                    return Err(error);
                }
            };
            assert_eq!(domain.index(), expected);
            owners.push(domain, GFP_KERNEL)?;
        }
        assert!(matches!(domains.allocate(), Err(EINVAL)));
        // Free and reacquire the last ID across the bitmap's first growth boundary.
        domains.release(owners.pop().unwrap());
        let domain = match domains.allocate() {
            Ok(domain) => domain,
            Err(error) => {
                while let Some(domain) = owners.pop() {
                    domains.release(domain);
                }
                return Err(error);
            }
        };
        assert_eq!(domain.index(), 66);
        domains.release(domain);
        while let Some(domain) = owners.pop() {
            domains.release(domain);
        }
        let domain = domains.allocate()?;
        assert_eq!(domain.index(), 1);
        domains.release(domain);
        Ok(())
    }
}
