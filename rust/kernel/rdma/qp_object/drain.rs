// SPDX-License-Identifier: GPL-2.0

//! Native drain sentinels backed by capability storage reserved at QP creation.

use super::{
    PostingOutcome,
    QueuePairOperations,
    QueuePairs,
    ReceiveRequests,
    SendRequests, //
};
use crate::{
    bindings,
    error::to_result,
    prelude::*,
    types::{
        Opaque,
        ScopeGuard, //
    }, //
};
use core::ptr;

/// Encodes the callback using the native union's byte layout, including on 32-bit big endian.
#[inline]
fn callback_value(cqe: *mut bindings::ib_cqe) -> u64 {
    let mut value = bindings::ib_wc__bindgen_ty_1 { wr_id: 0 };
    value.wr_cqe = cqe;
    // SAFETY: The full union was initialized through wr_id before the narrower pointer write.
    // Reading its scalar member preserves the pointer's placement without uninitialized bytes.
    unsafe { value.wr_id }
}

/// The callback receives the first field, and the pinned stack owner survives its completion.
#[repr(C)]
struct Wait {
    cqe: bindings::ib_cqe,
    done: Opaque<bindings::completion>,
}

impl Wait {
    /// # Safety
    ///
    /// `wc` must contain a pointer to the first field of this initialized, retained wait.
    unsafe extern "C" fn complete(_cq: *mut bindings::ib_cq, wc: *mut bindings::ib_wc) {
        // SAFETY: Only this drain supplies this callback and a pointer to its pinned first
        // field. Its owner waits for completion before releasing the stack allocation.
        unsafe {
            let this = (*wc).__bindgen_anon_1.wr_cqe.cast::<Self>();
            bindings::complete((*this).done.get());
        }
    }

    /// # Safety
    ///
    /// The caller retains this initialized wait and the core-allocated CQ until return.
    #[inline(always)]
    unsafe fn wait(&self, cq: *mut bindings::ib_cq) {
        // SAFETY: The drain contract retains the CQ and excludes competing direct polling.
        // As in the native drain helper, a direct CQ needs this task to reap its sentinel.
        unsafe {
            if (*cq).poll_ctx == bindings::ib_poll_context_IB_POLL_DIRECT {
                while bindings::wait_for_completion_timeout(
                    self.done.get(),
                    crate::time::msecs_to_jiffies(100),
                ) == 0
                {
                    bindings::ib_process_cq_direct(cq, -1);
                }
            } else {
                bindings::wait_for_completion(self.done.get());
            }
        }
    }
}

impl<T: QueuePairOperations> QueuePairs<T> {
    /// # Safety
    ///
    /// The native drain contract retains this kernel QP and its ib_alloc_cq parents, reserves
    /// space for one request/completion, excludes other posting and permits sleeping.
    pub(super) unsafe extern "C" fn drain_send(core: *mut bindings::ib_qp) {
        // SAFETY: The native caller satisfies the complete drain contract above.
        if let Err(error) = unsafe { Self::drain(core, false) } {
            pr_warn!("failed to drain send queue: {}\n", error.to_errno());
        }
    }

    /// # Safety
    ///
    /// The native drain contract retains a kernel QP with a private RQ and its ib_alloc_cq
    /// parent, reserves one request/completion, excludes other posting and permits sleeping.
    pub(super) unsafe extern "C" fn drain_receive(core: *mut bindings::ib_qp) {
        // SAFETY: The native caller satisfies the complete drain contract above.
        if let Err(error) = unsafe { Self::drain(core, true) } {
            pr_warn!("failed to drain receive queue: {}\n", error.to_errno());
        }
    }

    /// # Safety
    ///
    /// The caller satisfies the corresponding native SQ or private-RQ drain contract.
    unsafe fn drain(core: *mut bindings::ib_qp, receive: bool) -> Result {
        // SAFETY: The caller retains this adapter's initialized QP and its native parents.
        let qp = unsafe { Self::borrow(core) };
        let control = qp.identity.drain_control(receive);
        let mut attributes = bindings::ib_qp_attr {
            qp_state: bindings::ib_qp_state_IB_QPS_ERR,
            ..Default::default()
        };
        // SAFETY: The retained QP is modified in sleepable context with initialized state.
        to_result(unsafe {
            bindings::ib_modify_qp(
                core,
                &mut attributes,
                bindings::ib_qp_attr_mask_IB_QP_STATE as c_int,
            )
        })?;

        let wait = core::pin::pin!(Wait {
            cqe: bindings::ib_cqe {
                done: Some(Wait::complete),
            },
            done: Opaque::uninit(),
        });
        // SAFETY: The completion is initialized in its pinned, exclusively owned stack slot.
        unsafe { bindings::init_completion(wait.done.get()) };
        let cqe = ptr::from_ref(&wait.cqe).cast_mut();
        let posting = qp.identity.begin_post()?;
        let completion = control.capture(&qp.identity, receive, callback_value(cqe))?;
        // Revocation also covers provider rejection before acceptance. An accepted request
        // reaches wait below even when the provider subsequently reports an error.
        let _revoke = ScopeGuard::new(|| control.revoke());
        let outcome = PostingOutcome::new(None);
        let result = if receive {
            let request = bindings::ib_recv_wr {
                __bindgen_anon_1: bindings::ib_recv_wr__bindgen_ty_1 { wr_cqe: cqe },
                ..Default::default()
            };
            let mut bad = ptr::null();
            // SAFETY: The initialized descriptor-free sentinel and exclusive failure output
            // remain live throughout traversal; its callback storage remains until the wait.
            let requests = unsafe { ReceiveRequests::from_raw(&request, &mut bad) }
                .track(None, &outcome)
                .with_reserved(completion);
            qp.provider().post_receive(qp, requests)
        } else {
            let request = bindings::ib_rdma_wr {
                wr: bindings::ib_send_wr {
                    __bindgen_anon_1: bindings::ib_send_wr__bindgen_ty_1 { wr_cqe: cqe },
                    opcode: bindings::ib_wr_opcode_IB_WR_RDMA_WRITE,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut bad = ptr::null();
            // SAFETY: The initialized RDMA extension has no SGEs. Both it and the exclusive
            // failure output remain live during traversal; callback storage survives the wait.
            let requests = unsafe { SendRequests::from_raw(&request.wr, &mut bad, qp.kind) }
                .track(None, &outcome)
                .with_reserved(completion);
            qp.provider().post_send(qp, requests)
        };
        drop(posting);
        outcome.get().unwrap_or(result)?;
        let cq = if receive {
            qp.parents.receive
        } else {
            qp.parents.send
        };
        // SAFETY: Native core ownership retains the CQ. The sentinel was accepted and the
        // reserved capability remains valid until its callback completes this pinned wait.
        unsafe { wait.wait(cq) };
        Ok(())
    }
}

#[cfg(all(CONFIG_RUST_KUNIT_TESTS, CONFIG_INFINIBAND = "y"))]
#[crate::macros::kunit_tests(rust_rdma_drain)]
mod tests {
    use super::*;

    /// # Safety
    ///
    /// The test installs this only on its initialized private CQ. cq_context names the
    /// retained Wait until this callback transfers its single completion into output.
    unsafe extern "C" fn poll(
        cq: *mut bindings::ib_cq,
        count: c_int,
        output: *mut bindings::ib_wc,
    ) -> c_int {
        // SAFETY: The direct CQ processor supplies its retained CQ and writable output.
        unsafe {
            if count <= 0 || (*cq).cq_context.is_null() {
                return 0;
            }
            output.write(bindings::ib_wc {
                __bindgen_anon_1: bindings::ib_wc__bindgen_ty_1 {
                    wr_cqe: (*cq).cq_context.cast(),
                },
                ..Default::default()
            });
            (*cq).cq_context = ptr::null_mut();
        }
        1
    }

    #[test]
    fn callback_identifier_preserves_native_union_bytes() {
        let mut cqe = bindings::ib_cqe::default();
        let pointer = ptr::from_mut(&mut cqe);
        let value = callback_value(pointer);
        let decoded = bindings::ib_wc__bindgen_ty_1 { wr_id: value };
        // SAFETY: callback_value initialized every union byte and encoded this pointer.
        assert_eq!(unsafe { decoded.wr_cqe }, pointer);
        let mut expected = [0; size_of::<u64>()];
        expected[..size_of::<usize>()].copy_from_slice(&(pointer as usize).to_ne_bytes());
        assert_eq!(value.to_ne_bytes(), expected);
    }

    #[test]
    fn direct_drain_wait_polls_its_native_sentinel() -> Result {
        let wait = core::pin::pin!(Wait {
            cqe: bindings::ib_cqe {
                done: Some(Wait::complete),
            },
            done: Opaque::uninit(),
        });
        let mut device = KBox::new(bindings::ib_device::default(), GFP_KERNEL)?;
        device.ops.poll_cq = Some(poll);
        let mut cq = bindings::ib_cq {
            device: &mut *device,
            poll_ctx: bindings::ib_poll_context_IB_POLL_DIRECT,
            cq_context: ptr::from_ref(&wait.cqe).cast_mut().cast(),
            ..Default::default()
        };
        // SAFETY: The stack wait is pinned and exclusively initialized before publication.
        unsafe { bindings::init_completion(wait.done.get()) };
        // SAFETY: This retained CQ has one initialized output-producing callback, and this
        // test is its exclusive direct poller. The actual core processor invokes Wait::complete.
        unsafe { wait.wait(&mut cq) };
        assert!(cq.cq_context.is_null());
        Ok(())
    }

    #[test]
    fn queued_drain_callback_wakes_the_destroying_task() -> Result {
        let wait = core::pin::pin!(Wait {
            cqe: bindings::ib_cqe {
                done: Some(Wait::complete),
            },
            done: Opaque::uninit(),
        });
        let mut cq = bindings::ib_cq {
            poll_ctx: bindings::ib_poll_context_IB_POLL_WORKQUEUE,
            ..Default::default()
        };
        // SAFETY: The pinned wait is initialized before the worker can observe its address.
        unsafe { bindings::init_completion(wait.done.get()) };
        let address = ptr::from_ref(&wait.cqe) as usize;
        crate::workqueue::system_dfl().try_spawn(GFP_KERNEL, move || {
            let mut wc = bindings::ib_wc {
                __bindgen_anon_1: bindings::ib_wc__bindgen_ty_1 {
                    wr_cqe: address as *mut bindings::ib_cqe,
                },
                ..Default::default()
            };
            // SAFETY: The spawning task retains the pinned wait until this callback signals
            // it; the callback makes no access to that allocation after signaling completion.
            unsafe { Wait::complete(ptr::null_mut(), &mut wc) };
        })?;
        // SAFETY: The stack CQ and initialized wait survive until the queued callback signals.
        unsafe { wait.wait(&mut cq) };
        Ok(())
    }
}
