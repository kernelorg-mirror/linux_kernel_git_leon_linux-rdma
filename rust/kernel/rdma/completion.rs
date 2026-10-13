// SPDX-License-Identifier: GPL-2.0

//! Owned completion values and bounded writes to kernel polling output.

use crate::{
    bindings,
    prelude::*, //
};
use core::{
    marker::PhantomData,
    ptr::NonNull, //
};

/// An opaque QP identity copied into a kernel completion.
///
/// This value retains neither the QP nor its resources and never dereferences its address.
/// Kernel verbs consumers must retain their QPs while handling their completions. Keeping
/// completions unpolled must not keep a destroyed QP or its registrations alive.
#[derive(Clone, Copy)]
pub struct QueuePairIdentity {
    address: NonNull<bindings::ib_qp>,
    number: u32,
}

// SAFETY: The address is an opaque completion value, never dereferenced through this type.
unsafe impl Send for QueuePairIdentity {}
// SAFETY: Sharing this immutable identity does not access the pointed-to allocation.
unsafe impl Sync for QueuePairIdentity {}

impl QueuePairIdentity {
    /// Captures a QP's immutable number and opaque completion address.
    ///
    /// # Safety
    ///
    /// `qp` must be an initialized, live QP with an immutable number during this call.
    /// Returning this identity in a completion must obey the kernel verbs consumer's QP
    /// lifetime contract; the returned value does not acquire an object reference.
    #[inline]
    pub unsafe fn from_raw(qp: *mut bindings::ib_qp) -> Self {
        Self {
            // SAFETY: The caller supplies an initialized, live allocation and immutable number.
            address: unsafe { NonNull::new_unchecked(qp) },
            // SAFETY: The number remains initialized and unchanged during capture.
            number: unsafe { (*qp).qp_num },
        }
    }

    /// Returns the captured QP number without accessing the QP allocation.
    #[inline]
    pub fn number(self) -> u32 {
        self.number
    }
}

/// Scalar fields of an RDMA work completion, without a QP pointer or storage borrow.
#[derive(Clone, Default)]
pub struct CompletionData {
    /// Opaque identifier supplied with the posted request.
    pub id: u64,
    /// Completion status from `enum ib_wc_status`.
    pub status: u32,
    /// Completed operation from `enum ib_wc_opcode`.
    pub opcode: u32,
    /// Provider-specific diagnostic value.
    pub vendor_error: u32,
    /// Number of completed bytes.
    pub length: u32,
    /// Immediate or invalidation data in the byte order of the selected union member.
    pub immediate: [u8; 4],
    /// Source QP number.
    pub source: u32,
    /// Source local identifier.
    pub source_lid: u32,
    /// Flags from `enum ib_wc_flags` selecting valid optional fields.
    pub flags: u32,
    /// Partition key index.
    pub pkey_index: u16,
    /// Service level.
    pub service_level: u8,
    /// Destination local identifier path bits.
    pub destination_path: u8,
    /// Local port number.
    pub port: u32,
    /// Source Ethernet address.
    pub source_mac: [u8; 6],
    /// Received VLAN identifier.
    pub vlan: u16,
    /// Received network header type.
    pub network: u8,
}

/// A completion value which can be kept in provider-owned kernel storage.
///
/// Its QP identity is only copied to the polling caller; no method dereferences it.
#[derive(Clone)]
pub struct Completion {
    qp: QueuePairIdentity,
    data: CompletionData,
}

impl Completion {
    /// Size of the C kernel completion ABI, including its padding.
    pub const CORE_SIZE: usize = size_of::<bindings::ib_wc>();

    /// Constructs a completion without retaining its QP or request storage.
    #[inline]
    pub fn new(qp: QueuePairIdentity, data: CompletionData) -> Self {
        Self { qp, data }
    }

    fn into_raw(self) -> bindings::ib_wc {
        let mut wc = bindings::ib_wc::default();
        wc.__bindgen_anon_1.wr_id = self.data.id;
        wc.status = self.data.status;
        wc.opcode = self.data.opcode;
        wc.vendor_err = self.data.vendor_error;
        wc.byte_len = self.data.length;
        wc.qp = self.qp.address.as_ptr();
        wc.ex.imm_data = u32::from_ne_bytes(self.data.immediate);
        wc.src_qp = self.data.source;
        wc.slid = self.data.source_lid;
        wc.wc_flags = self.data.flags as c_int;
        wc.pkey_index = self.data.pkey_index;
        wc.sl = self.data.service_level;
        wc.dlid_path_bits = self.data.destination_path;
        wc.port_num = self.data.port;
        wc.smac = self.data.source_mac;
        wc.vlan_id = self.data.vlan;
        wc.network_hdr_type = self.data.network;
        wc
    }
}

/// Bounded output granted by a kernel completion-polling caller.
///
/// # Invariants
///
/// `output` denotes `capacity` writable C completions, with exclusive access for `'a`.
/// Their contents need not be initialized. `written` never exceeds `capacity`.
/// `device` is the retained CQ's device and its port range remains unchanged for `'a`.
pub struct CompletionOutput<'a> {
    device: *mut bindings::ib_device,
    output: *mut bindings::ib_wc,
    capacity: usize,
    written: usize,
    _borrow: PhantomData<&'a mut [core::mem::MaybeUninit<bindings::ib_wc>]>,
}

impl<'a> CompletionOutput<'a> {
    /// Borrows a polling caller's output array without reading uninitialized entries.
    ///
    /// # Safety
    ///
    /// Positive `count` requires an aligned array of that many writable completions, fitting
    /// within Rust's maximum allocation size, with exclusive access for `'a`. A nonpositive
    /// count denotes an empty array and permits a null output pointer. `cq` must be non-null and
    /// identify the retained, initialized CQ, whose initialized device and port range remain
    /// live and unchanged for `'a`. Kernel callers must retain native request callbacks and QPs
    /// while handling the returned completions, according to the verbs completion contract.
    #[inline]
    pub unsafe fn from_raw(
        cq: *mut bindings::ib_cq,
        output: *mut bindings::ib_wc,
        count: c_int,
    ) -> Self {
        // INVARIANT: The caller retains the CQ's initialized device and grants the complete
        // array exclusively; nothing is written yet.
        Self {
            // SAFETY: The caller retains this initialized CQ and its device.
            device: unsafe { (*cq).device },
            output,
            capacity: count.max(0) as usize,
            written: 0,
            _borrow: PhantomData,
        }
    }

    /// Returns how many more entries fit in this output.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.capacity - self.written
    }

    /// Returns the number of initialized completions written so far.
    #[inline]
    pub fn written(&self) -> usize {
        self.written
    }

    /// Writes one initialized completion after checking its port.
    ///
    /// An out-of-range port or full output fails without writing an entry. Port zero remains
    /// valid for completions without port metadata.
    pub fn push(&mut self, completion: Completion) -> Result {
        if self.remaining() == 0 {
            return Err(ENOSPC);
        }
        // Native completion consumers may index port_data regardless of status or flags.
        // Port zero is its allocated initial slot and represents absent completion metadata.
        // SAFETY: The invariant retains the device and its initialized, unchanged port range.
        if unsafe { bindings::rdma_is_port_valid(self.device, completion.data.port) } == 0
            && completion.data.port != 0
        {
            return Err(EINVAL);
        }
        // SAFETY: The invariant grants this in-bounds element exclusively. A whole-value write
        // initializes every field without reading the old storage or dereferencing the QP.
        unsafe { self.output.add(self.written).write(completion.into_raw()) };
        self.written += 1;
        Ok(())
    }
}
