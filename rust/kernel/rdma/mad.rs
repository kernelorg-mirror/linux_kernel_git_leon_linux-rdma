// SPDX-License-Identifier: GPL-2.0

//! Standard InfiniBand management datagrams and provider callback metadata.

use crate::bindings;
use core::{
    marker::PhantomData,
    mem::{
        offset_of,
        size_of, //
    }, //
};

/// The common management header, with multibyte values in host byte order.
#[derive(Clone, Copy, Debug, Default)]
pub struct MadHeader {
    /// Base management version.
    pub base_version: u8,
    /// Management class.
    pub class: u8,
    /// Class-specific version.
    pub class_version: u8,
    /// Management method, including the response bit.
    pub method: u8,
    /// Management status.
    pub status: u16,
    /// Class-specific header field.
    pub class_specific: u16,
    /// Transaction identifier.
    pub transaction_id: u64,
    /// Attribute identifier.
    pub attribute_id: u16,
    /// Reserved header field, preserved when copying a request.
    pub reserved: u16,
    /// Attribute modifier.
    pub attribute_modifier: u32,
}

/// A standard 256-byte management datagram represented by native values.
///
/// This type does not represent the larger Omni-Path datagram format. Its data bytes retain
/// their wire byte order; only the common header is decoded.
#[derive(Clone)]
pub struct Mad {
    /// Common header.
    pub header: MadHeader,
    /// Class-specific header and attribute bytes.
    pub data: [u8; 232],
}

impl Default for Mad {
    #[inline]
    fn default() -> Self {
        Self {
            header: MadHeader::default(),
            data: [0; 232],
        }
    }
}

impl Mad {
    pub(super) fn from_raw(input: &bindings::ib_mad) -> Self {
        let header = &input.mad_hdr;
        Self {
            header: MadHeader {
                base_version: header.base_version,
                class: header.mgmt_class,
                class_version: header.class_version,
                method: header.method,
                status: u16::from_be(header.status),
                class_specific: u16::from_be(header.class_specific),
                transaction_id: u64::from_be(header.tid),
                attribute_id: u16::from_be(header.attr_id),
                reserved: u16::from_be(header.resv),
                attribute_modifier: u32::from_be(header.attr_mod),
            },
            data: input.data,
        }
    }

    pub(super) fn into_raw(self) -> bindings::ib_mad {
        bindings::ib_mad {
            mad_hdr: bindings::ib_mad_hdr {
                base_version: self.header.base_version,
                mgmt_class: self.header.class,
                class_version: self.header.class_version,
                method: self.header.method,
                status: self.header.status.to_be(),
                class_specific: self.header.class_specific.to_be(),
                tid: self.header.transaction_id.to_be(),
                attr_id: self.header.attribute_id.to_be(),
                resv: self.header.reserved.to_be(),
                attr_mod: self.header.attribute_modifier.to_be(),
            },
            data: self.data,
        }
    }
}

crate::impl_flags!(
    /// Management-key checks which the caller allows a provider to bypass.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct MadFlags(u32);

    /// One management-key check override.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum MadFlag {
        /// Ignore the management key.
        IgnoreManagementKey = bindings::ib_process_mad_flags_IB_MAD_IGNORE_MKEY,
        /// Ignore the baseboard management key.
        IgnoreBaseboardKey = bindings::ib_process_mad_flags_IB_MAD_IGNORE_BKEY,
    }
);

/// Addressing metadata from a successful MAD receive completion.
#[derive(Clone, Copy, Debug)]
pub struct MadSource {
    /// Source queue pair number.
    pub queue_pair: u32,
    /// Source local identifier.
    pub local_id: u32,
    /// Partition-key table index.
    pub pkey_index: u16,
    /// Service level.
    pub service_level: u8,
    /// Destination local-identifier path bits.
    pub destination_path_bits: u8,
}

/// A management request and its callback-scoped receive metadata.
///
/// Local queries need not have a receive completion or global route header.
///
/// # Invariants
///
/// Non-null completion metadata comes from a successful MAD receive or a core-synthesized
/// local SMP completion and remains live and unchanged for `'a`. A non-null GRH is readable
/// for `'a` when the completion has `IB_WC_GRH`. The pointers never escape safe accessors.
pub struct MadRequest<'a> {
    /// Port selected by the core.
    pub port: u32,
    /// Key-check overrides requested by the core.
    pub flags: MadFlags,
    /// The decoded management datagram.
    pub input: &'a Mad,
    completion: *const bindings::ib_wc,
    grh: *const bindings::ib_grh,
    _borrow: PhantomData<&'a ()>,
}

impl<'a> MadRequest<'a> {
    // Caller retains callback metadata satisfying this type's invariants for 'a.
    /// # Safety
    ///
    /// The optional completion and flagged GRH must satisfy the type invariants and remain
    /// readable for 'a.
    pub(super) unsafe fn new(
        port: u32,
        flags: i32,
        input: &'a Mad,
        completion: *const bindings::ib_wc,
        grh: *const bindings::ib_grh,
    ) -> Self {
        // INVARIANT: The caller keeps the optional completion and flagged GRH readable.
        Self {
            port,
            flags: MadFlags(flags as u32),
            input,
            completion,
            grh,
            _borrow: PhantomData,
        }
    }

    /// Copies the source addressing fields, if the request has a receive completion.
    #[inline]
    pub fn source(&self) -> Option<MadSource> {
        if self.completion.is_null() {
            return None;
        }
        // SAFETY: These fields are initialized for successful MAD receives and local SMPs.
        // Read individual fields without borrowing uninitialized optional completion fields.
        Some(unsafe {
            MadSource {
                queue_pair: (*self.completion).src_qp,
                local_id: (*self.completion).slid,
                pkey_index: (*self.completion).pkey_index,
                service_level: (*self.completion).sl,
                destination_path_bits: (*self.completion).dlid_path_bits,
            }
        })
    }

    /// Copies the wire-format global route header only when the completion marks it valid.
    #[inline]
    pub fn global_route(&self) -> Option<[u8; 40]> {
        if self.completion.is_null() || self.grh.is_null() {
            return None;
        }
        // SAFETY: The invariant keeps the completion flags readable. Only the GRH flag
        // authorizes reading the optional header, whose wire representation has no padding.
        unsafe {
            if (*self.completion).wc_flags & bindings::ib_wc_flags_IB_WC_GRH as i32 == 0 {
                return None;
            }
            Some(self.grh.cast::<[u8; 40]>().read())
        }
    }
}

/// The action the MAD core should take after the provider callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MadDisposition {
    /// Processing failed; leave the core's output storage untouched.
    Failure,
    /// Processing succeeded without requesting a reply.
    Success,
    /// Send the output datagram as a reply.
    Reply,
    /// The provider consumed the request; stop processing it.
    Consumed,
}

impl MadDisposition {
    #[inline]
    pub(super) fn as_raw(self) -> i32 {
        use bindings::{
            ib_mad_result_IB_MAD_RESULT_CONSUMED as CONSUMED,
            ib_mad_result_IB_MAD_RESULT_FAILURE as FAILURE,
            ib_mad_result_IB_MAD_RESULT_REPLY as REPLY,
            ib_mad_result_IB_MAD_RESULT_SUCCESS as SUCCESS, //
        };
        (match self {
            Self::Failure => FAILURE,
            Self::Success => SUCCESS,
            Self::Reply => SUCCESS | REPLY,
            Self::Consumed => SUCCESS | CONSUMED,
        }) as i32
    }
}

/// Initialized response storage supplied to a standard MAD provider callback.
#[derive(Default)]
pub struct MadOutput {
    /// The response datagram.
    pub message: Mad,
    /// Optional replacement partition-key index. `None` preserves the core's value.
    pub pkey_index: Option<u16>,
}

const _: () = assert!(size_of::<bindings::ib_mad>() == 256);
const _: () = assert!(offset_of!(bindings::ib_mad, data) == 24);
const _: () = assert!(size_of::<bindings::ib_grh>() == 40);
