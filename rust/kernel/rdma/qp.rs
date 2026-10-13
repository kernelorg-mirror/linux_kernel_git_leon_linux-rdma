// SPDX-License-Identifier: GPL-2.0

//! Selected queue-pair attributes at the RDMA provider boundary.

use super::{
    AccessFlags,
    AddressAttributes,
    AddressRequest, //
};
use crate::{
    bindings,
    prelude::*, //
};

/// Queue-pair transports supported by the native work-request adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum QueuePairType {
    /// Reliable connected transport.
    ReliableConnected = bindings::ib_qp_type_IB_QPT_RC,
    /// Unreliable connected transport.
    UnreliableConnected = bindings::ib_qp_type_IB_QPT_UC,
    /// Unreliable datagram transport.
    UnreliableDatagram = bindings::ib_qp_type_IB_QPT_UD,
    /// General-services management datagrams.
    GeneralService = bindings::ib_qp_type_IB_QPT_GSI,
}

impl QueuePairType {
    /// Rejects transports not represented by this adapter.
    #[inline]
    pub fn from_encoding(value: u32) -> Result<Self> {
        match value {
            bindings::ib_qp_type_IB_QPT_RC => Ok(Self::ReliableConnected),
            bindings::ib_qp_type_IB_QPT_UC => Ok(Self::UnreliableConnected),
            bindings::ib_qp_type_IB_QPT_UD => Ok(Self::UnreliableDatagram),
            bindings::ib_qp_type_IB_QPT_GSI => Ok(Self::GeneralService),
            _ => Err(EOPNOTSUPP),
        }
    }

    /// Returns the core transport encoding.
    #[inline]
    pub fn encoding(self) -> u32 {
        self as u32
    }

    /// Returns whether operation-specific requests use connected layouts.
    #[inline]
    pub fn is_connected(self) -> bool {
        matches!(self, Self::ReliableConnected | Self::UnreliableConnected)
    }
}

/// Queue-pair states accepted by the core transition table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum QueuePairState {
    /// Initial state, with transport processing disabled.
    Reset = bindings::ib_qp_state_IB_QPS_RESET,
    /// Initialized transport parameters.
    Init = bindings::ib_qp_state_IB_QPS_INIT,
    /// Ready to receive packets.
    ReadyToReceive = bindings::ib_qp_state_IB_QPS_RTR,
    /// Ready to send and receive packets.
    ReadyToSend = bindings::ib_qp_state_IB_QPS_RTS,
    /// Draining the send queue.
    SendQueueDrain = bindings::ib_qp_state_IB_QPS_SQD,
    /// Send queue error.
    SendQueueError = bindings::ib_qp_state_IB_QPS_SQE,
    /// Queue-pair error.
    Error = bindings::ib_qp_state_IB_QPS_ERR,
}

impl QueuePairState {
    /// Decodes a state without accepting indices outside the core transition table.
    #[inline]
    pub fn from_encoding(value: u32) -> Result<Self> {
        match value {
            bindings::ib_qp_state_IB_QPS_RESET => Ok(Self::Reset),
            bindings::ib_qp_state_IB_QPS_INIT => Ok(Self::Init),
            bindings::ib_qp_state_IB_QPS_RTR => Ok(Self::ReadyToReceive),
            bindings::ib_qp_state_IB_QPS_RTS => Ok(Self::ReadyToSend),
            bindings::ib_qp_state_IB_QPS_SQD => Ok(Self::SendQueueDrain),
            bindings::ib_qp_state_IB_QPS_SQE => Ok(Self::SendQueueError),
            bindings::ib_qp_state_IB_QPS_ERR => Ok(Self::Error),
            _ => Err(EINVAL),
        }
    }

    /// Returns the core state encoding.
    #[inline]
    pub fn encoding(self) -> u32 {
        self as u32
    }
}

/// Limits for one private work queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkQueueCapacity {
    /// Maximum outstanding work requests.
    pub work_requests: u32,
    /// Maximum scatter/gather entries per request.
    pub scatter_gather: u32,
}

/// Queue-pair capacities, excluding private receive limits when an SRQ supplies receives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueuePairCapacity {
    /// Send queue limits.
    pub send: WorkQueueCapacity,
    /// Private receive queue limits, absent for an SRQ-backed QP.
    pub receive: Option<WorkQueueCapacity>,
    /// Maximum inline send payload in bytes.
    pub inline: u32,
}

impl QueuePairCapacity {
    /// Writes actual queue capacities without touching absent SRQ receive limits.
    ///
    /// # Safety
    ///
    /// `output` must point to aligned, exclusively writable `ib_qp_cap` storage. Unrepresented
    /// fields need not be initialized and are left untouched.
    #[inline]
    pub unsafe fn write_to(&self, output: *mut bindings::ib_qp_cap) {
        // SAFETY: The caller grants these selected fields exclusively. Field projections
        // neither borrow the enclosing object nor read unselected, possibly uninitialized data.
        unsafe {
            (*output).max_send_wr = self.send.work_requests;
            (*output).max_send_sge = self.send.scatter_gather;
            (*output).max_inline_data = self.inline;
            if let Some(receive) = self.receive {
                (*output).max_recv_wr = receive.work_requests;
                (*output).max_recv_sge = receive.scatter_gather;
            }
        }
    }

    /// Copies the capacities relevant to a QP's receive mode.
    ///
    /// # Safety
    ///
    /// `raw` must point into live, aligned storage. The send and inline fields must be
    /// initialized and unchanged for the call; receive fields need only satisfy these
    /// requirements when `private_receive` is true. `max_rdma_ctxs` is not read.
    #[inline]
    pub unsafe fn from_raw(raw: *const bindings::ib_qp_cap, private_receive: bool) -> Self {
        // SAFETY: The caller supplies stable selected fields. A field projection does not
        // borrow the enclosing C struct or read ignored receive fields or max_rdma_ctxs.
        unsafe {
            Self {
                send: WorkQueueCapacity {
                    work_requests: (*raw).max_send_wr,
                    scatter_gather: (*raw).max_send_sge,
                },
                receive: private_receive.then(|| WorkQueueCapacity {
                    work_requests: (*raw).max_recv_wr,
                    scatter_gather: (*raw).max_recv_sge,
                }),
                inline: (*raw).max_inline_data,
            }
        }
    }
}

/// Basic QP creation attributes without borrowed core object pointers.
///
/// This representation supports RC, UC, UD and GSI with no optional creation flags. Parent
/// object pointers are only checked for presence here; their borrows belong to the core adapter.
pub struct QueuePairInitAttributes {
    /// Requested transport.
    pub kind: QueuePairType,
    /// Requested or actual private queue capacities.
    pub capacity: QueuePairCapacity,
    /// Completion signaling encoding, retained for provider policy.
    pub signaling: u32,
    /// Management port, selected only for GSI.
    pub management_port: Option<u32>,
}

impl QueuePairInitAttributes {
    /// Copies selected basic creation attributes and rejects missing completion queues.
    ///
    /// Flags are checked before reading transport or queue fields. Unsupported transports are
    /// rejected before inspecting parents; private receive limits are read only without an SRQ.
    ///
    /// # Safety
    ///
    /// `raw` must point into aligned, live storage. Fields reached by the selection rules above
    /// must be initialized and unchanged, including capacity fields selected by
    /// `QueuePairCapacity::from_raw`. The signaling field must be initialized after successful
    /// parent checks, and port_num only for GSI. Parent pointers are not dereferenced.
    pub unsafe fn from_raw(raw: *const bindings::ib_qp_init_attr) -> Result<Self> {
        // SAFETY: The caller retains the selected fields. Each branch rejects unsupported
        // layouts before reading further fields, and no enclosing C reference is formed.
        unsafe {
            if (*raw).create_flags != 0 {
                return Err(EOPNOTSUPP);
            }
            let kind = QueuePairType::from_encoding((*raw).qp_type)?;
            if (*raw).send_cq.is_null() || (*raw).recv_cq.is_null() {
                return Err(EINVAL);
            }
            Ok(Self {
                kind,
                capacity: QueuePairCapacity::from_raw(&raw const (*raw).cap, (*raw).srq.is_null()),
                signaling: (*raw).sq_sig_type,
                management_port: (kind == QueuePairType::GeneralService).then(|| (*raw).port_num),
            })
        }
    }
}

/// Owned query attributes without core pointers or borrowed address storage.
pub struct QueuePairAttributes {
    /// Reported transport state.
    pub state: QueuePairState,
    /// Current state sampled by the provider.
    pub current_state: QueuePairState,
    /// Whether the send queue is draining.
    pub draining: u8,
    /// Asynchronous draining notification setting.
    pub draining_notification: u8,
    /// Encoded path MTU.
    pub path_mtu: u32,
    /// Encoded path migration state.
    pub migration_state: u32,
    /// Negotiated remote access rights.
    pub access: AccessFlags,
    /// Datagram queue key.
    pub qkey: u32,
    /// Current receive packet sequence number.
    pub receive_psn: u32,
    /// Current send packet sequence number.
    pub send_psn: u32,
    /// Destination queue-pair number.
    pub destination: u32,
    /// Current private queue capacities.
    pub capacity: QueuePairCapacity,
    /// Primary address, without a retained source GID pointer.
    pub primary: Option<AddressAttributes>,
    /// Alternate address, without a retained source GID pointer.
    pub alternate: Option<AddressAttributes>,
    /// Primary partition-key index.
    pub pkey_index: u16,
    /// Alternate partition-key index.
    pub alternate_pkey_index: u16,
    /// Maximum outstanding read or atomic requests.
    pub max_read_atomic: u8,
    /// Maximum incoming read or atomic requests.
    pub max_destination_read_atomic: u8,
    /// Minimum receiver-not-ready timeout.
    pub min_rnr_timer: u8,
    /// Primary port number.
    pub port: u32,
    /// Encoded primary acknowledgment timeout.
    pub timeout: u8,
    /// Retry count.
    pub retry: u8,
    /// Receiver-not-ready retry count.
    pub rnr_retry: u8,
    /// Alternate port number.
    pub alternate_port: u32,
    /// Encoded alternate acknowledgment timeout.
    pub alternate_timeout: u8,
}

impl QueuePairAttributes {
    /// Initializes a complete core query result, leaving unrepresented fields zeroed.
    ///
    /// # Safety
    ///
    /// `output` must be aligned, exclusively writable storage for one `ib_qp_attr`. It must
    /// not contain owned resources requiring release before being overwritten.
    pub unsafe fn write_to(&self, output: *mut bindings::ib_qp_attr) {
        let mut raw = bindings::ib_qp_attr {
            qp_state: self.state.encoding(),
            cur_qp_state: self.current_state.encoding(),
            sq_draining: self.draining,
            en_sqd_async_notify: self.draining_notification,
            path_mtu: self.path_mtu,
            path_mig_state: self.migration_state,
            qp_access_flags: u32::from(self.access) as c_int,
            qkey: self.qkey,
            rq_psn: self.receive_psn,
            sq_psn: self.send_psn,
            dest_qp_num: self.destination,
            ..Default::default()
        };
        raw.cap.max_send_wr = self.capacity.send.work_requests;
        raw.cap.max_send_sge = self.capacity.send.scatter_gather;
        raw.cap.max_inline_data = self.capacity.inline;
        if let Some(receive) = self.capacity.receive {
            raw.cap.max_recv_wr = receive.work_requests;
            raw.cap.max_recv_sge = receive.scatter_gather;
        }
        if let Some(primary) = self.primary {
            raw.ah_attr = primary.to_raw();
        }
        if let Some(alternate) = self.alternate {
            raw.alt_ah_attr = alternate.to_raw();
        }
        raw.pkey_index = self.pkey_index;
        raw.alt_pkey_index = self.alternate_pkey_index;
        raw.max_rd_atomic = self.max_read_atomic;
        raw.max_dest_rd_atomic = self.max_destination_read_atomic;
        raw.min_rnr_timer = self.min_rnr_timer;
        raw.port_num = self.port;
        raw.timeout = self.timeout;
        raw.retry_cnt = self.retry;
        raw.rnr_retry = self.rnr_retry;
        raw.alt_port_num = self.alternate_port;
        raw.alt_timeout = self.alternate_timeout;
        // SAFETY: The caller grants complete writable output. Every field is initialized;
        // address conversion leaves the GID pointers null and transfers no core ownership.
        unsafe { output.write(raw) };
    }
}

/// Selected alternate path, copied while the core retains its source GID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlternatePath {
    /// Alternate address and source GID snapshot.
    pub address: AddressRequest,
    /// Alternate port number.
    pub port: u32,
    /// Alternate partition-key index.
    pub pkey_index: u16,
    /// Encoded alternate acknowledgment timeout.
    pub timeout: u8,
}

/// An owned snapshot of the standard attributes selected for QP modification.
///
/// Absent fields were not selected and were not read. Address requests contain copied GIDs,
/// so the snapshot retains neither the C attributes nor their core-owned source pointers.
#[derive(Clone, Copy, Debug)]
pub struct QueuePairChange {
    /// Requested next state.
    pub state: Option<QueuePairState>,
    /// Caller-supplied current state for transition validation.
    pub current_state: Option<QueuePairState>,
    /// Enable asynchronous notification when the send queue finishes draining.
    pub draining_notification: Option<u8>,
    /// Requested remote access permissions, retaining unsupported bits for validation.
    pub access: Option<AccessFlags>,
    /// Partition-key index.
    pub pkey_index: Option<u16>,
    /// Port number.
    pub port: Option<u32>,
    /// Datagram queue key.
    pub qkey: Option<u32>,
    /// Primary address and source GID snapshot.
    pub primary: Option<AddressRequest>,
    /// Encoded path MTU, retained for provider validation.
    pub path_mtu: Option<u32>,
    /// Encoded acknowledgment timeout.
    pub timeout: Option<u8>,
    /// Retry count.
    pub retry: Option<u8>,
    /// Receiver-not-ready retry count.
    pub rnr_retry: Option<u8>,
    /// Initial receive packet sequence number.
    pub receive_psn: Option<u32>,
    /// Maximum outstanding read or atomic requests.
    pub max_read_atomic: Option<u8>,
    /// Alternate path and its associated attributes.
    pub alternate: Option<AlternatePath>,
    /// Minimum receiver-not-ready timeout.
    pub min_rnr_timer: Option<u8>,
    /// Initial send packet sequence number.
    pub send_psn: Option<u32>,
    /// Maximum outstanding incoming read or atomic requests.
    pub max_destination_read_atomic: Option<u8>,
    /// Encoded path migration state, retained for provider validation.
    pub migration_state: Option<u32>,
    /// Requested capacities, omitting SRQ-backed receive fields.
    pub capacity: Option<QueuePairCapacity>,
    /// Destination queue-pair number.
    pub destination: Option<u32>,
}

impl QueuePairChange {
    /// Copies only standard attributes selected by `mask`.
    ///
    /// Unknown mask bits are rejected before reading any attribute. State encodings are
    /// checked before they can be used as indices in the core transition table.
    ///
    /// # Safety
    ///
    /// `raw` must point into live, aligned storage. Selected fields must be initialized and
    /// unchanged for the call. A selected capacity must satisfy
    /// [`QueuePairCapacity::from_raw`] for `private_receive`. Selected addresses must satisfy
    /// [`AddressRequest::from_raw`], including retained source GID attributes.
    #[inline]
    pub unsafe fn from_raw(
        raw: *const bindings::ib_qp_attr,
        mask: u32,
        private_receive: bool,
    ) -> Result<Self> {
        if mask & !bindings::ib_qp_attr_mask_IB_QP_ATTR_STANDARD_BITS != 0 {
            return Err(EOPNOTSUPP);
        }
        // SAFETY: The caller supplies stable selected fields and retained address sources.
        // `then` evaluates its closure only for selected attributes, avoiding whole-struct
        // copies and references to potentially uninitialized C storage.
        unsafe {
            Ok(Self {
                state: (mask & bindings::ib_qp_attr_mask_IB_QP_STATE != 0)
                    .then(|| QueuePairState::from_encoding((*raw).qp_state))
                    .transpose()?,
                current_state: (mask & bindings::ib_qp_attr_mask_IB_QP_CUR_STATE != 0)
                    .then(|| QueuePairState::from_encoding((*raw).cur_qp_state))
                    .transpose()?,
                draining_notification: (mask & bindings::ib_qp_attr_mask_IB_QP_EN_SQD_ASYNC_NOTIFY
                    != 0)
                    .then(|| (*raw).en_sqd_async_notify),
                access: (mask & bindings::ib_qp_attr_mask_IB_QP_ACCESS_FLAGS != 0)
                    .then(|| AccessFlags::from_bits((*raw).qp_access_flags as u32)),
                pkey_index: (mask & bindings::ib_qp_attr_mask_IB_QP_PKEY_INDEX != 0)
                    .then(|| (*raw).pkey_index),
                port: (mask & bindings::ib_qp_attr_mask_IB_QP_PORT != 0).then(|| (*raw).port_num),
                qkey: (mask & bindings::ib_qp_attr_mask_IB_QP_QKEY != 0).then(|| (*raw).qkey),
                primary: (mask & bindings::ib_qp_attr_mask_IB_QP_AV != 0)
                    .then(|| AddressRequest::from_raw(&raw const (*raw).ah_attr))
                    .transpose()?,
                path_mtu: (mask & bindings::ib_qp_attr_mask_IB_QP_PATH_MTU != 0)
                    .then(|| (*raw).path_mtu),
                timeout: (mask & bindings::ib_qp_attr_mask_IB_QP_TIMEOUT != 0)
                    .then(|| (*raw).timeout),
                retry: (mask & bindings::ib_qp_attr_mask_IB_QP_RETRY_CNT != 0)
                    .then(|| (*raw).retry_cnt),
                rnr_retry: (mask & bindings::ib_qp_attr_mask_IB_QP_RNR_RETRY != 0)
                    .then(|| (*raw).rnr_retry),
                receive_psn: (mask & bindings::ib_qp_attr_mask_IB_QP_RQ_PSN != 0)
                    .then(|| (*raw).rq_psn),
                max_read_atomic: (mask & bindings::ib_qp_attr_mask_IB_QP_MAX_QP_RD_ATOMIC != 0)
                    .then(|| (*raw).max_rd_atomic),
                alternate: (mask & bindings::ib_qp_attr_mask_IB_QP_ALT_PATH != 0)
                    .then(|| -> Result<AlternatePath> {
                        Ok(AlternatePath {
                            address: AddressRequest::from_raw(&raw const (*raw).alt_ah_attr)?,
                            port: (*raw).alt_port_num,
                            pkey_index: (*raw).alt_pkey_index,
                            timeout: (*raw).alt_timeout,
                        })
                    })
                    .transpose()?,
                min_rnr_timer: (mask & bindings::ib_qp_attr_mask_IB_QP_MIN_RNR_TIMER != 0)
                    .then(|| (*raw).min_rnr_timer),
                send_psn: (mask & bindings::ib_qp_attr_mask_IB_QP_SQ_PSN != 0)
                    .then(|| (*raw).sq_psn),
                max_destination_read_atomic: (mask
                    & bindings::ib_qp_attr_mask_IB_QP_MAX_DEST_RD_ATOMIC
                    != 0)
                    .then(|| (*raw).max_dest_rd_atomic),
                migration_state: (mask & bindings::ib_qp_attr_mask_IB_QP_PATH_MIG_STATE != 0)
                    .then(|| (*raw).path_mig_state),
                capacity: (mask & bindings::ib_qp_attr_mask_IB_QP_CAP != 0)
                    .then(|| QueuePairCapacity::from_raw(&raw const (*raw).cap, private_receive)),
                destination: (mask & bindings::ib_qp_attr_mask_IB_QP_DEST_QPN != 0)
                    .then(|| (*raw).dest_qp_num),
            })
        }
    }

    /// Returns the attribute mask matching the current snapshot fields.
    #[inline]
    pub fn mask(&self) -> u32 {
        let mut mask = 0;
        if self.state.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_STATE;
        }
        if self.current_state.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_CUR_STATE;
        }
        if self.draining_notification.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_EN_SQD_ASYNC_NOTIFY;
        }
        if self.access.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_ACCESS_FLAGS;
        }
        if self.pkey_index.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_PKEY_INDEX;
        }
        if self.port.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_PORT;
        }
        if self.qkey.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_QKEY;
        }
        if self.primary.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_AV;
        }
        if self.path_mtu.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_PATH_MTU;
        }
        if self.timeout.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_TIMEOUT;
        }
        if self.retry.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_RETRY_CNT;
        }
        if self.rnr_retry.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_RNR_RETRY;
        }
        if self.receive_psn.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_RQ_PSN;
        }
        if self.max_read_atomic.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_MAX_QP_RD_ATOMIC;
        }
        if self.alternate.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_ALT_PATH;
        }
        if self.min_rnr_timer.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_MIN_RNR_TIMER;
        }
        if self.send_psn.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_SQ_PSN;
        }
        if self.max_destination_read_atomic.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_MAX_DEST_RD_ATOMIC;
        }
        if self.migration_state.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_PATH_MIG_STATE;
        }
        if self.capacity.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_CAP;
        }
        if self.destination.is_some() {
            mask |= bindings::ib_qp_attr_mask_IB_QP_DEST_QPN;
        }
        mask
    }

    /// Checks the complete modification against the core's transport-specific policy.
    ///
    /// An explicitly selected current state takes precedence over `current`. If no next state
    /// is selected, the attribute mask must be valid for a same-state modification.
    #[inline]
    pub fn check_transition(&self, current: QueuePairState, kind: QueuePairType) -> Result {
        let current = self.current_state.unwrap_or(current);
        let next = self.state.unwrap_or(current);
        // SAFETY: Both state enums and the transport enum contain only valid core table indices.
        if unsafe {
            bindings::ib_modify_qp_is_ok(
                current.encoding(),
                next.encoding(),
                kind.encoding(),
                self.mask(),
            )
        } {
            Ok(())
        } else {
            Err(EINVAL)
        }
    }
}

#[cfg(CONFIG_RUST_KUNIT_TESTS)]
#[crate::macros::kunit_tests(rust_rdma_qp_attributes)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    #[cfg(CONFIG_INFINIBAND = "y")]
    #[test]
    fn attribute_only_changes_obey_the_state_table() -> Result {
        let attributes = bindings::ib_qp_attr::default();
        // SAFETY: All selected fields are initialized and unchanged during the borrow.
        let change = unsafe {
            QueuePairChange::from_raw(
                &attributes,
                bindings::ib_qp_attr_mask_IB_QP_ACCESS_FLAGS,
                true,
            )?
        };
        assert_eq!(
            change.check_transition(QueuePairState::Reset, QueuePairType::ReliableConnected),
            Err(EINVAL)
        );
        assert_eq!(
            change.check_transition(QueuePairState::Init, QueuePairType::ReliableConnected),
            Ok(())
        );
        Ok(())
    }

    #[cfg(CONFIG_INFINIBAND = "y")]
    #[test]
    fn changed_fields_cannot_bypass_transition_validation() -> Result {
        let attributes = bindings::ib_qp_attr::default();
        // SAFETY: The selected zero mask reads no uninitialized fields.
        let mut change = unsafe { QueuePairChange::from_raw(&attributes, 0, true)? };
        assert_eq!(
            change.check_transition(QueuePairState::Reset, QueuePairType::ReliableConnected),
            Ok(())
        );
        change.access = Some(AccessFlags::from_bits(0));
        assert_eq!(
            change.check_transition(QueuePairState::Reset, QueuePairType::ReliableConnected),
            Err(EINVAL)
        );
        change.state = Some(QueuePairState::Init);
        change.port = Some(1);
        change.pkey_index = Some(0);
        assert_eq!(
            change.check_transition(QueuePairState::Reset, QueuePairType::ReliableConnected),
            Ok(())
        );
        change.port = None;
        assert_eq!(
            change.check_transition(QueuePairState::Reset, QueuePairType::ReliableConnected),
            Err(EINVAL)
        );
        Ok(())
    }

    #[test]
    fn basic_creation_skips_unsupported_and_srq_storage() -> Result {
        let mut storage = MaybeUninit::<bindings::ib_qp_init_attr>::uninit();
        let raw = storage.as_mut_ptr();
        // SAFETY: Unsupported flags reject the request before any other field is selected.
        unsafe { (&raw mut (*raw).create_flags).write(1) };
        assert!(matches!(
            // SAFETY: The only selected field is initialized and retained for the call.
            unsafe { QueuePairInitAttributes::from_raw(raw) },
            Err(EOPNOTSUPP)
        ));
        // SAFETY: The following writes initialize supported common fields and send limits.
        // Parent pointers are presence markers only; the decoder never dereferences them.
        unsafe {
            (&raw mut (*raw).create_flags).write(0);
            (&raw mut (*raw).qp_type).write(bindings::ib_qp_type_IB_QPT_RC);
            (&raw mut (*raw).send_cq).write(core::ptr::dangling_mut());
            (&raw mut (*raw).recv_cq).write(core::ptr::dangling_mut());
            (&raw mut (*raw).srq).write(core::ptr::dangling_mut());
            (&raw mut (*raw).sq_sig_type).write(bindings::ib_sig_type_IB_SIGNAL_ALL_WR);
            (&raw mut (*raw).cap.max_send_wr).write(7);
            (&raw mut (*raw).cap.max_send_sge).write(3);
            (&raw mut (*raw).cap.max_inline_data).write(29);
        }
        // SAFETY: Selected common/send fields are initialized. SRQ receive limits, the
        // non-management port and optional extension fields remain uninitialized and unread.
        let attributes = unsafe { QueuePairInitAttributes::from_raw(raw)? };
        assert_eq!(attributes.kind, QueuePairType::ReliableConnected);
        assert_eq!(attributes.capacity.send.work_requests, 7);
        assert_eq!(attributes.capacity.send.scatter_gather, 3);
        assert_eq!(attributes.capacity.inline, 29);
        assert!(attributes.capacity.receive.is_none());
        assert!(attributes.management_port.is_none());

        let mut output = bindings::ib_qp_cap {
            max_recv_wr: 0xa5,
            max_recv_sge: 0x5a,
            max_rdma_ctxs: 11,
            ..Default::default()
        };
        // SAFETY: This output is aligned and exclusively writable.
        unsafe { attributes.capacity.write_to(&mut output) };
        assert_eq!(
            (
                output.max_send_wr,
                output.max_send_sge,
                output.max_inline_data
            ),
            (7, 3, 29)
        );
        assert_eq!(
            (
                output.max_recv_wr,
                output.max_recv_sge,
                output.max_rdma_ctxs
            ),
            (0xa5, 0x5a, 11)
        );
        Ok(())
    }

    #[test]
    fn unselected_storage_and_srq_receive_limits_are_not_read() -> Result {
        let mut storage = MaybeUninit::<bindings::ib_qp_attr>::uninit();
        let raw = storage.as_mut_ptr();
        // SAFETY: No fields are selected, so none require initialization.
        let empty = unsafe { QueuePairChange::from_raw(raw, 0, true)? };
        assert_eq!(empty.mask(), 0);
        assert!(empty.state.is_none());
        assert!(empty.capacity.is_none());
        assert!(empty.primary.is_none());
        assert!(empty.alternate.is_none());

        // SAFETY: These writes initialize only the selected fields in exclusive storage.
        unsafe {
            (&raw mut (*raw).cap.max_send_wr).write(7);
            (&raw mut (*raw).cap.max_send_sge).write(3);
            (&raw mut (*raw).cap.max_inline_data).write(29);
            (&raw mut (*raw).cur_qp_state).write(bindings::ib_qp_state_IB_QPS_RTS);
        }
        let mask = bindings::ib_qp_attr_mask_IB_QP_CAP | bindings::ib_qp_attr_mask_IB_QP_CUR_STATE;
        // SAFETY: Only current state and send capacities are selected. The absent private
        // receive queue excludes its fields; qp_state and max_rdma_ctxs remain uninitialized.
        let change = unsafe { QueuePairChange::from_raw(raw, mask, false)? };
        assert_eq!(change.current_state, Some(QueuePairState::ReadyToSend));
        assert!(change.state.is_none());
        let capacity = change.capacity.unwrap();
        assert_eq!(capacity.send.work_requests, 7);
        assert_eq!(capacity.send.scatter_gather, 3);
        assert_eq!(capacity.inline, 29);
        assert!(capacity.receive.is_none());
        Ok(())
    }

    #[test]
    fn invalid_mask_and_state_encodings_are_rejected() {
        let mut storage = MaybeUninit::<bindings::ib_qp_attr>::uninit();
        let raw = storage.as_mut_ptr();
        // SAFETY: Unknown mask bits are rejected before the uninitialized state is read.
        let invalid = unsafe { QueuePairChange::from_raw(raw, u32::MAX, true) };
        assert!(matches!(invalid, Err(EOPNOTSUPP)));
        // SAFETY: The selected state is initialized; every other field remains unselected.
        unsafe { (&raw mut (*raw).qp_state).write(u32::MAX) };
        // SAFETY: Only the initialized state is selected.
        let invalid =
            unsafe { QueuePairChange::from_raw(raw, bindings::ib_qp_attr_mask_IB_QP_STATE, true) };
        assert!(matches!(invalid, Err(EINVAL)));
        for value in 0..=bindings::ib_qp_state_IB_QPS_ERR {
            assert_eq!(
                QueuePairState::from_encoding(value).unwrap().encoding(),
                value
            );
        }
    }
}
