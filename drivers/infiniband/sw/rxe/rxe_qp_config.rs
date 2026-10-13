// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Copied transport configuration, published under the QP state lock.

#![forbid(unsafe_code)]

use super::{
    rxe_ah::Addresses,
    rxe_av::AddressVector,
    rxe_param as params,
    rxe_queue::Producer,
    rxe_send::Request, //
};
use kernel::{
    prelude::*,
    rdma::{
        AccessFlags,
        QueuePairAttributes,
        QueuePairChange,
        QueuePairInitAttributes,
        QueuePairState,
        QueuePairType, //
    },
    sync::{
        atomic::Atomic,
        Mutex,
        SpinLockIrq, //
    }, //
};

/// Sleepable control serialization and IRQ-safe transport configuration.
#[pin_data]
pub(crate) struct Control {
    pub(crate) multicast: Atomic<u32>,
    #[pin]
    pub(super) events: SpinLockIrq<u32>,
    #[pin]
    pub(crate) operation: Mutex<()>,
    #[pin]
    pub(crate) state: SpinLockIrq<Shared>,
    #[pin]
    pub(crate) send_producer: SpinLockIrq<Producer>,
    #[pin]
    pub(crate) receive_producer: SpinLockIrq<Producer>,
}

impl Control {
    /// Copies one coherent configuration sample for a core query.
    pub(crate) fn query(
        &self,
        capacity: Capacity,
        receive_psn: u32,
        send_psn: u32,
    ) -> QueuePairAttributes {
        let shared = self.state.lock();
        let attributes = &shared.attributes;
        let traffic = &shared.traffic;
        let state = QueuePairState::from_encoding(attributes.qp_state).expect("validated QP state");
        QueuePairAttributes {
            state,
            current_state: state,
            draining: attributes.sq_draining,
            draining_notification: attributes.en_sqd_async_notify,
            path_mtu: traffic.path_mtu,
            migration_state: attributes.path_mig_state,
            access: traffic.access(),
            qkey: attributes.qkey,
            receive_psn,
            send_psn,
            destination: traffic.destination,
            capacity,
            primary: Some(shared.primary.attributes()),
            alternate: Some(shared.alternate.attributes()),
            pkey_index: attributes.pkey_index,
            alternate_pkey_index: attributes.alt_pkey_index,
            max_read_atomic: traffic.max_rd_atomic,
            max_destination_read_atomic: traffic.max_dest_rd_atomic,
            min_rnr_timer: traffic.min_rnr_timer,
            port: attributes.port_num,
            timeout: traffic.timeout,
            retry: traffic.retry,
            rnr_retry: traffic.rnr,
            alternate_port: attributes.alt_port_num,
            alternate_timeout: attributes.alt_timeout,
        }
    }

    /// Copies the connected path or resolves a datagram's owned address metadata.
    pub(crate) fn address(
        &self,
        connected: bool,
        addresses: &Addresses,
        pd: u32,
        request: &Request,
    ) -> Option<AddressVector> {
        if connected {
            return Some(self.state.lock().primary);
        }
        let number = request.address_handle();
        if number == 0 {
            super::rxe_av::decode(request.legacy_address_vector()).ok()
        } else {
            addresses.lookup(pd, number)
        }
    }

    pub(crate) fn new() -> Result<Pin<KBox<Self>>> {
        let state = Shared {
            valid: false,
            resetting: false,
            generation: 0,
            attributes: Attributes::zeroed(),
            traffic: Config {
                path_mtu: 1,
                mtu: 256,
                ..Config::zeroed()
            },
            primary: AddressVector::zeroed(),
            alternate: AddressVector::zeroed(),
            retrans_timeout: false,
            rnr_timeout: false,
        };
        KBox::pin_init(
            pin_init!(Self {
                multicast: Atomic::new(0),
                events <- kernel::new_spinlock_irq!(0),
                operation <- kernel::new_mutex!(()),
                state <- kernel::new_spinlock_irq!(state),
                send_producer <- kernel::new_spinlock_irq!(Producer::zeroed()),
                receive_producer <- kernel::new_spinlock_irq!(Producer::zeroed()),
            }),
            GFP_KERNEL,
        )
    }
}

/// Scalar query attributes, without borrowed core address or capability storage.
#[derive(Clone, Copy, Zeroable)]
pub(crate) struct Attributes {
    pub(crate) qp_state: u32,
    pub(crate) sq_draining: u8,
    pub(crate) en_sqd_async_notify: u8,
    pub(crate) pkey_index: u16,
    pub(crate) qkey: u32,
    pub(crate) port_num: u32,
    pub(crate) alt_port_num: u32,
    pub(crate) alt_pkey_index: u16,
    pub(crate) alt_timeout: u8,
    pub(crate) path_mig_state: u32,
}

/// State shared by ingress, timers, transport tasks and control operations.
///
/// The native IRQ lock owns every mutable field. Transport tasks copy settings before
/// dropping the guard; no borrow can survive unlocking or cross a sleeping operation.
pub(crate) struct Shared {
    pub(crate) valid: bool,
    // RESET closes admission independently of asynchronous error transitions.
    pub(crate) resetting: bool,
    pub(crate) generation: u32,
    pub(crate) attributes: Attributes,
    pub(crate) traffic: Config,
    pub(crate) primary: AddressVector,
    pub(crate) alternate: AddressVector,
    pub(crate) retrans_timeout: bool,
    pub(crate) rnr_timeout: bool,
}

/// Validated address snapshots captured before a QP modification changes state.
#[derive(Default)]
pub(crate) struct Paths {
    pub(crate) primary: Option<AddressVector>,
    pub(crate) alternate: Option<AddressVector>,
}

pub(crate) use kernel::rdma::{
    QueuePairCapacity as Capacity,
    WorkQueueCapacity as QueueCapacity, //
};

/// Checks both private queues while excluding SRQ-owned receive limits.
pub(crate) fn check_capacity(capacity: &Capacity) -> Result {
    fn check_queue(queue: &QueueCapacity) -> Result {
        if queue.work_requests > params::RXE_MAX_QP_WR || queue.scatter_gather > params::RXE_MAX_SGE
        {
            return Err(EINVAL);
        }
        Ok(())
    }
    check_queue(&capacity.send)?;
    if let Some(receive) = &capacity.receive {
        check_queue(receive)?;
    }
    if capacity.inline as usize > params::RXE_MAX_INLINE_DATA {
        return Err(EINVAL);
    }
    Ok(())
}

/// Checks basic creation limits and RXE's single management port.
pub(crate) fn check_init(attributes: &QueuePairInitAttributes) -> Result {
    check_capacity(&attributes.capacity)?;
    if attributes.kind == QueuePairType::GeneralService && attributes.management_port != Some(1) {
        return Err(EINVAL);
    }
    Ok(())
}

/// Validates native modification values and captures paths before changing transport state.
pub(crate) fn check_change(change: &QueuePairChange, connected: bool) -> Result<Paths> {
    // Preserve alternate-path metadata for modify/query compatibility. Transport
    // uses the primary path; RXE does not advertise automatic path migration.
    if change.migration_state.is_some_and(|state| {
        !matches!(
            state,
            kernel::bindings::ib_mig_state_IB_MIG_MIGRATED
                | kernel::bindings::ib_mig_state_IB_MIG_REARM
                | kernel::bindings::ib_mig_state_IB_MIG_ARMED
        )
    }) {
        return Err(EINVAL);
    }
    if change.port.is_some_and(|port| port != 1) {
        return Err(EINVAL);
    }
    if let Some(capacity) = &change.capacity {
        check_capacity(capacity)?;
    }
    if let Some(access) = change.access {
        if !connected || u32::from(access) & !params::RXE_ACCESS_SUPPORTED_QP != 0 {
            return Err(EINVAL);
        }
    }
    let primary = change
        .primary
        .map(AddressVector::from_request)
        .transpose()?;
    let alternate = change
        .alternate
        .map(|path| {
            if path.port != 1 || path.timeout > 31 {
                return Err(EINVAL);
            }
            AddressVector::from_request(path.address)
        })
        .transpose()?;
    if change.path_mtu.is_some_and(|mtu| {
        !(kernel::rdma::Mtu::Mtu256.encoding()..=kernel::rdma::Mtu::Mtu4096.encoding())
            .contains(&mtu)
    }) {
        return Err(EINVAL);
    }
    if change
        .max_read_atomic
        .is_some_and(|value| u32::from(value) > params::RXE_MAX_QP_RD_ATOM)
    {
        return Err(EINVAL);
    }
    if change
        .max_destination_read_atomic
        .is_some_and(|value| u32::from(value) > params::RXE_MAX_QP_RD_ATOM)
    {
        return Err(EINVAL);
    }
    if change.timeout.is_some_and(|timeout| timeout > 31)
        || change.min_rnr_timer.is_some_and(|timer| timer > 31)
        || change.retry.is_some_and(|retry| retry > 7)
        || change.rnr_retry.is_some_and(|retry| retry > 7)
    {
        return Err(EINVAL);
    }
    Ok(Paths { primary, alternate })
}

/// Mutable transport settings, independent of task-owned progress and core attribute storage.
///
/// A published QP reads or changes this value only under its state lock. Packet processing
/// retains a copy, allowing control updates without aliasing requester or responder borrows.
#[derive(Clone, Copy, Zeroable)]
pub(crate) struct Config {
    pub(crate) mtu: u32,
    pub(crate) path_mtu: u32,
    pub(crate) access_bits: u32,
    pub(crate) destination: u32,
    pub(crate) source_port: u16,
    pub(crate) timeout: u8,
    pub(crate) timeout_jiffies: u64,
    pub(crate) min_rnr_timer: u8,
    pub(crate) retry: u8,
    pub(crate) rnr: u8,
    pub(crate) max_rd_atomic: u8,
    pub(crate) max_dest_rd_atomic: u8,
}

impl Config {
    pub(crate) fn access(&self) -> AccessFlags {
        AccessFlags::from_bits(self.access_bits)
    }
}
