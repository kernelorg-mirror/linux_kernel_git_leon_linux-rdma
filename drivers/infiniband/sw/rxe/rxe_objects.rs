// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Native queue-pair ownership, publication and identity reservation.

#![forbid(unsafe_code)]

use super::{
    rxe_comp::Retransmit,
    rxe_device::DeviceData,
    rxe_id::Identities,
    rxe_inflight::Inflight,
    rxe_mmap::Mappings,
    rxe_param as params,
    rxe_qp_config::{
        check_init,
        Control, //
    },
    rxe_queue::{
        ReceiveQueue,
        SendQueue, //
    },
    rxe_req::ReceiverReady,
    rxe_req_state::ReadCredits,
    rxe_task_ffi::Task,
    rxe_types::{
        QueuePair,
        QueuePairRef, //
    },
    rxe_uapi, //
};
use kernel::{
    bindings,
    prelude::*,
    rbtree::{
        RBTree,
        RBTreeNodeReservation, //
    },
    rdma::{
        ContextData,
        QueuePairCreation,
        QueuePairInitAttributes,
        QueuePairParents,
        QueuePairType, //
    },
    sync::{
        atomic::Atomic,
        static_lock_class,
        Mutex,
        SpinLockIrq, //
    },
    time::timer::Timer,
    types::ScopeGuard, //
};

const _: () = assert!(size_of::<bindings::rxe_create_cq_resp>() == rxe_uapi::MAPPING_SIZE);
const _: () = assert!(size_of::<bindings::rxe_resize_cq_resp>() == rxe_uapi::MAPPING_SIZE);
const _: () = assert!(size_of::<bindings::rxe_create_qp_resp>() == rxe_uapi::QP_RESPONSE_SIZE);
const _: () = assert!(size_of::<bindings::rxe_create_srq_resp>() == rxe_uapi::SRQ_RESPONSE_SIZE);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_create_qp_resp, rq_mi) == 0);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_create_qp_resp, sq_mi) == 16);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_create_srq_resp, srq_num) == 16);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_create_srq_resp, reserved) == 20);

/// All provider state is owned separately from the opaque C QP header.
pub(crate) struct Owner {
    pub(crate) index: u32,
    pub(crate) pd: u32,
    pub(crate) gsi: bool,
    pub(crate) sq: SendQueue,
    pub(crate) rq: ReceiveQueue,
    pub(crate) send_task: Task,
    pub(crate) recv_task: Task,
    pub(crate) recv_psn: Atomic<u32>,
    pub(crate) send_psn: Atomic<u32>,
    pub(crate) read_credits: ReadCredits,
    pub(crate) inflight: Inflight,
    pub(crate) retrans_timer: Timer<Retransmit>,
    pub(crate) rnr_nak_timer: Timer<ReceiverReady>,
    pub(crate) control: Pin<KBox<Control>>,
}

pub(crate) type Publication = RBTreeNodeReservation<u32, QueuePairRef>;

/// Cyclic identities are released only after core reference draining and native cleanup.
#[pin_data]
pub(crate) struct Pairs {
    #[pin]
    identities: Mutex<Identities>,
    #[pin]
    published: SpinLockIrq<RBTree<u32, QueuePairRef>>,
}

impl Pairs {
    pub(crate) fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            identities <- kernel::new_mutex!(Identities::new(
                params::RXE_MIN_QP_INDEX,
                params::RXE_MAX_QP_INDEX,
                params::RXE_MAX_QP,
            )),
            published <- kernel::new_spinlock_irq!(RBTree::new()),
        })
    }

    pub(crate) fn lookup(&self, index: u32) -> Option<QueuePairRef> {
        self.published.lock().get(&index).cloned()
    }

    pub(crate) fn publish(&self, qp: QueuePairRef, node: Publication) {
        self.published
            .lock()
            .insert(node.into_node(qp.data().index, qp));
    }

    pub(crate) fn unpublish(&self, index: u32) {
        let removed = self.published.lock().remove_node(&index);
        drop(removed);
    }

    /// Retains each visited QP under the registry lock, then releases the lock before use.
    pub(crate) fn visit(&self, mut visit: impl FnMut(&QueuePair)) {
        let mut next = 0;
        loop {
            let qp = {
                let pairs = self.published.lock();
                pairs
                    .cursor_lower_bound(&next)
                    .map(|cursor| cursor.current().1.clone())
            };
            let Some(qp) = qp else { break };
            next = qp.data().index + 1;
            visit(&qp);
        }
    }

    pub(crate) fn create(
        &self,
        device: Pin<&DeviceData>,
        parents: QueuePairParents<'_, DeviceData>,
        mut attributes: QueuePairInitAttributes,
        data: Option<ContextData<'_, DeviceData>>,
    ) -> Result<QueuePairCreation<KBox<Owner>, Publication>> {
        check_init(&attributes)?;
        let user = data.is_some();
        let (context, output) = if let Some(data) = data {
            let (context, data) = data.split();
            let present = data.has_output_buffer();
            let (input, output) = data.split();
            if !input.is_empty() || output.len() < rxe_uapi::QP_RESPONSE_SIZE {
                return Err(EINVAL);
            }
            (Some(context), present.then_some(output))
        } else {
            (None, None)
        };
        let (receive_output, send_output) = rxe_uapi::split_mapping(output)?;
        let publication = Publication::new(GFP_KERNEL)?;
        let allocation = KBox::<Owner>::new_uninit(GFP_KERNEL)?;
        let index = self.identities.lock().allocate()?;
        let identity = ScopeGuard::new(|| self.identities.lock().release(index));
        let gsi = attributes.kind == QueuePairType::GeneralService;
        let number = if gsi { 1 } else { index };
        let control = Control::new()?;
        {
            let mut shared = control.state.lock();
            shared.valid = true;
            shared.attributes.qp_state = bindings::ib_qp_state_IB_QPS_RESET;
            if gsi {
                shared.attributes.port_num = attributes.management_port.unwrap();
            }
            shared.traffic.source_port =
                (params::RXE_ROCE_V2_SPORT + kernel::hash::hash_32::<14>(number)) as u16;
        }
        let send_task = Task::new()?;
        let recv_task = Task::new()?;
        let retrans_timer = Timer::new(c"rxe retransmit", static_lock_class!())?;
        let rnr_nak_timer = Timer::new(c"rxe receiver ready", static_lock_class!())?;
        let sq = SendQueue::new(
            &device.mappings,
            &mut attributes.capacity,
            user,
            context,
            send_output,
        )?;
        let sq = ScopeGuard::new_with_data(sq, |queue| queue.release(&device.mappings));
        let rq = ReceiveQueue::new(
            &device.mappings,
            &mut attributes.capacity,
            context,
            receive_output,
        )?;
        let rq = ScopeGuard::new_with_data(rq, |queue| queue.release(&device.mappings));
        if gsi {
            device
                .port
                .claim_gsi(core::num::NonZero::new(index).unwrap())?;
        }
        // No fallible operation follows the GSI reservation or ownership transfer.
        let owner = allocation.write(Owner {
            index,
            pd: parents.domain().index(),
            gsi,
            sq: sq.dismiss(),
            rq: rq.dismiss(),
            send_task,
            recv_task,
            retrans_timer,
            rnr_nak_timer,
            control,
            recv_psn: Atomic::new(0),
            send_psn: Atomic::new(0),
            read_credits: ReadCredits::zeroed(),
            inflight: Inflight::zeroed(),
        });
        identity.dismiss();
        Ok(QueuePairCreation {
            owner,
            publication,
            number,
            capacity: attributes.capacity,
        })
    }

    pub(crate) fn release(&self, mappings: &Mappings, owner: KBox<Owner>) {
        let index = owner.index;
        KBox::into_inner(owner).release(mappings);
        self.identities.lock().release(index);
    }
}

impl Owner {
    fn release(self, mappings: &Mappings) {
        self.sq.release(mappings);
        self.rq.release(mappings);
    }
}
