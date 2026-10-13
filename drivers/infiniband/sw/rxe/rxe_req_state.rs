// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Request segmentation, packet contents and bounded retry reconstruction.

#![forbid(unsafe_code)]

use super::{
    rxe_mr::MrRef,
    rxe_mr_data::Buffer,
    rxe_send::SendWqe,
    rxe_wire::{
        Base,
        Extension,
        TransportMut, //
    }, //
};
use crate::rxe_param::{
    GSI_QKEY,
    RXE_ATMETH_MASK,
    RXE_ATOMIC_WRITE_MASK,
    RXE_DETH_MASK,
    RXE_END_MASK,
    RXE_FETH_MASK,
    RXE_FLUSH_MASK,
    RXE_IETH_MASK,
    RXE_IMMDT_MASK,
    RXE_MAX_PKT_PER_ACK,
    RXE_READ_MASK,
    RXE_RETH_MASK,
    RXE_SEND_MASK,
    RXE_START_MASK,
    RXE_WRITE_MASK,
    RXE_WRITE_OR_SEND_MASK,
    WQE_STATE_DONE,
    WQE_STATE_PENDING,
    WQE_STATE_POSTED,
    WQE_STATE_PROCESSING,
    WR_ATOMIC_MASK,
    WR_ATOMIC_WRITE_MASK,
    WR_FLUSH_MASK,
    WR_INLINE_MASK,
    WR_MAX_QPT,
    WR_READ_MASK,
    WR_READ_OR_WRITE_MASK,
    WR_WRITE_OR_SEND_MASK, //
};
use core::num::NonZeroU32;
use kernel::bindings::{
    ib_qp_type_IB_QPT_GSI as IB_QPT_GSI,
    ib_qp_type_IB_QPT_RC as IB_QPT_RC,
    ib_qp_type_IB_QPT_UC as IB_QPT_UC,
    ib_qp_type_IB_QPT_UD as IB_QPT_UD,
    ib_send_flags_IB_SEND_INLINE as IB_SEND_INLINE,
    ib_send_flags_IB_SEND_SOLICITED as IB_SEND_SOLICITED,
    ib_wr_opcode_IB_WR_ATOMIC_CMP_AND_SWP as IB_WR_ATOMIC_CMP_AND_SWP,
    ib_wr_opcode_IB_WR_ATOMIC_FETCH_AND_ADD as IB_WR_ATOMIC_FETCH_AND_ADD,
    ib_wr_opcode_IB_WR_ATOMIC_WRITE as IB_WR_ATOMIC_WRITE,
    ib_wr_opcode_IB_WR_FLUSH as IB_WR_FLUSH,
    ib_wr_opcode_IB_WR_LOCAL_INV as IB_WR_LOCAL_INV,
    ib_wr_opcode_IB_WR_RDMA_READ as IB_WR_RDMA_READ,
    ib_wr_opcode_IB_WR_RDMA_READ_WITH_INV as IB_WR_RDMA_READ_WITH_INV,
    ib_wr_opcode_IB_WR_RDMA_WRITE as IB_WR_RDMA_WRITE,
    ib_wr_opcode_IB_WR_RDMA_WRITE_WITH_IMM as IB_WR_RDMA_WRITE_WITH_IMM,
    ib_wr_opcode_IB_WR_REG_MR as IB_WR_REG_MR,
    ib_wr_opcode_IB_WR_SEND as IB_WR_SEND,
    ib_wr_opcode_IB_WR_SEND_WITH_IMM as IB_WR_SEND_WITH_IMM,
    ib_wr_opcode_IB_WR_SEND_WITH_INV as IB_WR_SEND_WITH_INV,
    IB_OPCODE_RC_ATOMIC_WRITE,
    IB_OPCODE_RC_COMPARE_SWAP,
    IB_OPCODE_RC_FETCH_ADD,
    IB_OPCODE_RC_FLUSH,
    IB_OPCODE_RC_RDMA_READ_REQUEST,
    IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE,
    IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE,
    IB_OPCODE_UD_SEND_ONLY,
    IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE, //
};
use kernel::{
    prelude::*,
    sync::atomic::{
        Atomic,
        Full,
        Relaxed, //
    },
};

/// Requester state owned by RXE.
#[derive(Zeroable)]
pub(crate) struct Requester {
    pub(crate) wqe_index: i32,
    pub(crate) psn: u32,
    pub(crate) opcode: i32,
    pub(crate) wait_fence: bool,
    pub(crate) need_rd_atomic: bool,
    pub(crate) wait_psn: bool,
    pub(crate) need_retry: bool,
    pub(crate) wait_for_rnr_timer: bool,
    pub(crate) noack_pkts: i32,
    pub(crate) again: bool,
}

/// Negotiated read/atomic credits shared with the serialized QP control path.
#[derive(Zeroable)]
pub(crate) struct ReadCredits {
    // High word: negotiated limit. Low word: outstanding requests. Changing the
    // limit must retain credits held by requests awaiting a response in SQD.
    state: Atomic<u64>,
}

impl ReadCredits {
    pub(crate) fn set(&self, limit: u32) {
        let mut state = self.state.load(Relaxed);
        loop {
            let next = (u64::from(limit) << 32) | u64::from(state as u32);
            match self.state.cmpxchg(state, next, Full) {
                Ok(_) => return,
                Err(current) => state = current,
            }
        }
    }

    /// Forgets flushed requests while both transport tasks are stopped during RESET.
    pub(crate) fn reset(&self) {
        self.state
            .store(self.state.load(Relaxed) & !u64::from(u32::MAX), Relaxed);
    }

    #[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
    fn available(&self) -> u32 {
        let state = self.state.load(Relaxed);
        ((state >> 32) as u32).saturating_sub(state as u32)
    }

    pub(crate) fn outstanding(&self) -> u32 {
        self.state.load(Relaxed) as u32
    }

    fn take(&self) -> bool {
        let mut state = self.state.load(Relaxed);
        loop {
            if state as u32 >= (state >> 32) as u32 {
                return false;
            }
            match self.state.cmpxchg(state, state + 1, Full) {
                Ok(_) => return true,
                Err(current) => state = current,
            }
        }
    }

    fn release(&self) {
        self.state.fetch_sub(1, Relaxed);
    }
}

impl Requester {
    pub(crate) fn wake_psn(&mut self) {
        if self.wait_psn {
            self.wait_psn = false;
            self.again = true;
        }
    }

    pub(crate) fn wake_fence(&mut self) {
        if self.wait_fence {
            self.wait_fence = false;
            self.again = true;
        }
    }

    pub(crate) fn take_read_credit(&mut self, credits: &ReadCredits) -> bool {
        self.need_rd_atomic = !credits.take();
        !self.need_rd_atomic
    }

    /// Returns whether the completer should cancel timeout retry after waking the requester.
    pub(crate) fn release_read_credit(&mut self, credits: &ReadCredits) -> bool {
        credits.release();
        if self.need_rd_atomic {
            self.need_rd_atomic = false;
            self.again = true;
            true
        } else {
            false
        }
    }
}

/// Copied queue and transport parameters for one serialized requester invocation.
pub(super) struct Config {
    pub(super) kind: u32,
    pub(super) mtu: NonZeroU32,
    pub(super) max_sge: u32,
    pub(super) max_inline: usize,
    pub(super) queue_mask: u32,
    pub(super) source: u32,
    pub(super) destination: u32,
    pub(super) source_port: u16,
}

pub(super) fn work_mask(kind: u32, opcode: u32) -> u32 {
    if opcode > IB_WR_REG_MR || kind >= WR_MAX_QPT || opcode == IB_WR_RDMA_READ_WITH_INV {
        return 0;
    }
    super::rxe_opcode::work_mask(opcode, kind)
}

/// Rejects an invalid shared-ring request before any transport packet is emitted.
pub(super) fn validate_work(wqe: &SendWqe<'_>, config: &Config) -> Result {
    if wqe.mask == 0 || wqe.dma.length > super::rxe_param::RXE_PORT_MAX_MSG_SZ {
        return Err(EINVAL);
    }
    if wqe.mask & WR_READ_MASK != 0 && wqe.dma.length.div_ceil(config.mtu.get()) > 0x800000 {
        return Err(EINVAL);
    }
    if wqe.mask & WR_ATOMIC_MASK != 0 && (wqe.dma.length != 8 || wqe.iova & 7 != 0) {
        return Err(EINVAL);
    }
    if wqe.wr.send_flags & IB_SEND_INLINE as u32 != 0 {
        if wqe.mask & WR_INLINE_MASK == 0 || wqe.dma.length as usize > config.max_inline {
            return Err(EINVAL);
        }
    } else if wqe.mask & (WR_WRITE_OR_SEND_MASK | WR_READ_MASK | WR_ATOMIC_MASK) != 0
        && (wqe.dma.num_sge > config.max_sge
            || (wqe.dma.resid != 0 && wqe.dma.cur_sge >= config.max_sge))
    {
        return Err(EINVAL);
    }
    Ok(())
}

/// Keeps outstanding reservations within half the PSN space, including the endpoint.
pub(super) fn read_fits_window(
    wqe: &SendWqe<'_>,
    config: &Config,
    requester: u32,
    completer: u32,
) -> bool {
    let outstanding = requester.wrapping_sub(completer) & 0xffffff;
    wqe.mask & WR_READ_MASK == 0
        || outstanding + wqe.dma.resid.div_ceil(config.mtu.get()).max(1) <= 0x800000
}

pub(super) fn advance(progress: &mut Requester, queue_mask: u32) {
    progress.wqe_index = ((progress.wqe_index as u32).wrapping_add(1) & queue_mask) as i32;
}

fn select_opcode(kind: u32, previous: i32, opcode: u32, fits: bool) -> Result<u8> {
    if matches!(kind, IB_QPT_UD | IB_QPT_GSI) {
        return match opcode {
            IB_WR_SEND => Ok(IB_OPCODE_UD_SEND_ONLY as u8),
            IB_WR_SEND_WITH_IMM => Ok(IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE as u8),
            _ => Err(EINVAL),
        };
    }
    if kind != IB_QPT_RC && kind != IB_QPT_UC {
        return Err(EINVAL);
    }
    let transport = if kind == IB_QPT_UC { 0x20 } else { 0 };
    let write = matches!(opcode, IB_WR_RDMA_WRITE | IB_WR_RDMA_WRITE_WITH_IMM);
    let send = matches!(opcode, IB_WR_SEND | IB_WR_SEND_WITH_IMM)
        || (kind == IB_QPT_RC && opcode == IB_WR_SEND_WITH_INV);
    if write || send {
        let first = transport + if write { 6 } else { 0 };
        let middle = first + 1;
        let continued = previous == first || previous == middle;
        let last = if continued { first + 2 } else { first + 4 };
        let selected = if !fits {
            if continued {
                middle
            } else {
                first
            }
        } else if opcode == IB_WR_SEND_WITH_INV {
            if continued {
                IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE as i32
            } else {
                IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE as i32
            }
        } else if matches!(opcode, IB_WR_RDMA_WRITE_WITH_IMM | IB_WR_SEND_WITH_IMM) {
            last + 1
        } else {
            last
        };
        return Ok(selected as u8);
    }
    if kind == IB_QPT_UC {
        return Err(EINVAL);
    }
    Ok(match opcode {
        IB_WR_FLUSH => IB_OPCODE_RC_FLUSH,
        IB_WR_RDMA_READ => IB_OPCODE_RC_RDMA_READ_REQUEST,
        IB_WR_ATOMIC_CMP_AND_SWP => IB_OPCODE_RC_COMPARE_SWAP,
        IB_WR_ATOMIC_FETCH_AND_ADD => IB_OPCODE_RC_FETCH_ADD,
        IB_WR_ATOMIC_WRITE => IB_OPCODE_RC_ATOMIC_WRITE,
        IB_WR_REG_MR | IB_WR_LOCAL_INV => opcode,
        _ => return Err(EINVAL),
    } as u8)
}

pub(super) fn next_opcode(progress: &Requester, wqe: &SendWqe<'_>, config: &Config) -> Result<u8> {
    select_opcode(
        config.kind,
        progress.opcode,
        wqe.wr.opcode,
        wqe.dma.resid <= config.mtu.get(),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Replay {
    Stop,
    Skip,
    Prepared,
}

/// Restores one retained request without reading client progress or wrapping addresses.
pub(super) fn retry_work(
    progress: &mut Requester,
    wqe: &mut SendWqe<'_>,
    config: &Config,
    completed_psn: u32,
    first: &mut bool,
) -> Result<Replay> {
    let mask = work_mask(config.kind, wqe.wr.opcode);
    if wqe.state == WQE_STATE_POSTED && !wqe.replaying {
        return Ok(Replay::Stop);
    }
    if wqe.state == WQE_STATE_DONE {
        return Ok(Replay::Skip);
    }
    if mask == 0
        || (mask & (WR_WRITE_OR_SEND_MASK | WR_READ_MASK | WR_ATOMIC_MASK) != 0
            && wqe.wr.send_flags & IB_SEND_INLINE as u32 == 0
            && wqe.dma.num_sge > config.max_sge)
    {
        return Err(EINVAL);
    }
    wqe.iova = if mask
        & (WR_ATOMIC_MASK | WR_READ_OR_WRITE_MASK | WR_FLUSH_MASK | WR_ATOMIC_WRITE_MASK)
        != 0
    {
        wqe.wr.address()
    } else {
        0
    };
    if !*first || mask & WR_READ_MASK == 0 {
        wqe.dma.reset();
    }
    if *first {
        *first = false;
        if mask & WR_WRITE_OR_SEND_MASK != 0 {
            let npsn = completed_psn.wrapping_sub(wqe.first_psn) & 0xffffff;
            if npsn >= wqe.dma.length.div_ceil(config.mtu.get()).max(1) {
                return Err(EINVAL);
            }
            if npsn != 0 {
                // Every acknowledged fragment precedes the terminal packet and is a
                // full MTU. Seek once through the bounded SGE list, even for a 2 GiB WR.
                let length = npsn.checked_mul(config.mtu.get()).ok_or(EINVAL)?;
                progress.opcode = i32::from(select_opcode(config.kind, -1, wqe.wr.opcode, false)?);
                if npsn > 1 {
                    progress.opcode = i32::from(select_opcode(
                        config.kind,
                        progress.opcode,
                        wqe.wr.opcode,
                        false,
                    )?);
                }
                if wqe.wr.send_flags & IB_SEND_INLINE as u32 != 0 {
                    wqe.dma.resid = wqe.dma.resid.checked_sub(length).ok_or(EINVAL)?;
                    wqe.dma.sge_offset = length;
                } else {
                    wqe.dma()?.advance(length as usize)?;
                }
            }
        }
        if mask & WR_READ_MASK != 0 {
            let consumed = wqe.dma.length.checked_sub(wqe.dma.resid).ok_or(EINVAL)?;
            let remaining = wqe.last_psn.wrapping_sub(completed_psn) & 0xffffff;
            if super::rxe_wire::psn_compare(completed_psn, wqe.first_psn) < 0
                || remaining >= 0x800000
                || remaining + 1 != wqe.dma.resid.div_ceil(config.mtu.get()).max(1)
                || consumed % config.mtu.get() != 0
            {
                return Err(EINVAL);
            }
            wqe.iova = wqe.iova.checked_add(u64::from(consumed)).ok_or(EINVAL)?;
        }
    }
    // Do not admit responses until this replay is sent, but keep it eligible
    // while SQD blocks work which has never started.
    wqe.state = WQE_STATE_POSTED;
    wqe.replaying = true;
    Ok(Replay::Prepared)
}

/// Selects base-header fields and updates acknowledgment pacing.
pub(super) fn base(
    progress: &mut Requester,
    wqe: &SendWqe<'_>,
    config: &Config,
    opcode: u8,
) -> Base {
    let mask = super::rxe_opcode::info(opcode).mask;
    let wr = &wqe.wr;
    let solicited = wr.send_flags & IB_SEND_SOLICITED as u32 != 0
        && mask & RXE_END_MASK != 0
        && (mask & RXE_SEND_MASK != 0
            || mask & (RXE_WRITE_MASK | RXE_IMMDT_MASK) == RXE_WRITE_MASK | RXE_IMMDT_MASK);
    let qpn = if mask & RXE_DETH_MASK != 0 {
        wr.destination()
    } else {
        config.destination
    };
    let mut ack = false;
    if !matches!(config.kind, IB_QPT_UD | IB_QPT_UC) {
        ack = mask & RXE_END_MASK != 0;
        if !ack {
            ack = progress.noack_pkts > RXE_MAX_PKT_PER_ACK as i32;
            progress.noack_pkts = progress.noack_pkts.wrapping_add(1);
        }
    }
    if ack {
        progress.noack_pkts = 0;
    }
    Base {
        opcode,
        psn: progress.psn,
        qpn,
        solicited,
        ack,
    }
}

/// Encodes only extensions present in the checked packet layout.
pub(super) fn encode(wire: &mut TransportMut<'_>, wqe: &SendWqe<'_>, config: &Config) -> Result {
    let opcode = wire.opcode();
    let mask = wire.mask();
    let wr = &wqe.wr;
    if mask & RXE_RETH_MASK != 0 {
        let key = if mask & RXE_FETH_MASK != 0 {
            wr.flush().key
        } else {
            wr.remote_key()
        };
        wire.set(Extension::Remote {
            address: wqe.iova,
            key,
            length: wqe.dma.resid,
        })?;
    }
    if mask & RXE_FETH_MASK != 0 {
        wire.set(Extension::Flush {
            kind: wr.flush().kind,
            level: wr.flush().level,
        })?;
    }
    if mask & RXE_IMMDT_MASK != 0 {
        wire.set(Extension::Immediate(wr.immediate()))?;
    }
    if mask & RXE_IETH_MASK != 0 {
        wire.set(Extension::Invalidate(wr.invalidate_key()))?;
    }
    if mask & RXE_ATMETH_MASK != 0 {
        let (swap, compare) = if u32::from(opcode) == IB_OPCODE_RC_COMPARE_SWAP {
            (wr.swap(), wr.compare_add())
        } else {
            (wr.compare_add(), 0)
        };
        wire.set(Extension::Atomic {
            address: wqe.iova,
            key: wr.atomic_key(),
            swap,
            compare,
        })?;
    }
    if mask & RXE_DETH_MASK != 0 {
        let key = if config.source == 1 {
            GSI_QKEY
        } else {
            wr.datagram_key()
        };
        wire.set(Extension::Datagram {
            key,
            source: config.source,
        })?;
    }
    Ok(())
}

/// Fills bounded inline, scatter-list or atomic-write payload storage.
pub(super) fn fill(
    wire: &mut TransportMut<'_>,
    wqe: &mut SendWqe<'_>,
    max_inline: usize,
    lookup: impl FnMut(u32) -> Option<MrRef>,
) -> Result {
    let mask = wire.mask();
    if mask & (RXE_WRITE_OR_SEND_MASK | RXE_ATOMIC_WRITE_MASK) != 0 {
        let data = wire.payload()?;
        if mask & RXE_ATOMIC_WRITE_MASK != 0 {
            wqe.copy_atomic_write(data)?;
        } else if wqe.wr.send_flags & IB_SEND_INLINE as u32 != 0 {
            wqe.copy_inline(data, max_inline)?;
        } else {
            wqe.dma()?.copy(Buffer::Read(data), lookup)?;
        }
    } else if mask & RXE_FLUSH_MASK != 0 {
        wqe.dma.resid = 0;
    }
    Ok(())
}

/// Advances send progress after successful network handoff.
pub(super) fn update(
    progress: &mut Requester,
    wqe: &mut SendWqe<'_>,
    config: &Config,
    opcode: u8,
    payload: u32,
) {
    let mask = super::rxe_opcode::info(opcode).mask;
    wqe.replaying = false;
    wqe.state = if mask & RXE_END_MASK == 0 {
        WQE_STATE_PROCESSING
    } else if config.kind == IB_QPT_RC {
        WQE_STATE_PENDING
    } else {
        WQE_STATE_DONE
    };
    let packets = if matches!(config.kind, IB_QPT_RC | IB_QPT_UC)
        && mask & (RXE_READ_MASK | RXE_WRITE_OR_SEND_MASK) != 0
    {
        ((u64::from(wqe.dma.resid) + u64::from(payload)).div_ceil(u64::from(config.mtu.get())))
            .max(1) as u32
    } else {
        1
    };
    if mask & RXE_START_MASK != 0 {
        wqe.first_psn = progress.psn;
        wqe.last_psn = progress.psn.wrapping_add(packets - 1) & 0xffffff;
    }
    progress.psn = if mask & RXE_READ_MASK != 0 {
        wqe.first_psn.wrapping_add(packets) & 0xffffff
    } else {
        progress.psn.wrapping_add(1) & 0xffffff
    };
    progress.opcode = i32::from(opcode);
    if mask & RXE_END_MASK != 0 {
        advance(progress, config.queue_mask);
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_req_state)]
mod tests {
    use super::*;
    use crate::{
        rxe_ring::Storage,
        rxe_send::SendSnapshots,
        rxe_wire::{
            packet_len,
            Transport, //
        },
        rxe_wqe::SEND_HEADER_SIZE, //
    };

    #[test]
    fn read_credit_exhaustion_and_wakeup() {
        let credits = ReadCredits::zeroed();
        let mut requester = Requester::zeroed();
        assert!(!requester.take_read_credit(&credits));
        assert!(requester.need_rd_atomic);
        assert_eq!(credits.available(), 0);
        credits.set(2);
        assert!(requester.take_read_credit(&credits));
        assert!(requester.take_read_credit(&credits));
        assert!(!requester.need_rd_atomic);
        assert!(!requester.take_read_credit(&credits));
        assert_eq!(credits.available(), 0);
        assert!(requester.release_read_credit(&credits));
        assert!(requester.again);
        assert!(!requester.need_rd_atomic);
        requester.again = false;
        assert!(!requester.release_read_credit(&credits));
        assert!(!requester.again);
        assert_eq!(credits.available(), 2);
        requester.wait_fence = true;
        requester.wake_fence();
        assert!(requester.again);
        assert!(!requester.wait_fence);
        requester.again = false;
        requester.wait_psn = true;
        requester.wake_psn();
        assert!(requester.again);
        assert!(!requester.wait_psn);
    }

    #[test]
    fn replacing_credit_limit_preserves_outstanding_requests() {
        let credits = ReadCredits::zeroed();
        credits.set(3);
        assert!(credits.take());
        assert!(credits.take());
        credits.set(0);
        assert_eq!(credits.available(), 0);
        assert_eq!(credits.outstanding(), 2);
        credits.set(1);
        assert_eq!(credits.available(), 0);
        assert!(!credits.take());
        credits.release();
        assert!(!credits.take());
        credits.release();
        assert_eq!(credits.available(), 1);
        assert!(credits.take());
        credits.set(4);
        assert_eq!(credits.available(), 3);
        credits.release();
        assert_eq!(credits.available(), 4);
        assert_eq!(credits.outstanding(), 0);
    }

    #[test]
    fn flush_and_atomic_write_retries_keep_remote_address() -> Result {
        let config = config(IB_QPT_RC);
        for opcode in [IB_WR_FLUSH, IB_WR_ATOMIC_WRITE] {
            let (storage, mut snapshots) = queue(opcode, 8, 0x12345000)?;
            let mut work = snapshots.get(&storage, 0)?;
            work.state = WQE_STATE_PENDING;
            let mut progress = Requester::zeroed();
            assert_eq!(
                retry_work(&mut progress, &mut work, &config, 0, &mut true)?,
                Replay::Prepared
            );
            assert_eq!(work.iova, 0x12345000);
        }
        Ok(())
    }

    #[test]
    fn descriptor_free_retries_ignore_scatter_counts() -> Result {
        let mut config = config(IB_QPT_RC);
        config.max_sge = 0;
        for (opcode, length) in [(IB_WR_FLUSH, 4096), (IB_WR_ATOMIC_WRITE, 8)] {
            for count in [1, u32::MAX] {
                let (storage, mut snapshots) = queue(opcode, length, 0x12345000)?;
                let mut work = snapshots.get(&storage, 0)?;
                work.wr.send_flags = 0;
                work.mask = work_mask(config.kind, opcode);
                work.dma.num_sge = count;
                assert_eq!(validate_work(&work, &config), Ok(()));
                work.state = WQE_STATE_PENDING;
                work.dma.resid = 0;
                let mut progress = Requester::zeroed();
                assert_eq!(
                    retry_work(&mut progress, &mut work, &config, 0, &mut true)?,
                    Replay::Prepared
                );
                assert_eq!(work.iova, 0x12345000);
                assert_eq!(work.dma.resid, length);
                assert_eq!(work.state, WQE_STATE_POSTED);
                assert!(work.replaying);
            }
        }
        for opcode in [
            IB_WR_RDMA_WRITE,
            IB_WR_RDMA_READ,
            IB_WR_ATOMIC_FETCH_AND_ADD,
        ] {
            let (storage, mut snapshots) = queue(opcode, 8, 0x12345000)?;
            let mut work = snapshots.get(&storage, 0)?;
            work.wr.send_flags = 0;
            work.dma.num_sge = 1;
            work.state = WQE_STATE_PENDING;
            let mut progress = Requester::zeroed();
            assert_eq!(
                retry_work(&mut progress, &mut work, &config, 0, &mut true),
                Err(EINVAL)
            );
        }
        Ok(())
    }

    fn config(kind: u32) -> Config {
        Config {
            kind,
            mtu: NonZeroU32::new(256).unwrap(),
            max_sge: 1,
            max_inline: 512,
            queue_mask: 3,
            source: 7,
            destination: 9,
            source_port: 4791,
        }
    }

    fn queue(opcode: u32, length: u32, address: u64) -> Result<(Storage, KBox<SendSnapshots>)> {
        let size = SEND_HEADER_SIZE + 512;
        let storage = Storage::new(1, size as u32, 64)?;
        let mut bytes = [0; SEND_HEADER_SIZE + 512];
        bytes[12..16].copy_from_slice(&opcode.to_ne_bytes());
        bytes[16..20].copy_from_slice(&((IB_SEND_INLINE | IB_SEND_SOLICITED) as u32).to_ne_bytes());
        bytes[20..24].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        bytes[24..32].copy_from_slice(&address.to_ne_bytes());
        bytes[32..36].copy_from_slice(&0xaabbccddu32.to_ne_bytes());
        bytes[184..188].copy_from_slice(&length.to_ne_bytes());
        for (i, byte) in bytes[SEND_HEADER_SIZE..].iter_mut().enumerate() {
            *byte = i as u8;
        }
        storage.memory().write(storage.offset(0), &bytes)?;
        let snapshots = SendSnapshots::new(&storage, size)?;
        Ok((storage, snapshots))
    }

    #[test]
    fn maximum_read_reserves_half_the_psn_space_and_retries() -> Result {
        let config = config(IB_QPT_RC);
        let (storage, mut snapshots) = queue(IB_WR_RDMA_READ, 1 << 31, 0x1000)?;
        let mut work = snapshots.get(&storage, 0)?;
        work.wr.send_flags = 0;
        work.mask = work_mask(config.kind, work.wr.opcode);
        assert_eq!(validate_work(&work, &config), Ok(()));
        assert!(read_fits_window(&work, &config, 0xffffff, 0xffffff));
        assert!(!read_fits_window(&work, &config, 0, 0xffffff));
        work.dma.resid -= 256;
        assert!(read_fits_window(&work, &config, 0, 0xffffff));
        assert!(!read_fits_window(&work, &config, 1, 0xffffff));
        work.dma.length += 1;
        assert_eq!(validate_work(&work, &config), Err(EINVAL));
        work.dma.length -= 1;

        for first in [0u32, 0x800001, 0xffffff] {
            work.dma.resid = work.dma.length;
            let mut progress = Requester::zeroed();
            progress.psn = first;
            update(
                &mut progress,
                &mut work,
                &config,
                IB_OPCODE_RC_RDMA_READ_REQUEST as u8,
                0,
            );
            let next = first.wrapping_add(0x800000) & 0xffffff;
            assert_eq!(progress.psn, next);
            assert_eq!(work.first_psn, first);
            assert_eq!(work.last_psn, next.wrapping_sub(1) & 0xffffff);
            assert_eq!(work.state, WQE_STATE_PENDING);
            // The ordinary requester throttle prevents any further transmission.
            assert!(
                super::super::rxe_wire::psn_compare(
                    progress.psn,
                    first.wrapping_add(super::super::rxe_param::RXE_MAX_UNACKED_PSNS)
                ) > 0
            );
            for packets in [0, 1, 0x7fffff] {
                work.state = WQE_STATE_PENDING;
                work.dma.resid = work.dma.length - packets * config.mtu.get();
                assert_eq!(
                    retry_work(
                        &mut progress,
                        &mut work,
                        &config,
                        first.wrapping_add(packets) & 0xffffff,
                        &mut true
                    )?,
                    Replay::Prepared
                );
                assert_eq!(work.iova, 0x1000 + u64::from(packets * config.mtu.get()));
                assert!(work.replaying);
            }
        }
        Ok(())
    }

    #[test]
    fn shared_atomic_requests_require_one_aligned_word() -> Result {
        let config = config(IB_QPT_RC);
        for opcode in [IB_WR_ATOMIC_CMP_AND_SWP, IB_WR_ATOMIC_FETCH_AND_ADD] {
            let (storage, mut snapshots) = queue(opcode, 16, 0x1000)?;
            let mut work = snapshots.get(&storage, 0)?;
            work.wr.send_flags = 0;
            work.mask = work_mask(config.kind, opcode);
            assert_eq!(validate_work(&work, &config), Err(EINVAL));
            work.dma.length = 8;
            work.dma.resid = 8;
            assert_eq!(validate_work(&work, &config), Ok(()));
            work.iova += 1;
            assert_eq!(validate_work(&work, &config), Err(EINVAL));
            work.iova -= 1;
            work.dma.length = 0;
            assert_eq!(validate_work(&work, &config), Err(EINVAL));
        }
        Ok(())
    }

    #[test]
    fn descriptor_free_requests_allow_zero_scatter_capacity() -> Result {
        let mut config = config(IB_QPT_RC);
        config.max_sge = 0;
        config.max_inline = 8;
        for (opcode, length) in [(IB_WR_FLUSH, 4096), (IB_WR_ATOMIC_WRITE, 8)] {
            let (storage, mut snapshots) = queue(opcode, length, 0x1000)?;
            let mut work = snapshots.get(&storage, 0)?;
            work.wr.send_flags = 0;
            work.mask = work_mask(config.kind, opcode);
            assert_eq!(work.dma.num_sge, 0);
            assert_eq!(work.dma.resid, length);
            assert_eq!(validate_work(&work, &config), Ok(()));
        }
        for opcode in [
            IB_WR_RDMA_WRITE,
            IB_WR_RDMA_READ,
            IB_WR_ATOMIC_FETCH_AND_ADD,
        ] {
            let (storage, mut snapshots) = queue(opcode, 8, 0x1000)?;
            let mut work = snapshots.get(&storage, 0)?;
            work.wr.send_flags = 0;
            work.mask = work_mask(config.kind, opcode);
            assert_eq!(validate_work(&work, &config), Err(EINVAL));
        }
        Ok(())
    }

    #[test]
    fn oversized_inline_requests_fail_before_the_first_segment() -> Result {
        let mut config = config(IB_QPT_RC);
        config.max_inline = 256;
        let (storage, mut snapshots) = queue(IB_WR_RDMA_WRITE, 507, 0x1000)?;
        let mut work = snapshots.get(&storage, 0)?;
        work.mask = work_mask(config.kind, work.wr.opcode);
        assert_eq!(validate_work(&work, &config), Err(EINVAL));
        // A short remaining fragment cannot make an oversized request admissible.
        work.dma.resid = 251;
        assert_eq!(validate_work(&work, &config), Err(EINVAL));
        work.dma.length = 256;
        work.dma.resid = 256;
        assert_eq!(validate_work(&work, &config), Ok(()));
        work.wr.opcode = IB_WR_RDMA_READ;
        work.mask = work_mask(config.kind, work.wr.opcode);
        assert_eq!(validate_work(&work, &config), Err(EINVAL));
        Ok(())
    }

    #[test]
    fn segmented_inline_write_preserves_headers_payload_and_psn_wrap() -> Result {
        for kind in [IB_QPT_RC, IB_QPT_UC] {
            let config = config(kind);
            let (storage, mut snapshots) = queue(IB_WR_RDMA_WRITE_WITH_IMM, 507, 0x1003)?;
            let mut work = snapshots.get(&storage, 0)?;
            let mut progress = Requester::zeroed();
            progress.opcode = -1;
            progress.psn = 0xffffff;
            progress.wqe_index = 3;
            let transport = if kind == IB_QPT_UC { 0x20 } else { 0 };
            let mut offset = 0;
            for (index, (opcode, length)) in [(6, 256), (9, 251)].into_iter().enumerate() {
                let opcode = opcode + transport;
                assert_eq!(next_opcode(&progress, &work, &config)?, opcode);
                let mut bytes = KVec::from_elem(0, packet_len(opcode, length)?, GFP_KERNEL)?;
                {
                    let mut wire = TransportMut::initialize(
                        &mut bytes,
                        base(&mut progress, &work, &config, opcode),
                        length,
                    )?;
                    encode(&mut wire, &work, &config)?;
                    fill(&mut wire, &mut work, config.max_inline, |_| {
                        panic!("inline MR lookup")
                    })?;
                }
                let wire = Transport::parse(&bytes[..bytes.len() - 4])?;
                assert_eq!(wire.psn(), (0xffffff + index as u32) & 0xffffff);
                assert_eq!(wire.qpn(), 9);
                assert_eq!(wire.solicited(), index == 1);
                assert_eq!(wire.ack_requested(), kind == IB_QPT_RC && index == 1);
                if index == 0 {
                    let remote = wire.remote()?;
                    assert_eq!(remote.address, 0x1003);
                    assert_eq!(remote.key, 0xaabbccdd);
                    assert_eq!(remote.length, 507);
                }
                if index == 1 {
                    assert_eq!(wire.immediate()?, [0x12, 0x34, 0x56, 0x78]);
                    assert_eq!(wire.pad(), 1);
                }
                for (i, byte) in wire.payload()?.iter().enumerate() {
                    assert_eq!(*byte, (offset + i) as u8);
                }
                offset += length;
                update(&mut progress, &mut work, &config, opcode, length as u32);
                assert_eq!(work.first_psn, 0xffffff);
                assert_eq!(work.last_psn, 0);
            }
            assert_eq!(progress.psn, 1);
            assert_eq!(progress.wqe_index, 0);
            assert_eq!(work.dma.resid, 0);
            assert_eq!(
                work.state,
                if kind == IB_QPT_RC {
                    WQE_STATE_PENDING
                } else {
                    WQE_STATE_DONE
                }
            );
        }
        Ok(())
    }

    #[test]
    fn retries_restore_partial_send_and_reject_out_of_range_progress() -> Result {
        let config = config(IB_QPT_RC);
        let (storage, mut snapshots) = queue(IB_WR_SEND, 507, 0)?;
        let mut work = snapshots.get(&storage, 0)?;
        let mut progress = Requester::zeroed();
        progress.opcode = -1;
        work.state = WQE_STATE_PENDING;
        work.first_psn = 0xffffff;
        let mut first = true;
        assert_eq!(
            retry_work(&mut progress, &mut work, &config, 0, &mut first)?,
            Replay::Prepared
        );
        assert!(!first);
        assert_eq!(work.dma.resid, 251);
        assert_eq!(work.dma.sge_offset, 256);
        assert_eq!(next_opcode(&progress, &work, &config)?, 2);
        assert_eq!(work.state, WQE_STATE_POSTED);
        assert!(work.replaying);
        assert_eq!(
            super::super::rxe_comp_state::select_work(Some(&work), true),
            super::super::rxe_comp_state::State::Done
        );
        work.replaying = false;
        assert_eq!(
            retry_work(&mut progress, &mut work, &config, 0, &mut first)?,
            Replay::Stop
        );
        work.state = WQE_STATE_DONE;
        assert_eq!(
            retry_work(&mut progress, &mut work, &config, 0, &mut first)?,
            Replay::Skip
        );
        work.state = WQE_STATE_PENDING;
        first = true;
        assert_eq!(
            retry_work(&mut progress, &mut work, &config, 1, &mut first),
            Err(EINVAL)
        );
        work.wr.opcode = u32::MAX;
        assert_eq!(
            retry_work(&mut progress, &mut work, &config, 0, &mut first),
            Err(EINVAL)
        );
        assert_eq!(work_mask(u32::MAX, IB_WR_SEND), 0);
        Ok(())
    }

    #[test]
    fn single_packet_operations_reserve_one_psn() -> Result {
        for (kind, opcode, wire_opcode) in [
            (IB_QPT_UD, IB_WR_SEND, IB_OPCODE_UD_SEND_ONLY),
            (IB_QPT_GSI, IB_WR_SEND, IB_OPCODE_UD_SEND_ONLY),
            (
                IB_QPT_RC,
                IB_WR_ATOMIC_FETCH_AND_ADD,
                IB_OPCODE_RC_FETCH_ADD,
            ),
        ] {
            let config = config(kind);
            let (storage, mut snapshots) = queue(opcode, 512, 0)?;
            let mut work = snapshots.get(&storage, 0)?;
            let mut progress = Requester::zeroed();
            progress.psn = 0xffffff;
            update(&mut progress, &mut work, &config, wire_opcode as u8, 0);
            assert_eq!(work.first_psn, 0xffffff);
            assert_eq!(work.last_psn, 0xffffff);
            assert_eq!(progress.psn, 0);
        }
        Ok(())
    }

    #[test]
    fn read_retry_preserves_destination_cursor_and_checks_remote_address() -> Result {
        let config = config(IB_QPT_RC);
        for (address, valid) in [(0x1003, true), (u64::MAX - 255, false)] {
            let (storage, mut snapshots) = queue(IB_WR_RDMA_READ, 601, address)?;
            let mut work = snapshots.get(&storage, 0)?;
            let mut progress = Requester::zeroed();
            progress.opcode = -1;
            work.state = WQE_STATE_PENDING;
            work.last_psn = 2;
            work.dma.resid = 345;
            work.dma.sge_offset = 256;
            let cursor = work.dma;
            let result = retry_work(&mut progress, &mut work, &config, 1, &mut true);
            assert_eq!(work.dma, cursor);
            if valid {
                assert_eq!(result?, Replay::Prepared);
                assert_eq!(work.iova, 0x1103);
                progress.psn = 0xffffff;
                update(&mut progress, &mut work, &config, 0x0c, 0);
                assert_eq!(work.first_psn, 0xffffff);
                assert_eq!(work.last_psn, 0);
                assert_eq!(progress.psn, 1);
            } else {
                assert_eq!(result, Err(EINVAL));
            }
        }
        Ok(())
    }

    #[test]
    fn datagrams_preserve_management_key_and_reject_oversized_inline_data() -> Result {
        for source in [1, 7] {
            let mut config = config(IB_QPT_UD);
            config.source = source;
            let (storage, mut snapshots) = queue(IB_WR_SEND_WITH_IMM, 8, 0)?;
            storage
                .memory()
                .write(storage.offset(0) + 24, &0x556677u32.to_ne_bytes())?;
            storage
                .memory()
                .write(storage.offset(0) + 28, &0x11223344u32.to_ne_bytes())?;
            let mut work = snapshots.get(&storage, 0)?;
            let mut progress = Requester::zeroed();
            let opcode = next_opcode(&progress, &work, &config)?;
            let mut bytes = KVec::from_elem(0, packet_len(opcode, 8)?, GFP_KERNEL)?;
            let mut wire = TransportMut::initialize(
                &mut bytes,
                base(&mut progress, &work, &config, opcode),
                8,
            )?;
            encode(&mut wire, &work, &config)?;
            let cursor = work.dma;
            assert_eq!(fill(&mut wire, &mut work, 7, |_| None), Err(EINVAL));
            assert_eq!(work.dma, cursor);
            fill(&mut wire, &mut work, 8, |_| None)?;
            let wire = Transport::parse(&bytes[..bytes.len() - 4])?;
            assert_eq!(wire.qpn(), 0x556677);
            assert!(!wire.ack_requested());
            assert!(wire.solicited());
            assert_eq!(wire.immediate()?, [0x12, 0x34, 0x56, 0x78]);
            assert_eq!(wire.datagram()?.source, source);
            assert_eq!(
                wire.datagram()?.key,
                if source == 1 { GSI_QKEY } else { 0x11223344 }
            );
        }
        Ok(())
    }
    #[test]
    fn maximum_legal_retry_seeks_once_and_preserves_done_work() -> Result {
        let config = config(IB_QPT_RC);
        let length = super::super::rxe_param::RXE_PORT_MAX_MSG_SZ;
        let (storage, mut snapshots) = queue(IB_WR_SEND, length, 0)?;
        storage
            .memory()
            .write(storage.offset(0) + 16, &0u32.to_ne_bytes())?;
        storage
            .memory()
            .write(storage.offset(0) + 196, &1u32.to_ne_bytes())?;
        storage.memory().write(
            storage.offset(0) + SEND_HEADER_SIZE + 8,
            &length.to_ne_bytes(),
        )?;
        let mut work = snapshots.get(&storage, 0)?;
        work.state = WQE_STATE_PENDING;
        let mut progress = Requester::zeroed();
        progress.opcode = -1;
        assert_eq!(
            retry_work(&mut progress, &mut work, &config, 0x7fffff, &mut true)?,
            Replay::Prepared
        );
        assert_eq!(work.dma.resid, 256);
        assert_eq!(work.dma.sge_offset, length - 256);
        assert_eq!(next_opcode(&progress, &work, &config)?, 2);
        work.wr.opcode = IB_WR_REG_MR;
        work.state = WQE_STATE_DONE;
        let cursor = work.dma;
        assert_eq!(
            retry_work(&mut progress, &mut work, &config, 0, &mut true)?,
            Replay::Skip
        );
        assert_eq!(work.state, WQE_STATE_DONE);
        assert_eq!(work.dma, cursor);
        assert_eq!(work_mask(IB_QPT_RC, IB_WR_RDMA_READ_WITH_INV), 0);
        Ok(())
    }

    #[test]
    fn read_retry_rejects_inconsistent_progress_after_partial_replay() -> Result {
        let config = config(IB_QPT_RC);
        for (first, last, completed, residual, valid) in [
            (0, 2, 1, 345, true),
            (1, 2, 1, 345, true),
            (1, 2, 0, 345, false),
            (0, 2, 3, 0, false),
            (0, 2, 1, 473, false),
            (0, 2, 1, 89, false),
        ] {
            let (storage, mut snapshots) = queue(IB_WR_RDMA_READ, 601, 0x1000)?;
            let mut work = snapshots.get(&storage, 0)?;
            work.state = WQE_STATE_PENDING;
            work.first_psn = first;
            work.last_psn = last;
            work.dma.resid = residual;
            let mut progress = Requester::zeroed();
            assert_eq!(
                retry_work(&mut progress, &mut work, &config, completed, &mut true).is_ok(),
                valid
            );
        }
        Ok(())
    }
}
