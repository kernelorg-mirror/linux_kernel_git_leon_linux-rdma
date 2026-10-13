// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Native mutable port attributes, borrowed through the port's typed lock.

#![forbid(unsafe_code)]

use super::{
    rxe_param as params,
    rxe_recv_check::Rejection, //
};
use core::num::NonZero;
use kernel::{
    prelude::*,
    rdma::{
        Device,
        LinkLayer,
        Mtu,
        PhysicalState,
        PortAttributes,
        PortCapability,
        PortImmutable,
        PortModification,
        PortModify,
        PortState, //
    }, //
    sync::SpinLockIrq,
};

/// Port identity and mutable attributes owned until final core deallocation.
#[pin_data]
pub(crate) struct Port {
    raw_gid: [u8; 6],
    #[pin]
    state: SpinLockIrq<State>,
}

impl Port {
    pub(crate) fn new(raw_gid: [u8; 6], mtu: Mtu) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            raw_gid,
            state <- kernel::new_spinlock_irq!(State::new(mtu, params::RXE_PORT_PORT_CAP_FLAGS)),
        })
    }

    pub(crate) fn mtu(&self) -> Mtu {
        self.state.lock().mtu()
    }

    pub(crate) fn set_mtu(&self, mtu: Mtu) {
        self.state.lock().set_mtu(mtu);
    }

    pub(crate) fn reject(&self, rejection: Rejection) {
        self.state.lock().reject(rejection);
    }

    /// Reserves the management QP number until the owning QP starts destruction.
    pub(crate) fn claim_gsi(&self, index: NonZero<u32>) -> Result<NonZero<u32>> {
        let mut state = self.state.lock();
        if state.gsi.is_some() {
            return Err(EINVAL);
        }
        state.gsi = Some(index);
        Ok(index)
    }

    /// Releases only the matching reservation, before its pool index can be reused.
    pub(crate) fn release_gsi(&self, index: NonZero<u32>) {
        let mut state = self.state.lock();
        if state.gsi == Some(index) {
            state.gsi = None;
        }
    }

    /// Acquires the management QP while its reservation remains locked.
    ///
    /// The lookup runs with interrupts disabled and must retain the QP before returning.
    pub(crate) fn lookup_gsi<T>(&self, lookup: impl FnOnce(NonZero<u32>) -> T) -> Option<T> {
        let state = self.state.lock();
        state.gsi.map(lookup)
    }

    pub(crate) fn query_gid(&self, _port: u32, _index: i32) -> Result<[u8; 16]> {
        let mut gid = [0; 16];
        gid[..6].copy_from_slice(&self.raw_gid);
        Ok(gid)
    }

    pub(crate) fn query_pkey(&self, _port: u32, index: u16) -> Result<u16> {
        if index != 0 {
            return Err(EINVAL);
        }
        Ok(0xffff)
    }

    pub(crate) fn link_layer(&self, port: u32) -> LinkLayer {
        if port == 1 {
            LinkLayer::Ethernet
        } else {
            LinkLayer::Unspecified
        }
    }

    pub(crate) fn query_port<T>(&self, device: &Device<T>, port: u32) -> Result<PortAttributes> {
        if port != 1 {
            return Err(EINVAL);
        }
        let state = *self.state.lock();
        // Drop the attribute lock before the sleeping Ethernet link query.
        let link = device.ethernet_link(port)?;
        Ok(PortAttributes {
            state: if link.active {
                PortState::Active
            } else {
                PortState::Down
            },
            max_mtu: Mtu::Mtu4096,
            active_mtu: state.mtu(),
            gid_tbl_len: params::RXE_PORT_GID_TBL_LEN as i32,
            port_cap_flags: state.capabilities(),
            max_msg_sz: params::RXE_PORT_MAX_MSG_SZ,
            bad_pkey_cntr: state.bad_partition(),
            qkey_viol_cntr: state.bad_datagram(),
            pkey_tbl_len: params::RXE_PORT_PKEY_TBL_LEN as u16,
            lid: params::RXE_PORT_LID,
            sm_lid: params::RXE_PORT_SM_LID,
            lmc: params::RXE_PORT_LMC as u8,
            max_vl_num: params::RXE_PORT_MAX_VL_NUM as u8,
            sm_sl: params::RXE_PORT_SM_SL as u8,
            subnet_timeout: params::RXE_PORT_SUBNET_TIMEOUT as u8,
            init_type_reply: params::RXE_PORT_INIT_TYPE_REPLY as u8,
            active_width: link.width,
            active_speed: link.speed,
            phys_state: if link.active {
                PhysicalState::LinkUp
            } else if link.enabled {
                PhysicalState::Polling
            } else {
                PhysicalState::Disabled
            },
            ..Default::default()
        })
    }

    pub(crate) fn modify_port(&self, port: u32, change: PortModification) -> Result {
        if port != 1 {
            return Err(EINVAL);
        }
        if u32::from(change.flags) & !(PortModify::ResetQkey as u32) != 0 {
            return Err(EOPNOTSUPP);
        }
        self.state.lock().modify(
            change.set_capabilities,
            change.clear_capabilities,
            change.flags.contains(PortModify::ResetQkey),
        );
        Ok(())
    }

    pub(crate) fn port_immutable<T>(&self, device: &Device<T>, port: u32) -> Result<PortImmutable> {
        let attr = self.query_port(device, port)?;
        Ok(PortImmutable {
            pkey_tbl_len: attr.pkey_tbl_len.into(),
            gid_tbl_len: attr.gid_tbl_len,
            capabilities: PortCapability::RoceUdp
                | PortCapability::IbMad
                | PortCapability::IbCm
                | PortCapability::IbAddress
                | PortCapability::EthernetAh,
            max_mad_size: 256,
        })
    }
}

/// A coherent copy of mutable port attributes; link state is sampled separately.
#[derive(Clone, Copy)]
pub(crate) struct State {
    mtu: Mtu,
    capabilities: u32,
    bad_partition: u32,
    bad_datagram: u32,
    gsi: Option<NonZero<u32>>,
}

impl State {
    pub(crate) fn new(mtu: Mtu, capabilities: u32) -> Self {
        Self {
            mtu,
            capabilities,
            bad_partition: 0,
            bad_datagram: 0,
            gsi: None,
        }
    }

    pub(crate) fn mtu(&self) -> Mtu {
        self.mtu
    }

    pub(crate) fn capabilities(&self) -> u32 {
        self.capabilities
    }

    pub(crate) fn bad_partition(&self) -> u32 {
        self.bad_partition
    }

    pub(crate) fn bad_datagram(&self) -> u32 {
        self.bad_datagram
    }

    pub(crate) fn set_mtu(&mut self, mtu: Mtu) {
        self.mtu = mtu;
    }

    pub(crate) fn modify(&mut self, set: u32, clear: u32, reset_datagram: bool) {
        self.capabilities = (self.capabilities | set) & !clear;
        if reset_datagram {
            self.bad_datagram = 0;
        }
    }

    pub(crate) fn reject(&mut self, rejection: Rejection) {
        let count = match rejection {
            Rejection::PartitionKey => &mut self.bad_partition,
            Rejection::DatagramKey => &mut self.bad_datagram,
            Rejection::Invalid => return,
        };
        *count = count.saturating_add(1).min(0xffff);
    }
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_port)]
mod tests {
    use super::*;

    #[test]
    fn management_reservation_rejects_duplicates_and_allows_reuse() {
        let port = KBox::pin_init(Port::new([0; 6], Mtu::Mtu1024), GFP_KERNEL).unwrap();
        let first = NonZero::new(16).unwrap();
        let second = NonZero::new(17).unwrap();
        assert_eq!(port.claim_gsi(first), Ok(first));
        assert_eq!(port.claim_gsi(second), Err(EINVAL));
        port.release_gsi(second);
        assert_eq!(port.lookup_gsi(|index| index), Some(first));
        port.release_gsi(first);
        assert_eq!(port.lookup_gsi(|index| index), None);
        assert_eq!(port.claim_gsi(second), Ok(second));
        port.release_gsi(first);
        assert_eq!(port.lookup_gsi(|index| index), Some(second));
        port.release_gsi(second);
    }

    #[test]
    fn modification_and_counter_saturation() {
        let mut state = State::new(Mtu::Mtu1024, 0b11);
        state.bad_partition = 0xfffe;
        state.bad_datagram = 0xfffe;
        for _ in 0..3 {
            state.reject(Rejection::PartitionKey);
            state.reject(Rejection::DatagramKey);
        }
        assert_eq!(state.bad_partition(), 0xffff);
        assert_eq!(state.bad_datagram(), 0xffff);
        state.modify(0b110, 0b10, true);
        assert_eq!(state.capabilities(), 0b101);
        assert_eq!(state.bad_partition(), 0xffff);
        assert_eq!(state.bad_datagram(), 0);
        state.set_mtu(Mtu::Mtu2048);
        assert_eq!(state.mtu().bytes(), 2048);
    }
}
