// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Owned RDMA device creation and registration dependencies.

#![forbid(unsafe_code)]

use crate::{
    rxe_device::{
        DeviceData,
        Parameters, //
    },
    rxe_ns::{
        self,
        Tunnels, //
    },
    rxe_param as params, //
};
use kernel::{
    bindings,
    net::notifier,
    prelude::*,
    rdma::{
        link,
        software,
        Device as RdmaDevice, //
    },
    sync::{
        atomic::{
            Acquire,
            AtomicFlag,
            Release, //
        },
        Mutex,
        MutexGuard, //
    }, //
};

static REGISTERED: AtomicFlag = AtomicFlag::new(false);

/// Owns the driver's registrations and enforces their dependency order.
///
/// # Invariants
///
/// This is the only registration instance. Link callbacks can run only while
/// the notifier and namespace storage are live. Shutdown drains devices before
/// dropping dependencies and releasing the singleton claim.
pub(crate) struct Registration {
    _links: Pin<KBox<link::Registration<Links>>>,
}

/// Keeps dependency drop order intact even if allocation fails before pin initialization.
struct Dependencies {
    _notifier: Pin<KBox<notifier::Registration<crate::rxe_net_control::Events>>>,
    _namespace: Pin<KBox<rxe_ns::Registration>>,
    _instance: Instance,
}

struct Instance;

#[pin_data]
struct Links {
    #[pin]
    creation: Mutex<()>,
    tunnels: rxe_ns::Key,
    _dependencies: Dependencies,
}

impl Registration {
    pub(crate) fn new() -> Result<Self> {
        REGISTERED
            .cmpxchg(false, true, Acquire)
            .map_err(|_| EBUSY)?;
        let instance = Instance;
        let namespace = KBox::pin_init(rxe_ns::Registration::new(), GFP_KERNEL)?;
        let tunnels = namespace.key();
        let notifier = KBox::pin_init(
            notifier::Registration::new(Ok(crate::rxe_net_control::Events), 0),
            GFP_KERNEL,
        )?;
        let dependencies = Dependencies {
            _notifier: notifier,
            _namespace: namespace,
            _instance: instance,
        };
        let links = KBox::pin_init(
            link::Registration::new_managed(
                c"rxe",
                bindings::rdma_driver_id_RDMA_DRIVER_RXE,
                try_pin_init!(Links {
                    creation <- kernel::new_mutex!(()),
                    tunnels,
                    _dependencies: dependencies,
                }),
            ),
            GFP_KERNEL,
        )?;
        // INVARIANT: The registered handler owns every dependency. Both failed
        // construction and successful shutdown release the claim last.
        Ok(Self { _links: links })
    }
}

impl link::Operations for Links {
    type Device = super::rxe_device::DeviceData;

    fn new_link(self: Pin<&Self>, link: link::NewLink<'_, Self>) -> Result {
        let creation = self.creation.lock();
        let info = link.net_device().link_info();
        let mut address = [0u8; 6];
        if info.address().is_empty() {
            kernel::random::get_bytes(&mut address);
            address[0] = (address[0] & 0xfe) | 0x02;
        } else {
            let length = info.address().len().min(address.len());
            address[..length].copy_from_slice(&info.address()[..length]);
        }
        // INVARIANT: The core request retains its inputs and handler. The
        // creation guard stays owned throughout policy and registration,
        // and link configuration was copied under RTNL.
        let request = LinkRequest {
            link,
            address,
            mtu: info.mtu,
            vlan: info.is_vlan,
            tunnels: self.tunnels,
            _creation: creation,
        };
        crate::rxe_device::newlink(request)
    }

    fn delete_link(self: Pin<&Self>, device: &RdmaDevice<Self::Device>) -> Result {
        device.provider().close_tunnels();
        Ok(())
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        REGISTERED.store(false, Release);
    }
}

/// A borrowed, serialized link-creation request from the RDMA core.
///
/// # Invariants
///
/// `link` keeps the callback inputs and registration dependencies live.
/// `_creation` excludes other creators, and the address and MTU were copied
/// under RTNL. No ordinary reference covers the mutable C net_device.
pub(crate) struct LinkRequest<'a> {
    link: link::NewLink<'a, Links>,
    address: [u8; 6],
    mtu: u32,
    vlan: bool,
    tunnels: rxe_ns::Key,
    _creation: MutexGuard<'a, ()>,
}

impl LinkRequest<'_> {
    pub(crate) fn address(&self) -> [u8; 6] {
        self.address
    }

    pub(crate) fn mtu(&self) -> u32 {
        self.mtu
    }

    pub(crate) fn is_vlan(&self) -> bool {
        self.vlan
    }

    pub(crate) fn is_configured(&self) -> bool {
        super::rxe_net_control::get_device(self.link.net_device()).is_some()
    }

    pub(crate) fn register(self, parameters: Parameters) -> Result {
        let location = self.link.net_device().location()?;
        let tunnels = Tunnels::new(self.tunnels, location.namespace())?;
        let mac = parameters.raw_gid;
        let config = software::Configuration {
            node_description: c"rxe",
            node_guid: [
                mac[0] ^ 2,
                mac[1],
                mac[2],
                0xff,
                0xfe,
                mac[3],
                mac[4],
                mac[5],
            ],
            user_abi_version: params::RXE_UVERBS_ABI_VERSION,
            user_commands: software::UserCommand::PostSend | software::UserCommand::RequestNotify,
        };
        let device = software::UnregisteredDevice::new(
            location.namespace(),
            config,
            DeviceData::new(parameters, tunnels),
        )?
        .with_memory_windows()
        .with_multicast();
        #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
        let device = device.with_memory_advice();
        device.register(&self.link, location.namespace())
    }
}
