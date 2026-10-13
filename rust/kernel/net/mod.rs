// SPDX-License-Identifier: GPL-2.0

//! Networking.

mod device;
pub use device::{
    Device,
    DeviceLocation,
    DeviceName,
    DeviceRef,
    LinkInfo,
    RtnlGuard, //
};

#[cfg(CONFIG_RUST_PHYLIB_ABSTRACTIONS)]
pub mod phy;

pub mod netlink;

pub mod notifier;

pub mod skbuff;

pub mod namespace;
pub mod socket;

#[cfg(CONFIG_NET_UDP_TUNNEL)]
pub mod udp_tunnel;
