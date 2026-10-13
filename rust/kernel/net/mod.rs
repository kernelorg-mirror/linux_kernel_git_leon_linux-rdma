// SPDX-License-Identifier: GPL-2.0

//! Networking.

#[cfg(CONFIG_RUST_PHYLIB_ABSTRACTIONS)]
pub mod phy;

pub mod netlink;
pub mod skbuff;

pub mod namespace;
