// SPDX-License-Identifier: GPL-2.0

//! RDMA port association with network devices and Ethernet link queries.

use super::Device;
use crate::{
    bindings,
    error::{
        code::ENODEV,
        to_result,
        Result, //
    },
    net::DeviceRef, //
};

/// Independently sampled Ethernet link properties in RDMA encodings.
///
/// The values do not prevent subsequent link changes. Network-device association, speed,
/// carrier and administrative state need not have been sampled at the same instant.
pub struct EthernetLink {
    /// Whether the associated network device is running and has carrier.
    pub active: bool,
    /// Whether the network device is administratively enabled.
    pub enabled: bool,
    /// Link speed in the RDMA core's `ib_port_speed` encoding.
    pub speed: u16,
    /// Link width in the RDMA core's `ib_port_width` encoding.
    pub width: u8,
}

impl<T> Device<T> {
    /// Acquires a reference to the network device associated with a port.
    ///
    /// Returns `None` for an invalid port or one without an associated network device.
    /// The reference protects allocation lifetime, not registration or association state.
    /// Call from process context: the core lookup takes a lock without disabling softirqs.
    #[inline]
    pub fn net_device(&self, port: u32) -> Option<DeviceRef> {
        // SAFETY: The device borrow keeps its initialized core resources live. The core checks
        // the port and serializes lookup, returning an owned reference when one is present.
        let device = unsafe { bindings::ib_device_get_netdev(self.as_raw(), port) };
        if device.is_null() {
            None
        } else {
            // SAFETY: The successful core lookup transfers one initialized netdev reference.
            Some(unsafe { DeviceRef::from_raw(device) })
        }
    }

    /// Samples whether an Ethernet port's network device is running and has carrier.
    ///
    /// Call from process context, like [`Self::net_device`]. This does not sleep or take RTNL.
    /// The state can change immediately after the sample.
    /// Returns `None` for an invalid port or one without an associated network device.
    #[inline]
    pub fn ethernet_active(&self, port: u32) -> Option<bool> {
        let device = self.net_device(port)?;
        // SAFETY: The owned reference retains the network device. The helper samples its
        // state through networking's bit accessors without exposing ordinary field references.
        Some(unsafe {
            bindings::ib_get_curr_port_state(device.as_raw())
                == bindings::ib_port_state_IB_PORT_ACTIVE
        })
    }

    /// Queries Ethernet speed and link state for a port.
    ///
    /// This method may sleep and must be called without RTNL or the netdev's instance or
    /// operations lock held. The RDMA core acquires these locks while querying Ethernet
    /// settings. Missing associations and unregistered devices return errors. A failed
    /// settings query or unknown speed instead uses the core's nominal 1 Gb/s fallback,
    /// converted to RDMA speed and width encodings.
    pub fn ethernet_link(&self, port: u32) -> Result<EthernetLink> {
        let device = self.net_device(port).ok_or(ENODEV)?;
        let mut speed = 0;
        let mut width = 0;
        // SAFETY: The device borrow retains core resources and the scalar output pointers are
        // exclusively writable. The core serializes the Ethernet query under RTNL.
        to_result(unsafe {
            bindings::ib_get_eth_speed(self.as_raw(), port, &mut speed, &mut width)
        })?;
        // SAFETY: The owned netdev reference spans both observations. The helpers sample
        // networking state without lending references to concurrently modified fields.
        let (active, enabled) = unsafe {
            (
                bindings::ib_get_curr_port_state(device.as_raw())
                    == bindings::ib_port_state_IB_PORT_ACTIVE,
                bindings::netif_get_flags(device.as_raw()) & bindings::net_device_flags_IFF_UP != 0,
            )
        };
        Ok(EthernetLink {
            active,
            enabled,
            speed,
            width,
        })
    }
}
