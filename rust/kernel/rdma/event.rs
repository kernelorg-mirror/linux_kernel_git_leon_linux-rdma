// SPDX-License-Identifier: GPL-2.0

//! Asynchronous RDMA port event publication.

use super::Device;
use crate::{
    bindings,
    prelude::*, //
};

/// A change in port availability reported by a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PortEvent {
    /// The port is active and available for communication.
    Active = bindings::ib_event_type_IB_EVENT_PORT_ACTIVE,
    /// The port has become unavailable.
    Error = bindings::ib_event_type_IB_EVENT_PORT_ERR,
}

impl<T> Device<T> {
    /// Queues a port event for cache synchronization and client notification.
    ///
    /// This does not sleep. Returns `ENODEV` once registration references have drained and
    /// `EINVAL` for an invalid port. As with the C interface, allocation failure can drop an
    /// event without reporting an error. Success does not imply that clients received the event.
    #[inline]
    pub fn dispatch_port_event(&self, port: u32, event: PortEvent) -> Result {
        let device = self.as_raw();
        let _registration = self.try_to_ref().ok_or(ENODEV)?;
        // SAFETY: Device port numbering is initialized and stable while registered.
        if unsafe { bindings::rdma_is_port_valid(device, port) } == 0 {
            return Err(EINVAL);
        }
        let mut notification = bindings::ib_event {
            device,
            event: event as bindings::ib_event_type,
            ..Default::default()
        };
        notification.element.port_num = port;
        // SAFETY: The validated port and initialized cache remain live through publication.
        // The core copies this stack event. Its cache cleanup drains queued work before
        // releasing the device and provider data, even after our registration reference ends.
        unsafe { bindings::ib_dispatch_event(&notification) };
        Ok(())
    }
}
