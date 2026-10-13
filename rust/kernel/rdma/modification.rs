// SPDX-License-Identifier: GPL-2.0

//! Selected device attributes at the provider modification boundary.

use crate::{
    bindings,
    prelude::*, //
};

const _: () = assert!(bindings::IB_DEVICE_NODE_DESC_MAX == 64);

/// Device attributes selected by a core modification request.
#[derive(Clone, Copy, Debug)]
pub struct DeviceModification {
    /// System-image GUID in host byte order, when selected.
    pub system_image_guid: Option<u64>,
    /// Fixed-width node description, which need not contain a terminating NUL.
    pub node_description: Option<[u8; 64]>,
}

impl DeviceModification {
    /// Copies only attributes selected by a supported modification mask.
    ///
    /// # Safety
    ///
    /// Every selected field in `attributes` must be initialized, readable and stable for the
    /// call. Unselected fields need not be initialized; an empty or unsupported mask reads none.
    pub(super) unsafe fn from_raw(
        mask: c_int,
        attributes: *const bindings::ib_device_modify,
    ) -> Result<Self> {
        let guid = bindings::ib_device_modify_flags_IB_DEVICE_MODIFY_SYS_IMAGE_GUID as c_int;
        let description = bindings::ib_device_modify_flags_IB_DEVICE_MODIFY_NODE_DESC as c_int;
        if mask & !(guid | description) != 0 {
            return Err(EOPNOTSUPP);
        }
        // SAFETY: Each field is read only inside its selected, caller-initialized branch.
        unsafe {
            Ok(Self {
                system_image_guid: (mask & guid != 0).then(|| (*attributes).sys_image_guid),
                node_description: (mask & description != 0).then(|| (*attributes).node_desc),
            })
        }
    }
}

#[cfg(CONFIG_RUST_KUNIT_TESTS)]
#[crate::macros::kunit_tests(rust_rdma_device_modification)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    #[test]
    fn guid_request_does_not_read_description() -> Result {
        let mut storage = MaybeUninit::<bindings::ib_device_modify>::uninit();
        let attributes = storage.as_mut_ptr();
        let guid = 0x1234_5678_9abc_def0;
        // SAFETY: This initializes exactly the GUID field selected below.
        unsafe { (&raw mut (*attributes).sys_image_guid).write(guid) };
        // SAFETY: The selected GUID is initialized and retained; the description is unselected.
        let change = unsafe {
            DeviceModification::from_raw(
                bindings::ib_device_modify_flags_IB_DEVICE_MODIFY_SYS_IMAGE_GUID as c_int,
                attributes,
            )
        }?;
        assert_eq!(change.system_image_guid, Some(guid));
        assert_eq!(change.node_description, None);
        Ok(())
    }

    #[test]
    fn description_request_does_not_read_guid() -> Result {
        let mut storage = MaybeUninit::<bindings::ib_device_modify>::uninit();
        let attributes = storage.as_mut_ptr();
        let description = [0xa5u8; 64];
        // SAFETY: This initializes all bytes of exactly the description field selected below.
        unsafe { (&raw mut (*attributes).node_desc).write(description) };
        // SAFETY: The selected array is initialized and retained; the GUID is unselected.
        let change = unsafe {
            DeviceModification::from_raw(
                bindings::ib_device_modify_flags_IB_DEVICE_MODIFY_NODE_DESC as c_int,
                attributes,
            )
        }?;
        assert_eq!(change.node_description, Some(description));
        assert_eq!(change.system_image_guid, None);
        Ok(())
    }

    #[test]
    fn empty_and_unsupported_masks_do_not_read_input() -> Result {
        // SAFETY: An empty mask selects no input storage.
        let change = unsafe { DeviceModification::from_raw(0, core::ptr::null()) }?;
        assert_eq!(change.system_image_guid, None);
        assert_eq!(change.node_description, None);
        assert!(matches!(
            // SAFETY: Unsupported bits reject the request before any input access.
            unsafe { DeviceModification::from_raw(-1, core::ptr::null()) },
            Err(EOPNOTSUPP)
        ));
        Ok(())
    }
}
