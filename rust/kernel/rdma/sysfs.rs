// SPDX-License-Identifier: GPL-2.0

//! Ownership of legacy provider sysfs attributes.

use super::{
    Device,
    DeviceOperations,
    Operations, //
};
use crate::{
    bindings,
    prelude::*,
    sysfs::Buffer,
    types::{
        Opaque,
        ScopeGuard, //
    }, //
};
use core::ptr;

/// Checks a single sysfs path component before publishing its descriptor.
pub(super) const fn valid_name(name: &CStr) -> bool {
    let bytes = name.to_bytes();
    if bytes.is_empty()
        || (bytes.len() == 1 && bytes[0] == b'.')
        || (bytes.len() == 2 && bytes[0] == b'.' && bytes[1] == b'.')
    {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'/' {
            return false;
        }
        index += 1;
    }
    true
}

/// A read-only attribute preserving an existing provider's sysfs ABI.
///
/// New RDMA device parameters should be exposed through netlink instead of adding sysfs files.
/// The callback runs in sleepable context and may run concurrently with other provider calls.
/// It receives a registration reference keeping core resources and provider data alive.
pub struct ReadOnlyAttribute<T: DeviceOperations> {
    name: &'static CStr,
    show: fn(Pin<&T>, &Device<T>, &mut Buffer<'_>) -> Result,
}

impl<T: DeviceOperations> ReadOnlyAttribute<T> {
    /// Describes a named attribute with mode 0444.
    #[inline]
    pub const fn new(
        name: &'static CStr,
        show: fn(Pin<&T>, &Device<T>, &mut Buffer<'_>) -> Result,
    ) -> Self {
        assert!(valid_name(name));
        Self { name, show }
    }
}

#[repr(C)]
struct Entry<T: DeviceOperations> {
    raw: Opaque<bindings::device_attribute>,
    description: &'static ReadOnlyAttribute<T>,
}

/// Owns stable descriptors and the null-terminated pointer array used by the RDMA core.
///
/// # Invariants
///
/// The vectors never grow after construction. `raw` points to `attributes`, whose non-null
/// elements point into `entries`. The owning provider state retains the pinned group until
/// device removal has drained attribute callbacks, including compat devices and failed setup.
#[pin_data]
pub(super) struct Group<T: DeviceOperations> {
    #[pin]
    raw: Opaque<bindings::attribute_group>,
    _attributes: KVec<*mut bindings::attribute>,
    _entries: KVec<Entry<T>>,
}

// SAFETY: The private vectors and descriptors are immutable once initialized. The core only
// reads them, and their lockdep keys are static. Provider callbacks require T: Send + Sync.
unsafe impl<T: DeviceOperations> Send for Group<T> {}
// SAFETY: Shared access exposes only immutable descriptors and synchronized provider callbacks.
unsafe impl<T: DeviceOperations> Sync for Group<T> {}

impl<T: DeviceOperations> Group<T> {
    pub(super) fn new() -> Result<Pin<KBox<Self>>> {
        let mut entries = KVec::with_capacity(T::ATTRIBUTES.len(), GFP_KERNEL)?;
        let mut attributes = KVec::with_capacity(
            T::ATTRIBUTES.len().checked_add(1).ok_or(EOVERFLOW)?,
            GFP_KERNEL,
        )?;
        for description in T::ATTRIBUTES {
            let mut raw = bindings::device_attribute::default();
            raw.attr.name = description.name.as_char_ptr();
            raw.attr.mode = 0o444;
            #[cfg(CONFIG_DEBUG_LOCK_ALLOC)]
            {
                // Equivalent to sysfs_attr_init(): dynamic attributes need a static class key.
                raw.attr.key = crate::sync::static_lock_class!().as_ptr();
            }
            raw.__bindgen_anon_1.show = Some(Self::show);
            entries.push(
                Entry {
                    raw: Opaque::new(raw),
                    description,
                },
                GFP_KERNEL,
            )?;
        }
        for entry in &entries {
            // SAFETY: Each initialized entry remains in this allocation, which will not grow.
            attributes.push(unsafe { &raw mut (*entry.raw.get()).attr }, GFP_KERNEL)?;
        }
        attributes.push(ptr::null_mut(), GFP_KERNEL)?;
        let mut raw = bindings::attribute_group::default();
        raw.__bindgen_anon_2.attrs = attributes.as_mut_ptr();
        // INVARIANT: The completed vectors own every pointer target and are never changed.
        KBox::pin_init(
            pin_init!(Self {
                raw: Opaque::new(raw),
                _attributes: attributes,
                _entries: entries,
            }),
            GFP_KERNEL,
        )
    }

    #[inline]
    pub(super) fn as_raw(&self) -> *const bindings::attribute_group {
        self.raw.get()
    }

    /// # Safety
    ///
    /// The caller must retain a core or compat device owned by this adapter, a Group entry
    /// installed on that device, and one exclusively writable output page for the complete
    /// callback.
    unsafe extern "C" fn show(
        device: *mut bindings::device,
        attribute: *mut bindings::device_attribute,
        output: *mut c_char,
    ) -> isize {
        // SAFETY: The RDMA core installs this group only on its own core and compat devices.
        // An active sysfs callback keeps the device and its owning provider allocation alive.
        let device =
            unsafe { (*crate::container_of!(device, bindings::ib_core_device, dev)).owner };
        // SAFETY: The live allocation permits acquiring a registration reference. A sysfs
        // reference alone would not prevent core resources from being torn down.
        if !unsafe { bindings::ib_device_try_get(device) } {
            return ENODEV.to_errno() as isize;
        }
        let _registration = ScopeGuard::new(|| {
            // SAFETY: Release exactly the reference acquired above, after the provider call.
            unsafe { bindings::ib_device_put(device) };
        });
        // SAFETY: Our callback's attribute is an Entry kept alive by the pinned Group. Core
        // unregistration waits for our registration reference before releasing its resources.
        // sysfs supplies an exclusively writable page and consumes only the returned prefix.
        unsafe {
            let entry = crate::container_of!(Opaque::cast_from(attribute), Entry<T>, raw);
            let description = (*entry).description;
            let data = Operations::<T>::data(device);
            let device = Device::from_raw(device);
            let mut output = Buffer::new(output.cast(), crate::page::PAGE_SIZE);
            match (description.show)(data, device, &mut output) {
                Ok(()) => output.finish() as isize,
                Err(error) => error.to_errno() as isize,
            }
        }
    }
}
