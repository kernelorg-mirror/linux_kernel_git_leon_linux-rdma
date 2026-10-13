// SPDX-License-Identifier: GPL-2.0

//! Provider callbacks backed by owned, pinned Rust data.

use super::{
    Device,
    DeviceAttributes,
    DeviceModification,
    Mad,
    MadDisposition,
    MadOutput,
    MadRequest,
    PortAttributes,
    PortImmutable,
    PortModification,
    StatisticsDescription,
    UserData, //
};
use crate::{
    bindings,
    prelude::*,
    sync::Mutex,
    types::ForeignOwnable, //
};
use core::{
    marker::PhantomData,
    ptr, //
};

/// The link layer of an RDMA port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkLayer {
    /// No link layer is available for this port.
    Unspecified,
    /// Native InfiniBand.
    InfiniBand,
    /// Ethernet, including RoCE.
    Ethernet,
}

impl LinkLayer {
    fn as_raw(self) -> bindings::rdma_link_layer {
        match self {
            Self::Unspecified => bindings::rdma_link_layer_IB_LINK_LAYER_UNSPECIFIED,
            Self::InfiniBand => bindings::rdma_link_layer_IB_LINK_LAYER_INFINIBAND,
            Self::Ethernet => bindings::rdma_link_layer_IB_LINK_LAYER_ETHERNET,
        }
    }
}

/// Device operations implemented by a provider's Rust data.
///
/// Callbacks may run concurrently. Implementations must synchronize their own mutable state.
/// The data stays pinned until the core's final device deallocation, including registration
/// failure. A callback receives a shared borrow of this data, never of the core's C allocation.
#[vtable]
pub trait DeviceOperations: Send + Sync + Sized + 'static {
    /// Read-only files preserving an existing provider's sysfs ABI.
    ///
    /// Reads before registration is enabled or after it has drained return `ENODEV`.
    /// New RDMA device parameters should use netlink instead.
    const ATTRIBUTES: &'static [super::ReadOnlyAttribute<Self>] = &[];

    /// Enables the provider before the RDMA core attaches clients.
    ///
    /// Called in sleepable context with a core registration reference and initialized caches,
    /// without RTNL held. The core may call this again after moving the device to another
    /// network namespace. An error aborts initial registration.
    fn enable(self: Pin<&Self>, _device: &Device<Self>) -> Result {
        Ok(())
    }

    /// Queries device capabilities, with optional userspace provider buffers.
    ///
    /// Called in sleepable context. The provider validates any input and writes its own
    /// userspace response before returning the device attributes.
    fn query_device(
        self: Pin<&Self>,
        _data: Option<UserData<'_, Self>>,
    ) -> Result<DeviceAttributes> {
        Err(EOPNOTSUPP)
    }

    /// Applies selected device attributes in sleepable context.
    ///
    /// On success, the adapter publishes a selected node description through the core's
    /// synchronized setter. Device modification callbacks and that publication are serialized
    /// together. The provider handles any system-image GUID update in its own data.
    fn modify_device(self: Pin<&Self>, _change: DeviceModification) -> Result {
        Err(EOPNOTSUPP)
    }

    /// Returns a GID in network byte order. Called in sleepable context.
    fn query_gid(self: Pin<&Self>, port: u32, index: i32) -> Result<[u8; 16]>;

    /// Returns a partition key in host byte order. Called in sleepable context.
    fn query_pkey(self: Pin<&Self>, port: u32, index: u16) -> Result<u16>;

    /// Returns the port's link layer. This callback must not sleep.
    fn link_layer(self: Pin<&Self>, port: u32) -> LinkLayer;

    /// Queries port attributes. Called in sleepable context without RTNL held.
    fn query_port(self: Pin<&Self>, _device: &Device<Self>, _port: u32) -> Result<PortAttributes> {
        Err(EOPNOTSUPP)
    }

    /// Modifies port attributes. Called in sleepable context.
    fn modify_port(self: Pin<&Self>, _port: u32, _change: PortModification) -> Result {
        Err(EOPNOTSUPP)
    }

    /// Queries immutable port properties during registration, before GID-cache initialization.
    ///
    /// Called in sleepable context without RTNL held. The core has initialized port data and
    /// any network-device association, but this callback must not assume a populated GID cache.
    fn port_immutable(
        self: Pin<&Self>,
        _device: &Device<Self>,
        _port: u32,
    ) -> Result<PortImmutable> {
        Err(EOPNOTSUPP)
    }

    /// Describes device-wide counters.
    ///
    /// Called in sleepable context during registration. Counter descriptions must remain
    /// unchanged until device removal. Device-wide counter reads use port number zero.
    /// Leave this method unimplemented when counters are unavailable. Implementing it also
    /// requires implementing [`Self::read_statistics`].
    fn device_statistics(self: Pin<&Self>) -> StatisticsDescription {
        build_error!(crate::error::VTABLE_DEFAULT_ERROR)
    }

    /// Describes a port's counters.
    ///
    /// Called in sleepable context during registration. A port's counter descriptions must
    /// remain unchanged until device removal. More than one allocation may use this table.
    /// Leave this method unimplemented when counters are unavailable. Implementing it also
    /// requires implementing [`Self::read_statistics`] and supplying a table for every port.
    fn port_statistics(self: Pin<&Self>, _port: u32) -> StatisticsDescription {
        build_error!(crate::error::VTABLE_DEFAULT_ERROR)
    }

    /// Refreshes all counter values for a device or port. Called in sleepable context.
    ///
    /// The core supplies exclusive access to this allocation's values, either before publishing
    /// it or under its statistics mutex. Other allocations and device operations may run
    /// concurrently. The slice length matches the table supplied for this device or port.
    /// A successful return refreshes the core's cache timestamp for the complete table.
    fn read_statistics(self: Pin<&Self>, _port: u32, _values: &mut [u64]) -> Result {
        Err(EOPNOTSUPP)
    }

    /// Processes a standard 256-byte management datagram. This callback must not sleep.
    ///
    /// The output starts zeroed. Success or Reply copies it to the core and sets the output
    /// size to 256 bytes; Failure or Consumed leaves the output untouched. This interface does
    /// not support larger Omni-Path datagrams. The provider must not advertise that capability.
    fn process_mad(
        self: Pin<&Self>,
        _request: MadRequest<'_>,
        _output: &mut MadOutput,
    ) -> MadDisposition {
        MadDisposition::Failure
    }
}

#[pin_data]
struct State<T: DeviceOperations> {
    #[pin]
    data: T,
    #[pin]
    modification: Mutex<()>,
    release: Option<unsafe extern "C" fn(*mut bindings::ib_device)>,
    attributes: Option<Pin<KBox<super::sysfs::Group<T>>>>,
}

/// Installs the Rust callback boundary on a core-allocated device.
///
/// This adapter supports providers whose allocation and remaining operations are still managed
/// through the C API. Installation transfers ownership to the core; there is no separately
/// droppable guard that could release the data while callbacks remain callable.
pub struct Operations<T: DeviceOperations>(PhantomData<T>);

impl<T: DeviceOperations> Operations<T> {
    /// Initializes provider data and installs its operations before device publication.
    ///
    /// The previous `dealloc_driver` callback runs before the Rust data is dropped. On failure,
    /// the device is unchanged. On success, `ib_dealloc_device()` owns release of the data.
    ///
    /// # Safety
    ///
    /// `device` must be a live, exclusively owned, unpublished allocation from `ib_alloc_device`.
    /// Its `dev.driver_data`, `query_gid`, `query_pkey` and `get_link_layer` slots must be unused.
    /// Slots corresponding to implemented optional methods must also be unused. If a statistics
    /// allocator is implemented, both statistics allocation slots and `get_hw_stats` must be
    /// unused. While any callback is running, the device's DMA configuration must remain
    /// initialized and unchanged.
    /// If device modification is implemented, all concurrent node-description accesses must
    /// use the core's synchronized helpers. Direct initialization before publication is allowed.
    /// If `T::ATTRIBUTES` is nonempty, `device_group` must also be unused and remain unchanged
    /// after installation. The core must remove sysfs files before final deallocation.
    /// Its operations owner must be unset or the module implementing `T`.
    /// Before that module can unload, device creation must stop and `ib_unregister_driver`
    /// must fence every device using these operations, including queued unregistration.
    /// After success, the caller must not change those slots, the owner or `dealloc_driver`, and
    /// must eventually let the core deallocate the device. The previous deallocation callback
    /// must not free the core allocation or invoke any of the installed callbacks.
    pub unsafe fn install(
        device: *mut bindings::ib_device,
        data: impl PinInit<T, Error>,
    ) -> Result {
        build_assert!(
            !(T::HAS_DEVICE_STATISTICS || T::HAS_PORT_STATISTICS) || T::HAS_READ_STATISTICS,
            "statistics descriptions require read_statistics"
        );
        // SAFETY: The caller exclusively owns the initialized allocation.
        let release = unsafe { (*device).ops.dealloc_driver };
        let identity = super::registry::prepare::<T>(device)?;
        let attributes = if T::ATTRIBUTES.is_empty() {
            None
        } else {
            Some(super::sysfs::Group::<T>::new()?)
        };
        let state = KBox::pin_init(
            try_pin_init!(State {
                data <- data,
                modification <- crate::new_mutex!(()),
                release,
                attributes,
            }),
            GFP_KERNEL,
        )?;
        // SAFETY: The caller reserves these slots. All fallible initialization is complete.
        // The core retains the foreign owner until the installed final deallocation callback.
        unsafe {
            if let Some(attributes) = &state.attributes {
                (*device).ops.device_group = attributes.as_raw();
            }
            (*device).__bindgen_anon_1.dev.driver_data = state.into_foreign();
            (*device).ops.owner = crate::module::this_module::<T::OwnerModule>().as_ptr();
            (*device).ops.query_gid = Some(Self::query_gid);
            (*device).ops.query_pkey = Some(Self::query_pkey);
            (*device).ops.get_link_layer = Some(Self::link_layer);
            if T::HAS_ENABLE {
                (*device).ops.enable_driver = Some(Self::enable);
            }
            if T::HAS_QUERY_DEVICE {
                (*device).ops.query_device = Some(Self::query_device);
            }
            if T::HAS_MODIFY_DEVICE {
                (*device).ops.modify_device = Some(Self::modify_device);
            }
            if T::HAS_QUERY_PORT {
                (*device).ops.query_port = Some(Self::query_port);
            }
            if T::HAS_MODIFY_PORT {
                (*device).ops.modify_port = Some(Self::modify_port);
            }
            if T::HAS_PORT_IMMUTABLE {
                (*device).ops.get_port_immutable = Some(Self::port_immutable);
            }
            if T::HAS_DEVICE_STATISTICS {
                (*device).ops.alloc_hw_device_stats = Some(Self::alloc_device_statistics);
            }
            if T::HAS_PORT_STATISTICS {
                (*device).ops.alloc_hw_port_stats = Some(Self::alloc_port_statistics);
            }
            if T::HAS_DEVICE_STATISTICS || T::HAS_PORT_STATISTICS {
                (*device).ops.get_hw_stats = Some(Self::read_statistics);
            }
            if T::HAS_PROCESS_MAD {
                (*device).ops.process_mad = Some(Self::process_mad);
            }
            (*device).ops.dealloc_driver = Some(Self::release);
        }
        super::registry::insert(identity);
        Ok(())
    }

    /// Borrows the provider data within a live device operation.
    ///
    /// # Safety
    ///
    /// `device` must have been successfully installed by this `Operations<T>`. Its final
    /// deallocation must be excluded for `'a`. This does not grant access to core resources
    /// such as GID tables, whose lifetime may end before the allocation is released.
    #[inline]
    pub unsafe fn data<'a>(device: *mut bindings::ib_device) -> Pin<&'a T> {
        // SAFETY: Installation stored this foreign owner; the caller excludes final release.
        // `data` is structurally pinned and never moved before its containing owner is dropped.
        unsafe {
            Pin::<KBox<State<T>>>::borrow((*device).__bindgen_anon_1.dev.driver_data)
                .map_unchecked(|state| &state.data)
        }
    }

    /// # Safety
    ///
    /// The caller must retain the installed device in sleepable context and initialize the
    /// selected input fields. The core description lock must be initialized.
    unsafe extern "C" fn modify_device(
        device: *mut bindings::ib_device,
        mask: c_int,
        attributes: *mut bindings::ib_device_modify,
    ) -> c_int {
        // SAFETY: The core retains the device and initializes selected input fields. Allocation
        // initialized the description lock, and installation reserves the modification callback.
        unsafe {
            let result = (|| -> Result {
                let change = DeviceModification::from_raw(mask, attributes)?;
                let description = change.node_description;
                let state =
                    Pin::<KBox<State<T>>>::borrow((*device).__bindgen_anon_1.dev.driver_data);
                let _modification = state.modification.lock();
                Self::data(device).modify_device(change)?;
                if let Some(description) = description {
                    bindings::ib_set_node_desc(device, description.as_ptr().cast());
                }
                Ok(())
            })();
            match result {
                Ok(()) => 0,
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain a registration reference with initialized cache and port
    /// resources throughout this sleepable callback.
    unsafe extern "C" fn enable(device: *mut bindings::ib_device) -> c_int {
        // SAFETY: The core retains a registration reference and has initialized the cache and
        // port resources before invoking this callback, including on namespace re-enablement.
        unsafe {
            match Self::data(device).enable(Device::from_raw(device)) {
                Ok(()) => 0,
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain the installed device and must supply exclusive output storage.
    /// Optional driver data belongs to the live uverbs bundle, with disassociation excluded.
    unsafe extern "C" fn query_device(
        device: *mut bindings::ib_device,
        output: *mut bindings::ib_device_attr,
        udata: *mut bindings::ib_udata,
    ) -> c_int {
        // SAFETY: The core retains the installed device and supplies exclusive output storage.
        // Optional driver data belongs to the live uverbs bundle, with disassociation excluded.
        unsafe {
            match Self::data(device).query_device(UserData::from_raw(udata)) {
                Ok(attr) => {
                    output.write(attr.into_raw());
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain the installed device and must provide exclusive output storage.
    unsafe extern "C" fn query_gid(
        device: *mut bindings::ib_device,
        port: u32,
        index: c_int,
        output: *mut bindings::ib_gid,
    ) -> c_int {
        // SAFETY: The core pins the installed device and provides exclusive output storage.
        unsafe {
            match Self::data(device).query_gid(port, index) {
                Ok(raw) => {
                    output.write(bindings::ib_gid { raw });
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain the installed device and must provide exclusive output storage.
    unsafe extern "C" fn query_pkey(
        device: *mut bindings::ib_device,
        port: u32,
        index: u16,
        output: *mut u16,
    ) -> c_int {
        // SAFETY: The core pins the installed device and provides exclusive output storage.
        unsafe {
            match Self::data(device).query_pkey(port, index) {
                Ok(key) => {
                    output.write(key);
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain the installed device throughout this callback.
    unsafe extern "C" fn link_layer(
        device: *mut bindings::ib_device,
        port: u32,
    ) -> bindings::rdma_link_layer {
        // SAFETY: The core pins the installed device throughout this callback.
        unsafe { Self::data(device) }.link_layer(port).as_raw()
    }

    /// # Safety
    ///
    /// The caller must retain the installed device and must provide exclusive output storage.
    /// Its initialized core resources and DMA configuration remain live during the query.
    unsafe extern "C" fn query_port(
        device: *mut bindings::ib_device,
        port: u32,
        output: *mut bindings::ib_port_attr,
    ) -> c_int {
        // SAFETY: The core pins the installed device and provides exclusive output storage.
        // Its initialized core resources and DMA configuration remain live during the query.
        unsafe {
            match Self::data(device).query_port(Device::from_raw(device), port) {
                Ok(attr) => {
                    let mut raw = attr.into_raw();
                    // iw_query_port() owns these fields and initializes them before this call.
                    if bindings::rdma_protocol_iwarp(device, port) {
                        raw.state = (*output).state;
                        raw.phys_state = (*output).phys_state;
                        raw.max_mtu = (*output).max_mtu;
                        raw.active_mtu = (*output).active_mtu;
                    }
                    output.write(raw);
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain the installed device and must supply stable input with the
    /// fields required by the modification flags initialized.
    unsafe extern "C" fn modify_port(
        device: *mut bindings::ib_device,
        port: u32,
        flags: c_int,
        input: *mut bindings::ib_port_modify,
    ) -> c_int {
        // SAFETY: The core pins the installed device and supplies stable input with the fields
        // required by the modification flags initialized.
        unsafe {
            let change = PortModification::from_raw(flags as u32, input);
            match Self::data(device).modify_port(port, change) {
                Ok(()) => 0,
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain the installed device with initialized port data and provide
    /// aligned, exclusively writable output. No initialized GID cache is required.
    unsafe extern "C" fn port_immutable(
        device: *mut bindings::ib_device,
        port: u32,
        output: *mut bindings::ib_port_immutable,
    ) -> c_int {
        // SAFETY: The core retains the unpublished device and exclusive output. Port data is
        // initialized before this callback; the device borrow grants no GID-cache capability.
        unsafe {
            match Self::data(device).port_immutable(Device::from_raw(device), port) {
                Ok(attr) => {
                    output.write(attr.into_raw());
                    0
                }
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain the installed device in sleepable context.
    unsafe extern "C" fn alloc_device_statistics(
        device: *mut bindings::ib_device,
    ) -> *mut bindings::rdma_hw_stats {
        // SAFETY: The core pins the installed device and permits sleeping allocation.
        unsafe { Self::data(device) }
            .device_statistics()
            .allocate::<T>()
    }

    /// # Safety
    ///
    /// The caller must retain the installed device in sleepable context.
    unsafe extern "C" fn alloc_port_statistics(
        device: *mut bindings::ib_device,
        port: u32,
    ) -> *mut bindings::rdma_hw_stats {
        // SAFETY: The core pins the installed device and permits sleeping allocation.
        unsafe { Self::data(device) }
            .port_statistics(port)
            .allocate::<T>()
    }

    /// # Safety
    ///
    /// The caller must retain the installed device and a statistics allocation from the
    /// paired allocator. Its num_counters entries must be initialized and exclusively
    /// writable.
    unsafe extern "C" fn read_statistics(
        device: *mut bindings::ib_device,
        stats: *mut bindings::rdma_hw_stats,
        port: u32,
        _index: c_int,
    ) -> c_int {
        if stats.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: The core retains the installed device and the allocation from our paired
        // allocator. Its initialized flexible array has num_counters entries. The core grants
        // exclusive access to the values, without granting a mutable borrow of its mutex.
        unsafe {
            let count = (*stats).num_counters;
            let values =
                core::slice::from_raw_parts_mut((&raw mut (*stats).value).cast(), count as usize);
            match Self::data(device).read_statistics(port, values) {
                Ok(()) => count,
                Err(error) => error.to_errno(),
            }
        }
    }

    /// # Safety
    ///
    /// The caller must retain the installed device and stable input and optional receive
    /// metadata. Valid GRH metadata must be readable, and output, size and pkey must be
    /// disjoint, aligned, exclusively writable storage of their indicated types.
    unsafe extern "C" fn process_mad(
        device: *mut bindings::ib_device,
        flags: c_int,
        port: u32,
        completion: *const bindings::ib_wc,
        grh: *const bindings::ib_grh,
        input: *const bindings::ib_mad,
        output: *mut bindings::ib_mad,
        size: *mut usize,
        pkey: *mut u16,
    ) -> c_int {
        // SAFETY: The core retains the installed device and supplies initialized input, stable
        // optional receive metadata and disjoint exclusive output of at least one standard MAD.
        // GRH data is read only when marked valid. The response is initialized independently
        // and written only after the provider returns, without reading any previous output.
        unsafe {
            let input = Mad::from_raw(&*input);
            let request = MadRequest::new(port, flags, &input, completion, grh);
            let mut response = MadOutput::default();
            let disposition = Self::data(device).process_mad(request, &mut response);
            if matches!(disposition, MadDisposition::Success | MadDisposition::Reply) {
                output.write(response.message.into_raw());
                size.write(size_of::<bindings::ib_mad>());
                if let Some(index) = response.pkey_index {
                    pkey.write(index);
                }
            }
            disposition.as_raw()
        }
    }

    /// # Safety
    ///
    /// The core must exclude further operations and release this adapter's initialized owner
    /// exactly once, while retaining its allocation and parents until this callback returns.
    unsafe extern "C" fn release(device: *mut bindings::ib_device) {
        super::registry::remove(device);
        // SAFETY: The core invokes final deallocation once, after draining operations. Take
        // back exactly the foreign owner installed above. The previous callback cannot free
        // the core allocation, so the Rust data remains alive throughout its cleanup.
        unsafe {
            let state =
                Pin::<KBox<State<T>>>::from_foreign((*device).__bindgen_anon_1.dev.driver_data);
            (*device).__bindgen_anon_1.dev.driver_data = ptr::null_mut();
            if let Some(release) = state.release {
                release(device);
            }
            drop(state);
        }
    }
}
