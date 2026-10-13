// SPDX-License-Identifier: GPL-2.0

//! Owned registration of single-port software RDMA devices.

use super::{
    link,
    QueuePairOperations, //
};
use crate::{
    bindings,
    error::to_result,
    net::namespace::{
        Namespace,
        NamespaceRef, //
    },
    prelude::*,
    types::ScopeGuard, //
};
use core::{
    marker::PhantomData,
    mem::size_of,
    ptr::{
        self,
        NonNull, //
    }, //
};

crate::impl_flags!(
    /// Additional legacy userspace commands implemented by the native queue adapters.
    ///
    /// User completion queues must provide their own mapped polling interface. Legacy
    /// command polling is not supported: the native polling adapter only emits completions
    /// carrying kernel request capabilities.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct UserCommands(u64);

    /// A legacy userspace command not included in the core's default command mask.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum UserCommand {
        /// Ring a mapped userspace send queue with an empty write-command request chain.
        ///
        /// Nonempty chains are unsupported; work requests must be published in the mapped queue.
        PostSend = 1 << bindings::ib_uverbs_write_cmds_IB_USER_VERBS_CMD_POST_SEND,
        /// Post receive work requests through the write-command interface.
        PostReceive = 1 << bindings::ib_uverbs_write_cmds_IB_USER_VERBS_CMD_POST_RECV,
        /// Post shared receive work requests through the write-command interface.
        PostSharedReceive = 1 << bindings::ib_uverbs_write_cmds_IB_USER_VERBS_CMD_POST_SRQ_RECV,
        /// Arm completion notification through the write-command interface.
        RequestNotify = 1 << bindings::ib_uverbs_write_cmds_IB_USER_VERBS_CMD_REQ_NOTIFY_CQ,
    }
);

/// Identity and userspace compatibility settings copied before device publication.
pub struct Configuration<'a> {
    /// Initial node description, at most 64 bytes excluding its terminating NUL.
    pub node_description: &'a CStr,
    /// Node GUID in network byte order.
    pub node_guid: [u8; 8],
    /// Provider-specific userspace ABI version.
    pub user_abi_version: u32,
    /// Additional legacy command entry points to enable.
    pub user_commands: UserCommands,
}

/// Owns an unpublished software device with native provider and queue callbacks installed.
///
/// The device has one channel-adapter port, tracked virtual DMA, and one completion vector
/// per possible CPU. Publication requires a managed link registration, which fences device
/// callbacks before its handler can disappear. Failed construction or publication releases
/// all initialized provider resources through the core deallocator.
///
/// # Invariants
///
/// An externally observable owner has `device: Some`, uniquely owning an unpublished core
/// allocation with `Operations<T>` and every mandatory native queue adapter installed. The
/// immutable virtual DMA configuration and `_namespace` remain live until publication or
/// deallocation. Only successful publication clears `device`, before this owner is dropped.
pub struct UnregisteredDevice<T: QueuePairOperations> {
    device: Option<NonNull<bindings::ib_device>>,
    _namespace: NamespaceRef,
    windows: bool,
    multicast: bool,
    advice: bool,
    _provider: PhantomData<fn() -> T>,
}

impl<T: QueuePairOperations> UnregisteredDevice<T> {
    /// Initializes an unpublished device in `namespace`, in sleepable context.
    ///
    /// The provider must implement device and port queries and immutable port properties.
    /// Missing implementations return `EINVAL` before allocation. The core can force the
    /// initial namespace when RDMA namespace sharing is enabled.
    pub fn new(
        namespace: &Namespace,
        config: Configuration<'_>,
        data: impl PinInit<T, Error>,
    ) -> Result<Self> {
        if !T::HAS_QUERY_DEVICE || !T::HAS_QUERY_PORT || !T::HAS_PORT_IMMUTABLE {
            return Err(EINVAL);
        }
        let description = config.node_description.to_bytes();
        if description.len() > 64 {
            return Err(EINVAL);
        }
        let namespace = namespace.try_to_ref().ok_or(ENODEV)?;
        // SAFETY: The active namespace is fully initialized. The allocation contains exactly
        // the core header; native provider state is installed separately below.
        let device = NonNull::new(unsafe {
            bindings::_ib_alloc_device(size_of::<bindings::ib_device>(), namespace.as_raw())
        })
        .ok_or(ENOMEM)?;
        let allocation = ScopeGuard::new_with_data(device, |device| {
            // SAFETY: Until publication this guard owns the allocation. The core deallocator
            // releases whichever callbacks and virtual DMA resources have been initialized.
            unsafe { bindings::ib_dealloc_device(device.as_ptr()) };
        });
        let raw = device.as_ptr();
        // SAFETY: This guard exclusively owns initialization, and no callbacks can run yet.
        // The core zeroed the node description; the bounded copy preserves its remaining bytes.
        unsafe {
            ptr::copy_nonoverlapping(
                description.as_ptr().cast(),
                (*raw).node_desc.as_mut_ptr(),
                description.len(),
            );
            (*raw).node_type = bindings::RDMA_NODE_IB_CA as u8;
            (*raw).phys_port_cnt = 1;
            (*raw).num_comp_vectors = bindings::num_possible_cpus() as c_int;
            (*raw).node_guid = u64::from_ne_bytes(config.node_guid);
            (*raw).name_assign_type = bindings::rdma_nl_name_assign_type_RDMA_NAME_ASSIGN_TYPE_USER;
            (*raw).uverbs_cmd_mask |= u64::from(config.user_commands);
            (*raw).ops.uverbs_abi_ver = config.user_abi_version;
            to_result(bindings::ib_virt_dma_enable(raw))?;
            super::Operations::install(raw, data)?;
            super::UserContexts::<T>::install(raw);
            super::ProtectionDomains::<T>::install(raw);
            super::MemoryRegions::<T>::install(raw);
            super::AddressHandles::<T>::install(raw);
            super::BasicSharedReceiveQueues::<T>::install(raw);
            super::CompletionQueues::<T>::install(raw);
            super::QueuePairs::<T>::install(raw);
        }
        // INVARIANT: All mandatory callbacks and matching provider ownership are installed.
        // The allocation guard transfers cleanup to this owner with no fallible steps remaining.
        Ok(Self {
            device: Some(allocation.dismiss()),
            _namespace: namespace,
            windows: false,
            multicast: false,
            advice: false,
            _provider: PhantomData,
        })
    }

    /// Enables native memory-window callbacks. Repeated calls have no additional effect.
    pub fn with_memory_windows(mut self) -> Self
    where
        T: super::MemoryWindowOperations,
    {
        if !self.windows {
            // SAFETY: The unpublished owner has matching provider and PD adapters. These
            // slots have not been installed before and cannot be changed through another API.
            unsafe { super::MemoryWindows::<T>::install(self.device.unwrap().as_ptr()) };
            self.windows = true;
        }
        self
    }

    /// Enables native multicast callbacks. Repeated calls have no additional effect.
    pub fn with_multicast(mut self) -> Self
    where
        T: super::MulticastOperations,
    {
        if !self.multicast {
            // SAFETY: The unpublished owner has matching provider and QP adapters, and this
            // is the only API which installs its previously unused multicast callbacks.
            unsafe { super::MulticastGroups::<T>::install(self.device.unwrap().as_ptr()) };
            self.multicast = true;
        }
        self
    }

    /// Enables native memory-advice callbacks. Repeated calls have no additional effect.
    pub fn with_memory_advice(mut self) -> Self
    where
        T: super::MemoryAdviceOperations,
    {
        if !self.advice {
            // SAFETY: The unpublished owner has matching provider and PD adapters, and this
            // is the only API which installs its previously unused memory-advice callback.
            unsafe { super::MemoryAdvice::<T>::install(self.device.unwrap().as_ptr()) };
            self.advice = true;
        }
        self
    }

    /// Publishes this device through a matching managed link request.
    ///
    /// `network_namespace` must match the associated netdev while RTNL protects association.
    /// In exclusive RDMA namespace mode it must also match this device's allocation namespace.
    /// The provider must handle netdev unregistration by unregistering this RDMA device or
    /// detaching its netdev association. Otherwise netdev removal waits for the retained link.
    /// Provider enablement must revalidate dependencies which can change before publication;
    /// the core makes the device available to retained notifier lookups before calling enable.
    /// This consumes the owner on success and error and may sleep without RTNL held.
    pub fn register<L>(
        mut self,
        request: &link::NewLink<'_, L>,
        network_namespace: &NamespaceRef,
    ) -> Result
    where
        L: link::Operations<Device = T>,
    {
        let driver_id = request.driver_id().ok_or(EINVAL)?;
        let raw = self.device.unwrap().as_ptr();
        // SAFETY: The unpublished allocation and active network namespace are retained.
        // The core permits a different allocation namespace only in shared namespace mode.
        if !unsafe { bindings::rdma_dev_access_netns(raw, network_namespace.as_raw()) } {
            return Err(ENODEV);
        }
        // SAFETY: This unpublished owner controls driver identity and the unused link slot.
        // A managed request retains its handler and provides the required teardown fence.
        unsafe {
            (*raw).ops.driver_id = driver_id;
            request.attach(raw);
        }
        let netdev = request.net_device().as_raw();
        // SAFETY: The request retains the netdev allocation. RTNL excludes migration and
        // removal while checking its registered namespace and associating the device.
        let result = unsafe {
            bindings::rtnl_lock();
            let result = if u32::from((*netdev).reg_state)
                == bindings::netdev_reg_state_NETREG_REGISTERED
                && bindings::dev_net(netdev) == network_namespace.as_raw()
            {
                bindings::ib_device_set_netdev(raw, netdev, 1)
            } else {
                ENODEV.to_errno()
            };
            bindings::rtnl_unlock();
            result
        };
        to_result(result)?;
        // SAFETY: Every required callback, stable virtual DMA configuration and network
        // association are installed. The request and active core namespace span registration.
        // Failure leaves caller ownership intact, even if concurrent removal was attempted.
        to_result(unsafe {
            bindings::ib_register_device(raw, request.name().as_char_ptr(), ptr::null_mut())
        })?;
        // The core may already have freed the device. Clear only our local ownership token;
        // dropping this value releases the temporary namespace reference without touching raw.
        self.device = None;
        Ok(())
    }
}

impl<T: QueuePairOperations> Drop for UnregisteredDevice<T> {
    fn drop(&mut self) {
        if let Some(device) = self.device {
            // SAFETY: A present token means publication did not succeed. The matching native
            // deallocator drains provider ownership before the core frees this allocation.
            unsafe { bindings::ib_dealloc_device(device.as_ptr()) };
        }
    }
}
