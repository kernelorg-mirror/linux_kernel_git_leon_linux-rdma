// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
// Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.

//! Device capabilities, link policy and module lifetime.

#![forbid(unsafe_code)]

use crate::{
    rxe_ns::Tunnels,
    rxe_param as params,
    rxe_port::Port,
    rxe_register::{
        LinkRequest,
        Registration, //
    },
    rxe_uapi, //
};
use kernel::{
    prelude::*,
    rdma::{
        AddressAttributes,
        AddressCreateFlag,
        AddressCreateFlags,
        AddressHandleOperations,
        AddressReleaseFlags,
        AddressRequest,
        AtomicCapability,
        BasicSharedReceiveOperations,
        CompletionAttributes,
        CompletionCapacity,
        CompletionCreation,
        CompletionNotify,
        CompletionOutput,
        CompletionQueueOperations,
        ContextData,
        Device,
        DeviceAttributes,
        DeviceCapability,
        DeviceModification,
        DeviceOperations,
        KernelCapability,
        LinkLayer,
        MadDisposition,
        MadOutput,
        MadRequest,
        MemoryWindowOperations,
        MemoryWindowType,
        Mtu,
        MulticastOperations,
        PortAttributes,
        PortEvent,
        PortImmutable,
        PortModification,
        ProtectionDomainFlags,
        ProtectionDomainOperations,
        QueuePair,
        QueuePairChange,
        QueuePairCreation,
        QueuePairInitAttributes,
        QueuePairOperations,
        QueuePairParents,
        QueuePairQuery,
        QueuePairRef,
        ReadOnlyAttribute,
        ReceiveRequests,
        ReleaseError,
        SendRequests,
        SharedReceiveAttributes,
        SharedReceiveChange,
        UserContextOperations,
        UserData,
        WindowCreation, //
    },
    sync::{
        atomic::{
            Atomic,
            Relaxed, //
        },
        Mutex, //
    },
    sysfs::Buffer, //
};

/// Value-only device settings, built before the allocation is published.
pub(crate) struct Parameters {
    attr: DeviceAttributes,
    pub(crate) raw_gid: [u8; 6],
    mtu: Mtu,
}

impl Parameters {
    fn new(raw_gid: [u8; 6], ndev_mtu: u32) -> Self {
        let mtu = mtu_from_netdev(ndev_mtu);
        let mut attr = DeviceAttributes {
            vendor_id: params::RXE_VENDOR_ID,
            max_mr_size: params::RXE_MAX_MR_SIZE,
            page_size_cap: u64::from(params::RXE_PAGE_SIZE_CAP),
            max_qp: params::RXE_MAX_QP,
            max_qp_wr: params::RXE_MAX_QP_WR,
            device_cap_flags: DeviceCapability::BadPkeyCounter
                | DeviceCapability::BadQkeyCounter
                | DeviceCapability::ChangePhysicalPort
                | DeviceCapability::UdAvPortEnforcement
                | DeviceCapability::PortActiveEvent
                | DeviceCapability::SystemImageGuid
                | DeviceCapability::RcRnrNakGeneration
                | DeviceCapability::SrqResize
                | DeviceCapability::MemoryManagementExtensions
                | DeviceCapability::MemoryWindow
                | DeviceCapability::FlushGlobal
                | DeviceCapability::MemoryWindowType2B
                | DeviceCapability::AtomicWrite,
            kernel_cap_flags: KernelCapability::AllowUserUnregister.into(),
            max_send_sge: params::RXE_MAX_SGE,
            max_recv_sge: params::RXE_MAX_SGE,
            max_sge_rd: params::RXE_MAX_SGE_RD,
            max_cq: params::RXE_MAX_CQ,
            max_cqe: params::RXE_MAX_CQE,
            max_mr: params::RXE_MAX_MR,
            max_mw: params::RXE_MAX_MW,
            max_pd: params::RXE_MAX_PD,
            max_qp_rd_atom: params::RXE_MAX_QP_RD_ATOM,
            max_res_rd_atom: params::RXE_MAX_RES_RD_ATOM,
            max_qp_init_rd_atom: params::RXE_MAX_QP_INIT_RD_ATOM,
            atomic_cap: AtomicCapability::Hca,
            max_mcast_grp: params::RXE_MAX_MCAST_GRP,
            max_mcast_qp_attach: params::RXE_MAX_MCAST_QP_ATTACH,
            max_total_mcast_qp_attach: params::RXE_MAX_TOT_MCAST_QP_ATTACH,
            max_ah: params::RXE_MAX_AH,
            max_srq: params::RXE_MAX_SRQ,
            max_srq_wr: params::RXE_MAX_SRQ_WR,
            max_srq_sge: params::RXE_MAX_SRQ_SGE,
            max_fast_reg_page_list_len: params::RXE_MAX_FMR_PAGE_LIST_LEN,
            max_pkeys: params::RXE_MAX_PKEYS as u16,
            local_ca_ack_delay: params::RXE_LOCAL_CA_ACK_DELAY as u8,
            sys_image_guid: u64::from_be_bytes([
                raw_gid[0] ^ 2,
                raw_gid[1],
                raw_gid[2],
                0xff,
                0xfe,
                raw_gid[3],
                raw_gid[4],
                raw_gid[5],
            ]),
            ..Default::default()
        };
        if cfg!(CONFIG_ARCH_HAS_PMEM_API) {
            attr.device_cap_flags |= DeviceCapability::FlushPersistent;
        }
        #[cfg(CONFIG_INFINIBAND_ON_DEMAND_PAGING)]
        let attr = {
            let mut attr = attr;
            use kernel::rdma::{
                OdpSupport,
                OdpTransportCapability as Odp, //
            };
            attr.kernel_cap_flags |= KernelCapability::OnDemandPaging;
            attr.odp_caps.general = OdpSupport::Supported.into();
            attr.odp_caps.ud = Odp::Send | Odp::Receive | Odp::SrqReceive;
            attr.odp_caps.rc = Odp::Send
                | Odp::Receive
                | Odp::Write
                | Odp::Read
                | Odp::Atomic
                | Odp::SrqReceive
                | Odp::Flush
                | Odp::AtomicWrite;
            attr
        };
        Self { attr, raw_gid, mtu }
    }
}

/// Native provider data retained by the RDMA callback owner until final deallocation.
#[pin_data]
pub(crate) struct DeviceData {
    // Release work callbacks before the remaining native device fields.
    pub(crate) workqueue: kernel::workqueue::OwnedQueue,
    #[pin]
    tunnels: Mutex<Option<Tunnels>>,
    attributes: DeviceAttributes,
    sys_image_guid: Atomic<u64>,
    contexts: super::rxe_context::Contexts,
    #[pin]
    domains: super::rxe_pd::Domains,
    #[pin]
    receives: super::rxe_srq::Queues,
    #[pin]
    completions: super::rxe_cq::Queues,
    #[pin]
    pub(crate) pairs: super::rxe_objects::Pairs,
    #[pin]
    pub(crate) addresses: super::rxe_ah::Addresses,
    #[pin]
    pub(crate) groups: super::rxe_mcast::Groups,
    #[pin]
    pub(crate) windows: super::rxe_mw::Windows,
    #[pin]
    pub(crate) regions: super::rxe_mr::Regions,
    #[pin]
    pub(crate) mappings: super::rxe_mmap::Mappings,
    pub(crate) counters: super::rxe_hw_counters::Counters,
    #[pin]
    pub(crate) port: Port,
}

impl DeviceData {
    pub(crate) fn new(parameters: Parameters, tunnels: Tunnels) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            workqueue: kernel::workqueue::OwnedQueue::new_unbound(
                c"rxe_wq", kernel::workqueue::OwnedQueue::MAX_ACTIVE,
            )?,
            tunnels <- kernel::new_mutex!(Some(tunnels)),
            attributes: parameters.attr,
            contexts: super::rxe_context::Contexts::new(params::RXE_MAX_UCONTEXT),
            counters: super::rxe_hw_counters::Counters::zeroed(),
            sys_image_guid: Atomic::new(parameters.attr.sys_image_guid),
            port <- Port::new(parameters.raw_gid, parameters.mtu),
            domains <- super::rxe_pd::Domains::new(params::RXE_MAX_PD),
            receives <- super::rxe_srq::Queues::new(),
            completions <- super::rxe_cq::Queues::new(),
            pairs <- super::rxe_objects::Pairs::new(),
            addresses <- super::rxe_ah::Addresses::new(params::RXE_MAX_AH),
            groups <- super::rxe_mcast::Groups::new(),
            windows <- super::rxe_mw::Windows::new(),
            regions <- super::rxe_mr::Regions::new(),
            mappings <- super::rxe_mmap::Mappings::new(),
        })
    }

    pub(crate) fn close_tunnels(&self) {
        let tunnels = self.tunnels.lock().take();
        drop(tunnels);
    }

    pub(crate) fn tunnel(&self, ipv4: bool) -> Result<kernel::net::udp_tunnel::SocketRef> {
        self.tunnels
            .lock()
            .as_ref()
            .and_then(|tunnels| tunnels.socket(ipv4))
            .ok_or(ENODEV)
    }

    fn show_parent(self: Pin<&Self>, device: &Device<Self>, output: &mut Buffer<'_>) -> Result {
        let network = device.net_device(1).ok_or(ENODEV)?;
        let name = network.name();
        output.write_bytes(name.as_bytes())?;
        output.write_bytes(b"\n")
    }
}

#[vtable]
impl DeviceOperations for DeviceData {
    const ATTRIBUTES: &'static [ReadOnlyAttribute<Self>] =
        &[ReadOnlyAttribute::new(c"parent", Self::show_parent)];

    fn modify_device(self: Pin<&Self>, change: DeviceModification) -> Result {
        if let Some(guid) = change.system_image_guid {
            self.sys_image_guid.store(guid, Relaxed);
        }
        Ok(())
    }

    fn enable(self: Pin<&Self>, device: &Device<Self>) -> Result {
        // Close the gap between netdev association and core publication. At this point
        // notifier lookups can retain the enabled device, so later removal is queued normally.
        let netdev = device.net_device(1).ok_or(ENODEV)?;
        // Keep registration and namespace membership stable through publication of the
        // initial port event. Unregister notifiers also close tunnels under this lock.
        let rtnl = kernel::net::RtnlGuard::lock();
        let location = netdev.location_locked(&rtnl)?;
        if self.tunnel(true)?.namespace().as_raw() != location.namespace().as_raw() {
            return Err(ENODEV);
        }
        self.port
            .set_mtu(mtu_from_netdev(netdev.link_info_locked(&rtnl).mtu));
        let active = device.ethernet_active(1).ok_or(ENODEV)?;
        let event = if active {
            PortEvent::Active
        } else {
            PortEvent::Error
        };
        device.dispatch_port_event(1, event)?;
        if !active {
            self.counters
                .increment(super::rxe_hw_counters::Counter::LinkDown);
        }
        Ok(())
    }

    fn query_device(
        self: Pin<&Self>,
        data: Option<UserData<'_, Self>>,
    ) -> Result<DeviceAttributes> {
        rxe_uapi::query_device(data)?;
        let mut attributes = self.attributes;
        attributes.sys_image_guid = self.sys_image_guid.load(Relaxed);
        Ok(attributes)
    }

    fn port_statistics(self: Pin<&Self>, _port: u32) -> kernel::rdma::StatisticsDescription {
        super::rxe_hw_counters::STATISTICS.description(10)
    }

    fn read_statistics(self: Pin<&Self>, port: u32, values: &mut [u64]) -> Result {
        if port == 0 {
            return Err(EINVAL);
        }
        for (value, sample) in values.iter_mut().zip(self.counters.snapshot()) {
            *value = sample as u64;
        }
        Ok(())
    }

    fn process_mad(
        self: Pin<&Self>,
        request: MadRequest<'_>,
        output: &mut MadOutput,
    ) -> MadDisposition {
        super::rxe_mad::process(
            request.input,
            &mut output.message,
            request.port,
            &self.counters.snapshot(),
        )
    }

    fn query_gid(self: Pin<&Self>, port: u32, index: i32) -> Result<[u8; 16]> {
        self.port.query_gid(port, index)
    }

    fn query_pkey(self: Pin<&Self>, port: u32, index: u16) -> Result<u16> {
        self.port.query_pkey(port, index)
    }

    fn link_layer(self: Pin<&Self>, port: u32) -> LinkLayer {
        self.port.link_layer(port)
    }

    fn query_port(self: Pin<&Self>, device: &Device<Self>, port: u32) -> Result<PortAttributes> {
        self.port.query_port(device, port)
    }

    fn modify_port(self: Pin<&Self>, port: u32, change: PortModification) -> Result {
        self.port.modify_port(port, change)
    }

    fn port_immutable(self: Pin<&Self>, device: &Device<Self>, port: u32) -> Result<PortImmutable> {
        self.port.port_immutable(device, port)
    }
}

#[vtable]
impl UserContextOperations for DeviceData {
    type Context = KBox<super::rxe_context::Context>;

    fn create_context(
        self: Pin<&Self>,
        _data: Option<UserData<'_, Self>>,
    ) -> Result<Self::Context> {
        let context = super::rxe_context::Context::new()?;
        self.contexts.acquire()?;
        Ok(context)
    }

    fn release_context(self: Pin<&Self>, _context: Self::Context) {
        self.contexts.release();
    }

    fn disassociate_context(self: Pin<&Self>, _context: &super::rxe_context::Context) {
        // RXE maps ordinary RAM retained by each VMA, with no device mappings to revoke.
    }

    fn mmap(
        self: Pin<&Self>,
        context: &super::rxe_context::Context,
        vma: &kernel::mm::virt::VmaNew,
    ) -> Result {
        self.mappings.map(context, vma)
    }
}

impl ProtectionDomainOperations for DeviceData {
    type Domain = KBox<super::rxe_pd::Domain>;

    fn create_domain(
        self: Pin<&Self>,
        _flags: ProtectionDomainFlags,
        _data: Option<UserData<'_, Self>>,
    ) -> Result<Self::Domain> {
        self.domains.allocate()
    }

    fn release_domain(self: Pin<&Self>, owner: Self::Domain, _data: Option<UserData<'_, Self>>) {
        self.domains.release(owner);
    }
}

#[vtable]
impl AddressHandleOperations for DeviceData {
    type AddressHandle = KBox<super::rxe_ah::Handle>;
    const USER_ADDRESS_HANDLES: bool = true;

    fn create_address(
        self: Pin<&Self>,
        domain: &super::rxe_pd::Domain,
        request: AddressRequest,
        flags: AddressCreateFlags,
        _transmit_slave: Option<&kernel::net::Device>,
        data: Option<UserData<'_, Self>>,
    ) -> Result<Self::AddressHandle> {
        let vector = super::rxe_av::AddressVector::from_request(request)?;
        let allocation = if flags.contains(AddressCreateFlag::Sleepable) {
            GFP_KERNEL
        } else {
            GFP_ATOMIC
        };
        self.addresses
            .create(domain.index(), vector, allocation, data)
    }

    fn modify_address(
        self: Pin<&Self>,
        handle: &super::rxe_ah::Handle,
        request: AddressRequest,
    ) -> Result {
        let vector = super::rxe_av::AddressVector::from_request(request)?;
        self.addresses.modify(handle, vector);
        Ok(())
    }

    fn query_address(
        self: Pin<&Self>,
        handle: &super::rxe_ah::Handle,
    ) -> Result<AddressAttributes> {
        Ok(self.addresses.query(handle).attributes())
    }

    fn release_address(self: Pin<&Self>, owner: Self::AddressHandle, _flags: AddressReleaseFlags) {
        self.addresses.release(owner);
    }
}

impl CompletionQueueOperations for DeviceData {
    type CompletionQueue = Pin<KBox<super::rxe_cq::Queue>>;

    fn create_completion_queue(
        self: Pin<&Self>,
        attributes: CompletionAttributes,
        data: Option<ContextData<'_, Self>>,
    ) -> Result<CompletionCreation<Self::CompletionQueue>> {
        self.completions.create(&self.mappings, attributes, data)
    }

    fn resize_completion_queue(
        self: Pin<&Self>,
        queue: Pin<&super::rxe_cq::Queue>,
        entries: u32,
        data: Option<ContextData<'_, Self>>,
    ) -> Result<CompletionCapacity> {
        queue.resize(&self.mappings, entries, data)
    }

    fn poll_completion_queue(
        self: Pin<&Self>,
        queue: Pin<&super::rxe_cq::Queue>,
        output: &mut CompletionOutput<'_>,
    ) -> Result {
        queue.poll(output)
    }

    fn peek_completion_queue(
        self: Pin<&Self>,
        queue: Pin<&super::rxe_cq::Queue>,
        maximum: u32,
    ) -> u32 {
        queue.peek(maximum)
    }

    fn arm_completion_queue(
        self: Pin<&Self>,
        queue: Pin<&super::rxe_cq::Queue>,
        flags: CompletionNotify,
    ) -> Result<bool> {
        Ok(queue.arm(flags))
    }

    fn release_completion_queue(
        self: Pin<&Self>,
        owner: Self::CompletionQueue,
        _data: Option<UserData<'_, Self>>,
    ) {
        self.completions.release(&self.mappings, owner);
    }
}

impl BasicSharedReceiveOperations for DeviceData {
    type SharedReceive = Pin<KBox<super::rxe_srq::SharedReceive>>;

    fn create_shared_receive(
        self: Pin<&Self>,
        _domain: &super::rxe_pd::Domain,
        attributes: &mut SharedReceiveAttributes,
        data: Option<ContextData<'_, Self>>,
    ) -> Result<Self::SharedReceive> {
        self.receives.create(&self.mappings, attributes, data)
    }

    fn modify_shared_receive(
        self: Pin<&Self>,
        queue: Pin<&super::rxe_srq::SharedReceive>,
        change: &mut SharedReceiveChange,
        data: Option<ContextData<'_, Self>>,
    ) -> Result {
        queue.modify(&self.mappings, change, data)
    }

    fn query_shared_receive(
        self: Pin<&Self>,
        queue: Pin<&super::rxe_srq::SharedReceive>,
    ) -> Result<SharedReceiveAttributes> {
        Ok(queue.query())
    }

    fn post_shared_receive(
        self: Pin<&Self>,
        queue: Pin<&super::rxe_srq::SharedReceive>,
        requests: ReceiveRequests<'_>,
    ) -> Result {
        queue.post(requests)
    }

    fn release_shared_receive(
        self: Pin<&Self>,
        owner: Self::SharedReceive,
        _data: Option<UserData<'_, Self>>,
    ) -> Result<(), ReleaseError<Self::SharedReceive>> {
        self.receives.release(&self.mappings, owner);
        Ok(())
    }
}

impl MemoryWindowOperations for DeviceData {
    type MemoryWindow = KBox<super::rxe_mw::Handle>;

    fn create_window(
        self: Pin<&Self>,
        domain: &super::rxe_pd::Domain,
        kind: MemoryWindowType,
        _data: Option<UserData<'_, Self>>,
    ) -> Result<WindowCreation<Self::MemoryWindow>> {
        self.windows.create(domain.index(), kind)
    }

    fn release_window(
        self: Pin<&Self>,
        owner: Self::MemoryWindow,
    ) -> Result<(), ReleaseError<Self::MemoryWindow>> {
        self.windows.release(owner);
        Ok(())
    }
}

/// InfiniBand payload size supported by the underlying network MTU.
pub(crate) fn mtu_from_netdev(mtu: u32) -> Mtu {
    match mtu.saturating_sub(params::RXE_MAX_HDR_LENGTH) {
        0..512 => Mtu::Mtu256,
        512..1024 => Mtu::Mtu512,
        1024..2048 => Mtu::Mtu1024,
        2048..4096 => Mtu::Mtu2048,
        _ => Mtu::Mtu4096,
    }
}

/// Validates the requested link and supplies its device settings.
pub(crate) fn newlink(request: LinkRequest<'_>) -> Result {
    if request.is_vlan() {
        pr_err!("rxe creation allowed on top of a real device only\n");
        return Err(EPERM);
    }
    if request.is_configured() {
        pr_err!("RXE is already configured on this network device\n");
        return Err(EEXIST);
    }
    let parameters = Parameters::new(request.address(), request.mtu());
    request.register(parameters)
}

impl QueuePairOperations for DeviceData {
    type QueuePair = KBox<super::rxe_objects::Owner>;
    type QueuePairPublication = super::rxe_objects::Publication;

    fn create_queue_pair(
        self: Pin<&Self>,
        parents: QueuePairParents<'_, Self>,
        attributes: QueuePairInitAttributes,
        data: Option<ContextData<'_, Self>>,
    ) -> Result<QueuePairCreation<Self::QueuePair, Self::QueuePairPublication>> {
        self.pairs.create(self, parents, attributes, data)
    }

    fn publish_queue_pair(
        self: Pin<&Self>,
        qp: QueuePairRef<Self>,
        publication: Self::QueuePairPublication,
    ) {
        self.pairs.publish(qp, publication);
    }

    fn modify_queue_pair(
        self: Pin<&Self>,
        qp: &QueuePair<Self>,
        change: QueuePairChange,
        _data: Option<UserData<'_, Self>>,
    ) -> Result {
        super::rxe_qp::modify(qp, change)
    }

    fn query_queue_pair(
        self: Pin<&Self>,
        qp: &QueuePair<Self>,
        _mask: u32,
    ) -> Result<QueuePairQuery> {
        super::rxe_qp::query(qp)
    }

    fn post_send(
        self: Pin<&Self>,
        qp: &QueuePair<Self>,
        requests: SendRequests<'_, Self>,
    ) -> Result {
        super::rxe_post::send(qp, requests)
    }

    fn post_receive(
        self: Pin<&Self>,
        qp: &QueuePair<Self>,
        requests: ReceiveRequests<'_>,
    ) -> Result {
        super::rxe_post::receive(qp, requests)
    }

    fn ring_send_queue(self: Pin<&Self>, qp: &QueuePair<Self>) -> Result {
        super::rxe_post::ring(qp)
    }

    fn retire_queue_pair(
        self: Pin<&Self>,
        qp: &QueuePair<Self>,
        _data: Option<UserData<'_, Self>>,
    ) {
        super::rxe_qp::retire(qp)
    }

    fn release_queue_pair(self: Pin<&Self>, owner: Self::QueuePair) {
        self.pairs.release(&self.mappings, owner);
    }
}

impl MulticastOperations for DeviceData {
    fn attach_multicast(
        self: Pin<&Self>,
        qp: &QueuePair<Self>,
        gid: [u8; 16],
        _lid: u16,
    ) -> Result {
        super::rxe_mcast_control::attach(qp, gid)
    }

    fn detach_multicast(
        self: Pin<&Self>,
        qp: &QueuePair<Self>,
        gid: [u8; 16],
        _lid: u16,
    ) -> Result {
        super::rxe_mcast_control::detach(qp, gid)
    }
}

/// Owns registration, which drains devices before releasing their dependencies.
pub(crate) struct RxeModule {
    _registration: Registration,
}

impl kernel::Module for RxeModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let registration = Registration::new()?;
        pr_info!("loaded\n");
        Ok(Self {
            _registration: registration,
        })
    }
}
