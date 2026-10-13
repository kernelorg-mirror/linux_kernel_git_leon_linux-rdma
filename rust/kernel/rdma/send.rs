// SPDX-License-Identifier: GPL-2.0

//! Borrowed kernel send requests, selected extensions and bounded inline copies.

use super::{
    AccessFlags,
    AddressHandleOperations,
    AddressHandles,
    MemoryRegion,
    MemoryRegionOperations,
    MemoryRegions,
    QueuePairType,
    ScatterGather, //
};
use crate::{
    bindings,
    prelude::*,
    types::ForeignOwnable, //
};
use bindings::{
    ib_wr_opcode_IB_WR_ATOMIC_CMP_AND_SWP as CAS,
    ib_wr_opcode_IB_WR_ATOMIC_FETCH_AND_ADD as FAA,
    ib_wr_opcode_IB_WR_LOCAL_INV as LOCAL_INV,
    ib_wr_opcode_IB_WR_RDMA_READ as READ,
    ib_wr_opcode_IB_WR_RDMA_READ_WITH_INV as READ_INV,
    ib_wr_opcode_IB_WR_RDMA_WRITE as WRITE,
    ib_wr_opcode_IB_WR_RDMA_WRITE_WITH_IMM as WRITE_IMM,
    ib_wr_opcode_IB_WR_REG_MR as REG_MR,
    ib_wr_opcode_IB_WR_SEND as SEND,
    ib_wr_opcode_IB_WR_SEND_WITH_IMM as SEND_IMM,
    ib_wr_opcode_IB_WR_SEND_WITH_INV as SEND_INV, //
};
use core::marker::PhantomData;

/// Copied remote address and access key for an RDMA request.
pub struct RemoteSend {
    /// Address in the peer's registered address space.
    pub address: u64,
    /// Remote registration key.
    pub key: u32,
}

/// Copied operands for a compare-and-swap or fetch-and-add request.
pub struct AtomicSend {
    /// Address in the peer's registered address space.
    pub address: u64,
    /// Remote registration key.
    pub key: u32,
    /// Comparison value or amount to add.
    pub compare_add: u64,
    /// Replacement value, zero for fetch-and-add without reading its unused field.
    pub swap: u64,
}

/// Datagram metadata with an address handle borrowed from the posting caller.
pub struct DatagramSend<'a, T: AddressHandleOperations> {
    /// Native address-handle data retained during this borrow.
    pub address: <T::AddressHandle as ForeignOwnable>::Borrowed<'a>,
    /// Destination queue-pair number.
    pub destination: u32,
    /// Destination queue key.
    pub key: u32,
    /// Partition-key index for general services, zero for ordinary datagrams.
    pub pkey: u16,
}

/// Registration metadata copied while the posting caller retains the core MR.
pub struct RegisterSend<'a, T> {
    /// Borrowed native region; asynchronous work must retain its own provider reference.
    pub region: &'a MemoryRegion<T>,
    /// Requested registration key.
    pub key: u32,
    /// Requested access rights.
    pub access: AccessFlags,
    /// First I/O virtual address.
    pub address: u64,
    /// Number of bytes in the translation.
    pub length: u64,
}

/// One send request retained by a kernel posting call.
///
/// # Invariants
///
/// One identifier union member, opcode, flags, count and link are initialized and unchanged for
/// `'a`. Positive counts retain a stable descriptor array satisfying `ScatterGather::from_raw`.
/// Only fields selected by the opcode and actual QP transport need initialization. Selected
/// address handles and memory regions belong to `T` and remain initialized with release
/// excluded. Selected registration attributes remain unchanged. Nonempty inline sources are
/// readable CPU memory for their declared lengths and remain unchanged throughout `'a`.
pub struct SendRequest<'a, T> {
    raw: *const bindings::ib_send_wr,
    kind: QueuePairType,
    _borrow: PhantomData<&'a T>,
}

impl<T> SendRequest<'_, T> {
    /// Returns the queue-pair transport which determines extension layout.
    #[inline]
    pub fn kind(&self) -> QueuePairType {
        self.kind
    }

    /// Returns the opaque identifier to reproduce in a completion.
    #[inline]
    pub fn id(&self) -> u64 {
        // SAFETY: The caller initialized either identifier member. The native boundary
        // materializes unused bytes when a pointer is narrower than the opaque identifier.
        unsafe { bindings::ib_send_wr_id(self.raw) }
    }

    /// Returns the opcode before provider-specific validation.
    #[inline]
    pub fn opcode(&self) -> u32 {
        // SAFETY: The initialized opcode remains stable throughout the borrow.
        unsafe { (*self.raw).opcode }
    }

    /// Returns the posting flags before provider-specific validation.
    #[inline]
    pub fn flags(&self) -> u32 {
        // SAFETY: The initialized flags remain stable throughout the borrow.
        unsafe { (*self.raw).send_flags as u32 }
    }

    /// Copies the selected immediate or invalidation value in its original byte order.
    #[inline]
    pub fn immediate(&self) -> [u8; 4] {
        // SAFETY: The opcode selects the initialized union member. Other requests leave
        // the union unread, including when its storage is uninitialized.
        unsafe {
            match self.opcode() {
                SEND_IMM | WRITE_IMM => (*self.raw).ex.imm_data.to_ne_bytes(),
                SEND_INV | LOCAL_INV | READ_INV => (*self.raw).ex.invalidate_rkey.to_ne_bytes(),
                _ => [0; 4],
            }
        }
    }

    /// Returns the descriptor count before provider capacity validation.
    #[inline]
    pub fn scatter_gather_count(&self) -> c_int {
        // SAFETY: The initialized count remains stable throughout the borrow.
        unsafe { (*self.raw).num_sge }
    }

    /// Borrows descriptors without granting access to their described memory.
    #[inline]
    pub fn scatter_gather(&self) -> Result<&[ScatterGather]> {
        match self.scatter_gather_count() {
            count if count < 0 => Err(EINVAL),
            0 => Ok(&[]),
            // SAFETY: Positive counts retain an initialized descriptor pointer and array.
            count => unsafe { ScatterGather::from_raw((*self.raw).sg_list, count) },
        }
    }

    /// Copies an RDMA extension only for a matching connected request.
    #[inline]
    pub fn remote(&self) -> Option<RemoteSend> {
        if !self.kind.is_connected()
            || !matches!(self.opcode(), WRITE | WRITE_IMM | READ | READ_INV)
        {
            return None;
        }
        let raw = self.raw.cast::<bindings::ib_rdma_wr>();
        // SAFETY: Transport and opcode select this extension and its initialized fields.
        Some(unsafe {
            RemoteSend {
                address: (*raw).remote_addr,
                key: (*raw).rkey,
            }
        })
    }

    /// Copies only operands selected by a connected atomic request.
    #[inline]
    pub fn atomic(&self) -> Option<AtomicSend> {
        if !self.kind.is_connected() || !matches!(self.opcode(), CAS | FAA) {
            return None;
        }
        let raw = self.raw.cast::<bindings::ib_atomic_wr>();
        // SAFETY: The selected extension and operands are initialized. Fetch-and-add does
        // not initialize or use swap; masked-operation fields are never read here.
        Some(unsafe {
            AtomicSend {
                address: (*raw).remote_addr,
                key: (*raw).rkey,
                compare_add: (*raw).compare_add,
                swap: if self.opcode() == CAS { (*raw).swap } else { 0 },
            }
        })
    }

    /// Copies a subrange of one declared inline source into initialized destination storage.
    ///
    /// An arbitrary address cannot confer read permission: the request must select inline
    /// data, and the entire nonempty range must lie within one retained source descriptor.
    /// The destination must not overlap that source range; overlap returns `EINVAL`.
    pub fn read_inline(&self, address: u64, output: &mut [u8]) -> Result {
        if self.flags() & bindings::ib_send_flags_IB_SEND_INLINE as u32 == 0 {
            return Err(EINVAL);
        }
        if output.is_empty() {
            return Ok(());
        }
        let end = address.checked_add(output.len() as u64).ok_or(EFAULT)?;
        if !self.scatter_gather()?.iter().any(|entry| {
            address >= entry.address()
                && entry
                    .address()
                    .checked_add(u64::from(entry.length()))
                    .is_some_and(|limit| end <= limit)
        }) {
            return Err(EFAULT);
        }
        let address = usize::try_from(address).map_err(|_| EFAULT)?;
        let end = address.checked_add(output.len()).ok_or(EFAULT)?;
        let destination = output.as_ptr() as usize;
        let destination_end = destination.checked_add(output.len()).ok_or(EFAULT)?;
        if address < destination_end && destination < end {
            return Err(EINVAL);
        }
        // SAFETY: The request's invariant retains this readable, unchanged inline range.
        // The destination borrow is writable, and the checked ranges do not overlap.
        unsafe {
            bindings::memcpy(
                output.as_mut_ptr().cast(),
                address as *const c_void,
                output.len(),
            )
        };
        Ok(())
    }
}

impl<T: AddressHandleOperations> SendRequest<'_, T> {
    /// Borrows datagram address data only for a matching UD or GSI send.
    #[inline]
    pub fn datagram(&self) -> Option<DatagramSend<'_, T>> {
        if self.kind.is_connected() || !matches!(self.opcode(), SEND | SEND_IMM) {
            return None;
        }
        let raw = self.raw.cast::<bindings::ib_ud_wr>();
        // SAFETY: Transport and opcode select the initialized UD extension. The caller
        // retains the address handle belonging to T. Ordinary UD does not read pkey_index.
        Some(unsafe {
            DatagramSend {
                address: AddressHandles::<T>::data((*raw).ah),
                destination: (*raw).remote_qpn,
                key: (*raw).remote_qkey,
                pkey: if self.kind == QueuePairType::GeneralService {
                    (*raw).pkey_index
                } else {
                    0
                },
            }
        })
    }
}

impl<T: MemoryRegionOperations> SendRequest<'_, T> {
    /// Borrows a registration target and copies its selected attributes.
    #[inline]
    pub fn registration(&self) -> Option<RegisterSend<'_, T>> {
        if !self.kind.is_connected() || self.opcode() != REG_MR {
            return None;
        }
        let raw = self.raw.cast::<bindings::ib_reg_wr>();
        // SAFETY: REG_MR selects this initialized extension. The caller retains the region
        // belonging to T, excludes its deregistration and keeps its translation stable.
        Some(unsafe {
            let region = (*raw).mr;
            RegisterSend {
                region: MemoryRegions::<T>::borrow(region),
                key: (*raw).key,
                access: AccessFlags::from_bits((*raw).access as u32),
                address: (*region).iova,
                length: (*region).length,
            }
        })
    }
}

/// A stable kernel send chain and exclusive first-failure output.
///
/// # Invariants
///
/// Each node in the acyclic chain satisfies `SendRequest`'s invariant for `'a`. The transport
/// matches the originating QP. `bad` is writable and does not alias requests, descriptors or
/// inline sources; no other writer accesses it during the cursor's lifetime.
pub struct SendRequests<'a, T> {
    next: *const bindings::ib_send_wr,
    bad: *mut *const bindings::ib_send_wr,
    kind: QueuePairType,
    _borrow: PhantomData<&'a mut T>,
}

impl<'a, T> SendRequests<'a, T> {
    /// Borrows a kernel send chain, including an empty chain.
    ///
    /// # Safety
    ///
    /// The inputs must satisfy the type invariant for `'a`. Each caller initializes either
    /// `wr_id` or `wr_cqe`; unused union bytes need not be initialized. Selected AHs and MRs
    /// must belong to T's installed adapters. The kernel caller separately retains
    /// non-inline DMA mappings and registrations for asynchronously posted work.
    #[inline]
    pub unsafe fn from_raw(
        first: *const bindings::ib_send_wr,
        bad: *mut *const bindings::ib_send_wr,
        kind: QueuePairType,
    ) -> Self {
        // SAFETY: The caller grants writable, nonaliasing output. A provider may reject
        // the entire chain before visiting it, so establish that failure result now.
        unsafe { bad.write(first) };
        // INVARIANT: The caller retains the chain and its selected resources, supplies its
        // actual transport and grants exclusive access to the failure output.
        Self {
            next: first,
            bad,
            kind,
            _borrow: PhantomData,
        }
    }

    /// Visits requests in order, preserving the successful prefix on failure.
    ///
    /// Failure records the first rejected request. The output is unspecified on success.
    pub fn try_for_each(mut self, mut post: impl FnMut(SendRequest<'_, T>) -> Result) -> Result {
        while !self.next.is_null() {
            // INVARIANT: The cursor retains this node, selected extensions and resources.
            if let Err(error) = post(SendRequest {
                raw: self.next,
                kind: self.kind,
                _borrow: PhantomData,
            }) {
                // SAFETY: The caller grants writable, nonaliasing failure output.
                unsafe { self.bad.write(self.next) };
                return Err(error);
            }
            // SAFETY: The cursor retains the initialized, unchanged next link.
            self.next = unsafe { (*self.next).next };
        }
        Ok(())
    }

    /// Rejects posting before visiting requests and records the first request, possibly null.
    #[inline]
    pub fn reject(self, error: Error) -> Result {
        // SAFETY: The cursor owns writable, nonaliasing failure output even for an empty chain.
        unsafe { self.bad.write(self.next) };
        Err(error)
    }
}

#[cfg(CONFIG_RUST_KUNIT_TESTS)]
#[crate::macros::kunit_tests(rust_rdma_send_requests)]
mod tests {
    use super::*;
    use core::{
        mem::MaybeUninit,
        ptr, //
    };

    #[test]
    fn callback_identifier_preserves_pointer_bytes() -> Result {
        let mut storage = MaybeUninit::<bindings::ib_send_wr>::uninit();
        let raw = storage.as_mut_ptr();
        let callback = ptr::dangling_mut::<bindings::ib_cqe>();
        let mut bad = ptr::null();
        // SAFETY: Initialize only selected common fields. On 32-bit targets, wr_cqe
        // leaves part of its identifier union uninitialized, as permitted by C callers.
        unsafe {
            (&raw mut (*raw).next).write(ptr::null_mut());
            (&raw mut (*raw).__bindgen_anon_1.wr_cqe).write(callback);
            (&raw mut (*raw).num_sge).write(0);
            (&raw mut (*raw).opcode).write(SEND);
            (&raw mut (*raw).send_flags).write(0);
        }
        // SAFETY: The initialized common fields are stable; no descriptor, immediate or
        // transport extension is selected. The opaque callback pointer is never dereferenced.
        let requests = unsafe {
            SendRequests::<()>::from_raw(raw, &mut bad, QueuePairType::ReliableConnected)
        };
        requests.try_for_each(|request| {
            assert_eq!(
                &request.id().to_ne_bytes()[..size_of::<usize>()],
                &(callback as usize).to_ne_bytes()
            );
            Ok(())
        })
    }

    #[test]
    fn fetch_add_leaves_unselected_storage_unread() -> Result {
        let mut storage = MaybeUninit::<bindings::ib_atomic_wr>::uninit();
        let raw = storage.as_mut_ptr();
        let mut bad = ptr::null();
        // SAFETY: These field projections initialize exactly the base and atomic fields
        // selected by fetch-and-add with zero descriptors. No complete C reference is formed.
        unsafe {
            (&raw mut (*raw).wr.next).write(ptr::null_mut());
            (&raw mut (*raw).wr.__bindgen_anon_1.wr_id).write(17);
            (&raw mut (*raw).wr.num_sge).write(0);
            (&raw mut (*raw).wr.opcode).write(FAA);
            (&raw mut (*raw).wr.send_flags).write(0);
            (&raw mut (*raw).remote_addr).write(0x1000);
            (&raw mut (*raw).rkey).write(3);
            (&raw mut (*raw).compare_add).write(7);
        }
        // SAFETY: The selected fields are initialized and retained. The unselected SG
        // pointer, immediate union, swap and masked operands remain uninitialized.
        let requests = unsafe {
            SendRequests::<()>::from_raw(raw.cast(), &mut bad, QueuePairType::ReliableConnected)
        };
        requests.try_for_each(|request| {
            assert_eq!(request.id(), 17);
            assert!(request.scatter_gather()?.is_empty());
            assert_eq!(request.immediate(), [0; 4]);
            let atomic = request.atomic().unwrap();
            assert_eq!(
                (atomic.address, atomic.key, atomic.compare_add, atomic.swap),
                (0x1000, 3, 7, 0)
            );
            assert!(request.remote().is_none());
            Ok(())
        })?;
        assert_eq!(bad, raw.cast());
        Ok(())
    }

    #[test]
    fn early_rejection_initializes_failure_output() -> Result {
        let request = bindings::ib_send_wr {
            opcode: SEND,
            ..Default::default()
        };
        let mut bad = MaybeUninit::uninit();
        // SAFETY: The initialized request remains live and has no descriptors or selected
        // extension. The failure output is writable but deliberately uninitialized.
        let requests = unsafe {
            SendRequests::<()>::from_raw(
                &request,
                bad.as_mut_ptr(),
                QueuePairType::ReliableConnected,
            )
        };
        let reject = |_requests: SendRequests<'_, ()>| Err::<(), _>(EINVAL);
        assert_eq!(reject(requests), Err(EINVAL));
        // SAFETY: Construction initializes the failure output even without cursor traversal.
        assert_eq!(unsafe { bad.assume_init() }, &raw const request);
        Ok(())
    }

    #[test]
    fn inline_bounds_and_partial_chain_failure() -> Result {
        let mut input = [1u8, 2, 3, 4];
        let mut descriptor = bindings::ib_sge {
            addr: input.as_ptr() as u64,
            length: 4,
            lkey: 0,
        };
        let mut second = bindings::ib_send_wr {
            opcode: SEND,
            ..Default::default()
        };
        let first = bindings::ib_send_wr {
            next: &mut second,
            opcode: SEND,
            send_flags: bindings::ib_send_flags_IB_SEND_INLINE as c_int,
            num_sge: 1,
            sg_list: &mut descriptor,
            ..Default::default()
        };
        let mut bad = ptr::null();
        let mut visited = 0;
        // SAFETY: Both initialized nodes and descriptors remain stable; the first request
        // retains readable inline input. The second has no descriptors or selected extension.
        let requests = unsafe {
            SendRequests::<()>::from_raw(&first, &mut bad, QueuePairType::ReliableConnected)
        };
        let result = requests.try_for_each(|request| {
            visited += 1;
            if visited == 2 {
                return Err(ENOMEM);
            }
            let mut output = [0; 2];
            request.read_inline(descriptor.addr + 1, &mut output)?;
            assert_eq!(output, [2, 3]);
            assert_eq!(
                request.read_inline(descriptor.addr + 3, &mut output),
                Err(EFAULT)
            );
            assert_eq!(request.read_inline(1, &mut output), Err(EFAULT));
            assert_eq!(
                request.read_inline(descriptor.addr, &mut input),
                Err(EINVAL)
            );
            assert_eq!(input, [1, 2, 3, 4]);
            Ok(())
        });
        assert_eq!(result, Err(ENOMEM));
        assert_eq!(bad, &raw const second);
        assert_eq!(visited, 2);
        Ok(())
    }
}
