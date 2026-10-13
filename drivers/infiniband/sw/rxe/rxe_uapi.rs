// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Userspace command validation and native RXE response encoding.

#![forbid(unsafe_code)]

use super::{
    rxe_ring::{
        CONSUMER_OFFSET,
        HEADER_SIZE,
        PRODUCER_OFFSET, //
    },
    rxe_wqe::{
        RECV_HEADER_SIZE,
        SEND_DMA_OFFSET,
        SEND_HEADER_SIZE,
        SEND_WR_SIZE,
        SGE_SIZE, //
    }, //
};
use kernel::{
    bindings,
    prelude::*,
    uaccess::{
        UserPtr,
        UserSlice,
        UserSliceWriter, //
    }, //
};

pub(crate) type UserData<'a> = kernel::rdma::UserData<'a, super::rxe_device::DeviceData>;

pub(crate) const MAPPING_SIZE: usize = 16;
pub(crate) const QP_RESPONSE_SIZE: usize = 2 * MAPPING_SIZE;
pub(crate) const SRQ_RESPONSE_SIZE: usize = MAPPING_SIZE + 8;

const _: () = assert!(size_of::<bindings::mminfo>() == super::rxe_uapi::MAPPING_SIZE);
const _: () = assert!(core::mem::offset_of!(bindings::mminfo, size) == 8);
const _: () = assert!(core::mem::offset_of!(bindings::mminfo, pad) == 12);
const _: () = assert!(size_of::<bindings::rxe_queue_buf>() == HEADER_SIZE);
const _: () =
    assert!(core::mem::offset_of!(bindings::rxe_queue_buf, producer_index) == PRODUCER_OFFSET);
const _: () =
    assert!(core::mem::offset_of!(bindings::rxe_queue_buf, consumer_index) == CONSUMER_OFFSET);
const _: () = assert!(size_of::<bindings::rxe_send_wqe>() == SEND_HEADER_SIZE);
const _: () = assert!(size_of::<bindings::rxe_recv_wqe>() == RECV_HEADER_SIZE);
const _: () = assert!(size_of::<bindings::ib_sge>() == SGE_SIZE);
const _: () = assert!(size_of::<bindings::rxe_send_wr>() == SEND_WR_SIZE);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_send_wqe, dma) == SEND_DMA_OFFSET);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_send_wr, wr) == 24);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_send_wr, opcode) == 12);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_send_wr, send_flags) == 16);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_send_wr, ex) == 20);
const _: () = assert!(size_of::<bindings::rxe_av>() == 88);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_av, grh) == 8);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_av, sgid_addr) == 32);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_av, dgid_addr) == 60);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_dma_info, length) == 0);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_dma_info, resid) == 4);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_dma_info, cur_sge) == 8);
const _: () = assert!(core::mem::offset_of!(bindings::rxe_dma_info, num_sge) == 12);
const _: () = assert!(size_of::<bindings::rxe_dma_info>() == super::rxe_mr_data::DMA_HEADER_SIZE);

/// The queue mapping descriptor, encoded without exposing Rust padding bytes.
#[derive(Default)]
pub(crate) struct MappingDescriptor {
    pub(crate) offset: u64,
    pub(crate) size: u32,
}

impl MappingDescriptor {
    pub(crate) fn write(&self, output: &mut UserSliceWriter) -> Result {
        let mut bytes = [0; MAPPING_SIZE];
        bytes[..8].copy_from_slice(&self.offset.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.size.to_ne_bytes());
        output.write_slice(&bytes)
    }
}

/// Separates the first mapping descriptor from subsequent response fields.
pub(crate) fn split_mapping(
    output: Option<UserSliceWriter>,
) -> Result<(Option<UserSliceWriter>, Option<UserSliceWriter>)> {
    match output {
        Some(output) => {
            let (first, rest) = output.split_at(MAPPING_SIZE)?;
            Ok((Some(first), Some(rest)))
        }
        None => Ok((None, None)),
    }
}

/// Writes the SRQ number without modifying the response's reserved word.
pub(crate) fn write_srq_number(output: Option<UserSliceWriter>, number: u32) -> Result {
    if let Some(mut output) = output {
        output.write_slice(&number.to_ne_bytes())?;
    }
    Ok(())
}

/// Uses the SRQ command's mapping address; zero requests no mapping descriptor.
pub(crate) fn srq_mapping(address: u64) -> Option<UserSliceWriter> {
    (address != 0)
        .then(|| UserSlice::new(UserPtr::from_addr(address as usize), MAPPING_SIZE).writer())
}

/// Rejects nonzero device-query extensions and clears the provider response.
pub(crate) fn query_device(data: Option<UserData<'_>>) -> Result {
    if let Some(data) = data {
        let (input, output) = data.split();
        if !input.is_empty() {
            input.read(&mut [], 0)?;
        }
        output.clear()?;
    }
    Ok(())
}

/// Decodes the userspace mapping address in `rxe_modify_srq_cmd`.
pub(crate) fn modify_srq(data: Option<UserData<'_>>) -> Result<u64> {
    let mut command = [0; 8];
    if let Some(data) = data {
        let (input, _) = data.split();
        input.read(&mut command, 8)?;
    }
    Ok(u64::from_ne_bytes(command))
}

/// Returns the AH number, selecting the legacy address-vector ABI for short responses.
pub(crate) fn create_ah(data: Option<UserData<'_>>, number: u32) -> Result<u32> {
    if let Some(data) = data {
        if !data.has_output_buffer() {
            return Ok(0);
        }
        let (_, mut output) = data.split();
        // The response has a u32 AH number and a reserved u32. Existing providers require
        // space for both fields, but RXE writes only the number and leaves the tail untouched.
        if output.len() < 8 {
            return Ok(0);
        }
        output.write_slice(&number.to_ne_bytes())?;
    }
    Ok(number)
}
