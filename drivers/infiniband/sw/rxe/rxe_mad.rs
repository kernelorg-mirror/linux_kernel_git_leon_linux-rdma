// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2026 zhenwei pi <zhenwei.pi@linux.dev>

//! RXE performance management datagrams.

#![forbid(unsafe_code)]

use crate::{
    rxe_hw_counters::Snapshot,
    rxe_param as params, //
};
use kernel::rdma::{
    Mad,
    MadDisposition, //
};

const CLASS_PORT_INFO: u16 = 0x0001;
const PORT_COUNTERS: u16 = 0x0012;
const PORT_COUNTERS_EXT: u16 = 0x001d;
const EXT_WIDTH: u16 = 1 << 9;
const PERFORMANCE_MANAGEMENT: u8 = 4;
const GET: u8 = 1;
const GET_RESPONSE: u8 = 0x81;
const TRAP: u8 = 5;
const TRAP_REPRESS: u8 = 7;
const UNSUPPORTED_VERSION: u16 = 0x0004;
const UNSUPPORTED_METHOD: u16 = 0x0008;
const UNSUPPORTED_ATTRIBUTE: u16 = 0x000c;
const INVALID_FIELD: u16 = 0x001c;
const CLASS_CAPABILITIES_OFFSET: usize = 2;
const LINK_DOWNED_OFFSET: usize = 7;

/// Formats a performance MAD from sampled counters into disjoint output storage.
///
/// The 40-byte performance-management header precedes the attribute data. Write
/// individual fields as bytes so packed wire structures need no pointer casts.
pub(crate) fn process(
    input: &Mad,
    output: &mut Mad,
    port: u32,
    counters: &Snapshot,
) -> MadDisposition {
    if port != 1 {
        return MadDisposition::Failure;
    }

    *output = Mad::default();
    if input.header.class != PERFORMANCE_MANAGEMENT {
        output.header.status = UNSUPPORTED_METHOD;
        return MadDisposition::Success;
    }
    // Responses and traps belong to MAD agents, not a second response from the provider.
    if input.header.method & 0x80 != 0 || matches!(input.header.method, TRAP | TRAP_REPRESS) {
        return MadDisposition::Success;
    }
    output.header = input.header;
    output.header.method = GET_RESPONSE;
    output.header.status = 0;
    if input.header.class_version != 1 {
        output.header.status = UNSUPPORTED_VERSION;
        return MadDisposition::Reply;
    }
    if input.header.method != GET {
        output.header.status = UNSUPPORTED_METHOD;
        return MadDisposition::Reply;
    }

    if input.header.attribute_modifier != 0
        || (matches!(input.header.attribute_id, PORT_COUNTERS | PORT_COUNTERS_EXT)
            && input.data[41] != 1)
    {
        output.header.status = INVALID_FIELD;
        return MadDisposition::Reply;
    }

    let data = &mut output.data[40..];
    match input.header.attribute_id {
        CLASS_PORT_INFO => {
            data[0] = 1;
            data[1] = 1;
            let offset = CLASS_CAPABILITIES_OFFSET;
            data[offset..offset + 2].copy_from_slice(&EXT_WIDTH.to_be_bytes());
        }
        PORT_COUNTERS => {
            data[1] = input.data[41];
            // IBA 1.8 section 16.1.3.5 requires saturation, including negatives.
            data[LINK_DOWNED_OFFSET] =
                counters[params::RXE_CNT_LINK_DOWNED as usize].clamp(0, i64::from(u8::MAX)) as u8;
        }
        PORT_COUNTERS_EXT => {
            data[1] = input.data[41];
            let fields = [
                (8, counters[params::RXE_CNT_SENT_BYTES as usize] >> 2),
                (16, counters[params::RXE_CNT_RCVD_BYTES as usize] >> 2),
                (24, counters[params::RXE_CNT_SENT_PKTS as usize]),
                (32, counters[params::RXE_CNT_RCVD_PKTS as usize]),
            ];
            for (offset, value) in fields {
                data[offset..offset + 8].copy_from_slice(&(value as u64).to_be_bytes());
            }
        }
        _ => {
            output.header.status = UNSUPPORTED_ATTRIBUTE;
            return MadDisposition::Reply;
        }
    }
    MadDisposition::Reply
}

#[cfg(CONFIG_RDMA_RXE_KUNIT_TEST)]
#[kernel::macros::kunit_tests(rxe_mad)]
mod tests {
    use super::*;

    fn request(attribute: u16) -> Mad {
        let mut mad = Mad::default();
        mad.header.base_version = 1;
        mad.header.class_version = 1;
        mad.header.class = PERFORMANCE_MANAGEMENT;
        mad.header.method = GET;
        mad.header.attribute_id = attribute;
        if matches!(attribute, PORT_COUNTERS | PORT_COUNTERS_EXT) {
            mad.data[41] = 1;
        }
        mad
    }

    #[test]
    fn extended_counter_wire_bytes() {
        let mut output = Mad::default();
        output.data.fill(0xff);
        let mut counters = [0; params::RXE_NUM_OF_COUNTERS as usize];
        counters[params::RXE_CNT_SENT_BYTES as usize] = 0x102030405060708;
        counters[params::RXE_CNT_RCVD_BYTES as usize] = 7;
        counters[params::RXE_CNT_SENT_PKTS as usize] = 0x102030405060708;
        counters[params::RXE_CNT_RCVD_PKTS as usize] = 9;
        assert_eq!(
            process(&request(PORT_COUNTERS_EXT), &mut output, 1, &counters),
            MadDisposition::Reply
        );
        // Expected bytes at PMA wire offsets.
        assert_eq!(
            &output.data[48..56],
            &[0, 0x40, 0x80, 0xc1, 1, 0x41, 0x81, 0xc2]
        );
        assert_eq!(&output.data[56..64], &1u64.to_be_bytes());
        assert_eq!(&output.data[64..72], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&output.data[72..80], &9u64.to_be_bytes());
        assert!(output.data[..41].iter().all(|byte| *byte == 0));
        assert_eq!(output.data[41], 1);
        assert!(output.data[42..48].iter().all(|byte| *byte == 0));
        assert!(output.data[80..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn counter_saturation_and_capability() {
        let mut output = Mad::default();
        let mut counters = [0; params::RXE_NUM_OF_COUNTERS as usize];
        for (count, expected) in [(-1, 0), (0, 0), (254, 254), (255, 255), (256, 255)] {
            counters[params::RXE_CNT_LINK_DOWNED as usize] = count;
            assert_eq!(
                process(&request(PORT_COUNTERS), &mut output, 1, &counters),
                MadDisposition::Reply
            );
            assert_eq!(output.data[47], expected);
        }
        assert_eq!(
            process(&request(CLASS_PORT_INFO), &mut output, 1, &counters),
            MadDisposition::Reply
        );
        assert_eq!(&output.data[42..44], &[2, 0]);
    }

    #[test]
    fn response_header_and_method_admission() {
        let mut input = request(PORT_COUNTERS_EXT);
        input.header.transaction_id = 0x1234_5678_9abc_def0;
        input.header.attribute_modifier = 0;
        input.data[41] = 1;
        let mut output = Mad::default();
        let counters = [0; params::RXE_NUM_OF_COUNTERS as usize];
        assert_eq!(
            process(&input, &mut output, 1, &counters),
            MadDisposition::Reply
        );
        assert_eq!(output.header.base_version, 1);
        assert_eq!(output.header.class, PERFORMANCE_MANAGEMENT);
        assert_eq!(output.header.class_version, 1);
        assert_eq!(output.header.method, GET_RESPONSE);
        assert_eq!(output.header.transaction_id, input.header.transaction_id);
        assert_eq!(output.header.attribute_id, PORT_COUNTERS_EXT);
        assert_eq!(output.header.attribute_modifier, 0);
        assert_eq!(output.data[41], 1);
        input.header.method = GET_RESPONSE;
        assert_eq!(
            process(&input, &mut output, 1, &counters),
            MadDisposition::Success
        );
        input.header.method = 2;
        assert_eq!(
            process(&input, &mut output, 1, &counters),
            MadDisposition::Reply
        );
        assert_eq!(output.header.method, GET_RESPONSE);
        assert_eq!(output.header.status, UNSUPPORTED_METHOD);
        input.header.class_version = 2;
        assert_eq!(
            process(&input, &mut output, 1, &counters),
            MadDisposition::Reply
        );
        assert_eq!(output.header.status, UNSUPPORTED_VERSION);
    }

    #[test]
    fn reject_invalid_port_selection_and_response_methods() {
        let mut output = Mad::default();
        let counters = [0; params::RXE_NUM_OF_COUNTERS as usize];
        for attribute in [CLASS_PORT_INFO, PORT_COUNTERS, PORT_COUNTERS_EXT] {
            let mut input = request(attribute);
            input.header.attribute_modifier = 7;
            assert_eq!(
                process(&input, &mut output, 1, &counters),
                MadDisposition::Reply
            );
            assert_eq!(output.header.status, INVALID_FIELD);
        }
        for attribute in [PORT_COUNTERS, PORT_COUNTERS_EXT] {
            for port in [0, 2, 255] {
                let mut input = request(attribute);
                input.data[41] = port;
                assert_eq!(
                    process(&input, &mut output, 1, &counters),
                    MadDisposition::Reply
                );
                assert_eq!(output.header.status, INVALID_FIELD);
                assert!(output.data.iter().all(|byte| *byte == 0));
            }
        }
        for method in [GET_RESPONSE, TRAP, TRAP_REPRESS] {
            let mut input = request(PORT_COUNTERS);
            input.header.method = method;
            assert_eq!(
                process(&input, &mut output, 1, &counters),
                MadDisposition::Success
            );
        }
    }

    #[test]
    fn unsupported_requests() {
        let mut output = Mad::default();
        output.data.fill(0xff);
        let counters = [0; params::RXE_NUM_OF_COUNTERS as usize];
        assert_eq!(
            process(&request(PORT_COUNTERS), &mut output, 0, &counters),
            MadDisposition::Failure
        );
        assert!(output.data.iter().all(|byte| *byte == 0xff));
        assert_eq!(
            process(&request(0xffff), &mut output, 1, &counters),
            MadDisposition::Reply
        );
        assert_eq!(output.header.status, UNSUPPORTED_ATTRIBUTE);
        let mut input = request(PORT_COUNTERS);
        input.header.class = 0;
        assert_eq!(
            process(&input, &mut output, 1, &counters),
            MadDisposition::Success
        );
        assert_eq!(output.header.status, UNSUPPORTED_METHOD);
    }
}
