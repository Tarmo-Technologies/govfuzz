// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Result};

fn main() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let event_path = std::env::var("GOVFUZZ_EVENTS_PATH").map_err(std::io::Error::other)?;
    let mut bytes = Vec::new();
    push_begin(&mut bytes, 1);
    push_target(&mut bytes, 0x42);
    push_crumb(&mut bytes, 1);
    match input.as_str() {
        "match" => push_canonical_handler(&mut bytes, 9),
        "multi-handler" => {
            push_canonical_handler(&mut bytes, 5);
            push_canonical_handler(&mut bytes, 9);
        }
        "mismatch" => push_canonical_handler(&mut bytes, 10),
        _ if input.contains("boom") && !input.contains("crash") => std::process::exit(2),
        _ if input.contains("crash") => push_canonical_handler(&mut bytes, 9),
        _ => push_canonical_handler(&mut bytes, 10),
    }
    push_end(&mut bytes, 0);
    std::fs::write(event_path, bytes)
}

fn push_canonical_handler(bytes: &mut Vec<u8>, handler_line: u32) {
    push_handler(
        bytes,
        HandlerFields {
            exception_name: "CONSTRAINT_ERROR",
            exception_message: "bad input",
            handler_file: "pkg.adb",
            handler_line,
            last_breadcrumb: 1,
            target_id: 0x42,
            testcase_id: 1,
        },
    );
}

fn push_begin(bytes: &mut Vec<u8>, testcase_id: u64) {
    bytes.push(1);
    bytes.extend_from_slice(&testcase_id.to_le_bytes());
}

fn push_end(bytes: &mut Vec<u8>, result_class: u8) {
    bytes.push(2);
    bytes.push(result_class);
}

fn push_crumb(bytes: &mut Vec<u8>, id: u32) {
    bytes.push(3);
    bytes.extend_from_slice(&id.to_le_bytes());
}

fn push_target(bytes: &mut Vec<u8>, id: u32) {
    bytes.push(4);
    bytes.extend_from_slice(&id.to_le_bytes());
}

struct HandlerFields<'a> {
    exception_name: &'a str,
    exception_message: &'a str,
    handler_file: &'a str,
    handler_line: u32,
    last_breadcrumb: u32,
    target_id: u32,
    testcase_id: u64,
}

fn push_handler(bytes: &mut Vec<u8>, fields: HandlerFields<'_>) {
    bytes.push(5);
    push_string(bytes, fields.exception_name);
    push_string(bytes, fields.exception_message);
    push_string(bytes, fields.handler_file);
    bytes.extend_from_slice(&fields.handler_line.to_le_bytes());
    bytes.extend_from_slice(&fields.last_breadcrumb.to_le_bytes());
    bytes.extend_from_slice(&fields.target_id.to_le_bytes());
    bytes.extend_from_slice(&fields.testcase_id.to_le_bytes());
}

fn push_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}
