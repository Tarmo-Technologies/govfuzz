// SPDX-License-Identifier: Apache-2.0

//! `govfuzz cmplog` subcommand: ingest a runtrace audit log and
//! print recovered cmplog operands as a JSON token list.
//!
//! Use case: after `GOVFUZZ_CMPLOG=1 GOVFUZZ_RUNTRACE_LOG=audit.jsonl
//! ./harness < input` writes runtime cmp operands to audit.jsonl,
//! `govfuzz cmplog ingest --log audit.jsonl` prints the deduplicated
//! token list. Pipe that into a future `govfuzz fuzz --dictionary
//! <file>` to seed the engine's mutator with RedQueen-style splice
//! candidates.

use cmplog::ingest_from_jsonl_log;
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct CmplogArgs {
    #[command(subcommand)]
    pub command: CmplogCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum CmplogCommand {
    /// Ingest a runtrace audit log and print recovered cmplog
    /// operands as a JSON token list.
    Ingest(IngestArgs),
}

#[derive(Debug, clap::Args)]
pub struct IngestArgs {
    /// Path to a `GOVFUZZ_RUNTRACE_LOG` JSONL file produced by
    /// the runtrace_shim with GOVFUZZ_CMPLOG=1 set.
    #[arg(long, value_name = "PATH")]
    pub log: PathBuf,

    /// Output format. `json` (default) emits a JSON array of
    /// base64-encoded token bytes; `tokens` emits one token per
    /// line, hex-encoded.
    #[arg(long, default_value = "json")]
    pub format: String,
}

pub fn run(args: CmplogArgs) -> i32 {
    match args.command {
        CmplogCommand::Ingest(ingest) => run_ingest(ingest),
    }
}

fn run_ingest(args: IngestArgs) -> i32 {
    let log = match ingest_from_jsonl_log(&args.log) {
        Ok(log) => log,
        Err(error) => {
            gfeprintln!("error: {error}");
            return 1;
        }
    };
    let tokens = log.dictionary_tokens();
    match args.format.as_str() {
        "json" => {
            let value: Vec<String> = tokens.iter().map(|t| base64_encode(t)).collect();
            println!(
                "{}",
                serde_json::to_string(&value).unwrap_or_else(|_| "[]".to_owned())
            );
        }
        "tokens" => {
            for token in &tokens {
                println!("{}", hex_encode(token));
            }
        }
        other => {
            gfeprintln!("error: unknown --format {other}");
            return 2;
        }
    }
    0
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Minimal base64 encoder for the JSON output path. The token
/// list is rarely large enough to need streaming; this hand-rolled
/// path avoids pulling a base64 crate into the cli.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let b = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        out.push(ALPHA[((b >> 18) & 0x3F) as usize] as char);
        out.push(ALPHA[((b >> 12) & 0x3F) as usize] as char);
        out.push(ALPHA[((b >> 6) & 0x3F) as usize] as char);
        out.push(ALPHA[(b & 0x3F) as usize] as char);
    }
    let remainder = chunks.remainder();
    match remainder.len() {
        1 => {
            let b = (remainder[0] as u32) << 16;
            out.push(ALPHA[((b >> 18) & 0x3F) as usize] as char);
            out.push(ALPHA[((b >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let b = ((remainder[0] as u32) << 16) | ((remainder[1] as u32) << 8);
            out.push(ALPHA[((b >> 18) & 0x3F) as usize] as char);
            out.push(ALPHA[((b >> 12) & 0x3F) as usize] as char);
            out.push(ALPHA[((b >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_lower_hex() {
        assert_eq!(hex_encode(&[0xab, 0x01]), "ab01");
    }

    #[test]
    fn base64_encode_three_bytes_aligned() {
        // "Man" -> "TWFu" per RFC4648.
        assert_eq!(base64_encode(b"Man"), "TWFu");
    }

    #[test]
    fn base64_encode_two_bytes_pads_one_equals() {
        assert_eq!(base64_encode(b"Ma"), "TWE=");
    }

    #[test]
    fn base64_encode_one_byte_pads_two_equals() {
        assert_eq!(base64_encode(b"M"), "TQ==");
    }

    #[test]
    fn base64_encode_empty_returns_empty() {
        assert_eq!(base64_encode(b""), "");
    }
}
