// SPDX-License-Identifier: Apache-2.0

use event_log::{HandlerEvent, Testcase};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature(pub [u8; 32]);

impl Signature {
    pub fn hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        decode_hex_32(&hex)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

pub fn compute_signature(testcase: &Testcase, handler: &HandlerEvent) -> Signature {
    let explicit_raise_id = preceding_matching_raise_breadcrumb(testcase, handler);
    let handler_location = format!("{}:{}", handler.handler_file, handler.handler_line);

    let fields = [
        handler.target_id.to_string(),
        handler.exception_name.clone(),
        handler_location,
        handler.last_breadcrumb.to_string(),
        explicit_raise_id.unwrap_or_default(),
        // M5 has no call sequences yet; M9 will replace this stable singleton.
        "0".to_owned(),
        // M5 has raw byte inputs, but no typed parameter-shape hash until M8+.
        String::new(),
        // M5 does not emit return classifications yet.
        String::new(),
        // M5 does not emit resource-growth or timeout signals yet.
        String::new(),
    ];
    let input = fields.join("\0");
    let digest = Sha256::digest(input.as_bytes());
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    Signature(bytes)
}

fn preceding_matching_raise_breadcrumb(
    testcase: &Testcase,
    handler: &HandlerEvent,
) -> Option<String> {
    testcase
        .raises
        .iter()
        .filter(|raise| {
            raise.sequence_index < handler.sequence_index
                && raise
                    .exception_name
                    .eq_ignore_ascii_case(&handler.exception_name)
        })
        .max_by_key(|raise| raise.sequence_index)
        .map(|raise| raise.breadcrumb.to_string())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("signature hex must be 64 chars, got {}", hex.len()));
    }

    let mut out = [0_u8; 32];
    let bytes = hex.as_bytes();
    for index in 0..32 {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid signature hex byte 0x{byte:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_signature, Signature};
    use event_log::{HandlerEvent, Testcase};

    #[test]
    fn compute_signature_is_deterministic_for_same_inputs() {
        let testcase = canonical_testcase();
        let left = compute_signature(&testcase, &testcase.handlers[0]);
        let right = compute_signature(&testcase, &testcase.handlers[0]);

        assert_eq!(left, right);
    }

    #[test]
    fn compute_signature_changes_with_target_id() {
        let left = canonical_testcase();
        let mut right = canonical_testcase();
        right.handlers[0].target_id = 0x43;
        right.target_id = 0x43;

        assert_ne!(
            compute_signature(&left, &left.handlers[0]),
            compute_signature(&right, &right.handlers[0])
        );
    }

    #[test]
    fn compute_signature_changes_with_exception_name() {
        let left = canonical_testcase();
        let mut right = canonical_testcase();
        right.handlers[0].exception_name = "PROGRAM_ERROR".to_owned();

        assert_ne!(
            compute_signature(&left, &left.handlers[0]),
            compute_signature(&right, &right.handlers[0])
        );
    }

    #[test]
    fn compute_signature_changes_with_handler_line() {
        let left = canonical_testcase();
        let mut right = canonical_testcase();
        right.handlers[0].handler_line = 10;

        assert_ne!(
            compute_signature(&left, &left.handlers[0]),
            compute_signature(&right, &right.handlers[0])
        );
    }

    #[test]
    fn compute_signature_changes_with_last_breadcrumb() {
        let left = canonical_testcase();
        let mut right = canonical_testcase();
        right.handlers[0].last_breadcrumb = 2;

        assert_ne!(
            compute_signature(&left, &left.handlers[0]),
            compute_signature(&right, &right.handlers[0])
        );
    }

    #[test]
    fn compute_signature_for_swallowed_ce_handler_matches_known_value() {
        let testcase = canonical_testcase();

        assert_eq!(
            compute_signature(&testcase, &testcase.handlers[0]).hex(),
            "20b41fb2a2ceeabc9f0403546af14199d4ccacc54e55f6fcb5855015b5eb63bd"
        );
    }

    #[test]
    fn compute_signature_uses_preceding_matching_raise_breadcrumb() {
        let without_raise = canonical_testcase();
        let mut with_raise = canonical_testcase();
        with_raise.raises.push(event_log::RaiseEvent {
            sequence_index: 1,
            exception_name: "CONSTRAINT_ERROR".to_owned(),
            file: "pkg.adb".to_owned(),
            line: 8,
            breadcrumb: 99,
        });
        with_raise.handlers[0].sequence_index = 2;

        assert_ne!(
            compute_signature(&without_raise, &without_raise.handlers[0]),
            compute_signature(&with_raise, &with_raise.handlers[0])
        );
    }

    #[test]
    fn compute_signature_ignores_matching_raise_after_handler() {
        let without_raise = canonical_testcase();
        let mut raise_after_handler = canonical_testcase();
        raise_after_handler.raises.push(event_log::RaiseEvent {
            sequence_index: 3,
            exception_name: "CONSTRAINT_ERROR".to_owned(),
            file: "pkg.adb".to_owned(),
            line: 12,
            breadcrumb: 99,
        });

        assert_eq!(
            compute_signature(&without_raise, &without_raise.handlers[0]),
            compute_signature(&raise_after_handler, &raise_after_handler.handlers[0])
        );
    }

    #[test]
    fn signature_serde_round_trip_via_hex() {
        let signature = Signature([0xAB; 32]);

        let json = serde_json::to_string(&signature).unwrap();
        let decoded: Signature = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, signature);
        assert_eq!(
            json,
            "\"abababababababababababababababababababababababababababababababab\""
        );
    }

    #[test]
    fn signature_hex_is_64_chars_lowercase() {
        let signature = Signature([0xAF; 32]);
        let hex = signature.hex();

        assert_eq!(hex.len(), 64);
        assert!(hex
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit()));
    }

    fn canonical_testcase() -> Testcase {
        let handler = HandlerEvent {
            sequence_index: 3,
            exception_name: "CONSTRAINT_ERROR".to_owned(),
            exception_message: "bad input".to_owned(),
            handler_file: "pkg.adb".to_owned(),
            handler_line: 9,
            last_breadcrumb: 1,
            target_id: 0x42,
            testcase_id: 1,
        };

        Testcase {
            testcase_id: 1,
            target_id: 0x42,
            target_entered: false,
            crumbs: vec![1],
            handlers: vec![handler],
            raises: Vec::new(),
            top_level: None,
            end: None,
            mocks: Vec::new(),
        }
    }
}
