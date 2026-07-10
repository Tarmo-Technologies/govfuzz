// SPDX-License-Identifier: Apache-2.0

//! Pass mode controls what bytes the shim's fakes serve to the
//! target on read() calls. Set by the auto loop via
//! GOVFUZZ_RUNTRACE_MODE before exec'ing the harness; the shim
//! reads + caches once at first use.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Audit-only — Slice B behaviour. Hooks log + pass through
    /// without substituting fakes. Default when env var is unset.
    Audit,
    /// Pass 1 of the cascade. Fakes are CREATED (so the target's
    /// open() etc. succeed) but every read() returns EOF on first
    /// call. Catches the "external world is absent" code paths.
    Empty,
    /// Pass 2. Each faked resource gets its own RNG, seeded by
    /// (harness_id, resource_name, fuzz_seed). Reads serve
    /// pseudo-random bytes, gradually exhausted.
    Rng,
    /// Pass 3. Reads pull bytes from the fuzz-input shared memfd
    /// so the fuzzer's coverage feedback learns to route bytes
    /// to fake resources that gate interesting code paths.
    FuzzDriven,
}

impl Mode {
    pub fn from_env_byte_str(value: &[u8]) -> Mode {
        match value {
            b"empty" => Mode::Empty,
            b"rng" => Mode::Rng,
            b"fuzz_driven" => Mode::FuzzDriven,
            _ => Mode::Audit,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Audit => "audit",
            Mode::Empty => "empty",
            Mode::Rng => "rng",
            Mode::FuzzDriven => "fuzz_driven",
        }
    }

    pub fn is_faking(self) -> bool {
        !matches!(self, Mode::Audit)
    }
}

static CURRENT: OnceLock<Mode> = OnceLock::new();

pub fn current() -> Mode {
    *CURRENT.get_or_init(|| {
        std::env::var_os("GOVFUZZ_RUNTRACE_MODE")
            .map(|v| Mode::from_env_byte_str(v.as_encoded_bytes()))
            .unwrap_or(Mode::Audit)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_mode() {
        assert_eq!(Mode::from_env_byte_str(b"empty"), Mode::Empty);
        assert_eq!(Mode::from_env_byte_str(b"rng"), Mode::Rng);
        assert_eq!(Mode::from_env_byte_str(b"fuzz_driven"), Mode::FuzzDriven);
        assert_eq!(Mode::from_env_byte_str(b""), Mode::Audit);
        assert_eq!(Mode::from_env_byte_str(b"junk"), Mode::Audit);
    }

    #[test]
    fn is_faking_is_correct() {
        assert!(!Mode::Audit.is_faking());
        assert!(Mode::Empty.is_faking());
        assert!(Mode::Rng.is_faking());
        assert!(Mode::FuzzDriven.is_faking());
    }

    #[test]
    fn as_str_round_trips_via_from_env() {
        for m in [Mode::Empty, Mode::Rng, Mode::FuzzDriven] {
            assert_eq!(Mode::from_env_byte_str(m.as_str().as_bytes()), m);
        }
    }
}
