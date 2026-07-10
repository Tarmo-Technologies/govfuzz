// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Pass {
    Empty,
    Rng,
    FuzzDriven,
}

impl Pass {
    pub const ALL: &'static [Pass] = &[Pass::Empty, Pass::Rng, Pass::FuzzDriven];

    pub fn as_str(self) -> &'static str {
        match self {
            Pass::Empty => "empty",
            Pass::Rng => "rng",
            Pass::FuzzDriven => "fuzz_driven",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Pass> {
        match s {
            "empty" => Some(Pass::Empty),
            "rng" => Some(Pass::Rng),
            "fuzz_driven" => Some(Pass::FuzzDriven),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for p in Pass::ALL {
            assert_eq!(Pass::from_str(p.as_str()), Some(*p));
        }
    }

    #[test]
    fn unknown_returns_none() {
        assert_eq!(Pass::from_str("garbage"), None);
    }
}
