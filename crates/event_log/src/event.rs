// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventTag {
    Begin = 1,
    End = 2,
    Crumb = 3,
    Target = 4,
    Handler = 5,
    Raise = 6,
    Mock = 7,
    TopLevel = 8,
}

impl EventTag {
    pub fn try_from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Begin),
            2 => Some(Self::End),
            3 => Some(Self::Crumb),
            4 => Some(Self::Target),
            5 => Some(Self::Handler),
            6 => Some(Self::Raise),
            7 => Some(Self::Mock),
            8 => Some(Self::TopLevel),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Event {
    Begin {
        testcase_id: u64,
    },
    End {
        result_class: u8,
    },
    Crumb {
        id: u32,
    },
    Target {
        id: u32,
    },
    Handler {
        exception_name: String,
        exception_message: String,
        handler_file: String,
        handler_line: u32,
        last_breadcrumb: u32,
        target_id: u32,
        testcase_id: u64,
    },
    Raise {
        exception_name: String,
        file: String,
        line: u32,
        breadcrumb: u32,
    },
    Mock {
        symbol: String,
    },
    TopLevel {
        exception_name: String,
        exception_message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::EventTag;

    #[test]
    fn event_tag_try_from_byte_recognizes_known_tags() {
        assert_eq!(EventTag::try_from_byte(1), Some(EventTag::Begin));
        assert_eq!(EventTag::try_from_byte(2), Some(EventTag::End));
        assert_eq!(EventTag::try_from_byte(3), Some(EventTag::Crumb));
        assert_eq!(EventTag::try_from_byte(4), Some(EventTag::Target));
        assert_eq!(EventTag::try_from_byte(5), Some(EventTag::Handler));
        assert_eq!(EventTag::try_from_byte(6), Some(EventTag::Raise));
        assert_eq!(EventTag::try_from_byte(7), Some(EventTag::Mock));
        assert_eq!(EventTag::try_from_byte(8), Some(EventTag::TopLevel));
    }

    #[test]
    fn event_tag_try_from_byte_returns_none_for_unknown() {
        assert_eq!(EventTag::try_from_byte(0), None);
        assert_eq!(EventTag::try_from_byte(9), None);
        assert_eq!(EventTag::try_from_byte(u8::MAX), None);
    }

    #[test]
    fn event_tag_round_trip_byte_to_enum_to_byte() {
        for byte in 1..=8 {
            let tag = EventTag::try_from_byte(byte).unwrap();
            assert_eq!(tag as u8, byte);
        }
    }

    #[test]
    fn event_tag_discriminants_match_probe_constants() {
        assert_eq!(EventTag::Begin as u8, 1);
        assert_eq!(EventTag::End as u8, 2);
        assert_eq!(EventTag::Crumb as u8, 3);
        assert_eq!(EventTag::Target as u8, 4);
        assert_eq!(EventTag::Handler as u8, 5);
        assert_eq!(EventTag::Raise as u8, 6);
        assert_eq!(EventTag::Mock as u8, 7);
        assert_eq!(EventTag::TopLevel as u8, 8);
    }
}
