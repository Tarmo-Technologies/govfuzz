// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use crate::cdr::{CdrError, CdrReader, Endianness};

pub const HEADER_LEN: usize = 12;
pub const TAG_INTERNET_IOP: u32 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageType {
    Request,
    Reply,
    CancelRequest,
    LocateRequest,
    LocateReply,
    CloseConnection,
    MessageError,
    Fragment,
    Unknown(u8),
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Request,
            1 => Self::Reply,
            2 => Self::CancelRequest,
            3 => Self::LocateRequest,
            4 => Self::LocateReply,
            5 => Self::CloseConnection,
            6 => Self::MessageError,
            7 => Self::Fragment,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageHeader {
    pub version: Version,
    pub endian: Endianness,
    pub fragmented: bool,
    pub message_type: MessageType,
    pub body_len: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedMessage<'a> {
    pub header: MessageHeader,
    pub body: &'a [u8],
    pub remaining: &'a [u8],
}

impl<'a> ParsedMessage<'a> {
    pub fn body_reader(&self) -> CdrReader<'a> {
        CdrReader::with_alignment_base(self.body, self.header.endian, HEADER_LEN)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRequest10<'a> {
    pub service_contexts: Vec<ServiceContext<'a>>,
    pub request_id: u32,
    pub response_expected: bool,
    pub object_key: &'a [u8],
    pub operation: String,
    pub requesting_principal: &'a [u8],
    pub arguments: &'a [u8],
    arguments_alignment_base: usize,
    endian: Endianness,
}

impl<'a> ParsedRequest10<'a> {
    pub fn arguments_reader(&self) -> CdrReader<'a> {
        CdrReader::with_alignment_base(self.arguments, self.endian, self.arguments_alignment_base)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRequest11<'a> {
    pub service_contexts: Vec<ServiceContext<'a>>,
    pub request_id: u32,
    pub response_expected: bool,
    pub reserved: [u8; 3],
    pub object_key: &'a [u8],
    pub operation: String,
    pub requesting_principal: &'a [u8],
    pub arguments: &'a [u8],
    arguments_alignment_base: usize,
    endian: Endianness,
}

impl<'a> ParsedRequest11<'a> {
    pub fn arguments_reader(&self) -> CdrReader<'a> {
        CdrReader::with_alignment_base(self.arguments, self.endian, self.arguments_alignment_base)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRequest12<'a> {
    pub service_contexts: Vec<ServiceContext<'a>>,
    pub request_id: u32,
    pub response_flags: u8,
    pub target: TargetAddress<'a>,
    pub operation: String,
    pub arguments: &'a [u8],
    arguments_alignment_base: usize,
    endian: Endianness,
}

impl<'a> ParsedRequest12<'a> {
    pub fn arguments_reader(&self) -> CdrReader<'a> {
        CdrReader::with_alignment_base(self.arguments, self.endian, self.arguments_alignment_base)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedReply1_0_1_1<'a> {
    pub service_contexts: Vec<ServiceContext<'a>>,
    pub request_id: u32,
    pub status: ReplyStatus,
    pub body: &'a [u8],
    body_alignment_base: usize,
    endian: Endianness,
}

impl<'a> ParsedReply1_0_1_1<'a> {
    pub fn body_reader(&self) -> CdrReader<'a> {
        CdrReader::with_alignment_base(self.body, self.endian, self.body_alignment_base)
    }
}

pub type ParsedReply10<'a> = ParsedReply1_0_1_1<'a>;
pub type ParsedReply11<'a> = ParsedReply1_0_1_1<'a>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedReply12<'a> {
    pub service_contexts: Vec<ServiceContext<'a>>,
    pub request_id: u32,
    pub status: ReplyStatus,
    pub body: &'a [u8],
    body_alignment_base: usize,
    endian: Endianness,
}

impl<'a> ParsedReply12<'a> {
    pub fn body_reader(&self) -> CdrReader<'a> {
        CdrReader::with_alignment_base(self.body, self.endian, self.body_alignment_base)
    }

    pub fn forwarded_ior(&self) -> Result<Option<Ior<'a>>, GiopError> {
        match self.status {
            ReplyStatus::LocationForward | ReplyStatus::LocationForwardPerm => {
                let mut reader = self.body_reader();
                Ok(Some(read_ior(&mut reader)?))
            }
            _ => Ok(None),
        }
    }

    pub fn forwarded_iiop_profiles(&self) -> Result<Vec<IiopProfile<'a>>, GiopError> {
        match self.forwarded_ior()? {
            Some(ior) => Ok(ior.iiop_profiles()?),
            None => Ok(Vec::new()),
        }
    }

    pub fn addressing_disposition(&self) -> Result<Option<i16>, GiopError> {
        match self.status {
            ReplyStatus::NeedsAddressingMode => {
                let mut reader = self.body_reader();
                Ok(Some(reader.read_i16()?))
            }
            _ => Ok(None),
        }
    }

    pub fn system_exception(&self) -> Result<Option<SystemExceptionBody>, GiopError> {
        match self.status {
            ReplyStatus::SystemException => {
                let mut reader = self.body_reader();
                Ok(Some(read_system_exception_body(&mut reader)?))
            }
            _ => Ok(None),
        }
    }

    pub fn user_exception(&self) -> Result<Option<UserExceptionBody<'a>>, GiopError> {
        match self.status {
            ReplyStatus::UserException => {
                let mut reader = self.body_reader();
                let exception_id = reader.read_string()?;
                Ok(Some(UserExceptionBody {
                    exception_id,
                    remaining: &self.body[reader.position()..],
                }))
            }
            _ => Ok(None),
        }
    }

    pub fn reply_body(&self) -> Result<ParsedReplyBody12<'a>, GiopError> {
        match self.status {
            ReplyStatus::NoException => Ok(ParsedReplyBody12::NoException(self.body)),
            ReplyStatus::UserException => {
                let mut reader = self.body_reader();
                let exception_id = reader.read_string()?;
                Ok(ParsedReplyBody12::UserException(UserExceptionBody {
                    exception_id,
                    remaining: &self.body[reader.position()..],
                }))
            }
            ReplyStatus::SystemException => {
                let mut reader = self.body_reader();
                Ok(ParsedReplyBody12::SystemException(
                    read_system_exception_body(&mut reader)?,
                ))
            }
            ReplyStatus::LocationForward => {
                let mut reader = self.body_reader();
                Ok(ParsedReplyBody12::LocationForward(read_ior(&mut reader)?))
            }
            ReplyStatus::LocationForwardPerm => {
                let mut reader = self.body_reader();
                Ok(ParsedReplyBody12::LocationForwardPerm(read_ior(
                    &mut reader,
                )?))
            }
            ReplyStatus::NeedsAddressingMode => {
                let mut reader = self.body_reader();
                Ok(ParsedReplyBody12::NeedsAddressingMode(reader.read_i16()?))
            }
            ReplyStatus::Unknown(status) => Ok(ParsedReplyBody12::Unknown {
                status,
                body: self.body,
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedLocateRequest12<'a> {
    pub request_id: u32,
    pub target: TargetAddress<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedLocateReply12<'a> {
    pub request_id: u32,
    pub status: LocateStatus,
    pub body: &'a [u8],
    body_alignment_base: usize,
    endian: Endianness,
}

impl<'a> ParsedLocateReply12<'a> {
    pub fn body_reader(&self) -> CdrReader<'a> {
        CdrReader::with_alignment_base(self.body, self.endian, self.body_alignment_base)
    }

    pub fn forwarded_ior(&self) -> Result<Option<Ior<'a>>, GiopError> {
        match self.status {
            LocateStatus::ObjectForward | LocateStatus::ObjectForwardPerm => {
                let mut reader = self.body_reader();
                Ok(Some(read_ior(&mut reader)?))
            }
            _ => Ok(None),
        }
    }

    pub fn forwarded_iiop_profiles(&self) -> Result<Vec<IiopProfile<'a>>, GiopError> {
        match self.forwarded_ior()? {
            Some(ior) => Ok(ior.iiop_profiles()?),
            None => Ok(Vec::new()),
        }
    }

    pub fn addressing_disposition(&self) -> Result<Option<i16>, GiopError> {
        match self.status {
            LocateStatus::NeedsAddressingMode => {
                let mut reader = self.body_reader();
                Ok(Some(reader.read_i16()?))
            }
            _ => Ok(None),
        }
    }

    pub fn system_exception(&self) -> Result<Option<SystemExceptionBody>, GiopError> {
        match self.status {
            LocateStatus::SystemException => {
                let mut reader = self.body_reader();
                Ok(Some(read_system_exception_body(&mut reader)?))
            }
            _ => Ok(None),
        }
    }

    pub fn reply_body(&self) -> Result<ParsedLocateReplyBody12<'a>, GiopError> {
        match self.status {
            LocateStatus::UnknownObject => Ok(ParsedLocateReplyBody12::UnknownObject(self.body)),
            LocateStatus::ObjectHere => Ok(ParsedLocateReplyBody12::ObjectHere(self.body)),
            LocateStatus::ObjectForward => {
                let mut reader = self.body_reader();
                Ok(ParsedLocateReplyBody12::ObjectForward(read_ior(
                    &mut reader,
                )?))
            }
            LocateStatus::ObjectForwardPerm => {
                let mut reader = self.body_reader();
                Ok(ParsedLocateReplyBody12::ObjectForwardPerm(read_ior(
                    &mut reader,
                )?))
            }
            LocateStatus::SystemException => {
                let mut reader = self.body_reader();
                Ok(ParsedLocateReplyBody12::SystemException(
                    read_system_exception_body(&mut reader)?,
                ))
            }
            LocateStatus::NeedsAddressingMode => {
                let mut reader = self.body_reader();
                Ok(ParsedLocateReplyBody12::NeedsAddressingMode(
                    reader.read_i16()?,
                ))
            }
            LocateStatus::Unknown(status) => Ok(ParsedLocateReplyBody12::Unknown {
                status,
                body: self.body,
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedCancelRequest {
    pub request_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedFragment12<'a> {
    pub request_id: u32,
    pub data: &'a [u8],
    data_alignment_base: usize,
    endian: Endianness,
}

impl<'a> ParsedFragment12<'a> {
    pub fn data_reader(&self) -> CdrReader<'a> {
        CdrReader::with_alignment_base(self.data, self.endian, self.data_alignment_base)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedGiop10<'a> {
    Request(ParsedRequest10<'a>),
    Reply(ParsedReply10<'a>),
    CancelRequest(ParsedCancelRequest),
    CloseConnection,
    MessageError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedGiop11<'a> {
    Request(ParsedRequest11<'a>),
    Reply(ParsedReply11<'a>),
    CancelRequest(ParsedCancelRequest),
    CloseConnection,
    MessageError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedGiop12<'a> {
    Request(ParsedRequest12<'a>),
    Reply(ParsedReply12<'a>),
    CancelRequest(ParsedCancelRequest),
    LocateRequest(ParsedLocateRequest12<'a>),
    LocateReply(ParsedLocateReply12<'a>),
    CloseConnection,
    MessageError,
    Fragment(ParsedFragment12<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedGiop<'a> {
    Giop10(ParsedGiop10<'a>),
    Giop11(ParsedGiop11<'a>),
    Giop12(ParsedGiop12<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedGiopMessage<'a> {
    pub header: MessageHeader,
    pub message: ParsedGiop<'a>,
    pub remaining: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedGiop12Message<'a> {
    pub header: MessageHeader,
    pub message: ParsedGiop12<'a>,
    pub remaining: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReassembledGiop12Message {
    pub header: MessageHeader,
    pub body: Vec<u8>,
    pub frame_ranges: Vec<GiopFrameRange>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GiopFrameRange {
    pub offset: usize,
    pub len: usize,
    pub message_type: MessageType,
    pub fragmented: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GiopReassemblyError {
    Giop(GiopError),
    FragmentWithoutInitial {
        request_id: u32,
        offset: usize,
    },
    DuplicateInitial {
        request_id: u32,
        offset: usize,
    },
    FragmentRequestIdMismatch {
        expected: u32,
        actual: u32,
        offset: usize,
    },
    UnfinishedFragmentedMessage {
        request_id: u32,
    },
}

impl fmt::Display for GiopReassemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Giop(error) => write!(formatter, "{error}"),
            Self::FragmentWithoutInitial { request_id, offset } => write!(
                formatter,
                "GIOP 1.2 fragment for request id {request_id} at offset {offset} has no initial fragmented message"
            ),
            Self::DuplicateInitial { request_id, offset } => write!(
                formatter,
                "GIOP 1.2 fragmented message for request id {request_id} at offset {offset} overlaps an unfinished message"
            ),
            Self::FragmentRequestIdMismatch {
                expected,
                actual,
                offset,
            } => write!(
                formatter,
                "GIOP 1.2 fragment at offset {offset} has request id {actual}, expected {expected}"
            ),
            Self::UnfinishedFragmentedMessage { request_id } => write!(
                formatter,
                "GIOP 1.2 fragmented message for request id {request_id} was not completed"
            ),
        }
    }
}

impl std::error::Error for GiopReassemblyError {}

impl From<GiopError> for GiopReassemblyError {
    fn from(error: GiopError) -> Self {
        Self::Giop(error)
    }
}

#[derive(Clone, Debug)]
struct OpenFragmentedMessage {
    request_id: u32,
    header: MessageHeader,
    body: Vec<u8>,
    frame_ranges: Vec<GiopFrameRange>,
}

#[derive(Clone, Debug)]
pub struct Giop12Messages<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for Giop12Messages<'a> {
    type Item = Result<ParsedGiop12Message<'a>, GiopError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }

        match parse_message_1_2(self.remaining) {
            Ok(message) => {
                self.remaining = message.remaining;
                Some(Ok(message))
            }
            Err(error) => {
                self.remaining = &[];
                Some(Err(error))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyStatus {
    NoException,
    UserException,
    SystemException,
    LocationForward,
    LocationForwardPerm,
    NeedsAddressingMode,
    Unknown(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocateStatus {
    UnknownObject,
    ObjectHere,
    ObjectForward,
    ObjectForwardPerm,
    SystemException,
    NeedsAddressingMode,
    Unknown(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionStatus {
    CompletedYes,
    CompletedNo,
    CompletedMaybe,
    Unknown(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemExceptionBody {
    pub exception_id: String,
    pub minor_code: u32,
    pub completion_status: CompletionStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserExceptionBody<'a> {
    pub exception_id: String,
    pub remaining: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedReplyBody12<'a> {
    NoException(&'a [u8]),
    UserException(UserExceptionBody<'a>),
    SystemException(SystemExceptionBody),
    LocationForward(Ior<'a>),
    LocationForwardPerm(Ior<'a>),
    NeedsAddressingMode(i16),
    Unknown { status: u32, body: &'a [u8] },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedLocateReplyBody12<'a> {
    UnknownObject(&'a [u8]),
    ObjectHere(&'a [u8]),
    ObjectForward(Ior<'a>),
    ObjectForwardPerm(Ior<'a>),
    SystemException(SystemExceptionBody),
    NeedsAddressingMode(i16),
    Unknown { status: u32, body: &'a [u8] },
}

impl From<u32> for ReplyStatus {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::NoException,
            1 => Self::UserException,
            2 => Self::SystemException,
            3 => Self::LocationForward,
            4 => Self::LocationForwardPerm,
            5 => Self::NeedsAddressingMode,
            other => Self::Unknown(other),
        }
    }
}

impl From<u32> for LocateStatus {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::UnknownObject,
            1 => Self::ObjectHere,
            2 => Self::ObjectForward,
            3 => Self::ObjectForwardPerm,
            4 => Self::SystemException,
            5 => Self::NeedsAddressingMode,
            other => Self::Unknown(other),
        }
    }
}

impl From<u32> for CompletionStatus {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::CompletedYes,
            1 => Self::CompletedNo,
            2 => Self::CompletedMaybe,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaggedProfile<'a> {
    pub tag: u32,
    pub profile_data: &'a [u8],
}

impl<'a> TaggedProfile<'a> {
    pub fn iiop_profile(&self) -> Result<Option<IiopProfile<'a>>, CdrError> {
        if self.tag == TAG_INTERNET_IOP {
            read_iiop_profile_body(self.profile_data).map(Some)
        } else {
            Ok(None)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaggedComponent<'a> {
    pub tag: u32,
    pub component_data: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ior<'a> {
    pub type_id: String,
    pub profiles: Vec<TaggedProfile<'a>>,
}

impl<'a> Ior<'a> {
    pub fn iiop_profiles(&self) -> Result<Vec<IiopProfile<'a>>, CdrError> {
        let mut profiles = Vec::new();

        for profile in &self.profiles {
            if let Some(iiop_profile) = profile.iiop_profile()? {
                profiles.push(iiop_profile);
            }
        }

        Ok(profiles)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IorAddressingInfo<'a> {
    pub selected_profile_index: u32,
    pub ior: Ior<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetAddress<'a> {
    KeyAddr(&'a [u8]),
    ProfileAddr(TaggedProfile<'a>),
    ReferenceAddr(IorAddressingInfo<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IiopProfile<'a> {
    pub version: Version,
    pub host: String,
    pub port: u16,
    pub object_key: &'a [u8],
    pub components: Vec<TaggedComponent<'a>>,
    pub remaining: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceContext<'a> {
    pub context_id: u32,
    pub data: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GiopError {
    TruncatedHeader {
        len: usize,
    },
    TruncatedBody {
        declared: u32,
        available: usize,
    },
    UnsupportedVersion(Version),
    InvalidFlags {
        version: Version,
        flags: u8,
    },
    UnexpectedMessageType {
        expected: MessageType,
        actual: MessageType,
    },
    UnsupportedMessageType(MessageType),
    InvalidRequestReserved {
        offset: usize,
        reserved: [u8; 3],
    },
    UnsupportedTargetAddress {
        disposition: i16,
    },
    BadMagic([u8; 4]),
    Cdr(CdrError),
}

impl fmt::Display for GiopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { len } => {
                write!(
                    f,
                    "truncated GIOP header: expected {HEADER_LEN} bytes, got {len}"
                )
            }
            Self::TruncatedBody {
                declared,
                available,
            } => write!(
                f,
                "truncated GIOP body: declared {declared} byte(s), had {available}"
            ),
            Self::UnsupportedVersion(version) => {
                write!(
                    f,
                    "unsupported GIOP version {}.{}",
                    version.major, version.minor
                )
            }
            Self::InvalidFlags { version, flags } => write!(
                f,
                "invalid GIOP {}.{} flags/byte-order value 0x{flags:02x}",
                version.major, version.minor
            ),
            Self::UnexpectedMessageType { expected, actual } => write!(
                f,
                "unexpected GIOP message type {actual:?}, expected {expected:?}"
            ),
            Self::UnsupportedMessageType(actual) => {
                write!(f, "unsupported GIOP message type {actual:?}")
            }
            Self::InvalidRequestReserved { offset, reserved } => write!(
                f,
                "nonzero GIOP request reserved bytes at body offset {offset}: {reserved:?}"
            ),
            Self::UnsupportedTargetAddress { disposition } => {
                write!(
                    f,
                    "unsupported GIOP target address disposition {disposition}"
                )
            }
            Self::BadMagic(magic) => write!(f, "bad GIOP magic: {magic:?}"),
            Self::Cdr(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for GiopError {}

impl From<CdrError> for GiopError {
    fn from(error: CdrError) -> Self {
        Self::Cdr(error)
    }
}

pub fn parse_header(input: &[u8]) -> Result<MessageHeader, GiopError> {
    if input.len() < HEADER_LEN {
        return Err(GiopError::TruncatedHeader { len: input.len() });
    }

    let magic = [input[0], input[1], input[2], input[3]];
    if magic != *b"GIOP" {
        return Err(GiopError::BadMagic(magic));
    }

    let version = Version {
        major: input[4],
        minor: input[5],
    };
    let flags = input[6];
    let (endian, fragmented) = match (version.major, version.minor) {
        (1, 0) => match flags {
            0 => (Endianness::Big, false),
            1 => (Endianness::Little, false),
            _ => return Err(GiopError::InvalidFlags { version, flags }),
        },
        (1, 1) | (1, 2) => {
            if flags & !0x03 != 0 {
                return Err(GiopError::InvalidFlags { version, flags });
            }
            let endian = if flags & 0x01 == 0 {
                Endianness::Big
            } else {
                Endianness::Little
            };
            (endian, flags & 0x02 != 0)
        }
        _ => return Err(GiopError::UnsupportedVersion(version)),
    };
    let body_len = match endian {
        Endianness::Big => u32::from_be_bytes([input[8], input[9], input[10], input[11]]),
        Endianness::Little => u32::from_le_bytes([input[8], input[9], input[10], input[11]]),
    };

    Ok(MessageHeader {
        version,
        endian,
        fragmented,
        message_type: MessageType::from(input[7]),
        body_len,
    })
}

pub fn parse_message(input: &[u8]) -> Result<ParsedMessage<'_>, GiopError> {
    let header = parse_header(input)?;
    let body_len = header.body_len as usize;
    let available = input.len() - HEADER_LEN;

    if available < body_len {
        return Err(GiopError::TruncatedBody {
            declared: header.body_len,
            available,
        });
    }

    let body_end = HEADER_LEN + body_len;
    Ok(ParsedMessage {
        header,
        body: &input[HEADER_LEN..body_end],
        remaining: &input[body_end..],
    })
}

pub fn read_service_context_list<'a>(
    reader: &mut CdrReader<'a>,
) -> Result<Vec<ServiceContext<'a>>, CdrError> {
    const SERVICE_CONTEXT_MIN_LEN: usize = 8;

    let count_offset = reader.position();
    let count = reader.read_u32()? as usize;
    let remaining = reader.remaining();
    let max_possible_contexts = remaining / SERVICE_CONTEXT_MIN_LEN;
    if count > max_possible_contexts {
        return Err(CdrError::SequenceLengthExceedsRemaining {
            offset: count_offset,
            declared: count as u32,
            remaining,
            element_min_size: SERVICE_CONTEXT_MIN_LEN,
        });
    }

    let mut contexts = Vec::with_capacity(count);

    for _ in 0..count {
        contexts.push(ServiceContext {
            context_id: reader.read_u32()?,
            data: reader.read_octet_sequence()?,
        });
    }

    Ok(contexts)
}

fn read_system_exception_body(reader: &mut CdrReader<'_>) -> Result<SystemExceptionBody, CdrError> {
    Ok(SystemExceptionBody {
        exception_id: reader.read_string()?,
        minor_code: reader.read_u32()?,
        completion_status: CompletionStatus::from(reader.read_u32()?),
    })
}

fn read_tagged_profile<'a>(reader: &mut CdrReader<'a>) -> Result<TaggedProfile<'a>, CdrError> {
    Ok(TaggedProfile {
        tag: reader.read_u32()?,
        profile_data: reader.read_octet_sequence()?,
    })
}

fn read_tagged_profile_list<'a>(
    reader: &mut CdrReader<'a>,
) -> Result<Vec<TaggedProfile<'a>>, CdrError> {
    const TAGGED_PROFILE_MIN_LEN: usize = 8;

    let count_offset = reader.position();
    let count = reader.read_u32()? as usize;
    let remaining = reader.remaining();
    let max_possible_profiles = remaining / TAGGED_PROFILE_MIN_LEN;
    if count > max_possible_profiles {
        return Err(CdrError::SequenceLengthExceedsRemaining {
            offset: count_offset,
            declared: count as u32,
            remaining,
            element_min_size: TAGGED_PROFILE_MIN_LEN,
        });
    }

    let mut profiles = Vec::with_capacity(count);

    for _ in 0..count {
        profiles.push(read_tagged_profile(reader)?);
    }

    Ok(profiles)
}

fn read_ior<'a>(reader: &mut CdrReader<'a>) -> Result<Ior<'a>, CdrError> {
    Ok(Ior {
        type_id: reader.read_string()?,
        profiles: read_tagged_profile_list(reader)?,
    })
}

fn read_tagged_component<'a>(reader: &mut CdrReader<'a>) -> Result<TaggedComponent<'a>, CdrError> {
    Ok(TaggedComponent {
        tag: reader.read_u32()?,
        component_data: reader.read_octet_sequence()?,
    })
}

fn read_tagged_component_list<'a>(
    reader: &mut CdrReader<'a>,
) -> Result<Vec<TaggedComponent<'a>>, CdrError> {
    const TAGGED_COMPONENT_MIN_LEN: usize = 8;

    let count_offset = reader.position();
    let count = reader.read_u32()? as usize;
    let remaining = reader.remaining();
    let max_possible_components = remaining / TAGGED_COMPONENT_MIN_LEN;
    if count > max_possible_components {
        return Err(CdrError::SequenceLengthExceedsRemaining {
            offset: count_offset,
            declared: count as u32,
            remaining,
            element_min_size: TAGGED_COMPONENT_MIN_LEN,
        });
    }

    let mut components = Vec::with_capacity(count);

    for _ in 0..count {
        components.push(read_tagged_component(reader)?);
    }

    Ok(components)
}

pub fn read_iiop_profile_body(input: &[u8]) -> Result<IiopProfile<'_>, CdrError> {
    let mut reader = CdrReader::from_encapsulation(input)?;
    let version = Version {
        major: reader.read_octet()?,
        minor: reader.read_octet()?,
    };
    let host = reader.read_string()?;
    let port = reader.read_u16()?;
    let object_key = reader.read_octet_sequence()?;
    let components = if version.major == 1 && version.minor == 0 {
        Vec::new()
    } else {
        read_tagged_component_list(&mut reader)?
    };
    let remaining_offset = 1 + reader.position();

    Ok(IiopProfile {
        version,
        host,
        port,
        object_key,
        components,
        remaining: &input[remaining_offset..],
    })
}

pub fn read_request_1_0<'a>(frame: &ParsedMessage<'a>) -> Result<ParsedRequest10<'a>, GiopError> {
    if frame.header.message_type != MessageType::Request {
        return Err(GiopError::UnexpectedMessageType {
            expected: MessageType::Request,
            actual: frame.header.message_type,
        });
    }

    if frame.header.version != (Version { major: 1, minor: 0 }) {
        return Err(GiopError::UnsupportedVersion(frame.header.version));
    }

    let mut reader = frame.body_reader();
    let service_contexts = read_service_context_list(&mut reader)?;
    let request_id = reader.read_u32()?;
    let response_expected = reader.read_bool()?;
    let object_key = reader.read_octet_sequence()?;
    let operation = reader.read_string()?;
    let requesting_principal = reader.read_octet_sequence()?;
    if reader.remaining() > 0 {
        reader.align_to(8)?;
    }
    let arguments_offset = reader.position();

    Ok(ParsedRequest10 {
        service_contexts,
        request_id,
        response_expected,
        object_key,
        operation,
        requesting_principal,
        arguments: &frame.body[arguments_offset..],
        arguments_alignment_base: HEADER_LEN + arguments_offset,
        endian: frame.header.endian,
    })
}

pub fn read_request_1_1<'a>(frame: &ParsedMessage<'a>) -> Result<ParsedRequest11<'a>, GiopError> {
    if frame.header.message_type != MessageType::Request {
        return Err(GiopError::UnexpectedMessageType {
            expected: MessageType::Request,
            actual: frame.header.message_type,
        });
    }

    if frame.header.version != (Version { major: 1, minor: 1 }) {
        return Err(GiopError::UnsupportedVersion(frame.header.version));
    }

    let mut reader = frame.body_reader();
    let service_contexts = read_service_context_list(&mut reader)?;
    let request_id = reader.read_u32()?;
    let response_expected = reader.read_bool()?;
    let reserved_offset = reader.position();
    let reserved = [
        reader.read_octet()?,
        reader.read_octet()?,
        reader.read_octet()?,
    ];
    if reserved != [0, 0, 0] {
        return Err(GiopError::InvalidRequestReserved {
            offset: reserved_offset,
            reserved,
        });
    }
    let object_key = reader.read_octet_sequence()?;
    let operation = reader.read_string()?;
    let requesting_principal = reader.read_octet_sequence()?;
    if reader.remaining() > 0 {
        reader.align_to(8)?;
    }
    let arguments_offset = reader.position();

    Ok(ParsedRequest11 {
        service_contexts,
        request_id,
        response_expected,
        reserved,
        object_key,
        operation,
        requesting_principal,
        arguments: &frame.body[arguments_offset..],
        arguments_alignment_base: HEADER_LEN + arguments_offset,
        endian: frame.header.endian,
    })
}

pub fn read_reply_1_0<'a>(frame: &ParsedMessage<'a>) -> Result<ParsedReply10<'a>, GiopError> {
    read_reply_1_0_1_1(frame, Version { major: 1, minor: 0 })
}

pub fn read_reply_1_1<'a>(frame: &ParsedMessage<'a>) -> Result<ParsedReply11<'a>, GiopError> {
    read_reply_1_0_1_1(frame, Version { major: 1, minor: 1 })
}

fn read_reply_1_0_1_1<'a>(
    frame: &ParsedMessage<'a>,
    version: Version,
) -> Result<ParsedReply1_0_1_1<'a>, GiopError> {
    if frame.header.message_type != MessageType::Reply {
        return Err(GiopError::UnexpectedMessageType {
            expected: MessageType::Reply,
            actual: frame.header.message_type,
        });
    }

    if frame.header.version != version {
        return Err(GiopError::UnsupportedVersion(frame.header.version));
    }

    let mut reader = frame.body_reader();
    let service_contexts = read_service_context_list(&mut reader)?;
    let request_id = reader.read_u32()?;
    let status = ReplyStatus::from(reader.read_u32()?);
    if reader.remaining() > 0 {
        reader.align_to(8)?;
    }
    let body_offset = reader.position();

    Ok(ParsedReply1_0_1_1 {
        service_contexts,
        request_id,
        status,
        body: &frame.body[body_offset..],
        body_alignment_base: HEADER_LEN + body_offset,
        endian: frame.header.endian,
    })
}

pub fn read_reply_1_2<'a>(frame: &ParsedMessage<'a>) -> Result<ParsedReply12<'a>, GiopError> {
    if frame.header.message_type != MessageType::Reply {
        return Err(GiopError::UnexpectedMessageType {
            expected: MessageType::Reply,
            actual: frame.header.message_type,
        });
    }

    if frame.header.version != (Version { major: 1, minor: 2 }) {
        return Err(GiopError::UnsupportedVersion(frame.header.version));
    }

    let mut reader = frame.body_reader();
    let request_id = reader.read_u32()?;
    let status = ReplyStatus::from(reader.read_u32()?);
    let service_contexts = read_service_context_list(&mut reader)?;
    if reader.remaining() > 0 {
        reader.align_to(8)?;
    }
    let body_offset = reader.position();

    Ok(ParsedReply12 {
        service_contexts,
        request_id,
        status,
        body: &frame.body[body_offset..],
        body_alignment_base: HEADER_LEN + body_offset,
        endian: frame.header.endian,
    })
}

pub fn read_locate_request_1_2<'a>(
    frame: &ParsedMessage<'a>,
) -> Result<ParsedLocateRequest12<'a>, GiopError> {
    if frame.header.message_type != MessageType::LocateRequest {
        return Err(GiopError::UnexpectedMessageType {
            expected: MessageType::LocateRequest,
            actual: frame.header.message_type,
        });
    }

    if frame.header.version != (Version { major: 1, minor: 2 }) {
        return Err(GiopError::UnsupportedVersion(frame.header.version));
    }

    let mut reader = frame.body_reader();

    Ok(ParsedLocateRequest12 {
        request_id: reader.read_u32()?,
        target: read_target_address(&mut reader)?,
    })
}

pub fn read_locate_reply_1_2<'a>(
    frame: &ParsedMessage<'a>,
) -> Result<ParsedLocateReply12<'a>, GiopError> {
    if frame.header.message_type != MessageType::LocateReply {
        return Err(GiopError::UnexpectedMessageType {
            expected: MessageType::LocateReply,
            actual: frame.header.message_type,
        });
    }

    if frame.header.version != (Version { major: 1, minor: 2 }) {
        return Err(GiopError::UnsupportedVersion(frame.header.version));
    }

    let mut reader = frame.body_reader();
    let request_id = reader.read_u32()?;
    let status = LocateStatus::from(reader.read_u32()?);
    let body_offset = reader.position();

    Ok(ParsedLocateReply12 {
        request_id,
        status,
        body: &frame.body[body_offset..],
        body_alignment_base: HEADER_LEN + body_offset,
        endian: frame.header.endian,
    })
}

pub fn read_cancel_request(frame: &ParsedMessage<'_>) -> Result<ParsedCancelRequest, GiopError> {
    if frame.header.message_type != MessageType::CancelRequest {
        return Err(GiopError::UnexpectedMessageType {
            expected: MessageType::CancelRequest,
            actual: frame.header.message_type,
        });
    }

    let mut reader = frame.body_reader();

    Ok(ParsedCancelRequest {
        request_id: reader.read_u32()?,
    })
}

pub fn read_fragment_1_2<'a>(frame: &ParsedMessage<'a>) -> Result<ParsedFragment12<'a>, GiopError> {
    if frame.header.message_type != MessageType::Fragment {
        return Err(GiopError::UnexpectedMessageType {
            expected: MessageType::Fragment,
            actual: frame.header.message_type,
        });
    }

    if frame.header.version != (Version { major: 1, minor: 2 }) {
        return Err(GiopError::UnsupportedVersion(frame.header.version));
    }

    let mut reader = frame.body_reader();
    let request_id = reader.read_u32()?;
    let data_offset = reader.position();

    Ok(ParsedFragment12 {
        request_id,
        data: &frame.body[data_offset..],
        data_alignment_base: HEADER_LEN + data_offset,
        endian: frame.header.endian,
    })
}

pub fn read_message_typed<'a>(frame: &ParsedMessage<'a>) -> Result<ParsedGiop<'a>, GiopError> {
    match (frame.header.version.major, frame.header.version.minor) {
        (1, 0) => read_message_1_0(frame).map(ParsedGiop::Giop10),
        (1, 1) => read_message_1_1(frame).map(ParsedGiop::Giop11),
        (1, 2) => read_message_1_2(frame).map(ParsedGiop::Giop12),
        _ => Err(GiopError::UnsupportedVersion(frame.header.version)),
    }
}

pub fn read_message_1_0<'a>(frame: &ParsedMessage<'a>) -> Result<ParsedGiop10<'a>, GiopError> {
    if frame.header.version != (Version { major: 1, minor: 0 }) {
        return Err(GiopError::UnsupportedVersion(frame.header.version));
    }

    match frame.header.message_type {
        MessageType::Request => read_request_1_0(frame).map(ParsedGiop10::Request),
        MessageType::Reply => read_reply_1_0(frame).map(ParsedGiop10::Reply),
        MessageType::CancelRequest => read_cancel_request(frame).map(ParsedGiop10::CancelRequest),
        MessageType::CloseConnection => Ok(ParsedGiop10::CloseConnection),
        MessageType::MessageError => Ok(ParsedGiop10::MessageError),
        _ => Err(GiopError::UnsupportedMessageType(frame.header.message_type)),
    }
}

pub fn read_message_1_1<'a>(frame: &ParsedMessage<'a>) -> Result<ParsedGiop11<'a>, GiopError> {
    if frame.header.version != (Version { major: 1, minor: 1 }) {
        return Err(GiopError::UnsupportedVersion(frame.header.version));
    }

    match frame.header.message_type {
        MessageType::Request => read_request_1_1(frame).map(ParsedGiop11::Request),
        MessageType::Reply => read_reply_1_1(frame).map(ParsedGiop11::Reply),
        MessageType::CancelRequest => read_cancel_request(frame).map(ParsedGiop11::CancelRequest),
        MessageType::CloseConnection => Ok(ParsedGiop11::CloseConnection),
        MessageType::MessageError => Ok(ParsedGiop11::MessageError),
        _ => Err(GiopError::UnsupportedMessageType(frame.header.message_type)),
    }
}

pub fn read_message_1_2<'a>(frame: &ParsedMessage<'a>) -> Result<ParsedGiop12<'a>, GiopError> {
    if frame.header.version != (Version { major: 1, minor: 2 }) {
        return Err(GiopError::UnsupportedVersion(frame.header.version));
    }

    match frame.header.message_type {
        MessageType::Request => read_request_1_2(frame).map(ParsedGiop12::Request),
        MessageType::Reply => read_reply_1_2(frame).map(ParsedGiop12::Reply),
        MessageType::CancelRequest => read_cancel_request(frame).map(ParsedGiop12::CancelRequest),
        MessageType::LocateRequest => {
            read_locate_request_1_2(frame).map(ParsedGiop12::LocateRequest)
        }
        MessageType::LocateReply => read_locate_reply_1_2(frame).map(ParsedGiop12::LocateReply),
        MessageType::CloseConnection => Ok(ParsedGiop12::CloseConnection),
        MessageType::MessageError => Ok(ParsedGiop12::MessageError),
        MessageType::Fragment => read_fragment_1_2(frame).map(ParsedGiop12::Fragment),
        MessageType::Unknown(_) => {
            Err(GiopError::UnsupportedMessageType(frame.header.message_type))
        }
    }
}

pub fn parse_message_typed(input: &[u8]) -> Result<ParsedGiopMessage<'_>, GiopError> {
    let frame = parse_message(input)?;
    let header = frame.header;
    let remaining = frame.remaining;
    let message = read_message_typed(&frame)?;

    Ok(ParsedGiopMessage {
        header,
        message,
        remaining,
    })
}

pub fn parse_message_1_2(input: &[u8]) -> Result<ParsedGiop12Message<'_>, GiopError> {
    let frame = parse_message(input)?;
    let header = frame.header;
    let remaining = frame.remaining;
    let message = read_message_1_2(&frame)?;

    Ok(ParsedGiop12Message {
        header,
        message,
        remaining,
    })
}

pub fn parse_messages_1_2(input: &[u8]) -> Giop12Messages<'_> {
    Giop12Messages { remaining: input }
}

pub fn reassemble_messages_1_2(
    input: &[u8],
) -> Result<Vec<ReassembledGiop12Message>, GiopReassemblyError> {
    let mut output = Vec::new();
    let mut open: Option<OpenFragmentedMessage> = None;
    let mut remaining = input;
    let mut offset = 0_usize;

    while !remaining.is_empty() {
        let frame = parse_message(remaining)?;
        if frame.header.version != (Version { major: 1, minor: 2 }) {
            return Err(GiopReassemblyError::Giop(GiopError::UnsupportedVersion(
                frame.header.version,
            )));
        }

        let frame_len = HEADER_LEN + frame.body.len();
        let range = GiopFrameRange {
            offset,
            len: frame_len,
            message_type: frame.header.message_type,
            fragmented: frame.header.fragmented,
        };

        match frame.header.message_type {
            MessageType::Fragment => {
                let fragment = read_fragment_1_2(&frame)?;
                let Some(open_message) = open.as_mut() else {
                    return Err(GiopReassemblyError::FragmentWithoutInitial {
                        request_id: fragment.request_id,
                        offset,
                    });
                };
                if fragment.request_id != open_message.request_id {
                    return Err(GiopReassemblyError::FragmentRequestIdMismatch {
                        expected: open_message.request_id,
                        actual: fragment.request_id,
                        offset,
                    });
                }

                open_message.body.extend_from_slice(fragment.data);
                open_message.frame_ranges.push(range);

                if !frame.header.fragmented {
                    let mut completed = open.take().expect("open message is present");
                    completed.header.fragmented = false;
                    completed.header.body_len = completed.body.len() as u32;
                    output.push(ReassembledGiop12Message {
                        header: completed.header,
                        body: completed.body,
                        frame_ranges: completed.frame_ranges,
                    });
                }
            }
            _ if frame.header.fragmented => {
                let request_id = request_id_for_fragmented_initial(&frame)?;
                if open.is_some() {
                    return Err(GiopReassemblyError::DuplicateInitial { request_id, offset });
                }
                open = Some(OpenFragmentedMessage {
                    request_id,
                    header: frame.header,
                    body: frame.body.to_vec(),
                    frame_ranges: vec![range],
                });
            }
            _ => output.push(ReassembledGiop12Message {
                header: frame.header,
                body: frame.body.to_vec(),
                frame_ranges: vec![range],
            }),
        }

        remaining = frame.remaining;
        offset += frame_len;
    }

    if let Some(open_message) = open {
        return Err(GiopReassemblyError::UnfinishedFragmentedMessage {
            request_id: open_message.request_id,
        });
    }

    Ok(output)
}

fn request_id_for_fragmented_initial(frame: &ParsedMessage<'_>) -> Result<u32, GiopError> {
    let mut reader = frame.body_reader();
    match frame.header.message_type {
        MessageType::Request
        | MessageType::Reply
        | MessageType::LocateRequest
        | MessageType::LocateReply
        | MessageType::CancelRequest => reader.read_u32().map_err(GiopError::from),
        _ => Err(GiopError::UnsupportedMessageType(frame.header.message_type)),
    }
}

pub fn read_request_1_2<'a>(frame: &ParsedMessage<'a>) -> Result<ParsedRequest12<'a>, GiopError> {
    if frame.header.message_type != MessageType::Request {
        return Err(GiopError::UnexpectedMessageType {
            expected: MessageType::Request,
            actual: frame.header.message_type,
        });
    }

    if frame.header.version != (Version { major: 1, minor: 2 }) {
        return Err(GiopError::UnsupportedVersion(frame.header.version));
    }

    let mut reader = frame.body_reader();
    let request_id = reader.read_u32()?;
    let response_flags = reader.read_octet()?;
    let reserved_offset = reader.position();
    let reserved = [
        reader.read_octet()?,
        reader.read_octet()?,
        reader.read_octet()?,
    ];
    if reserved != [0, 0, 0] {
        return Err(GiopError::InvalidRequestReserved {
            offset: reserved_offset,
            reserved,
        });
    }

    let target = read_target_address(&mut reader)?;
    let operation = reader.read_string()?;
    let service_contexts = read_service_context_list(&mut reader)?;
    if reader.remaining() > 0 {
        reader.align_to(8)?;
    }
    let arguments_offset = reader.position();

    Ok(ParsedRequest12 {
        service_contexts,
        request_id,
        response_flags,
        target,
        operation,
        arguments: &frame.body[arguments_offset..],
        arguments_alignment_base: HEADER_LEN + arguments_offset,
        endian: frame.header.endian,
    })
}

fn read_target_address<'a>(reader: &mut CdrReader<'a>) -> Result<TargetAddress<'a>, GiopError> {
    let disposition = reader.read_i16()?;
    match disposition {
        0 => Ok(TargetAddress::KeyAddr(reader.read_octet_sequence()?)),
        1 => Ok(TargetAddress::ProfileAddr(read_tagged_profile(reader)?)),
        2 => Ok(TargetAddress::ReferenceAddr(IorAddressingInfo {
            selected_profile_index: reader.read_u32()?,
            ior: read_ior(reader)?,
        })),
        _ => Err(GiopError::UnsupportedTargetAddress { disposition }),
    }
}
