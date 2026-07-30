//! Frozen message, capability, and lifecycle state types.

use crate::{ProtocolError, REQUIRED_CAPABILITIES};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum MessageKind {
    Hello = 1,
    HelloAck = 2,
    Generate = 10,
    Get = 11,
    List = 12,
    Delete = 13,
    Begin = 20,
    UpdateAad = 21,
    Update = 22,
    Finish = 23,
    Abort = 24,
    Result = 30,
    Error = 31,
}

impl TryFrom<u64> for MessageKind {
    type Error = ProtocolError;

    fn try_from(value: u64) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::HelloAck),
            10 => Ok(Self::Generate),
            11 => Ok(Self::Get),
            12 => Ok(Self::List),
            13 => Ok(Self::Delete),
            20 => Ok(Self::Begin),
            21 => Ok(Self::UpdateAad),
            22 => Ok(Self::Update),
            23 => Ok(Self::Finish),
            24 => Ok(Self::Abort),
            30 => Ok(Self::Result),
            31 => Ok(Self::Error),
            _ => Err(ProtocolError::UnsupportedValue),
        }
    }
}

impl From<MessageKind> for u64 {
    fn from(value: MessageKind) -> Self {
        match value {
            MessageKind::Hello => 1,
            MessageKind::HelloAck => 2,
            MessageKind::Generate => 10,
            MessageKind::Get => 11,
            MessageKind::List => 12,
            MessageKind::Delete => 13,
            MessageKind::Begin => 20,
            MessageKind::UpdateAad => 21,
            MessageKind::Update => 22,
            MessageKind::Finish => 23,
            MessageKind::Abort => 24,
            MessageKind::Result => 30,
            MessageKind::Error => 31,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityBitmap(u64);

impl CapabilityBitmap {
    pub const REQUIRED: Self = Self(REQUIRED_CAPABILITIES);

    pub const fn parse(value: u64) -> Result<Self, ProtocolError> {
        if value == REQUIRED_CAPABILITIES {
            Ok(Self(value))
        } else {
            Err(ProtocolError::UnsupportedValue)
        }
    }

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestId([u8; 16]);

impl RequestId {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId([u8; 32]);

impl SessionId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum AliasState {
    Active = 1,
    Lost = 2,
    Quarantined = 3,
    Deleted = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProtocolState {
    New,
    Established,
    OperationLive,
    Finished,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Transition {
    SendHello,
    AcceptHello,
    Begin,
    Abort,
    Finish,
    Close,
}

impl ProtocolState {
    pub const fn transition(self, transition: Transition) -> Result<Self, ProtocolError> {
        match (self, transition) {
            (Self::New, Transition::SendHello) => Ok(Self::New),
            (Self::New, Transition::AcceptHello) | (Self::OperationLive, Transition::Abort) => {
                Ok(Self::Established)
            }
            (Self::Established, Transition::Begin) => Ok(Self::OperationLive),
            (Self::OperationLive, Transition::Finish) => Ok(Self::Finished),
            (Self::Established | Self::Finished, Transition::Close) => Ok(Self::Closed),
            _ => Err(ProtocolError::InvalidTransition),
        }
    }
}
