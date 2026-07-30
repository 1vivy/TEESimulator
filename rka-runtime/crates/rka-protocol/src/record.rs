//! Length-prefixed TLS stream records.

use crate::{MAX_FRAME_BYTES, ProtocolError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Payload<'a>(&'a [u8]);

impl<'a> Payload<'a> {
    pub const fn parse(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        if bytes.is_empty() {
            return Err(ProtocolError::EmptyPayload);
        }
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(ProtocolError::PayloadTooLarge {
                actual: bytes.len(),
                maximum: MAX_FRAME_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record<'a> {
    payload: &'a [u8],
}

impl<'a> Record<'a> {
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

pub fn decode_record(bytes: &[u8]) -> Result<Record<'_>, ProtocolError> {
    let prefix = bytes.get(..4).ok_or(ProtocolError::Truncated)?;
    let declared = u32::from_be_bytes(
        prefix
            .try_into()
            .map_err(|_| ProtocolError::RecordLengthMismatch)?,
    );
    let declared = usize::try_from(declared).map_err(|_| ProtocolError::PayloadTooLarge {
        actual: usize::MAX,
        maximum: MAX_FRAME_BYTES,
    })?;
    if declared == 0 {
        return Err(ProtocolError::EmptyPayload);
    }
    if declared > MAX_FRAME_BYTES {
        return Err(ProtocolError::PayloadTooLarge {
            actual: declared,
            maximum: MAX_FRAME_BYTES,
        });
    }
    let payload = bytes.get(4..).ok_or(ProtocolError::Truncated)?;
    if payload.len() != declared {
        return Err(ProtocolError::RecordLengthMismatch);
    }
    Ok(Record { payload })
}

pub fn encode_record(payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if payload.is_empty() {
        return Err(ProtocolError::EmptyPayload);
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::PayloadTooLarge {
            actual: payload.len(),
            maximum: MAX_FRAME_BYTES,
        });
    }
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::PayloadTooLarge {
        actual: payload.len(),
        maximum: MAX_FRAME_BYTES,
    })?;
    let mut record = Vec::with_capacity(payload.len().saturating_add(4));
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(payload);
    Ok(record)
}
