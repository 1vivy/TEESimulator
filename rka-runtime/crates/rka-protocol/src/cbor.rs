//! Deterministic RFC 8949 primitives.

use crate::{MAX_FRAME_BYTES, ProtocolError};

#[derive(Debug)]
pub struct CborReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CborReader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) const fn is_complete(&self) -> bool {
        self.offset == self.bytes.len()
    }

    pub(crate) const fn position(&self) -> usize {
        self.offset
    }

    pub(crate) fn peek(&self) -> Result<u8, ProtocolError> {
        self.bytes
            .get(self.offset)
            .copied()
            .ok_or(ProtocolError::Truncated)
    }

    pub(crate) fn skip_item(&mut self) -> Result<(), ProtocolError> {
        crate::cbor_validate::validate_item(self, 1)
    }

    pub(crate) fn slice_from(&self, start: usize) -> Result<&'a [u8], ProtocolError> {
        self.bytes
            .get(start..self.offset)
            .ok_or(ProtocolError::Truncated)
    }

    pub(crate) fn unsigned(&mut self) -> Result<u64, ProtocolError> {
        let (major, value) = self.header()?;
        if major != 0 {
            return Err(ProtocolError::WrongType);
        }
        Ok(value)
    }

    pub(crate) fn map(&mut self) -> Result<usize, ProtocolError> {
        self.collection(5)
    }

    pub(crate) fn array(&mut self) -> Result<usize, ProtocolError> {
        self.collection(4)
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], ProtocolError> {
        let (major, length) = self.header()?;
        if major != 2 {
            return Err(ProtocolError::WrongType);
        }
        self.take(length)
    }

    pub(crate) fn text(&mut self) -> Result<&'a str, ProtocolError> {
        let (major, length) = self.header()?;
        if major != 3 {
            return Err(ProtocolError::WrongType);
        }
        core::str::from_utf8(self.take(length)?).map_err(|_| ProtocolError::WrongType)
    }

    pub(crate) fn boolean(&mut self) -> Result<bool, ProtocolError> {
        let value = *self
            .bytes
            .get(self.offset)
            .ok_or(ProtocolError::Truncated)?;
        self.offset = self.offset.saturating_add(1);
        match value {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(ProtocolError::WrongType),
        }
    }

    fn collection(&mut self, expected: u8) -> Result<usize, ProtocolError> {
        let (major, length) = self.header()?;
        if major != expected {
            return Err(ProtocolError::WrongType);
        }
        usize::try_from(length).map_err(|_| ProtocolError::LengthOutOfRange)
    }

    fn take(&mut self, length: u64) -> Result<&'a [u8], ProtocolError> {
        let length = usize::try_from(length).map_err(|_| ProtocolError::LengthOutOfRange)?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ProtocolError::LengthOutOfRange)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtocolError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn header(&mut self) -> Result<(u8, u64), ProtocolError> {
        let initial = *self
            .bytes
            .get(self.offset)
            .ok_or(ProtocolError::Truncated)?;
        self.offset = self
            .offset
            .checked_add(1)
            .ok_or(ProtocolError::LengthOutOfRange)?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let value = match additional {
            value @ 0..=23 => u64::from(value),
            24 => self.read_argument(1, 24)?,
            25 => self.read_argument(2, 256)?,
            26 => self.read_argument(4, 65_536)?,
            27 => self.read_argument(8, 4_294_967_296)?,
            31 => return Err(ProtocolError::IndefiniteLength),
            _ => return Err(ProtocolError::NonCanonical),
        };
        Ok((major, value))
    }

    fn read_argument(&mut self, width: usize, minimum: u64) -> Result<u64, ProtocolError> {
        let bytes =
            self.take(u64::try_from(width).map_err(|_| ProtocolError::LengthOutOfRange)?)?;
        let value = bytes.iter().fold(0_u64, |accumulator, byte| {
            (accumulator << 8) | u64::from(*byte)
        });
        if value < minimum {
            return Err(ProtocolError::NonCanonical);
        }
        Ok(value)
    }
}

#[derive(Debug, Default)]
pub struct CborWriter {
    bytes: Vec<u8>,
}

impl CborWriter {
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity.min(MAX_FRAME_BYTES)),
        }
    }

    pub fn unsigned(&mut self, value: u64) {
        self.header(0, value);
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.header(
            2,
            u64::try_from(value.len()).map_or(u64::MAX, |length| length),
        );
        self.bytes.extend_from_slice(value);
    }

    pub fn text(&mut self, value: &str) {
        self.header(
            3,
            u64::try_from(value.len()).map_or(u64::MAX, |length| length),
        );
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub fn array(&mut self, length: usize) {
        self.header(4, u64::try_from(length).map_or(u64::MAX, |value| value));
    }

    pub fn map(&mut self, length: usize) {
        self.header(5, u64::try_from(length).map_or(u64::MAX, |value| value));
    }

    pub fn boolean(&mut self, value: bool) {
        self.bytes.push(if value { 0xf5 } else { 0xf4 });
    }

    pub(crate) fn raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn header(&mut self, major: u8, value: u64) {
        let prefix = major << 5;
        match value {
            0..=23 => self
                .bytes
                .push(prefix | u8::try_from(value).map_or(23, |byte| byte)),
            24..=255 => {
                self.bytes.push(prefix | 0x18);
                self.bytes
                    .push(u8::try_from(value).map_or(u8::MAX, |byte| byte));
            }
            256..=65_535 => {
                self.bytes.push(prefix | 0x19);
                self.bytes.extend_from_slice(
                    &u16::try_from(value)
                        .map_or(u16::MAX, |number| number)
                        .to_be_bytes(),
                );
            }
            65_536..=4_294_967_295 => {
                self.bytes.push(prefix | 0x1a);
                self.bytes.extend_from_slice(
                    &u32::try_from(value)
                        .map_or(u32::MAX, |number| number)
                        .to_be_bytes(),
                );
            }
            _ => {
                self.bytes.push(prefix | 0x1b);
                self.bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
}
