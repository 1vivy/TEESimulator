use rka_protocol::{CborWriter, validate_deterministic_cbor};

use crate::StateError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReplayNamespace {
    Opaque,
    Session,
    Request,
}

impl ReplayNamespace {
    const fn tag(self) -> u64 {
        match self {
            Self::Opaque => 0,
            Self::Session => 1,
            Self::Request => 2,
        }
    }

    const fn parse(value: u64) -> Result<Self, StateError> {
        match value {
            0 => Ok(Self::Opaque),
            1 => Ok(Self::Session),
            2 => Ok(Self::Request),
            _ => Err(StateError::Corrupt),
        }
    }

    const fn valid_id(self, id: &[u8]) -> bool {
        match self {
            Self::Opaque => id.is_empty(),
            Self::Session => id.len() == 32,
            Self::Request => id.len() == 16,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Tombstone {
    pub key: Vec<u8>,
    pub seconds: u64,
    pub epoch: u64,
    pub namespace: ReplayNamespace,
    pub id: Vec<u8>,
}

pub fn encode(entries: &[Tombstone]) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(entries.len().saturating_mul(112));
    writer.array(entries.len());
    for entry in entries {
        writer.array(5);
        writer.unsigned(entry.seconds);
        writer.unsigned(entry.epoch);
        writer.bytes(&entry.key);
        writer.unsigned(entry.namespace.tag());
        writer.bytes(&entry.id);
    }
    writer.finish()
}

pub fn decode(bytes: &[u8], maximum: usize) -> Result<Vec<Tombstone>, StateError> {
    validate_deterministic_cbor(bytes).map_err(|_| StateError::Corrupt)?;
    let mut decoder = Decoder::new(bytes);
    let count = decoder.array()?;
    if count > maximum {
        return Err(StateError::Corrupt);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if decoder.array()? != 5 {
            return Err(StateError::Corrupt);
        }
        let entry = Tombstone {
            seconds: decoder.unsigned()?,
            epoch: decoder.unsigned()?,
            key: decoder.bytes()?.to_vec(),
            namespace: ReplayNamespace::parse(decoder.unsigned()?)?,
            id: decoder.bytes()?.to_vec(),
        };
        if entry.key.is_empty()
            || !entry.namespace.valid_id(&entry.id)
            || entries.iter().any(|seen: &Tombstone| {
                seen.key == entry.key
                    || (entry.namespace != ReplayNamespace::Opaque
                        && seen.namespace == entry.namespace
                        && seen.id == entry.id)
            })
        {
            return Err(StateError::Corrupt);
        }
        entries.push(entry);
    }
    if decoder.complete() {
        Ok(entries)
    } else {
        Err(StateError::Corrupt)
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array(&mut self) -> Result<usize, StateError> {
        let (major, length) = self.header()?;
        if major != 4 {
            return Err(StateError::Corrupt);
        }
        usize::try_from(length).map_err(|_| StateError::Corrupt)
    }

    fn unsigned(&mut self) -> Result<u64, StateError> {
        let (major, value) = self.header()?;
        if major == 0 {
            Ok(value)
        } else {
            Err(StateError::Corrupt)
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8], StateError> {
        let (major, length) = self.header()?;
        if major != 2 {
            return Err(StateError::Corrupt);
        }
        self.take(usize::try_from(length).map_err(|_| StateError::Corrupt)?)
    }

    const fn complete(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn header(&mut self) -> Result<(u8, u64), StateError> {
        let initial = *self.bytes.get(self.offset).ok_or(StateError::Corrupt)?;
        self.offset = self.offset.checked_add(1).ok_or(StateError::Corrupt)?;
        let additional = initial & 0x1f;
        let value = match additional {
            value @ 0..=23 => u64::from(value),
            24 => self.argument(1, 24)?,
            25 => self.argument(2, 256)?,
            26 => self.argument(4, 65_536)?,
            27 => self.argument(8, 4_294_967_296)?,
            _ => return Err(StateError::Corrupt),
        };
        Ok((initial >> 5, value))
    }

    fn argument(&mut self, width: usize, minimum: u64) -> Result<u64, StateError> {
        let value = self
            .take(width)?
            .iter()
            .fold(0_u64, |current, byte| (current << 8) | u64::from(*byte));
        if value < minimum {
            return Err(StateError::Corrupt);
        }
        Ok(value)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StateError> {
        let end = self.offset.checked_add(length).ok_or(StateError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(StateError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }
}
