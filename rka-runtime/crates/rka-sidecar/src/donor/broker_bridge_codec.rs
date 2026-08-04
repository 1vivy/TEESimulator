use rka_protocol::{HashDomain, hash_bytes};

use super::{BrokerFailure, GeneratedKey, RemoteKeyHandle};

pub(super) fn decode_public_key(response: &[u8]) -> Result<GeneratedKey, BrokerFailure> {
    let mut cursor = Cursor::new(response);
    let handle = RemoteKeyHandle::new(cursor.array()?);
    let spki = cursor.bytes(1, 65_536)?;
    let count = usize::from(cursor.u8()?);
    if !(2..=20).contains(&count) {
        return Err(BrokerFailure::Rejected);
    }
    let mut chain = Vec::with_capacity(count);
    for _ in 0..count {
        chain.push(cursor.bytes(1, 65_536)?);
    }
    let transcript_signature = cursor.bytes(1, 65_536)?;
    cursor.finish()?;
    Ok(GeneratedKey::new(
        handle,
        chain,
        hash_bytes(HashDomain::RkpPublic, &spki),
        super::broker_characteristics::exact_characteristics_hash(),
    )
    .with_transcript_signature(transcript_signature))
}

pub(super) fn decode_update(response: &[u8]) -> Result<(usize, Vec<u8>), BrokerFailure> {
    let mut cursor = Cursor::new(response);
    let consumed = usize::try_from(cursor.u32()?).map_err(|_| BrokerFailure::Rejected)?;
    let output = cursor.bytes(0, 65_536)?;
    cursor.finish()?;
    Ok((consumed, output))
}

pub(super) fn decode_finish(response: &[u8]) -> Result<Vec<u8>, BrokerFailure> {
    let mut cursor = Cursor::new(response);
    let signature = cursor.bytes(1, 65_536)?;
    cursor.finish()?;
    Ok(signature)
}

pub(super) fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), BrokerFailure> {
    let length = u32::try_from(value.len()).map_err(|_| BrokerFailure::Rejected)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BrokerFailure> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BrokerFailure::Rejected)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BrokerFailure::Rejected)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BrokerFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| BrokerFailure::Rejected)
    }

    fn u8(&mut self) -> Result<u8, BrokerFailure> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(BrokerFailure::Rejected)
    }

    fn u32(&mut self) -> Result<u32, BrokerFailure> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn bytes(&mut self, minimum: usize, maximum: usize) -> Result<Vec<u8>, BrokerFailure> {
        let length = usize::try_from(self.u32()?).map_err(|_| BrokerFailure::Rejected)?;
        if length < minimum || length > maximum {
            return Err(BrokerFailure::Rejected);
        }
        Ok(self.take(length)?.to_vec())
    }

    const fn finish(self) -> Result<(), BrokerFailure> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BrokerFailure::Rejected)
        }
    }
}
