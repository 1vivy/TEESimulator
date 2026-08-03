//! Atomic current/next state for a candidate-owned synthetic RKP lease.

use std::fmt;

use ring::digest::{Context, SHA256};
use thiserror::Error;
use zeroize::Zeroize;

pub const MAX_SYNTHETIC_LEASE_STATE_BYTES: usize = 1_048_576;
pub const MAX_SYNTHETIC_LEASE_PKCS8_BYTES: usize = 4_096;
pub const MAX_SYNTHETIC_LEASE_CERTIFICATE_BYTES: usize = 65_536;
pub const MAX_SYNTHETIC_LEASE_CHAIN_BYTES: usize = 524_288;
pub const MAX_SYNTHETIC_LEASE_CERTIFICATES: usize = 20;

const MAGIC: &[u8; 5] = b"RKSL\x01";

/// Secret candidate lease material. Debug output is intentionally metadata-only.
pub struct SyntheticLeaseBundle {
    epoch: u64,
    profile_id_hash: [u8; 32],
    peer_spki_hash: [u8; 32],
    not_before_millis: u64,
    not_after_millis: u64,
    lease_id: [u8; 32],
    private_key_pkcs8: Vec<u8>,
    public_spki: Vec<u8>,
    certificate_chain: Vec<Vec<u8>>,
}

impl SyntheticLeaseBundle {
    /// Validates and owns one complete candidate lease.
    #[allow(
        clippy::too_many_arguments,
        reason = "the frozen lease record binds all security-relevant metadata"
    )]
    pub fn new(
        epoch: u64,
        profile_id_hash: [u8; 32],
        peer_spki_hash: [u8; 32],
        not_before_millis: u64,
        not_after_millis: u64,
        private_key_pkcs8: Vec<u8>,
        public_spki: Vec<u8>,
        certificate_chain: Vec<Vec<u8>>,
        now_millis: u64,
    ) -> Result<Self, SyntheticLeaseError> {
        validate_material(
            &private_key_pkcs8,
            &public_spki,
            &certificate_chain,
            not_before_millis,
            not_after_millis,
            now_millis,
        )?;
        let lease_id = derive_lease_id(
            epoch,
            &profile_id_hash,
            &peer_spki_hash,
            not_before_millis,
            not_after_millis,
            &public_spki,
            &certificate_chain,
        );
        Ok(Self {
            epoch,
            profile_id_hash,
            peer_spki_hash,
            not_before_millis,
            not_after_millis,
            lease_id,
            private_key_pkcs8,
            public_spki,
            certificate_chain,
        })
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn profile_id_hash(&self) -> &[u8; 32] {
        &self.profile_id_hash
    }

    pub const fn peer_spki_hash(&self) -> &[u8; 32] {
        &self.peer_spki_hash
    }

    pub const fn not_before_millis(&self) -> u64 {
        self.not_before_millis
    }

    pub const fn not_after_millis(&self) -> u64 {
        self.not_after_millis
    }

    pub const fn lease_id(&self) -> &[u8; 32] {
        &self.lease_id
    }

    pub fn private_key_pkcs8(&self) -> &[u8] {
        &self.private_key_pkcs8
    }

    pub fn public_spki(&self) -> &[u8] {
        &self.public_spki
    }

    pub fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.certificate_chain
    }

    fn encode(&self, output: &mut Vec<u8>) -> Result<(), SyntheticLeaseError> {
        output.extend_from_slice(&self.epoch.to_be_bytes());
        output.extend_from_slice(&self.profile_id_hash);
        output.extend_from_slice(&self.peer_spki_hash);
        output.extend_from_slice(&self.not_before_millis.to_be_bytes());
        output.extend_from_slice(&self.not_after_millis.to_be_bytes());
        output.extend_from_slice(&self.lease_id);
        put_u16_bytes(output, &self.private_key_pkcs8)?;
        put_u16_bytes(output, &self.public_spki)?;
        output.push(
            u8::try_from(self.certificate_chain.len()).map_err(|_| SyntheticLeaseError::Invalid)?,
        );
        for certificate in &self.certificate_chain {
            put_u32_bytes(output, certificate)?;
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor<'_>, now_millis: u64) -> Result<Self, SyntheticLeaseError> {
        let epoch = cursor.u64()?;
        let profile_id_hash = cursor.array()?;
        let peer_spki_hash = cursor.array()?;
        let not_before_millis = cursor.u64()?;
        let not_after_millis = cursor.u64()?;
        let stored_lease_id = cursor.array()?;
        let private_key_pkcs8 = cursor
            .u16_bytes(1, MAX_SYNTHETIC_LEASE_PKCS8_BYTES)?
            .to_vec();
        let public_spki = cursor
            .u16_bytes(1, MAX_SYNTHETIC_LEASE_CERTIFICATE_BYTES)?
            .to_vec();
        let count = usize::from(cursor.u8()?);
        if !(2..=MAX_SYNTHETIC_LEASE_CERTIFICATES).contains(&count) {
            return Err(SyntheticLeaseError::Invalid);
        }
        let mut certificate_chain = Vec::new();
        certificate_chain
            .try_reserve_exact(count)
            .map_err(|_| SyntheticLeaseError::Capacity)?;
        let mut chain_bytes = 0_usize;
        for _ in 0..count {
            let certificate = cursor
                .u32_bytes(1, MAX_SYNTHETIC_LEASE_CERTIFICATE_BYTES)?
                .to_vec();
            chain_bytes = chain_bytes
                .checked_add(certificate.len())
                .ok_or(SyntheticLeaseError::Capacity)?;
            if chain_bytes > MAX_SYNTHETIC_LEASE_CHAIN_BYTES {
                return Err(SyntheticLeaseError::Capacity);
            }
            certificate_chain.push(certificate);
        }
        let bundle = Self::new(
            epoch,
            profile_id_hash,
            peer_spki_hash,
            not_before_millis,
            not_after_millis,
            private_key_pkcs8,
            public_spki,
            certificate_chain,
            now_millis,
        )?;
        if bundle.lease_id != stored_lease_id {
            return Err(SyntheticLeaseError::Tampered);
        }
        Ok(bundle)
    }
}

impl fmt::Debug for SyntheticLeaseBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticLeaseBundle")
            .field("epoch", &self.epoch)
            .field("certificate_count", &self.certificate_chain.len())
            .field("private_key", &"redacted")
            .finish_non_exhaustive()
    }
}

impl Drop for SyntheticLeaseBundle {
    fn drop(&mut self) {
        self.private_key_pkcs8.zeroize();
        self.public_spki.zeroize();
        self.certificate_chain.iter_mut().for_each(Zeroize::zeroize);
        self.profile_id_hash.zeroize();
        self.peer_spki_hash.zeroize();
        self.lease_id.zeroize();
    }
}

/// Result of installing a received lease bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::exhaustive_enums,
    reason = "the persisted installation receipt has exactly three frozen outcomes"
)]
pub enum SyntheticLeaseInstall {
    Current,
    Next,
    Duplicate,
}

/// One atomic optional-current/optional-next candidate lease record.
#[derive(Debug, Default)]
pub struct SyntheticLeaseState {
    current: Option<SyntheticLeaseBundle>,
    next: Option<SyntheticLeaseBundle>,
}

impl SyntheticLeaseState {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            current: None,
            next: None,
        }
    }

    pub const fn current(&self) -> Option<&SyntheticLeaseBundle> {
        self.current.as_ref()
    }

    pub const fn next(&self) -> Option<&SyntheticLeaseBundle> {
        self.next.as_ref()
    }

    pub fn next_epoch(&self) -> Result<u64, SyntheticLeaseError> {
        match (&self.current, &self.next) {
            (None, None) => Ok(0),
            (Some(current), None) => current
                .epoch
                .checked_add(1)
                .ok_or(SyntheticLeaseError::EpochGap),
            (Some(_), Some(_)) => Err(SyntheticLeaseError::NextOccupied),
            (None, Some(_)) => Err(SyntheticLeaseError::Corrupt),
        }
    }

    pub fn install(
        &mut self,
        bundle: SyntheticLeaseBundle,
    ) -> Result<SyntheticLeaseInstall, SyntheticLeaseError> {
        let Some(current) = self.current.as_ref() else {
            if self.next.is_some() || bundle.epoch != 0 {
                return Err(SyntheticLeaseError::EpochGap);
            }
            self.current = Some(bundle);
            return Ok(SyntheticLeaseInstall::Current);
        };
        if bundle.epoch == current.epoch {
            return if bundle.lease_id == current.lease_id {
                Ok(SyntheticLeaseInstall::Duplicate)
            } else {
                Err(SyntheticLeaseError::Replay)
            };
        }
        let expected = current
            .epoch
            .checked_add(1)
            .ok_or(SyntheticLeaseError::EpochGap)?;
        if bundle.epoch < expected {
            return Err(SyntheticLeaseError::Downgrade);
        }
        if bundle.epoch > expected {
            return Err(SyntheticLeaseError::EpochGap);
        }
        if let Some(next) = self.next.as_ref() {
            return if bundle.lease_id == next.lease_id {
                Ok(SyntheticLeaseInstall::Duplicate)
            } else {
                Err(SyntheticLeaseError::Replay)
            };
        }
        self.next = Some(bundle);
        Ok(SyntheticLeaseInstall::Next)
    }

    pub fn promote(&mut self) -> Result<(), SyntheticLeaseError> {
        let next = self.next.take().ok_or(SyntheticLeaseError::MissingNext)?;
        self.current = Some(next);
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, SyntheticLeaseError> {
        if self.current.is_none() && self.next.is_some() {
            return Err(SyntheticLeaseError::Corrupt);
        }
        let mut output = Vec::new();
        output
            .try_reserve(4_096)
            .map_err(|_| SyntheticLeaseError::Capacity)?;
        output.extend_from_slice(MAGIC);
        output.push(u8::from(self.current.is_some()));
        output.push(u8::from(self.next.is_some()));
        if let Some(current) = &self.current {
            current.encode(&mut output)?;
        }
        if let Some(next) = &self.next {
            next.encode(&mut output)?;
        }
        if output.len() > MAX_SYNTHETIC_LEASE_STATE_BYTES {
            return Err(SyntheticLeaseError::Capacity);
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8], now_millis: u64) -> Result<Self, SyntheticLeaseError> {
        if bytes.len() > MAX_SYNTHETIC_LEASE_STATE_BYTES {
            return Err(SyntheticLeaseError::Capacity);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(MAGIC.len())? != MAGIC {
            return Err(SyntheticLeaseError::Corrupt);
        }
        let current_present = cursor.flag()?;
        let next_present = cursor.flag()?;
        if !current_present && next_present {
            return Err(SyntheticLeaseError::Corrupt);
        }
        let current = current_present
            .then(|| SyntheticLeaseBundle::decode(&mut cursor, now_millis))
            .transpose()?;
        let next = next_present
            .then(|| SyntheticLeaseBundle::decode(&mut cursor, now_millis))
            .transpose()?;
        cursor.finish()?;
        if let (Some(current), Some(next)) = (&current, &next)
            && (current.epoch.checked_add(1) != Some(next.epoch)
                || current.profile_id_hash != next.profile_id_hash
                || current.peer_spki_hash != next.peer_spki_hash)
        {
            return Err(SyntheticLeaseError::EpochGap);
        }
        Ok(Self { current, next })
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum SyntheticLeaseError {
    #[error("synthetic lease is invalid")]
    Invalid,
    #[error("synthetic lease is expired")]
    Expired,
    #[error("synthetic lease record is corrupt")]
    Corrupt,
    #[error("synthetic lease record was tampered")]
    Tampered,
    #[error("synthetic lease replay was rejected")]
    Replay,
    #[error("synthetic lease downgrade was rejected")]
    Downgrade,
    #[error("synthetic lease epoch gap was rejected")]
    EpochGap,
    #[error("synthetic lease next slot is occupied")]
    NextOccupied,
    #[error("synthetic lease next slot is missing")]
    MissingNext,
    #[error("synthetic lease capacity was exceeded")]
    Capacity,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the frozen lease validation binds secret, public, chain, and validity fields"
)]
fn validate_material(
    private_key_pkcs8: &[u8],
    public_spki: &[u8],
    certificate_chain: &[Vec<u8>],
    not_before_millis: u64,
    not_after_millis: u64,
    now_millis: u64,
) -> Result<(), SyntheticLeaseError> {
    if private_key_pkcs8.is_empty()
        || private_key_pkcs8.len() > MAX_SYNTHETIC_LEASE_PKCS8_BYTES
        || public_spki.is_empty()
        || public_spki.len() > MAX_SYNTHETIC_LEASE_CERTIFICATE_BYTES
        || !(2..=MAX_SYNTHETIC_LEASE_CERTIFICATES).contains(&certificate_chain.len())
        || not_after_millis <= not_before_millis
        || now_millis < not_before_millis
        || now_millis >= not_after_millis
    {
        return Err(if now_millis >= not_after_millis {
            SyntheticLeaseError::Expired
        } else {
            SyntheticLeaseError::Invalid
        });
    }
    let total = certificate_chain
        .iter()
        .try_fold(0_usize, |sum, certificate| {
            if certificate.is_empty() || certificate.len() > MAX_SYNTHETIC_LEASE_CERTIFICATE_BYTES {
                return Err(SyntheticLeaseError::Invalid);
            }
            sum.checked_add(certificate.len())
                .ok_or(SyntheticLeaseError::Capacity)
        })?;
    if total > MAX_SYNTHETIC_LEASE_CHAIN_BYTES {
        return Err(SyntheticLeaseError::Capacity);
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the lease identity hashes every security-relevant record field"
)]
fn derive_lease_id(
    epoch: u64,
    profile_id_hash: &[u8; 32],
    peer_spki_hash: &[u8; 32],
    not_before_millis: u64,
    not_after_millis: u64,
    public_spki: &[u8],
    certificate_chain: &[Vec<u8>],
) -> [u8; 32] {
    let mut digest = Context::new(&SHA256);
    digest.update(b"TEESimulator-RS synthetic lease id v1\0");
    digest.update(&epoch.to_be_bytes());
    digest.update(profile_id_hash);
    digest.update(peer_spki_hash);
    digest.update(&not_before_millis.to_be_bytes());
    digest.update(&not_after_millis.to_be_bytes());
    digest.update(&public_spki.len().to_be_bytes());
    digest.update(public_spki);
    for certificate in certificate_chain {
        digest.update(&certificate.len().to_be_bytes());
        digest.update(certificate);
    }
    let mut value = [0_u8; 32];
    value.copy_from_slice(digest.finish().as_ref());
    value
}

fn put_u16_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SyntheticLeaseError> {
    output.extend_from_slice(
        &u16::try_from(bytes.len())
            .map_err(|_| SyntheticLeaseError::Capacity)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_u32_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SyntheticLeaseError> {
    output.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| SyntheticLeaseError::Capacity)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

#[cfg(test)]
#[path = "synthetic_lease_tests.rs"]
mod tests;

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SyntheticLeaseError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SyntheticLeaseError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SyntheticLeaseError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SyntheticLeaseError> {
        self.take(N)?
            .try_into()
            .map_err(|_| SyntheticLeaseError::Corrupt)
    }

    fn u8(&mut self) -> Result<u8, SyntheticLeaseError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(SyntheticLeaseError::Corrupt)
    }

    fn flag(&mut self) -> Result<bool, SyntheticLeaseError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SyntheticLeaseError::Corrupt),
        }
    }

    fn u64(&mut self) -> Result<u64, SyntheticLeaseError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn u16_bytes(
        &mut self,
        minimum: usize,
        maximum: usize,
    ) -> Result<&'a [u8], SyntheticLeaseError> {
        let length = usize::from(u16::from_be_bytes(self.array()?));
        if length < minimum || length > maximum {
            return Err(SyntheticLeaseError::Invalid);
        }
        self.take(length)
    }

    fn u32_bytes(
        &mut self,
        minimum: usize,
        maximum: usize,
    ) -> Result<&'a [u8], SyntheticLeaseError> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| SyntheticLeaseError::Capacity)?;
        if length < minimum || length > maximum {
            return Err(SyntheticLeaseError::Invalid);
        }
        self.take(length)
    }

    const fn finish(self) -> Result<(), SyntheticLeaseError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SyntheticLeaseError::Corrupt)
        }
    }
}
