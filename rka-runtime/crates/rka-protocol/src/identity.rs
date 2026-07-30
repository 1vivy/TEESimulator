//! Canonical candidate identity wire model.

use crate::{
    HashDomain, MAX_AAID_BYTES, MAX_CURRENT_SIGNERS, MAX_PACKAGE_NAME_BYTES, MAX_PACKAGES,
    MAX_SIGNER_BYTES, ProtocolError,
    cbor::{CborReader, CborWriter},
    hash_cbor,
};

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PackageIdentity<'a> {
    pub package_name: &'a str,
    pub version_code: u64,
    pub current_signers: Vec<&'a [u8]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CandidateIdentity<'a> {
    pub android_user: u32,
    pub uid: u32,
    pub packages: Vec<PackageIdentity<'a>>,
    pub aaid_der: &'a [u8],
    pub identity_hash: [u8; 32],
    pub policy_lineage_hash: [u8; 32],
}

pub fn decode_candidate_identity(bytes: &[u8]) -> Result<CandidateIdentity<'_>, ProtocolError> {
    crate::validate_deterministic_cbor(bytes)?;
    let mut reader = CborReader::new(bytes);
    if reader.map()? != 6 {
        return Err(ProtocolError::MissingField);
    }
    expect_key(&mut reader, 0)?;
    let android_user = bounded_u32(reader.unsigned()?)?;
    expect_key(&mut reader, 1)?;
    let uid = bounded_u32(reader.unsigned()?)?;
    expect_key(&mut reader, 2)?;
    let packages = decode_packages(&mut reader)?;
    expect_key(&mut reader, 3)?;
    let aaid_der = reader.bytes()?;
    if aaid_der.is_empty() || aaid_der.len() > MAX_AAID_BYTES {
        return Err(ProtocolError::LengthOutOfRange);
    }
    expect_key(&mut reader, 4)?;
    let identity_hash = fixed(reader.bytes()?)?;
    expect_key(&mut reader, 5)?;
    let policy_lineage_hash = fixed(reader.bytes()?)?;
    if !reader.is_complete() {
        return Err(ProtocolError::UnknownField);
    }
    let identity = CandidateIdentity {
        android_user,
        uid,
        packages,
        aaid_der,
        identity_hash,
        policy_lineage_hash,
    };
    if hash_cbor(
        HashDomain::Identity,
        &encode_without_identity_hash(&identity),
    ) != identity.identity_hash
    {
        return Err(ProtocolError::UnsupportedValue);
    }
    Ok(identity)
}

pub fn admit_candidate_identity(
    bytes: &[u8],
    authenticated_uid: u32,
) -> Result<CandidateIdentity<'_>, ProtocolError> {
    let identity = decode_candidate_identity(bytes)?;
    if identity.uid != authenticated_uid {
        return Err(ProtocolError::CrossUidGrant);
    }
    Ok(identity)
}

pub fn decode_identity_reader<'a>(
    reader: &mut CborReader<'a>,
) -> Result<CandidateIdentity<'a>, ProtocolError> {
    let start = reader.position();
    reader.skip_item()?;
    let encoded = reader.slice_from(start)?;
    decode_candidate_identity(encoded)
}

fn decode_packages<'a>(
    reader: &mut CborReader<'a>,
) -> Result<Vec<PackageIdentity<'a>>, ProtocolError> {
    let count = reader.array()?;
    if count == 0 || count > MAX_PACKAGES {
        return Err(ProtocolError::LengthOutOfRange);
    }
    let mut packages = Vec::with_capacity(count);
    for _ in 0..count {
        if reader.array()? != 3 {
            return Err(ProtocolError::MissingField);
        }
        let package_name = reader.text()?;
        if package_name.is_empty() || package_name.len() > MAX_PACKAGE_NAME_BYTES {
            return Err(ProtocolError::LengthOutOfRange);
        }
        let version_code = reader.unsigned()?;
        let signer_count = reader.array()?;
        if signer_count == 0 || signer_count > MAX_CURRENT_SIGNERS {
            return Err(ProtocolError::LengthOutOfRange);
        }
        let mut current_signers = Vec::with_capacity(signer_count);
        for _ in 0..signer_count {
            let signer = reader.bytes()?;
            if signer.is_empty() || signer.len() > MAX_SIGNER_BYTES {
                return Err(ProtocolError::LengthOutOfRange);
            }
            if current_signers
                .last()
                .is_some_and(|previous| *previous >= signer)
            {
                return Err(ProtocolError::InvalidOrdering);
            }
            current_signers.push(signer);
        }
        if packages
            .last()
            .is_some_and(|previous: &PackageIdentity<'_>| {
                previous.package_name.as_bytes() >= package_name.as_bytes()
            })
        {
            return Err(ProtocolError::InvalidOrdering);
        }
        packages.push(PackageIdentity {
            package_name,
            version_code,
            current_signers,
        });
    }
    Ok(packages)
}

fn encode_without_identity_hash(identity: &CandidateIdentity<'_>) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(256);
    writer.map(5);
    writer.unsigned(0);
    writer.unsigned(u64::from(identity.android_user));
    writer.unsigned(1);
    writer.unsigned(u64::from(identity.uid));
    writer.unsigned(2);
    writer.array(identity.packages.len());
    for package in &identity.packages {
        writer.array(3);
        writer.text(package.package_name);
        writer.unsigned(package.version_code);
        writer.array(package.current_signers.len());
        for signer in &package.current_signers {
            writer.bytes(signer);
        }
    }
    writer.unsigned(3);
    writer.bytes(identity.aaid_der);
    writer.unsigned(5);
    writer.bytes(&identity.policy_lineage_hash);
    writer.finish()
}

fn bounded_u32(value: u64) -> Result<u32, ProtocolError> {
    u32::try_from(value).map_err(|_| ProtocolError::LengthOutOfRange)
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProtocolError> {
    bytes
        .try_into()
        .map_err(|_| ProtocolError::LengthOutOfRange)
}

fn expect_key(reader: &mut CborReader<'_>, expected: u64) -> Result<(), ProtocolError> {
    if reader.unsigned()? == expected {
        Ok(())
    } else {
        Err(ProtocolError::UnknownField)
    }
}
