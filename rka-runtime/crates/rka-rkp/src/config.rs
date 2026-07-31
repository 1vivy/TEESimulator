//! Strict provisioning configuration values and deterministic request encoding.

use std::fmt;

use thiserror::Error;

const MAX_TEXT_BYTES: usize = 4096;

/// Configuration boundary failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ConfigError {
    /// A value is empty or exceeds its fixed boundary.
    #[error("provisioning configuration value is outside its fixed boundary")]
    InvalidValue,
    /// A URL is not a canonical HTTPS root base.
    #[error("provisioning base URL is not a canonical HTTPS root")]
    InvalidBaseUrl,
    /// A fetch response is not the exact bounded CBOR shape.
    #[error("invalid provisioning response")]
    InvalidResponse,
    /// A challenge was outside 16..=64 bytes.
    #[error("invalid provisioning challenge")]
    ChallengeSize,
}

/// Canonical HTTPS origin with no credentials, path, query, or fragment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaseUrl(String);

impl BaseUrl {
    /// Parses a strict canonical HTTPS root base.
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let authority = value
            .strip_prefix("https://")
            .ok_or(ConfigError::InvalidBaseUrl)?;
        if authority.is_empty()
            || authority.len() > MAX_TEXT_BYTES
            || authority.bytes().any(|byte| {
                byte.is_ascii_whitespace()
                    || matches!(byte, b'/' | b'?' | b'#' | b'@' | b'%' | b'\\')
                    || byte.is_ascii_uppercase()
            })
        {
            return Err(ConfigError::InvalidBaseUrl);
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        if !valid_host(host) || !valid_port(port)? {
            return Err(ConfigError::InvalidBaseUrl);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the canonical serialized base.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_port(port: Option<&str>) -> Result<bool, ConfigError> {
    let Some(port) = port else {
        return Ok(true);
    };
    if port.is_empty() || port.starts_with('0') || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(false);
    }
    Ok(port
        .parse::<u16>()
        .map_err(|_| ConfigError::InvalidBaseUrl)?
        > 0)
}

/// The only donor observations serialized into `fetchEekChain`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisioningInfo {
    fingerprint: String,
    id: u64,
    version: u64,
}

impl ProvisioningInfo {
    /// Copies bounded provisioning request fields.
    pub fn new(fingerprint: &str, id: u64, version: u64) -> Result<Self, ConfigError> {
        if !valid_text(fingerprint) {
            return Err(ConfigError::InvalidValue);
        }
        Ok(Self {
            fingerprint: fingerprint.to_owned(),
            id,
            version,
        })
    }

    /// Encodes the exact deterministic CBOR map `{fingerprint, id, version}`.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ConfigError> {
        let mut output = Vec::new();
        output.push(0xa3);
        encode_text(&mut output, "fingerprint");
        encode_text(&mut output, &self.fingerprint);
        encode_text(&mut output, "id");
        encode_unsigned(&mut output, self.id);
        encode_text(&mut output, "version");
        encode_unsigned(&mut output, self.version);
        Ok(output)
    }
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.contains('\0')
}

fn encode_text(output: &mut Vec<u8>, value: &str) {
    encode_major(output, 3, value.len());
    output.extend_from_slice(value.as_bytes());
}

fn encode_major(output: &mut Vec<u8>, major: u8, value: usize) {
    if value < 24 {
        output.push((major << 5) | u8::try_from(value).unwrap_or(0));
    } else if let Ok(short) = u8::try_from(value) {
        output.extend_from_slice(&[(major << 5) | 0x18, short]);
    } else {
        output.push((major << 5) | 0x19);
        output.extend_from_slice(&u16::try_from(value).unwrap_or(u16::MAX).to_be_bytes());
    }
}

fn encode_unsigned(output: &mut Vec<u8>, value: u64) {
    if value < 24 {
        output.push(u8::try_from(value).unwrap_or(0));
    } else if let Ok(short) = u8::try_from(value) {
        output.extend_from_slice(&[0x18, short]);
    } else if let Ok(short) = u16::try_from(value) {
        output.push(0x19);
        output.extend_from_slice(&short.to_be_bytes());
    } else if let Ok(short) = u32::try_from(value) {
        output.push(0x1a);
        output.extend_from_slice(&short.to_be_bytes());
    } else {
        output.push(0x1b);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

pub(crate) fn parse_fetch_response(body: &[u8]) -> Result<(Vec<u8>, Option<BaseUrl>), ConfigError> {
    let mut cursor = CborCursor::new(body);
    let fields = cursor.array_len()?;
    if !(2..=3).contains(&fields) {
        return Err(ConfigError::InvalidResponse);
    }
    cursor.eek_chains()?;
    let challenge = cursor.bytes()?.to_vec();
    let mut override_url = None;
    if fields == 3 {
        for _ in 0..cursor.map_len()? {
            match cursor.text()? {
                "provisioning_url" => override_url = Some(BaseUrl::parse(cursor.text()?)?),
                "num_extra_attestation_keys"
                | "time_to_refresh_hours"
                | "bad_cert_start"
                | "bad_cert_end" => {
                    cursor.unsigned()?;
                }
                _ => return Err(ConfigError::InvalidResponse),
            }
        }
    }
    if !cursor.finished() {
        return Err(ConfigError::InvalidResponse);
    }
    if !(16..=64).contains(&challenge.len()) {
        return Err(ConfigError::ChallengeSize);
    }
    Ok((challenge, override_url))
}

struct CborCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CborCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn map_len(&mut self) -> Result<usize, ConfigError> {
        self.length(5)
    }
    fn array_len(&mut self) -> Result<usize, ConfigError> {
        self.length(4)
    }
    fn text(&mut self) -> Result<&'a str, ConfigError> {
        let length = self.length(3)?;
        std::str::from_utf8(self.take(length)?).map_err(|_| ConfigError::InvalidResponse)
    }
    fn bytes(&mut self) -> Result<&'a [u8], ConfigError> {
        let length = self.length(2)?;
        self.take(length)
    }
    fn unsigned(&mut self) -> Result<usize, ConfigError> {
        self.length(0)
    }
    fn eek_chains(&mut self) -> Result<(), ConfigError> {
        for _ in 0..self.array_len()? {
            if self.array_len()? != 2 {
                return Err(ConfigError::InvalidResponse);
            }
            self.unsigned()?;
            for _ in 0..self.array_len()? {
                self.bytes()?;
            }
        }
        Ok(())
    }
    fn length(&mut self, major: u8) -> Result<usize, ConfigError> {
        let head = *self.take(1)?.first().ok_or(ConfigError::InvalidResponse)?;
        if head >> 5 != major {
            return Err(ConfigError::InvalidResponse);
        }
        match head & 0x1f {
            value @ 0..=23 => Ok(usize::from(value)),
            24 => Ok(usize::from(
                *self.take(1)?.first().ok_or(ConfigError::InvalidResponse)?,
            )),
            25 => {
                let bytes: [u8; 2] = self
                    .take(2)?
                    .try_into()
                    .map_err(|_| ConfigError::InvalidResponse)?;
                Ok(usize::from(u16::from_be_bytes(bytes)))
            }
            _ => Err(ConfigError::InvalidResponse),
        }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ConfigError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ConfigError::InvalidResponse)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ConfigError::InvalidResponse)?;
        self.offset = end;
        Ok(value)
    }
    const fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{BaseUrl, ProvisioningInfo};

    #[test]
    fn provisioning_info_golden() {
        let info = ProvisioningInfo::new("fp", 42, 16).unwrap();
        let encoded = info.to_cbor().unwrap();

        assert_eq!(
            encoded,
            hex("a36b66696e6765727072696e74626670626964182a6776657273696f6e10")
        );
        for excluded in [
            b"https://" as &[u8],
            b"rollout",
            b"configuration",
            b"budget",
            b"identity",
            b"credential",
        ] {
            assert!(!encoded.windows(excluded.len()).any(|item| item == excluded));
        }
    }

    #[test]
    fn base_url_is_strict_https_root() {
        assert!(BaseUrl::parse("https://rkp.example:8443").is_ok());
        for invalid in [
            "http://rkp.example",
            "https://rkp.example/path",
            "https://rkp.example?x=1",
            "https://rkp.example#x",
            "https://RKP.example",
            "https://rkp.example/",
            "https://rkp%2eexample",
        ] {
            assert!(BaseUrl::parse(invalid).is_err(), "{invalid}");
        }
        assert!(BaseUrl::parse(&["https://user", "@rkp.example"].concat()).is_err());
    }

    fn hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }
}
