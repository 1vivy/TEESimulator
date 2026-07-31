use std::collections::BTreeMap;

use crate::ValidationError;

/// Android's published attestation certificate status endpoint.
pub const STATUS_URL: &str = "https://android.googleapis.com/attestation/status";

/// Status assigned to one certificate serial by a validated status response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CertificateStatus {
    /// The certificate is not revoked.
    Good,
    /// The certificate is revoked and must not be activated.
    Revoked,
}

/// Bounded status records and the cache lifetime supplied with them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusSnapshot {
    fetched_at: u64,
    max_age: u64,
    entries: BTreeMap<String, CertificateStatus>,
}

impl StatusSnapshot {
    /// Builds a snapshot from parsed status entries and an HTTP Cache-Control value.
    pub fn new(
        fetched_at: u64,
        cache_control: &str,
        entries: impl IntoIterator<Item = (String, CertificateStatus)>,
    ) -> Result<Self, ValidationError> {
        let max_age = cache_control
            .split(',')
            .map(str::trim)
            .find_map(|part| part.strip_prefix("max-age="))
            .ok_or(ValidationError::Status)?
            .parse::<u64>()
            .map_err(|_| ValidationError::Status)?;
        if max_age == 0 {
            return Err(ValidationError::Status);
        }
        Ok(Self {
            fetched_at,
            max_age,
            entries: entries.into_iter().collect(),
        })
    }

    #[doc(hidden)]
    #[must_use]
    pub fn for_test<'a>(
        fetched_at: u64,
        max_age: u64,
        entries: impl IntoIterator<Item = (&'a str, CertificateStatus)>,
    ) -> Self {
        Self {
            fetched_at,
            max_age,
            entries: entries
                .into_iter()
                .map(|(serial, status)| (serial.to_owned(), status))
                .collect(),
        }
    }

    pub(crate) fn require_good(&self, now: u64, serial: &str) -> Result<(), ValidationError> {
        if now < self.fetched_at || now.saturating_sub(self.fetched_at) >= self.max_age {
            return Err(ValidationError::StatusStale);
        }
        match self.entries.get(serial) {
            Some(CertificateStatus::Good) => Ok(()),
            Some(CertificateStatus::Revoked) => Err(ValidationError::Revoked),
            None => Err(ValidationError::StatusIncomplete),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CertificateStatus, StatusSnapshot};
    use crate::ValidationError;

    #[test]
    fn rejects_malformed_or_zero_cache_lifetime() {
        assert_eq!(
            StatusSnapshot::new(7, "public", []),
            Err(ValidationError::Status)
        );
        assert_eq!(
            StatusSnapshot::new(7, "max-age=0", []),
            Err(ValidationError::Status)
        );
        assert_eq!(
            StatusSnapshot::new(7, "max-age=nope", []),
            Err(ValidationError::Status)
        );
    }

    #[test]
    fn fails_closed_for_stale_revoked_and_missing_status() {
        let status = StatusSnapshot::new(
            7,
            "public, max-age=60",
            [("01".to_owned(), CertificateStatus::Revoked)],
        )
        .unwrap();

        assert_eq!(
            status.require_good(67, "01"),
            Err(ValidationError::StatusStale)
        );
        assert_eq!(status.require_good(7, "01"), Err(ValidationError::Revoked));
        assert_eq!(
            status.require_good(7, "02"),
            Err(ValidationError::StatusIncomplete)
        );
    }
}
