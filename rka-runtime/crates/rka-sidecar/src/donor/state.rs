use std::{
    fs,
    path::{Path, PathBuf},
};

use super::DonorError;
use crate::provisioning_io::atomic_replace;

const MAGIC: &[u8; 5] = b"RKDT\x01";
const COMMITTED: u8 = 1;
const PENDING: u8 = 2;
const COMMITTED_BYTES: usize = 38;
const PENDING_BYTES: usize = 190;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TranscriptState {
    Committed([u8; 32]),
    Pending(PendingTranscript),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PendingTranscript {
    pub prior: [u8; 32],
    pub request_hash: [u8; 32],
    pub next: [u8; 32],
    pub peer: [u8; 32],
    pub epoch: u64,
    pub session: [u8; 32],
    pub request_id: [u8; 16],
}

#[derive(Debug)]
pub(super) struct TranscriptJournal {
    path: PathBuf,
    state: TranscriptState,
}

impl TranscriptJournal {
    pub(super) fn open(root: &Path, legacy: [u8; 32]) -> Result<Self, DonorError> {
        let path = root.join("donor-transcript-v1");
        let state = match fs::read(&path) {
            Ok(encoded) => decode(&encoded)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                TranscriptState::Committed(legacy)
            }
            Err(_) => return Err(DonorError::Storage),
        };
        Ok(Self { path, state })
    }

    pub(super) const fn committed(&self) -> Result<[u8; 32], DonorError> {
        match self.state {
            TranscriptState::Committed(value) => Ok(value),
            TranscriptState::Pending(_) => Err(DonorError::Quarantined),
        }
    }

    pub(super) fn reserve(&mut self, pending: PendingTranscript) -> Result<(), DonorError> {
        if self.committed()? != pending.prior {
            return Err(DonorError::TranscriptMismatch);
        }
        let encoded = encode_pending(pending);
        atomic_replace(&self.path, &encoded).map_err(|_| DonorError::Storage)?;
        self.state = TranscriptState::Pending(pending);
        Ok(())
    }

    pub(super) fn commit_result(
        &mut self,
        request_head: [u8; 32],
        result_head: [u8; 32],
    ) -> Result<(), DonorError> {
        let TranscriptState::Pending(pending) = self.state else {
            return Err(DonorError::Storage);
        };
        if pending.next != request_head {
            return Err(DonorError::Storage);
        }
        let mut encoded = Vec::with_capacity(COMMITTED_BYTES);
        encoded.extend_from_slice(MAGIC);
        encoded.push(COMMITTED);
        encoded.extend_from_slice(&result_head);
        atomic_replace(&self.path, &encoded).map_err(|_| DonorError::Storage)?;
        self.state = TranscriptState::Committed(result_head);
        Ok(())
    }
}

fn encode_pending(pending: PendingTranscript) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(PENDING_BYTES);
    encoded.extend_from_slice(MAGIC);
    encoded.push(PENDING);
    encoded.extend_from_slice(&pending.prior);
    encoded.extend_from_slice(&pending.request_hash);
    encoded.extend_from_slice(&pending.next);
    encoded.extend_from_slice(&pending.peer);
    encoded.extend_from_slice(&pending.epoch.to_be_bytes());
    encoded.extend_from_slice(&pending.session);
    encoded.extend_from_slice(&pending.request_id);
    encoded
}

fn decode(encoded: &[u8]) -> Result<TranscriptState, DonorError> {
    if encoded.get(..5) != Some(MAGIC) {
        return Err(DonorError::Storage);
    }
    match encoded.get(5).copied() {
        Some(COMMITTED) if encoded.len() == COMMITTED_BYTES => {
            let value = encoded
                .get(6..38)
                .and_then(|value| value.try_into().ok())
                .ok_or(DonorError::Storage)?;
            Ok(TranscriptState::Committed(value))
        }
        Some(PENDING) if encoded.len() == PENDING_BYTES => {
            let mut cursor = Cursor::new(encoded.get(6..).ok_or(DonorError::Storage)?);
            Ok(TranscriptState::Pending(PendingTranscript {
                prior: cursor.array()?,
                request_hash: cursor.array()?,
                next: cursor.array()?,
                peer: cursor.array()?,
                epoch: cursor.u64()?,
                session: cursor.array()?,
                request_id: cursor.array()?,
            }))
        }
        _ => Err(DonorError::Storage),
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DonorError> {
        let value = self
            .0
            .get(..N)
            .and_then(|value| value.try_into().ok())
            .ok_or(DonorError::Storage)?;
        self.0 = self.0.get(N..).ok_or(DonorError::Storage)?;
        Ok(value)
    }

    fn u64(&mut self) -> Result<u64, DonorError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn reopen_with_pending_transcript_is_terminally_quarantined() {
        // Given
        let root = root();
        let mut journal = TranscriptJournal::open(&root, [1; 32]).unwrap();
        journal.reserve(pending()).unwrap();

        // When
        let reopened = TranscriptJournal::open(&root, [1; 32]).unwrap();

        // Then
        assert_eq!(reopened.committed(), Err(DonorError::Quarantined));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn commit_advances_only_after_durable_pending() {
        // Given
        let root = root();
        let mut journal = TranscriptJournal::open(&root, [1; 32]).unwrap();
        assert_eq!(
            journal.commit_result([3; 32], [8; 32]),
            Err(DonorError::Storage)
        );
        journal.reserve(pending()).unwrap();

        // When
        journal.commit_result([3; 32], [8; 32]).unwrap();

        // Then
        assert_eq!(
            TranscriptJournal::open(&root, [1; 32]).unwrap().committed(),
            Ok([8; 32])
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_commit_keeps_the_durable_pending_quarantine() {
        // Given
        let root = root();
        let backup = root.with_extension("backup");
        let mut journal = TranscriptJournal::open(&root, [1; 32]).unwrap();
        journal.reserve(pending()).unwrap();
        fs::rename(&root, &backup).unwrap();
        fs::write(&root, b"blocks-parent-directory").unwrap();

        // When
        let result = journal.commit_result([3; 32], [8; 32]);

        // Then
        assert_eq!(result, Err(DonorError::Storage));
        assert_eq!(journal.committed(), Err(DonorError::Quarantined));
        fs::remove_file(&root).unwrap();
        fs::rename(&backup, &root).unwrap();
        assert_eq!(
            TranscriptJournal::open(&root, [1; 32]).unwrap().committed(),
            Err(DonorError::Quarantined)
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn pending() -> PendingTranscript {
        PendingTranscript {
            prior: [1; 32],
            request_hash: [2; 32],
            next: [3; 32],
            peer: [4; 32],
            epoch: 5,
            session: [6; 32],
            request_id: [7; 16],
        }
    }

    fn root() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "rka-donor-transcript-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
}
