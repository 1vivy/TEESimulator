#![allow(missing_docs, reason = "integration tests are behavior-named")]

use rka_sidecar::bridge::{
    BridgeMessage, CandidateBridgeOperation, ExchangeRole, PublicBytes, RequestId, decode_frame,
    encode_frame,
};
use rka_sidecar::candidate::{PairingAdmission, PairingCatalog};
use rka_sidecar::donor::{DeleteRequest, DonorError, DonorRuntime};
use rka_state::{PairedActivationRecord, StateError, StateStore};

#[test]
fn donor_bridge_candidate_command_matches_authenticated_jvm_wire_golden()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let command = BridgeMessage::CandidateCommand(
        RequestId::new(0x0102_0304_0506_0708),
        CandidateBridgeOperation::List,
        PublicBytes::bounded(b"abc", 0, 32)?,
    );

    // When
    let encoded = encode_frame(&command, ExchangeRole::DonorRequest)?;
    let decoded = decode_frame(encoded.as_slice(), ExchangeRole::DonorRequest)?;

    // Then
    assert_eq!(encoded.as_slice(), candidate_command_golden());
    assert_eq!(decoded, command);
    Ok(())
}

const fn candidate_command_golden() -> &'static [u8] {
    &[
        0x52, 0x4b, 0x42, 0x31, 0x01, 0x01, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x61,
        0x62, 0x63,
    ]
}

#[test]
fn production_donor_runtime_is_closed_until_authenticated_pairing() {
    let mut catalog = PairingCatalog::empty();
    catalog
        .admit(PairingAdmission::new(([2; 32], [3; 32], 4), [8; 32]))
        .unwrap();
    let context = catalog.lookup([2; 32], [3; 32], 4).unwrap();
    let mut runtime = DonorRuntime::new(std::path::Path::new("/unused/broker.sock"));
    let request = DeleteRequest::new(
        [1; 16],
        rka_sidecar::donor::AccessContext {
            peer_spki_hash: [2; 32],
            profile_id_hash: [3; 32],
            profile_epoch: 4,
            session_id: [5; 32],
            candidate_nonce: [6; 32],
            donor_nonce: [7; 32],
            candidate_identity_hash: [8; 32],
            now_ms: 9,
        },
        [10; 16],
    );

    assert_eq!(runtime.get(&context, request), Err(DonorError::Unpaired));
}

#[test]
fn donor_runtime_open_requires_both_durable_trust_records() -> Result<(), Box<dyn std::error::Error>>
{
    let root = std::env::temp_dir().join(format!("rka-donor-open-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;

    let runtime = DonorRuntime::open(&root, std::path::Path::new("/unused/broker.sock"));

    assert!(!runtime.is_active());
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn donor_runtime_open_rejects_a_pair_without_an_active_lease()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let root = std::env::temp_dir().join(format!("rka-donor-pair-only-{}", std::process::id()));
    let store = TestStore(root.join("records"));
    PairedActivationRecord {
        peer_spki_hash: [1; 32],
        profile_id_hash: [2; 32],
        profile_epoch: 3,
        candidate_identity_hash: [4; 32],
        session_id: [5; 32],
        candidate_nonce: [6; 32],
        donor_nonce: [7; 32],
        prior_transcript_hash: [8; 32],
    }
    .persist(&store)?;

    // When
    let runtime = DonorRuntime::open(&root, std::path::Path::new("/unused/broker.sock"));

    // Then
    assert!(!runtime.is_active());
    std::fs::remove_dir_all(root)?;
    Ok(())
}

struct TestStore(std::path::PathBuf);

impl StateStore for TestStore {
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        let value = std::fs::read(self.0.join(key_name(key))).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StateError::Missing
            } else {
                StateError::Storage
            }
        })?;
        output
            .get_mut(..value.len())
            .ok_or(StateError::Capacity)?
            .copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        std::fs::create_dir_all(&self.0).map_err(|_| StateError::Storage)?;
        std::fs::write(self.0.join(key_name(key)), value).map_err(|_| StateError::Storage)
    }
}

fn key_name(key: &[u8]) -> String {
    key.iter().fold(String::new(), |mut output, byte| {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
        output
    })
}
