use std::{
    fs,
    os::unix::{fs::MetadataExt, net::UnixListener},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use rka_protocol::{CborWriter, HashDomain, hash_bytes, hash_cbor, transcript_hash};

mod broker;
mod result;
mod state;

const EPOCH: u64 = 9;
const SESSION: [u8; 32] = [0x77; 32];
const IRPC: [u8; 32] = [0x88; 32];
const RKP_PUBLIC: [u8; 32] = [0x91; 32];
const HANDLE: [u8; 32] = [0xb1; 32];
const PHASES: [[u8; 32]; 5] = [[0x92; 32], [0x93; 32], [0x94; 32], [0x95; 32], [0x96; 32]];
const CHAIN: [u8; 6] = [0x30, 1, 0, 0x30, 1, 1];
const AAID: &[u8] = b"authoritative-aaid";
const PAIRED_LINEAGE: [u8; 32] = [0x22; 32];
pub(crate) const FOREIGN_LINEAGE: [u8; 32] = [0x23; 32];

#[allow(
    clippy::redundant_pub_crate,
    reason = "the sibling direct-session runner proof owns this fixture"
)]
pub(crate) struct Fixture {
    pub root: PathBuf,
    pub broker_socket: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub initial_transcript: [u8; 32],
    identity_hash: [u8; 32],
    started_ms: u64,
}

impl Fixture {
    pub(crate) fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_peer([0x55; 32])
    }

    pub(crate) fn new_with_peer(
        peer_spki_hash: [u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = PathBuf::from("/tmp").join(format!(
            "rka-live-generate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let identity_hash = identity_hash();
        let initial_transcript = [0xc1; 32];
        state::persist(&root, identity_hash, initial_transcript, peer_spki_hash)?;
        let metadata = fs::metadata(&root)?;
        let started_ms = uptime_ms()?;
        Ok(Self {
            broker_socket: root.join("broker.sock"),
            root,
            uid: metadata.uid(),
            gid: metadata.gid(),
            initial_transcript,
            identity_hash,
            started_ms,
        })
    }

    pub(crate) fn generate_frame(&self, ordinal: u8, prior: [u8; 32]) -> Vec<u8> {
        self.generate_frame_with_lineage(ordinal, prior, PAIRED_LINEAGE)
    }

    /// Self-consistent identity built from `lineage`; the persisted pair keeps its own.
    pub(crate) fn generate_frame_with_lineage(
        &self,
        ordinal: u8,
        prior: [u8; 32],
        lineage: [u8; 32],
    ) -> Vec<u8> {
        let request_id = [ordinal; 16];
        let sequence = u32::from(ordinal).saturating_mul(2).saturating_sub(1);
        let without = self.frame(request_id, sequence, ordinal, None, lineage);
        let current = transcript_hash(&prior, &without);
        self.frame(request_id, sequence, ordinal, Some(current), lineage)
    }

    pub(crate) fn serve_broker(listener: &UnixListener, ordinal: u8) -> Result<Vec<u8>, String> {
        broker::serve(listener, ordinal)
    }

    pub(crate) fn capture_broker_without_response(
        listener: &UnixListener,
    ) -> Result<Vec<u8>, String> {
        broker::capture_without_response(listener)
    }

    pub(crate) fn runtime(
        &self,
        exchanges: usize,
    ) -> Result<crate::donor::DonorRuntime, Box<dyn std::error::Error>> {
        let mut runtime = crate::donor::DonorRuntime::open(&self.root, &self.broker_socket);
        runtime.broker = crate::donor::BridgeDonorBroker::new_authenticated_test(
            &self.broker_socket,
            exchanges,
        )?;
        Ok(runtime)
    }

    pub(crate) fn authenticated_exchanges(runtime: &crate::donor::DonorRuntime) -> usize {
        runtime.broker.authenticated_test_exchanges()
    }

    pub(crate) fn expected_broker_payload(ordinal: u8, prior: [u8; 32]) -> Vec<u8> {
        let mut payload = vec![0xa0 | ordinal; 16];
        payload.extend_from_slice(&HANDLE);
        put_bytes(&mut payload, b"0123456789abcdef");
        put_bytes(&mut payload, AAID);
        put_bytes(&mut payload, &prior);
        payload.push(2);
        put_bytes(&mut payload, &CHAIN[..3]);
        put_bytes(&mut payload, &CHAIN[3..]);
        payload
    }

    pub(crate) fn expected_result_body(&self, ordinal: u8) -> Vec<u8> {
        result::expected_body(ordinal, self.identity_hash, self.started_ms)
    }

    pub(crate) fn cleanup(self) -> std::io::Result<()> {
        fs::remove_dir_all(self.root)
    }

    fn frame(
        &self,
        request_id: [u8; 16],
        sequence: u32,
        ordinal: u8,
        transcript: Option<[u8; 32]>,
        identity: [u8; 32],
    ) -> Vec<u8> {
        let mut writer = CborWriter::with_capacity(1400);
        writer.map(if transcript.is_some() { 8 } else { 7 });
        for (key, value) in [(0, 2), (1, 10)] {
            writer.unsigned(key);
            writer.unsigned(value);
        }
        writer.unsigned(2);
        writer.bytes(&request_id);
        writer.unsigned(3);
        writer.bytes(&SESSION);
        writer.unsigned(4);
        writer.unsigned(EPOCH);
        writer.unsigned(5);
        writer.unsigned(u64::from(sequence));
        writer.unsigned(6);
        writer.map(3);
        writer.unsigned(0);
        encode_identity(&mut writer, identity);
        writer.unsigned(1);
        foreground(&mut writer, [0xa0 | ordinal; 16]);
        writer.unsigned(2);
        encode_envelope(&mut writer, self.identity_hash, self.started_ms);
        if let Some(value) = transcript {
            writer.unsigned(7);
            writer.bytes(&value);
        }
        writer.finish()
    }
}

fn foreground(writer: &mut CborWriter, alias: [u8; 16]) {
    writer.map(7);
    for (key, value) in [(0, 1), (1, 3), (2, 1), (3, 2), (4, 4)] {
        writer.unsigned(key);
        writer.unsigned(value);
    }
    writer.unsigned(5);
    writer.bytes(b"0123456789abcdef");
    writer.unsigned(6);
    writer.bytes(&alias);
}

fn identity_hash() -> [u8; 32] {
    identity_hash_for(PAIRED_LINEAGE)
}

fn identity_hash_for(lineage: [u8; 32]) -> [u8; 32] {
    let mut unsigned = CborWriter::with_capacity(256);
    identity_prefix(&mut unsigned, 5);
    unsigned.unsigned(5);
    unsigned.bytes(&lineage);
    hash_cbor(HashDomain::Identity, &unsigned.finish())
}

fn encode_identity(writer: &mut CborWriter, lineage: [u8; 32]) {
    identity_prefix(writer, 6);
    writer.unsigned(4);
    writer.bytes(&identity_hash_for(lineage));
    writer.unsigned(5);
    writer.bytes(&lineage);
}

fn identity_prefix(writer: &mut CborWriter, size: usize) {
    writer.map(size);
    writer.unsigned(0);
    writer.unsigned(0);
    writer.unsigned(1);
    writer.unsigned(10_001);
    writer.unsigned(2);
    writer.array(1);
    writer.array(3);
    writer.text("com.example.candidate");
    writer.unsigned(1);
    writer.array(1);
    writer.bytes(b"signer");
    writer.unsigned(3);
    writer.bytes(AAID);
}

fn encode_envelope(writer: &mut CborWriter, identity_hash: [u8; 32], started_ms: u64) {
    writer.map(17);
    writer.unsigned(0);
    writer.unsigned(1);
    for (key, value) in [(1, identity_hash), (2, hash_bytes(HashDomain::Aaid, AAID))] {
        writer.unsigned(key);
        writer.bytes(&value);
    }
    writer.unsigned(3);
    writer.unsigned(EPOCH);
    for (key, value) in [(4, [0x33; 32]), (5, [0x44; 32]), (6, IRPC)] {
        writer.unsigned(key);
        writer.bytes(&value);
    }
    writer.unsigned(7);
    writer.array(1);
    writer.bytes(&RKP_PUBLIC);
    for (offset, value) in PHASES.iter().enumerate() {
        writer.unsigned(8_u64.saturating_add(u64::try_from(offset).unwrap_or(u64::MAX)));
        writer.bytes(value);
    }
    writer.unsigned(13);
    writer.unsigned(started_ms);
    writer.unsigned(14);
    writer.unsigned(120);
    writer.unsigned(15);
    writer.unsigned(1);
    writer.unsigned(16);
    writer.unsigned(0);
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    output.extend_from_slice(value);
}
fn uptime_ms() -> Result<u64, Box<dyn std::error::Error>> {
    let value = fs::read_to_string("/proc/uptime")?;
    let value = value.split_whitespace().next().ok_or("missing uptime")?;
    let (seconds, fraction) = value.split_once('.').ok_or("invalid uptime")?;
    let seconds = seconds.parse::<u64>()?;
    let centiseconds = fraction.get(..2).ok_or("short uptime")?.parse::<u64>()?;
    Ok(seconds
        .saturating_mul(1_000)
        .saturating_add(centiseconds.saturating_mul(10)))
}
