use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixListener},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::bridge::{
    BridgeMessage, CandidateBridgeOperation, ExchangeRole, PublicBytes, RequestId, decode_frame,
    encode_frame,
};
use rka_protocol::{CborWriter, HashDomain, hash_bytes, hash_cbor, transcript_hash};

mod state;

const EPOCH: u64 = 9;
const SESSION: [u8; 32] = [0x77; 32];
const IRPC: [u8; 32] = [0x88; 32];
const RKP_PUBLIC: [u8; 32] = [0x91; 32];
const HANDLE: [u8; 32] = [0xb1; 32];
const PHASES: [[u8; 32]; 5] = [[0x92; 32], [0x93; 32], [0x94; 32], [0x95; 32], [0x96; 32]];
const CHAIN: [u8; 6] = [0x30, 1, 0, 0x30, 1, 1];
const AAID: &[u8] = b"authoritative-aaid";

pub(super) struct Fixture {
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
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = PathBuf::from("/tmp").join(format!(
            "rka-live-generate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let identity_hash = identity_hash();
        let initial_transcript = [0xc1; 32];
        state::persist(&root, identity_hash, initial_transcript)?;
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
        let request_id = [ordinal; 16];
        let sequence = u32::from(ordinal).saturating_mul(2).saturating_sub(1);
        let without = self.frame(request_id, sequence, ordinal, None);
        let current = transcript_hash(&prior, &without);
        self.frame(request_id, sequence, ordinal, Some(current))
    }

    fn broker_reply(ordinal: u8) -> Result<BridgeMessage, Box<dyn std::error::Error>> {
        let mut payload = vec![0xd0 | ordinal; 16];
        put_bytes(&mut payload, b"leaf-spki");
        payload.push(2);
        put_bytes(&mut payload, b"leaf");
        put_bytes(&mut payload, b"root");
        put_bytes(&mut payload, b"transcript-signature");
        Ok(BridgeMessage::CandidateReply(
            RequestId::new(u64::from(ordinal)),
            CandidateBridgeOperation::Generate,
            PublicBytes::bounded(&payload, 1, 1_048_571)?,
        ))
    }

    fn generate_payload(message: BridgeMessage) -> Result<Vec<u8>, String> {
        match message {
            BridgeMessage::CandidateCommand(_, CandidateBridgeOperation::Generate, payload) => {
                Ok(payload.as_slice().to_vec())
            }
            _ => Err("broker did not receive CandidateCommand Generate".to_owned()),
        }
    }

    pub(crate) fn serve_broker(listener: &UnixListener, ordinal: u8) -> Result<Vec<u8>, String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let mut header = [0; 24];
        stream
            .read_exact(&mut header)
            .map_err(|error| error.to_string())?;
        let body_length = u32::from_be_bytes(
            header[16..20]
                .try_into()
                .map_err(|_| "invalid bridge header")?,
        ) as usize;
        let mut request = header.to_vec();
        request.resize(24_usize.saturating_add(body_length), 0);
        stream
            .read_exact(request.get_mut(24..).ok_or("invalid bridge body")?)
            .map_err(|error| error.to_string())?;
        let command = decode_frame(&request, ExchangeRole::DonorRequest)
            .map_err(|error| error.to_string())?;
        let response = encode_frame(
            &Self::broker_reply(ordinal).map_err(|error| error.to_string())?,
            ExchangeRole::DonorResponse,
        )
        .map_err(|error| error.to_string())?;
        stream
            .write_all(response.as_slice())
            .map_err(|error| error.to_string())?;
        Self::generate_payload(command)
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

    pub(crate) fn cleanup(self) -> std::io::Result<()> {
        fs::remove_dir_all(self.root)
    }

    fn frame(
        &self,
        request_id: [u8; 16],
        sequence: u32,
        ordinal: u8,
        transcript: Option<[u8; 32]>,
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
        encode_identity(&mut writer, self.identity_hash);
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
    let mut unsigned = CborWriter::with_capacity(256);
    identity_prefix(&mut unsigned, 5);
    unsigned.unsigned(5);
    unsigned.bytes(&[0x22; 32]);
    hash_cbor(HashDomain::Identity, &unsigned.finish())
}

fn encode_identity(writer: &mut CborWriter, identity_hash: [u8; 32]) {
    identity_prefix(writer, 6);
    writer.unsigned(4);
    writer.bytes(&identity_hash);
    writer.unsigned(5);
    writer.bytes(&[0x22; 32]);
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
