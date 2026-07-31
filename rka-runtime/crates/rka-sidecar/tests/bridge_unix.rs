//! Real filesystem `AF_UNIX` exchange, timeout, and peer-death tests.

use std::{
    error::Error,
    fs,
    io::Write,
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    thread,
    time::Duration,
};

use rka_sidecar::bridge::{
    BridgeError, BridgeMessage, BrokerKeyMetadata, Correlation, ExchangeRole, NetworkHandle,
    PublicBytes, RequestId, decode_frame, encode_frame, read_frame,
};

struct SocketPath(PathBuf);

impl Drop for SocketPath {
    fn drop(&mut self) {
        let _removed = fs::remove_file(&self.0);
    }
}

fn request() -> Result<BridgeMessage, BridgeError> {
    Ok(BridgeMessage::PublicKeyRequest(
        RequestId::new(9),
        PublicBytes::bounded(&[7; 16], 16, 64)?,
        1,
    ))
}

fn response() -> Result<BridgeMessage, BridgeError> {
    Ok(BridgeMessage::PublicKeyResponse(
        RequestId::new(9),
        PublicBytes::bounded(&[1], 1, 1)?,
        vec![BrokerKeyMetadata::new(0, [2; 32], [3; 32], [4; 32])?],
    ))
}

fn exchange(
    name: &str,
    request_role: ExchangeRole,
    response_role: ExchangeRole,
) -> Result<(), Box<dyn Error>> {
    let path = SocketPath(
        std::env::temp_dir().join(format!("rka-task8-{name}-{}.sock", std::process::id())),
    );
    let _stale = fs::remove_file(&path.0);
    let listener = UnixListener::bind(&path.0)?;
    let server = thread::spawn(move || -> Result<(), BridgeError> {
        let (mut stream, _) = listener.accept().map_err(|_| BridgeError::Io)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|_| BridgeError::Io)?;
        let decoded = read_frame(&mut stream, request_role)?;
        if decoded.request_id() != RequestId::new(9) {
            return Err(BridgeError::Correlation);
        }
        let reply = response()?;
        let encoded = encode_frame(&reply, response_role)?;
        stream
            .write_all(encoded.as_slice())
            .map_err(|_| BridgeError::Io)
    });
    let mut client = UnixStream::connect(&path.0)?;
    let outbound = request()?;
    let encoded = encode_frame(&outbound, request_role)?;
    client.set_write_timeout(Some(Duration::from_secs(1)))?;
    client.write_all(encoded.as_slice())?;
    client.set_read_timeout(Some(Duration::from_secs(1)))?;
    let inbound = read_frame(&mut client, response_role)?;
    assert_eq!(inbound.request_id(), RequestId::new(9));
    assert!(server.join().is_ok_and(|result| result.is_ok()));
    Ok(())
}

#[test]
fn bridge_real_unix_fixture_exchanges_donor_and_candidate_roles() -> Result<(), Box<dyn Error>> {
    exchange(
        "donor",
        ExchangeRole::DonorRequest,
        ExchangeRole::DonorResponse,
    )?;
    exchange(
        "candidate",
        ExchangeRole::CandidateRequest,
        ExchangeRole::CandidateResponse,
    )
}

#[test]
fn bridge_real_unix_peer_death_is_typed_and_immediate() -> Result<(), Box<dyn Error>> {
    let (mut reader, writer) = UnixStream::pair()?;
    drop(writer);
    assert_eq!(
        read_frame(&mut reader, ExchangeRole::CandidateRequest),
        Err(BridgeError::PeerDied)
    );
    Ok(())
}

#[test]
fn bridge_correlation_rejects_kind_id_generation_replay_and_out_of_order()
-> Result<(), Box<dyn Error>> {
    let request = request()?;
    let correlation = Correlation::new(&request, 3)?;
    let response = response()?;
    assert!(correlation.accepts(&response, 3));
    assert!(!correlation.accepts(&response, 2));
    let wrong_id = BridgeMessage::PublicKeyResponse(
        RequestId::new(10),
        PublicBytes::bounded(&[1], 1, 1)?,
        vec![BrokerKeyMetadata::new(0, [2; 32], [3; 32], [4; 32])?],
    );
    assert!(!correlation.accepts(&wrong_id, 3));
    let wrong_kind = BridgeMessage::PublicResult(
        RequestId::new(9),
        NetworkHandle::new([3; 16]),
        PublicBytes::bounded(&[4], 1, 1)?,
        vec![PublicBytes::bounded(&[5], 1, 1)?],
    );
    let encoded = encode_frame(&wrong_kind, ExchangeRole::DonorResponse)?;
    let decoded_wrong_kind = decode_frame(encoded.as_slice(), ExchangeRole::DonorResponse)?;
    assert!(!correlation.accepts(&decoded_wrong_kind, 3));
    Ok(())
}

#[test]
fn bridge_preserves_two_exact_key_identities_and_rejects_order_mutation()
-> Result<(), Box<dyn Error>> {
    let message = BridgeMessage::PublicKeyResponse(
        RequestId::new(12),
        PublicBytes::bounded(&[9], 1, 1)?,
        vec![
            BrokerKeyMetadata::new(0, [1; 32], [2; 32], [3; 32])?,
            BrokerKeyMetadata::new(1, [4; 32], [5; 32], [6; 32])?,
        ],
    );
    let encoded = encode_frame(&message, ExchangeRole::DonorResponse)?;
    let decoded = decode_frame(encoded.as_slice(), ExchangeRole::DonorResponse)?;
    let BridgeMessage::PublicKeyResponse(_, _, keys) = decoded else {
        return Err("wrong response".into());
    };
    let first = keys.first().ok_or("first key")?;
    let second = keys.get(1).ok_or("second key")?;
    assert_eq!(first.handle(), &[1; 32]);
    assert_eq!(second.public_key_hash(), &[5; 32]);
    assert_eq!(second.spki_hash(), &[6; 32]);

    let mut mutated = encoded.as_slice().to_vec();
    *mutated.get_mut(127).ok_or("second order")? = 0;
    assert_eq!(
        decode_frame(&mutated, ExchangeRole::DonorResponse),
        Err(BridgeError::NonCanonical)
    );
    Ok(())
}
