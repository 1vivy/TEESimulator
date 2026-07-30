//! Real filesystem `AF_UNIX` exchange, timeout, and peer-death tests.

use std::{
    error::Error,
    fs,
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    thread,
    time::Duration,
};

use rka_sidecar::bridge::{
    BridgeError, BridgeMessage, Correlation, ExchangeRole, Hash32, NetworkHandle, PublicBytes,
    RequestId, decode_frame, encode_frame, read_frame_with_timeout, write_frame_with_timeout,
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
        vec![Hash32::new([2; 32])],
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
        let decoded = read_frame_with_timeout(&mut stream, request_role, Duration::from_secs(1))?;
        if decoded.request_id() != RequestId::new(9) {
            return Err(BridgeError::Correlation);
        }
        let reply = response()?;
        let encoded = encode_frame(&reply, response_role)?;
        write_frame_with_timeout(&mut stream, &encoded, Duration::from_secs(1))
    });
    let mut client = UnixStream::connect(&path.0)?;
    let outbound = request()?;
    let encoded = encode_frame(&outbound, request_role)?;
    write_frame_with_timeout(&mut client, &encoded, Duration::from_secs(1))?;
    let inbound = read_frame_with_timeout(&mut client, response_role, Duration::from_secs(1))?;
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
fn bridge_real_unix_blocked_read_obeys_kernel_timeout() -> Result<(), Box<dyn Error>> {
    let (mut reader, _writer) = UnixStream::pair()?;
    assert_eq!(
        read_frame_with_timeout(
            &mut reader,
            ExchangeRole::DonorResponse,
            Duration::from_millis(20),
        ),
        Err(BridgeError::Deadline)
    );
    Ok(())
}

#[test]
fn bridge_real_unix_peer_death_is_typed_and_immediate() -> Result<(), Box<dyn Error>> {
    let (mut reader, writer) = UnixStream::pair()?;
    drop(writer);
    assert_eq!(
        read_frame_with_timeout(
            &mut reader,
            ExchangeRole::CandidateRequest,
            Duration::from_secs(1),
        ),
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
        vec![Hash32::new([2; 32])],
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
