use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
};

use crate::bridge::{
    BridgeMessage, CandidateBridgeOperation, ExchangeRole, PublicBytes, RequestId, decode_frame,
    encode_frame,
};

pub(super) fn serve(listener: &UnixListener, ordinal: u8) -> Result<Vec<u8>, String> {
    let (mut stream, command) = receive(listener)?;
    let response = encode_frame(
        &reply(ordinal).map_err(|error| error.to_string())?,
        ExchangeRole::DonorResponse,
    )
    .map_err(|error| error.to_string())?;
    stream
        .write_all(response.as_slice())
        .map_err(|error| error.to_string())?;
    let payload = generate_payload(command)?;
    let mut eof = [0; 1];
    if stream.read(&mut eof).map_err(|error| error.to_string())? != 0 {
        return Err("sidecar sent trailing broker bytes".to_owned());
    }
    Ok(payload)
}

pub(super) fn capture_without_response(listener: &UnixListener) -> Result<Vec<u8>, String> {
    let (_stream, command) = receive(listener)?;
    generate_payload(command)
}

fn receive(
    listener: &UnixListener,
) -> Result<(std::os::unix::net::UnixStream, BridgeMessage), String> {
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
    let command =
        decode_frame(&request, ExchangeRole::DonorRequest).map_err(|error| error.to_string())?;
    Ok((stream, command))
}

fn reply(ordinal: u8) -> Result<BridgeMessage, Box<dyn std::error::Error>> {
    let mut payload = vec![0xd0 | ordinal; 16];
    put_bytes(&mut payload, format!("leaf-spki-{ordinal}").as_bytes());
    payload.push(2);
    put_bytes(&mut payload, format!("leaf-{ordinal}").as_bytes());
    put_bytes(&mut payload, format!("root-{ordinal}").as_bytes());
    put_bytes(
        &mut payload,
        format!("transcript-signature-{ordinal}").as_bytes(),
    );
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

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    output.extend_from_slice(value);
}
