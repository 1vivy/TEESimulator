//! Canonical RKA v2 frame and request bodies.

use crate::{
    CapabilityBitmap, MAX_UPDATE_BYTES, MessageKind, PROTOCOL_VERSION, ProtocolError, RequestId,
    SessionId,
    cbor::{CborReader, CborWriter},
    envelope::{Envelope, decode_envelope_reader},
    identity::{CandidateIdentity, decode_identity_reader},
    request::{ForegroundRequest, decode_request_reader},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Hello {
    pub profile_id_hash: [u8; 32],
    pub candidate_nonce: [u8; 32],
    pub capabilities: CapabilityBitmap,
}

impl Hello {
    pub const fn new(
        profile_id_hash: [u8; 32],
        candidate_nonce: [u8; 32],
        capabilities: CapabilityBitmap,
    ) -> Self {
        Self {
            profile_id_hash,
            candidate_nonce,
            capabilities,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FrameBody<'a> {
    Hello(Hello),
    Generate {
        identity: Box<CandidateIdentity<'a>>,
        request: ForegroundRequest<'a>,
        envelope: Box<Envelope<'a>>,
        encoded: &'a [u8],
    },
    Handle([u8; 16]),
    List([u8; 32]),
    Begin([u8; 16]),
    Chunk {
        operation_handle: [u8; 16],
        chunk: &'a [u8],
    },
    Finish {
        operation_handle: [u8; 16],
        final_input: &'a [u8],
    },
    Response(&'a [u8]),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Frame<'a> {
    pub kind: MessageKind,
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub profile_epoch: u64,
    pub sequence: u32,
    pub body: FrameBody<'a>,
    pub transcript_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct FrameContext {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub profile_epoch: u64,
    pub sequence: u32,
}

impl FrameContext {
    pub const fn new(ids: (RequestId, SessionId), ordinal: (u64, u32)) -> Self {
        Self {
            request_id: ids.0,
            session_id: ids.1,
            profile_epoch: ordinal.0,
            sequence: ordinal.1,
        }
    }
}

impl<'a> Frame<'a> {
    pub const fn new(context: FrameContext, kind: MessageKind, body: FrameBody<'a>) -> Self {
        Self {
            kind,
            request_id: context.request_id,
            session_id: context.session_id,
            profile_epoch: context.profile_epoch,
            sequence: context.sequence,
            body,
            transcript_hash: [0; 32],
        }
    }

    #[must_use]
    pub const fn with_transcript_hash(mut self, transcript_hash: [u8; 32]) -> Self {
        self.transcript_hash = transcript_hash;
        self
    }
}

pub fn decode_frame(bytes: &[u8]) -> Result<Frame<'_>, ProtocolError> {
    crate::validate_deterministic_cbor(bytes)?;
    let mut reader = CborReader::new(bytes);
    if reader.map()? != 8 {
        return Err(ProtocolError::MissingField);
    }
    expect_unsigned(&mut reader, 0, PROTOCOL_VERSION)?;
    expect_key(&mut reader, 1)?;
    let kind = MessageKind::try_from(reader.unsigned()?)?;
    expect_key(&mut reader, 2)?;
    let request_id = RequestId::new(fixed(reader.bytes()?)?);
    expect_key(&mut reader, 3)?;
    let session_id = SessionId::new(fixed(reader.bytes()?)?);
    expect_key(&mut reader, 4)?;
    let profile_epoch = reader.unsigned()?;
    expect_key(&mut reader, 5)?;
    let sequence =
        u32::try_from(reader.unsigned()?).map_err(|_| ProtocolError::LengthOutOfRange)?;
    expect_key(&mut reader, 6)?;
    let body = decode_body(&mut reader, kind)?;
    expect_key(&mut reader, 7)?;
    let transcript_hash = fixed(reader.bytes()?)?;
    if !reader.is_complete() {
        return Err(ProtocolError::UnknownField);
    }
    Ok(Frame {
        kind,
        request_id,
        session_id,
        profile_epoch,
        sequence,
        body,
        transcript_hash,
    })
}

#[must_use]
pub fn encode_frame_without_transcript(frame: &Frame<'_>) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(256);
    writer.map(7);
    encode_header(&mut writer, frame);
    writer.finish()
}

#[must_use]
pub fn encode_frame(frame: &Frame<'_>) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(320);
    writer.map(8);
    encode_header(&mut writer, frame);
    writer.unsigned(7);
    writer.bytes(&frame.transcript_hash);
    writer.finish()
}

fn encode_header(writer: &mut CborWriter, frame: &Frame<'_>) {
    writer.unsigned(0);
    writer.unsigned(PROTOCOL_VERSION);
    writer.unsigned(1);
    writer.unsigned(frame.kind.into());
    writer.unsigned(2);
    writer.bytes(&frame.request_id.bytes());
    writer.unsigned(3);
    writer.bytes(&frame.session_id.bytes());
    writer.unsigned(4);
    writer.unsigned(frame.profile_epoch);
    writer.unsigned(5);
    writer.unsigned(u64::from(frame.sequence));
    writer.unsigned(6);
    encode_body(writer, &frame.body);
}

include!("frame_body.rs");

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

fn expect_unsigned(
    reader: &mut CborReader<'_>,
    key: u64,
    expected: u64,
) -> Result<(), ProtocolError> {
    expect_key(reader, key)?;
    if reader.unsigned()? == expected {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedValue)
    }
}
