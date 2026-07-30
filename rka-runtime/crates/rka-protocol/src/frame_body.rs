fn decode_body<'a>(
    reader: &mut CborReader<'a>,
    kind: MessageKind,
) -> Result<FrameBody<'a>, ProtocolError> {
    match kind {
        MessageKind::Hello => decode_hello(reader).map(FrameBody::Hello),
        MessageKind::Generate => decode_generate(reader),
        MessageKind::Get | MessageKind::Delete | MessageKind::Abort => {
            decode_single_bytes(reader).map(FrameBody::Handle)
        }
        MessageKind::List => decode_single_bytes(reader).map(FrameBody::List),
        MessageKind::Begin => decode_begin(reader).map(FrameBody::Begin),
        MessageKind::UpdateAad | MessageKind::Update => decode_chunk(reader),
        MessageKind::Finish => decode_finish(reader),
        MessageKind::HelloAck | MessageKind::Result | MessageKind::Error => {
            let start = reader.position();
            crate::response::validate_response_reader(reader, kind)?;
            Ok(FrameBody::Response(reader.slice_from(start)?))
        }
    }
}

fn decode_hello(reader: &mut CborReader<'_>) -> Result<Hello, ProtocolError> {
    if reader.map()? != 5 {
        return Err(ProtocolError::MissingField);
    }
    expect_unsigned(reader, 0, 1)?;
    expect_unsigned(reader, 1, 1)?;
    expect_key(reader, 2)?;
    let profile_id_hash = fixed(reader.bytes()?)?;
    expect_key(reader, 3)?;
    let candidate_nonce = fixed(reader.bytes()?)?;
    expect_key(reader, 4)?;
    let capabilities = CapabilityBitmap::parse(reader.unsigned()?)?;
    Ok(Hello {
        profile_id_hash,
        candidate_nonce,
        capabilities,
    })
}

fn decode_generate<'a>(reader: &mut CborReader<'a>) -> Result<FrameBody<'a>, ProtocolError> {
    let start = reader.position();
    if reader.map()? != 3 {
        return Err(ProtocolError::MissingField);
    }
    expect_key(reader, 0)?;
    let identity = decode_identity_reader(reader)?;
    expect_key(reader, 1)?;
    let request = decode_request_reader(reader)?;
    expect_key(reader, 2)?;
    let envelope = decode_envelope_reader(reader)?;
    let encoded = reader.slice_from(start)?;
    Ok(FrameBody::Generate {
        identity: Box::new(identity),
        request,
        envelope: Box::new(envelope),
        encoded,
    })
}

fn decode_single_bytes<const N: usize>(
    reader: &mut CborReader<'_>,
) -> Result<[u8; N], ProtocolError> {
    if reader.map()? != 1 {
        return Err(ProtocolError::MissingField);
    }
    expect_key(reader, 0)?;
    fixed(reader.bytes()?)
}

fn decode_begin(reader: &mut CborReader<'_>) -> Result<[u8; 16], ProtocolError> {
    if reader.map()? != 4 {
        return Err(ProtocolError::MissingField);
    }
    expect_key(reader, 0)?;
    let handle = fixed(reader.bytes()?)?;
    expect_unsigned(reader, 1, 2)?;
    expect_unsigned(reader, 2, 4)?;
    expect_unsigned(reader, 3, 0)?;
    Ok(handle)
}

fn decode_chunk<'a>(reader: &mut CborReader<'a>) -> Result<FrameBody<'a>, ProtocolError> {
    if reader.map()? != 2 {
        return Err(ProtocolError::MissingField);
    }
    expect_key(reader, 0)?;
    let operation_handle = fixed(reader.bytes()?)?;
    expect_key(reader, 1)?;
    let chunk = reader.bytes()?;
    if chunk.len() > MAX_UPDATE_BYTES {
        return Err(ProtocolError::LengthOutOfRange);
    }
    Ok(FrameBody::Chunk {
        operation_handle,
        chunk,
    })
}

fn decode_finish<'a>(reader: &mut CborReader<'a>) -> Result<FrameBody<'a>, ProtocolError> {
    if reader.map()? != 2 {
        return Err(ProtocolError::MissingField);
    }
    expect_key(reader, 0)?;
    let operation_handle = fixed(reader.bytes()?)?;
    expect_key(reader, 1)?;
    let final_input = reader.bytes()?;
    if final_input.len() > MAX_UPDATE_BYTES {
        return Err(ProtocolError::LengthOutOfRange);
    }
    Ok(FrameBody::Finish {
        operation_handle,
        final_input,
    })
}

fn encode_body(writer: &mut CborWriter, body: &FrameBody<'_>) {
    match body {
        FrameBody::Hello(hello) => {
            writer.map(5);
            writer.unsigned(0);
            writer.unsigned(1);
            writer.unsigned(1);
            writer.unsigned(1);
            writer.unsigned(2);
            writer.bytes(&hello.profile_id_hash);
            writer.unsigned(3);
            writer.bytes(&hello.candidate_nonce);
            writer.unsigned(4);
            writer.unsigned(hello.capabilities.bits());
        }
        FrameBody::Handle(handle) => encode_handle(writer, handle),
        FrameBody::List(identity_hash) => encode_handle(writer, identity_hash),
        FrameBody::Begin(handle) => encode_begin(writer, handle),
        FrameBody::Chunk {
            operation_handle,
            chunk,
        } => encode_pair(writer, operation_handle, chunk),
        FrameBody::Finish {
            operation_handle,
            final_input,
        } => encode_pair(writer, operation_handle, final_input),
        FrameBody::Response(bytes) => writer.raw(bytes),
        FrameBody::Generate { encoded, .. } => writer.raw(encoded),
    }
}

fn encode_handle<const N: usize>(writer: &mut CborWriter, handle: &[u8; N]) {
    writer.map(1);
    writer.unsigned(0);
    writer.bytes(handle);
}

fn encode_begin(writer: &mut CborWriter, handle: &[u8; 16]) {
    writer.map(4);
    writer.unsigned(0);
    writer.bytes(handle);
    writer.unsigned(1);
    writer.unsigned(2);
    writer.unsigned(2);
    writer.unsigned(4);
    writer.unsigned(3);
    writer.unsigned(0);
}

fn encode_pair(writer: &mut CborWriter, handle: &[u8; 16], bytes: &[u8]) {
    writer.map(2);
    writer.unsigned(0);
    writer.bytes(handle);
    writer.unsigned(1);
    writer.bytes(bytes);
}
