type BodyWriter = fn(&mut CborWriter, &[u8; 32]);

struct SchemaVector {
    pub name: &'static str,
    pub bytes: Vec<u8>,
}

fn schema_vectors() -> Vec<SchemaVector> {
    let specifications: [(&str, MessageKind, BodyWriter); 21] = [
        ("hello", MessageKind::Hello, hello),
        ("hello_ack", MessageKind::HelloAck, hello_ack),
        ("generate", MessageKind::Generate, generate),
        ("get", MessageKind::Get, alias),
        ("list", MessageKind::List, identity_handle),
        ("delete", MessageKind::Delete, alias),
        ("begin", MessageKind::Begin, begin),
        ("update_aad", MessageKind::UpdateAad, chunk),
        ("update", MessageKind::Update, chunk),
        ("finish", MessageKind::Finish, finish),
        ("abort", MessageKind::Abort, operation),
        ("result_generate", MessageKind::Result, result_generate),
        ("result_get", MessageKind::Result, result_get),
        ("result_list", MessageKind::Result, result_list),
        ("result_delete", MessageKind::Result, result_delete),
        ("result_begin", MessageKind::Result, result_begin),
        ("result_update_aad", MessageKind::Result, result_update_aad),
        ("result_update", MessageKind::Result, result_update),
        ("result_finish", MessageKind::Result, result_finish),
        ("result_abort", MessageKind::Result, result_abort),
        ("error", MessageKind::Error, error),
    ];
    let mut previous = [0_u8; 32];
    specifications
        .into_iter()
        .enumerate()
        .map(|(sequence, (name, kind, body))| {
            let (bytes, current) = frame((kind, sequence, body, &previous));
            previous = current;
            SchemaVector { name, bytes }
        })
        .collect()
}

fn old_begin_frame() -> Vec<u8> {
    frame((MessageKind::Begin, 0, alias, &[0; 32])).0
}

fn wrong_begin_result_frame() -> Vec<u8> {
    frame((MessageKind::Result, 0, wrong_begin_result, &[0; 32])).0
}

fn wrong_begin_result(writer: &mut CborWriter, _previous: &[u8; 32]) {
    writer.map(2);
    pair_unsigned(writer, 0, MessageKind::Begin.into());
    key(writer, 1);
    writer.map(2);
    pair_bytes(writer, 0, &[0x77; 16]);
    pair_unsigned(writer, 1, 65_535);
}

type FrameInput<'a> = (MessageKind, usize, BodyWriter, &'a [u8; 32]);

fn frame(input: FrameInput<'_>) -> (Vec<u8>, [u8; 32]) {
    let previous = input.3;
    let without_transcript = frame_map(7, input, None);
    let current = transcript_hash(previous, &without_transcript);
    (frame_map(8, input, Some(&current)), current)
}

fn frame_map(
    count: usize,
    input: FrameInput<'_>,
    transcript: Option<&[u8; 32]>,
) -> Vec<u8> {
    let (kind, sequence, body, previous) = input;
    let mut writer = CborWriter::with_capacity(768);
    writer.map(count);
    pair_unsigned(&mut writer, 0, 2);
    pair_unsigned(&mut writer, 1, kind.into());
    pair_bytes(&mut writer, 2, &[0x22; 16]);
    pair_bytes(&mut writer, 3, &[0x11; 32]);
    pair_unsigned(&mut writer, 4, 7);
    pair_unsigned(
        &mut writer,
        5,
        u64::try_from(sequence).map_or(u64::MAX, |value| value),
    );
    key(&mut writer, 6);
    body(&mut writer, previous);
    if let Some(value) = transcript {
        pair_bytes(&mut writer, 7, value);
    }
    writer.finish()
}
