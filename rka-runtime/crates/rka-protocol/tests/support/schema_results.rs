fn result_generate(writer: &mut CborWriter, previous: &[u8; 32]) {
    result(writer, (MessageKind::Generate, generate_result, previous));
}

fn result_get(writer: &mut CborWriter, previous: &[u8; 32]) {
    result(writer, (MessageKind::Get, generate_result, previous));
}

fn generate_result(writer: &mut CborWriter, previous: &[u8; 32]) {
    writer.map(5);
    pair_bytes(writer, 0, &[0x55; 16]);
    key(writer, 1);
    writer.array(2);
    writer.bytes(&[0x30, 0x01]);
    writer.bytes(&[0x30, 0x02]);
    pair_bytes(writer, 2, &[0x12; 32]);
    key(writer, 3);
    envelope(writer, &identity_hash());
    key(writer, 4);
    leaf_proof(writer, previous);
}

fn leaf_proof(writer: &mut CborWriter, previous: &[u8; 32]) {
    writer.map(6);
    for (key_value, byte) in (0_u64..5).zip(0x21_u8..=0x25) {
        pair_bytes(writer, key_value, &[byte; 32]);
    }
    pair_bytes(writer, 5, &leaf_signature(previous));
}

fn result_list(writer: &mut CborWriter, previous: &[u8; 32]) {
    result(
        writer,
        (
            MessageKind::List,
            |result, _| {
                result.map(1);
                key(result, 0);
                result.array(1);
                result.array(3);
                result.bytes(&[0x55; 16]);
                result.bytes(&[0x33; 32]);
                result.unsigned(1);
            },
            previous,
        ),
    );
}

fn result_delete(writer: &mut CborWriter, previous: &[u8; 32]) {
    result(
        writer,
        (
            MessageKind::Delete,
            |result, _| {
                boolean_result(result, true);
            },
            previous,
        ),
    );
}

fn result_begin(writer: &mut CborWriter, previous: &[u8; 32]) {
    result(
        writer,
        (
            MessageKind::Begin,
            |result, _| {
                result.map(2);
                pair_bytes(result, 0, &[0x77; 16]);
                pair_unsigned(result, 1, 65_536);
            },
            previous,
        ),
    );
}

fn result_update_aad(writer: &mut CborWriter, previous: &[u8; 32]) {
    result(writer, (MessageKind::UpdateAad, update_result, previous));
}

fn result_update(writer: &mut CborWriter, previous: &[u8; 32]) {
    result(writer, (MessageKind::Update, update_result, previous));
}

fn update_result(writer: &mut CborWriter, _previous: &[u8; 32]) {
    writer.map(2);
    pair_unsigned(writer, 0, 5);
    pair_bytes(writer, 1, b"out");
}

fn result_finish(writer: &mut CborWriter, previous: &[u8; 32]) {
    result(
        writer,
        (
            MessageKind::Finish,
            |result, _| {
                result.map(2);
                pair_bytes(result, 0, &[0x30, 0x44]);
                pair_bytes(result, 1, &[0x88; 32]);
            },
            previous,
        ),
    );
}

fn result_abort(writer: &mut CborWriter, previous: &[u8; 32]) {
    result(
        writer,
        (
            MessageKind::Abort,
            |result, _| {
                boolean_result(result, true);
            },
            previous,
        ),
    );
}

type ResultInput<'a> = (MessageKind, BodyWriter, &'a [u8; 32]);

fn result(writer: &mut CborWriter, input: ResultInput<'_>) {
    let (triggering, body, previous) = input;
    writer.map(2);
    pair_unsigned(writer, 0, triggering.into());
    key(writer, 1);
    body(writer, previous);
}

fn boolean_result(writer: &mut CborWriter, value: bool) {
    writer.map(1);
    key(writer, 0);
    writer.boolean(value);
}

fn error(writer: &mut CborWriter, _previous: &[u8; 32]) {
    writer.map(5);
    pair_unsigned(writer, 0, MessageKind::Generate.into());
    pair_unsigned(writer, 1, 1);
    key(writer, 2);
    writer.boolean(false);
    key(writer, 3);
    writer.boolean(false);
    pair_bytes(writer, 4, &[0x90; 32]);
}
