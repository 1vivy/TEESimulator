fn hello(writer: &mut CborWriter, _previous: &[u8; 32]) {
    writer.map(5);
    pair_unsigned(writer, 0, 1);
    pair_unsigned(writer, 1, 1);
    pair_bytes(writer, 2, &[0x33; 32]);
    pair_bytes(writer, 3, &[0x44; 32]);
    pair_unsigned(writer, 4, 15);
}

fn hello_ack(writer: &mut CborWriter, _previous: &[u8; 32]) {
    writer.map(4);
    key(writer, 0);
    writer.boolean(true);
    pair_bytes(writer, 1, &[0x41; 32]);
    pair_bytes(writer, 2, &[0x42; 32]);
    pair_bytes(writer, 3, &[0x43; 32]);
}

fn generate(writer: &mut CborWriter, _previous: &[u8; 32]) {
    let identity_hash = identity_hash();
    writer.map(3);
    key(writer, 0);
    identity(writer, &identity_hash);
    key(writer, 1);
    foreground_request(writer);
    key(writer, 2);
    envelope(writer, &identity_hash);
}

fn identity_hash() -> [u8; 32] {
    let mut writer = CborWriter::with_capacity(128);
    writer.map(5);
    pair_unsigned(&mut writer, 0, 0);
    pair_unsigned(&mut writer, 1, 10_123);
    packages(&mut writer);
    pair_bytes(&mut writer, 3, &[0x30, 0x00]);
    pair_bytes(&mut writer, 5, &[0x99; 32]);
    hash_cbor(HashDomain::Identity, &writer.finish())
}

fn identity(writer: &mut CborWriter, identity_hash: &[u8; 32]) {
    writer.map(6);
    pair_unsigned(writer, 0, 0);
    pair_unsigned(writer, 1, 10_123);
    packages(writer);
    pair_bytes(writer, 3, &[0x30, 0x00]);
    pair_bytes(writer, 4, identity_hash);
    pair_bytes(writer, 5, &[0x99; 32]);
}

fn packages(writer: &mut CborWriter) {
    key(writer, 2);
    writer.array(1);
    writer.array(3);
    writer.text("org.example.app");
    writer.unsigned(1);
    writer.array(1);
    writer.bytes(&[0x30, 0x01]);
}

fn foreground_request(writer: &mut CborWriter) {
    writer.map(7);
    for (key_value, value) in [(0, 1), (1, 3), (2, 1), (3, 2), (4, 4)] {
        pair_unsigned(writer, key_value, value);
    }
    pair_bytes(writer, 5, &[0x66; 16]);
    pair_bytes(writer, 6, &[0x55; 16]);
}

fn envelope(writer: &mut CborWriter, identity_hash: &[u8; 32]) {
    writer.map(11);
    pair_unsigned(writer, 0, 1);
    pair_bytes(writer, 1, identity_hash);
    pair_bytes(writer, 2, &[0xaa; 32]);
    pair_unsigned(writer, 3, 7);
    pair_bytes(writer, 4, &[0xcc; 32]);
    pair_bytes(writer, 5, &[0xdd; 32]);
    pair_bytes(writer, 6, &[0xee; 32]);
    pair_unsigned(writer, 13, 1_000);
    pair_unsigned(writer, 14, TTL_SECONDS);
    pair_unsigned(writer, 15, 1);
    pair_unsigned(writer, 16, 0);
}

fn alias(writer: &mut CborWriter, _previous: &[u8; 32]) {
    single_bytes(writer, &[0x55; 16]);
}

fn identity_handle(writer: &mut CborWriter, _previous: &[u8; 32]) {
    single_bytes(writer, &[0x33; 32]);
}

fn operation(writer: &mut CborWriter, _previous: &[u8; 32]) {
    single_bytes(writer, &[0x77; 16]);
}

fn single_bytes(writer: &mut CborWriter, value: &[u8]) {
    writer.map(1);
    pair_bytes(writer, 0, value);
}

fn begin(writer: &mut CborWriter, _previous: &[u8; 32]) {
    writer.map(4);
    pair_bytes(writer, 0, &[0x55; 16]);
    pair_unsigned(writer, 1, 2);
    pair_unsigned(writer, 2, 4);
    pair_unsigned(writer, 3, 0);
}

fn chunk(writer: &mut CborWriter, _previous: &[u8; 32]) {
    writer.map(2);
    pair_bytes(writer, 0, &[0x77; 16]);
    pair_bytes(writer, 1, b"chunk");
}

fn finish(writer: &mut CborWriter, _previous: &[u8; 32]) {
    writer.map(2);
    pair_bytes(writer, 0, &[0x77; 16]);
    pair_bytes(writer, 1, b"final");
}

fn pair_unsigned(writer: &mut CborWriter, key_value: u64, value: u64) {
    key(writer, key_value);
    writer.unsigned(value);
}

fn pair_bytes(writer: &mut CborWriter, key_value: u64, value: &[u8]) {
    key(writer, key_value);
    writer.bytes(value);
}

fn key(writer: &mut CborWriter, value: u64) {
    writer.unsigned(value);
}
