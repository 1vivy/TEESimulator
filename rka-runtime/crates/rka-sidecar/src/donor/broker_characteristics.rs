use rka_protocol::{CborWriter, HashDomain, hash_cbor};

pub(super) fn exact_characteristics_hash() -> [u8; 32] {
    let mut writer = CborWriter::with_capacity(32);
    writer.map(8);
    for (key, value) in [(0, 1), (1, 3), (2, 1)] {
        writer.unsigned(key);
        writer.unsigned(value);
    }
    writer.unsigned(3);
    writer.array(1);
    writer.unsigned(2);
    writer.unsigned(4);
    writer.array(1);
    writer.unsigned(4);
    writer.unsigned(5);
    writer.unsigned(0);
    writer.unsigned(6);
    writer.boolean(true);
    writer.unsigned(7);
    writer.boolean(false);
    hash_cbor(HashDomain::Profile, &writer.finish())
}
