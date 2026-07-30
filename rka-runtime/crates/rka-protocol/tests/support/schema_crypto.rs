fn envelope_bytes() -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(384);
    envelope(&mut writer, &identity_hash());
    writer.finish()
}

fn leaf_signature(previous: &[u8; 32]) -> Vec<u8> {
    let envelope_hash = hash_cbor(HashDomain::Envelope, &envelope_bytes());
    let mut preimage = Vec::with_capacity(160);
    preimage.extend_from_slice(b"TEESIM-RKA-V2/LEAF-PROOF\0");
    preimage.extend_from_slice(&envelope_hash);
    preimage.extend_from_slice(previous);
    preimage.extend_from_slice(&[0x21; 32]);
    preimage.extend_from_slice(&[0x22; 32]);
    der_signature(&sha256(&preimage))
}

fn der_signature(digest: &[u8; 32]) -> Vec<u8> {
    let (left, right) = digest.split_at(16);
    let first = der_integer(left);
    let second = der_integer(right);
    let length = first.len().saturating_add(second.len());
    let mut signature = Vec::with_capacity(length.saturating_add(2));
    signature.push(0x30);
    signature.push(u8::try_from(length).map_or(u8::MAX, |value| value));
    signature.extend_from_slice(&first);
    signature.extend_from_slice(&second);
    signature
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    let needs_prefix = value.first().is_some_and(|byte| byte & 0x80 != 0);
    let length = value.len().saturating_add(usize::from(needs_prefix));
    let mut encoded = Vec::with_capacity(length.saturating_add(2));
    encoded.push(0x02);
    encoded.push(u8::try_from(length).map_or(u8::MAX, |byte| byte));
    if needs_prefix {
        encoded.push(0);
    }
    encoded.extend_from_slice(value);
    encoded
}
