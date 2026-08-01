use rka_protocol::{CborWriter, HashDomain, hash_cbor};

use crate::{ProfileInput, Role};

#[doc(hidden)]
pub fn profile_id(input: &ProfileInput) -> [u8; 32] {
    let donor_spki = match input.local_role {
        Role::Donor => input.local_spki,
        Role::Candidate => input.peer_spki,
    };
    let candidate_spki = match input.local_role {
        Role::Candidate => input.local_spki,
        Role::Donor => input.peer_spki,
    };
    let mut map = CborWriter::with_capacity(512);
    map.map(10);
    map.unsigned(0);
    map.unsigned(2);
    map.unsigned(1);
    map.unsigned(input.epoch);
    map.unsigned(2);
    map.bytes(&donor_spki);
    map.unsigned(3);
    map.bytes(&candidate_spki);
    map.unsigned(4);
    map.text(input.endpoint.host());
    map.unsigned(5);
    map.unsigned(u64::from(input.endpoint.port()));
    map.unsigned(6);
    map.array(input.allowed_identities.len());
    for identity in &input.allowed_identities {
        map.bytes(identity);
    }
    map.unsigned(7);
    map.bytes(&input.root_hash);
    map.unsigned(8);
    map.unsigned(input.policy_version);
    map.unsigned(9);
    map.unsigned(input.dial_mode.tag());
    let map = map.finish();
    let mut preimage = Vec::with_capacity(map.len().saturating_add(14));
    preimage.extend_from_slice(&[0xa2, 0x00, 0x6a]);
    preimage.extend_from_slice(b"profile-id");
    preimage.push(0x01);
    preimage.extend_from_slice(&map);
    hash_cbor(HashDomain::Profile, &preimage)
}
