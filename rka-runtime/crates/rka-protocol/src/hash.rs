//! SHA-256 domain-separated protocol hashes.

use crate::{
    AAID_DOMAIN, AUDIT_DOMAIN, CHAIN_SET_DOMAIN, ENVELOPE_DOMAIN, FRAME_DOMAIN, IDENTITY_DOMAIN,
    IRPC_DOMAIN, LEAF_PROOF_DOMAIN, PROFILE_DOMAIN, RKP_PUBLIC_DOMAIN,
};

const INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const ROUND: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HashDomain {
    Frame,
    Identity,
    Aaid,
    Profile,
    Irpc,
    RkpPublic,
    ChainSet,
    Envelope,
    LeafProof,
    Audit,
}

impl HashDomain {
    #[must_use]
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Frame => FRAME_DOMAIN,
            Self::Identity => IDENTITY_DOMAIN,
            Self::Aaid => AAID_DOMAIN,
            Self::Profile => PROFILE_DOMAIN,
            Self::Irpc => IRPC_DOMAIN,
            Self::RkpPublic => RKP_PUBLIC_DOMAIN,
            Self::ChainSet => CHAIN_SET_DOMAIN,
            Self::Envelope => ENVELOPE_DOMAIN,
            Self::LeafProof => LEAF_PROOF_DOMAIN,
            Self::Audit => AUDIT_DOMAIN,
        }
    }
}

#[must_use]
pub fn hash_bytes(domain: HashDomain, bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(domain.bytes().len().saturating_add(bytes.len()));
    input.extend_from_slice(domain.bytes());
    input.extend_from_slice(bytes);
    sha256(&input)
}

#[must_use]
pub fn hash_cbor(domain: HashDomain, canonical_cbor: &[u8]) -> [u8; 32] {
    hash_bytes(domain, canonical_cbor)
}

#[must_use]
pub fn transcript_hash(previous: &[u8; 32], frame_without_transcript: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        FRAME_DOMAIN
            .len()
            .saturating_add(previous.len())
            .saturating_add(frame_without_transcript.len()),
    );
    input.extend_from_slice(FRAME_DOMAIN);
    input.extend_from_slice(previous);
    input.extend_from_slice(frame_without_transcript);
    sha256(&input)
}

#[must_use]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let bit_length = u64::try_from(input.len()).map_or(u64::MAX, |length| length.saturating_mul(8));
    let padded_length = input
        .len()
        .saturating_add(9)
        .div_ceil(64)
        .saturating_mul(64);
    let mut padded = Vec::with_capacity(padded_length);
    padded.extend_from_slice(input);
    padded.push(0x80);
    padded.resize(padded_length.saturating_sub(8), 0);
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = INITIAL;
    for block in padded.chunks_exact(64) {
        compress(&mut state, block);
    }
    let mut output = [0_u8; 32];
    for (target, word) in output.chunks_exact_mut(4).zip(state) {
        target.copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut words = Vec::with_capacity(64);
    for bytes in block.chunks_exact(4) {
        let word = <[u8; 4]>::try_from(bytes).map_or(0, u32::from_be_bytes);
        words.push(word);
    }
    for index in 16_usize..64 {
        let index_15 = index.saturating_sub(15);
        let index_2 = index.saturating_sub(2);
        let s0 = word(&words, index_15).rotate_right(7)
            ^ word(&words, index_15).rotate_right(18)
            ^ (word(&words, index_15) >> 3);
        let s1 = word(&words, index_2).rotate_right(17)
            ^ word(&words, index_2).rotate_right(19)
            ^ (word(&words, index_2) >> 10);
        words.push(
            word(&words, index.saturating_sub(16))
                .wrapping_add(s0)
                .wrapping_add(word(&words, index.saturating_sub(7)))
                .wrapping_add(s1),
        );
    }
    let mut working = *state;
    for (index, constant) in ROUND.iter().enumerate() {
        let sigma1 = word(&working, 4).rotate_right(6)
            ^ word(&working, 4).rotate_right(11)
            ^ word(&working, 4).rotate_right(25);
        let choose =
            (word(&working, 4) & word(&working, 5)) ^ (!word(&working, 4) & word(&working, 6));
        let temporary1 = word(&working, 7)
            .wrapping_add(sigma1)
            .wrapping_add(choose)
            .wrapping_add(*constant)
            .wrapping_add(word(&words, index));
        let sigma0 = word(&working, 0).rotate_right(2)
            ^ word(&working, 0).rotate_right(13)
            ^ word(&working, 0).rotate_right(22);
        let majority = (word(&working, 0) & word(&working, 1))
            ^ (word(&working, 0) & word(&working, 2))
            ^ (word(&working, 1) & word(&working, 2));
        working = [
            temporary1.wrapping_add(sigma0).wrapping_add(majority),
            word(&working, 0),
            word(&working, 1),
            word(&working, 2),
            word(&working, 3).wrapping_add(temporary1),
            word(&working, 4),
            word(&working, 5),
            word(&working, 6),
        ];
    }
    for (target, value) in state.iter_mut().zip(working) {
        *target = target.wrapping_add(value);
    }
}

fn word(values: &[u32], index: usize) -> u32 {
    values.get(index).copied().map_or(0, |value| value)
}
