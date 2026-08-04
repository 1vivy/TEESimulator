#![allow(
    clippy::redundant_pub_crate,
    reason = "the crate-private codec shares closed record types with its sibling budget module"
)]

use rka_protocol::{CborWriter, validate_deterministic_cbor};

use crate::{StateError, replay_codec::Decoder};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeerFailures {
    pub(crate) namespace: [u8; 32],
    pub(crate) timestamps: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FailureState {
    pub(crate) observed_at: u64,
    pub(crate) peers: Vec<PeerFailures>,
}

pub(crate) fn encode(state: &FailureState) -> Vec<u8> {
    let timestamp_count = state
        .peers
        .iter()
        .map(|peer| peer.timestamps.len())
        .sum::<usize>();
    let mut writer = CborWriter::with_capacity(
        16_usize
            .saturating_add(state.peers.len().saturating_mul(40))
            .saturating_add(timestamp_count.saturating_mul(9)),
    );
    writer.array(2);
    writer.unsigned(state.observed_at);
    writer.array(state.peers.len());
    for peer in &state.peers {
        writer.array(2);
        writer.bytes(&peer.namespace);
        writer.array(peer.timestamps.len());
        for timestamp in &peer.timestamps {
            writer.unsigned(*timestamp);
        }
    }
    writer.finish()
}

pub(crate) fn decode(
    bytes: &[u8],
    maximum_peers: usize,
    maximum_timestamps: usize,
) -> Result<FailureState, StateError> {
    validate_deterministic_cbor(bytes).map_err(|_| StateError::Corrupt)?;
    let mut decoder = Decoder::new(bytes);
    if decoder.array()? != 2 {
        return Err(StateError::Corrupt);
    }
    let observed_at = decoder.unsigned()?;
    let count = decoder.array()?;
    if count > maximum_peers {
        return Err(StateError::Corrupt);
    }
    let mut peers = Vec::with_capacity(count);
    for _ in 0..count {
        if decoder.array()? != 2 {
            return Err(StateError::Corrupt);
        }
        let namespace = decoder
            .bytes()?
            .try_into()
            .map_err(|_| StateError::Corrupt)?;
        let timestamp_count = decoder.array()?;
        if timestamp_count == 0 || timestamp_count > maximum_timestamps {
            return Err(StateError::Corrupt);
        }
        let mut timestamps = Vec::with_capacity(timestamp_count);
        for _ in 0..timestamp_count {
            let timestamp = decoder.unsigned()?;
            if timestamp > observed_at
                || timestamps
                    .last()
                    .is_some_and(|previous| timestamp < *previous)
            {
                return Err(StateError::Corrupt);
            }
            timestamps.push(timestamp);
        }
        if peers
            .last()
            .is_some_and(|previous: &PeerFailures| previous.namespace >= namespace)
        {
            return Err(StateError::Corrupt);
        }
        peers.push(PeerFailures {
            namespace,
            timestamps,
        });
    }
    if !decoder.complete() {
        return Err(StateError::Corrupt);
    }
    Ok(FailureState { observed_at, peers })
}
