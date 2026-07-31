use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
};

use crate::bridge::{BridgeMessage, ExchangeRole, decode_frame, encode_frame};

use super::BrokerFailure;
use super::broker_bridge::BridgeDonorBroker;

impl BridgeDonorBroker {
    #[must_use]
    pub(super) fn new_local_test(socket: &Path) -> Self {
        let mut broker = Self::new(socket);
        broker.local_codec = true;
        broker
    }
}

pub(super) fn local_exchange(
    socket: &Path,
    request: &BridgeMessage,
) -> Result<BridgeMessage, BrokerFailure> {
    let mut stream = UnixStream::connect(socket).map_err(|_| BrokerFailure::Unavailable)?;
    let encoded =
        encode_frame(request, ExchangeRole::DonorRequest).map_err(|_| BrokerFailure::Rejected)?;
    stream
        .write_all(encoded.as_slice())
        .map_err(|_| BrokerFailure::Unavailable)?;
    let mut header = [0; 24];
    stream
        .read_exact(&mut header)
        .map_err(|_| BrokerFailure::Unavailable)?;
    let length = u32::from_be_bytes(
        header[16..20]
            .try_into()
            .map_err(|_| BrokerFailure::Rejected)?,
    ) as usize;
    let mut response = header.to_vec();
    response.resize(24_usize.saturating_add(length), 0);
    stream
        .read_exact(response.get_mut(24..).ok_or(BrokerFailure::Rejected)?)
        .map_err(|_| BrokerFailure::Unavailable)?;
    decode_frame(&response, ExchangeRole::DonorResponse).map_err(|_| BrokerFailure::Rejected)
}
