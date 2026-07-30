//! Authenticated RKB1 broker bridge.
#![allow(
    clippy::mod_module_files,
    reason = "the task ownership boundary requires the module root under src/bridge/"
)]

mod cancel;
mod codec;
mod decode_body;
mod error;
mod identity;
mod model;
mod runtime;
mod trusted_record;

pub use cancel::CancellationToken;
pub use codec::{
    EncodedFrame, decode_frame, encode_frame, read_frame, read_frame_with_timeout,
    write_frame_with_timeout,
};
pub use error::BridgeError;
pub use identity::{BrokerRole, PeerCredentials, authenticate_broker_peer};
pub use model::{
    BridgeMessage, Correlation, ExchangeRole, Hash32, NetworkHandle, PublicBytes, RequestId,
    expected_response_tag,
};
pub use runtime::{RoleExecutor, RuntimeSnapshot, SidecarRole};
