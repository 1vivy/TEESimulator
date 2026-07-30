//! Authenticated RKB1 broker bridge.
#![allow(
    clippy::mod_module_files,
    reason = "the task ownership boundary requires the module root under src/bridge/"
)]

mod codec;
mod deadline;
mod decode_body;
mod error;
mod executor_state;
mod identity;
mod model;
mod runtime;
mod socket;
#[cfg(test)]
mod socket_tests;
mod trusted_record;

pub use codec::{EncodedFrame, decode_frame, encode_frame, read_frame};
pub use error::BridgeError;
pub use executor_state::RuntimeSnapshot;
pub use identity::{BrokerRole, PeerCredentials, authenticate_broker_peer};
pub use model::{
    BridgeMessage, Correlation, ExchangeRole, Hash32, NetworkHandle, PublicBytes, RequestId,
    expected_response_tag,
};
pub use runtime::{BrokerOperation, RoleExecutor, SidecarRole};
