//! Paired-only donor RKA lifecycle orchestration.
#![allow(
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::mod_module_files,
    clippy::too_many_arguments,
    missing_docs,
    reason = "the frozen donor schema is closed, multi-field, and owned by this directory"
)]

pub(crate) mod actor;
mod broker;
mod broker_bridge;
mod broker_bridge_codec;
mod broker_characteristics;
mod collision;
mod dispatch;
mod dispatch_codec;
mod dispatch_preflight;
#[cfg(test)]
pub(crate) mod dispatch_tests;
mod ingress;
mod ingress_io;
mod ingress_path;
pub(crate) mod lease;
mod lock_depth;
mod model;
mod operations;
mod peer_death;
pub mod quota;
mod runtime;
mod scheduler;
mod service;
mod service_preflight;
mod service_replay;
mod service_state;
mod shard;
pub(crate) mod state;
mod supervisor_ops;
mod validation;

pub use broker::{
    BrokerBegin, BrokerFailure, BrokerGenerate, DonorBroker, GeneratedKey, PublicKeyResult,
};
pub use broker_bridge::BridgeDonorBroker;
pub use ingress::{DonorIngress, DonorIngressError, ServeOutcome};
pub use lock_depth::donor_lock_depth;
pub use model::{
    AccessContext, BeginRequest, DeleteRequest, DonorError, DonorKeyState, FinishRequest,
    GenerateCoordinates, GenerateEvidence, GenerateKeyMaterial, GenerateRequest, OperationRequest,
    PairedPolicy, RemoteKeyHandle, RemoteOperationHandle, RkpKeyHandle,
};
pub use quota::{DonorQuota, SessionPermit};
pub use runtime::DonorRuntime;
#[allow(
    unused_imports,
    reason = "Task 24 consumes this internal activation boundary after authentication"
)]
pub(crate) use runtime::activate_authenticated_pair;
pub use scheduler::{PendingTeeReply, TeeCommand, TeeExecutor, TeeReply, TeeScheduler};
pub use service::{BeginResult, DonorRkaService, FinishResult, GenerateResult};
pub use shard::{CandidateShard, DonorSupervisor};
