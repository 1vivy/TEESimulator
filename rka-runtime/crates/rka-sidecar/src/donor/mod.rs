//! Paired-only donor RKA lifecycle orchestration.
#![allow(
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::mod_module_files,
    clippy::too_many_arguments,
    missing_docs,
    reason = "the frozen donor schema is closed, multi-field, and owned by this directory"
)]

mod broker;
mod broker_bridge;
mod collision;
mod dispatch;
mod dispatch_codec;
mod ingress;
mod model;
mod operations;
mod runtime;
mod service;
mod service_replay;
mod validation;

pub use broker::{
    BrokerBegin, BrokerFailure, BrokerGenerate, DonorBroker, GeneratedKey, PublicKeyResult,
};
pub use broker_bridge::BridgeDonorBroker;
pub use ingress::{DonorIngress, DonorIngressError, ServeOutcome};
pub use model::{
    AccessContext, BeginRequest, DeleteRequest, DonorError, DonorKeyState, FinishRequest,
    GenerateCoordinates, GenerateEvidence, GenerateKeyMaterial, GenerateRequest, OperationRequest,
    PairedPolicy, RemoteKeyHandle, RemoteOperationHandle, RkpKeyHandle,
};
pub use runtime::DonorRuntime;
#[allow(
    unused_imports,
    reason = "Task 24 consumes this internal activation boundary after authentication"
)]
pub(crate) use runtime::activate_authenticated_pair;
pub use service::{BeginResult, DonorRkaService, FinishResult, GenerateResult};
