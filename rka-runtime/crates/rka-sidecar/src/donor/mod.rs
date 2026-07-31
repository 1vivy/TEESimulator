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
mod model;
mod operations;
mod service;
mod validation;

pub use broker::{
    BrokerBegin, BrokerFailure, BrokerGenerate, DonorBroker, GeneratedKey, PublicKeyResult,
};
pub use model::{
    AccessContext, BeginRequest, DeleteRequest, DonorError, DonorKeyState, FinishRequest,
    GenerateRequest, OperationRequest, PairedPolicy, RemoteKeyHandle, RemoteOperationHandle,
};
pub use service::{BeginResult, DonorRkaService, FinishResult, GenerateResult};
