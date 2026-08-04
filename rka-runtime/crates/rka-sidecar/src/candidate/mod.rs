//! Authenticated candidate identity and pairing catalog.

#![allow(
    clippy::mod_module_files,
    reason = "the required candidate/{mod.rs,id.rs,catalog.rs} layout owns this trust boundary"
)]

mod catalog;
mod codec;
mod id;

pub use catalog::{CatalogAdmission, CatalogError, PairingAdmission, PairingCatalog};
pub use id::{AuthenticatedCandidateContext, CandidateId};
