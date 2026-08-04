//! Authenticated candidate identity and pairing catalog.

#![allow(
    clippy::mod_module_files,
    reason = "the required candidate/{mod.rs,id.rs,catalog.rs} layout owns this trust boundary"
)]

pub(crate) mod authority;
mod catalog;
mod cleanup;
mod codec;
mod id;
mod layout;
mod migrate;

pub use catalog::{CatalogAdmission, CatalogError, PairingAdmission, PairingCatalog};
pub use cleanup::{LegacyCleanup, cleanup_legacy};
pub use id::{AuthenticatedCandidateContext, CandidateId};
pub use layout::CandidateLayout;
pub use migrate::{MigrationError, MigrationStage, migrate_legacy_with};
