#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_const_for_fn,
    clippy::too_many_arguments,
    clippy::unused_self,
    missing_docs,
    unreachable_pub,
    reason = "bounded test builders favor readable scenario assembly and observable call counts"
)]

#[path = "support/broker.rs"]
mod broker;
#[path = "support/encoding.rs"]
mod encoding;
#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/generate.rs"]
mod generate;

pub use broker::FakeBroker;
pub use fixture::Fixture;
