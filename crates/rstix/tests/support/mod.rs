//! Shared helpers for rstix integration tests.

mod fixtures;
mod roundtrip;

pub use fixtures::load_spec_fixture;
pub use roundtrip::{assert_fixture_rejects, roundtrip};
