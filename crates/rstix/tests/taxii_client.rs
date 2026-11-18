//! TAXII client integration tests (wiremock).

#[path = "taxii/address_filter_tests.rs"]
mod address_filter_tests;
#[path = "taxii/auth_tests.rs"]
mod auth_tests;
#[path = "taxii/build.rs"]
mod build;
#[path = "taxii/collections_tests.rs"]
mod collections_tests;
#[path = "taxii/coverage_tests.rs"]
mod coverage_tests;
#[path = "taxii/discovery_tests.rs"]
mod discovery_tests;
#[path = "taxii/error_tests.rs"]
mod error_tests;
#[path = "taxii/filter_tests.rs"]
mod filter_tests;
#[path = "taxii/gap_tests.rs"]
mod gap_tests;
#[path = "taxii/objects_tests.rs"]
mod objects_tests;
#[path = "taxii/pagination_tests.rs"]
mod pagination_tests;
#[path = "taxii/retry_tests.rs"]
mod retry_tests;
#[path = "taxii/status_tests.rs"]
mod status_tests;
#[path = "taxii/support.rs"]
mod support;
#[path = "taxii/tls_tests.rs"]
mod tls_tests;
