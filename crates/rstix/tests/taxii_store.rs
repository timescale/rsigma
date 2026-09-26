//! TAXII collection ingest into store integration tests.

#[cfg(feature = "validate")]
#[path = "taxii/ingest_attck_tests.rs"]
mod ingest_attck_tests;
#[path = "taxii/ingest_support.rs"]
mod ingest_support;
#[path = "taxii/ingest_tests.rs"]
mod ingest_tests;
#[cfg(feature = "validate")]
#[path = "taxii/ingest_validate_tests.rs"]
mod ingest_validate_tests;
