//! Daemon-side enrichment configuration loader.
//!
//! Parses the `enrichers:` block from the daemon's enrichers config file
//! (loaded via `--enrichers <path>`), validates template-namespace
//! references at load time, and produces an
//! [`EnrichmentPipeline`](rsigma_runtime::EnrichmentPipeline) that the
//! daemon's sink task uses to enrich each result before sink delivery.
//!
//! Splitting this module out from `enrichment` in `rsigma-runtime` keeps
//! YAML parsing (a CLI-shaped concern) out of the runtime crate, which
//! must stay deserialization-agnostic so library consumers can build
//! enrichers programmatically.

pub mod config;

pub use config::{build_enrichers_full, load_enrichers_file};
