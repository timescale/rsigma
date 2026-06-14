//! Daemon-side enrichment configuration.
//!
//! The enrichers YAML loader now lives in
//! [`rsigma_runtime::enrichment::config`] so every in-process consumer of the
//! enrichment pipeline (the daemon and the MCP server) shares one loader. This
//! module re-exports the pieces the daemon uses so the call sites in
//! `daemon/server.rs` stay unchanged.

pub use rsigma_runtime::enrichment::config::{build_enrichers_full, load_enrichers_file};
