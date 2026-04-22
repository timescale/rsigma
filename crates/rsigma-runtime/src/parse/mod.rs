//! Log format parsers for the rsigma runtime.
//!
//! Each sub-module provides a zero-dependency parser for a specific log format.
//! Parsers return simple owned types (`Vec<(String, String)>`, structs) that
//! the Phase 3 input adapters convert into [`rsigma_eval::KvEvent`] or similar.

pub mod logfmt;
