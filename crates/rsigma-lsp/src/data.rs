//! Shared data constants for Sigma detection rules.
//!
//! These tables now live in [`rsigma_parser::reference`] so the LSP, the MCP
//! server, and any other tooling share one source of truth. They are re-exported
//! here so the LSP's hover and completion modules keep referring to
//! `data::MODIFIERS` / `data::MITRE_TACTICS` unchanged.

pub use rsigma_parser::reference::{MITRE_TACTICS, MODIFIERS};
