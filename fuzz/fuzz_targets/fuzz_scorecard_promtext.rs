#![no_main]

//! Fuzz the `rule scorecard` Prometheus text-exposition parser, the command's
//! single untrusted-input surface. The parser must never panic on any byte
//! input; every malformed or unrelated line is skipped.
//!
//! The parser is std-only and lives in the CLI binary crate, so it is included
//! here by source path rather than as a library dependency (the `rsigma` crate
//! has no library target).

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/rsigma-cli/src/commands/scorecard/promtext.rs"]
mod promtext;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = promtext::parse_exposition(text);
    }
});
