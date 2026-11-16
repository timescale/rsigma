//! Structured exit codes for CI/CD scripting.
//!
//! These codes let callers distinguish between "the tool ran successfully but
//! found something" (detections, lint findings) and "the tool could not run
//! because of a configuration or rule error."

/// Operation completed successfully.
/// For `eval`: events were processed (detections may or may not have fired).
/// For `lint`: no findings at the configured severity threshold.
/// For `validate`: all rules parsed and compiled.
pub const SUCCESS: i32 = 0;

/// Findings were produced.
/// For `eval --fail-on-detection`: at least one detection or correlation fired.
/// For `lint --fail-level`: at least one finding at or above the threshold.
pub const FINDINGS: i32 = 1;

/// Rule syntax, parse, or compilation error.
/// The input rules could not be loaded or compiled.
pub const RULE_ERROR: i32 = 2;

/// Pipeline, configuration, or invalid argument error.
/// A pipeline file could not be loaded, a CLI argument was invalid,
/// or the tool was misconfigured.
pub const CONFIG_ERROR: i32 = 3;

/// The run started but did not complete cleanly.
/// For `engine daemon --input stdin`: a signal stopped it before end of
/// input, reading stdin failed, output reached neither its sink nor the
/// DLQ, the final state save failed, or a pipeline task panicked.
#[cfg(feature = "daemon")]
pub const RUNTIME_ERROR: i32 = 4;
