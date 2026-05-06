//! Command source resolver: runs a local command and captures stdout.

use std::time::Instant;

use rsigma_eval::pipeline::sources::{DataFormat, ExtractExpr};

use super::extract::apply_extract;
use super::file::parse_data;
use super::{ResolvedValue, SourceError, SourceErrorKind};

/// Resolve a command source by executing it and parsing stdout.
pub async fn resolve_command(
    command: &[String],
    format: DataFormat,
    extract_expr: Option<&ExtractExpr>,
) -> Result<ResolvedValue, SourceError> {
    if command.is_empty() {
        return Err(SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch("command is empty".into()),
        });
    }

    let output = tokio::process::Command::new(&command[0])
        .args(&command[1..])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!("failed to spawn '{}': {e}", command[0])),
        })?
        .wait_with_output()
        .await
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!("command execution failed: {e}")),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!(
                "command exited with {}: {}",
                output.status,
                stderr.trim()
            )),
        });
    }

    let stdout = String::from_utf8(output.stdout).map_err(|e| SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Parse(format!("command output is not valid UTF-8: {e}")),
    })?;

    let parsed = parse_data(&stdout, format)?;

    let data = if let Some(expr) = extract_expr {
        apply_extract(&parsed, expr)?
    } else {
        parsed
    };

    Ok(ResolvedValue {
        data,
        resolved_at: Instant::now(),
        from_cache: false,
    })
}
