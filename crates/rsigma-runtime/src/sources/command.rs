//! Command source resolver: runs a local command and captures stdout.

use std::time::{Duration, Instant};

use rsigma_eval::pipeline::sources::{DataFormat, ExtractExpr};
use tokio::io::AsyncReadExt;

use super::extract::apply_extract;
use super::file::parse_data;
use super::{MAX_SOURCE_RESPONSE_BYTES, ResolvedValue, SourceError, SourceErrorKind};

const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolve a command source by executing it and parsing stdout.
pub async fn resolve_command(
    command: &[String],
    format: DataFormat,
    extract_expr: Option<&ExtractExpr>,
    timeout: Option<Duration>,
) -> Result<ResolvedValue, SourceError> {
    resolve_command_with_limit(
        command,
        format,
        extract_expr,
        timeout,
        MAX_SOURCE_RESPONSE_BYTES,
    )
    .await
}

/// Same as [`resolve_command`] but with a configurable stdout size limit.
pub async fn resolve_command_with_limit(
    command: &[String],
    format: DataFormat,
    extract_expr: Option<&ExtractExpr>,
    timeout: Option<Duration>,
    max_stdout_bytes: usize,
) -> Result<ResolvedValue, SourceError> {
    if command.is_empty() {
        return Err(SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch("command is empty".into()),
        });
    }

    let mut child = tokio::process::Command::new(&command[0])
        .args(&command[1..])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!("failed to spawn '{}': {e}", command[0])),
        })?;

    let deadline = timeout.unwrap_or(DEFAULT_COMMAND_TIMEOUT);

    let result = tokio::time::timeout(deadline, async {
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        if let Some(mut stdout) = child.stdout.take() {
            let mut tmp = vec![0u8; 8192];
            loop {
                let n = stdout.read(&mut tmp).await.map_err(|e| SourceError {
                    source_id: String::new(),
                    kind: SourceErrorKind::Fetch(format!("failed to read stdout: {e}")),
                })?;
                if n == 0 {
                    break;
                }
                if stdout_buf.len() + n > max_stdout_bytes {
                    let _ = child.kill().await;
                    return Err(SourceError {
                        source_id: String::new(),
                        kind: SourceErrorKind::ResourceLimit(format!(
                            "command stdout exceeds {max_stdout_bytes} byte limit"
                        )),
                    });
                }
                stdout_buf.extend_from_slice(&tmp[..n]);
            }
        }

        if let Some(mut stderr) = child.stderr.take() {
            let cap = 64 * 1024; // 64 KB for error messages
            let mut tmp = vec![0u8; 4096];
            loop {
                let n = stderr.read(&mut tmp).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                if stderr_buf.len() + n > cap {
                    break;
                }
                stderr_buf.extend_from_slice(&tmp[..n]);
            }
        }

        let status = child.wait().await.map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!("command execution failed: {e}")),
        })?;

        Ok((status, stdout_buf, stderr_buf))
    })
    .await;

    let (status, stdout_bytes, stderr_bytes) = match result {
        Ok(inner) => inner?,
        Err(_) => {
            let _ = child.kill().await;
            return Err(SourceError {
                source_id: String::new(),
                kind: SourceErrorKind::Timeout,
            });
        }
    };

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr_bytes);
        return Err(SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!(
                "command exited with {}: {}",
                status,
                stderr.trim()
            )),
        });
    }

    let stdout = String::from_utf8(stdout_bytes).map_err(|e| SourceError {
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
