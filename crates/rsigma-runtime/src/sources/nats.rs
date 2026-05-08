//! NATS push source resolver: subscribes to a NATS subject for live updates.

use std::time::Instant;

use rsigma_eval::pipeline::sources::{DataFormat, ExtractExpr};

use super::extract::apply_extract;
use super::file::parse_data;
use super::{MAX_SOURCE_RESPONSE_BYTES, ResolvedValue, SourceError, SourceErrorKind};

/// Check that a NATS payload does not exceed the size limit.
fn check_payload_size(payload: &[u8], max_bytes: usize) -> Result<(), SourceError> {
    if payload.len() > max_bytes {
        return Err(SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::ResourceLimit(format!(
                "NATS message payload ({} bytes) exceeds {} byte limit",
                payload.len(),
                max_bytes
            )),
        });
    }
    Ok(())
}

/// Resolve a NATS source by connecting and fetching the latest message.
///
/// For the initial resolution, this connects to the NATS server and subscribes
/// briefly to the subject. For push sources, the initial value may be Null if
/// no message is immediately available; the refresh scheduler will handle
/// ongoing updates via subscription.
#[cfg(feature = "nats")]
pub async fn resolve_nats_initial(
    url: &str,
    subject: &str,
    format: DataFormat,
    extract_expr: Option<&ExtractExpr>,
) -> Result<ResolvedValue, SourceError> {
    use futures::StreamExt;

    let client = async_nats::connect(url).await.map_err(|e| SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Fetch(format!("failed to connect to NATS at {url}: {e}")),
    })?;

    let mut sub = client
        .subscribe(subject.to_string())
        .await
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!("failed to subscribe to '{subject}': {e}")),
        })?;

    let data = match tokio::time::timeout(std::time::Duration::from_secs(1), sub.next()).await {
        Ok(Some(msg)) => {
            check_payload_size(&msg.payload, MAX_SOURCE_RESPONSE_BYTES)?;
            let raw = std::str::from_utf8(&msg.payload).map_err(|e| SourceError {
                source_id: String::new(),
                kind: SourceErrorKind::Parse(format!("NATS message is not valid UTF-8: {e}")),
            })?;
            let parsed = parse_data(raw, format)?;
            if let Some(expr) = extract_expr {
                apply_extract(&parsed, expr)?
            } else {
                parsed
            }
        }
        _ => serde_json::Value::Null,
    };

    Ok(ResolvedValue {
        data,
        resolved_at: Instant::now(),
        from_cache: false,
    })
}

/// Parse a raw NATS message payload into a resolved value.
///
/// Rejects payloads exceeding `MAX_SOURCE_RESPONSE_BYTES`.
#[cfg(feature = "nats")]
pub fn parse_nats_message(
    payload: &[u8],
    format: DataFormat,
    extract_expr: Option<&ExtractExpr>,
) -> Result<serde_json::Value, SourceError> {
    check_payload_size(payload, MAX_SOURCE_RESPONSE_BYTES)?;
    let raw = std::str::from_utf8(payload).map_err(|e| SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Parse(format!("NATS message is not valid UTF-8: {e}")),
    })?;
    let parsed = parse_data(raw, format)?;
    if let Some(expr) = extract_expr {
        apply_extract(&parsed, expr)
    } else {
        Ok(parsed)
    }
}
