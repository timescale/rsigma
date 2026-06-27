//! Shared Prometheus production-volume reader for the detection-as-code `rule`
//! commands.
//!
//! `rule scorecard` and `rule hygiene` both join per-rule fire counts from the
//! two `rsigma_*_matches_by_rule_total` families by `rule_title`. The reader is
//! lifted here so the two commands share one parser and one loader rather than
//! reimplementing the exposition format. The hand-rolled text parser lives in
//! the std-only [`promtext`] submodule so the `fuzz_scorecard_promtext`
//! cargo-fuzz target can compile it standalone via a `#[path]` include.

mod promtext;

use std::collections::BTreeMap;

pub(crate) use promtext::{CORRELATION_METRIC, DETECTION_METRIC};

/// A failure loading or fetching a Prometheus source, carrying the house
/// exit-code intent: an input that is missing or unfetchable is `Unreadable`
/// (exit 2); a response that is present but does not parse is `Malformed`
/// (exit 3).
#[derive(Debug)]
pub(crate) enum MetricsError {
    /// The source could not be read or fetched (missing file, unreachable URL).
    Unreadable(String),
    /// The source was read but did not parse against the expected shape.
    Malformed(String),
}

impl std::fmt::Display for MetricsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricsError::Unreadable(m) | MetricsError::Malformed(m) => f.write_str(m),
        }
    }
}

/// Production fire signal joined by `rule_title`.
#[derive(Debug, Clone, Default)]
pub(crate) struct MetricsData {
    /// `rule_title` -> summed counter value across both `*_matches_by_rule_total`
    /// families. `rule_title` is not guaranteed unique (see
    /// `docs/reference/metrics.md`); colliding titles add together here.
    pub(crate) by_title: BTreeMap<String, u64>,
    /// `rule_title` -> Unix-seconds last-fired, only populated by a Prometheus
    /// `query_range` fetch (a `window`); an exposition snapshot or a raw
    /// `/metrics` endpoint yields current counter values only.
    pub(crate) last_fired: BTreeMap<String, i64>,
}

/// Load the Prometheus source. With no `window`, `spec` is a local exposition
/// snapshot file or a `/metrics` endpoint URL parsed for current counter
/// values. With a `window`, `spec` is a Prometheus query-API base and the two
/// counter families are range-queried for last-fired and current value.
pub(crate) fn load_metrics(spec: &str, window: Option<&str>) -> Result<MetricsData, MetricsError> {
    match window {
        Some(window) => query_range(spec, window),
        None => {
            let text = read_spec(spec)?;
            Ok(MetricsData {
                by_title: promtext::parse_exposition(&text),
                last_fired: BTreeMap::new(),
            })
        }
    }
}

/// Read a spec that is either a local path or an `http(s)` URL (a `/metrics`
/// endpoint). URLs are fetched with the synchronous `ureq` client, the same
/// transport convention `rule coverage` uses.
fn read_spec(spec: &str) -> Result<String, MetricsError> {
    if is_url(spec) {
        http_get(spec)
    } else {
        std::fs::read_to_string(spec)
            .map_err(|e| MetricsError::Unreadable(format!("could not read metrics {spec}: {e}")))
    }
}

fn is_url(spec: &str) -> bool {
    spec.starts_with("http://") || spec.starts_with("https://")
}

fn http_get(url: &str) -> Result<String, MetricsError> {
    match ureq::get(url).call() {
        Ok(resp) => resp
            .into_body()
            .read_to_string()
            .map_err(|e| MetricsError::Unreadable(format!("reading response from {url}: {e}"))),
        Err(e) => Err(MetricsError::Unreadable(format!(
            "could not fetch metrics from {url}: {e}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Prometheus query-API range query (optional window)
// ---------------------------------------------------------------------------

/// Range-query the two counter families against a Prometheus query API base,
/// deriving current value (summed by `rule_title`) and a last-fired timestamp
/// (the sample at which a series last increased).
fn query_range(base: &str, window: &str) -> Result<MetricsData, MetricsError> {
    if !is_url(base) {
        return Err(MetricsError::Unreadable(format!(
            "a metrics window requires the metrics source to be a Prometheus query-API base URL, got {base}"
        )));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let lookback = parse_window_secs(window).ok_or_else(|| {
        MetricsError::Unreadable(format!(
            "invalid metrics window '{window}' (expected e.g. 7d, 24h, 30m)"
        ))
    })?;
    let start = now - lookback;
    let step = (lookback / 100).max(60); // ~100 samples, at least one per minute

    let mut data = MetricsData::default();
    for metric in [DETECTION_METRIC, CORRELATION_METRIC] {
        let url = format!(
            "{}/api/v1/query_range?query={metric}&start={start}&end={now}&step={step}",
            base.trim_end_matches('/')
        );
        let body = http_get(&url)?;
        merge_range_response(&body, &mut data).map_err(MetricsError::Malformed)?;
    }
    Ok(data)
}

/// Parse a `humantime`-lite window (`<n>[s|m|h|d|w]`) into seconds without a new
/// dependency. Shared by the range query and the hygiene silence/staleness
/// thresholds.
pub(crate) fn parse_window_secs(window: &str) -> Option<i64> {
    let window = window.trim();
    let (num, unit) = window.split_at(window.find(|c: char| !c.is_ascii_digit())?);
    let n: i64 = num.parse().ok()?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return None,
    };
    Some(n * mult)
}

/// Fold one `query_range` matrix response into `data`: the last sample is the
/// current value (summed by title), and the last timestamp at which a series
/// value increased is its last-fired.
fn merge_range_response(body: &str, data: &mut MetricsData) -> Result<(), String> {
    let parsed: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("parsing query_range response: {e}"))?;
    let results = parsed
        .get("data")
        .and_then(|d| d.get("result"))
        .and_then(|r| r.as_array())
        .ok_or_else(|| "query_range response missing data.result".to_string())?;
    for series in results {
        let Some(title) = series
            .get("metric")
            .and_then(|m| m.get("rule_title"))
            .and_then(|t| t.as_str())
        else {
            continue;
        };
        let Some(values) = series.get("values").and_then(|v| v.as_array()) else {
            continue;
        };
        let mut prev: Option<f64> = None;
        let mut last_value = 0.0f64;
        let mut last_fired_ts: Option<i64> = None;
        for sample in values {
            let Some(arr) = sample.as_array() else {
                continue;
            };
            let ts = arr.first().and_then(|t| t.as_f64());
            let val = arr
                .get(1)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<f64>().ok());
            let (Some(ts), Some(val)) = (ts, val) else {
                continue;
            };
            if prev.is_some_and(|p| val > p) {
                last_fired_ts = Some(ts as i64);
            }
            prev = Some(val);
            last_value = val;
        }
        *data.by_title.entry(title.to_string()).or_insert(0) += last_value.round().max(0.0) as u64;
        if let Some(ts) = last_fired_ts {
            data.last_fired.insert(title.to_string(), ts);
        }
    }
    Ok(())
}

/// Format a Unix timestamp as a UTC RFC 3339 string without a date dependency.
pub(crate) fn unix_to_rfc3339(secs: i64) -> String {
    // Days since the Unix epoch and the within-day remainder.
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Howard Hinnant's `civil_from_days`: convert days-since-epoch to a
/// (year, month, day) civil date in the proleptic Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_parse_units() {
        assert_eq!(parse_window_secs("7d"), Some(604_800));
        assert_eq!(parse_window_secs("24h"), Some(86_400));
        assert_eq!(parse_window_secs("30m"), Some(1_800));
        assert_eq!(parse_window_secs("90s"), Some(90));
        assert_eq!(parse_window_secs("bogus"), None);
        assert_eq!(parse_window_secs("10y"), None);
    }

    #[test]
    fn rfc3339_epoch_and_known_date() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2021-01-01T00:00:00Z = 1609459200
        assert_eq!(unix_to_rfc3339(1_609_459_200), "2021-01-01T00:00:00Z");
    }

    #[test]
    fn merge_range_extracts_value_and_last_fired() {
        let body = r#"{
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [
                    {
                        "metric": {"rule_title": "Whoami", "level": "low"},
                        "values": [[1609459200, "2"], [1609459260, "2"], [1609459320, "5"]]
                    }
                ]
            }
        }"#;
        let mut data = MetricsData::default();
        merge_range_response(body, &mut data).unwrap();
        assert_eq!(data.by_title.get("Whoami"), Some(&5));
        // The value increased at the last sample (1609459320).
        assert_eq!(data.last_fired.get("Whoami"), Some(&1_609_459_320));
        assert_eq!(unix_to_rfc3339(1_609_459_320), "2021-01-01T00:02:00Z");
    }
}
