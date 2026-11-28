//! `TemplateEnricher`: pure string interpolation for enrichment.
//!
//! `template` is the simplest of the four primitives: it performs no I/O,
//! cannot fail at runtime past template parse errors caught at config load,
//! and is intended for cheap synthetic fields like runbook URLs and summary
//! strings.
//!
//! # Template syntax
//!
//! Two forms are recognized:
//!
//! - `${<name>}` (single segment, no dot): environment variable lookup.
//!   Empty when the env var is unset.
//! - `${detection.<path>}` or `${correlation.<path>}`: kind-specific
//!   variable. Only the namespace matching the enricher's declared
//!   [`EnricherKind`](super::EnricherKind) is allowed; the other namespace
//!   fails [`validate_template_namespace`] at config load.
//!
//! Detection paths:
//! - `rule.title` / `rule.id` / `rule.level`
//! - `tenant` (empty when the result is untenanted)
//! - `tags` (joined with `,`)
//! - `fields.<name>` (the matched value of `<name>` from `matched_fields`;
//!   the enrichment renderers fall back to the retained event when the rule
//!   did not match on `<name>`)
//! - `event.<dotted.path>` (navigate `DetectionBody::event` by JSON segment)
//!
//! Correlation paths:
//! - `rule.title` / `rule.id` / `rule.level`
//! - `tenant` (empty when the result is untenanted)
//! - `tags` (joined with `,`)
//! - `type` (`event_count`, `temporal`, …)
//! - `aggregated_value` / `timespan_secs`
//! - `group_key` (joined `field=value,…`) or `group_key.<field>`
//!
//! `${detection.ocsf}` and `${correlation.ocsf}` insert the result's OCSF
//! Detection Finding as raw JSON. They are valid only in a webhook body, as a
//! whole JSON value; every other templated field rejects them at config load.
//!
//! Anything else (unrecognized prefix, dotted env var, etc.) is rejected at
//! config load, **not** at runtime, so a deployment with a typo never starts
//! producing partly-rendered enrichments under load.
//!
//! The public [`render_template`], [`render_template_url`], and
//! [`render_template_json`] functions resolve `fields.<name>` only from
//! `matched_fields`. The crate-visible `render_enricher_template*` functions
//! additionally read `<name>` from the retained event when no matched field
//! has that name. Webhook templates keep the public behavior, so a webhook
//! reads an unmatched field only through `event.<path>`.

use std::sync::LazyLock;

use async_trait::async_trait;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use rsigma_eval::{EvaluationResult, ResultBody};
use rsigma_parser::Level;

use super::{EnrichError, Enricher, EnricherKind, OnError, Scope, inject_enrichment};

/// Matches `${<contents>}` where contents is anything except `}`.
///
/// We deliberately allow non-alphanumeric content inside the braces (dots,
/// underscores) and leave classification to [`classify_ref`] so error
/// messages can pinpoint the offending reference.
static TEMPLATE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$\{([^}]+)\}").unwrap());

/// The path that inserts the result's OCSF finding into a webhook body.
const OCSF_PATH: &str = "ocsf";

/// Key of the object substituted for an OCSF reference when checking that a
/// webhook body uses it as a whole JSON value. The quotes make a reference
/// inside a string literal fail to parse.
const OCSF_PROBE_KEY: &str = "rsigma_ocsf_probe";

/// Classification of a single `${...}` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VarRef {
    /// `${detection.<rest>}`
    Detection(String),
    /// `${correlation.<rest>}`
    Correlation(String),
    /// `${ENV_VAR}` — single segment, no dot.
    Env(String),
    /// Anything else (dotted but unknown prefix, empty, …). Always an
    /// error at config load.
    Invalid(String),
}

impl VarRef {
    fn is_ocsf(&self) -> bool {
        matches!(self, VarRef::Detection(path) | VarRef::Correlation(path) if path == OCSF_PATH)
    }
}

fn classify_ref(name: &str) -> VarRef {
    if let Some(rest) = name.strip_prefix("detection.") {
        VarRef::Detection(rest.to_string())
    } else if let Some(rest) = name.strip_prefix("correlation.") {
        VarRef::Correlation(rest.to_string())
    } else if name.contains('.') || name.is_empty() {
        VarRef::Invalid(name.to_string())
    } else {
        VarRef::Env(name.to_string())
    }
}

/// Failure modes for [`validate_template_namespace`].
#[derive(Debug, Clone)]
pub enum TemplateError {
    /// Reference uses the opposite namespace from the enricher's declared
    /// kind (e.g. `${correlation.*}` inside a `kind: detection` enricher).
    CrossNamespace {
        enricher_id: String,
        enricher_kind: EnricherKind,
        reference: String,
        field: &'static str,
    },
    /// Reference is malformed (empty `${}`, dotted prefix that is neither
    /// `detection.` nor `correlation.`, …).
    Malformed {
        enricher_id: String,
        reference: String,
        field: &'static str,
    },
    /// `${detection.ocsf}` / `${correlation.ocsf}` outside a webhook body, or
    /// inside one but not as a whole JSON value.
    MisplacedOcsf {
        enricher_id: String,
        reference: String,
        field: &'static str,
    },
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateError::CrossNamespace {
                enricher_id,
                enricher_kind,
                reference,
                field,
            } => write!(
                f,
                "enricher '{enricher_id}' (kind: {kind}) references '${{{reference}}}' in field '{field}'; this is the wrong namespace for a {kind} enricher",
                kind = enricher_kind.as_str(),
            ),
            TemplateError::Malformed {
                enricher_id,
                reference,
                field,
            } => write!(
                f,
                "enricher '{enricher_id}': malformed template reference '${{{reference}}}' in field '{field}'; expected ${{detection.*}}, ${{correlation.*}}, or ${{ENV_VAR}}",
            ),
            TemplateError::MisplacedOcsf {
                enricher_id,
                reference,
                field,
            } => write!(
                f,
                "enricher '{enricher_id}': '${{{reference}}}' in field '{field}' is only valid as a whole JSON value in a webhook body",
            ),
        }
    }
}

impl std::error::Error for TemplateError {}

/// Validate that every `${...}` reference inside `text` matches the
/// enricher's declared kind.
///
/// `field` is included in the error message so operators can find the
/// offending YAML key (e.g. `template`, `url`, `headers.Authorization`).
/// Called at config load time for every templated config value across every
/// enricher; rejects the daemon startup on the first failure rather than
/// the first runtime hit.
///
/// `${detection.ocsf}` and `${correlation.ocsf}` are rejected here: they are
/// valid only in a webhook body, which is checked with
/// `validate_webhook_body_template` instead.
pub fn validate_template_namespace(
    text: &str,
    enricher_kind: EnricherKind,
    enricher_id: &str,
    field: &'static str,
) -> Result<(), TemplateError> {
    validate_references(text, enricher_kind, enricher_id, field, false)
}

/// Reject a URL template whose tenant reference lands in the authority.
///
/// A `${detection.tenant}` or `${correlation.tenant}` reference changes the
/// rendered value per result. It may appear only after the first `/` that
/// follows the scheme and authority, so the destination host stays fixed for
/// the webhook or HTTP enricher's client, cache, and rate limiter.
pub fn validate_url_tenant_position(url: &str) -> Result<(), String> {
    let tenant_refs = ["${detection.tenant}", "${correlation.tenant}"];
    if !tenant_refs.iter().any(|needle| url.contains(needle)) {
        return Ok(());
    }
    // Render with two different tenants and compare what a URL parser sees:
    // the destination must not move between them.
    let render = |tenant: &str| {
        TEMPLATE_RE
            .replace_all(url, |caps: &regex::Captures| {
                let whole = caps.get(0).unwrap().as_str();
                if tenant_refs.contains(&whole) {
                    return tenant.to_string();
                }
                match classify_ref(caps.get(1).unwrap().as_str()) {
                    VarRef::Env(name) => std::env::var(name).unwrap_or_default(),
                    _ => "x".to_string(),
                }
            })
            .into_owned()
    };
    let (one, two) = ("rsigmatenantone", "rsigmatenanttwo");
    let fixed = match (
        reqwest::Url::parse(&render(one)),
        reqwest::Url::parse(&render(two)),
    ) {
        (Ok(a), Ok(b)) => {
            a.scheme() == b.scheme()
                && a.username() == b.username()
                && a.password() == b.password()
                && a.host_str() == b.host_str()
                && a.port() == b.port()
                && !a.scheme().contains(one)
                && !a.username().contains(one)
                && !a.password().is_some_and(|p| p.contains(one))
                && !a.host_str().is_some_and(|h| h.contains(one))
        }
        _ => false,
    };
    if !fixed {
        return Err(format!(
            "url '{url}' must be an absolute URL whose scheme and authority do not use a tenant reference; \
             ${{detection.tenant}} and ${{correlation.tenant}} are only valid in the path or query"
        ));
    }
    Ok(())
}

/// Validate a webhook body template: the namespace rules of
/// [`validate_template_namespace`], plus `${detection.ocsf}` /
/// `${correlation.ocsf}` allowed only where a whole JSON value can stand.
///
/// The check substitutes a JSON object for each OCSF reference and `0` for
/// every other reference, then requires the body to parse and to hold every
/// substituted object. A reference inside a string literal or in key position
/// fails. Bodies without an OCSF reference are not parsed, so a non-JSON body
/// keeps working.
pub(crate) fn validate_webhook_body_template(
    text: &str,
    kind: EnricherKind,
    webhook_id: &str,
) -> Result<(), TemplateError> {
    const FIELD: &str = "body";
    validate_references(text, kind, webhook_id, FIELD, true)?;

    let mut first_ocsf: Option<String> = None;
    let mut ocsf_count = 0usize;
    let probe = TEMPLATE_RE.replace_all(text, |caps: &regex::Captures| {
        let inner = caps.get(1).unwrap().as_str();
        if classify_ref(inner).is_ocsf() {
            ocsf_count += 1;
            first_ocsf.get_or_insert_with(|| inner.to_string());
            format!("{{\"{OCSF_PROBE_KEY}\":0}}")
        } else {
            "0".to_string()
        }
    });
    let Some(reference) = first_ocsf else {
        return Ok(());
    };
    let whole_values = serde_json::from_str::<serde_json::Value>(&probe)
        .map(|value| count_ocsf_probes(&value) == ocsf_count)
        .unwrap_or(false);
    if whole_values {
        Ok(())
    } else {
        Err(TemplateError::MisplacedOcsf {
            enricher_id: webhook_id.to_string(),
            reference,
            field: FIELD,
        })
    }
}

fn count_ocsf_probes(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) if map.len() == 1 && map.contains_key(OCSF_PROBE_KEY) => 1,
        serde_json::Value::Object(map) => map.values().map(count_ocsf_probes).sum(),
        serde_json::Value::Array(items) => items.iter().map(count_ocsf_probes).sum(),
        _ => 0,
    }
}

fn validate_references(
    text: &str,
    enricher_kind: EnricherKind,
    enricher_id: &str,
    field: &'static str,
    allow_ocsf: bool,
) -> Result<(), TemplateError> {
    for caps in TEMPLATE_RE.captures_iter(text) {
        let inner = caps.get(1).unwrap().as_str();
        let reference = classify_ref(inner);
        if reference.is_ocsf() && !allow_ocsf {
            return Err(TemplateError::MisplacedOcsf {
                enricher_id: enricher_id.to_string(),
                reference: inner.to_string(),
                field,
            });
        }
        match reference {
            VarRef::Env(_) => {}
            VarRef::Detection(_) if enricher_kind == EnricherKind::Detection => {}
            VarRef::Correlation(_) if enricher_kind == EnricherKind::Correlation => {}
            VarRef::Detection(_) | VarRef::Correlation(_) => {
                return Err(TemplateError::CrossNamespace {
                    enricher_id: enricher_id.to_string(),
                    enricher_kind,
                    reference: inner.to_string(),
                    field,
                });
            }
            VarRef::Invalid(_) => {
                return Err(TemplateError::Malformed {
                    enricher_id: enricher_id.to_string(),
                    reference: inner.to_string(),
                    field,
                });
            }
        }
    }
    Ok(())
}

/// Return the names of every `${ENV_VAR}` reference inside `text`, in order
/// of first appearance and without duplicates.
///
/// Rendering expands these from the process environment, so a caller that
/// accepts templates from an untrusted party (the MCP server) uses this to
/// reject them before building the enricher.
pub fn env_references(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut names: Vec<String> = Vec::new();
    for caps in TEMPLATE_RE.captures_iter(text) {
        if let VarRef::Env(name) = classify_ref(caps.get(1).unwrap().as_str())
            && seen.insert(name.clone())
        {
            names.push(name);
        }
    }
    names
}

/// Whether `text` references a detection payload that the event fallback can
/// resolve: `fields.<name>`, `event.<path>`, or bare `event`.
pub(crate) fn references_detection_payload(text: &str) -> bool {
    TEMPLATE_RE.captures_iter(text).any(|caps| {
        matches!(
            classify_ref(caps.get(1).unwrap().as_str()),
            VarRef::Detection(path)
                if path == "event" || path.starts_with("event.") || path.starts_with("fields.")
        )
    })
}

/// Message for an enrichment key that rendered empty.
///
/// A template that can read a detection payload gets a hint about the event
/// fallback. A template that cannot (a correlation template, or one that only
/// references rule metadata, tags, or the tenant) keeps the plain message.
#[cfg(any(feature = "mmdb-enrich", feature = "dns-enrich", test))]
pub(crate) fn empty_key_message(template: &str) -> String {
    if references_detection_payload(template) {
        "key rendered empty; the field is neither a matched field nor present in the event"
            .to_string()
    } else {
        "key rendered empty".to_string()
    }
}

/// Render `text` against `result`, expanding every `${...}` reference.
///
/// Values for missing fields render as the empty string (matching the
/// source-side `TemplateExpander` behaviour). Cross-namespace references
/// are caught at config load by [`validate_template_namespace`] and
/// therefore must not reach this function; if one does, it renders as
/// the empty string rather than panicking, since the same render path is
/// reused by tests.
pub fn render_template(text: &str, result: &EvaluationResult) -> String {
    render_with(text, result, false, |_, s| s)
}

/// Like [`render_template`], but percent-encodes every `${detection.*}` and
/// `${correlation.*}` value for use inside a URL.
///
/// Event-derived values are attacker-influenced, so each one is encoded as a
/// single URL component: everything except ASCII letters, digits, `-`, `_`,
/// `.`, and `~` is percent-encoded, including `/`, `?`, `#`, `&`, `=`, and
/// `%`. A value cannot add path segments, start a query or fragment, or smuggle
/// a pre-encoded sequence. `${ENV_VAR}` values are inserted verbatim because
/// operators use them for whole URL parts (a webhook path, a token).
pub fn render_template_url(text: &str, result: &EvaluationResult) -> String {
    render_with(text, result, false, |source, s| match source {
        ValueSource::Env => s,
        ValueSource::Result | ValueSource::Ocsf => url_component_escape(&s),
    })
}

/// Like [`render_template`], but JSON-string-escapes every substituted value.
///
/// Use this for a templated body that is a JSON document: interpolated values
/// (rule titles, event field strings) are attacker-influenced, so a value
/// containing a quote, backslash, or control character would otherwise break
/// the rendered payload. The escaper serializes each substitution as a JSON
/// string and strips the surrounding quotes, yielding content safe to drop
/// inside a JSON string literal. A placeholder outside a string literal is
/// still inserted as raw text. URLs use [`render_template_url`]; headers keep
/// [`render_template`] because header parsing rejects CR and LF.
pub fn render_template_json(text: &str, result: &EvaluationResult) -> String {
    render_with(text, result, false, |_, s| json_escape_value(s))
}

/// Like [`render_template`], but `fields.<name>` falls back to the retained
/// event when the rule did not match on `<name>`.
///
/// This is the renderer every enrichment primitive uses. A matched field
/// always wins, even when its value is null or empty. Otherwise `<name>` is
/// read from the event as a whole top-level key first, then by dotted path.
pub(crate) fn render_enricher_template(text: &str, result: &EvaluationResult) -> String {
    render_with(text, result, true, |_, s| s)
}

/// Like [`render_enricher_template`], but percent-encodes every
/// `${detection.*}` and `${correlation.*}` value as one URL component.
pub(crate) fn render_enricher_template_url(text: &str, result: &EvaluationResult) -> String {
    render_with(text, result, true, |source, s| match source {
        ValueSource::Env => s,
        ValueSource::Result | ValueSource::Ocsf => url_component_escape(&s),
    })
}

/// Like [`render_enricher_template`], but JSON-string-escapes every
/// substituted value.
pub(crate) fn render_enricher_template_json(text: &str, result: &EvaluationResult) -> String {
    render_with(text, result, true, |_, s| json_escape_value(s))
}

/// Like [`render_template_json`], but `${detection.ocsf}` /
/// `${correlation.ocsf}` insert the raw JSON `ocsf` returns, unescaped.
///
/// Only a webhook body validated by `validate_webhook_body_template` may
/// contain those references, so the inserted finding always lands where a
/// whole JSON value belongs.
pub(crate) fn render_template_json_with_ocsf(
    text: &str,
    result: &EvaluationResult,
    ocsf: impl Fn() -> String,
) -> String {
    render_with(text, result, false, |source, s| match source {
        ValueSource::Ocsf => ocsf(),
        ValueSource::Env | ValueSource::Result => json_escape_value(s),
    })
}

/// Validate a webhook JSON body, then render it.
///
/// `${detection.ocsf}` and `${correlation.ocsf}` are inserted as raw JSON only
/// after `validate_webhook_body_template` has accepted them as whole JSON
/// values. A template that fails that check is not rendered.
pub fn render_webhook_body(
    text: &str,
    kind: EnricherKind,
    webhook_id: &str,
    result: &EvaluationResult,
    ocsf: impl Fn() -> String,
) -> Result<String, TemplateError> {
    validate_webhook_body_template(text, kind, webhook_id)?;
    Ok(render_template_json_with_ocsf(text, result, ocsf))
}

/// One `${...}` reference in a template, by where its value comes from.
pub(crate) enum TemplateRef<'a> {
    /// `${ENV_VAR}`, with the variable's name.
    Env(&'a str),
    /// Any other reference, with the text between the braces. Rendered from
    /// the evaluation result with [`render_enricher_reference`].
    Result(&'a str),
}

/// Every `${...}` reference in `text`, with its byte range, in order.
pub(crate) fn template_refs(
    text: &str,
) -> impl Iterator<Item = (std::ops::Range<usize>, TemplateRef<'_>)> {
    TEMPLATE_RE.captures_iter(text).map(|caps| {
        let whole = caps.get(0).unwrap();
        let inner = caps.get(1).unwrap().as_str();
        let reference = match classify_ref(inner) {
            VarRef::Env(_) => TemplateRef::Env(inner),
            _ => TemplateRef::Result(inner),
        };
        (whole.range(), reference)
    })
}

/// Render one non-environment reference (the text between `${` and `}`)
/// the way [`render_enricher_template`] renders it.
pub(crate) fn render_enricher_reference(inner: &str, result: &EvaluationResult) -> String {
    resolve_reference(inner, result, true).1
}

/// Where a substituted value came from, so an escaper can treat operator
/// environment values differently from evaluation-result values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueSource {
    Env,
    Result,
    /// `${detection.ocsf}` / `${correlation.ocsf}` on a result of the
    /// matching kind. Renders empty unless the renderer supplies a finding.
    Ocsf,
}

/// Shared render core: substitute every `${...}` reference, then run each
/// substituted value through `escape`.
fn render_with<F: Fn(ValueSource, String) -> String>(
    text: &str,
    result: &EvaluationResult,
    fallback: bool,
    escape: F,
) -> String {
    TEMPLATE_RE
        .replace_all(text, |caps: &regex::Captures| {
            let (source, raw) = resolve_reference(caps.get(1).unwrap().as_str(), result, fallback);
            escape(source, raw)
        })
        .into_owned()
}

/// Resolve the text between `${` and `}` against `result`.
fn resolve_reference(
    inner: &str,
    result: &EvaluationResult,
    fallback: bool,
) -> (ValueSource, String) {
    match classify_ref(inner) {
        VarRef::Env(name) => (ValueSource::Env, std::env::var(name).unwrap_or_default()),
        VarRef::Detection(path) => match &result.body {
            ResultBody::Detection(_) if path == OCSF_PATH => (ValueSource::Ocsf, String::new()),
            ResultBody::Detection(_) => (
                ValueSource::Result,
                render_detection_path(&path, result, fallback),
            ),
            ResultBody::Correlation(_) => (ValueSource::Result, String::new()),
        },
        VarRef::Correlation(path) => match &result.body {
            ResultBody::Correlation(_) if path == OCSF_PATH => (ValueSource::Ocsf, String::new()),
            ResultBody::Correlation(_) => {
                (ValueSource::Result, render_correlation_path(&path, result))
            }
            ResultBody::Detection(_) => (ValueSource::Result, String::new()),
        },
        VarRef::Invalid(_) => (ValueSource::Result, String::new()),
    }
}

/// Bytes left unencoded in a URL component: RFC 3986 unreserved characters.
const URL_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Percent-encode a value as one URL component.
///
/// `.` and `..` are dot segments under the URL standard even when written as
/// `%2E`, so a value that is exactly one of them has its dots encoded twice
/// (`%252E`). The receiver then sees the literal text `%2E` instead of a
/// reference to the current or parent path.
fn url_component_escape(value: &str) -> String {
    if value == "." || value == ".." {
        return "%252E".repeat(value.len());
    }
    utf8_percent_encode(value, URL_COMPONENT).to_string()
}

/// JSON-string-escape a substituted value: serialize it as a JSON string and
/// drop the surrounding quotes.
fn json_escape_value(s: String) -> String {
    let quoted = serde_json::to_string(&s).unwrap_or_else(|_| "\"\"".to_string());
    quoted
        .get(1..quoted.len().saturating_sub(1))
        .unwrap_or("")
        .to_string()
}

fn render_detection_path(path: &str, result: &EvaluationResult, fallback: bool) -> String {
    let body = match result.as_detection() {
        Some(b) => b,
        None => return String::new(),
    };
    if path == "tenant" {
        return result
            .header
            .tenant_id
            .as_ref()
            .map(|tenant| tenant.as_str().to_string())
            .unwrap_or_default();
    }
    if let Some(rest) = path.strip_prefix("rule.") {
        return render_rule_field(rest, result);
    }
    if path == "tags" {
        return result.header.tags.join(",");
    }
    if let Some(name) = path.strip_prefix("fields.") {
        for fm in &body.matched_fields {
            if fm.field == name {
                return json_to_string(&fm.value);
            }
        }
        if fallback && let Some(event) = &body.event {
            if let Some(value) = event.as_object().and_then(|map| map.get(name)) {
                return json_to_string(value);
            }
            return navigate_json(event, name)
                .map(json_to_string)
                .unwrap_or_default();
        }
        return String::new();
    }
    if let Some(rest) = path.strip_prefix("event.") {
        if let Some(event) = &body.event {
            return navigate_json(event, rest)
                .map(json_to_string)
                .unwrap_or_default();
        }
        return String::new();
    }
    if path == "event" {
        return body.event.as_ref().map(json_to_string).unwrap_or_default();
    }
    String::new()
}

fn render_correlation_path(path: &str, result: &EvaluationResult) -> String {
    let body = match result.as_correlation() {
        Some(b) => b,
        None => return String::new(),
    };
    if path == "tenant" {
        return result
            .header
            .tenant_id
            .as_ref()
            .map(|tenant| tenant.as_str().to_string())
            .unwrap_or_default();
    }
    if let Some(rest) = path.strip_prefix("rule.") {
        return render_rule_field(rest, result);
    }
    if path == "tags" {
        return result.header.tags.join(",");
    }
    if path == "type" {
        return body.correlation_type.as_str().to_string();
    }
    if path == "aggregated_value" {
        return format_f64(body.aggregated_value);
    }
    if path == "timespan_secs" {
        return body.timespan_secs.to_string();
    }
    if path == "group_key" {
        return body
            .group_key
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",");
    }
    if let Some(name) = path.strip_prefix("group_key.") {
        for (k, v) in &body.group_key {
            if k == name {
                return v.clone();
            }
        }
        return String::new();
    }
    String::new()
}

fn render_rule_field(rest: &str, result: &EvaluationResult) -> String {
    match rest {
        "title" => result.header.rule_title.clone(),
        "id" => result.header.rule_id.clone().unwrap_or_default(),
        "level" => result
            .header
            .level
            .map(|l: Level| l.as_str().to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Navigate a JSON value by dotted path (`"a.b.c"`).
///
/// Numeric segments index into arrays; everything else looks up object
/// keys. Returns `None` on any miss. Mirrors the behaviour of
/// [`crate::sources::TemplateExpander`]'s navigator so the two surfaces
/// behave identically for operators.
fn navigate_json<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        match current {
            serde_json::Value::Object(map) => current = map.get(segment)?,
            serde_json::Value::Array(arr) => {
                let idx: usize = segment.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

fn json_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// Format an `f64` matching the JSON `serde_json` default: integers as
/// `"73"`, fractions as `"3.5"`. Avoids `to_string()`'s scientific
/// notation drift for large values.
fn format_f64(v: f64) -> String {
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        v.to_string()
    }
}

// ---------------------------------------------------------------------------
// TemplateEnricher implementation
// ---------------------------------------------------------------------------

/// Pure-template enricher: renders a single template string and writes the
/// rendered value into `enrichments[<inject_field>]`.
///
/// All template namespace validation has happened at config load via
/// [`validate_template_namespace`], so `enrich()` is infallible past
/// runtime checks (the only failure mode is an opaque internal panic from
/// the regex engine, which would itself be a bug).
pub struct TemplateEnricher {
    id: String,
    kind: EnricherKind,
    inject_field: String,
    template: String,
    timeout: std::time::Duration,
    on_error: OnError,
    scope: Scope,
}

impl TemplateEnricher {
    /// Construct a `TemplateEnricher`.
    ///
    /// `template` is **not** re-validated here; callers must ensure
    /// [`validate_template_namespace`] has been run at config load.
    pub fn new(
        id: String,
        kind: EnricherKind,
        inject_field: String,
        template: String,
        timeout: std::time::Duration,
        on_error: OnError,
        scope: Scope,
    ) -> Self {
        Self {
            id,
            kind,
            inject_field,
            template,
            timeout,
            on_error,
            scope,
        }
    }
}

#[async_trait]
impl Enricher for TemplateEnricher {
    fn kind(&self) -> EnricherKind {
        self.kind
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn inject_field(&self) -> &str {
        &self.inject_field
    }

    fn timeout(&self) -> std::time::Duration {
        self.timeout
    }

    fn scope(&self) -> &Scope {
        &self.scope
    }

    fn on_error(&self) -> OnError {
        self.on_error
    }

    async fn enrich(&self, result: &mut EvaluationResult) -> Result<(), EnrichError> {
        let rendered = render_enricher_template(&self.template, result);
        inject_enrichment(
            result,
            &self.inject_field,
            serde_json::Value::String(rendered),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use rsigma_eval::result::{DetectionBody, FieldMatch, ResultBody, RuleHeader};

    fn detection(title: &str, field: &str, value: serde_json::Value) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: title.to_string(),
                rule_id: Some("rule-1".to_string()),
                tenant_id: None,
                level: Some(Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec!["selection".to_string()],
                matched_fields: vec![FieldMatch::new(field, value)],
                event: None,
            }),
        }
    }

    #[test]
    fn identity_render_is_unchanged() {
        let r = detection("Whoami", "CommandLine", serde_json::json!("whoami /all"));
        assert_eq!(
            render_template(
                "rule=${detection.rule.title} cmd=${detection.fields.CommandLine}",
                &r
            ),
            "rule=Whoami cmd=whoami /all",
        );
    }

    #[test]
    fn env_references_lists_only_env_vars_once() {
        assert_eq!(
            env_references(
                "${HOME}/${detection.rule.title}/${correlation.type}/${HOME}/${AWS_SECRET}/${a.b}/${}"
            ),
            vec!["HOME".to_string(), "AWS_SECRET".to_string()],
        );
        assert!(env_references("plain ${detection.fields.x} text").is_empty());
    }

    #[test]
    fn env_references_stays_linear_in_distinct_names() {
        let n = 100_000;
        let text: String = (0..n).map(|i| format!("${{V{i}}}")).collect();
        let started = std::time::Instant::now();
        assert_eq!(env_references(&text).len(), n);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn json_escape_keeps_payload_valid_with_hostile_values() {
        // A rule title with a quote, backslash, newline, and a control char
        // would break a JSON body without escaping.
        let r = detection("evil \" \\ \n\u{0001} title", "x", serde_json::json!("v"));
        let body = render_template_json(r#"{"text":"${detection.rule.title}"}"#, &r);
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("escaped body must be valid JSON");
        assert_eq!(parsed["text"], "evil \" \\ \n\u{0001} title");
    }

    #[test]
    fn json_escape_leaves_safe_values_untouched() {
        let r = detection("PlainTitle", "x", serde_json::json!("v"));
        let body = render_template_json(r#"{"text":"${detection.rule.title}"}"#, &r);
        assert_eq!(body, r#"{"text":"PlainTitle"}"#);
    }

    #[test]
    fn json_escape_blocks_key_injection() {
        let r = detection("T", "user", serde_json::json!(r#"a","admin":true,"x":"y"#));
        let body = render_template_json(r#"{"user":"${detection.fields.user}"}"#, &r);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.as_object().unwrap().len(), 1);
        assert_eq!(parsed["user"], r#"a","admin":true,"x":"y"#);
    }

    fn render_url_field(value: &str) -> String {
        let r = detection("T", "f", serde_json::json!(value));
        render_template_url("https://api.example/v1/${detection.fields.f}/info", &r)
    }

    #[test]
    fn url_escape_encodes_path_traversal() {
        assert_eq!(
            render_url_field("/../../admin"),
            "https://api.example/v1/%2F..%2F..%2Fadmin/info"
        );
    }

    #[test]
    fn url_escape_double_encodes_bare_dot_segments() {
        assert_eq!(
            render_url_field(".."),
            "https://api.example/v1/%252E%252E/info"
        );
        assert_eq!(render_url_field("."), "https://api.example/v1/%252E/info");
        assert_eq!(render_url_field("..."), "https://api.example/v1/.../info");
    }

    #[test]
    fn url_escape_encodes_pre_encoded_sequences() {
        assert_eq!(
            render_url_field("%2e%2e"),
            "https://api.example/v1/%252e%252e/info"
        );
    }

    #[test]
    fn url_escape_encodes_query_and_fragment_delimiters() {
        assert_eq!(
            render_url_field("a?b=1&c=2#frag"),
            "https://api.example/v1/a%3Fb%3D1%26c%3D2%23frag/info"
        );
    }

    #[test]
    fn url_escape_leaves_unreserved_values_untouched() {
        assert_eq!(
            render_url_field("host-01.corp_x~y"),
            "https://api.example/v1/host-01.corp_x~y/info"
        );
    }

    #[test]
    fn url_escape_encodes_non_ascii_as_utf8() {
        assert_eq!(
            render_url_field("é "),
            "https://api.example/v1/%C3%A9%20/info"
        );
    }

    #[test]
    fn url_escape_leaves_env_values_verbatim() {
        let var = "RSIGMA_TEMPLATE_URL_TEST_PATH";
        // SAFETY: the variable name is unique to this test.
        unsafe { std::env::set_var(var, "services/T000/B000/xyz") };
        let r = detection("T", "f", serde_json::json!("a/b"));
        let url = render_template_url(
            &format!("https://hooks.example/${{{var}}}?u=${{detection.fields.f}}"),
            &r,
        );
        assert_eq!(url, "https://hooks.example/services/T000/B000/xyz?u=a%2Fb");
    }

    #[test]
    fn url_escaped_values_do_not_traverse_after_parsing() {
        for value in ["..", ".", "/../../admin", "%2e%2e", "../admin"] {
            let rendered = render_url_field(value);
            let parsed = reqwest::Url::parse(&rendered).unwrap();
            assert!(
                parsed.path().starts_with("/v1/") && parsed.path().ends_with("/info"),
                "{value:?} rendered to {rendered} which parses to {}",
                parsed.path()
            );
            assert_eq!(parsed.path_segments().unwrap().count(), 3, "{value:?}");
        }
    }

    #[test]
    fn tenant_paths_render_the_header_tenant() {
        let mut r = detection("Whoami", "CommandLine", serde_json::json!("whoami"));
        r.header.tenant_id = Some(rsigma_eval::TenantId::new("tenant-a").unwrap());
        assert_eq!(render_template("${detection.tenant}", &r), "tenant-a");
        assert_eq!(
            render_template_url("${detection.tenant}", &r),
            "tenant-a",
            "a tenant id is URL-safe"
        );
        r.header.tenant_id = None;
        assert_eq!(render_template("${detection.tenant}", &r), "");
    }

    #[test]
    fn a_tenant_reference_in_a_url_authority_is_refused() {
        assert!(
            validate_url_tenant_position("https://example.test/${detection.tenant}/hook").is_ok()
        );
        assert!(
            validate_url_tenant_position("https://${detection.tenant}.example.test/hook").is_err()
        );
        assert!(
            validate_url_tenant_position("https://${correlation.tenant}.example.test").is_err()
        );
        assert!(validate_url_tenant_position("https://example.test/hook").is_ok());
        assert!(validate_url_tenant_position("https://example.test?t=${detection.tenant}").is_ok());
        assert!(
            validate_url_tenant_position("https://user:${detection.tenant}@example.test/").is_err()
        );
        assert!(validate_url_tenant_position("https://example.test:${detection.tenant}/").is_err());
    }

    #[test]
    fn a_tenant_reference_cannot_reach_the_host_without_a_double_slash() {
        for url in [
            "https:${detection.tenant}/hook",
            "https:/${detection.tenant}/hook",
            "https:\\\\${detection.tenant}/hook",
            "${detection.tenant}.example.test/hook",
        ] {
            assert!(validate_url_tenant_position(url).is_err(), "{url}");
        }
    }

    #[test]
    fn an_env_reference_is_resolved_before_the_authority_check() {
        // SAFETY: test-only variable with a unique name.
        unsafe { std::env::set_var("RSIGMA_TEST_TENANT_URL_BASE", "https://") };
        assert!(
            validate_url_tenant_position(
                "${RSIGMA_TEST_TENANT_URL_BASE}${detection.tenant}.example.test/hook"
            )
            .is_err()
        );
        unsafe { std::env::set_var("RSIGMA_TEST_TENANT_URL_HOST", "https://example.test") };
        assert!(
            validate_url_tenant_position("${RSIGMA_TEST_TENANT_URL_HOST}/${detection.tenant}")
                .is_ok()
        );
    }
}
