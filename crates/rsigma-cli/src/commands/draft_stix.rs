//! Draft Sigma rules from a STIX 2.1 bundle or one indicator object.
//!
//! The rule id is a UUID v5 over [`RULE_NAMESPACE`], the mapped logsource
//! category, and the sorted indicator ids. The same input yields the same id.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::process;

use rsigma_eval::pipeline::sources::STIX_OBSERVABLE_KEYS;
use rsigma_eval::{ValueDraftSpec, ValueSelection, draft_rule_from_values};
use rstix::core::StixTimestamp;
use rstix::{Bundle, ObservableExtraction, ObservableKind, ParseOptions, SdoObject, StixObject};
use serde::Serialize;
use uuid::Uuid;

use super::draft::{CorrelationTypeArg, DraftArgs, EmitMode};
use crate::exit_code;
use crate::output::{OutputCtx, OutputFormat};

/// Namespace for rule ids drafted from STIX indicators.
pub(crate) const RULE_NAMESPACE: Uuid = uuid::uuid!("6f0e2a1c-9b34-4d5e-8c71-2a9f0b6d4e18");

const HIGH_CONFIDENCE: u8 = 85;
const DESCRIPTION_LIMIT: usize = 1000;

pub(crate) fn run(args: DraftArgs, ctx: OutputCtx) {
    if let Some(flag) = conflict(&args) {
        eprintln!("error: --from-stix cannot be combined with {flag}");
        process::exit(exit_code::CONFIG_ERROR);
    }
    if let Some(unknown) = unknown_observable(&args.observable) {
        eprintln!(
            "error: unknown observable {unknown}; valid keys: {}",
            STIX_OBSERVABLE_KEYS.join(", ")
        );
        process::exit(exit_code::CONFIG_ERROR);
    }
    let path = args.from_stix.as_deref().unwrap_or("-");
    let raw = match read_input(path) {
        Ok(raw) => raw,
        Err(error) => {
            eprintln!("error: {error}");
            process::exit(exit_code::RULE_ERROR);
        }
    };
    let date = args
        .date
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());
    let options = DraftStixOptions {
        title: args.title,
        date,
        logsource_category: args.logsource_category,
        logsource_product: args.logsource_product,
        logsource_service: args.logsource_service,
        observables: args.observable,
        include_expired: args.include_expired,
        now: StixTimestamp::now(),
    };
    let outcome = match draft_stix(&raw, &options) {
        Ok(outcome) => outcome,
        Err(error) => {
            eprintln!("error: {error}");
            process::exit(exit_code::RULE_ERROR);
        }
    };
    if outcome.rules.is_empty() {
        if args.emit == EmitMode::Report {
            print_report(&outcome.report);
        }
        eprintln!("no draftable indicators");
        process::exit(exit_code::FINDINGS);
    }
    match args.emit {
        EmitMode::Yaml => {
            if ctx.explicit_format {
                ctx.warn_unsupported("rule draft --from-stix", "Sigma YAML");
            }
            print!("{}", outcome.rules.join("---\n"));
        }
        EmitMode::Report => {
            if ctx.format != OutputFormat::Json {
                ctx.warn_unsupported("rule draft --from-stix --emit report", "JSON");
            }
            print_report(&outcome.report);
        }
    }
}

fn conflict(args: &DraftArgs) -> Option<&'static str> {
    if args.event.is_some() {
        return Some("--event");
    }
    if args.groups.is_some() {
        return Some("--groups");
    }
    if args.negative.is_some() {
        return Some("--negative");
    }
    if args.baseline.is_some() {
        return Some("--baseline");
    }
    if !args.group_by.is_empty() {
        return Some("--group-by");
    }
    if args.correlation_type != CorrelationTypeArg::Auto {
        return Some("--correlation-type");
    }
    if args.min_groups != 3 {
        return Some("--min-groups");
    }
    if args.window_margin != 1.5 {
        return Some("--window-margin");
    }
    if args.max_fields != 4 {
        return Some("--max-fields");
    }
    if args.min_prevalence != 1.0 {
        return Some("--min-prevalence");
    }
    if !args.include_fields.is_empty() {
        return Some("--include-field");
    }
    if !args.exclude_fields.is_empty() {
        return Some("--exclude-field");
    }
    if args.skip_baseline_eval {
        return Some("--skip-baseline-eval");
    }
    None
}

fn unknown_observable(observables: &[String]) -> Option<&str> {
    observables
        .iter()
        .find(|key| !STIX_OBSERVABLE_KEYS.contains(&key.as_str()))
        .map(String::as_str)
}

fn read_input(path: &str) -> io::Result<String> {
    if path == "-" {
        let mut raw = String::new();
        io::stdin().read_to_string(&mut raw)?;
        return Ok(raw);
    }
    std::fs::read_to_string(path)
        .map_err(|error| io::Error::new(error.kind(), format!("failed to read {path}: {error}")))
}

fn print_report(report: &StixDraftReport) {
    let text = serde_json::to_string_pretty(report).unwrap_or_else(|error| {
        eprintln!("error: {error}");
        process::exit(exit_code::RULE_ERROR);
    });
    println!("{text}");
}

struct DraftStixOptions {
    title: Option<String>,
    date: String,
    logsource_category: Option<String>,
    logsource_product: Option<String>,
    logsource_service: Option<String>,
    observables: Vec<String>,
    include_expired: bool,
    now: StixTimestamp,
}

struct DraftStixOutcome {
    rules: Vec<String>,
    report: StixDraftReport,
}

#[derive(Serialize)]
struct StixDraftReport {
    rules: Vec<String>,
    used: Vec<UsedIndicator>,
    skipped: Vec<SkippedIndicator>,
}

#[derive(Serialize)]
struct UsedIndicator {
    id: String,
    kinds: Vec<String>,
    values: Vec<String>,
}

#[derive(Serialize)]
struct SkippedIndicator {
    id: String,
    reason: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    Ipv4,
    Ipv6,
    Ipv4Cidr,
    Ipv6Cidr,
    Domain,
    Url,
    Hashes,
    FileName,
    RegistryKey,
}

struct Contributor {
    name: Option<String>,
    description: Option<String>,
    confidence: Option<u8>,
    references: BTreeSet<String>,
    tags: BTreeSet<String>,
}

struct Bucket {
    slots: BTreeMap<Slot, BTreeSet<String>>,
    contributors: BTreeMap<String, Contributor>,
}

fn draft_stix(raw: &str, options: &DraftStixOptions) -> Result<DraftStixOutcome, String> {
    let text = bundle_text(raw)?;
    let mut parse_options = ParseOptions::new().allow_custom(true);
    parse_options.max_object_count = 100_000;
    let bundle = Bundle::parse_with_options(&text, &parse_options)
        .map_err(|error| format!("failed to parse STIX: {error}"))?;

    let filter: BTreeSet<&str> = options.observables.iter().map(String::as_str).collect();
    let mut buckets: BTreeMap<&'static str, Bucket> = BTreeMap::new();
    let mut used: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    let mut skipped = Vec::new();

    for object in bundle.objects() {
        let StixObject::Sdo(SdoObject::Indicator(indicator)) = object else {
            continue;
        };
        let id = indicator.common.id.to_string();
        if indicator.common.revoked == Some(true) {
            skipped.push(SkippedIndicator {
                id: id.clone(),
                reason: "revoked",
            });
            continue;
        }
        if !options.include_expired && indicator.valid_from > options.now {
            skipped.push(SkippedIndicator {
                id: id.clone(),
                reason: "not_yet_valid",
            });
            continue;
        }
        if !options.include_expired
            && indicator
                .valid_until
                .as_ref()
                .is_some_and(|until| until <= &options.now)
        {
            skipped.push(SkippedIndicator {
                id: id.clone(),
                reason: "expired",
            });
            continue;
        }
        let Ok(pattern) = indicator.pattern.parsed_pattern() else {
            skipped.push(SkippedIndicator {
                id: id.clone(),
                reason: "pattern_type",
            });
            continue;
        };
        let items = match pattern.simple_observables() {
            ObservableExtraction::Simple(items) => items,
            ObservableExtraction::Unsupported(_) => {
                skipped.push(SkippedIndicator {
                    id: id.clone(),
                    reason: "unsupported_pattern",
                });
                continue;
            }
        };

        let mut accepted: Vec<(ObservableKind, Slot, String, String)> = Vec::new();
        let mut filtered = false;
        for item in items {
            let Some(kind) = item.kind else {
                continue;
            };
            if !filter.is_empty() && !filter.contains(kind.key()) {
                if mapped(kind, &item.value).is_some() {
                    filtered = true;
                }
                continue;
            }
            if let Some((slot, formatted)) = mapped(kind, &item.value) {
                accepted.push((kind, slot, formatted, item.value));
            }
        }
        if accepted.is_empty() {
            skipped.push(SkippedIndicator {
                id: id.clone(),
                reason: if filtered {
                    "filtered_observable"
                } else {
                    "unmapped_observable"
                },
            });
            continue;
        }

        let contributor = Contributor {
            name: indicator.name.clone(),
            description: indicator.description.clone(),
            confidence: indicator.common.confidence.map(|value| value.get()),
            references: indicator
                .common
                .external_references
                .iter()
                .filter_map(|reference| reference.url.clone())
                .filter(|url| !url.trim().is_empty())
                .collect(),
            tags: indicator
                .kill_chain_phases
                .iter()
                .filter(|phase| phase.kill_chain_name == "mitre-attack")
                .map(|phase| attack_tag(&phase.phase_name))
                .filter(|tag| tag != "attack.")
                .collect(),
        };
        let used_entry = used.entry(id.clone()).or_default();
        for (kind, slot, formatted, value) in accepted {
            let category = category_of(slot);
            let bucket = buckets.entry(category).or_insert_with(|| Bucket {
                slots: BTreeMap::new(),
                contributors: BTreeMap::new(),
            });
            bucket.slots.entry(slot).or_default().insert(formatted);
            bucket
                .contributors
                .entry(id.clone())
                .or_insert_with(|| Contributor {
                    name: contributor.name.clone(),
                    description: contributor.description.clone(),
                    confidence: contributor.confidence,
                    references: contributor.references.clone(),
                    tags: contributor.tags.clone(),
                });
            used_entry.0.insert(kind.key().to_string());
            used_entry.1.insert(value);
        }
    }

    let mut rules = Vec::new();
    for (category, bucket) in &buckets {
        let yaml = emit_category(category, bucket, options)?;
        rules.push(yaml);
    }
    skipped.sort_by(|left, right| left.id.cmp(&right.id));
    let report = StixDraftReport {
        rules: rules.clone(),
        used: used
            .into_iter()
            .map(|(id, (kinds, values))| UsedIndicator {
                id,
                kinds: kinds.into_iter().collect(),
                values: values.into_iter().collect(),
            })
            .collect(),
        skipped,
    };
    Ok(DraftStixOutcome { rules, report })
}

fn emit_category(
    category: &str,
    bucket: &Bucket,
    options: &DraftStixOptions,
) -> Result<String, String> {
    let mut selections = Vec::new();
    for (slot, values) in &bucket.slots {
        if values.is_empty() {
            continue;
        }
        let (name, field, modifiers) = selection_meta(*slot);
        selections.push(ValueSelection {
            name: name.to_string(),
            field: field.to_string(),
            modifiers: modifiers
                .iter()
                .map(|modifier| (*modifier).to_string())
                .collect(),
            values: values.iter().cloned().collect(),
        });
    }
    let mut references = BTreeSet::new();
    let mut tags = BTreeSet::new();
    for contributor in bucket.contributors.values() {
        references.extend(contributor.references.iter().cloned());
        tags.extend(contributor.tags.iter().cloned());
    }
    let logsource_category = non_empty(options.logsource_category.as_deref())
        .unwrap_or(category)
        .to_string();
    let spec = ValueDraftSpec {
        title: rule_title(options.title.as_deref(), category, &bucket.contributors),
        description: describe(&bucket.contributors),
        references: references.into_iter().collect(),
        tags: tags.into_iter().collect(),
        rule_id: Some(rule_id(category, &bucket.contributors)),
        date: Some(options.date.clone()),
        logsource_category: Some(logsource_category),
        logsource_product: non_empty(options.logsource_product.as_deref()).map(str::to_string),
        logsource_service: non_empty(options.logsource_service.as_deref()).map(str::to_string),
        level: Some(rule_level(&bucket.contributors).to_string()),
        selections,
    };
    draft_rule_from_values(&spec).map_err(|error| error.to_string())
}

fn bundle_text(raw: &str) -> Result<String, String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|error| format!("invalid JSON: {error}"))?;
    match value.get("type").and_then(serde_json::Value::as_str) {
        Some("bundle") => Ok(raw.to_string()),
        Some("indicator") => {
            let bundle = serde_json::json!({
                "type": "bundle",
                "id": "bundle--00000000-0000-4000-8000-000000000001",
                "objects": [value],
            });
            serde_json::to_string(&bundle).map_err(|error| error.to_string())
        }
        Some(other) => Err(format!(
            "expected a STIX bundle or indicator, found type {other}"
        )),
        None => Err("expected a STIX bundle or indicator".to_string()),
    }
}

/// Hives Sysmon abbreviates, longest first so `HKCU` is not read as `HKU`.
const REGISTRY_HIVES: &[&str] = &[
    "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER",
    "HKEY_CURRENT_CONFIG",
    "HKEY_CLASSES_ROOT",
    "HKEY_USERS",
    "HKLM",
    "HKCU",
    "HKCR",
    "HKCC",
    "HKU",
];

fn canonical_ipv6(value: &str) -> String {
    value
        .parse::<std::net::Ipv6Addr>()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| value.to_string())
}

/// `TargetObject|contains` needle. The hive is dropped and the remaining key
/// is wrapped in backslashes, so a Sysmon value that uses a short hive and
/// appends the value name still matches. A key with no known hive keeps its
/// whole path, wrapped the same way. A hive with no key path is not drafted.
fn registry_contains_value(key: &str) -> Option<String> {
    let rest = strip_registry_hive(key).unwrap_or(key);
    let rest = rest.trim_matches('\\');
    if rest.is_empty() {
        return None;
    }
    Some(format!("\\{rest}\\"))
}

fn strip_registry_hive(key: &str) -> Option<&str> {
    let trimmed = key.trim();
    for hive in REGISTRY_HIVES {
        if !trimmed
            .get(..hive.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(hive))
        {
            continue;
        }
        let rest = &trimmed[hive.len()..];
        if rest.is_empty() || rest.starts_with('\\') {
            return Some(rest);
        }
    }
    None
}

fn mapped(kind: ObservableKind, value: &str) -> Option<(Slot, String)> {
    Some(match kind {
        ObservableKind::Ipv4 => (Slot::Ipv4, value.to_string()),
        ObservableKind::Ipv6 => (Slot::Ipv6, canonical_ipv6(value)),
        ObservableKind::Ipv4Cidr => (Slot::Ipv4Cidr, value.to_string()),
        ObservableKind::Ipv6Cidr => (Slot::Ipv6Cidr, value.to_string()),
        ObservableKind::Domain => (Slot::Domain, value.to_string()),
        ObservableKind::Url => (Slot::Url, value.to_string()),
        ObservableKind::Md5 => (Slot::Hashes, format!("MD5={value}")),
        ObservableKind::Sha1 => (Slot::Hashes, format!("SHA1={value}")),
        ObservableKind::Sha256 => (Slot::Hashes, format!("SHA256={value}")),
        ObservableKind::Sha512 => (Slot::Hashes, format!("SHA512={value}")),
        ObservableKind::FileName => (Slot::FileName, format!("\\{value}")),
        ObservableKind::RegistryKey => (Slot::RegistryKey, registry_contains_value(value)?),
        _ => return None,
    })
}

fn category_of(slot: Slot) -> &'static str {
    match slot {
        Slot::Ipv4 | Slot::Ipv6 | Slot::Ipv4Cidr | Slot::Ipv6Cidr => "network_connection",
        Slot::Domain => "dns_query",
        Slot::Url => "proxy",
        Slot::Hashes => "process_creation",
        Slot::FileName => "file_event",
        Slot::RegistryKey => "registry_set",
    }
}

fn selection_meta(slot: Slot) -> (&'static str, &'static str, &'static [&'static str]) {
    match slot {
        Slot::Ipv4 => ("selection_destination_ip", "DestinationIp", &[]),
        Slot::Ipv6 => ("selection_destination_ipv6", "DestinationIp", &[]),
        Slot::Ipv4Cidr => ("selection_destination_ip_cidr", "DestinationIp", &["cidr"]),
        Slot::Ipv6Cidr => (
            "selection_destination_ipv6_cidr",
            "DestinationIp",
            &["cidr"],
        ),
        Slot::Domain => ("selection_query_name", "QueryName", &[]),
        Slot::Url => ("selection_c_uri", "c-uri", &[]),
        Slot::Hashes => ("selection_hashes", "Hashes", &["contains"]),
        Slot::FileName => ("selection_target_filename", "TargetFilename", &["endswith"]),
        Slot::RegistryKey => ("selection_target_object", "TargetObject", &["contains"]),
    }
}

fn attack_tag(phase: &str) -> String {
    format!(
        "attack.{}",
        phase.trim().replace('-', "_").to_ascii_lowercase()
    )
}

fn rule_title(
    title: Option<&str>,
    category: &str,
    contributors: &BTreeMap<String, Contributor>,
) -> String {
    if let Some(title) = non_empty(title) {
        return title.to_string();
    }
    if contributors.len() == 1
        && let Some(name) = contributors
            .values()
            .next()
            .and_then(|contributor| non_empty(contributor.name.as_deref()))
    {
        return name.to_string();
    }
    format!("Indicators: {category} ({})", contributors.len())
}

fn rule_level(contributors: &BTreeMap<String, Contributor>) -> &'static str {
    if contributors.values().all(|contributor| {
        contributor
            .confidence
            .is_some_and(|value| value >= HIGH_CONFIDENCE)
    }) {
        "high"
    } else {
        "medium"
    }
}

fn rule_id(category: &str, contributors: &BTreeMap<String, Contributor>) -> String {
    let mut name = category.to_string();
    for id in contributors.keys() {
        name.push('\n');
        name.push_str(id);
    }
    Uuid::new_v5(&RULE_NAMESPACE, name.as_bytes()).to_string()
}

fn describe(contributors: &BTreeMap<String, Contributor>) -> Option<String> {
    let mut parts = Vec::new();
    for contributor in contributors.values() {
        let name = non_empty(contributor.name.as_deref());
        let description = non_empty(contributor.description.as_deref());
        let text = match (name, description) {
            (Some(name), Some(description)) => format!("{name}: {description}"),
            (Some(name), None) => name.to_string(),
            (None, Some(description)) => description.to_string(),
            (None, None) => continue,
        };
        parts.push(text.replace(['\n', '\r'], " "));
    }
    if parts.is_empty() {
        return None;
    }
    let joined = parts.join(" ");
    Some(joined.chars().take(DESCRIPTION_LIMIT).collect())
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> StixTimestamp {
        StixTimestamp::parse("2026-06-01T00:00:00.000Z").expect("clock")
    }

    fn options() -> DraftStixOptions {
        DraftStixOptions {
            title: None,
            date: "2026-06-01".to_string(),
            logsource_category: None,
            logsource_product: None,
            logsource_service: None,
            observables: Vec::new(),
            include_expired: false,
            now: now(),
        }
    }

    fn indicator(id: &str, name: &str, pattern: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": id,
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "name": name,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": "2020-01-01T00:00:00.000Z",
            "indicator_types": ["malicious-activity"]
        })
    }

    fn bundle(objects: Vec<serde_json::Value>) -> String {
        serde_json::json!({
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-0000000000aa",
            "objects": objects
        })
        .to_string()
    }

    #[test]
    fn mapping_splits_logsources_and_merges_hashes() {
        let mut object = indicator(
            "indicator--00000000-0000-4000-8000-000000000010",
            "Mixed",
            "[ipv4-addr:value = '198.51.100.7'] OR \
             [ipv4-addr:value = '198.51.100.0/24'] OR \
             [ipv6-addr:value = '2001:DB8::1'] OR \
             [domain-name:value = 'Bad.Example.com'] OR \
             [url:value = 'https://bad.example/a'] OR \
             [file:hashes.'MD5' = 'AABB'] OR \
             [file:hashes.'SHA-256' = 'EEFF'] OR \
             [file:name = 'evil.exe'] OR \
             [windows-registry-key:key = 'HKLM-Software'] OR \
             [email-addr:value = 'a@bad.example'] OR \
             [mutex:name = 'Global-Lock']",
        );
        object["confidence"] = serde_json::json!(90);
        object["kill_chain_phases"] = serde_json::json!([
            {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"},
            {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "delivery"}
        ]);
        let outcome = draft_stix(&bundle(vec![object]), &options()).unwrap();
        assert_eq!(outcome.rules.len(), 6);
        let yaml = outcome.rules.join("\n");
        assert!(yaml.contains("DestinationIp: 198.51.100.7"));
        assert!(yaml.contains("DestinationIp: '2001:db8::1'"));
        assert!(yaml.contains("DestinationIp|cidr: '198.51.100.0/24'"));
        assert!(yaml.contains("QueryName: bad.example"));
        assert!(yaml.contains("c-uri: 'https://bad.example/a'"));
        assert!(yaml.contains("'MD5=aabb'"));
        assert!(yaml.contains("'SHA256=eeff'"));
        assert!(yaml.contains("TargetFilename|endswith: '\\evil.exe'"));
        assert!(yaml.contains(r"TargetObject|contains: '\HKLM-Software\\'"));
        assert!(!yaml.contains("a@bad.example"));
        assert!(!yaml.contains("Global-Lock"));
        assert!(yaml.contains("attack.command_and_control"));
        assert!(!yaml.contains("delivery"));
        assert!(yaml.contains("level: high"));
        assert_eq!(outcome.report.used.len(), 1);
        assert!(outcome.report.used[0].kinds.contains(&"ipv4".to_string()));
        assert!(
            !outcome.report.used[0]
                .kinds
                .iter()
                .any(|kind| kind == "email")
        );
    }

    #[test]
    fn title_level_and_id_follow_the_contributors() {
        let mut first = indicator(
            "indicator--00000000-0000-4000-8000-000000000002",
            "First address",
            "[ipv4-addr:value = '198.51.100.8']",
        );
        first["confidence"] = serde_json::json!(90);
        let second = indicator(
            "indicator--00000000-0000-4000-8000-000000000003",
            "Second address",
            "[ipv4-addr:value = '198.51.100.9']",
        );
        let outcome = draft_stix(&bundle(vec![first, second]), &options()).unwrap();
        assert_eq!(outcome.rules.len(), 1);
        assert!(outcome.rules[0].contains("title: 'Indicators: network_connection (2)'"));
        assert!(outcome.rules[0].contains("level: medium"));
        let again = draft_stix(
            &bundle(vec![
                indicator(
                    "indicator--00000000-0000-4000-8000-000000000002",
                    "First address",
                    "[ipv4-addr:value = '198.51.100.8']",
                ),
                indicator(
                    "indicator--00000000-0000-4000-8000-000000000003",
                    "Second address",
                    "[ipv4-addr:value = '198.51.100.9']",
                ),
            ]),
            &options(),
        )
        .unwrap();
        // The second call drops confidence, so the level stays medium and the id matches.
        assert_eq!(
            outcome.rules[0]
                .lines()
                .find(|line| line.starts_with("id: ")),
            again.rules[0].lines().find(|line| line.starts_with("id: "))
        );
        assert!(outcome.rules[0].contains("id: 3110de92-5237-569d-af16-8eb9e207a119"));

        let mut options = options();
        options.title = Some("Pinned".into());
        options.logsource_product = Some("windows".into());
        let pinned = draft_stix(
            &bundle(vec![indicator(
                "indicator--00000000-0000-4000-8000-000000000001",
                "Beacon address",
                "[ipv4-addr:value = '198.51.100.7'] OR [domain-name:value = 'bad.example']",
            )]),
            &options,
        )
        .unwrap();
        assert_eq!(pinned.rules.len(), 2);
        assert!(
            pinned
                .rules
                .iter()
                .all(|rule| rule.starts_with("title: Pinned\n"))
        );
        assert!(
            pinned
                .rules
                .iter()
                .all(|rule| rule.contains("product: windows"))
        );
        let categories: Vec<_> = pinned
            .rules
            .iter()
            .filter_map(|rule| {
                rule.lines()
                    .find(|line| line.trim_start().starts_with("category: "))
            })
            .collect();
        assert_eq!(categories.len(), 2);
    }

    #[test]
    fn lifecycle_skips_are_reported_and_include_expired_keeps_both_windows() {
        let mut expired = indicator(
            "indicator--00000000-0000-4000-8000-000000000008",
            "Expired",
            "[ipv4-addr:value = '198.51.100.10']",
        );
        expired["valid_until"] = serde_json::json!("2020-06-01T00:00:00.000Z");
        let mut future = indicator(
            "indicator--00000000-0000-4000-8000-00000000000c",
            "Future",
            "[ipv4-addr:value = '198.51.100.11']",
        );
        future["valid_from"] = serde_json::json!("2099-01-01T00:00:00.000Z");
        let mut revoked = indicator(
            "indicator--00000000-0000-4000-8000-000000000007",
            "Revoked",
            "[ipv4-addr:value = '198.51.100.12']",
        );
        revoked["revoked"] = serde_json::json!(true);
        let raw = bundle(vec![expired, future, revoked]);
        let skipped = draft_stix(&raw, &options()).unwrap();
        assert!(skipped.rules.is_empty());
        let reasons: Vec<_> = skipped
            .report
            .skipped
            .iter()
            .map(|row| row.reason)
            .collect();
        assert_eq!(reasons, vec!["revoked", "expired", "not_yet_valid"]);

        let mut options = options();
        options.include_expired = true;
        let kept = draft_stix(&raw, &options).unwrap();
        assert_eq!(kept.rules.len(), 1);
        assert!(kept.rules[0].contains("198.51.100.10"));
        assert!(kept.rules[0].contains("198.51.100.11"));
        assert!(!kept.rules[0].contains("198.51.100.12"));
        assert_eq!(kept.report.skipped.len(), 1);
        assert_eq!(kept.report.skipped[0].reason, "revoked");
    }

    #[test]
    fn description_stops_at_one_thousand_characters() {
        let mut object = indicator(
            "indicator--00000000-0000-4000-8000-000000000020",
            "N",
            "[ipv4-addr:value = '198.51.100.20']",
        );
        object["description"] = serde_json::json!("x".repeat(2_000));
        let outcome = draft_stix(&bundle(vec![object]), &options()).unwrap();
        let line = outcome.rules[0]
            .lines()
            .find(|line| line.starts_with("description: "))
            .unwrap();
        let quoted = line.trim_start_matches("description: ");
        let inner = quoted
            .strip_prefix('\'')
            .and_then(|text| text.strip_suffix('\''))
            .unwrap();
        assert_eq!(inner.chars().count(), 1000);
        assert!(inner.starts_with("N: "));
    }

    #[test]
    fn a_repeated_indicator_id_fails_the_parse() {
        let id = "indicator--00000000-0000-4000-8000-000000000021";
        let older = indicator(id, "Old", "[ipv4-addr:value = '198.51.100.21']");
        let mut newer = indicator(id, "New", "[ipv4-addr:value = '198.51.100.21']");
        newer["modified"] = serde_json::json!("2025-01-01T00:00:00.000Z");
        newer["revoked"] = serde_json::json!(true);
        let error = match draft_stix(&bundle(vec![older, newer]), &options()) {
            Err(error) => error,
            Ok(_) => panic!("duplicate indicator ids were accepted"),
        };
        assert!(error.contains("duplicate bundle object id"), "{error}");
        assert!(error.contains(id), "{error}");
    }

    #[test]
    fn a_single_indicator_object_is_wrapped() {
        let object = indicator(
            "indicator--00000000-0000-4000-8000-000000000001",
            "Beacon address",
            "[ipv4-addr:value = '198.51.100.7']",
        );
        let outcome = draft_stix(&object.to_string(), &options()).unwrap();
        assert!(outcome.rules[0].contains("title: Beacon address"));
        assert!(outcome.rules[0].contains("id: 68e70f9d-8a24-5a4b-8718-7f20315e9734"));
    }

    #[test]
    fn ipv6_is_written_in_canonical_form_and_cidr_is_not() {
        let outcome = draft_stix(
            &bundle(vec![indicator(
                "indicator--00000000-0000-4000-8000-000000000024",
                "Address",
                "[ipv6-addr:value = '2001:0DB8:0000:0000:0000:0000:0000:0001'] OR \
                 [ipv6-addr:value = '2001:0DB8::/32']",
            )]),
            &options(),
        )
        .unwrap();
        let yaml = outcome.rules.join("\n");
        assert!(yaml.contains("DestinationIp: '2001:db8::1'"), "{yaml}");
        assert!(yaml.contains("'2001:0DB8::/32'"), "{yaml}");
        assert!(!yaml.contains("2001:0DB8:0000"), "{yaml}");
    }

    #[test]
    fn registry_key_drops_the_hive_and_uses_contains() {
        let cases = [
            (
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                r"\Software\Microsoft\Windows\CurrentVersion\Run\\",
            ),
            ("HKLM\\Software\\Run", r"\Software\Run\\"),
            ("HKEY_CURRENT_USER\\Software\\Run", r"\Software\Run\\"),
            ("HKCU\\Software\\Run", r"\Software\Run\\"),
            (
                "HKEY_USERS\\S-1-5-21\\Software\\Run",
                r"\S-1-5-21\Software\Run\\",
            ),
            ("HKU\\S-1-5-21\\Software\\Run", r"\S-1-5-21\Software\Run\\"),
            ("HKEY_CLASSES_ROOT\\Software\\Run", r"\Software\Run\\"),
            ("HKCR\\Software\\Run", r"\Software\Run\\"),
            ("HKEY_CURRENT_CONFIG\\Software\\Run", r"\Software\Run\\"),
            ("HKCC\\Software\\Run", r"\Software\Run\\"),
            ("hkey_local_machine\\Software\\Run", r"\Software\Run\\"),
            ("HKL€\\Software", r"\HKL€\Software\\"),
            (
                "HKEY_LOCAL_MACHIN€\\Software",
                r"\HKEY_LOCAL_MACHIN€\Software\\",
            ),
        ];
        for (key, needle) in cases {
            let pattern = format!(
                "[windows-registry-key:key = '{}']",
                key.replace('\\', "\\\\")
            );
            let outcome = draft_stix(
                &bundle(vec![indicator(
                    "indicator--00000000-0000-4000-8000-000000000023",
                    "Run key",
                    &pattern,
                )]),
                &options(),
            )
            .unwrap();
            let yaml = &outcome.rules[0];
            assert!(yaml.contains("TargetObject|contains:"), "{key}\n{yaml}");
            assert!(yaml.contains(needle), "{key}\n{yaml}");
        }

        let hive_only = draft_stix(
            &bundle(vec![indicator(
                "indicator--00000000-0000-4000-8000-000000000025",
                "Hive",
                "[windows-registry-key:key = 'HKEY_LOCAL_MACHINE']",
            )]),
            &options(),
        )
        .unwrap();
        assert!(hive_only.rules.is_empty());
        assert_eq!(hive_only.report.skipped[0].reason, "unmapped_observable");
    }

    #[test]
    fn valid_until_equal_to_the_clock_is_expired() {
        let mut object = indicator(
            "indicator--00000000-0000-4000-8000-000000000026",
            "Boundary",
            "[ipv4-addr:value = '198.51.100.26']",
        );
        object["valid_until"] = serde_json::json!("2026-06-01T00:00:00.000Z");
        let outcome = draft_stix(&bundle(vec![object]), &options()).unwrap();
        assert!(outcome.rules.is_empty());
        assert_eq!(outcome.report.skipped.len(), 1);
        assert_eq!(outcome.report.skipped[0].reason, "expired");
    }
}
