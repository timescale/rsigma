//! MMDB enricher throughput benchmarks.
//!
//! Measures the cost of looking up and injecting records for a 1,000-result
//! batch whose `SourceIp` cycles through IPv4 and IPv6 hit networks, plus a
//! batch where every lookup misses and the configured `default` is injected
//! instead. The `city` group runs over the synthetic City fixture. The
//! `merged` group runs over a fixture with a merged geo, ASN, and anonymity
//! layout, and covers several enrichers on one database, a wide projection,
//! and the full record. With the `mmdb-mmap` feature, the `mmap_` cases
//! repeat a case with the database memory-mapped. Databases are loaded once
//! and shared by the pipeline, so the measurement covers lookup, projection,
//! and injection rather than file I/O.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
use rsigma_parser::Level;
use rsigma_runtime::{EnrichersFile, build_enrichers};

const BATCH: usize = 1_000;

const FOUR_FIELDS: &str = "    fields:\n      country: country.iso_code\n      subdivision: subdivisions.0.iso_code\n      latitude: location.latitude\n      city: city.names.en\n";

const GEO_FIELDS: &str = "      country: country.iso_code
      region: subdivisions.0.iso_code
      city: city.names.en
      latitude: location.latitude
      longitude: location.longitude
      accuracy_km: location.accuracy_radius
      time_zone: location.time_zone
";

const ASN_FIELDS: &str = "      number: asn.autonomous_system_number
      organization: asn.autonomous_system_organization
      domain: asn.as_domain
";

const SINGLE_ASN_FIELDS: &str = "      asn: asn.autonomous_system_number
      as_org: asn.autonomous_system_organization
      as_domain: asn.as_domain
";

const ANONYMITY_FIELDS: &str = "      tor: proxy.is_tor
      vpn: proxy.is_vpn
      proxy: proxy.is_proxy
      hosting: proxy.is_hosting
      cdn: proxy.is_cdn
      school: proxy.is_school
      anonymous: proxy.is_anonymous
";

fn detection(ip: String) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Suspicious activity".to_string(),
            rule_id: Some("rule-1".to_string()),
            tenant_id: None,
            level: Some(Level::High),
            tags: vec!["attack.execution".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
            ruleset: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!(ip))],
            event: None,
        }),
    }
}

fn hit_ip(i: usize) -> String {
    let octet = i % 256;
    match i % 3 {
        0 => format!("192.0.2.{octet}"),
        1 => format!("198.51.100.{octet}"),
        _ => format!("2001:db8::{octet:x}"),
    }
}

fn miss_ip(i: usize) -> String {
    format!("203.0.113.{}", i % 256)
}

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/mmdb/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// One `mmdb` entry. `extra` holds the indented `fields` and `default`
/// lines.
fn entry(id: &str, db: &str, extra: &str) -> String {
    format!(
        r#"  - id: {id}
    kind: detection
    type: mmdb
    inject_field: {id}
    db_path: {}
    key: "${{detection.fields.SourceIp}}"
{extra}"#,
        fixture_path(db)
    )
}

fn pipeline_yaml(entries: &[String]) -> String {
    format!("enrichers:\n{}", entries.concat())
}

fn city_yaml(fields: &str, default: bool) -> String {
    let default = if default {
        "    default:\n      country_code: unknown\n"
    } else {
        ""
    };
    pipeline_yaml(&[entry(
        "geo",
        "city-test.mmdb",
        &format!("{fields}{default}"),
    )])
}

fn merged_three_enrichers_yaml() -> String {
    pipeline_yaml(&[
        entry(
            "geo",
            "merged-test.mmdb",
            &format!(
                "    fields:\n{GEO_FIELDS}    default: {{ country: \"unknown\" }}\n    on_error: \"null\"\n"
            ),
        ),
        entry(
            "asn",
            "merged-test.mmdb",
            &format!("    fields:\n{ASN_FIELDS}    default: {{ number: null }}\n"),
        ),
        entry(
            "anonymity",
            "merged-test.mmdb",
            &format!(
                "    fields:\n{ANONYMITY_FIELDS}    default: {{ tor: false, vpn: false, proxy: false, hosting: false }}\n"
            ),
        ),
    ])
}

fn merged_single_17_fields_yaml() -> String {
    pipeline_yaml(&[entry(
        "ip",
        "merged-test.mmdb",
        &format!(
            "    fields:\n{GEO_FIELDS}{SINGLE_ASN_FIELDS}{ANONYMITY_FIELDS}    default: {{ country: \"unknown\" }}\n    on_error: \"null\"\n"
        ),
    )])
}

fn run_group(
    c: &mut Criterion,
    rt: &tokio::runtime::Runtime,
    group_name: &str,
    cases: Vec<(&str, String, Vec<String>)>,
) {
    let mut group = c.benchmark_group(group_name);
    for (name, yaml, ips) in cases {
        let file: EnrichersFile = yaml_serde::from_str(&yaml).unwrap();
        let pipeline = build_enrichers(file).unwrap();
        let batch: Vec<EvaluationResult> = ips.into_iter().map(detection).collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &pipeline,
            |b, pipeline| {
                b.iter(|| {
                    let mut results = batch.clone();
                    rt.block_on(pipeline.run(&mut results));
                    black_box(&results);
                });
            },
        );
    }
    group.finish();
}

fn bench_mmdb(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let hits = || (0..BATCH).map(hit_ip).collect::<Vec<_>>();

    #[allow(unused_mut)]
    let mut city = vec![
        ("full_record", city_yaml("", false), hits()),
        (
            "four_field_projection",
            city_yaml(FOUR_FIELDS, false),
            hits(),
        ),
        (
            "all_miss_default",
            city_yaml("", true),
            (0..BATCH).map(miss_ip).collect(),
        ),
    ];
    #[cfg(feature = "mmdb-mmap")]
    city.push((
        "mmap_four_field_projection",
        mapped(city_yaml(FOUR_FIELDS, false)),
        hits(),
    ));
    run_group(c, &rt, "city", city);

    #[allow(unused_mut)]
    let mut merged = vec![
        ("three_enrichers", merged_three_enrichers_yaml(), hits()),
        ("single_17_fields", merged_single_17_fields_yaml(), hits()),
        (
            "full_record",
            pipeline_yaml(&[entry("geo", "merged-test.mmdb", "")]),
            hits(),
        ),
        (
            "four_field_projection",
            pipeline_yaml(&[entry("geo", "merged-test.mmdb", FOUR_FIELDS)]),
            hits(),
        ),
    ];
    #[cfg(feature = "mmdb-mmap")]
    merged.push((
        "mmap_three_enrichers",
        mapped(merged_three_enrichers_yaml()),
        hits(),
    ));
    run_group(c, &rt, "merged", merged);
}

/// The same pipeline with every entry memory-mapping its database.
#[cfg(feature = "mmdb-mmap")]
fn mapped(yaml: String) -> String {
    yaml.replace("    type: mmdb\n", "    type: mmdb\n    mmap: true\n")
}

criterion_group!(benches, bench_mmdb);
criterion_main!(benches);
