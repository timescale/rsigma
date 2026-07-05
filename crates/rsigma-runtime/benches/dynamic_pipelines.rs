//! Criterion benchmarks for the dynamic pipelines subsystem.
//!
//! Measures:
//! - Source resolution latency (file read + parse + extract)
//! - Template expansion throughput (var substitution with resolved data)
//! - End-to-end dynamic pipeline evaluation (resolve + expand + detect)

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rsigma_eval::pipeline::sources::{DataFormat, DynamicSource, ErrorPolicy, ExtractExpr};
use rsigma_eval::{CorrelationConfig, Pipeline};
use rsigma_runtime::sources::extract::apply_extract;
use rsigma_runtime::sources::file::parse_data;
use rsigma_runtime::{
    DefaultSourceResolver, LogProcessor, NoopMetrics, RuntimeEngine, SourceResolver,
    TemplateExpander,
};

// ---------------------------------------------------------------------------
// Synthetic data generators
// ---------------------------------------------------------------------------

fn gen_json_array(n: usize) -> String {
    let items: Vec<String> = (0..n).map(|i| format!("\"item_{i}\"")).collect();
    format!("[{}]", items.join(","))
}

fn gen_nested_json(depth: usize, breadth: usize) -> serde_json::Value {
    if depth == 0 {
        serde_json::json!(["a", "b", "c"])
    } else {
        let mut map = serde_json::Map::new();
        for i in 0..breadth {
            map.insert(format!("level_{i}"), gen_nested_json(depth - 1, breadth));
        }
        serde_json::Value::Object(map)
    }
}

fn make_source_file(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

fn make_file_source(path: &str) -> DynamicSource {
    use rsigma_eval::pipeline::sources::{RefreshPolicy, SourceType};
    DynamicSource {
        id: "bench_source".to_string(),
        source_type: SourceType::File {
            path: path.into(),
            format: DataFormat::Json,
            extract: None,
        },
        refresh: RefreshPolicy::Once,
        on_error: ErrorPolicy::Fail,
        required: true,
        timeout: None,
        default: None,
    }
}

fn make_file_source_with_extract(path: &str, extract: ExtractExpr) -> DynamicSource {
    use rsigma_eval::pipeline::sources::{RefreshPolicy, SourceType};
    DynamicSource {
        id: "bench_source".to_string(),
        source_type: SourceType::File {
            path: path.into(),
            format: DataFormat::Json,
            extract: Some(extract),
        },
        refresh: RefreshPolicy::Once,
        on_error: ErrorPolicy::Fail,
        required: true,
        timeout: None,
        default: None,
    }
}

fn make_pipeline_with_vars(n_vars: usize, _values_per_var: usize) -> Pipeline {
    let mut vars = HashMap::new();
    for i in 0..n_vars {
        vars.insert(format!("var_{i}"), vec![format!("${{source.src_{i}}}")]);
    }
    Pipeline {
        name: "bench-pipeline".to_string(),
        priority: 10,
        vars,
        transformations: vec![],
        finalizers: vec![],
        sources: vec![],
        source_refs: vec![],
    }
}

fn make_resolved_data(
    n_sources: usize,
    values_per_source: usize,
) -> HashMap<String, serde_json::Value> {
    let mut data = HashMap::new();
    for i in 0..n_sources {
        let arr: Vec<serde_json::Value> = (0..values_per_source)
            .map(|j| serde_json::Value::String(format!("value_{i}_{j}")))
            .collect();
        data.insert(format!("src_{i}"), serde_json::Value::Array(arr));
    }
    data
}

// ---------------------------------------------------------------------------
// Benchmark: source resolution latency (file read + JSON parse)
// ---------------------------------------------------------------------------

fn bench_source_resolution_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("source_resolve_file");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let resolver = DefaultSourceResolver::new();

    for n_items in [10, 100, 1000, 10_000] {
        let content = gen_json_array(n_items);
        let file = make_source_file(&content);
        let source = make_file_source(file.path().to_str().unwrap());

        group.bench_with_input(BenchmarkId::new("items", n_items), &source, |b, source| {
            b.iter(|| {
                rt.block_on(async {
                    let result = resolver.resolve(black_box(source)).await;
                    black_box(result.unwrap());
                });
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: parse_data (JSON parsing without file I/O)
// ---------------------------------------------------------------------------

fn bench_parse_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("source_parse_data");

    for n_items in [10, 100, 1000, 10_000] {
        let content = gen_json_array(n_items);

        group.bench_with_input(
            BenchmarkId::new("json_array", n_items),
            &content,
            |b, content| {
                b.iter(|| {
                    let result = parse_data(black_box(content), DataFormat::Json);
                    black_box(result.unwrap());
                });
            },
        );
    }

    // YAML parsing
    let yaml_content = "- item_0\n- item_1\n- item_2\n- item_3\n- item_4\n- item_5\n- item_6\n- item_7\n- item_8\n- item_9\n";
    group.bench_function("yaml_10", |b| {
        b.iter(|| {
            let result = parse_data(black_box(yaml_content), DataFormat::Yaml);
            black_box(result.unwrap());
        });
    });

    // Lines format
    let lines_content: String = (0..100).map(|i| format!("line_{i}\n")).collect();
    group.bench_function("lines_100", |b| {
        b.iter(|| {
            let result = parse_data(black_box(&lines_content), DataFormat::Lines);
            black_box(result.unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: extract expression evaluation (JQ, JSONPath, CEL)
// ---------------------------------------------------------------------------

fn bench_extract_expressions(c: &mut Criterion) {
    let mut group = c.benchmark_group("source_extract");

    let data = gen_nested_json(3, 3);

    // JQ: select from array at nested path
    let flat_data = serde_json::json!({
        "items": (0..100).map(|i| serde_json::json!({"name": format!("item_{i}"), "active": i % 2 == 0})).collect::<Vec<_>>(),
        "metadata": {"count": 100}
    });

    group.bench_function("jq_identity", |b| {
        b.iter(|| {
            let result = apply_extract(
                black_box(&flat_data),
                &ExtractExpr::Jq(".items".to_string()),
            );
            black_box(result.unwrap());
        });
    });

    group.bench_function("jq_filter", |b| {
        b.iter(|| {
            let result = apply_extract(
                black_box(&flat_data),
                &ExtractExpr::Jq(".items[] | select(.active) | .name".to_string()),
            );
            black_box(result.unwrap());
        });
    });

    group.bench_function("jq_nested_path", |b| {
        b.iter(|| {
            let result = apply_extract(
                black_box(&data),
                &ExtractExpr::Jq(".level_0.level_0.level_0".to_string()),
            );
            black_box(result.unwrap());
        });
    });

    // JSONPath
    group.bench_function("jsonpath_simple", |b| {
        b.iter(|| {
            let result = apply_extract(
                black_box(&flat_data),
                &ExtractExpr::JsonPath("$.items[*].name".to_string()),
            );
            black_box(result.unwrap());
        });
    });

    group.bench_function("jsonpath_filter", |b| {
        b.iter(|| {
            let result = apply_extract(
                black_box(&flat_data),
                &ExtractExpr::JsonPath("$.items[?@.active==true].name".to_string()),
            );
            black_box(result.unwrap());
        });
    });

    // CEL
    group.bench_function("cel_field_access", |b| {
        b.iter(|| {
            let result = apply_extract(
                black_box(&flat_data),
                &ExtractExpr::Cel("data.metadata.count".to_string()),
            );
            black_box(result.unwrap());
        });
    });

    group.bench_function("cel_list_filter", |b| {
        b.iter(|| {
            let result = apply_extract(
                black_box(&flat_data),
                &ExtractExpr::Cel("data.items.filter(x, x.active)".to_string()),
            );
            black_box(result.unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: template expansion throughput
// ---------------------------------------------------------------------------

fn bench_template_expansion(c: &mut Criterion) {
    let mut group = c.benchmark_group("template_expansion");

    // Vary number of vars
    for n_vars in [1, 5, 10, 20] {
        let pipeline = make_pipeline_with_vars(n_vars, 10);
        let resolved = make_resolved_data(n_vars, 10);

        group.bench_with_input(
            BenchmarkId::new("vars", n_vars),
            &(&pipeline, &resolved),
            |b, (pipeline, resolved)| {
                b.iter(|| {
                    let expanded =
                        TemplateExpander::expand(black_box(pipeline), black_box(resolved));
                    black_box(expanded);
                });
            },
        );
    }

    // Vary values per source (array size)
    for n_values in [10, 100, 1000] {
        let pipeline = make_pipeline_with_vars(5, n_values);
        let resolved = make_resolved_data(5, n_values);

        group.bench_with_input(
            BenchmarkId::new("values_per_source", n_values),
            &(&pipeline, &resolved),
            |b, (pipeline, resolved)| {
                b.iter(|| {
                    let expanded =
                        TemplateExpander::expand(black_box(pipeline), black_box(resolved));
                    black_box(expanded);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: source resolution with extract (full pipeline)
// ---------------------------------------------------------------------------

fn bench_resolve_with_extract(c: &mut Criterion) {
    let mut group = c.benchmark_group("source_resolve_with_extract");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let resolver = DefaultSourceResolver::new();

    let data = serde_json::json!({
        "indicators": (0..500).map(|i| serde_json::json!({
            "value": format!("ioc_{i}.malware.com"),
            "type": "domain",
            "active": i % 3 != 0
        })).collect::<Vec<_>>()
    });
    let content = serde_json::to_string(&data).unwrap();
    let file = make_source_file(&content);
    let path = file.path().to_str().unwrap().to_string();

    // File resolve + JQ extract
    let source_jq = make_file_source_with_extract(
        &path,
        ExtractExpr::Jq(".indicators[] | select(.active) | .value".to_string()),
    );
    group.bench_function("file_jq_filter_500", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = resolver.resolve(black_box(&source_jq)).await;
                black_box(result.unwrap());
            });
        });
    });

    // File resolve + JSONPath extract
    let source_jsonpath = make_file_source_with_extract(
        &path,
        ExtractExpr::JsonPath("$.indicators[?@.active==true].value".to_string()),
    );
    group.bench_function("file_jsonpath_filter_500", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = resolver.resolve(black_box(&source_jsonpath)).await;
                black_box(result.unwrap());
            });
        });
    });

    // File resolve + CEL extract
    let source_cel = make_file_source_with_extract(
        &path,
        ExtractExpr::Cel("data.indicators.filter(x, x.active).map(x, x.value)".to_string()),
    );
    group.bench_function("file_cel_filter_500", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = resolver.resolve(black_box(&source_cel)).await;
                black_box(result.unwrap());
            });
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: end-to-end dynamic pipeline detection
// ---------------------------------------------------------------------------

fn bench_dynamic_detection_e2e(c: &mut Criterion) {
    let mut group = c.benchmark_group("dynamic_detection_e2e");
    group.sample_size(20);

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Set up source file with IOC list
    let iocs: Vec<String> = (0..50).map(|i| format!("malware_{i}.exe")).collect();
    let source_content = serde_json::to_string(&iocs).unwrap();
    let source_file = make_source_file(&source_content);

    // Pipeline YAML with dynamic source + value_placeholders
    let pipeline_yaml = format!(
        r#"
name: bench-dynamic
priority: 10
vars:
  malicious_commands:
    - "${{source.iocs}}"
sources:
  - id: iocs
    type: file
    path: {}
    format: json
    refresh: once
    on_error: fail
transformations:
  - type: value_placeholders
"#,
        source_file.path().to_str().unwrap()
    );

    // Rule using the placeholder
    let rule_yaml = r#"
title: Bench Dynamic Rule
id: bench-dynamic-001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: "%malicious_commands%"
    condition: selection
level: high
"#;

    let dir = tempfile::tempdir().unwrap();
    let rule_path = dir.path().join("rule.yml");
    std::fs::write(&rule_path, rule_yaml).unwrap();
    let pipeline_path = dir.path().join("pipeline.yml");
    std::fs::write(&pipeline_path, &pipeline_yaml).unwrap();

    // Build engine with dynamic pipeline resolution
    let pipeline = rsigma_eval::pipeline::parse_pipeline(&pipeline_yaml).unwrap();
    let resolver: Arc<dyn SourceResolver> = Arc::new(DefaultSourceResolver::new());

    let mut engine = RuntimeEngine::new(
        rule_path.clone(),
        vec![pipeline],
        CorrelationConfig::default(),
        false,
    );
    engine.set_source_resolver(resolver);
    engine.set_pipeline_paths(vec![pipeline_path]);
    rt.block_on(engine.resolve_dynamic_pipelines()).unwrap();
    // `load_rules` re-resolves dynamic sources fail-closed and needs a tokio
    // runtime context to do so (multi-threaded, for `block_in_place`).
    rt.block_on(async { engine.load_rules() }).unwrap();

    let processor = LogProcessor::new(engine, Arc::new(NoopMetrics));

    // Generate events (mix of matching and non-matching)
    let events: Vec<String> = (0..1000)
        .map(|i| {
            if i % 10 == 0 {
                format!(
                    r#"{{"CommandLine":"malware_{}.exe --payload","Image":"cmd.exe"}}"#,
                    i % 50
                )
            } else {
                format!(r#"{{"CommandLine":"notepad.exe doc_{i}.txt","Image":"explorer.exe"}}"#)
            }
        })
        .collect();

    group.throughput(criterion::Throughput::Elements(1000));

    group.bench_function("detect_1000_events_50_iocs", |b| {
        b.iter(|| {
            let results = processor.process_batch_with_format(
                black_box(&events),
                &rsigma_runtime::InputFormat::Json,
                None,
            );
            black_box(results);
        });
    });

    // Also benchmark the reload path (resolve + rebuild)
    group.bench_function("reload_with_resolve", |b| {
        b.iter(|| {
            let result = rt.block_on(async { processor.reload_rules() });
            black_box(result.unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_source_resolution_file,
    bench_parse_data,
    bench_extract_expressions,
    bench_template_expansion,
    bench_resolve_with_extract,
    bench_dynamic_detection_e2e,
);
criterion_main!(benches);
