# Fuzzing

The workspace ships 28 [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html) harnesses under `fuzz/fuzz_targets/`. The `Fuzz` GitHub Actions workflow runs 22 of them weekly (Monday 03:00 UTC) on `libFuzzer`; specialized differential and subsystem targets remain manual.

## Harness inventory

| Target | Covers | Max input len in CI |
| -------- | -------- | --------------------- |
| `fuzz_parse_yaml` | The Sigma YAML parser (`parse_sigma_yaml`). | 8192 |
| `fuzz_condition` | Condition-expression parser only. | 512 |
| `fuzz_eval_matching` | Engine evaluation. Feeds parsed rules and constructed JSON events. | 65536 |
| `fuzz_eval_matcher_diff` | Differential test for the matcher optimizer (`optimize_any_of`): runs the Aho-Corasick fast path against the naive scalar fallback on the same needles and haystacks. Not in the weekly matrix; run manually. | (default) |
| `fuzz_field_modifiers` | The 30+ Sigma modifiers. | 256 |
| `fuzz_regex_compile` | The hardened regex compilation path (size and complexity caps). | 1024 |
| `fuzz_pipeline_yaml` | Pipeline YAML parser. | 4096 |
| `fuzz_pipeline_sources_yaml` | Dynamic-pipeline source spec parser. | 8192 |
| `fuzz_alert_pipeline_config` | Alert-pipeline configuration parser. | 4096 |
| `fuzz_input_formats` | The line-format parser (auto-detect, JSON, syslog, logfmt, CEF, plain). | 4096 |
| `fuzz_rule_tune` | False-positive-driven rule tuning over JSON FP and TP corpora. | 65536 |
| `fuzz_draft_groups` | Correlation draft grouping over grouped timed events (`draft_correlation`). | 65536 |
| `fuzz_extract_jq` | jq extract language. | 4096 |
| `fuzz_extract_jsonpath` | JSONPath extract language. | 4096 |
| `fuzz_extract_cel` | CEL extract language. | 4096 |
| `fuzz_template_expand` | The `${source.X}` template expander. | 4096 |
| `fuzz_include_parse` | Include-directive resolution. | 8192 |
| `fuzz_http_response` | The dynamic-pipeline HTTP-response parsing path. | 65536 |
| `fuzz_lint_fix` | Linter auto-fix application and reparsing. Not in the weekly matrix; run manually. | (default) |
| `fuzz_scorecard_promtext` | Detection scorecard Prometheus text parser. Not in the weekly matrix; run manually. | (default) |
| `fuzz_disposition_record` | Disposition record parsing. Not in the weekly matrix; run manually. | (default) |
| `fuzz_capture_spool` | Disposition capture spool documents (`parse_manifest`, `parse_provenance`, `parse_corpus_events`). | 65536 |
| `fuzz_otlp_logs_decode` | OTLP log ingestion: protobuf decoding of `ExportLogsServiceRequest` (the body of `POST /v1/logs` and the gRPC `LogsService` message) and `logs_request_to_raw_events`, asserting every converted record is valid JSON. Seeds in `fuzz/seeds/fuzz_otlp_logs_decode/` cover every `AnyValue` variant, many attributes, and nesting on both sides of prost's recursion limit. {{ added "0.25.0" }} | 65536 |
| `fuzz_risk_config` | Risk configuration parsing. Not in the weekly matrix; run manually. | (default) |
| `fuzz_lucene_frontend` | Lucene reverse-conversion frontend. Not in the weekly matrix; run manually. | (default) |
| `fuzz_stix_pattern` | STIX pattern parsing. | 4096 |
| `fuzz_rstix_parse_bundle` | The `rstix::parse_bundle` STIX bundle parse entrypoint. Seed locally from `tests/fixtures/spec/` or a downloaded ATT&CK bundle (see [rstix: Local MITRE ATT&CK corpus test](../library/rstix.md#rstix-testing-local-mitre-attck-corpus)). | 65536 |
| `fuzz_rstix_validate_json` | The `rstix::Validator::validate_json_str` Validation Pipeline raw JSON entry (`validate` feature). Seeds in `fuzz/seeds/fuzz_rstix_validate_json/`. | 65536 |

All targets live under [`fuzz/fuzz_targets/`](https://github.com/timescale/rsigma/tree/main/fuzz/fuzz_targets). The shared `Cargo.toml` is `fuzz/Cargo.toml`; it depends on `rsigma-parser`, `rsigma-eval`, `rsigma-convert`, `rsigma-runtime` (with `logfmt`, `cef`, and `otlp` features), `prost`, and `rstix` (with `serde`, `pattern`, and `validate` features).

## Run one target locally

Prefer the pinned nightly from CI (`FUZZ_TOOLCHAIN` in `.github/workflows/fuzz.yml`, currently `nightly-2026-07-23`). Floating `nightly` can fail under ASan:

```bash
rustup toolchain install nightly-2026-07-23 --profile minimal --component llvm-tools-preview
cargo +nightly-2026-07-23 install cargo-fuzz --locked
```

Then from the workspace root:

```bash
cargo +nightly-2026-07-23 fuzz run fuzz_parse_yaml -- -max_len=8192 -max_total_time=60
```

`-max_total_time=60` runs for one minute; drop it for an open-ended loop. Run output prints `cov:` increments as new branches are discovered; a crash dumps the offending corpus entry under `fuzz/artifacts/<target>/crash-<hash>`.

## Reproducing a crash

```bash
cargo +nightly-2026-07-23 fuzz run fuzz_parse_yaml fuzz/artifacts/fuzz_parse_yaml/crash-deadbeef...
```

You can also point a regular test at the offending bytes. Reducing the input via `cargo fuzz tmin <target> <crash-path>` before filing an issue is appreciated.

## Adding a new harness

1. Create `fuzz/fuzz_targets/fuzz_<name>.rs`:

   ```rust
   #![no_main]
   use libfuzzer_sys::fuzz_target;

   fuzz_target!(|data: &[u8]| {
       let Ok(s) = std::str::from_utf8(data) else { return; };
       let _ = rsigma_parser::parse_sigma_yaml(s);
   });
   ```

2. Register it in `fuzz/Cargo.toml`:

   ```toml
   [[bin]]
   name = "fuzz_<name>"
   path = "fuzz_targets/fuzz_<name>.rs"
   doc = false
   ```

3. Add an entry to the matrix in `.github/workflows/fuzz.yml`:

   ```yaml
   - target: fuzz_<name>
     max_len: 4096
   ```

4. Open a PR. The first weekly run will exercise the new harness for the default duration (180 seconds per target; tune via `workflow_dispatch` input).

## When to fuzz

Add a harness when you accept untrusted input and the parsing or matching code is non-trivial:

- A new input format (CEF, EVTX, …) -> add to `fuzz_input_formats` or a sibling.
- A new extract language -> mirror the `fuzz_extract_*` targets.
- A new dynamic-source data format -> extend `fuzz_pipeline_sources_yaml` or `fuzz_http_response`.
- A new condition operator -> extend `fuzz_condition`.

Differential fuzz harnesses (`fuzz_eval_matcher_diff`) are the canonical guard against matcher-optimizer regressions; when you touch `optimize_any_of` or the Aho-Corasick fast path, run the diff harness before opening a PR.

## Corpus

Seed corpora are committed under `fuzz/seeds/<target>/`. CI restores and saves `fuzz/corpus/<target>` between runs (cache key `fuzz-corpus-<target>-…`). On failure, crashes upload as a workflow artifact named `fuzz-crashes-<target>` (not the corpus). Download a crash artifact to reproduce locally with `cargo fuzz run <target> path/to/crash`.

## See also

- [Testing](testing.md) for the conventional test tiers.
- [Security Hardening](../reference/security.md) for the input-size and depth caps that the fuzz harnesses verify cannot be exceeded.
- The cargo-fuzz book: <https://rust-fuzz.github.io/book/cargo-fuzz.html>.
