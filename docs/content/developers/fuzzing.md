---
description: "How RSigma is fuzzed: the cargo-fuzz harness inventory, the weekly libFuzzer workflow, seed corpora, and how to run and add fuzz targets locally."
---

# Fuzzing

The workspace ships 51 [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html) harnesses under `fuzz/fuzz_targets/`. The `Fuzz` GitHub Actions workflow runs 45 of them weekly (Monday 03:00 UTC) on `libFuzzer`; specialized differential and subsystem targets remain manual. One job compiles every harness, and a job per scheduled target runs its binary from that build.

## Harness inventory

| Target | Covers | Max input len in CI |
| -------- | -------- | --------------------- |
| `fuzz_parse_yaml` | The Sigma YAML parser (`parse_sigma_yaml`). | 8192 |
| `fuzz_rule_fmt` | The Sigma formatter (`format_yaml`, `format_yaml_range`): idempotency, value equality, and comment and anchor preservation. | 8192 |
| `fuzz_condition` | Condition-expression parser only. Seeds in `fuzz/seeds/fuzz_condition/` include `not` runs and parentheses at and past the 64-level depth limit. {{ added "unreleased" }} | 512 |
| `fuzz_eval_matching` | Engine evaluation. Feeds parsed rules and constructed JSON events. | 65536 |
| `fuzz_eval_matcher_diff` | Differential test for the matcher optimizer (`optimize_any_of`): runs the Aho-Corasick fast path against the naive scalar fallback on the same needles and haystacks. Not in the weekly matrix; run manually. | (default) |
| `fuzz_field_modifiers` | The 30+ Sigma modifiers. | 256 |
| `fuzz_regex_compile` | The hardened regex compilation path (size and complexity caps). | 1024 |
| `fuzz_pipeline_yaml` | Pipeline YAML parser. | 4096 |
| `fuzz_apply_modifiers` | Differential test for `apply_modifiers: first`: a rule with arbitrary modifiers and values must match the same events whether a pipeline applies its modifiers first or leaves them for compilation. {{ added "unreleased" }} | 1024 |
| `fuzz_pipeline_sources_yaml` | Dynamic source spec parser. | 8192 |
| `fuzz_watchlist_request` | Watchlist push, replace, and delete bodies. The first byte selects the operation. The rest is JSON. {{ added "0.28.0" }} | 4096 |
| `fuzz_alert_pipeline_config` | Alert-pipeline configuration parser. | 4096 |
| `fuzz_silence_request` | `POST /api/v1/silences` bodies through the API silence builder: size limits before any compile, the bounded regex compile, and the regex memory budget of the silence store. Seeds in `fuzz/corpus/fuzz_silence_request/` include too many matchers, an over-long value, a regex over the size limit, and a value that would escape the full-match anchors. {{ added "unreleased" }} | 65536 |
| `fuzz_alert_pipeline_snapshot` | Alert-pipeline snapshot restore (`AlertPipelineSnapshot::from_json`): unreadable entries are skipped one by one, and whatever restores must save to a snapshot that reads back with no entry skipped. Seeds in `fuzz/corpus/fuzz_alert_pipeline_snapshot/` include mixed good and bad entries, a future version, and an entry nested past the read limit. {{ added "unreleased" }} | 65536 |
| `fuzz_enrichers_config` | Enrichers configuration parsing and validation through `parse_enrichers_config`: YAML deserialization, per-type key checks, template namespaces, scope, and extract compilation. Building enrichers does I/O and is not fuzzed. Seeds in `fuzz/corpus/fuzz_enrichers_config/` cover each built-in type and adversarial keys. {{ added "0.28.0" }} | 65536 |
| `fuzz_enricher_extract` | Event values in `lookup` extract programs. The first byte selects either a fixed jq, JSONPath, or CEL lookup program, which must return exactly the record the event value names (never an error, a decoy, or a secret record), or an arbitrary extract template, which may fail but must not panic or run past its limits. The rest is `<program>\0<value>`. {{ added "unreleased" }} | 4096 |
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
| `fuzz_otlp_logs_decode` | OTLP log ingestion: protobuf decoding of `ExportLogsServiceRequest` (the body of `POST /v1/logs` and the gRPC `LogsService` message) and `logs_request_to_raw_events`, asserting every converted record is valid JSON. Seeds in `fuzz/seeds/fuzz_otlp_logs_decode/` cover every `AnyValue` variant, many attributes, and nesting on both sides of prost's recursion limit. {{ added "0.25.0" }} The harness also checks that `count_log_records` matches the decoded record count and that `LogRecordConverter` stays within its event and request limits and accounts for every record; seeds add a large resource over many records, thousands of empty records, an oversized record, and unknown fields and groups. {{ added "unreleased" }} | 65536 |
| `fuzz_otlp_logs_json` | OTLP/JSON request bodies: `count_log_records_json` must never count fewer records than serde decoding produces, and conversion of what decodes stays within its limits. Seeds cover escaped and duplicate keys, odd shapes, and deep nesting. {{ added "unreleased" }} | 65536 |
| `fuzz_line_framer` | The `LineFramer` that cuts stdin, `unix://`, and `POST /api/v1/events` input into lines: the lines must not depend on how the stream is split into reads, every newline must yield one line, and no valid line may pass the cap. The first byte seeds the read boundaries. {{ added "unreleased" }} | 4096 |
| `fuzz_host_guard` | `Host` and `Origin` validation shared by the daemon API and the MCP HTTP transport: checks never panic, are deterministic, answer only 400 or 403, and a guard built from a host accepts that host. The input is newline-separated allowed hosts, `Host`, `Origin`, and HTTP/2 authority. {{ added "unreleased" }} | 1024 |
| `fuzz_postgres_select_fields` | PostgreSQL `fields` entries, one per input line, converted in every output format over flat columns and a JSONB column. A query that converts must keep rule content inside quoted identifiers and string literals: outside them its quotes and parentheses balance and it has no `;`, `--`, or `/*`. Seeds in `fuzz/seeds/fuzz_postgres_select_fields/` cover SigmaHQ field lists, aliases, aggregates, reserved words, JSONB paths, and comments, quotes, sub-selects, nested and unknown calls, and unbalanced parentheses. {{ added "unreleased" }} | 1024 |
| `fuzz_field_keys` | Bounded field-key walks over JSON events (`Event::visit_field_keys`): a walk must stay within its key, length, and byte budget, and `has_any_field` must agree with an unbounded walk. {{ added "unreleased" }} | 16384 |
| `fuzz_risk_config` | Risk configuration parsing. Not in the weekly matrix; run manually. | (default) |
| `fuzz_lucene_frontend` | Lucene reverse-conversion frontend. Not in the weekly matrix; run manually. Seeds in `fuzz/seeds/fuzz_lucene_frontend/` cover plain queries, value groups, and nesting past the depth limit. {{ added "unreleased" }} | (default) |
| `fuzz_stix_pattern` | STIX pattern parsing. Seeds in `fuzz/seeds/fuzz_stix_pattern/` include nested parentheses and `IN` lists, qualifier chains, and observation and comparison chains past their limits. {{ added "unreleased" }} | 4096 |
| `fuzz_taxii_envelope` | TAXII envelope parsing, including object-count, nesting, and string-length limits. Seeds in `fuzz/seeds/fuzz_taxii_envelope/` cover a valid envelope, a truncated envelope, and an oversized envelope. {{ added "0.28.0" }} A seed carries an `email-message` with RFC 2047 encoded-words. {{ added "unreleased" }} | 65536 |
| `fuzz_taxii_headers` | TAXII response header values: `Retry-After`, the HTTP `Date` clock skew, and `X-TAXII-Date-Added-*` timestamps shifted by arbitrary deltas. A shifted timestamp must stay in the RFC 3339 range and equal the value its wire form parses to. The first byte selects the header and the next eight bytes are the delta. Seeds in `fuzz/corpus/fuzz_taxii_headers/` cover huge and overflowing delays, far-future and past dates, and cursors at both ends of the range. {{ added "unreleased" }} | 1024 |
| `fuzz_taxii_dns_records` | SRV and TLSA record selection for TAXII discovery and DANE over arbitrary DNS messages, with a DNSSEC proof state per answer, then TLSA matching against arbitrary certificate bytes. With DNSSEC required, every SRV target kept must be proven Secure, and every target must form a URL. Seeds in `fuzz/corpus/fuzz_taxii_dns_records/` cover SRV sets, `.` and port-0 targets, a target with a slash in its label, TLSA usages 0 to 3 and an unknown one, and a truncated message. {{ added "unreleased" }} | 4096 |
| `fuzz_rstix_email_roundtrip` | `email-message` RFC 2047 decoding and the save and reload round trip: whatever the wire parse accepts must serialize and deserialize to the same object, still validate, and reload unchanged with decoding off, as `FsStore` reads it. The first byte selects a header-only message, one with `subject_enc`, or raw object JSON. Seeds in `fuzz/corpus/fuzz_rstix_email_roundtrip/` cover Latin-1, UTF-8, and ISO-2022-JP words, adjacent words, nested words that decode to another encoded-word or to nothing, and malformed words. {{ added "unreleased" }} | 8192 |
| `fuzz_stix_source` | `format: stix` bundle build at a fixed clock. A successful build must be an object with every observable key as an array and an `indicators` object. Seeds in `fuzz/seeds/fuzz_stix_source/` cover the source fixtures, a truncated bundle, duplicate ids, a 300-indicator bundle, and each unsupported pattern shape. {{ added "0.28.0" }} | 262144 |
| `fuzz_stix_draft` | Rule drafting from a STIX bundle. Bytes are parsed as a bundle or one indicator, simple observables are read out, and `draft_rule_from_values` emits YAML that must parse. Seeds in `fuzz/seeds/fuzz_stix_draft/` cover an indicator, a title and a URL that contain YAML metacharacters, and a truncated object. {{ added "0.28.0" }} | 65536 |
| `fuzz_rstix_parse_bundle` | The `rstix::parse_bundle` STIX bundle parse entrypoint. Seed locally from `tests/fixtures/spec/` or a downloaded ATT&CK bundle (see [rstix: Local MITRE ATT&CK corpus test](../library/rstix.md#rstix-testing-local-mitre-attck-corpus)). A committed seed in `fuzz/seeds/fuzz_rstix_parse_bundle/` carries an `email-message` with RFC 2047 encoded-words. {{ added "unreleased" }} | 65536 |
| `fuzz_rstix_validate_json` | The `rstix::Validator::validate_json_str` Validation Pipeline raw JSON entry (`validate` feature). Seeds in `fuzz/seeds/fuzz_rstix_validate_json/`. | 65536 |
| `fuzz_mmdb_record` | MMDB decoding and field projection (`mmdb-enrich` feature): `MmdbDatabase::from_bytes` over arbitrary bytes, then lookups for a fixed set of IPv4 and IPv6 addresses with no projection and with a projection that includes an array index. Seeds in `fuzz/corpus/fuzz_mmdb_record/` cover the synthetic fixtures, a truncated file, a metadata-marker-only file, and a file with corrupted search-tree bytes. {{ added "0.28.0" }} | 65536 |
| `fuzz_dns_answer` | DNS answer formatting and query-name normalization (`dns-enrich` feature): the first input byte selects a record type, the rest goes to `DnsRecordType::format_answers` as a wire-format response, and valid UTF-8 input also goes to `query_name` for that type and for `PTR`. Seeds in `fuzz/corpus/fuzz_dns_answer/` cover one response per stub-zone case, a truncated response, a compression-pointer loop, a response with 300 answers, and key inputs with long labels, IDNA text, and IPv6 literals. {{ added "0.28.0" }} | 4096 |
| `fuzz_ruleset_resolve` | Named ruleset resolution: the first input byte selects a spec, overlay list, or selector; `validate_spec` and `resolve_loaded` then run against embedded fixture rules with the inline-only overlay loader. Seeds in `fuzz/seeds/fuzz_ruleset_resolve/` cover each mode, an invalid glob, deeply nested custom attributes, a 240-element tag list, a null patch, and unknown keys at every level. {{ added "0.28.0" }} | 4096 |
| `fuzz_ocsf_sidecar` | Dedup sidecar OCSF serialization, risk-event mapping, and webhook JSON bodies. Arbitrary JSON goes to `dedup_summary_finding_opts` and, when it is a risk event, to `risk_event_finding_opts`, for schema `1.1.0` or `1.3.0`. The same bytes are rendered with `render_webhook_body`, so `${detection.ocsf}` and `${correlation.ocsf}` are validated, including a reference inside a string. Seeds in `fuzz/corpus/fuzz_ocsf_sidecar/` cover those shapes. The `${source.X}` expander does not see webhook placeholders, so the seeds live on this target. {{ added "0.28.0" }} | 8192 |
| `fuzz_correlation_absence` | Absence correlation state: hits, clock advances, finalize, and snapshot round trips. The input selects an embedded rule collection or supplies its own, then drives `process_event_at_for_tenant`, `advance_clock`, `finalize`, and `export_state`/`import_state`. Invariants: no panic, the pending-group counter matches introspection, finalize clears every pending obligation, and a snapshot round trip exports identical JSON. Seeds in `fuzz/seeds/fuzz_correlation_absence/` cover ordered login without MFA, a B before A under `temporal`, tumbling, deadman, negated and positive disjunctions, a chained parent, and snapshot round trips. {{ added "unreleased" }} | 8192 |

All targets live under [`fuzz/fuzz_targets/`](https://github.com/timescale/rsigma/tree/main/fuzz/fuzz_targets). The shared `Cargo.toml` is `fuzz/Cargo.toml`; it depends on `rsigma-parser`, `rsigma-eval`, `rsigma-convert`, `rsigma-runtime` (with `logfmt`, `cef`, `otlp`, `mmdb-enrich`, `dns-enrich`, and `stix-source` features), `prost`, and `rstix` (with `serde`, `pattern`, `validate`, and `taxii` features).

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

- A new input format (CEF, EVTX, …): add to `fuzz_input_formats` or a sibling.
- A new extract language: mirror the `fuzz_extract_*` targets.
- A new dynamic-source data format: extend `fuzz_pipeline_sources_yaml` or `fuzz_http_response`.
- A new binary lookup format: mirror `fuzz_mmdb_record`.
- A new condition operator: extend `fuzz_condition`.
- A new stateful correlation shape: extend `fuzz_correlation_absence`.

Differential fuzz harnesses (`fuzz_eval_matcher_diff`) are the canonical guard against matcher-optimizer regressions; when you touch `optimize_any_of` or the Aho-Corasick fast path, run the diff harness before opening a PR.

## Corpus

Seed corpora are committed under `fuzz/seeds/<target>/`. Each run uploads `fuzz/corpus/<target>` as a workflow artifact named `fuzz-corpus-<target>`, kept for 90 days, and the next run starts from the newest one that a run on `main` uploaded. The corpus is not in the Actions cache, which evicts an entry used once a week before the next run. On failure, crashes upload as a workflow artifact named `fuzz-crashes-<target>`. Download a crash artifact to reproduce locally with `cargo fuzz run <target> path/to/crash`.

## See also

- [Testing](testing.md) for the conventional test tiers.
- [Security Hardening](../reference/security.md) for the input-size and depth caps that the fuzz harnesses verify cannot be exceeded.
- The cargo-fuzz book: <https://rust-fuzz.github.io/book/cargo-fuzz.html>.
