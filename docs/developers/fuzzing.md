# Fuzzing

The workspace ships 17 [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html) harnesses under `fuzz/fuzz_targets/`. The `Fuzz` GitHub Actions workflow runs 16 of them weekly (Monday 03:00 UTC) on `libFuzzer`; `fuzz_eval_matcher_diff` remains a manual differential target.

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
| `fuzz_input_formats` | The line-format parser (auto-detect, JSON, syslog, logfmt, CEF, plain). | 4096 |
| `fuzz_extract_jq` | jq extract language. | 4096 |
| `fuzz_extract_jsonpath` | JSONPath extract language. | 4096 |
| `fuzz_extract_cel` | CEL extract language. | 4096 |
| `fuzz_template_expand` | The `${source.X}` template expander. | 4096 |
| `fuzz_include_parse` | Include-directive resolution. | 8192 |
| `fuzz_http_response` | The dynamic-pipeline HTTP-response parsing path. | 65536 |
| `fuzz_rstix_parse_bundle` | The `rstix::parse_bundle` STIX bundle parse entrypoint. Seed locally from `tests/fixtures/spec/` or a downloaded ATT&CK bundle (see [rstix — Local MITRE ATT&CK corpus test](../library/rstix.md#local-mitre-attck-corpus-not-in-git)). | 65536 |
| `fuzz_rstix_validate_json` | The `rstix::Validator::validate_json_str` Validation Pipeline raw JSON entry (`validate` feature). Seeds in `fuzz/seeds/fuzz_rstix_validate_json/`. | 65536 |

All targets live under [`fuzz/fuzz_targets/`](https://github.com/timescale/rsigma/tree/main/fuzz/fuzz_targets). The shared `Cargo.toml` is `fuzz/Cargo.toml`; it depends on `rsigma-parser`, `rsigma-eval`, and `rsigma-runtime` (with `logfmt` and `cef` features).

## Run one target locally

You need a nightly toolchain (libFuzzer is unstable):

```bash
rustup install nightly
cargo install cargo-fuzz
```

Then from the workspace root:

```bash
cargo +nightly fuzz run fuzz_parse_yaml -- -max_len=8192 -max_total_time=60
```

`-max_total_time=60` runs for one minute; drop it for an open-ended loop. Run output prints `cov:` increments as new branches are discovered; a crash dumps the offending corpus entry under `fuzz/artifacts/<target>/crash-<hash>`.

## Reproducing a crash

```bash
cargo +nightly fuzz run fuzz_parse_yaml fuzz/artifacts/fuzz_parse_yaml/crash-deadbeef...
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
   test = false
   doc = false
   bench = false
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

Seed corpora are not committed (they're large and quickly stale). The CI artifact for each weekly run is uploaded as a workflow artifact named `corpus-<target>`; download it to bootstrap a local run with `cargo fuzz run <target> path/to/corpus`.

## See also

- [Testing](testing.md) for the conventional test tiers.
- [Security Hardening](../reference/security.md) for the input-size and depth caps that the fuzz harnesses verify cannot be exceeded.
- The cargo-fuzz book: <https://rust-fuzz.github.io/book/cargo-fuzz.html>.
