# Library API

Every crate in the workspace publishes to crates.io and can be embedded in another Rust program. This section is the entry point for embedders, alternative-frontend authors, and contributors who need to understand the public Rust surface area.

For the canonical, line-by-line API reference, follow [docs.rs/rsigma](https://docs.rs/rsigma). The pages here are operator-facing overviews and pick a few representative examples per crate.

## Crate matrix

| Crate | Depends on | Use it when you want to... |
|-------|------------|----------------------------|
| [`rsigma-parser`](parser.md) | (nothing else from rsigma) | Parse a Sigma YAML file into a typed AST. |
| [`rsigma-ir`](ir.md) | `rsigma-parser` | Lower the AST into a modifier-resolved, selector-free HIR shared by eval and convert. |
| [`rsigma-eval`](eval.md) | `rsigma-parser`, `rsigma-ir` | Compile that AST (via HIR) and evaluate events against it; run correlations; apply pipelines. |
| [`rsigma-convert`](convert.md) | `rsigma-parser` | Emit backend-native query strings (PostgreSQL, LynxDB, or a custom backend you implement). |
| [`rsigma-runtime`](runtime.md) | `rsigma-parser`, `rsigma-eval` | Wrap the engine in a streaming runtime: input adapters, sinks, hot-reload, dynamic source resolution. |
| `rsigma-lsp` | `rsigma-parser`, `rsigma-eval` | Run the Sigma language server in your own editor integration. |
| [`rstix`](rstix.md) | (standalone STIX 2.1 library) | Parse STIX 2.1 bundles, run T1 advisory validation and optional T2 Validation Pipeline, evaluate STIX patterns (§9 Levels 1–3), build property graphs, resolve markings, store objects, register custom types, and stream large corpora (for example MITRE ATT&CK). |

`rsigma-cli` (the binary) ties everything together but is not a library and is not published to crates.io.

## Pick the right entry point

| You want to... | Reach for |
|----------------|-----------|
| Parse and validate a STIX 2.1 bundle (including ATT&CK-scale JSON) | `rstix` — `Bundle::parse` / `parse_reader`, then advisory `Bundle::validate` (see the [crate source](https://github.com/timescale/rsigma/tree/main/crates/rstix)). For untrusted ingest with named profiles and structured diagnostics, enable `validate` and use `Validator::validate_json_str` (see [Validation Pipeline](rstix.md#rstix-validation-pipeline)). |
| Lint or parse rules in a CI step | `rsigma-parser` only. |
| Run a one-shot evaluation against an in-memory event | `rsigma-parser` + `rsigma-eval`. |
| Generate SQL or SPL queries from rules | `rsigma-parser` + `rsigma-convert`. |
| Build a streaming detection pipeline (NATS in, NATS out, hot-reload, metrics) | `rsigma-parser` + `rsigma-eval` + `rsigma-runtime`. |
| Embed Sigma diagnostics into an editor | `rsigma-lsp` (consumes parser + eval internally). |

## Minimum working example

The smallest "match one event" program needs three crates:

```toml
# Cargo.toml
[dependencies]
rsigma-parser = "{{ rsigma.version }}"
rsigma-eval = "{{ rsigma.version }}"
serde_json = "1"
```

```rust
use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let yaml = r#"
title: Whoami
id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;

    let collection = parse_sigma_yaml(yaml)?;

    let mut engine = Engine::new();
    engine.add_collection(&collection)?;

    let event_json = json!({ "CommandLine": "cmd /c whoami" });
    let event = JsonEvent::borrow(&event_json);

    for m in engine.evaluate(&event) {
        println!("matched: {}", m.rule_title);
    }
    Ok(())
}
```

Output:

```text
matched: Whoami
```

Add `rsigma-convert` to emit SQL, or `rsigma-runtime` to wrap this in a daemon-like streaming pipeline. The per-crate pages walk through each layer.

## Versioning

The workspace ships every crate under a single shared version number. A v0.x release bumps every crate; you cannot mix `rsigma-parser` v0.10 with `rsigma-eval` v0.11. Pin all rsigma deps to the same version in your `Cargo.toml`. The [release-notes](../release-notes.md) (a mirror of `CHANGELOG.md`) document every public-API change.

Until v1.0 ships, minor versions can break public APIs. Lock dependencies in `Cargo.lock` and read the CHANGELOG before bumping.

## Feature flags

Every crate exposes a few opt-in features. The most useful for embedders:

- `rsigma-eval` -> `parallel`, `daachorse-index`.
- `rsigma-runtime` -> `nats`, `otlp`, `logfmt`, `cef`, `evtx`, `daachorse-index`.
- `rsigma-cli` -> `daemon`, `daemon-nats`, `daemon-otlp`, plus the leaf-crate features above.

Full inventory: [Feature flags reference](../reference/feature-flags.md).

## See also

- [WASM ABI](../reference/wasm-abi.md) for the stable `wasm32-unknown-unknown` host/guest contract and current build-compatibility guarantee.
- [Architecture](../reference/architecture.md) for how the crates fit together at runtime.
- [Benchmarks](../benchmarks.md) for the per-crate Criterion results.
- [Per-crate READMEs](https://github.com/timescale/rsigma/tree/main/crates) for the source-tracked, contributor-facing reference.
- [docs.rs/rsigma](https://docs.rs/rsigma) for the generated API documentation.
