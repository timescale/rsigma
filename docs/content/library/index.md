---
description: "Embed RSigma in your Rust programs: an overview of the published crates for Sigma parsing, intermediate representation, evaluation, conversion, and runtime."
---

# Library API

Every crate in the workspace publishes to crates.io and can be embedded in another Rust program. This section is the entry point for embedders, alternative-frontend authors, and contributors who need to understand the public Rust surface area.

For the canonical, line-by-line API reference, follow [docs.rs/rsigma](https://docs.rs/rsigma) and the per-crate docs.rs pages linked below. The pages here are operator-facing overviews and pick a few representative examples per crate.

## Crate matrix

| Crate | Depends on | Use it when you want to... |
|-------|------------|----------------------------|
| [`rsigma-parser`](parser.md) | (nothing else from RSigma) | Parse a Sigma YAML file into a typed AST; lint and auto-fix. |
| [`rsigma-ir`](ir.md) | `rsigma-parser` | Lower the AST into a modifier-resolved, selector-free HIR shared by eval and convert. |
| [`rsigma-eval`](eval.md) | `rsigma-parser`, `rsigma-ir` | Compile that AST (via HIR) and evaluate events against it; run correlations; apply pipelines; draft and tune rules. |
| [`rsigma-convert`](convert.md) | `rsigma-parser`, `rsigma-ir`, `rsigma-eval` | Emit backend-native query strings (PostgreSQL, LynxDB, Fibratus, or a custom `Backend`). |
| [`rsigma-runtime`](runtime.md) | `rsigma-parser`, `rsigma-eval` | Wrap the engine in a streaming runtime: input adapters, sinks, hot-reload, dynamic source resolution, enrichment, alert/risk layers. |
| [`rsigma-mcp`](mcp.md) | parser, eval, convert, runtime | Embed the Model Context Protocol tool surface in your own agent host. |
| `rsigma-lsp` | `rsigma-parser`, `rsigma-eval` | Run the Sigma language server in your own editor integration (no dedicated library page; see the [VS Code](../editors/vscode.md) and [Neovim](../editors/neovim.md) guides). |
| [`rstix`](rstix.md) | (standalone STIX 2.1 library) | Parse STIX 2.1 bundles, run T1 advisory validation and optional T2 Validation Pipeline, evaluate STIX patterns, build property graphs, resolve markings, store objects, and talk to TAXII. |

`rsigma-cli` (the binary) ties everything together but is not a library and is not published to crates.io.

## Pick the right entry point

| You want to... | Reach for |
|----------------|-----------|
| Parse and validate a STIX 2.1 bundle (including ATT&CK-scale JSON) | [`rstix`](rstix.md): `Bundle::parse` or `parse_reader`, then advisory `Bundle::validate`. For untrusted ingest with named profiles, enable `validate` and use `Validator::validate_json_str`. |
| Lint or parse Sigma rules in a CI step | [`rsigma-parser`](parser.md) only. |
| Run a one-shot evaluation against an in-memory event | [`rsigma-parser`](parser.md) + [`rsigma-eval`](eval.md). |
| Generate SQL, SPL2, or Fibratus rules from Sigma | [`rsigma-parser`](parser.md) + [`rsigma-convert`](convert.md). |
| Build a streaming detection pipeline (NATS in, NATS out, hot-reload, metrics) | [`rsigma-parser`](parser.md) + [`rsigma-eval`](eval.md) + [`rsigma-runtime`](runtime.md). |
| Expose parse/lint/eval/convert tools to an MCP client | [`rsigma-mcp`](mcp.md) or [`rsigma mcp serve`](../cli/mcp/serve.md). |
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
        println!("matched: {}", m.header.rule_title);
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

The workspace ships every crate under a single shared version number (currently {{ rsigma.version }}). Pin all RSigma deps to the same version in your `Cargo.toml`. The [release notes](../release-notes.md) (a mirror of `CHANGELOG.md`) document every public-API change.

On the shared 0.x line, minor versions can break public APIs. Lock dependencies in `Cargo.lock` and read the CHANGELOG before bumping.

## Feature flags

Every crate exposes a few opt-in features. The most useful for embedders:

- `rsigma-parser` -> `fix` (default on; YAML source auto-fixes).
- `rsigma-eval` -> `parallel`, `daachorse-index`.
- `rsigma-runtime` -> `nats`, `otlp`, `logfmt`, `cef`, `evtx`, `uds`, `daachorse-index`.
- `rsigma-mcp` -> `http` (Streamable HTTP transport).
- `rstix` -> `serde` (default), `pattern`, `validate`, `graph`, `marking`, `store`, `store-fs`, `taxii`, `taxii-store`.
- `rsigma-cli` -> `daemon`, `daemon-nats`, `daemon-otlp`, `daemon-tls`, `mcp`, plus the leaf-crate features above.

Full inventory: [Feature flags reference](../reference/feature-flags.md).

## See also

- [WASM ABI](../reference/wasm-abi.md) for the stable `wasm32-unknown-unknown` host/guest contract and current build-compatibility guarantee.
- [Architecture](../reference/architecture.md) for how the crates fit together at runtime.
- [Benchmarks](../benchmarks.md) for the per-crate Criterion results.
- [Per-crate READMEs](https://github.com/timescale/rsigma/tree/main/crates) for the source-tracked, contributor-facing reference.
- [docs.rs/rsigma](https://docs.rs/rsigma) for the generated API documentation.
