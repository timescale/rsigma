# RSigma

A complete Rust toolkit for the [Sigma](https://github.com/SigmaHQ/sigma) detection standard — parser, evaluation engine, linter, CLI, and LSP. rsigma parses Sigma YAML rules into a strongly-typed AST, compiles them into optimized matchers, and evaluates them directly against JSON log events in real time. It runs detection and stateful correlation logic in-process with memory-efficient compressed event storage, supports pySigma-compatible processing pipelines for field mapping and backend configuration, and streams results from NDJSON input — no external SIEM required. A built-in linter validates rules against 64 checks derived from the Sigma v2.1.0 specification with four severity levels and a full suppression system, and an LSP server provides real-time diagnostics, completions, and hover documentation in any editor.

| Crate | Description |
|-------|-------------|
| [`rsigma-parser`](crates/rsigma-parser/) | Parse Sigma YAML into a strongly-typed AST |
| [`rsigma-eval`](crates/rsigma-eval/) | Compile and evaluate rules against JSON events |
| [`rsigma-cli`](crates/rsigma-cli/) | CLI for parsing, validating, linting, and evaluating rules |
| [`rsigma-lsp`](crates/rsigma-lsp/) | Language Server Protocol (LSP) server for IDE support |

## Installation

```bash
# Build all crates
cargo build --release

# Install the CLI
cargo install --path crates/rsigma-cli

# Install the LSP server
cargo install --path crates/rsigma-lsp
```

## Quick Start

Evaluate events against Sigma rules from the command line:

```bash
# Single event (inline JSON)
rsigma eval -r path/to/rules/ -e '{"CommandLine": "cmd /c whoami"}'

# Read events from a file (@file syntax)
rsigma eval -r path/to/rules/ -e @events.ndjson

# Stream NDJSON from stdin
cat events.ndjson | rsigma eval -r path/to/rules/

# With a processing pipeline for field mapping
rsigma eval -r rules/ -p pipelines/ecs.yml -e '{"process.command_line": "whoami"}'
```

Or use the library directly:

```rust
use rsigma_parser::parse_sigma_yaml;
use rsigma_eval::{Engine, Event};
use serde_json::json;

let yaml = r#"
title: Detect Whoami
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;

let collection = parse_sigma_yaml(yaml).unwrap();
let mut engine = Engine::new();
engine.add_collection(&collection).unwrap();

let event = Event::from_value(&json!({"CommandLine": "cmd /c whoami"}));
let matches = engine.evaluate(&event);
assert_eq!(matches[0].rule_title, "Detect Whoami");
```

## Architecture

```
                    ┌──────────────────┐
   YAML input ───>  │   serde_yaml     │──> Raw YAML Value
                    └──────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   parser.rs      │──> Typed AST
                    │  (YAML → AST)    │   (SigmaRule, CorrelationRule,
                    └──────────────────┘    FilterRule, SigmaCollection)
                             │
            ┌────────────────┼──────────────┐
            ▼                ▼              ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │ sigma.pest │  │  value.rs  │  │   ast.rs   │
     │  (PEG      │  │ (SigmaStr, │  │ (AST types │
     │  grammar)  │  │  wildcards,│  │  modifiers,│
     │     +      │  │  timespan) │  │  enums)    │
     │condition.rs│  └────────────┘  └────────────┘
     │  (Pratt    │
     │  parser)   │
     └────────────┘
           │
     ┌─────┴───────────────────────────────────────────────┐
     │                                                     │
     ▼                                                     ▼
    ┌──────────────────────────────────────────┐   ┌────────────────────┐
    │              rsigma-eval                 │   │    rsigma-lsp      │
    │                                          │   │                    │
    │  pipeline/ ──> Pipeline (YAML parsing,   │   │  LSP server over   │
    │    conditions, transformations, state)   │   │  stdio (tower-lsp) │
    │    ↓ transforms SigmaRule AST            │   │                    │
    │                                          │   │  • diagnostics     │
    │  compiler.rs ──> CompiledRule            │   │    (lint + parse   │
    │  matcher.rs  ──> CompiledMatcher         │   │     + compile)     │
    │  engine.rs   ──> Engine (stateless)      │   │  • completions     │
    │                                          │   │  • hover           │
    │  correlation.rs ──> CompiledCorrelation  │   │  • document        │
    │    + EventBuffer (deflate-compressed)    │   │    symbols         │
    │  correlation_engine.rs ──> (stateful)    │   │                    │
    │    sliding windows, group-by, chaining,  │   │  Editors:          │
    │    alert suppression, action-on-fire,    │   │  VSCode, Neovim,   │
    │    memory management, event inclusion    │   │  Helix, Zed, ...   │
    │                                          │   └────────────────────┘
    │  rsigma.* custom attributes ─────────>   │
    │    engine config from pipelines          │
    └──────────────────────────────────────────┘
              │
              ▼
     ┌────────────────────┐
     │  MatchResult       │──> rule title, id, level, tags,
     │  CorrelationResult │   matched selections, field matches,
     └────────────────────┘   aggregated values, optional events
```

## Reference

- [pySigma](https://github.com/SigmaHQ/pySigma) — reference Python implementation
- [Sigma Specification V2.0.0](https://github.com/SigmaHQ/sigma-specification) — formal specification
- [sigma-rust](https://github.com/jopohl/sigma-rust) — Pratt parsing approach
- [sigmars](https://github.com/crowdalert/sigmars) — correlation support patterns

## License

MIT
