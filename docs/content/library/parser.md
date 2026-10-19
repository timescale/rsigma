# `rsigma-parser`

Parse Sigma rule YAML, correlation rules, filter rules, and condition expressions into a typed AST. The only crate that touches Sigma source; every other rsigma crate consumes the AST shapes defined here.

- [docs.rs/rsigma-parser](https://docs.rs/rsigma-parser)
- [README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-parser/README.md)
- [crates.io/crates/rsigma-parser](https://crates.io/crates/rsigma-parser)

## When to use

- A CI tool that needs to parse rules without compiling them. Cheaper than the full eval pipeline.
- A custom linter or migration tool that operates on the AST shape.
- A different evaluator front-end that wants to reuse the parser but not the matcher.
- The first step of any pipeline that ends in `rsigma-eval` or `rsigma-convert`.

For full rule loading, compilation, and event evaluation, layer [`rsigma-eval`](eval.md) on top. For backend query generation, use [`rsigma-convert`](convert.md).

## Install

```toml
[dependencies]
rsigma-parser = "{{ rsigma.version }}"
```

The crate has no RSigma dependencies and pulls in `yaml_serde` 0.10 (the maintained `serde_yaml` fork), `regex`, `regex-syntax` and `fancy-regex` (regular-expression validation), `pest`, and `thiserror`. Default features enable YAML source fixes via the optional `fix` feature (`yamlpatch` / `yamlpath`).

## Public surface

| Type | Purpose |
|------|---------|
| `parse_sigma_yaml(&str) -> Result<SigmaCollection, SigmaParserError>` | The main entry point. Accepts single-document or multi-document YAML (`---` separator). |
| `parse_sigma_file(&Path)`, `parse_sigma_directory(&Path)` | File and directory variants. |
| `SigmaCollection` | A bag of `SigmaRule`, `CorrelationRule`, and `FilterRule` parsed from one input, plus the `diagnostics` found while parsing it. |
| `CollectionDiagnostic`, `DiagnosticKind`, `DiagnosticSeverity` | One parse error or parse warning, with its kind, severity, message, document index, file path, and source location. See [Error handling](#error-handling). {{ added "0.25.0" }} |
| `SigmaRule` | A detection rule (`title`, `id`, `sigma_version`, `logsource`, `detection`, `condition`, …). |
| `CorrelationRule` | A correlation rule (`correlation:` block plus shared metadata). |
| `FilterRule` | A filter rule (`filter:` block plus shared metadata). |
| `version::{resolve_major, array_matching_enabled, is_unsupported, SPEC_VERSION_*}` | Sigma specification-version targeting: resolves the optional `sigma-version` attribute (absent ⇒ fixed floor, major 2) and gates version-sensitive syntax such as array-matching brackets (active at major 3+). |
| `ConditionExpr`, `ConditionOperator` | The parsed condition expression AST (Pratt parser, `not > and > or` precedence). |
| `parse_condition(&str) -> Result<ConditionExpr, SigmaParserError>` | Standalone condition-expression parser. |
| `Detection`, `DetectionItem`, `FieldSpec`, `SigmaValue`, `Modifier` | Detection-block building blocks. |
| `LogSource` | The `logsource:` block (`product`, `category`, `service`). |
| `validate::{check_detection_item, check_modifiers, check_regex, check_cidr, exists_flag}` | The semantic checks the parser runs on every detection item, exposed for tools that build or rewrite detection items in code. {{ added "0.24.0" }} |
| Linter (`lint::*`) | {{ rsigma.lint.rules }} spec-conformance checks (including cross-document reference checks over a directory). See [Lint Rules reference](../reference/lint-rules.md). |
| `lint::catalogue::catalogue() -> Vec<LintRuleInfo>` | Programmatic metadata for every lint rule: stable id, default severity, fix disposition, one-line description. |
| `ads::ads_catalogue() -> Vec<AdsSectionInfo>` | The nine [ADS](../guide/detection-strategy.md) sections: id, carrier field, default-required, description. `AdsSection`/`AdsDocument` read present and missing sections off a `SigmaRule`. |
| `lint::fix::apply_fixes_to_source(&str, &[&LintWarning]) -> SourceFixOutcome` | Apply every safe fix to a YAML source string, preserving comments and formatting; reports applied/failed counts. |
| `reference::{MODIFIERS, MITRE_TACTICS}` | Field-modifier descriptions and MITRE ATT&CK tactic metadata, shared with the LSP and the MCP server. |

The full enumeration of modifiers (30+), correlation types (8), and condition operators lives in [the crate README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-parser/README.md).

## Minimum example

```rust
use rsigma_parser::parse_sigma_yaml;

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

let collection = parse_sigma_yaml(yaml).unwrap();
assert_eq!(collection.rules.len(), 1);
assert_eq!(collection.rules[0].title, "Whoami");
```

## Linting

The linter runs the {{ rsigma.lint.rules }} spec-conformance checks against parsed (or partially parsed) rules and returns `LintWarning`s:

```rust
use rsigma_parser::lint::{lint_yaml_directory, LintConfig};

let config = LintConfig::default();
let results = lint_yaml_directory("rules/".as_ref(), &config)?;

for file in &results {
    for w in &file.warnings {
        println!("{}: [{}] {}", file.path.display(), w.rule, w.message);
    }
}
```

The full lint catalogue (severities, fix availability, worked examples) is the [Lint Rules reference](../reference/lint-rules.md). The `lint::Fix` machinery powers `rule lint --fix`.

### Programmatic catalogue and fixes

`lint::catalogue::catalogue()` returns the rule metadata as data, so a tool can enumerate the vocabulary without scraping the rule modules:

```rust
use rsigma_parser::lint::catalogue::catalogue;

for info in catalogue() {
    println!("{} ({}) fixable={}", info.name, info.default_severity, info.fix.is_some());
}
```

`lint::fix::apply_fixes_to_source` applies the safe fixes attached to a set of `LintWarning`s directly to a YAML string (the string-level core behind `rule lint --fix`, also used by the LSP and MCP server):

```rust
use rsigma_parser::lint::{lint_yaml_str, fix::apply_fixes_to_source};

let source = "title: Test\nStatus: test\nlogsource:\n    category: test\ndetection:\n    sel: {field: value}\n    condition: sel\n";
let warnings = lint_yaml_str(source);
let fixable: Vec<_> = warnings.iter().filter(|w| w.fix.is_some()).collect();
let outcome = apply_fixes_to_source(source, &fixable);
println!("applied {} fix(es)", outcome.applied);
```

## Condition parsing

The condition parser is exposed standalone so a tool that just wants to operate on `condition:` strings does not have to build a full rule:

```rust
use rsigma_parser::parse_condition;

let ast = parse_condition("selection_a and not (selection_b or selection_c)")?;
println!("{ast:#?}");
```

Bounds: `MAX_CONDITION_LEN = 64 KiB`, `MAX_CONDITION_DEPTH = 64`. See [Security Hardening](../reference/security.md#input-size-and-depth-caps).

## Semantic validation

{{ added "0.24.0" }}

The parser validates rule semantics, not only structure. A detection or filter rule fails to parse when its `logsource` is missing or sets none of `category`, `product`, and `service`, when a field combines conflicting modifiers (`|gt|lt`), when a value has the wrong type for its modifiers (a number under `contains`, a string under `gt`), when a `re` or `cidr` value is invalid, when a named detection is empty, or when the condition references a detection that does not exist. Each error is collected per document in `SigmaCollection::diagnostics` and names the field. The usable-logsource requirement is stricter than pySigma's parser, which accepts an empty `logsource` mapping.

The checks live in the `validate` module. `rsigma-ir` reruns `check_detection_item` when it lowers a rule, so detection items a processing pipeline rewrites after parsing are checked too. Invalid regex syntax still reaches the evaluator's regex compiler so library callers retain the specific `EvalError::InvalidRegex` error.

```rust
use rsigma_parser::validate::{check_modifiers, check_regex};
use rsigma_parser::Modifier;

assert!(check_modifiers(&[Modifier::Gt, Modifier::Lt]).is_err());
assert!(check_regex("a(b").is_err());
assert!(check_regex("(?<!x)y").is_ok());
```

`check_regex` accepts lookaround and backreferences, as pySigma does. The `rsigma-eval` regex engine does not support them, so such a rule parses and then fails to compile.

## Error handling

`SigmaParserError` from `thiserror` (also re-exported as `error::Result<T>`). Variants cover YAML syntax errors, missing required fields, invalid modifiers and modifier combinations (`InvalidModifiers`), invalid values and detections, condition-expression errors, and the size/depth caps above. `Condition` errors carry a `SourceLocation` so callers can highlight the offending location in source, and `kind()` returns the variant as a payload-free `SigmaParserErrorKind`.

The parse functions return `Err` only when they cannot start, for example when a file cannot be read. Problems inside the input are recorded on the returned collection as `CollectionDiagnostic` values in `SigmaCollection::diagnostics`, so one bad document does not hide the others: {{ added "0.25.0" }}

- `severity` is `Error` when a document, a file, or the rest of the YAML stream was dropped, and `Warning` when a document was kept with an invalid `status`, `level`, `related` entry, or `sigma-version` ignored.
- `kind` says what failed: `YamlSyntax`, `NotAMapping`, `CollectionAction`, `Document(SigmaParserErrorKind)`, `Metadata`, or `File(SigmaParserErrorKind)`.
- `document` is the zero-based index of the YAML document, `path` is the file when the collection was read from disk, and `location` is set for YAML syntax and condition errors.
- `Display` prints `message`.

`has_errors()`, `error_count()`, and `into_result()` count only errors, so warnings alone are not a failure. `warning_count()`, `errors()`, and `warnings()` give the rest.

```rust
use rsigma_parser::parse_sigma_yaml;

let collection = parse_sigma_yaml(yaml)?;
for warning in collection.warnings() {
    eprintln!("warning: {warning}");
}
let collection = collection.into_result().map_err(|diagnostics| {
    diagnostics.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")
})?;
```

## See also

- [`rsigma-eval`](eval.md) for the next layer: compile and evaluate.
- [`rsigma-convert`](convert.md) for generating backend queries from the AST.
- [Lint Rules reference](../reference/lint-rules.md) for the {{ rsigma.lint.rules }} lint checks the crate ships.
- [`rsigma-parser` README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-parser/README.md) for the full AST reference and modifier matrix.
- [docs.rs/rsigma-parser](https://docs.rs/rsigma-parser) for the generated API documentation.
