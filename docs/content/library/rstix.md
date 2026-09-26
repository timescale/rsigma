# rstix

`rstix` is the RSigma workspace crate for **STIX 2.1**. It provides typed Rust objects for all 42 built-in STIX types (3 meta, 19 SDO, 2 SRO, 18 SCO), bundle ingestion with streaming, extension round-trip, T1 advisory validation via `Bundle::validate()` (default `serde`), and an optional T2 Validation Pipeline (`validate` feature).

API reference: [docs.rs/rstix](https://docs.rs/rstix), the [crate README](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md), and the [crate source](https://github.com/timescale/rsigma/tree/main/crates/rstix).

```toml
# Cargo.toml
[dependencies]
rstix = "{{ rsigma.version }}"
# For Pattern Engine + Validation Pipeline:
# rstix = { version = "{{ rsigma.version }}", features = ["pattern", "validate"] }
# Graph, marking, store (combine as needed):
# rstix = { version = "{{ rsigma.version }}", features = ["graph", "marking", "store"] }
```

## Feature status

```mermaid
flowchart TB
    CF["Core Foundation<br/>(always on)"]
    SERDE["Data Model + Serialization<br/>`serde` default"]
    PAT["Pattern Engine<br/>`pattern`"]
    VAL["Validation Pipeline<br/>`validate`"]
    GMS["Graph · Marking · Store<br/>`graph` · `marking` · `store` · `store-fs`"]
    TAX["TAXII Client · ingest<br/>`taxii` · `taxii-store`"]

    CF --> SERDE
    SERDE --> PAT
    PAT --> VAL
    SERDE --> GMS
    SERDE --> TAX
```

Solid arrows are **feature dependencies** (`validate` → `pattern` → `serde`; `store-fs` → `store`; `taxii-store` → `taxii` + `store`). `graph`, `marking`, `store`, and `taxii` each require `serde` only.

| Area | Cargo feature(s) | Status |
| ----- | ---------------- | ------ |
| **Core Foundation** | *(always on)* | Complete |
| **Data Model + Serialization** | `serde` (default) | Complete: see [Validation tiers](#rstix-validation-tiers) and [Wire conformance](#rstix-wire-conformance-stix-21) |
| **Pattern Engine** | `pattern` | **Complete** |
| **Validation Pipeline** | `validate` | **Complete** |
| **Graph + Marking + Store** | `graph`, `marking`, `store`, `store-fs` | **Complete** |
| **TAXII Client** | `taxii`, `taxii-store` | **Complete** (collection ingest via `taxii-store`) |

## Quick start

```rust
use std::fs::File;
use std::io::BufReader;

use rstix::model::{Bundle, ValidationCode};
use rstix::parse_bundle;

// String parse (small bundles)
let bundle = parse_bundle(json_str)?;

// Streaming parse (large bundles, e.g. MITRE ATT&CK ~50 MiB)
let file = File::open("enterprise-attack.json")?;
let bundle = Bundle::parse_reader(BufReader::new(file))?;

// T0 MUST rules at parse; T1 SHOULD via bundle.validate()
let report = bundle.validate();
for warning in report.warnings_with_code(ValidationCode::StixW0031TlpV1Encoding) {
    eprintln!("{}: {}", warning.object_id.as_deref().unwrap_or("?"), warning.message);
}

// Round-trip
let out = serde_json::to_string(&bundle)?;
```

## Pattern Engine (STIX §9)

The optional **`pattern`** feature adds the full STIX patterning engine.

```mermaid
flowchart LR
    subgraph PE ["Pattern Engine (`pattern`) feature"]
        SRC["Pattern string"] --> LEX["Lexer"]
        LEX --> PAR["Parser<br/>Levels 1–3"]
        PAR --> AST["PatternAst"]
        AST --> TCK["SCO type checker"]
        TCK --> PAT["Pattern<br/>(validated)"]
        IND["Indicator STIX pattern<br/>(`serde` + `pattern`)"] --> PAT
        PAT --> EVAL["Evaluator"]
        CTX["ObservationContext"] --> EVAL
        PATH["Path resolver<br/>(_ref, extensions, CIDR)"] --> EVAL
        SEC["Regex safety<br/>(MATCHES)"] --> EVAL
        EVAL --> OUT["match result"]
        PAT --> CANON["Canonical printer"]
    end
```

| Component | Role | Status |
| --------- | ---- | ------ |
| Lexer | Tokenizer; 64 KiB input cap | Done |
| Parser | Recursive-descent parser | Done |
| SCO type checker | SCO schema + extension paths | Done |
| Evaluator | Level 1–3 evaluation | Done |
| Observation context | `ObservationContext`, observed-data builder | Done |
| Regex safety | Regex compile size limit + PCRE DOTALL for `MATCHES` | Done |
| Path resolver | Object-path resolution, CIDR, `_ref` via bundle | Done |
| Canonical printer | `Pattern::canonical` | Done |

```rust
use rstix::Pattern;
use rstix::pattern::{ObservationContext, TimestampedObservation};

let pattern = Pattern::parse("[ipv4-addr:value = '198.51.100.1/32']")?;
assert_eq!(pattern.canonical(), "[ipv4-addr:value = '198.51.100.1/32']");

let ctx = ObservationContext::from_scos(&observations);
assert!(pattern.evaluate(&ctx)?);
```

Build with `cargo build -p rstix --features pattern`.

### In scope (Pattern Engine (complete))

Lexer, Level 1–3 parser, SCO schema type-checker (18 built-in + custom types), `Pattern::parse`, `Pattern::evaluate`, `matches_single`, `matches_single_with_bundle`, `evaluate_observed_data`, `Pattern::canonical`, `IndicatorPattern` STIX AST wiring at deserialize, `IndicatorPattern::evaluate`, `IndicatorBuilder`, `ObservationContext`, full §9 comparison and temporal semantics, manifest-driven SCO field tests (`tests/pattern_eval_sco_fields.rs`, 276 cases), spec §9.8 parse/print round-trip tests, `fuzz_stix_pattern`.

Grammar authority: **STIX Specification §9**. Internal storage uses `PatternAst` after type-check.

Evaluation notes (STIX §9):

- **`TimestampedObservation::at`**: `Option<StixTimestamp>`; patterns with `WITHIN`, `FOLLOWEDBY`, `REPEATS`, or `START`/`STOP` return `MissingTimestamp` when any observation lacks a timestamp. Plain observation expressions accept `at: None`.
- **`matches_single_with_bundle`**: pass a bundle when Level 1 patterns dereference `_ref` paths. Absent optional `_ref` properties yield no match for comparisons and `false` for `EXISTS`; present refs that cannot be resolved in the bundle still return `RefResolution`.
- **`LIKE` / `MATCHES` (§9.6.1)**: pattern constants and string property values are NFC-normalized before comparison; `MATCHES` compiles with PCRE DOTALL (`.` matches newlines) and a 1 MiB compile-size cap.
- **Custom SCO types** (`x-usb-device`, …): vendor types deserialize as `CustomSco`; parsed and type-checked permissively (leaf properties as string).
- **`process:name`**: resolved from `image_ref` → file name when a bundle is present, otherwise from the executable token in `command_line`.
- **`file:created`**: alias for `ctime`.
- **`network-traffic:dst_ref.type`**: `_ref` dereference then `type` on the target SCO.
- **`file:hashes.MD5`**: dictionary dot-key syntax per §9.7.3.
- **`extensions.'…'`**: predefined SCO extension paths (e.g. `windows-pebinary-ext.sections[*].entropy`).
- **`ISSUBSET` / `ISSUPERSET` on string**: IP/CIDR subset checks per §9.6.

Tests: `tests/fixtures/pattern/` (STIX §9.8), `tests/fixtures/pattern/sco-fields/` (SCO field manifest, 276 cases), `tests/pattern_parse.rs`, `tests/pattern_spec_eval.rs`, `tests/pattern_eval_operators.rs`, `tests/pattern_eval_sco_fields.rs`, `tests/pattern_eval_errors.rs`, `tests/pattern_eval_security.rs`, `tests/pattern_indicator.rs` (requires `pattern` feature).

Downstream tooling may index indicators by `Pattern::observed_types()` without reimplementing pattern grammar.

## TAXII Client

Optional **`taxii`** feature: TAXII 2.1 HTTP client for all normative endpoint groups **covering Discovery, API Root, Collections, Objects, Manifests, and Status (Channels in spec §6 are RESERVED)**:

| Feature | Key API | Highlights |
| ------- | ------- | ---------- |
| `taxii` | `TaxiiClient`, `TaxiiEnvelope` | TAXII 2.1 HTTP client (rustls TLS 1.2+1.3, PEM and PKCS#12 mTLS, SPKI pin / DANE, auth, pagination, SRV + `dns_nameserver()`). Covers Discovery, API Root, Collections, Objects, Manifests, and Status. |

```rust
use rstix::taxii::{BearerAuth, TaxiiClient, TaxiiClientConfig, TaxiiFilter};
use futures::StreamExt;

let client = TaxiiClient::new(
    TaxiiClientConfig::new("https://taxii.example.com").auth(BearerAuth::new(token)),
)?;
let discovery = client.discover().await?;
let mut stream = client.objects_stream(api_root_url, "col1", TaxiiFilter::new());
while let Some(obj) = stream.next().await {
    let _obj = obj?;
}
```

```bash
cargo test -p rstix --features taxii --test taxii_client
```

Optional live harness: see [`tests/taxii-live/README.md`](https://github.com/timescale/rsigma/blob/main/crates/rstix/tests/taxii-live/README.md).

Full **API surface tables** and **invariant decisions**: [crate README: TAXII Client](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#taxii-client).

### Collection ingest (`taxii-store`)

Optional **`taxii-store`** feature (`taxii` + `store`): paginated collection fetch into [`StixStore`](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#collection-ingest-taxii-store) with bounded memory.

**Public API (breaking vs 0.22.0):** `ingest_collection` / `ingest_collection_with_bundle_id` return `IngestReport` (not `ImportReport`); `ingest_collection_with_bundle_id` takes `IngestOptions`.

```rust
use rstix::store::{MemoryStore, StixStore};
use rstix::taxii::{ingest_collection, IngestOptions, TaxiiClient, TaxiiClientConfig, TaxiiFilter};

let client = TaxiiClient::new(TaxiiClientConfig::new("https://taxii.example.com"))?;
let store = MemoryStore::new();
let report = ingest_collection(&client, &store, api_root_url, "col1", TaxiiFilter::new()).await?;
println!("added {}", report.import.objects_added);

// Optional validate-on-ingest (`validate` feature):
use rstix::taxii::ingest_collection_with_bundle_id;
let report = ingest_collection_with_bundle_id(
    &client, &store, api_root_url, "col1", TaxiiFilter::new(), bundle_id,
    IngestOptions::producer_strict(),
).await?;
```

Default ingest does not validate. With `validate`, each object is checked as a one-object synthetic bundle; use `IngestOptions::producer_strict()` (skips References). `interop_strict` is zero-leniency and still closed-bundle on refs — not for paginated ingest. Invalid objects are rejected by default when a validator is attached. Unresolved refs are audited after all pages against the store.

```bash
cargo test -p rstix --features taxii-store --test taxii_store --locked
cargo test -p rstix --features taxii-store,validate --test taxii_store --locked
```

## Graph + Marking + Store

Four optional feature flags (each implies `serde`; `store-fs` also implies `store`):

| Feature | Key API | Highlights |
| ------- | ------- | ---------- |
| `graph` | `StixGraph`, `RelationshipExpander` | `StixGraph::from_bundle`, sighting + relationship SRO edges, `in_refs` / incoming traversal, `EdgeTraversal` chain, `expand_from`, `unresolved_references` |
| `marking` | `MarkingResolver`, `TlpV2Level` | Effective TLP (incl. AMBER+STRICT), granular selector resolution, `permits_disclosure`, `EffectiveMarking::language_tags` |
| `store` | `StixStore`, `MemoryStore` | Type-indexed queries, full-text search, pagination, export/delete, SCO fingerprint conflicts in `ImportReport` |
| `store-fs` | `FsStore` | Filesystem-backed durable store (implies `store`) |

```rust
use rstix::graph::{EdgePredicate, StixGraph};
use rstix::marking::MarkingResolver;
use rstix::store::{MemoryStore, StixStore};
use rstix::parse_bundle;

let bundle = parse_bundle(json)?;
let graph = StixGraph::from_bundle(&bundle)?;
let resolver = MarkingResolver::new(&bundle);
let store = MemoryStore::new();
store.import_bundle(&bundle)?;
```

Acceptance: `cargo test -p rstix --features graph --test graph`; `--features marking --test marking`; `--features store --test store`; `--features store-fs --test store_fs`.

Full API and invariant tables: [crate README](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md).

### Pattern Engine design decisions

Formal record of engineering choices for the Pattern Engine. Full text: [crate README: Pattern Engine design decisions](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#pattern-engine-design-decisions).

#### DD-PE-001: `IndicatorBuilder` validates at `build()`, not in setters

| | |
| --- | --- |
| **Status** | Accepted (PR #296) |
| **Applies to** | `IndicatorBuilder`, `IndicatorBuilderError` |

**Context.** Indicators need STIX pattern parse/type-check (when `pattern` is enabled) plus `Indicator::validate()`. Construction paths are JSON deserialize and `IndicatorBuilder`.

**Decision.** Setters store configuration only. `build()` is the materialization boundary: required fields, `Pattern::parse` for STIX patterns, then `Indicator::validate()`. `stix_pattern()` does not parse.

**Rationale.**

1. **Parity with deserialize**: wire JSON parses the pattern when the `Indicator` is materialized, not per-field during tokenization.
2. **One error surface**: missing `valid_from`, bad pattern, and model invariants all return from `build()` as `IndicatorBuilderError`.
3. **Fluent API**: setters return `Self`; callers use a single `?` at the end of the chain.

**Alternatives not chosen:** parse in `stix_pattern() -> Result<Self, _>` (fail-fast but breaks fluent chain); error accumulation in the builder (same outcome, more state); type-state builder (compile-time safety, out of scope for the current Pattern Engine API).

**Consequences.** Pattern errors appear at `build()`. With `pattern` off, only the raw string is stored. Callers who want eager parse can use `IndicatorPattern::stix(...)?` and `.pattern(...)`.

## Public API surface

Grouped by **Cargo feature** (phase name). Rust module paths are implementation detail: enable features features in `Cargo.toml`, not module names.

### Always on: Core Foundation

| Symbol | Role |
| ------ | ---- |
| `StixId`, typed ID wrappers, `StixObjectKind` | ID parse, generate, typed conversions |
| `StixTimestamp`, `TaxiiTimestamp`, `Confidence`, `SpecVersion`, `LanguageTag` | Core wire types |
| `generate_sco_id`, `select_id_contributing_properties`, `jcs_canonicalize` | Deterministic SCO UUIDv5 |
| Vocabulary tables (`HASH_ALGORITHM_ENUM`, `REGION_OV`, …) | Closed and open STIX §10 tables |
| Typed SDO/SRO/SCO/meta structs, `ModelError` | Programmatic model (no bundle I/O without `serde`) |

### `serde`: Data Model + Serialization

| Symbol | Role |
| ------ | ---- |
| `parse_bundle(&str)` | Parse a bundle JSON string with default `ParseOptions`. |
| `Bundle` | Typed container; navigation, serialize, T1 `validate()`. |
| `StixObject` | Top-level enum: SDO / SCO / SRO / Meta / Custom. |
| `ParseOptions`, `TypeRegistry` | Limits, custom type registration. |
| `ValidationReport`, `ValidationCode`, `ValidationFinding` | T1 advisory validation output. |
| `ParseError`, `ModelError` | Parse-time failures for rules enforced at T0 (see [Validation tiers](#rstix-validation-tiers)). |

SDO/SRO/SCO families (19 SDOs, 2 SROs, 18 SCOs + 12 extensions), `IndicatorPattern`, `IndicatorBuilder`, common props, external references, granular markings, extension maps.

### `pattern`: Pattern Engine

| Symbol | Role |
| ------ | ---- |
| `Pattern`, `PatternAst`, `PatternScoType` | STIX §9 parse and type-check at crate root. |
| `Pattern::evaluate`, `matches_single`, `matches_single_with_bundle`, `evaluate_observed_data` | Level 1–3 evaluation. |
| `pattern::ObservationContext`, `pattern::TimestampedObservation` | Evaluation context. |
| `PatternError`, `PatternMatchError` | Lex/parse/type-check/match errors. |

### `validate`: Validation Pipeline

`Validator`, profiles (`consumer_strict`, `interop_strict`, …), `ValidationPhase`, structured `STIX-E/W/I/H` diagnostics: see [Validation Pipeline](#rstix-validation-pipeline).

### `graph` · `marking` · `store` · `store-fs` · `taxii` · `taxii-store`

See [Graph + Marking + Store](#rstix-graph-marking-store) and [TAXII Client](#rstix-taxii-client).

## Bundle parsing

### Methods

| Method | Use when |
| ------ | -------- |
| `Bundle::parse(&str)` | Entire JSON is in memory. |
| `Bundle::parse_with_options(&str, &ParseOptions)` | Custom types or stricter limits. |
| `Bundle::parse_reader(R: Read)` | Large files; uses `serde_json` streaming reader with byte cap. |
| `Bundle::parse_reader_with_options(R, &ParseOptions)` | Streaming + options. |

### Default `ParseOptions`

| Field | Default | Purpose |
| ----- | ------- | ------- |
| `max_nesting_depth` | 64 | Reject deeply nested JSON (DoS guard). |
| `max_string_length` | 1_048_576 (1 MiB) | Max length of any JSON string value. |
| `max_bundle_bytes` | 256 MiB | Max bytes read from stream / checked for string parse. |
| `max_object_count` | `usize::MAX` | Max objects in one bundle. |
| `allow_custom` | `false` | Unknown `type` → error unless registered or allowed. |

### Navigation

| Method | Description |
| ------ | ----------- |
| `bundle.objects()` | All objects in document order. |
| `bundle.get(&StixId)` | Untyped lookup by id. |
| `bundle.get_typed::<T>(&StixId)` | Typed lookup (`Malware`, custom types, …). |
| `bundle.objects_of_type::<T>()` | Iterator over all objects of type `T`. |
| `bundle.extra_properties(&StixId)` | Top-level `x_*` and hoisted extension keys peeled at parse. |
| `bundle.validate_refs()` | Re-run in-bundle ref existence and ref-kind checks (normally called during parse). |
| `bundle.validate()` | Collect T1 SHOULD-level semantic warnings. |

The typed lookup API is **`get_typed::<T>()`** (not `get::<T>()`) to avoid clashing with untyped `get`.

## Custom STIX types

Register extension SDOs per `ParseOptions` instance (not global):

```rust
use rstix::model::{Bundle, BundleObjectCast, ParseOptions, StixObject};

#[derive(serde::Deserialize, serde::Serialize)]
struct XMySdo { /* ... */ }

impl BundleObjectCast for XMySdo {
    fn cast_from(object: &StixObject) -> Option<&Self> {
        match object {
            StixObject::Custom(c) => c.downcast_typed(),
            _ => None,
        }
    }
}

let opts = ParseOptions::new().register_custom_type::<XMySdo>("x-my-sdo");
let bundle = Bundle::parse_with_options(json, &opts)?;
```

## Semantic validation (`Bundle::validate`)

Default **`serde` parse** enforces MUST rules wired at the deserialize boundary (see [Validation tiers](#rstix-validation-tiers)). **`Bundle::validate()`** collects **SHOULD**-level and advisory findings without rejecting the bundle. Stricter gates use the optional **`validate`** feature (`Validator` profiles).

| `ValidationCode` | Meaning |
| ---------------- | ------- |
| `StixW0031TlpV1Encoding` | Legacy TLP 1.x marking encoding or TLP1 marking ref (STIX-W0031). |
| `ScoDeterministicIdMismatch` | SCO `id` does not match UUIDv5 from id-contributing properties. |
| `GranularSelectorSemanticInvalid` | Granular-marking selector does not resolve on the object (also rejected at parse). |
| `LanguageContentValueMismatch` | Translation type, list length, or nested object shape does not mirror the target (§7.1.1; also rejected at parse). |
| `LanguageContentObjectModifiedMismatch` | `object_modified` does not match target `modified` (also rejected at parse). |
| `LocationCountryNotIso3166` | `country` is not ISO 3166-1 alpha-2. |
| `LocationRegionNotInOpenVocab` | `region` is not in STIX `region-ov`. |
| `InvalidCapecExternalReference` | CAPEC `external_id` shape (attack-pattern). |
| `InvalidCveExternalReference` | CVE `external_id` shape (vulnerability). |
| `RelationshipEndpointMatrixInvalid` | Relationship source/target types outside STIX 2.1 matrix (also `STIX-I0002` under `interop_strict`). |

`GranularSelectorSemanticInvalid`, `LanguageContentValueMismatch`, and `LanguageContentObjectModifiedMismatch` are enforced at parse (`ModelError`) and mirrored as T1 warnings when validating bundles built via `Bundle::from_objects()` without re-parsing wire JSON. Language-content keys for properties that do not exist on the target object are silently ignored (§7.1.1 MUST be ignored).

There is no `strict` parse flag on `Bundle::parse`. Use **`Validator`** profiles when structured diagnostics or profile-driven pass/fail is required.

### Data Model + Serialization design decisions

Formal record of wire-parse engineering choices. Full text: [crate README: Data Model + Serialization design decisions](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#data-model--serialization-design-decisions).

#### DD-DM-001: Wire MUST at parse (`domain-name`, `email-addr`, `url`)

| | |
| --- | --- |
| **Status** | Accepted (#327) |
| **Applies to** | `serde` feature (default), `domain-name`, `email-addr`, `url` SCO types |
| **Spec** | STIX 2.1 §6.4, §6.5, §6.15 |

**Context.** PR #315 previously gated strict IDNA / RFC 5322 / URL checks behind the optional `validate` feature. [Issue #267](https://github.com/timescale/rsigma/issues/267) directs MUST at parse and SHOULD via `Bundle::validate()`.

**Decision.** Malformed `domain-name`, `email-addr`, and `url` values are **rejected at default `serde` parse**. URL validation uses full RFC 3986 parse via the `url` crate (any valid absolute URL), not a scheme whitelist. Other wire-format checks use T1 (`Bundle::validate()`) or T2 (Validation Pipeline) as documented in [Validation tiers](#rstix-validation-tiers).

## Wire-format validation (DD-DM-001)

STIX **MUST** rules for `domain-name.value` (RFC 1034 / RFC 5890), `email-addr.value` (RFC 5322 addr-spec), and `url.value` (RFC 3986) are enforced at the **default `serde` parse boundary** per **DD-DM-001** above, via optional deps (`idna`, `email_address`, `url`, `base64`, `encoding_rs`) enabled by the `serde` feature. `--no-default-features` builds omit those crates.

| Field | Spec reference | Parse boundary (`serde`) |
| ----- | -------------- | ------------------------ |
| `domain-name.value` | RFC 1034 / 5890 | IDNA (UTS #46) + label rules |
| `email-addr.value` | RFC 5322 | RFC 5322 addr-spec (`email_address`) |
| `url.value` | RFC 3986 | RFC 3986 URL parse (`url` crate) |

The Validation Pipeline re-runs the same checks on typed objects during the schema phase.

SCO `*_enc` properties (§3.1 / §3.9.1) MUST be IANA character-set names and MUST NOT appear without their base property. Spec-defined properties are `file.name_enc` and `directory.path_enc`; other `_enc` keys in `common.extra` follow the same rules. `email-message` RFC 2047 encoded-words are decoded on ingest (§6.6). Pattern evaluation can address vendor `_enc` siblings via `common.extra` when present on the wire object.

## Extensions and round-trip

- Top-level **`x_*`** keys are peeled before typed deserialize → `Bundle::extra_properties()`, merged back on serialize.
- **`toplevel-property-extension`** keys are hoisted from `extensions` the same way.
- Standalone leaf deserialize stores unknown keys in **`common.extra`** (SDO/SRO/SCO) or **`MarkingDefinition.extra`**, drained into `extra_properties` during bundle parse.
- Deprecated observed-data **`objects`** maps accept embedded **SCO or SRO** members (`ObservedDataEmbeddedObject`).

### Serialization map conventions

When adding wire-facing maps, match existing `model/` types (PR #213 / #201 review lessons):

| Use | Map type | Examples |
| --- | -------- | -------- |
| JSON object properties where **stable key order** matters (strict round-trip, JCS, bundle re-serialize) | **`BTreeMap`** | `ExtensionMap`, `ExternalReference.hashes`, `LanguageContent.contents`, `common.extra`, SCO `hashes`, values in `Bundle.extra_properties()` |
| Internal **indexes** keyed by STIX id where order is irrelevant | **`HashMap`** | `Bundle.id_index`, graph adjacency, store buckets, marking resolver index |

Do not use `HashMap` for a new property bag that participates in `roundtrip_strict`.

## Testing

| Layer | Location |
| ----- | -------- |
| Wire round-trip | `tests/spec.rs`, `tests/fixtures/spec/` |
| Bundle integration | `tests/bundle.rs` |
| Semantic validation | `tests/validation.rs`, `tests/fixtures/validation/` |
| Validation Pipeline | `tests/validate_conformance.rs`, `tests/validate_diagnostic_coverage.rs`, `tests/validate_pipeline.rs`, `tests/fixtures/conformance/` (`validate` feature) |
| Graph / Marking / Store | `tests/graph.rs`, `tests/marking.rs`, `tests/store.rs`, `tests/store_fs.rs` |
| Streaming + custom types + ATT&CK | `tests/integration.rs` |
| Pattern parse + type-check + evaluation | `tests/pattern_parse.rs`, `tests/pattern_eval.rs`, `tests/pattern_spec_eval.rs`, `tests/pattern_eval_operators.rs`, `tests/pattern_eval_sco_fields.rs`, `tests/pattern_eval_errors.rs`, `tests/pattern_eval_security.rs`, `tests/pattern_indicator.rs`, `tests/fixtures/pattern/`, `tests/fixtures/pattern/sco-fields/` (requires `pattern` feature) |
| Fuzz | `fuzz/fuzz_targets/fuzz_rstix_parse_bundle.rs`, `fuzz/fuzz_targets/fuzz_rstix_validate_json.rs` (`validate` feature) |

Run crate tests:

```bash
cargo test -p rstix --features serde
cargo test -p rstix --features pattern   # Pattern Engine
```

### Local MITRE ATT&CK corpus

The full MITRE ATT&CK STIX bundle (~50 MiB) is available for download and parsing. CI uses a synthetic 5000-object streaming test. For local verification, download a bundle (for example MITRE ATT&CK 19.1) and point the integration test at it:

```bash
RSTIX_ATTCK_BUNDLE=/path/to/enterprise-attack-19.1.json \
  cargo test -p rstix --features serde attck_corpus_roundtrip_when_present -- --nocapture
```

This runs `parse_reader` → serialize → reparse and asserts object count stability. Verified against `enterprise-attack-19.1.json` (~53 MiB) locally.

Paginated TAXII ingest at ATT&CK scale: CI runs a synthetic 5 000-object test; with a local bundle, run `ingest_attck_corpus_paginated_when_present` (`taxii-store` + `validate`, `IngestOptions::producer_strict()`). See [crate README: ATT&CK-scale paginated TAXII ingest](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#attack-scale-paginated-taxii-ingest).

## STIX version vs TLP marking encoding

Three independent ideas: do not mix them:

| | STIX object model | TLP v1 encoding (legacy) | TLP v2 encoding (current) |
| --- | --- | --- | --- |
| **JSON** | `"spec_version": "2.1"` | `"definition_type":"tlp"`, `"definition":{"tlp":"white"}` | `"extensions":{…,"tlp_2_0":"clear"}` |
| **Meaning** | Object follows STIX 2.1 rules | Old TLP label wire format (deprecated for **new** markings) | Current TLP label wire format |
| **rstix constants** | `SpecVersion::V2_1` | `TLP1_WHITE_ID` … `TLP1_RED_ID` | `TLP2_CLEAR_ID` … `TLP2_RED_ID` |

A STIX **2.1** bundle can contain `marking-definition` objects that still use the **legacy TLP v1 encoding**: that is normal (ATT&CK references the predefined v1 UUIDs).

Full developer guide: [crate README: STIX version vs TLP marking encoding](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#stix-version-vs-tlp-marking-encoding).

## Validation tiers

| Tier | API | Severity | Examples |
| ---- | --- | -------- | -------- |
| **T0: parse** | `Bundle::parse`, `parse_reader`, leaf `Deserialize` | Hard error | Type discriminants, bundle container rules, in-bundle ref existence and ref kinds, DD-DM-001 domain/email/url format, ipv4/ipv6/mac address format, hash-algorithm-ov keys, closed enumerations at parse, granular selector semantics, language-content §7.1.1 mirroring for existing target fields, SCO MUST in `validate()` at deserialize |
| **T1: advisory** | `Bundle::validate()` | Warnings only | CAPEC/CVE external refs, TLP v1 (STIX-W0031), location ISO 3166, SCO deterministic id; parse-enforced rules still warn on `Bundle::from_objects()` bundles |
| **T2: pipeline** | `Validator` profiles (`validate` feature) | Structured diagnostics | All twelve validation phases; open-vocabulary extensions (`STIX-I0001`, Info: does not fail `interop_strict` per STIX §2.14); relationship matrix (`STIX-I0002`, Warning: fails `interop_strict`) |

Full detail: [crate README: Validation tiers](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#validation-tiers).

## Wire conformance (STIX 2.1)

Normative MUST rules wired at T0 parse are listed in [Model invariants](#rstix-model-invariants-summary). Negative fixtures live under `tests/fixtures/spec/`, `tests/fixtures/validation/`, and `tests/fixtures/conformance/`; wire-negative cases in `tests/spec.rs` fail parse and `Validator::interop_strict()`.

Full invariant table: [crate README: Model invariant decisions](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#model-invariant-decisions).

## Model invariants (summary)

Full table: [crate README: Model invariant decisions](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#model-invariant-decisions).

- **T0 (parse):** id/type match, in-bundle ref resolution, extension routing, SCO forbidden common props, SDO/SRO time ordering, DD-DM-001 domain/email/url format (full RFC 3986 for URLs), ipv4/ipv6/mac address format, hash-algorithm-ov key policy (`HASH_ALGORITHM_ENUM` or `x_` extension), open-vocab checks on grouping `context` and malware-analysis `result`, non-empty SDO `name`, non-empty report/grouping/note/opinion `object_refs`, artifact `encryption_algorithm` closed enum, granular selector resolution, language-content §7.1.1 mirroring for existing target fields (unknown target fields ignored), `_enc` IANA charset + pairing, and type-specific MUST rules in `ModelError`.
- **T1 (`Bundle::validate()`):** relationship matrix advisory on the bundle path, CAPEC/CVE, TLP v1 warnings (STIX-W0031), location country ISO 3166, SCO deterministic id; parse-enforced semantics still warn on bundles assembled with `Bundle::from_objects()`.
- **T2 (`interop_strict`):** `STIX-I0001` (open-vocab extension values such as unknown `location.region`) and `STIX-I0002` (relationship matrix) emit **Warning** severity and fail validation under zero leniency.
- **Map types:** wire-facing property bags use `BTreeMap` for deterministic JSON key order; internal id indexes use `HashMap`.

Pattern Engine engineering choices (separate from STIX spec invariants): [Pattern Engine design decisions](#rstix-graph-marking-store-pattern-engine-design-decisions).

## Validation Pipeline

Optional **`validate`** feature (implies `serde` + `pattern`) adds profile-based **`Validator`** with structured `STIX-E/W/I/H` diagnostics (T2). Advisory **`Bundle::validate()`** (T1) is available with **`serde` alone**; with `validate` enabled both paths share the same semantic check implementations: see **DD-VP-001** in the crate README.

| Profile | Phases | Use case |
| ------- | ------ | -------- |
| `consumer_permissive` | JSON, type, schema, references (4 of 12) | Mixed-trust ingest |
| `consumer_strict` | all 12 | Untrusted external input |
| `producer_strict` | all except references (11 of 12) | Publishing/export |
| `interop_strict` | all 12, zero leniency | OASIS interop tests |

```rust
use rstix::validate::{Validator, ValidationPhase};

let report = Validator::consumer_strict().validate_json_str(untrusted_json);
assert!(report.is_valid());

let partial = Validator::builder()
    .with_phase(ValidationPhase::Schema)
    .build()
    .validate_bundle(&bundle);
```

All twelve pipeline checks are implemented. The conformance harness (`tests/fixtures/conformance/`) and `validate_diagnostic_coverage` assert one case per `DiagnosticCode::ALL` entry (39 codes).

## Feature flags

| Feature | Purpose |
| ------- | ------- |
| `serde` (default) | Bundle parsing, serialization, advisory validation. |
| `pattern` | STIX pattern lexer, Level 1–3 parser, type-checker, and evaluator. |
| `validate` | Profile-based Validation Pipeline (`Validator`, structured diagnostics, conformance corpus). |
| `graph` | Property graph over parsed bundles (`StixGraph`, `RelationshipExpander`). |
| `marking` | TLP and statement marking resolution (`MarkingResolver`, granular selectors). |
| `store` | In-memory STIX store (`MemoryStore`, `StixQuery`, `ImportReport`). |
| `store-fs` | Filesystem-backed durable store (`FsStore`; implies `store`). |
| `taxii` | TAXII 2.1 HTTP client (`TaxiiClient`, `TaxiiEnvelope`, auth, pagination, retry, rustls TLS, DANE, DNS SRV). |
| `taxii-store` | TAXII collection ingest into `StixStore` (`ingest_collection`; implies `taxii` + `store`). |

## Related docs

- [Architecture: crate map](../reference/architecture.md#architecture-rstix)
- [Feature flags: rstix](../reference/feature-flags.md#feature-flags-rstix)
- [Fuzzing: `fuzz_rstix_parse_bundle`](../developers/fuzzing.md)
- [Fuzzing: `fuzz_rstix_validate_json`](../developers/fuzzing.md)
- [Crate README](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md)
