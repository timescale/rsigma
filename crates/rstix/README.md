# rstix

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rstix` is a Rust library crate for STIX 2.1 and TAXII 2.1 in the rsigma workspace.
Phase 1 (Core Foundation) is complete: core primitive types, deterministic SCO ID helpers,
and vocabulary tables are available for downstream model/validation phases.

Phase 2 (Data Model + Serialization) is **in progress**. Slice 1 lands the model skeleton,
leaf-type serde, and shared common property structures (`model::common`). This slice is
not releasable on its own; typed object enums, bundle parsing, and validation follow in
later slices.

This library is part of [rsigma].

## Public API

### Entry points

- `parse_bundle(json: &str)`: top-level STIX bundle parse entrypoint. In the current phase it returns `Err(ParseError::NotImplemented)`.
- `core::StixId::parse(id: &str)`: parse and validate STIX object IDs in `{type}--{uuid}` form.
- `core::StixId::generate(type_name: &str)`: create a random UUIDv4-based STIX ID for a type prefix.
- `id::generate_sco_id(kind, value)`: generate deterministic SCO IDs using canonicalized contributing properties.
- `id::select_id_contributing_properties(kind, value)`: extract SCO id-contributing fields.
- `id::jcs_canonicalize(value)`: canonicalize JSON for deterministic ID derivation.

### Error types

- `ParseError`: top-level parse error enum. The current phase includes only `NotImplemented`.
- `model::ModelError`: model-level invariant violations (for example non-empty `source_name`, granular-marking exclusivity).
- `core::StixIdError`: errors for STIX ID parsing and typed-ID conversion.
- `core::TimestampError`: errors for STIX/TAXII timestamp parsing.
- `core::ConfidenceError`: confidence range and scale-label errors.
- `core::LanguageTagError`: language tag parsing errors.
- `id::DeterministicIdError` / `id::JcsError`: deterministic SCO-ID derivation errors.

### Module surface

- `core` (always): `StixId`, typed IDs (42 wrappers), `StixObjectKind` + SDO/SCO/SRO/Meta discriminants, `StixTimestamp`, `TaxiiTimestamp`, `Confidence` and built-in scales, `SpecVersion`, `LanguageTag`, `QueryableStixObject`, `QueryValue`.
- `model` (always): `ModelError`; `model::common` — `SdoSroCommonProps`, `ScoCommonProps`, `ExternalReference`, `GranularMarking`, `ExtensionMap`, and related types.
- `id` (always): deterministic SCO ID derivation (`select_id_contributing_properties`, canonicalization, UUIDv5 generation).
- `vocab` (always): open/closed vocabulary tables and `OpinionValue` ordering enum.
- `serde_impls` (internal, `serde` feature): hand-written serializers for `StixId` and timestamps; typed-ID serde is generated in the `define_typed_id!` macro.

## Feature flags

- `serde` (default): enables serialization and deserialization support.

## Current Phase Status

- **Phase:** 2 in progress (slice 1 of ~7)
- **Implemented in slice 1:** `model` skeleton, leaf-type serde (`StixId`, timestamps, typed IDs, `LanguageTag`), and `model::common` property containers with fixture-backed integration tests.
- **Deferred to later slices:** typed SDO/SCO/SRO/Meta objects, `StixObject` dispatch, `Bundle` parsing, validation pipeline, graph/marking/store/TAXII runtime behaviors.

## Usage

```rust
use rstix::core::{IndicatorId, StixId, StixTimestamp};
use rstix::model::common::SdoSroCommonProps;
use rstix::{parse_bundle, ParseError};

let result = parse_bundle(r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000"}"#);
assert!(matches!(result, Err(ParseError::NotImplemented)));

let id = StixId::generate("indicator");
let typed = IndicatorId::from_stix_id(id).unwrap();
assert_eq!(typed.as_stix_id().type_name(), "indicator");

let ts = StixTimestamp::parse("2016-05-12T08:17:27.000Z").unwrap();
let common = SdoSroCommonProps::new(StixId::generate("campaign"), ts.clone(), ts);
let json = serde_json::to_string(&common).unwrap();
assert!(json.contains("\"spec_version\":\"2.1\""));
```

## Development Notes

- `rstix` follows rsigma workspace standards for MSRV, edition, lint policy, and CI checks.
- STIX wire-format tests: `tests/spec.rs` with JSON fixtures under `tests/fixtures/spec/`. Core parse/serde unit tests stay in `src/`.
- Release notes belong to the repository root `CHANGELOG.md` only.
- Public API and behavior updates must be synchronized with workspace docs under `docs/`.

## License

MIT License.

[rsigma]: https://github.com/timescale/rsigma
