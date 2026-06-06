# rstix

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rstix` is a Rust library crate for STIX 2.1 and TAXII 2.1 in the rsigma workspace.
Phase 1 (Core Foundation) is now implemented: core primitive types, deterministic SCO ID helpers,
and vocabulary tables are available for downstream model/validation phases.

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
- `core::StixIdError`: errors for STIX ID parsing and typed-ID conversion.
- `core::TimestampError`: errors for STIX/TAXII timestamp parsing.
- `core::ConfidenceError`: confidence range and scale-label errors.
- `core::LanguageTagError`: language tag parsing errors.
- `id::DeterministicIdError` / `id::JcsError`: deterministic SCO-ID derivation errors.

### Module surface

- `core` (always): `StixId`, typed IDs (42 wrappers), `StixObjectKind` + SDO/SCO/SRO/Meta discriminants, `StixTimestamp`, `TaxiiTimestamp`, `Confidence` and built-in scales, `SpecVersion`, `LanguageTag`, `QueryableStixObject`, `QueryValue`.
- `id` (always): deterministic SCO ID derivation (`select_id_contributing_properties`, canonicalization, UUIDv5 generation).
- `vocab` (always): open/closed vocabulary tables and `OpinionValue` ordering enum.
- `serde_impls` (`serde`): custom serialization/deserialization support.

## Feature flags

- `serde` (default): enables serialization and deserialization support.

## Current Phase Status

- **Phase:** 1 (Core Foundation) complete
- **Implemented in this phase:** core primitives (`core`), deterministic SCO ID helpers (`id`), and vocabulary tables (`vocab`) with tests and strict lint/build validation.
- **Deferred to later phases:** STIX object model, serialization dispatch, pattern engine, validation pipeline, graph/marking/store/taxii runtime behaviors.

## Usage

```rust
use rstix::core::{IndicatorId, StixId};
use rstix::id::generate_sco_id;
use rstix::{parse_bundle, ParseError};

let result = parse_bundle(r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000"}"#);
assert!(matches!(result, Err(ParseError::NotImplemented)));

let id = StixId::parse("indicator--550e8400-e29b-41d4-a716-446655440000").unwrap();
let typed = IndicatorId::from_stix_id(id).unwrap();
assert_eq!(typed.as_stix_id().type_name(), "indicator");

let file = serde_json::json!({"hashes":{"SHA-256":"abc"}});
let sco_id = generate_sco_id(rstix::core::ScoKind::File, &file).unwrap();
assert!(sco_id.as_str().starts_with("file--"));
```

## Development Notes

- `rstix` follows rsigma workspace standards for MSRV, edition, lint policy, and CI checks.
- Release notes belong to the repository root `CHANGELOG.md` only.
- Public API and behavior updates must be synchronized with workspace docs under `docs/`.

## License

MIT License.

[rsigma]: https://github.com/timescale/rsigma
