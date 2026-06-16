# rstix

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rstix` is a Rust library crate for STIX 2.1 and TAXII 2.1 in the rsigma workspace.
Phase 1 (Core Foundation) is complete: core primitive types, deterministic SCO ID helpers,
and vocabulary tables are available for downstream model/validation phases.

Phase 2 (Data Model + Serialization) is **in progress**. The `model::common`, `model::meta`, and `model::sro` modules are in place; typed SCO/SDO objects, `StixObject` dispatch, and `Bundle` parsing follow in later work.

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
- `model::ModelError`: model-level invariant violations (for example non-empty `source_name`, external-reference §2.5.2 detail fields, granular-marking exclusivity and selectors).
- `core::StixIdError`: errors for STIX ID parsing and typed-ID conversion.
- `core::TimestampError`: errors for STIX/TAXII timestamp parsing.
- `core::ConfidenceError`: confidence range and scale-label errors.
- `core::LanguageTagError`: language tag parsing errors.
- `id::DeterministicIdError` / `id::JcsError`: deterministic SCO-ID derivation errors.

### Module surface

- `core` (always): `StixId`, typed IDs (42 wrappers), `StixObjectKind` + SDO/SCO/SRO/Meta discriminants, `StixTimestamp`, `TaxiiTimestamp`, `Confidence` and built-in scales, `SpecVersion`, `LanguageTag`, `QueryableStixObject`, `QueryValue`.
- `model` (always): `ModelError`; `model::common` — `SdoSroCommonProps`, `ScoCommonProps`, `ExternalReference`, `GranularMarking`, `ExtensionMap`, and related types; `model::meta` — `MarkingDefinition`, `ExtensionDefinition`, `LanguageContent`, `MetaObject`, and TLP UUID constants; `model::sro` — `Relationship`, `Sighting`, `WhereSightedRef`, `SroObject`, `RelSourceRef`, `RelTargetRef`, `SightingOfRef`, and `Sighting::COUNT_MAX`.
- `id` (always): deterministic SCO ID derivation (`select_id_contributing_properties`, canonicalization, UUIDv5 generation).
- `vocab` (always): open/closed vocabulary tables and `OpinionValue` ordering enum.
- `serde_impls` (internal, `serde` feature): hand-written serializers for `StixId`, timestamps, and `Confidence`; typed-ID serde is generated in the `define_typed_id!` macro.

## Feature flags

- `serde` (default): enables serialization and deserialization support.

## Current Phase Status

- **Phase:** 2 in progress (`model::common`, `model::meta`, and `model::sro` landed)
- **Implemented:** `model::common`, leaf-type serde, `model::meta` (marking-definition, extension-definition, language-content), and `model::sro` (relationship, sighting) with fixture-backed tests.
- **Deferred:** SCO/SDO typed objects, `StixObject` dispatch, `Bundle` parsing, validation pipeline, graph/marking/store/TAXII runtime behaviors.

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
- Release notes belong to the repository root `CHANGELOG.md` only.
- Public API and behavior updates must be synchronized with workspace docs under `docs/`.

### Testing layout

Two layers, consistent across Phase 2:

| Layer | Location | Purpose |
| ----- | -------- | ------- |
| **Wire / JSON** | `tests/spec.rs` + `tests/fixtures/spec/` | Deserialize → serialize → reparse; negative fixtures; `roundtrip_strict` for complete types, subset `roundtrip` for common-property-only structs. |
| **Unit** | `#[cfg(test)]` in `src/` | Invariants, normative constant pins, and parse smoke tests that do not need a dedicated fixture file (or that use `include_str!` for a single inline read). |

Do not duplicate wire-format coverage in unit tests. Do not put fixture-backed integration tests under `src/test_support/`.

### STIX version vs TLP marking encoding

Developers often conflate three independent ideas. They are **not** the same axis:

| Concept | JSON signal | What it means | rstix API |
| ------- | ----------- | ------------- | --------- |
| **STIX object model** | `"spec_version": "2.1"` on any object | The object follows STIX **2.1** field rules. | `SpecVersion::V2_1` |
| **TLP v1 encoding** (legacy) | `"definition_type": "tlp"` and `"definition": {"tlp":"white"}` | Old way to embed a TLP label inside a `marking-definition`. **Deprecated for new markings** in STIX 2.1, but still in real bundles. | Match ids with `TLP1_WHITE_ID`, …, `TLP1_RED_ID`; read `MarkingDefinition::definition_type` / `definition` |
| **TLP v2 encoding** (current) | `"extensions": { … "tlp_2_0": "clear" }` | Current way predefined TLP markings are represented. | Match ids with `TLP2_CLEAR_ID`, …, `TLP2_RED_ID`; read `MarkingDefinition::extensions` |

**Key point:** a STIX **2.1** bundle routinely contains `marking-definition` objects that use the **legacy TLP v1 encoding**. That is why a fixture named `marking-definition-tlp-v1-white-stix21.json` has both `spec_version: "2.1"` and `definition_type: "tlp"` — the filename means *TLP wire encoding v1*, not *STIX version 1*.

```
STIX 2.1 bundle
└── marking-definition  (spec_version: "2.1")
    ├── Legacy path  ──► definition_type + definition     ← TLP v1 encoding (parse-only for ingestion)
    └── Current path ──► extensions.tlp_2_0             ← TLP v2 encoding (preferred for new content)
```

**What is deprecated in STIX 2.1 (meta objects on this branch):**

- Only the **TLP v1 encoding** (`definition_type` / `definition` for TLP labels). STIX 2.1 says producers should use TLP v2 (`extensions`) for new markings. rstix still **parses** v1 because ATT&CK and other feeds reference the four predefined v1 UUIDs.
- Phase 4 validation will emit **STIX-W0031** when v1 encoding is detected. Phase 2 does not warn yet — it deserializes.

**What is not deprecated:** `ExtensionDefinition`, `LanguageContent`, statement markings (`definition_type: "statement"`), and all five TLP v2 predefined markings.

**How to use the constants in application code:**

```rust
use rstix::core::StixId;
use rstix::model::meta::{MarkingDefinition, TLP1_WHITE_ID, TLP2_CLEAR_ID};

fn is_legacy_tlp_white(marking_id: &StixId) -> bool {
    marking_id.as_str() == TLP1_WHITE_ID
}

fn is_current_tlp_clear(marking_id: &StixId) -> bool {
    marking_id.as_str() == TLP2_CLEAR_ID
}

// After parsing a MarkingDefinition from JSON:
fn tlp_encoding(m: &MarkingDefinition) -> &'static str {
    if !m.extensions.is_empty() {
        "tlp-v2-extensions"
    } else if m.definition_type.as_deref() == Some("tlp") {
        "tlp-v1-legacy"
    } else {
        "other"
    }
}
```

Prefer **id comparison** (`TLP1_*` / `TLP2_*`) on `object_marking_refs` when you only need to know which predefined marking was applied. Inspect `definition` vs `extensions` only when you need the on-object encoding details.

**Test fixtures** under `tests/fixtures/spec/meta/` follow the naming pattern `marking-definition-tlp-v{1|2}-<level>-stix21.json`: TLP **encoding** version + level + STIX **2.1** object model.

### TLP marking-definition UUID constants

`model::meta::marking_def` exports nine public `TLP*` constants (four TLP 1.x + five TLP 2.0 predefined `marking-definition` ids from the STIX specification). Callers compare `object_marking_refs` and granular markings against these ids without loading JSON.

**Why the values are hardcoded:** they are normative spec identifiers, not application configuration. The constants are the public API surface for known TLP markings (the same pattern as Phase 1 SCO ID golden vectors).

**Why `constants_match_spec_ids` exists:** the unit test `constants_match_spec_ids` in `marking_def.rs` pins all nine ids against the spec literals so a mistaken edit to a `pub const` fails CI. It does not parse JSON; it guards the full constant set in one place.

**Relationship to wire tests:** `tests/spec.rs` round-trips `marking-definition-tlp-v1-white-stix21.json` (legacy TLP v1 encoding on a STIX 2.1 object) and `marking-definition-tlp-v2-clear-stix21.json` (current TLP v2 encoding). Parsed ids must match `TLP1_WHITE_ID` and `TLP2_CLEAR_ID`. See [STIX version vs TLP marking encoding](#stix-version-vs-tlp-marking-encoding) above.

**Limitation (intentional):** `constants_match_spec_ids` compares each constant to a duplicate literal in the test. It catches const drift relative to the test’s spec copy; wire round-trips independently validate parsing for the fixtures that exist.

### Model invariant decisions (`model::common`)

Phase 2 validates STIX invariants at deserialize time (and via `new` / `validate` for programmatic construction). Where the spec distinguishes “absent” from “invalid”, rstix **enforces** at parse time rather than deferring to a later validation pipeline:

| Area | Enforced behavior | Why not defer? |
| ---- | ----------------- | -------------- |
| `confidence` on SDO/SRO common props | `Option<Confidence>` — omitted in JSON → `None`; present values use typed `Confidence` (range + scale). | Distinguishes “not set” from “set to zero/unknown”; avoids silently accepting out-of-range integers. |
| `external-reference` (STIX §2.5.2) | Non-empty `source_name` **and** at least one of `description`, `url`, or `external_id`. | `source_name`-only objects are invalid per spec; rejecting at deserialize catches bad CTI data early. Negative fixture: `external-reference-source-only.json`. |
| `granular-marking` selectors | Field is **required** on deserialize (no `#[serde(default)]`); must be non-empty in `validate()`. | Empty or missing selectors are invalid; `with_marking_ref` / `with_lang` delegate to `new()` so the same rules apply programmatically. |
| `ExtensionDefinition.created_by_ref` | Required on deserialize (`ExtensionDefinitionMissingCreatedByRef`). | STIX §7.2.2 requires the authoring identity reference for extension definitions. |
| `Relationship.relationship_type` | ASCII `[a-z0-9-]` only; `stop_time` must be later than `start_time` when both set. | STIX §5.1.2 charset and time-window MUST rules. |
| `Sighting.count` | `0..=999_999_999` when present. | STIX §5.2.1 inclusive range. |
| `Sighting` time window | `last_seen >= first_seen` when both set. | STIX §5.2.1 ordering rule. |
| `Sighting.where_sighted_refs` | Each entry must be `identity` or `location` (`WhereSightedRef`). | STIX §5.2.1 reference targets. |
| `Relationship` / `Sighting` ref targets | `source_ref`, `target_ref`, `sighting_of_ref` accept any valid `StixId` at deserialize. | SDO/SCO-only / SDO-only validation deferred until `StixObject` dispatch. |
| `ExtensionMap` | Public `insert()` mirrors `BTreeMap` semantics. | Programmatic extension assembly without reaching into the inner map. |
| Round-trip helpers (`tests/support/roundtrip.rs`) | `roundtrip_strict`: re-serialized JSON must equal the fixture (complete types — meta objects, SRO objects, `ExternalReference`, `GranularMarking`, `ExtensionMap`). `roundtrip`: subset compare — every emitted field must match the fixture, extra fixture keys allowed, dropped fields not caught on object fixtures; use for `SdoSroCommonProps` / `ScoCommonProps` fixtures that carry unmodeled SDO keys until concrete SDO types land. | Strict mode catches dropped fields today; subset mode matches the Phase 2 common-prop testing contract from PR #201. |

## License

MIT License.

[rsigma]: https://github.com/timescale/rsigma
