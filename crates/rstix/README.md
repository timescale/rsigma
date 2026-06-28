# rstix

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rstix` is a Rust library crate for STIX 2.1 and TAXII 2.1 in the rsigma workspace.
**Core Foundation** is complete: core primitive types, deterministic SCO ID helpers,
and vocabulary tables are available for downstream model/validation phases.

**Data Model + Serialization** is **in progress**. The `model::common`, `model::meta`, `model::sdo`, `model::sro`, `model::sco`, `StixObject`, and `Bundle` layers are in place with fixture-backed tests. Streaming bundle parse, custom type registry, and the **Validation Pipeline** follow in later work.

This library is part of [rsigma].

## Public API

### Entry points

- `parse_bundle(json: &str)`: parse a STIX 2.1 bundle into a typed [`Bundle`](model::Bundle) (alias for [`Bundle::parse`](model::Bundle::parse)).
- `model::Bundle::parse_with_options(json, opts)`: bundle parse with [`ParseOptions`](model::ParseOptions) (custom types, object limits).
- `core::StixId::parse(id: &str)`: parse and validate STIX object IDs in `{type}--{uuid}` form.
- `core::StixId::generate(type_name: &str)`: create a random UUIDv4-based STIX ID for a type prefix.
- `id::generate_sco_id(kind, value)`: generate deterministic SCO IDs using canonicalized contributing properties.
- `id::select_id_contributing_properties(kind, value)`: extract SCO id-contributing fields.
- `id::jcs_canonicalize(value)`: canonicalize JSON for deterministic ID derivation.

### Error types

- `ParseError`: top-level parse error enum (JSON errors, bundle shape, duplicate ids, object limits, unknown types, and wrapped `ModelError`).
- `model::ModelError`: model-level invariant violations (for example non-empty `source_name`, external-reference §2.5.2 detail fields, granular-marking exclusivity and selectors).
- `core::StixIdError`: errors for STIX ID parsing and typed-ID conversion.
- `core::TimestampError`: errors for STIX/TAXII timestamp parsing.
- `core::ConfidenceError`: confidence range and scale-label errors.
- `core::LanguageTagError`: language tag parsing errors.
- `id::DeterministicIdError` / `id::JcsError`: deterministic SCO-ID derivation errors.

### Module surface

- `core` (always): `StixId`, typed IDs (42 wrappers), `StixObjectKind` + SDO/SCO/SRO/Meta discriminants, `StixTimestamp`, `TaxiiTimestamp`, `Confidence` and built-in scales, `SpecVersion`, `LanguageTag`, `QueryableStixObject`, `QueryValue`.
- `model` (always): `ModelError`; `model::common` — `SdoSroCommonProps`, `ScoCommonProps`, `ExternalReference`, `GranularMarking`, `ExtensionMap`, `KillChainPhase`, and related types; `model::meta` — `MarkingDefinition`, `ExtensionDefinition`, `LanguageContent`, `MetaObject`, and TLP UUID constants; `model::sdo` — all 19 STIX domain objects, `SdoObject`, `IndicatorPattern`, `ObservedDataForm`, and typed ref unions (`MalwareSampleRef`, `MalwareAnalysisSampleRef`); `model::sro` — `Relationship`, `Sighting`, `WhereSightedRef`, `SroObject`, `RelSourceRef`, `RelTargetRef`, `SightingOfRef`, and `Sighting::COUNT_MAX`; `model::sco` — all 18 STIX cyber-observable types, `ScoObject`, typed ref unions (`ref_types`), and 12 predefined SCO extensions under `model::sco::extensions`; `model::StixObject` — top-level enum dispatching SDO/SCO/SRO/Meta plus `CustomStixObject`; `model::Bundle` — bundle container with ref validation and `x_*` property capture; `model::ParseOptions` / `TypeRegistry` — parse-time limits and optional custom type registration.
- `id` (always): deterministic SCO ID derivation (`select_id_contributing_properties`, canonicalization, UUIDv5 generation).
- `vocab` (always): open/closed vocabulary tables and `OpinionValue` ordering enum.
- `serde_impls` (internal, `serde` feature): hand-written serializers for `StixId`, timestamps, and `Confidence`; typed-ID serde is generated in the `define_typed_id!` macro.

## Feature flags

- `serde` (default): enables serialization and deserialization support.

## Current Phase Status

- **Phase:** Data Model + Serialization in progress (`model::common`, `model::meta`, `model::sdo`, `model::sro`, `model::sco`, `StixObject`, and `Bundle` landed)
- **Implemented:** full typed object model for meta, all 19 SDOs, SROs, 18 SCOs (+ 12 extensions), `StixObject` dispatch, `Bundle::parse`, bundle-scoped reference existence checks, `x_*` top-level property capture, and `parse_bundle()`.
- **Deferred to later phases:** **Validation Pipeline** semantic checks (granular selector paths, language-content nested rules, STIX-W0031), **Pattern Engine** indicator AST, graph/store/TAXII runtime behaviors.
- **Data Model + Serialization** ship gate: optional real MITRE ATT&CK corpus via `RSTIX_ATTCK_BUNDLE` / `tests/fixtures/corpus/enterprise-attack.json` (synthetic large-bundle tests run in CI today).

## Usage

```rust
use rstix::core::{IndicatorId, StixId, StixTimestamp};
use rstix::model::common::SdoSroCommonProps;
use rstix::parse_bundle;

let bundle = parse_bundle(
    r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000","objects":[]}"#,
)
.unwrap();
assert_eq!(bundle.id().type_name(), "bundle");

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

Two layers, consistent across the Data Model + Serialization phase:

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
- The **Validation Pipeline** will emit **STIX-W0031** when v1 encoding is detected. Data Model + Serialization does not warn yet — it deserializes.

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

**Why the values are hardcoded:** they are normative spec identifiers, not application configuration. The constants are the public API surface for known TLP markings (the same pattern as Core Foundation SCO ID golden vectors).

**Why `constants_match_spec_ids` exists:** the unit test `constants_match_spec_ids` in `marking_def.rs` pins all nine ids against the spec literals so a mistaken edit to a `pub const` fails CI. It does not parse JSON; it guards the full constant set in one place.

**Relationship to wire tests:** `tests/spec.rs` round-trips `marking-definition-tlp-v1-white-stix21.json` (legacy TLP v1 encoding on a STIX 2.1 object) and `marking-definition-tlp-v2-clear-stix21.json` (current TLP v2 encoding). Parsed ids must match `TLP1_WHITE_ID` and `TLP2_CLEAR_ID`. See [STIX version vs TLP marking encoding](#stix-version-vs-tlp-marking-encoding) above.

**Limitation (intentional):** `constants_match_spec_ids` compares each constant to a duplicate literal in the test. It catches const drift relative to the test’s spec copy; wire round-trips independently validate parsing for the fixtures that exist.

### Model invariant decisions (`model::common`)

The **Data Model + Serialization** phase validates STIX invariants at deserialize time (and via `new` / `validate` for programmatic construction). Where the spec distinguishes “absent” from “invalid”, rstix **enforces** at parse time rather than deferring to a later validation pipeline.

**Spec audit record:** open vs resolved differentials vs `plan/stix-v2.1-spec.md` are documented in `plan/spec-differential-status.md` (local plan folder; not committed to git).

| Area | Enforced behavior | Why not defer? |
| ---- | ----------------- | -------------- |
| `confidence` on SDO/SRO common props | `Option<Confidence>` — omitted in JSON → `None`; present values use typed `Confidence` (range + scale). | Distinguishes “not set” from “set to zero/unknown”; avoids silently accepting out-of-range integers. |
| `external-reference` (STIX §2.5.2) | Non-empty `source_name` **and** at least one of `description`, `url`, or `external_id`. | `source_name`-only objects are invalid per spec; rejecting at deserialize catches bad CTI data early. Negative fixture: `external-reference-source-only.json`. |
| `granular-marking` selectors | Field is **required** on deserialize (no `#[serde(default)]`); must be non-empty in `validate()`. | Empty or missing selectors are invalid; `with_marking_ref` / `with_lang` delegate to `new()` so the same rules apply programmatically. |
| `ExtensionDefinition.created_by_ref` | Required on deserialize (`ExtensionDefinitionMissingCreatedByRef`). | STIX §7.2.2 requires the authoring identity reference for extension definitions. |
| `Relationship.relationship_type` | ASCII `[a-z0-9-]` only; `stop_time` must be later than `start_time` when both set; per-type source/target matrix from STIX 2.1 relationship tables (55 forward entries + common `related-to` / `derived-from` / `duplicate-of`). | STIX §5.1.2 charset, time-window, and relationship context tables. |
| `Sighting.summary` | Wire bool or string; stored as `Option<String>` (`true`/`false` normalized); serializes bool for `"true"`/`"false"`. | STIX §5.2.1 boolean default with string wire form. |
| SDO/SRO common props | `SdoSroCommonProps::validate`: id prefix matches `type`, `modified >= created`, marking refs not self, ref kind checks for `created_by_ref` / marking refs, `ExtensionMap::validate`. | STIX §3.2 / §7.2.1 shared invariants centralized in `model/validate.rs`. |
| Bundle container | Rejects bundle `spec_version`; requires bundle id prefix; `validate_refs` checks existence + ref kinds + language-content `object_modified` match; serialize merges `x_*` from `extra_properties`. | STIX §8 bundle rules; no default object count cap (`usize::MAX`). |
| SDO invariants | Removed stricter-than-spec empty-name / empty-list checks on grouping context length, note/opinion/report refs, malware-analysis product emptiness and analysis window ordering. Retained spec MUST rules: observed-data XOR + ordering + count range; indicator time window; malware family name when `is_family: true`; malware-analysis result/sco_refs + SCO kind on `analysis_sco_refs`; location geo rules; kill-chain phase empties; `OpinionValue` closed vocab; CAPEC/CVE external ref shape on attack-pattern/vulnerability; malware sample_refs same binary when `is_family: false`. | Align deserialize validation with STIX property tables — optional/empty wire values no longer rejected when spec is silent. |
| `Relationship` per-type matrix | Enforced via `validate_relationship_endpoints` (was deferred). | Previously README listed as Validation Pipeline deferral. |
| `language-content` | `object_modified` is `Option<StixTimestamp>`; `lang` rejected on common props; bundle validates match to target `modified`. | STIX §7.2.4. |
| `marking-definition` | `spec_version` required; legacy `definition_type` + `definition` required when `extensions` empty. | STIX §7.2.1. |
| `extension-definition` | Rejects `extensions`, `confidence`, and `lang` on common props. | STIX §7.2.2 forbidden common properties. |
| SCO ref/format checks | `file.contains_refs` SCO kind; domain-name/email-addr/url basic format validation; artifact `encryption_algorithm` closed vocab; observed-data `object_refs` SCO or SRO kind. | STIX §6 reference targets and vocabularies. |
| Extension map | Predefined extension keys (`*-ext`, TLP definition id) must not carry `extension_type`; toplevel-property-extension entries peeled before typed deserialize and hoisted keys stored in `extra_properties` (with unmodeled top-level keys captured on reparse). | STIX §3.10 / §7.3. |
| `Sighting.count` | `0..=999_999_999` when present. | STIX §5.2.1 inclusive range. |
| `Sighting` time window | `last_seen >= first_seen` when both set. | STIX §5.2.1 ordering rule. |
| `Sighting.where_sighted_refs` | Each entry must be `identity` or `location` (`WhereSightedRef`). | STIX §5.2.1 reference targets. |
| `Relationship` / `Sighting` ref kind | `source_ref` / `target_ref` must be SDO or SCO kinds; `sighting_of_ref` must be SDO kind (checked via `StixObjectKind` on the id prefix). | STIX §5.1.2 / §5.2.1 reference target classes. |
| Bundle reference existence | After parse, every collected internal ref must resolve to an object id present in the same bundle (`BundleReferenceMissing`). | Cross-object integrity within a bundle; standalone object JSON does not run this pass. |
| `x_*` top-level properties | Keys prefixed `x_` are peeled before typed deserialize and stored in `Bundle::extra_properties()` keyed by object id; re-merged on bundle serialize. | ATT&CK and vendor extensions (Group H3); typed fields remain lossless. |
| SDO `type` field | Each SDO struct rejects wrong/missing `"type"` at deserialize. | Same single-pass validation as SRO/meta/SCO objects. |
| SDO typed refs | `Malware.operating_system_refs` and `MalwareAnalysis` VM/OS/software refs use `SoftwareId`; sample refs use typed unions. | STIX §4.11.1 / §4.12.1 software-object constraints. |
| `Indicator.pattern` | Stored as `IndicatorPattern` enum (`Stix` vs `Other`); wire JSON remains flat `pattern` / `pattern_type` / `pattern_version`. | Separates STIX patterning from other languages without **Pattern Engine** AST parse. |
| `ObservedData` content | `ObservedDataForm` enum: `ObjectRefs` XOR `DeprecatedObjects` (embedded `ScoObject` map). | STIX §4.14 mutual exclusion. |
| `SdoObject` / `StixObject` | `#[non_exhaustive]`; `created()` / `modified()` populated for SDO/SRO/Meta arms, `None` for SCO. | STIX §3.2 common property rules. |
| SCO `type` field | Each SCO struct rejects wrong/missing `"type"` at deserialize (`UnexpectedObjectType`). | Same single-pass validation as SRO/meta/SDO objects. |
| SCO invariants (artifact, file, email-message, network-traffic, process, user-account, …) | Enforced in `validate()` called from custom `Deserialize`; see `ModelError` variants. | Spec MUST rules (payload XOR url, hashes or name, multipart body rules, protocols + endpoint refs, at-least-one-property types). |
| SCO typed ref unions | `DomainNameResolvesToRef`, `DirectoryContainsRef`, `NetworkTrafficEndpointRef`, `EmailMimeBodyRawRef` reject wrong target types at deserialize. | STIX §6 union ref targets. |
| SCO extensions | Parent types (`File`, `NetworkTraffic`, `Process`, `UserAccount`) call `validate_in_map` for known extension keys during `validate()`. Negative unit fixtures: shared `extensions/no-properties.json` for empty-body `*NoProperties` cases, plus per-extension invalid payloads where the failure mode differs. Parent `*-with-invalid-*-ext.json` fixtures in `spec.rs` prove dispatch. `ExtensionDeserializeFailed { key, detail }` preserves serde context. | Predefined extension invariants (STIX 2.1 §3.10). |
| `Process` at-least-one-property | §6.13 type-specific fields **or** `windows-process-ext` / `windows-service-ext` key present; extension body validated separately. | `plan/stix-v2.1-spec.md` §6.13. |
| `UserAccount` at-least-one-property | §6.16.1 specific fields **or** `unix-account-ext` key present; extension body validated separately (`windows-registry-key` checks §6.17.1 fields only — no predefined extension). | `plan/stix-v2.1-spec.md` §6.16 / §6.16.2 / §6.17. |
| `ScoObject` / `QueryValue` | `#[non_exhaustive]`; `created()` / `modified()` always `None` for SCO arms. | STIX §3.2 — SCOs have no created/modified. |
| `ExtensionMap` | Public `insert()` mirrors `BTreeMap` semantics. | Programmatic extension assembly without reaching into the inner map. |
| Round-trip helpers (`tests/support/roundtrip.rs`) | `roundtrip_strict`: re-serialized JSON must equal the fixture (complete types — meta, SDO, SRO, SCO, common leaf types). `roundtrip`: subset compare for `SdoSroCommonProps` / `ScoCommonProps` fixtures only. | Strict mode catches dropped fields; subset mode is documented as partial. |

## License

MIT License.

[rsigma]: https://github.com/timescale/rsigma
