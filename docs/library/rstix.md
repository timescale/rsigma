# rstix

`rstix` is the rsigma workspace crate for **STIX 2.1** (and future **TAXII 2.1** client work). It provides typed Rust objects for all 42 built-in STIX types, bundle ingestion, extension round-trip, and a semantic validation pipeline.

Canonical API reference: [docs.rs/rstix](https://docs.rs/rstix). Contributor-facing detail: [crate README](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md).

## Phase status

| Phase | Status |
| ----- | ------ |
| **Core Foundation** (`core`, `id`, `vocab`) | Complete |
| **Data Model + Serialization** (`model`, `Bundle`, `parse_reader`, `Bundle::validate`) | Complete |
| **Pattern Engine** (STIX indicator pattern AST) | Planned |
| **Graph + Marking + Store** | Planned |
| **TAXII Client** | Planned |

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

// MUST rules enforced at parse; SHOULD rules as warnings
let report = bundle.validate();
for warning in report.warnings_with_code(ValidationCode::StixW0031TlpV1Encoding) {
    eprintln!("{}: {}", warning.object_id.as_deref().unwrap_or("?"), warning.message);
}

// Round-trip
let out = serde_json::to_string(&bundle)?;
```

## Public API surface

### Crate root (`rstix`)

| Symbol | Role |
| ------ | ---- |
| `parse_bundle(&str)` | Parse a bundle JSON string with default [`ParseOptions`](https://docs.rs/rstix/latest/rstix/model/struct.ParseOptions.html). |
| `Bundle` | Typed container; navigation, serialize, `validate()`. |
| `StixObject` | Top-level enum: SDO / SCO / SRO / Meta / Custom. |
| `ParseOptions`, `TypeRegistry` | Limits, custom type registration. |
| `ValidationReport`, `ValidationCode`, `ValidationFinding` | Semantic validation output. |
| `ParseError`, `model::ModelError` | Parse-time failures (MUST rules). |

### `core`

`StixId`, 42 typed ID wrappers, `StixObjectKind`, `StixTimestamp`, `TaxiiTimestamp`, `Confidence`, `SpecVersion`, `LanguageTag`, `QueryableStixObject`, `QueryValue`.

### `model`

| Submodule | Contents |
| --------- | -------- |
| `common` | `SdoSroCommonProps`, `ScoCommonProps`, `ExternalReference`, `GranularMarking`, `ExtensionMap`, `KillChainPhase` |
| `meta` | `MarkingDefinition`, `ExtensionDefinition`, `LanguageContent`, TLP UUID constants |
| `sdo` | All 19 SDOs, `SdoObject`, `IndicatorPattern`, `ObservedDataForm`, `ObservedDataEmbeddedObject` |
| `sro` | `Relationship`, `Sighting`, `SroObject` |
| `sco` | All 18 SCOs, `ScoObject`, typed ref unions, 12 predefined extensions under `sco::extensions` |
| `validate` | Shared MUST validators (used at deserialize and bundle ref checks) |
| `validation` | `Bundle::validate()` implementation and `ValidationCode` enum |

### `id`

Deterministic SCO UUIDv5: `select_id_contributing_properties`, JCS canonicalization, `generate_sco_id`, `verify_sco_deterministic_id`.

### `vocab`

Closed enums (hash algorithms, encryption algorithms, opinion values) and open vocabularies (`REGION_OV`, malware types, etc.).

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
| `bundle.validate_refs()` | Re-run MUST ref resolution (normally called during parse). |

Plan API name `get::<T>()` is implemented as **`get_typed::<T>()`** to avoid clashing with untyped `get`.

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

Parse enforces STIX **MUST** rules (hard errors). **`Bundle::validate()`** collects **SHOULD**-level and advisory findings without rejecting the bundle.

| `ValidationCode` | Meaning |
| ---------------- | ------- |
| `StixW0031TlpV1Encoding` | Legacy TLP 1.x marking encoding or TLP1 marking ref (STIX-W0031). |
| `ScoDeterministicIdMismatch` | SCO `id` does not match UUIDv5 from id-contributing properties. |
| `GranularSelectorSemanticInvalid` | Granular-marking selector does not resolve on the object. |
| `LanguageContentFieldUnknown` | Translation field is not a property on the target object. |
| `LanguageContentValueMismatch` | Translation type or list length does not mirror the target property. |
| `LanguageContentObjectModifiedMismatch` | `object_modified` does not match target `modified`. |
| `LocationCountryNotIso3166` | `country` is not ISO 3166-1 alpha-2. |
| `LocationRegionNotInOpenVocab` | `region` is not in STIX `region-ov`. |
| `InvalidCapecExternalReference` | CAPEC `external_id` shape (attack-pattern). |
| `InvalidCveExternalReference` | CVE `external_id` shape (vulnerability). |
| `RelationshipEndpointMatrixInvalid` | Relationship source/target types outside STIX 2.1 matrix. |
| `EncryptionAlgorithmInvalid` | Artifact `encryption_algorithm` not in closed vocabulary. |

There is no `strict` parse flag: permissive parse + explicit `validate()` is the supported workflow (see maintainer direction on [issue #267](https://github.com/timescale/rsigma/issues/267)).

## Wire-format validation (pragmatic vs full spec)

STIX **SHOULD** cite full Internet standards for some string fields. rstix uses **lightweight structural checks** at parse time — enough to reject obvious garbage without pulling in full IDNA/email parsers.

| Field | STIX reference | rstix today | Full standard (not implemented) |
| ----- | -------------- | ----------- | -------------------------------- |
| `domain-name.value` | RFC 1034 / 5890 | Label structure, no empty labels, no `..` | **IDNA**: Unicode domain → Punycode (`xn--…`), full UTS #46 |
| `email-addr.value` | RFC 5322 | Non-empty local@domain with dot in domain, no whitespace | **RFC 5322**: full addr-spec grammar (quoted strings, comments, IP literals) |
| `url.value` | Valid URL | `http://`, `https://`, or `ftp://` prefix | WHATWG URL parser, IDNA in host, normalization |

**Why full IDNA / RFC 5322 are not in Data Model + Serialization:** they are large, locale-sensitive parsers unrelated to STIX object typing. Basic checks catch malformed CTI early; strict compliance belongs in an optional validation profile or a dedicated dependency (`idna`, `mail-parser`, etc.) if a downstream consumer requires it. This is documented in `plan/spec-differential-status.md` under later-phase polish.

## Extensions and round-trip

- Top-level **`x_*`** keys are peeled before typed deserialize → `Bundle::extra_properties()`, merged back on serialize.
- **`toplevel-property-extension`** keys are hoisted from `extensions` the same way.
- Standalone leaf deserialize stores unknown keys in **`common.extra`** (SDO/SRO/SCO) or **`MarkingDefinition.extra`**, drained into `extra_properties` during bundle parse.

## Testing

| Layer | Location |
| ----- | -------- |
| Wire round-trip | `tests/spec.rs`, `tests/fixtures/spec/` |
| Bundle integration | `tests/bundle.rs` |
| Semantic validation | `tests/validation.rs`, `tests/fixtures/validation/` |
| Streaming + custom types + ATT&CK | `tests/integration.rs` |
| Fuzz | `fuzz/fuzz_targets/fuzz_rstix_parse_bundle.rs` |

Run crate tests:

```bash
cargo test -p rstix --features serde
```

### Local MITRE ATT&CK corpus (not in git)

The full ATT&CK STIX bundle (~50 MiB) is **not committed**. CI uses a synthetic 5 000-object streaming test. For local verification, download a bundle (for example MITRE ATT&CK 19.1) and point the integration test at it:

```bash
# Example: file at plan/enterprise-attack-19.1.json (plan/ is gitignored)
RSTIX_ATTCK_BUNDLE=plan/enterprise-attack-19.1.json \
  cargo test -p rstix --features serde attck_corpus_roundtrip_when_present -- --nocapture
```

This runs `parse_reader` → serialize → reparse and asserts object count stability. Verified against `enterprise-attack-19.1.json` (~53 MiB) locally.

## STIX version vs TLP marking encoding

Three independent ideas — do not mix them:

| | STIX object model | TLP v1 encoding (legacy) | TLP v2 encoding (current) |
| --- | --- | --- | --- |
| **JSON** | `"spec_version": "2.1"` | `"definition_type":"tlp"`, `"definition":{"tlp":"white"}` | `"extensions":{…,"tlp_2_0":"clear"}` |
| **Meaning** | Object follows STIX 2.1 rules | Old TLP label wire format (deprecated for **new** markings) | Current TLP label wire format |
| **rstix constants** | `SpecVersion::V2_1` | `TLP1_WHITE_ID` … `TLP1_RED_ID` | `TLP2_CLEAR_ID` … `TLP2_RED_ID` |

A STIX **2.1** bundle can contain `marking-definition` objects that still use the **legacy TLP v1 encoding** — that is normal (ATT&CK references the predefined v1 UUIDs).

Full developer guide: [crate README — STIX version vs TLP marking encoding](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#stix-version-vs-tlp-marking-encoding).

## Model invariants (summary)

Full table: [crate README — Model invariant decisions](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#model-invariant-decisions-modelcommon).

- **MUST at parse:** id/type match, ref resolution in bundle, extension routing, SCO forbidden common props, SDO/SRO time ordering, and type-specific MUST rules documented in `ModelError`.
- **SHOULD via `validate()`:** relationship matrix, CAPEC/CVE, encryption algorithm, TLP v1 warnings, granular selector semantics, language-content rules, location country/region vocabularies, SCO deterministic id.

## Feature flags

| Feature | Purpose |
| ------- | ------- |
| `serde` (default) | Bundle parsing, serialization, validation. |

## Related docs

- [Architecture — crate map](../reference/architecture.md)
- [Feature flags — rstix](../reference/feature-flags.md#rstix)
- [Fuzzing — `fuzz_rstix_parse_bundle`](../developers/fuzzing.md)
- [Crate README](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md)
