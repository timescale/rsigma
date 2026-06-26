# rstix

`rstix` is the rsigma workspace crate for STIX 2.1 and TAXII 2.1 functionality.

- [README](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md)

The crate is delivered incrementally by phase. Phase 1 (Core Foundation) is complete with core primitives, deterministic SCO ID helpers, and vocabulary tables.

Phase 2 (Data Model + Serialization) is **in progress**. The `model::common`, `model::meta`, `model::sro`, and `model::sco` modules are in place; this work is not releasable on its own.

## Current scope

- Workspace-integrated crate with rsigma-standard metadata (`edition`, `MSRV`, licensing).
- Minimal feature/dependency surface aligned with implemented modules.
- Core primitives (`StixId`, object-kind discriminants, typed IDs, timestamps, confidence scales, spec version, language tags, query traits).
- Deterministic SCO ID helpers (`select_id_contributing_properties`, canonicalization, UUIDv5 generation).
- Open and closed vocabulary tables (`vocab`) including `OpinionValue` ordering.
- `model::common` property containers (`SdoSroCommonProps`, `ScoCommonProps`, `ExternalReference`, `GranularMarking`, `ExtensionMap`).
- `model::meta` objects (`MarkingDefinition`, `ExtensionDefinition`, `LanguageContent`, `MetaObject`) with TLP UUID constants.
- `model::sro` objects (`Relationship`, `Sighting`, `WhereSightedRef`, `SroObject`).
- `model::sco` objects (all 18 STIX cyber-observable types, `ScoObject`, typed ref unions, 12 predefined extensions).
- Leaf-type serde (`StixId`, timestamps, typed IDs, `LanguageTag`) via `serde_impls/` and inline/`macro` impls.
- Temporary `parse_bundle()` entrypoint that currently returns `ParseError::NotImplemented`.
- Integration tests in `tests/spec.rs` backed by JSON fixtures under `tests/fixtures/spec/`.

## Testing

See [crate README — Development Notes](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#development-notes) for the full convention. Summary:

- **Wire tests** (`tests/spec.rs`, `tests/fixtures/spec/`): JSON round-trip via `roundtrip_strict` (complete types) or subset `roundtrip` (common-property-only structs), plus reject fixtures.
- **Unit tests** (`src/**` `#[cfg(test)]`): invariants and normative pins without duplicating wire coverage.

### STIX version vs TLP marking encoding

Three separate ideas — do not mix them:

| | STIX object model | TLP v1 encoding (legacy) | TLP v2 encoding (current) |
| --- | --- | --- | --- |
| **JSON** | `"spec_version": "2.1"` | `"definition_type":"tlp"`, `"definition":{"tlp":"white"}` | `"extensions":{…,"tlp_2_0":"clear"}` |
| **Meaning** | Object follows STIX 2.1 rules | Old TLP label wire format (deprecated for **new** markings) | Current TLP label wire format |
| **rstix constants** | `SpecVersion::V2_1` | `TLP1_WHITE_ID` … `TLP1_RED_ID` | `TLP2_CLEAR_ID` … `TLP2_RED_ID` |

A STIX **2.1** bundle can contain `marking-definition` objects that still use the **legacy TLP v1 encoding** — that is normal (ATT&CK and others reference the predefined v1 UUIDs). Fixture names like `marking-definition-tlp-v1-white-stix21.json` mean: *TLP encoding v1, white level, STIX 2.1 object*.

Full developer guide (usage examples, deprecation scope, fixture naming): [crate README — STIX version vs TLP marking encoding](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#stix-version-vs-tlp-marking-encoding).

### TLP UUID constants (`model::meta::marking_def`)

Nine public constants (`TLP1_*`, `TLP2_*`) hold the predefined STIX `marking-definition` ids for Traffic Light Protocol 1.x and 2.0. They are hardcoded because the STIX specification assigns fixed UUIDs; consumers match markings by id without parsing bundle JSON.

| Check | What it validates |
| ----- | ----------------- |
| `constants_match_spec_ids` (unit, `marking_def.rs`) | All nine `pub const` values still equal the spec literals (regression pin for the full set). |
| `marking_definition_round_trips_legacy_and_current_tlp_encodings` (`tests/spec.rs`) | Legacy TLP v1 and current TLP v2 fixtures (both STIX 2.1) parse, round-trip; ids match `TLP1_WHITE_ID` / `TLP2_CLEAR_ID`. |
| `marking_definition_round_trips_with_common_properties` (`tests/spec.rs`) | Rich fixture with `created_by_ref`, `object_marking_refs`, `external_references`, and `granular_markings` round-trips without field loss. |
| `meta_types_reject_wrong_type_field` (`tests/spec.rs`) | Cross-type JSON rejected when `"type"` does not match the target meta struct. |

The unit pin does not replace wire tests: it covers ids that do not yet have dedicated JSON fixtures. The wire tests prove serde and field mapping for representative TLP 1.x and 2.0 shapes.

### Model invariant decisions (`model::common`)

rstix enforces STIX invariants at deserialize time (not deferred to a later validation pass). See [crate README — Model invariant decisions](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#model-invariant-decisions-modelcommon) for the full table. Summary:

- **`confidence`:** `Option<Confidence>` on SDO/SRO common props (absent vs present).
- **`external-reference` §2.5.2:** non-empty `source_name` plus at least one detail field (`description`, `url`, or `external_id`).
- **`granular-marking`:** required non-empty `selectors`; `marking_ref` xor `lang`.
- **`ExtensionDefinition`:** required `created_by_ref` (STIX §7.2.2).
- **Meta object `type`:** deserialize rejects JSON whose `"type"` does not match the target struct.
- **SRO object `type`:** same single-pass `"type"` validation for `Relationship` and `Sighting`.
- **SRO invariants:** `Relationship` relationship-type charset and time ordering; `Sighting` count range, time-window ordering, and `where_sighted_refs` identity/location typing — see [crate README — Model invariant decisions](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#model-invariant-decisions-modelcommon).
- **SRO deferral:** `source_ref` / `target_ref` / `sighting_of_ref` SDO/SCO target validation waits for `StixObject` dispatch.
- **SCO invariants:** artifact payload XOR url; file hashes-or-name; email-message multipart rules; network-traffic protocols and endpoint refs; at-least-one-property types (process, user-account, windows-registry-key, x509-certificate); typed ref unions for domain-name, directory, network-traffic endpoints, and email MIME raw refs — see [crate README — Model invariant decisions](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#model-invariant-decisions-modelcommon).
- **SCO query semantics:** `ScoObject::created()` / `modified()` always return `None`; ref fields expose `QueryValue::Id`.
- **Round-trip helpers:** `roundtrip_strict` requires full fixture equality for complete types. Subset `roundtrip` — every emitted field must match the fixture, extra fixture keys allowed, dropped fields not caught on object fixtures; for common-property structs that ignore extra SDO keys until concrete SDO types land in a later Phase 2 milestone.

## Feature flags

| Feature | Purpose |
| --------- | --------- |
| `serde` (default) | Serialization and deserialization support. |

## Related docs

- [`rstix` README](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md)
- [Architecture](../reference/architecture.md)
- [Feature flags reference](../reference/feature-flags.md)
- [Contributing](../contributing.md)
