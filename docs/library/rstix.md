# rstix

`rstix` is the rsigma workspace crate for STIX 2.1 and TAXII 2.1 functionality.

The crate is being delivered in phased slices. Phase 1 (Core Foundation) is implemented with core primitives, deterministic SCO ID helpers, and vocabulary tables.

## Current scope

- Workspace-integrated crate with rsigma-standard metadata (`edition`, `MSRV`, licensing).
- Minimal feature/dependency surface aligned with implemented modules.
- Core primitives (`StixId`, object-kind discriminants, typed IDs, timestamps, confidence scales, spec version, language tags, query traits).
- Deterministic SCO ID helpers (`select_id_contributing_properties`, canonicalization, UUIDv5 generation).
- Open and closed vocabulary tables (`vocab`) including `OpinionValue` ordering.
- Temporary `parse_bundle()` entrypoint that currently returns `ParseError::NotImplemented`.

## Feature flags

| Feature | Purpose |
| --------- | --------- |
| `serde` (default) | Serialization and deserialization support. |

## Related docs

- [Architecture](../reference/architecture.md)
- [Feature flags reference](../reference/feature-flags.md)
- [Contributing](../contributing.md)
