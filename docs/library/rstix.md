# rstix

`rstix` is the rsigma workspace crate for STIX 2.1 and TAXII 2.1 functionality.

The crate is being delivered in phased slices. Phase 1 (Core Foundation) is implemented with core primitives, deterministic SCO ID helpers, and vocabulary tables.

## Current scope

- Workspace-integrated crate with rsigma-standard metadata (`edition`, `MSRV`, licensing).
- Phase-oriented feature flags and dependency boundaries.
- Core primitives (`StixId`, object-kind discriminants, typed IDs, timestamps, confidence scales, spec version, language tags, query traits).
- Deterministic SCO ID helpers (`select_id_contributing_properties`, canonicalization, UUIDv5 generation).
- Open and closed vocabulary tables (`vocab`) including `OpinionValue` ordering.
- Temporary `parse_bundle()` entrypoint that currently returns `ParseError::NotImplemented`.

## Feature flags

| Feature | Purpose |
| --------- | --------- |
| `serde` (default) | Serialization and deserialization support. |
| `pattern` | STIX pattern parser and evaluator surface. |
| `validate` | STIX validation APIs (depends on `serde`, `pattern`). |
| `graph` | Graph traversal APIs. |
| `marking` | Marking and TLP APIs. |
| `store` | Storage/query APIs. |
| `enrichment` | Enrichment APIs (depends on `store`, `graph`). |
| `taxii` | TAXII client APIs (depends on `serde`, reqwest/tokio/secrecy). |
| `testing` | Test helpers and fixtures. |
| `full` | Convenience bundle for all functional modules except `testing`. |

## Related docs

- [Architecture](../reference/architecture.md)
- [Feature flags reference](../reference/feature-flags.md)
- [Contributing](../contributing.md)
