# rstix

`rstix` is a phase-driven Rust library crate for STIX 2.1 and TAXII 2.1 support inside the `rsigma` workspace.

Phase 0 intentionally ships only infrastructure and feature-flag scaffolding.

## Feature Flags

| Feature | Purpose |
|---|---|
| `serde` (default) | Enables serialization/deserialization support modules |
| `pattern` | STIX pattern parsing/evaluation module |
| `validate` | Validation pipeline module |
| `graph` | Graph traversal module |
| `marking` | Data marking semantics module |
| `store` | Storage abstraction module |
| `store-fs` | Filesystem-backed store support |
| `enrichment` | Enrichment APIs |
| `taxii` | TAXII client module |
| `auth-certificate` | TAXII certificate auth support |
| `testing` | Test helper interfaces |
| `full` | Enables all major optional features |

## Status

- Phase 0: crate skeleton and workspace integration
- No STIX/TAXII production behavior yet

## License

This crate inherits the workspace `MIT` license.
# rstix

`rstix` is a phase-driven Rust library crate for STIX 2.1 and TAXII 2.1 support inside the `rsigma` workspace.

Phase 0 intentionally ships only infrastructure and feature-flag scaffolding.

## Feature Flags

| Feature | Purpose |
|---|---|
| `serde` (default) | Enables serialization/deserialization support modules |
| `pattern` | STIX pattern parsing/evaluation module |
| `validate` | Validation pipeline module |
| `graph` | Graph traversal module |
| `marking` | Data marking semantics module |
| `store` | Storage abstraction module |
| `store-fs` | Filesystem-backed store support |
| `enrichment` | Enrichment APIs |
| `taxii` | TAXII client module |
| `auth-certificate` | TAXII certificate auth support |
| `testing` | Test helper interfaces |
| `full` | Enables all major optional features |

## Status

- Phase 0: crate skeleton and workspace integration
- No STIX/TAXII production behavior yet

## License

This crate inherits the workspace `MIT` license.
