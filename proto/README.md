# Sigma portable IR (protobuf interchange)

A language-neutral schema for a **post-pipeline, modifier-resolved, selector-resolved** Sigma rule. It is the single source of truth that an engine's internal HIR is generated from or conformance-locked against, and the wire message a remote backend (pySigma, RSigma, or any future engine) responds to.

The schema reconciles the RSigma parser AST/HIR with pySigma's resolved types, conditions, modifiers, correlations, and filters, so both engines lower to and consume the same form.

## Files

| File | Purpose |
|------|---------|
| `sigma_ir.proto` | The IR message schema: values, matchers, detections, conditions, rule/correlation/filter, metadata, and the `Pack` envelope. |
| `sigma_backend.proto` | The `SigmaBackend` gRPC service (`Capabilities` + `Convert`). A thin transport over the message schema; a backend can run as a local subprocess or a remote endpoint. |
| `conformance/` | Golden `(rule YAML -> canonical IR)` vectors that any implementation must reproduce. See `conformance/README.md`. |

## Level

The schema sits at the post-modifier, selector-resolved layer that both engines independently arrive at:

- **pySigma** applies modifiers (turning `contains`/`re`/`cidr`/`fieldref`/`gt` into resolved `SigmaType` values) and expands selectors in `postprocess`.
- **RSigma** lowers to its `IrMatcher`/`IrCondition` HIR.

Consequences baked into the schema:

- The wire IR is **fully modifier-resolved**: encoding modifiers (`base64`/`base64offset`/`wide`/`windash`) are applied before serialization, so no encoding logic ever crosses the wire (`base64offset`/`windash` become an `any_of` of resolved string matchers).
- **Negation is a detection-item flag** (`IrDetectionItem.negated`), matching pySigma's general `neq`/`SigmaNegateModifier`, not a numeric operator.
- **Selectors never cross the wire**; both engines expand them, so a consumer always sees a concrete boolean tree over named detections.

## Conventions

- Field numbers are stable once published; `reserved` ranges mark room for additive growth.
- `oneof` is used wherever the source model is a sum type.
- `oneof` arms avoid language keywords (`negation`/`conjunction`/`disjunction`/`boolean`) so generated code is clean in Python, Rust, and Go.
- Placeholders (pySigma `%name%` and RSigma `${source.*}`) are modeled as string **parts**, a superset of a value-level deferred reference. pySigma emits resolved literals; RSigma may emit a `dynamic_ref`.

## Compiling

```sh
# descriptor set (validation)
protoc --proto_path=. --descriptor_set_out=/dev/null sigma_ir.proto sigma_backend.proto

# language bindings (examples)
protoc --proto_path=. --python_out=out sigma_ir.proto sigma_backend.proto
# Rust via prost-build / tonic-build in build.rs
# Go via protoc-gen-go / protoc-gen-go-grpc
```

## Status and home

This lives on the `feat/portable-ir-proto` branch of the rsigma repo for now. The intent is to extract `proto/` into a neutral standalone `sigma-ir-schema` repo so a second implementation (pySigma) can vendor it credibly.
