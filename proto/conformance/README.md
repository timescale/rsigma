# Conformance vectors

Golden `(rule YAML -> canonical IR)` pairs. Serialization agreeing is necessary but not sufficient for portability: two engines must agree on **semantics** (modifier resolution order, default case-insensitivity, base64offset/windash expansion, selector expansion, the spec's ambiguous corners). These vectors pin that agreement.

## Vector format

Each file in `vectors/` is one vector:

```json
{
  "name": "string-contains",
  "description": "Human-readable explanation of what this pins.",
  "message_type": "IrRule",         // IrRule | IrCorrelation | IrFilter
  "input_yaml": "title: ...\n...",  // the Sigma document
  "ir": { ...canonical IR as proto3 JSON... }
}
```

- `ir` is **proto3 canonical JSON** for the `message_type`: lowerCamelCase field names, enum values as their string names (e.g. `"COMPARE_OP_GT"`), `oneof` as a single set key, `int64`/`uint64`/`sint64` as JSON strings, an empty message as `{}`.
- Comparison is **structural**: an implementation parses both its own output and the vector's `ir` into the proto message and compares messages, so proto3's omission of default/zero-value fields is harmless.

## `SigmaString.original`

`original` is for round-trip and diagnostics, not semantics; the `parts` are authoritative. In these vectors `original` is the value **rendered with wildcards as literal `*` / `?`** (e.g. a `contains: whoami` renders `*whoami*`, and an escaped `\*` renders `\*`). Implementations should compare on `parts`, not `original`, unless they intend an exact round-trip.

## Status (first cut, hand-authored)

These are the **intended** canonical outputs, authored by hand from the schema and its reconciliation rules. They are not yet produced by a reference engine, because the pySigma IR emitter and the RSigma binding are downstream work. Once an emitter exists, regenerate these from the reference engine and treat any diff as a bug in the vector or the engine.

Modifier expansions that are easy to get wrong (`base64offset`, `windash`) were computed with pySigma's exact algorithm, not eyeballed.

## Coverage

- Matchers: exact, contains, startswith, endswith, escaped-wildcard, regex (+flags), cidr, numeric compare, fieldref, exists, null, bool.
- Value linking: `all` (AND) and the default value-list OR.
- Expansions: `base64offset`, `windash`.
- Detections/conditions: keywords, selector resolution, `and not`.
- Top-level: an `event_count` correlation, a filter, a metadata-rich rule.

Next: one vector per remaining correlation type, the `ArrayMatch`/`Conditional` extensions, `timestamp` part matching, and adversarial inputs (CJK/emoji values, very large integers, deeply nested conditions).

## Validating a vector file against the schema

```sh
python3 -m venv .venv && .venv/bin/pip install protobuf
protoc --proto_path=.. --python_out=/tmp/pb ../sigma_ir.proto
# then json_format.ParseDict(vector["ir"], <message_type>()) must not raise
```
