# Schema Signatures

Schema signatures are the declarative rules that [schema routing](../guide/schema-routing.md) and [`engine classify`](../cli/engine/classify.md) use to recognize an event's schema from its content. This page is the complete reference for the signature grammar, the predicate forms, and their exact semantics.

A signature is a `name`, an optional `specificity`, and a `match` list of predicates that must all hold (logical AND). Signatures are loaded from the `schemas:` block of a `--schema-config` YAML file and merged over the built-ins. Multiple signatures may share a `name` (this is how OR across whole signatures is expressed): the built-in `sysmon` schema is three separate signatures, and the classifier reports the shared name.

```yaml
schemas:
  - name: my_vendor
    specificity: 70
    match:
      - field_present: vendor.product
      - equals: { field: event_type, value: alert }
      - any_of: [user.name, user.id]
```

## Specificity

When several signatures match one event, the highest `specificity` wins; ties break by name (ascending) for determinism. A tie between two different-name signatures at the winning specificity is reported as ambiguous by `engine classify` and the `rsigma_events_ambiguous_schema_total` daemon counter, since the name tie-break, not the specificity, decided the result.

User signatures default to specificity 50. The built-ins are:

| Schema | Specificity |
|--------|------------|
| `ecs_windows` / `ecs_linux` | 105 |
| `ecs` | 100 |
| `gcp_audit` | 95 |
| `github_audit` | 92 |
| `k8s_audit` | 92 |
| `azure_activitylogs` | 90 |
| `azure_auditlogs` | 90 |
| `azure_signinlogs` | 90 |
| `windows_eventlog` | 90 |
| `m365_audit` | 88 |
| `okta_system_log` | 88 |
| `sysmon` (channel/provider) | 88 |
| `aws_cloudtrail` | 85 |
| `cef` | 85 |
| `onelogin_events` | 85 |
| `aws_vpcflow` | 80 |
| `sysmon` (flat shape) | 80 |
| `osquery_result` | 75 |
| `docker_events` | 70 |
| `azure` (product-only) | 65 |
| `generic_json` | 0 |

The `ecs_windows` and `ecs_linux` specializations recognize an ECS event that also carries a platform marker, so they win over plain `ecs` and can attach a platform-specific implied logsource. They are aliases of `ecs` for routing (see [schema aliases](../guide/schema-routing.md#schema-aliases)), so an existing `ecs` binding still matches them.

## Field names

Predicate field names use the same dot-notation as event field access, so they resolve against both nested objects and flattened dotted keys. `ecs.version` matches both `{"ecs": {"version": "8.0"}}` and `{"ecs.version": "8.0"}`, and `Event.System.EventID` matches the rendered Windows Event Log nesting.

## Predicate forms

Each list item under `match` is exactly one predicate. Setting more than one form on a single item, or none, is an error.

| Form | YAML | Holds when |
|------|------|-----------|
| Field present | `field_present: <field>` | the field exists (any value, including an explicit `null`) |
| Field absent | `field_absent: <field>` | the field does not exist |
| Any present | `any_of: [<field>, ...]` | at least one of the fields exists |
| Equals | `equals: { field: <field>, value: <value> }` | the field's string-coerced value equals `value` (ASCII case-insensitive) |
| Matches | `matches: { field: <field>, value: <regex> }` | the field's string-coerced value matches the regex |
| Greater than | `gt: { field: <field>, value: <number> }` | the field is numeric-coercible and `> value` |
| Greater or equal | `gte: { field: <field>, value: <number> }` | the field is numeric-coercible and `>= value` |
| Less than | `lt: { field: <field>, value: <number> }` | the field is numeric-coercible and `< value` |
| Less or equal | `lte: { field: <field>, value: <number> }` | the field is numeric-coercible and `<= value` |
| In set | `in: { field: <field>, values: [...] }` | the field's string value equals one of `values` (ASCII case-insensitive) |
| Field equals field | `field_equals_field: { left: <a>, right: <b> }` | both fields exist and their string values are equal (case-insensitive) |
| Not | `not: <predicate>` | the inner predicate does not hold |
| Any | `any: [<predicate>, ...]` | at least one inner predicate holds (logical OR) |
| All | `all: [<predicate>, ...]` | every inner predicate holds (logical AND) |

### Semantics that are easy to miss

- `equals` and `in` are ASCII case-insensitive and operate on the string coercion of the value, so `equals: { field: EventID, value: "1" }` matches the number `1`.
- `matches` compiles the value as a regular expression at load time; an invalid regex fails config loading with an error naming the schema.
- The numeric forms (`gt`/`gte`/`lt`/`lte`) coerce the field to a number and fail closed (no match) on an absent or non-numeric field.
- `field_present` treats an explicit JSON `null` as present. Use `field_absent` for the opposite.
- `not`, `any`, and `all` nest, so real OR and NOT are expressible inside one signature (the top-level `match` list is AND-only). `any` and `all` require at least one sub-predicate.

### Composed example

```yaml
schemas:
  - name: my_vendor_windows
    specificity: 110
    match:
      - field_present: vendor.id
      - any:
          - field_present: winlog.channel
          - equals: { field: host.os.type, value: windows }
```

This recognizes a vendor schema that also carries a Windows marker; bind it with an implied `logsource:` (or alias it) so [schema-derived logsource pruning](../guide/schema-routing.md#schema-derived-logsource) attaches `product: windows`. The built-in `ecs_windows`/`ecs_linux` signatures do exactly this for ECS.

## Expressiveness ceiling

The predicate set is fixed. Cross-field logic beyond equality, arithmetic between fields, and value transforms are out of scope; model those in a processing pipeline or upstream. For alternatives across entirely different shapes, write multiple signatures that share a `name`.

## Validating a config

`rsigma engine classify --check --schema-config <path>` statically validates a config and exits non-zero on findings: unreachable signatures (a signature shadowed by a strictly-higher-specificity signature whose predicates are a subset), unknown or duplicate routing bindings, and routing bindings that reference a pipeline file that does not exist. Use `--explain` to see, per event, which predicates passed or failed.
