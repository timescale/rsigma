---
description: "Reference for rsigma engine classify: report which log schema each event matches, such as ECS, Sysmon, or CloudTrail, using built-in or custom signatures."
---

# `rsigma engine classify`

{{ added "0.18.0" }}

Report which schema each event matches, recognized from the event's content.

## Synopsis

```text
rsigma engine classify [OPTIONS]
```

## Description

Reads events and prints, per event, the schema RSigma recognizes it as (or `unknown`), plus a per-schema summary. Recognition is content-based: it keys off marker fields and values, not the wire format, so it tells ECS, flat Sysmon, rendered Windows Event Log, CEF, OCSF, and the Cloud/SaaS/Container builtins apart even when they all arrive as JSON.

This is a diagnostic for understanding a mixed dataset and for tuning schema signatures before wiring them into a pipeline. It does not load rules or evaluate detections. For the live equivalent on a running daemon, see the `GET /api/v1/schemas` endpoint and the `--observe-schemas` flag on [`engine daemon`](daemon.md). Offline signature proposals for unrecognized shapes are covered by [`engine discover-schemas`](discover-schemas.md).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-e, --event <EVENT>` | stdin | A single event as a JSON string, or `@path` to read NDJSON from a file. Without this flag, reads NDJSON from stdin. Binary `.evtx` paths are rejected with guidance to decode via [`engine eval`](eval.md) or convert to NDJSON first. |
| `--schema-config <PATH>` | unset | YAML file of user-defined schema signatures (and optional `routing:` bindings), merged over the built-ins. |
| `--explain` | off | Show, per event, why it classified as it did: the matched signature's per-predicate pass/fail, or for an unknown event the closest near-miss. |
| `--check` | off | Validate the `--schema-config` and exit (does not read events). Reports unreachable signatures, unknown or duplicate routing bindings, and missing pipeline files; exits non-zero on any finding. |

The global [`--output-format`](../../reference/output.md) flag selects `json`, `ndjson`, `table`, `csv`, or `tsv`.

## Built-in schemas

Host and endpoint shapes:

| Schema | Recognized by |
|--------|---------------|
| `ecs_windows` | `ecs.version` present plus a Windows marker (`winlog.*`, `host.os.type: windows`). Implies `product: windows`; routes as `ecs`. |
| `ecs_linux` | `ecs.version` present plus a Linux marker (`host.os.type: linux`, `host.os.kernel`). Implies `product: linux`; routes as `ecs`. |
| `ecs` | `ecs.version` present |
| `ocsf` | `class_uid` and `metadata.version` present |
| `windows_eventlog` | `Event.System.EventID` or `Event.System.Provider` present (rendered EVTX JSON) |
| `sysmon` | the Sysmon channel/provider, or flat `EventID` + `ProcessGuid` + `Image`/`CommandLine` |
| `cef` | `deviceVendor`, `deviceProduct`, and `signatureId` present |
| `generic_json` | any structured event matching no more-specific schema (specificity 0) |

Cloud, SaaS, and container shapes (always-on): `aws_cloudtrail`, `aws_vpcflow`, `azure_activitylogs`, `azure_auditlogs`, `azure_signinlogs`, `azure` (product-only fallback), `gcp_audit`, `m365_audit`, `github_audit`, `okta_system_log`, `onelogin_events`, `k8s_audit`, `docker_events`, `osquery_result`. Marker fields and shipper recipes are in [Cloud Collection Recipes](../../guide/cloud-collection-recipes.md); specificities are in [Schema Signatures](../../reference/schema-signatures.md#specificity).

An event that matches no signature (for example a field-less object `{}` or a non-JSON line counted as a parse error) is reported as `unknown`. A different-name specificity tie is reported as `ambiguous` on the event and in the summary.

## User signatures

`--schema-config` loads additional signatures. Each is a name, an optional `specificity` (higher wins on overlap; default 50), and a `match` list of conditions that must all hold:

```yaml
schemas:
  - name: my_vendor
    specificity: 70
    match:
      - field_present: vendor.product
      - equals:
          field: event_type
          value: alert
      - any_of: [user.name, user.id]
      - matches:
          field: message
          value: "^CEF:\\d"
      - field_absent: ecs.version
      - gte: { field: severity, value: 3 }
      - in: { field: action, values: [alert, block] }
      - any:
          - field_present: winlog.channel
          - equals: { field: host.os.type, value: windows }
```

The full grammar, every predicate form (including the numeric, set-membership, cross-field, and `not`/`any`/`all` group forms), and their exact semantics are in the [Schema Signatures reference](../../reference/schema-signatures.md).

## Explaining and validating

`--explain` prints, per event, why it classified as it did, the matched signature's predicates or the closest near-miss for an unknown event:

```bash
rsigma engine classify -e '{"EventID":1,"Image":"C:/cmd.exe"}' --explain
```

`--check` statically validates a config (unreachable signatures, unknown or duplicate routing bindings, missing pipeline files) and exits non-zero on findings, for CI:

```bash
rsigma engine classify --check --schema-config schemas.yml
```

When the config has a `routing:` section, classify also shows, per event, which pipeline-set it would route to, a dry-run of [schema routing](../../guide/schema-routing.md) without loading rules.

## Examples

Classify a single event:

```bash
rsigma engine classify -e '{"ecs.version":"8.11.0","process":{"command_line":"whoami"}}'
```

Classify an NDJSON stream and see the per-schema table:

```bash
cat events.ndjson | rsigma engine classify --output-format table
```

Tune custom signatures against a sample:

```bash
rsigma engine classify -e @sample.ndjson --schema-config schemas.yml --output-format json
```

## Output

The structured report carries a `summary` (`total_events`, `classified`, `unknown`, `ambiguous`, `parse_errors`, and `by_schema` counts) and an `events` array with the `index`, `schema`, `specificity`, optional `ambiguous`, optional `explanation` (with `--explain`), and optional `route` (when the config has `routing:`) of each event. In `table`, `csv`, `tsv`, and `ndjson` formats the per-event rows go to stdout and the summary line to stderr (unless `--no-stats`).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (or `--check` found no issues) |
| `2` | Bad event input (invalid inline JSON, unreadable `@path`, or a `.evtx` path) |
| `3` | Bad schema config (unreadable/invalid `--schema-config`, or `--check` findings) |

See [Exit Codes](../../reference/exit-codes.md) for the full scheme.

## See also

- [Schema Signatures](../../reference/schema-signatures.md) for the grammar, predicate forms, and builtin specificities.
- [Schema Routing](../../guide/schema-routing.md) for bindings driven by the same classifier.
- [Cloud Collection Recipes](../../guide/cloud-collection-recipes.md) for Cloud/SaaS/Container marker fields.
- [`engine discover-schemas`](discover-schemas.md) for offline signature proposals.
- [`engine daemon`](daemon.md) for `--observe-schemas` and `GET /api/v1/schemas`.
