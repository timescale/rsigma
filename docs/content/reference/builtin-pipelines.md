# Builtin Pipelines

RSigma embeds three ready-to-use processing pipelines in the binary so common Windows deployments work with no external YAML file. Reference them by name from any subcommand that accepts `-p`:

```bash
rsigma engine eval   -r rules/ -p ecs_windows -e @events.ndjson
rsigma engine daemon -r rules/ -p sysmon
rsigma backend convert rules/ -t fibratus -p fibratus_windows
rsigma backend convert rules/ -t postgres -p ecs_windows
```

Builtins are baked at compile time. Updating their content means upgrading rsigma; they are not file-watched, do not appear under `--reload`, and cannot be tweaked at runtime. Copy the YAML out to a local file (sources below) if you need to customize.

The builtin registry is the source of truth (`ecs_windows`, `fibratus_windows`, `sysmon` via `builtin_names()`). Extra YAML files may live under [`crates/rsigma-eval/pipelines/`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-eval/pipelines) without being builtins; load those by path with `-p path/to/file.yml`. Shipped examples include [`gcp_audit.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/gcp_audit.yml) (GCP audit `data.` prefix strip) and [`ecs_linux.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/ecs_linux.yml) (Sigma → ECS field mapping for `product: linux`, same categories as covered in that file — not a builtin `-p ecs_linux` name) {{ added "unreleased" }}.

## `ecs_windows`

Maps generic Sigma/Sysmon field names to Elastic Common Schema (ECS) as produced by [Winlogbeat](https://www.elastic.co/beats/winlogbeat) and [Elastic Agent](https://www.elastic.co/elastic-agent). Derived from `pySigma-backend-elasticsearch`'s `ecs_windows` pipeline.

```bash
rsigma engine eval -r rules/ -p ecs_windows \
    -e '{"process.command_line": "whoami", "winlog.channel": "Microsoft-Windows-Sysmon/Operational"}'
```

Priority: `20`. Source: [`pipelines/ecs_windows.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/ecs_windows.yml).

### What it maps

Each transformation is gated by `rule_conditions: logsource.category` so only the relevant logsource categories receive each rename.

| Category | Sigma fields → ECS fields |
|----------|---------------------------|
| `process_creation` (Sysmon Event ID 1) | `CommandLine` → `process.command_line`, `Image` → `process.executable`, `OriginalFileName` → `process.pe.original_file_name`, `CurrentDirectory` → `process.working_directory`, `ProcessGuid` → `process.entity_id`, `ProcessId` → `process.pid`, `ParentProcessGuid` → `process.parent.entity_id`, `ParentProcessId` → `process.parent.pid`, `ParentImage` → `process.parent.executable`, `ParentCommandLine` → `process.parent.command_line`, `User` → `user.name`, `IntegrityLevel` → `winlog.event_data.IntegrityLevel`, `Hashes` → `winlog.event_data.Hashes`, `Company` → `process.pe.company`, `Description` → `process.pe.description`, `Product` → `process.pe.product`, `FileVersion` → `process.pe.file_version` |
| `network_connection` (Sysmon Event ID 3) | `SourceIp` → `source.ip`, `SourceHostname` → `source.domain`, `SourcePort` → `source.port`, `DestinationIp` → `destination.ip`, `DestinationHostname` → `destination.domain`, `DestinationPort` → `destination.port`, `DestinationPortName` → `network.protocol`, `Protocol` → `network.transport`, `Image` → `process.executable`, `User` → `user.name`, `ProcessId` → `process.pid` |
| `image_load` (Sysmon Event ID 7) | `ImageLoaded` → `file.path`, `Image` → `process.executable`, `Signed`/`SignatureStatus`/`Signature` → `file.code_signature.*`, `Imphash` → `file.pe.imphash`, `Company`/`Description`/`Product`/`FileVersion`/`OriginalFileName` → `file.pe.*` |
| `file_event` (Sysmon Event ID 11) | `TargetFilename` → `file.path`, `Image` → `process.executable`, `User` → `user.name` |
| `registry_event` (Sysmon Event ID 12/13/14) | `TargetObject` → `registry.path`, `Details`/`EventType` → `winlog.event_data.*`, `Image` → `process.executable` |
| `dns_query` (Sysmon Event ID 22) | `QueryName` → `dns.question.name`, `QueryStatus` → `sysmon.dns.status`, `Image` → `process.executable` |
| `pipe_created` (Sysmon Event ID 17/18) | `PipeName` → `file.name`, `Image` → `process.executable` |
| `driver_load` (Sysmon Event ID 6) | `ImageLoaded` → `file.path`, `Signed`/`SignatureStatus`/`Signature`/`Imphash` → `file.code_signature.*` and `file.pe.*` |
| `create_remote_thread` (Sysmon Event ID 8) | `SourceImage` → `process.executable`, `SourceProcessId` → `process.pid`, `TargetImage`/`TargetProcessId`/`StartFunction` → `winlog.event_data.*` |
| `process_access` (Sysmon Event ID 10) | `SourceImage` → `process.executable`, `SourceProcessId` → `process.pid`, `TargetImage`/`TargetProcessId`/`GrantedAccess`/`CallTrace` → `winlog.event_data.*` |
| any Windows rule | `EventID` → `event.code`, `Channel` → `winlog.channel`, `Provider_Name` → `winlog.provider_name`, `ComputerName` → `winlog.computer_name` |

### Pair with the right input

`ecs_windows` assumes the agent has already flattened the Windows events into ECS shape. It does NOT flatten raw `.evtx` records (those are nested under `Event.System.*` and `Event.EventData.*`). For raw `.evtx` files, use dotted-path rules or write a custom flattening pipeline. See [Input Formats: EVTX](../guide/input-formats.md#evtx-windows-event-log-feature-gated).

## `fibratus_windows`

Maps Sigma Windows logsource categories and PascalCase fields onto Fibratus kernel-event names and the lowercase-dotted Fibratus vocabulary (`ps.exe`, `ps.cmdline`, `file.path`, `net.dip`, …). Use it when converting Windows rules to Fibratus YAML so the output matches upstream Fibratus rules-library style.

```bash
rsigma backend convert -t fibratus -p fibratus_windows rules/windows/process_creation/
```

Priority: `20`. Source: [`pipelines/fibratus_windows.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/fibratus_windows.yml).

### What it does

- `field_name_mapping` renames Sigma fields to Fibratus attributes per category (`process_creation`, `network_connection`, `file_event`, `image_load`, `registry_*`, `dns_query`, `pipe_created`, `create_remote_thread`, and related).
- `add_condition` injects `evt.name` discriminators (for example `CreateProcess`, `Connect`) so Fibratus can short-circuit on the event name before the rest of the body.
- Field notes follow Fibratus 3.0.0: on `CreateProcess`, `ps.*` describes the created (child) process and `ps.parent.*` the parent; cross-process targets use `evt.arg[...]`.

Pair with [`backend convert -t fibratus`](../cli/backend/convert.md) and the [Fibratus backend reference](backends/fibratus.md).

## `sysmon`

Adds `EventID` routing conditions so logsource-scoped rules (e.g. `category: process_creation`) match the corresponding Sysmon event types when evaluating raw Sysmon JSON. Derived from `pySigma-pipeline-sysmon`.

```bash
rsigma engine eval -r rules/ -p sysmon \
    -e '{"EventID": 1, "Image": "cmd.exe", "CommandLine": "whoami"}'
```

Priority: `10`. Source: [`pipelines/sysmon.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/sysmon.yml).

### What it adds

Each transformation is `add_condition` with a matching `rule_conditions: logsource.category`. The injected condition combines with the rule's own selection via AND.

| Logsource category | Injected condition |
|---------------------|--------------------|
| `process_creation` | `EventID: 1` |
| `file_change` | `EventID: 2` |
| `network_connection` | `EventID: 3` |
| `sysmon_status` | `EventID: [4, 16]` |
| `process_termination` | `EventID: 5` |
| `driver_load` | `EventID: 6` |
| `image_load` | `EventID: 7` |
| `create_remote_thread` | `EventID: 8` |
| `raw_access_thread` | `EventID: 9` |
| `process_access` | `EventID: 10` |
| `file_event` | `EventID: 11` |
| `registry_event` | `EventID: [12, 13, 14]` |
| `registry_add` | `EventID: 12` |
| `registry_delete` | `EventID: 12` |
| `registry_set` | `EventID: 13` |
| `registry_rename` | `EventID: 14` |
| `create_stream_hash` | `EventID: 15` |
| `pipe_created` | `EventID: [17, 18]` |
| `wmi_event` | `EventID: [19, 20, 21]` |
| `dns_query` | `EventID: 22` |
| `file_delete` | `EventID: 23` |
| `clipboard_capture` | `EventID: 24` |
| `process_tampering` | `EventID: 25` |
| `file_delete_detected` | `EventID: 26` |
| `file_block_executable` | `EventID: 27` |
| `file_block_shredding` | `EventID: 28` |
| `file_executable_detected` | `EventID: 29` |
| `sysmon_error` | `EventID: 255` |

After the routing conditions, a final `change_logsource` rewrites every Windows rule to `product: windows, service: sysmon` so downstream backends can use the unified logsource.

That rewrite is also the routing decision itself, in a form a consumer can read: rather than re-deriving which channel a `process_creation` rule belongs to, read `logsource.service` off the transformed rule. Use `Engine::rules()` after loading, or [`transform_collection`](../guide/processing-pipelines.md#inspecting-the-rewritten-rule) when you need the rule without loading it. A custom pipeline that routes by `add_condition` alone leaves the logsource untouched, so mirror this closing transformation if anything downstream keys off `service`.

### When it does NOT help

`sysmon` assumes events already have a flat `EventID` field. It does not flatten the nested EVTX shape. For raw `.evtx` input, either:

- Reference fields by their dotted EVTX path (`Event.System.EventID: 1`) directly in the rule, or
- Write a pipeline that `field_name_mapping`-renames `Event.System.EventID` to `EventID` before `sysmon` runs (higher `priority:`).

## Chaining builtins with file pipelines

Builtin and file pipelines compose by `priority:` (lower runs first). A typical Windows ECS deployment:

```bash
rsigma engine daemon -r rules/ \
    -p sysmon \
    -p ecs_windows \
    -p /etc/rsigma/pipelines/org-overrides.yml
```

`sysmon` (priority 10) adds the EventID conditions first; `ecs_windows` (priority 20) renames the field names to ECS; finally the org overrides at, say, priority 50 add per-tenant table routing.

## See also

- [Processing Pipelines](../guide/processing-pipelines.md) for the full pipeline grammar, transformation types, and dynamic pipelines.
- [Input Formats: EVTX](../guide/input-formats.md#evtx-windows-event-log-feature-gated) for why these builtins do not match raw EVTX directly.
- [`backend convert`](../cli/backend/convert.md) for using builtin pipelines during rule conversion.
- The OCSF pipelines (`pipelines/ocsf_postgres.yml`, `pipelines/ocsf_postgres_multi_table.yml`) live in [`crates/rsigma-convert/pipelines/`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-convert/pipelines) and are good copy-paste starting points for non-Windows schemas.
