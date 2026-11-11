---
description: "Reference for the optional ECS, CIM, OCSF, and Falcon pipelines that rewrite Sigma field names when you pass -p."
---

# Canonicalizing pipelines (issue #330)

RSigma ships optional **processing pipelines** that rewrite Sigma rule field names so portable rules match your indexed event schema when you pass **`-p`**. Nothing runs unless you opt in. Issue [#330](https://github.com/timescale/rsigma/issues/330) tracks portable rule rewrite for four indexed-event targets; the tables below describe the **intended contract** and what ships in-tree. Field maps are defined in the pipeline YAML and [Builtin Pipelines](builtin-pipelines.md); integration tests use vendor-shaped JSON that matches those maps, not pipeline output field names. {{ added "unreleased" }}

## Shipped pipelines

| Target | Load | Pipeline file | Builtin `-p` name |
|--------|------|---------------|-------------------|
| ECS (Windows) | `ecs_windows` | [`ecs_windows.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/ecs_windows.yml) | yes |
| ECS (Linux) | `ecs_linux` | [`ecs_linux.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/ecs_linux.yml) | yes |
| Splunk CIM | path | [`cim_events.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/cim_events.yml) | no |
| OCSF live JSON | path | [`ocsf_events.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/ocsf_events.yml) | no |
| CrowdStrike Falcon (Windows sensor JSON) | path | [`falcon_windows.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/falcon_windows.yml) | no |

Related path-only helper (not an ECS/CIM/OCSF/Falcon canonicalizer): [`gcp_audit.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/gcp_audit.yml) strips SigmaHQ `data.` prefixes for GCP audit rules.

## Sigma categories covered (portable core)

These five `logsource.category` values are the **issue #330 contract**, aligned with `ecs_linux` and portable Sigma rules:

| Category | ECS Windows/Linux | CIM | OCSF eval | Falcon Windows |
|----------|-------------------|-----|-----------|----------------|
| `process_creation` | yes | yes | yes | yes (`ProcessRollup2`) |
| `network_connection` | yes | yes | yes | yes (`NetworkConnectIP4`) |
| `file_event` | yes | yes | yes | yes (`PeFileWritten`, `FileWritten`, `NewFileWritten`) |
| `image_load` | yes | yes | yes | yes (`ImageLoadRollup2`) |
| `dns_query` | yes | yes | yes | yes (`DnsRequest`) |

Field-level maps live in [Builtin Pipelines](builtin-pipelines.md) (builtins and path-only sections). Integration tests in `crates/rsigma-eval/tests/*_pipeline.rs` exercise every category in the table with positive matches; each file includes negative controls when `-p` is not applied.

## Intentionally not in issue #330 scope

| Area | Use instead |
|------|-------------|
| Windows-only Sigma categories (`registry_event`, `pipe_created`, `driver_load`, `create_remote_thread`, `process_access`, …) on non-ECS targets | `ecs_windows` + `sysmon`, or vendor-specific rules |
| Falcon macOS/Linux `event_platform` and `NetworkConnectIP6` | Out of scope; use vendor-native rules or a follow-up pipeline file |
| OCSF **Detection Finding** sink output (`?format=ocsf`) | [OCSF Findings](../guide/ocsf-findings.md) |
| Postgres **convert** OCSF layout | `rsigma-convert/pipelines/ocsf_postgres*.yml` |
| `backend convert -t crowdstrike` | pySigma via [sigma-cli](backends/sigma-cli.md) |

## OCSF vs convert vs sink

| Mechanism | Purpose |
|-----------|---------|
| `ocsf_events.yml` | Rule rewrite on **input** OCSF JSON during eval/daemon |
| `?format=ocsf` on a sink | **Output** as class 2004 findings |
| `ocsf_postgres.yml` | SQL column names for `backend convert` |

## See also

- [Processing Pipelines](../guide/processing-pipelines.md)
- [Builtin Pipelines](builtin-pipelines.md)
