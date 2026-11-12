---
description: "Reference for the optional ECS, CIM, OCSF, and Falcon pipelines that rewrite Sigma field names when you pass -p."
---

# Canonicalizing Pipelines

{{ added "0.27.0" }}

Canonicalizing pipelines rewrite Sigma rule field names to match the schema of indexed events. They are optional and run only when selected with `-p`. RSigma ships canonicalizers for ECS, Splunk CIM, OCSF, and CrowdStrike Falcon.

Field maps are defined in the pipeline YAML and documented in [Builtin Pipelines](builtin-pipelines.md). Integration tests use vendor-shaped JSON that matches those maps.

## Shipped pipelines

| Target | Load with | Pipeline file |
|--------|-----------|---------------|
| ECS (Windows) | `-p ecs_windows` | [`ecs_windows.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/ecs_windows.yml) |
| ECS (Linux) | `-p ecs_linux` | [`ecs_linux.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/ecs_linux.yml) |
| Splunk CIM | `-p crates/rsigma-eval/pipelines/cim_events.yml` | [`cim_events.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/cim_events.yml) |
| OCSF live JSON | `-p crates/rsigma-eval/pipelines/ocsf_events.yml` | [`ocsf_events.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/ocsf_events.yml) |
| CrowdStrike Falcon (Windows sensor JSON) | `-p crates/rsigma-eval/pipelines/falcon_windows.yml` | [`falcon_windows.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/falcon_windows.yml) |

The path-only [`gcp_audit.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/gcp_audit.yml) helper strips SigmaHQ `data.` prefixes from GCP audit rules. It is not a schema canonicalizer.

## Supported Sigma categories

The canonicalizers share a portable core of five `logsource.category` values:

| Category | ECS Windows/Linux | CIM | OCSF eval | Falcon Windows |
|----------|-------------------|-----|-----------|----------------|
| `process_creation` | yes | yes | yes | yes (`ProcessRollup2`) |
| `network_connection` | yes | yes | yes | yes (`NetworkConnectIP4`) |
| `file_event` | yes | yes | yes | yes (`PeFileWritten`, `FileWritten`, `NewFileWritten`) |
| `image_load` | yes | yes | yes | yes (`ImageLoadRollup2`) |
| `dns_query` | yes | yes | yes | yes (`DnsRequest`) |

Field-level maps live in [Builtin Pipelines](builtin-pipelines.md) (builtins and path-only sections). Integration tests in `crates/rsigma-eval/tests/*_pipeline.rs` exercise every category in the table with positive matches; each file includes negative controls when `-p` is not applied.

## Out of scope

| Area | Use instead |
|------|-------------|
| Windows-only Sigma categories (`registry_event`, `pipe_created`, `driver_load`, `create_remote_thread`, `process_access`, …) on non-ECS targets | `ecs_windows` + `sysmon`, or vendor-specific rules |
| Falcon macOS/Linux `event_platform` and `NetworkConnectIP6` | Vendor-native rules or a custom pipeline |
| OCSF **Detection Finding** sink output (`?format=ocsf`) | [OCSF Findings](../guide/ocsf-findings.md) |
| Postgres **convert** OCSF layout | `rsigma-convert/pipelines/ocsf_postgres*.yml` |
| `backend convert -t crowdstrike` | pySigma via [sigma-cli](backends/sigma-cli.md) |

## OCSF input, output, and conversion

| Mechanism | Purpose |
|-----------|---------|
| `ocsf_events.yml` | Rule rewrite on **input** OCSF JSON during eval/daemon |
| `?format=ocsf` on a sink | **Output** as class 2004 findings |
| `ocsf_postgres.yml` | SQL column names for `backend convert` |

## See also

- [Processing Pipelines](../guide/processing-pipelines.md)
- [Builtin Pipelines](builtin-pipelines.md)
