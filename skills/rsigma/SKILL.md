---
name: rsigma
description: "Use the rsigma CLI and MCP server: engine eval, engine daemon, rule lint, rule fmt, rule draft, rule tune, rule backtest, rule coverage, rule scorecard, hunt run, backend convert, mcp serve. Prefer MCP tools when rsigma mcp serve is connected. For authoring Sigma YAML (detection, correlation, filters, pipelines, modifiers), use the sigma-rules skill. Use this skill whenever the user mentions rsigma, evaluating, linting, or formatting Sigma rules, matching rules against ECS, CIM, OCSF, Falcon, or UDM events, converting rules to a SIEM query, running a detection daemon, drafting or tuning rules from events, hunting an archive, measuring ATT&CK coverage, or backtesting and reviewing a ruleset, even if they do not name the binary."
---

# rsigma

Use rsigma to run Sigma rules. Author the YAML with the [sigma-rules](https://github.com/timescale/sigma-rules) skill (`npx skills add timescale/sigma-rules -g -y`). This skill covers the toolchain: command names, when to call MCP versus the CLI, and which command fits the job.

Flag tables and option lists live at [rsigma.io](https://rsigma.io/). Read them when you need a flag. Do not invent flags, and do not quote lint or auto-fix counts. The [linting guide](https://rsigma.io/guide/linting-rules/) is the catalogue.

## Command names

The CLI is noun-led. These old top-level forms do not exist:

| Do not run | Run instead |
|------------|-------------|
| `rsigma eval` | `rsigma engine eval` |
| `rsigma lint` | `rsigma rule lint` |
| `rsigma validate` | `rsigma rule validate` |
| `rsigma daemon` | `rsigma engine daemon` |

Groups:

| Group | Use it for |
|-------|------------|
| `engine` | Evaluate events, explain a miss, classify schemas, and run or inspect the daemon (`eval`, `explain`, `classify`, `discover-schemas`, `status`, `incidents`, `tap`, `tail`, `daemon`) |
| `rule` | Check and build rules (`parse`, `validate`, `lint`, `fmt`, `fields`, `draft`, `tune`, `reverse`, `doc`, `test`, `backtest`) and review a rule set (`coverage`, `scorecard`, `visibility`, `hygiene`) |
| `backend` | Convert rules to a query (`convert`, `targets`, `formats`) |
| `pipeline` | See how a pipeline rewrites a rule (`diff`) and dry-run dynamic sources (`resolve`) |
| `hunt` | Run converted rules read-only against a PostgreSQL archive and stream the matching rows back as events (`run`) |
| `mcp` | Serve the toolchain to an agent (`serve`) |
| `config` | Scaffold and inspect `rsigma.yaml`, and ask a running daemon to reload (`reload`) |
| `taxii` | Fill the local STIX store that `stix` enrichers read (`sync` from a TAXII server, `store` from a bundle file) |

`engine daemon` and `pipeline resolve` need a build with the `daemon` feature, and `mcp serve` needs `mcp`. `hunt run` executes queries only with `hunt-postgres` (`--emit sql` works in every build), `taxii` needs `taxii-sync`, and `stix` and `mmdb` enrichers need `stix-enrich` and `mmdb-enrich`. Release binaries and the Docker image include all of them; a `cargo install rsigma` build has only `daemon`. `rsigma --features` prints what this binary was built with.

Full tree: [CLI reference](https://rsigma.io/cli/).

## Prefer MCP when it is connected

If `rsigma mcp serve` is already connected, call its tools. They return JSON (`ok`, findings, matches) and you do not scrape CLI text. If it is not connected, use the CLI commands in [workflows.md](references/workflows.md).

Start a local server only when the user wants the agent wired up:

```bash
rsigma mcp serve --rules-dir rules/
```

Always pass `--rules-dir`. Without it, path arguments are unconfined, `fix_rules` and `format_rules` cannot write, and `--http` refuses to start. A non-loopback `--http` bind also needs `--auth-token`.

Point `--daemon-url` at a running daemon when the task is live triage (incidents, silences, dispositions). Those tools stay off until that URL is set. Writes stay behind `--allow-operate-writes`. By default the daemon refuses an open-ended or broad silence: `create_silence` needs `ends_at` or `duration` and an `=` matcher on `rule`, `match.<field>`, or `correlation.group_key.<field>`, so muting several rules takes one silence per rule. A daemon without an alert pipeline refuses every silence. A repository's `./rsigma.yaml` or `.rsigmarc` cannot turn these gates on; they come from flags, the user config, or `--config`. Details: [MCP server guide](https://rsigma.io/guide/mcp-server/).

## Which command

- One-shot check against a file or a few events: `engine eval`. A long-running process with reload, metrics, and sinks: `engine daemon`. Pass the daemon's config with `--config`: a discovered `./rsigma.yaml` or `.rsigmarc` cannot set its sources, enrichers, sinks, or API auth.
- A rule from exemplar events (optional baseline, or `--groups` for a temporal correlation): `rule draft`. A rule the user already described in words: write the YAML with sigma-rules, then lint and evaluate it here.
- A noisy rule with known false positives and true positives that must still fire: `rule tune`.
- Embedded `rsigma.exemplars`: `rule test`. A separate corpus and expectations file: `rule backtest`.
- Why a rule missed: `engine explain`. How a pipeline rewrote fields: `pipeline diff`.
- Events in an ECS, Splunk CIM, OCSF, CrowdStrike Falcon, or Google SecOps UDM shape: pass the matching pipeline with `-p`. See [Match the event schema](#match-the-event-schema).
- Real events from a PostgreSQL archive to feed draft, tune, test, or backtest: `hunt run`.
- A review of the rule set: `rule coverage` for ATT&CK gaps, `rule scorecard` for keep, tune, or retire verdicts, `rule hygiene` for silent, noisy, or ownerless rules, and `rule visibility` for telemetry coverage. The detection-strategy (ADS) document on a rule: `rule doc`, or `author_ads` on MCP.

The write-lint-evaluate-convert loop, with the MCP tool beside each CLI command, is in [workflows.md](references/workflows.md), along with hunting and rule set review.

## Match the event schema

Sigma rules use Sysmon-style field names. When events use another schema, a canonicalizing pipeline rewrites the rule's fields to match, and it runs only when passed with `-p` (or `pipelines` on MCP). Without it, the rules do not match those events.

| Events | Pipeline |
|--------|----------|
| ECS on Windows | `-p ecs_windows` |
| ECS on Linux | `-p ecs_linux` |
| Splunk CIM | `-p <dir>/cim_events.yml` |
| OCSF JSON | `-p <dir>/ocsf_events.yml` |
| CrowdStrike Falcon Windows sensor JSON | `-p <dir>/falcon_windows.yml` |
| Google SecOps UDM | `-p <dir>/udm_events.yml` |

Builtins load by name; `list_builtin_pipelines` on MCP lists them. The YAML pipelines load by path. They ship in `crates/rsigma-eval/pipelines/` in the repository, not inside release binaries or the Docker image, so check out or download the file first. The CIM, OCSF, Falcon, and UDM pipelines cover only the portable categories (`process_creation`, `network_connection`, `file_event`, `image_load`, `dns_query`). `ocsf_events.yml` rewrites rules for OCSF input; it is unrelated to the `?format=ocsf` sink, which writes OCSF findings. `resolve_pipeline` or `pipeline diff` shows what a pipeline changes. Scope and field maps: [Canonicalizing Pipelines](https://rsigma.io/reference/canonicalizing-pipelines/).

## Convert

Native targets run inside rsigma. Anything else is delegated to an installed [sigma-cli](https://github.com/SigmaHQ/sigma-cli).

```bash
rsigma backend targets
rsigma backend convert -t postgres rules/
rsigma backend convert -t splunk rules/
```

Native targets are `postgres` (`postgresql`, `pg`), `lynxdb`, and `fibratus`, plus a backend-neutral `test` target that is not a deployment backend. `backend targets` is the live list. Delegated conversion needs `sigma` on `PATH` (override with `RSIGMA_SIGMA_CLI`). The Docker image has no Python, so delegation is a local-binary feature. On MCP, `convert_rules` delegates only when the server was started with `--allow-sigma-cli`. Builtin pipeline names (`ecs_windows`, `ecs_linux`, `fibratus_windows`, `sysmon`) are not translated for delegated targets. Pass a sigma-cli pipeline name or a YAML path.

See [backend convert](https://rsigma.io/cli/backend/convert/) and [sigma-cli delegation](https://rsigma.io/reference/backends/sigma-cli/).
