# sigma-cli delegation

rsigma converts a handful of targets natively (`postgres`, `lynxdb`, `fibratus`). For any other target, `rsigma backend convert` delegates to an external [sigma-cli](https://github.com/SigmaHQ/sigma-cli) when one is installed, so the full pySigma backend ecosystem (`splunk`, `elasticsearch`, `kusto`, `qradar`, `loki`, `crowdstrike`, and 30+ more) is reachable through the same `rsigma backend convert` command. This is a light subprocess wrapper, not an embedded Python interpreter: no Python runtime is required unless you actually convert to a delegated target.

## Resolution order

`rsigma backend convert -t <target>` resolves the target in this order:

1. **Native backend.** If rsigma has a native backend for the target (`postgres`/`postgresql`/`pg`, `lynxdb`, `fibratus`), it is used, exactly as before. Native always wins.
2. **Delegated to sigma-cli.** Otherwise, if a `sigma` executable is discoverable, rsigma runs `sigma convert` with the original rule files and a mapped flag set, and relays its output. The result is identical to running sigma-cli directly.
3. **Error.** If neither is available, the command exits with code `3` and prints guidance to install sigma-cli (or fix the discovery override).

Because native always wins, a target that is delegated today is transparently taken over by a native backend if one ships later, with no change to how you invoke it.

## Discovery

rsigma finds sigma-cli in this order:

1. The `RSIGMA_SIGMA_CLI` environment variable, when set to a path to the `sigma` executable. An empty value is treated as unset.
2. A bare `sigma` resolved on `PATH`.

A spawn that fails because the executable is missing is reported as "not found" with install guidance, rather than as a conversion failure.

## Installing sigma-cli

```bash
pipx install sigma-cli
sigma plugin install <target>   # e.g. splunk, elasticsearch, loki, kusto
```

Confirm what is installed:

```bash
sigma plugin list --plugin-type backend
rsigma backend targets           # lists native targets plus sigma-cli's
```

## Flag mapping

`rsigma backend convert` flags map almost 1:1 to `sigma convert`:

| rsigma flag | sigma-cli flag |
|-------------|----------------|
| `-t, --target <TARGET>` | `-t, --target` |
| `-f, --format <FORMAT>` | `-f, --format` |
| `-p, --pipeline <P>` (repeatable) | `-p, --pipeline` |
| `--without-pipeline` | `--without-pipeline` |
| `-s, --skip-unsupported` | `-s, --skip-unsupported` |
| `-O, --option key=value` | `-O, --backend-option key=value` |
| `-O correlation_method=<m>` | `-c, --correlation-method <m>` |
| `[RULES]...` | `INPUT...` |

`-O correlation_method=<m>` is the only transform: rsigma's option style becomes sigma-cli's dedicated `-c/--correlation-method` flag.

## Output

sigma-cli's stdout is captured and routed through rsigma's normal output handling, so `-o <file>` and `--output-format json` behave as they do for native backends. With `--output-format json`, the delegated queries are wrapped as `{ "target", "format", "engine": "sigma-cli", "queries": [ { "query": ... } ] }`, one object per output line.

## Limitations

- **Per-rule directory output is native-only.** `-o <dir>/` (one file per rule) reuses a native backend's finalizer, which a delegated stream has no equivalent of, so delegated mode rejects a directory `--output`. Use a file path or stdout.
- **Pipeline shortcut names are not translated.** rsigma's builtin pipeline names (`ecs_windows`, `sysmon`) are not mapped to sigma-cli pipeline identifiers. In delegated mode, pass a sigma-cli pipeline name (see `sigma list pipelines`) or a YAML file path to `-p`.
- **CLI only.** Delegation applies to `rsigma backend convert` (and `backend targets`/`backend formats`). The MCP `convert` tool and the `rsigma_convert` library API convert with native backends only.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Conversion succeeded. |
| `2` | sigma-cli ran but exited non-zero (an unknown target, an unconvertible rule, and so on). Its stderr is relayed verbatim. |
| `3` | No native backend and sigma-cli was not found, a directory `--output` in delegated mode, or another CLI configuration error. |

## See also

- [Rule Conversion](../../guide/rule-conversion.md#delegated-targets-sigma-cli) for the narrative workflow.
- [`backend convert`](../../cli/backend/convert.md), [`backend targets`](../../cli/backend/targets.md), [`backend formats`](../../cli/backend/formats.md).
- [PostgreSQL](postgres.md), [LynxDB](lynxdb.md), and [Fibratus](fibratus.md) for the native backends.
