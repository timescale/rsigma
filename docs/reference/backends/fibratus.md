# Fibratus Backend

The `fibratus` backend converts Sigma rules into [Fibratus](https://github.com/rabbitstack/fibratus) rule YAML, the rule format consumed by Fibratus's open-source Windows kernel-event detection and EDR engine. It is the first conversion target aimed at an endpoint sensor rather than a centralized log store; the produced rules drop directly into a Fibratus installation's `Rules/` directory and are accepted by the same loader that ships with the upstream rules library.

For the workflow walkthrough see [Rule Conversion](../../guide/rule-conversion.md#fibratus). For Fibratus-side operational topics (rule installation, alerting sinks, the filter language, the macro library) see the [Fibratus documentation](https://www.fibratus.io/).

## How it differs from PostgreSQL and LynxDB

Fibratus is a runtime detection engine, not a log store. Three differences drive the backend design:

- **Case-insensitive matching needs an operator switch, not a wrapper.** Fibratus's plain operators (`=`, `contains`, `startswith`, `endswith`, `matches`, `in`, `intersects`) are case-sensitive; the `i`-prefixed cousins (`icontains`, `istartswith`, ...) are case-insensitive. Sigma defaults to case-insensitive matching, so the backend emits the `i`-prefixed forms by default and flips to the bare forms only when Sigma's `|cased` modifier is present (or when `-O case_sensitive=true` is set globally).
- **Regex is a function call, not an operator.** Fibratus has no `=~`-style regex operator; instead it exposes the [`regex(field, 'pat1', 'pat2', ...) = true`](https://www.fibratus.io/) filter function. Sigma `|re` lowers to that call; the negated form uses a leading `not`. The underlying RE2 engine rejects PCRE-only constructs (lookarounds, backreferences); patterns that use those return a structured `UnsupportedModifier` rather than emitting something Fibratus would reject at load time.
- **YAML envelope, not query string.** Every rule emits as a complete YAML document with `name`, `id`, `description`, `labels`, `condition`, `min-engine-version`, and optional `action`. Multi-rule output is `---`-separated so the entire stream loads as a valid YAML stream.

Fibratus has a native `not` operator and no parser envelope, so the backend ships no De Morgan negation push-down (unlike Loki) and no stream-selector machinery.

## Backend options

Pass with `-O key=value` (repeatable). Unknown keys are silently ignored so forward-compatible flags can be added without breaking existing invocations.

| Option | Default | Purpose |
|--------|---------|---------|
| `action` | unset | Comma-separated list of Fibratus actions to append to each rule envelope (`-O action=kill,isolate` emits `action: [- name: kill, - name: isolate]`). |
| `min_engine` | `3.0.0` | Value written to the `min-engine-version:` field of every emitted rule. |
| `use_macros` | `true` | Phase-3 macro recognition. Reserved for a follow-up pass that rewrites recognized condition sub-trees as upstream macro calls (`spawn_process`/`open_file`/...). Currently a no-op flag. |
| `default_logsource` | `windows` | Default `product:` to assume when a Sigma rule lacks an explicit logsource. Used by the matching pipeline transformations. |
| `emit_metadata` | `true` | When `false`, omit the `description:` and `labels:` blocks. Useful when the target Fibratus install already enriches rule metadata from another source. |
| `max_repeated_slots` | `5` | Maximum number of repeated/distinct sequence stages the backend generates when emulating `event_count` / `value_count` correlation. Thresholds above the cap return `UnsupportedCorrelation`. |
| `temporal_permute` | `false` | Reserved for emitting `N!` permutation rules under the same group for `temporal` (any-order) correlations. Currently the backend falls back to the ordered form. |
| `case_sensitive` | `false` | Force the bare (case-sensitive) operators globally. Equivalent to setting `|cased` on every value. |

## Modifier mapping

Verified against the Fibratus backend's unit tests at [`crates/rsigma-convert/src/backends/fibratus`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-convert/src/backends/fibratus).

| Sigma feature | Fibratus filter expression |
|---------------|----------------------------|
| Field equality | `field imatches 'value'` (Sigma defaults to case-insensitive string matching; `imatches` without wildcards is a literal-equality glob and preserves the semantics). With `\|cased`: `field matches 'value'`. |
| `contains` modifier | `field icontains 'value'` (case-insensitive default); `field contains 'value'` with `\|cased`. |
| `startswith` / `endswith` modifier | `field istartswith 'value'` / `field iendswith 'value'`; bare form with `\|cased`. |
| Wildcards (`*`, `?`) in the value | `field imatches '*pat?ern*'`; bare `matches` with `\|cased`. |
| Regex (`re` modifier) | `regex(field, 'pattern') = true`; the negated form is `not regex(field, 'pattern') = true`. Patterns using lookarounds (`(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`) or backreferences are rejected up-front with `UnsupportedModifier`. |
| CIDR (`cidr` modifier) | `cidr_contains(field, '10.0.0.0/8')`. |
| Numeric compare (`gt`/`gte`/`lt`/`lte`) | `field > N`, `field >= N`, `field < N`, `field <= N`. |
| `exists: true` / `false` | `field != null` / `field = null`. |
| `null` value | `field = null`. |
| Field reference (`fieldref` modifier) | `field1 = field2` (Fibratus supports field-to-field comparison natively). |
| Boolean `AND`, `OR`, `NOT` | Lowercase tokens; OR groups inside AND are explicitly parenthesized so the standard Sigma precedence is preserved. |
| IN-list helper (`convert_condition_as_in_expression`) | `field iin ('a', 'b')` by default; `field in ('a', 'b')` when every item has `|cased` or `-O case_sensitive=true` is set. |
| Keywords (unbound full-text search) | `UnsupportedKeyword` — Fibratus has no equivalent of Splunk-style keyword search. |

Integer, float, and boolean values keep their literal form (`evt.pid = 4`, `ps.is_protected = true`). Strings are single-quoted; literal `\`, `'`, `*`, and `?` characters are backslash-escaped so the filter engine treats them as literals everywhere outside `matches`/`imatches` wildcards.

## Field naming

Fibratus identifiers are lowercase dotted paths (`ps.exe`, `ps.cmdline`, `file.path`, `registry.path`, `net.dip`, `thread.callstack.symbols`). Sigma rules use PascalCase Windows-event field names (`Image`, `CommandLine`, `TargetFilename`, `TargetObject`, `DestinationIp`). The backend does not invent field renames on its own; the bundled `fibratus_windows` builtin pipeline does the translation per logsource category.

Always pair the backend with `-p fibratus_windows` when converting upstream SigmaHQ Windows rules:

```sh
rsigma backend convert rules/windows/process_creation/ -t fibratus -p fibratus_windows
```

The pipeline maps logsource categories to `evt.name` discriminators and renames fields:

| Sigma logsource | Fibratus `evt.name` | Representative field renames |
|-----------------|---------------------|-------------------------------|
| `process_creation` | `CreateProcess` | `Image -> ps.exe`, `CommandLine -> ps.cmdline`, `ParentImage -> ps.parent.exe`, `User -> ps.username` |
| `process_termination` | `TerminateProcess` | `Image -> ps.exe`, `ProcessId -> ps.pid` |
| `file_event` | `CreateFile` | `TargetFilename -> file.path`, `Image -> ps.exe` |
| `file_delete` | `DeleteFile` | `TargetFilename -> file.path` |
| `network_connection` | `Connect` | `DestinationIp -> net.dip`, `DestinationPort -> net.dport`, `SourceIp -> net.sip`, `Initiated -> net.is_outbound` |
| `dns_query` | `QueryDns` | `QueryName -> net.dns.name`, `QueryStatus -> net.dns.rcode`, `QueryResults -> net.dns.answers` |
| `image_load` | `LoadModule` | `ImageLoaded -> image.path`, `Signed -> image.signature.exists`, `Hashes -> image.hashes` |
| `registry_set` | `RegSetValue` | `TargetObject -> registry.path`, `Details -> registry.value` |
| `registry_add` | `RegCreateKey` | `TargetObject -> registry.path` |
| `registry_delete` | `RegDeleteKey` | `TargetObject -> registry.path` |
| `pipe_created` | `CreateFile` + `file.type = 'Pipe'` | `PipeName -> file.name` |
| `create_remote_thread` | `CreateThread` | `SourceImage -> ps.exe`, `TargetImage -> thread.image`, `StartAddress -> thread.start_address` |
| `driver_load` | `LoadModule` | `ImageLoaded -> image.path`, `Signed -> image.signature.exists` |
| `process_access` | `OpenProcess` | `SourceImage -> ps.exe`, `TargetImage -> ps.access.image`, `GrantedAccess -> ps.access.mask` |

A final `change_logsource` transformation tags every matched rule with `product: windows`, `service: fibratus` so downstream tooling can re-route by service.

## ATT&CK tags

Sigma `tags:` entries are flattened into the `labels:` block Fibratus expects. The mapping mirrors how the [upstream Fibratus rules library](https://github.com/rabbitstack/fibratus/tree/master/rules) names ATT&CK labels:

- `attack.<tactic_short_name>` becomes `tactic.id` + `tactic.name` + `tactic.ref` via a static MITRE ATT&CK lookup.
- `attack.t<NNNN>` (a base technique) becomes `technique.id` + `technique.ref`.
- `attack.t<NNNN>.<sub>` (a sub-technique) becomes `subtechnique.id` + `subtechnique.ref`. The parent `technique.*` keys are only emitted if the rule *also* carries the base-technique tag; the backend does not invent a parent technique because doing so would diverge from the rule author's stated tags.
- Anything else passes through as `tag.<original>: <original>` so the YAML loader sees a string value rather than a typed bool.

```yaml
tags:
  - attack.defense_evasion
  - attack.t1055
  - attack.t1055.001
```

becomes

```yaml
labels:
  tactic.id: TA0005
  tactic.name: Defense Evasion
  tactic.ref: 'https://attack.mitre.org/tactics/TA0005/'
  technique.id: T1055
  technique.ref: 'https://attack.mitre.org/techniques/T1055/'
  subtechnique.id: T1055.001
  subtechnique.ref: 'https://attack.mitre.org/techniques/T1055/001/'
```

## Output formats

Pick with `-f <format>`. Four formats; `default`, `yaml`, and `rule` are aliases for the same YAML envelope:

### `default` (alias `yaml`, `rule`)

One YAML rule document per Sigma rule, separated by `---`:

```yaml
name: Suspicious cmd via Explorer
id: 11111111-2222-3333-4444-555555555555
description: |
  Detect cmd.exe spawned by explorer.exe with whoami in args.
labels:
  tactic.id: TA0002
  tactic.name: Execution
  tactic.ref: 'https://attack.mitre.org/tactics/TA0002/'
condition: >
  ps.exe iendswith '\\cmd.exe' and ps.parent.exe iendswith '\\explorer.exe'
  and ps.cmdline icontains 'whoami' and evt.name imatches 'CreateProcess'
min-engine-version: 3.0.0
```

### `expr`

Filter expression only, no YAML envelope. Useful for piping into ad-hoc Fibratus run commands:

```text
ps.exe iendswith '\\cmd.exe' and ps.parent.exe iendswith '\\explorer.exe' and ps.cmdline icontains 'whoami' and evt.name imatches 'CreateProcess'
```

## Correlation rules

Fibratus 1.10+ uses an inline DSL inside `condition:` for stateful sequences; the backend lowers Sigma correlation rules to that DSL. Coverage matrix:

| Sigma correlation type | Fibratus mapping | Notes |
|------------------------|------------------|-------|
| `temporal_ordered` | `sequence` with one stage per referenced rule in declaration order, `\| by <primary group_by field>` per stage. | First-class. |
| `temporal` (any-order) | Same shape; Fibratus sequences are ordered. | Document the divergence in your rule description. |
| `event_count` with `gte`/`gt` threshold up to `-O max_repeated_slots` | `sequence` with N repeated stages of the referenced rule. | Default cap: 5. |
| `value_count` over a single `field:` with the same threshold cap | `sequence` with N aliased stages (`\| as e1`, `\| as e2`, ...) plus pairwise inequality constraints (`field != $e1.field and field != $e2.field and ...`). | Single-field only. |
| `event_count` / `value_count` with `lt`/`lte`/`eq`/`neq` predicates, ranges, or thresholds above the cap | `UnsupportedCorrelation` | The bounded-sequence emulation only expresses "at least N occurrences". |
| `value_sum`, `value_avg`, `value_percentile`, `value_median` | `UnsupportedCorrelation` | Fibratus has no running-sum / quantile primitive. |

Secondary group-by fields (beyond the first) are pinned via inline `and $1.<field> = <field>` bindings on every stage past the first, so multi-field group-by works regardless of whether the Fibratus `by` clause supports lists.

Example: 3 failed authentications from the same source IP within 5 minutes lowers to

```yaml
name: Brute force from single source
id: 22222222-aaaa-bbbb-cccc-000000000002
description: |
  3 failed logins from the same source within 5 minutes.
labels:
  tactic.id: TA0006
  tactic.name: Credential Access
  tactic.ref: 'https://attack.mitre.org/tactics/TA0006/'
  technique.id: T1110.001
  technique.ref: 'https://attack.mitre.org/techniques/T1110/001/'
condition: >
  sequence
  maxspan 5m
    |evt.name imatches 'AuthFail'
    | by net.sip
    |evt.name imatches 'AuthFail'
    | by net.sip
    |evt.name imatches 'AuthFail'
    | by net.sip
min-engine-version: 3.0.0
```

## Caveats and follow-ups

- **Multi-value CIDR / regex.** The shared `default_convert_detection_item` dispatch only reads the first value when the field carries `|cidr` or `|re`. This affects every text backend in the workspace; the Fibratus backend inherits the gap. Workaround: emit one rule per CIDR/regex value, or split with `|` alternation inside a single regex pattern.
- **`temporal_permute`.** The CLI option is reserved; the backend currently falls back to the ordered form for `temporal` correlations even with the flag set. Permutation emission is a follow-up.
- **Macro recognition (`use_macros`).** The macro library is loaded at backend init, but the AST-level recognition pass that rewrites recognized sub-trees into idiomatic macro calls (`spawn_process`, `open_file`, ...) is not wired yet. The flag has no effect today; the rendered output uses the raw `evt.name = '...'` forms instead of macros.

## Related material

- [Fibratus documentation](https://www.fibratus.io/) — runtime, rule language, alerting.
- [Fibratus rules library](https://github.com/rabbitstack/fibratus/tree/master/rules) — upstream-hand-authored detection corpus the converter mimics stylistically.
- [Rule Conversion guide](../../guide/rule-conversion.md) — broader workflow including pipeline composition, output handling, and multi-backend strategies.
