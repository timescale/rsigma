# Fibratus Backend

The `fibratus` backend converts Sigma rules into [Fibratus](https://github.com/rabbitstack/fibratus) rule YAML, the rule format consumed by Fibratus's open-source kernel-event detection and EDR engine. It is the first conversion target aimed at an endpoint sensor rather than a centralized log store; the produced rules drop directly into a Fibratus installation's `Rules/` directory and are accepted by the same loader that ships with the upstream rules library.

For the workflow walkthrough see [Rule Conversion](../../guide/rule-conversion.md#fibratus). For Fibratus-side operational topics (rule installation, alerting sinks, the filter language, the macro library) see the [Fibratus documentation](https://www.fibratus.io/).

## How it differs from PostgreSQL and LynxDB

Fibratus is a runtime detection engine, not a log store. Three differences drive the backend design:

- **Case-insensitive matching needs an operator switch, not a wrapper.** Fibratus's plain operators (`=`, `contains`, `startswith`, `endswith`, `matches`, `in`, `intersects`) are case-sensitive; the `i`-prefixed cousins (`icontains`, `istartswith`, ...) and the `~=` string-equality operator are not. Sigma defaults to case-insensitive matching, so the backend emits the case-insensitive forms by default and flips to the bare forms only when Sigma's `|cased` modifier is present (or when `-O case_sensitive=true` is set globally). Plain literal equality (no `*`/`?` wildcards) uses the dedicated string-equality operators (`~=` default, `=` cased) instead of a wildcard match because they evaluate more efficiently and read the way the upstream rules library writes literal equality; `imatches`/`matches` are reserved for values that actually carry wildcards. The `evt.name` event discriminator always uses the exact `=` operator, matching the macro and rules libraries.
- **Regex is a function call, not an operator.** Fibratus has no `=~`-style regex operator; instead it exposes the [`regex(field, 'pat1', 'pat2', ...) = true`](https://www.fibratus.io/) filter function. Sigma `|re` lowers to that call; the negated form uses a leading `not`. The underlying RE2 engine rejects PCRE-only constructs (lookarounds, backreferences); patterns that use those return a structured `UnsupportedModifier` rather than emitting something Fibratus would reject at load time.
- **YAML envelope, not query string.** Every rule emits as a complete YAML document with `name`, `id`, `description`, `labels`, `condition`, `min-engine-version`, and optional `action`. Multi-rule output is `---`-separated so the entire stream loads as a valid YAML stream.

Fibratus has a native `not` operator and no parser envelope, so the backend ships no De Morgan negation push-down (unlike Loki) and no stream-selector machinery.

## Backend options

Pass with `-O key=value` (repeatable). Unknown keys are silently ignored so forward-compatible flags can be added without breaking existing invocations.

| Option | Default | Purpose |
|--------|---------|---------|
| `action` | unset | Comma-separated list of Fibratus actions to append to each rule envelope (`-O action=kill,isolate` emits `action: [- name: kill, - name: isolate]`). |
| `min_engine` | `3.0.0` | Value written to the `min-engine-version:` field of every emitted rule. |
| `use_macros` | `true` | When `true`, rewrites recognized condition clause runs into idiomatic Fibratus macro calls (`spawn_process`, `create_thread`, `write_file`, `read_file`, `open_file`, `create_file`, `set_value`, `open_process`, `open_thread`, ...). The recognizer walks top-level `and` clauses and greedy-longest-match-replaces contiguous runs that match a macro's clause sequence (single-clause forms like `evt.name = 'CreateProcess'` and multi-clause runs like `evt.name = 'CreateFile' and file.operation ~= 'OPEN' and file.status ~= 'Success'`). Each clause is matched against both the exact (`=`) and case-insensitive (`~=`) operator forms, so it recognizes the same macros regardless of `-O case_sensitive`. Set to `false` to keep the raw `evt.name = '...'` forms. |
| `default_logsource` | `windows` | Default `product:` to assume when a Sigma rule lacks an explicit logsource. Used by the matching pipeline transformations. |
| `emit_metadata` | `true` | When `false`, omit the `description:` and `labels:` blocks. Useful when the target Fibratus install already enriches rule metadata from another source. |
| `max_repeated_slots` | `5` | Maximum number of repeated/distinct sequence stages the backend generates when emulating `event_count` / `value_count` correlation. Thresholds above the cap return `UnsupportedCorrelation`. |
| `temporal_permute` | `false` | When `true`, expands a `temporal` (any-order) correlation into one ordered sequence document per permutation of the referenced rules (so any matching order alerts), capped at N <= 3 (1/2/6 documents). Larger correlations return `UnsupportedCorrelation`. Each document gets a distinct title and id suffix so Fibratus treats them as separate rules. |
| `correlation_method` | unset | Override a rule's own `rsigma.window` for this conversion (pySigma-style). Two values: `sliding` (the native Fibratus `sequence ... maxspan` form) and `session` (degraded sliding sequence + warning). `tumbling` is intentionally absent because Fibratus cannot represent it; passing it returns `UnsupportedCorrelation`. `rsigma backend formats fibratus` lists the available methods. |
| `gap` | unset | Default session gap (e.g. `5m`, `2h`) for rules that request a session window without declaring their own `rsigma.gap`. Used only in the warning text the degraded session path emits; the rendered Fibratus query still relies on `maxspan` for the time-window cap because the engine has no `maxpause`-style primitive. A rule's own `rsigma.gap` always wins. |
| `case_sensitive` | `false` | Force the bare (case-sensitive) operators globally. Equivalent to setting `|cased` on every value. |

## Modifier mapping

Verified against the Fibratus backend's unit tests at [`crates/rsigma-convert/src/backends/fibratus`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-convert/src/backends/fibratus).

| Sigma feature | Fibratus filter expression |
|---------------|----------------------------|
| Field equality (literal, no wildcards) | `field ~= 'value'` (Sigma defaults to case-insensitive matching; `~=` is Fibratus's case-insensitive string-equality operator). With `\|cased`: `field = 'value'`. The `evt.name` discriminator always uses `=`. |
| `contains` modifier | `field icontains 'value'` (case-insensitive default); `field contains 'value'` with `\|cased`. |
| `startswith` / `endswith` modifier | `field istartswith 'value'` / `field iendswith 'value'`; bare form with `\|cased`. |
| Wildcards (`*`, `?`) in the value | `field imatches '*pat?ern*'`; bare `matches` with `\|cased`. |
| Multi-value list (OR / "any of") | A single list-operator clause: `field iin ('a', 'b')` for literals, `field imatches ('a*', 'b?')` when any value carries a wildcard, `field icontains ('a', 'b')` / `istartswith` / `iendswith` for the substring modifiers (bare `in`/`matches`/`contains`/... with `\|cased`). |
| Multi-value list with `\|all` ("all of") | AND-joined individual clauses (`field icontains 'a' and field icontains 'b'`); a list right-hand side is OR-only, so conjunction cannot collapse into one clause. |
| Regex (`re` modifier) | `regex(field, 'pattern') = true`; multi-value `\|re` collapses into a single variadic call `regex(field, 'p1', 'p2') = true`; the negated form is `not regex(field, 'pattern') = true`. Patterns using lookarounds (`(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`) or backreferences are rejected up-front with `UnsupportedModifier`. |
| CIDR (`cidr` modifier) | `cidr_contains(field, '10.0.0.0/8')`; multi-value `\|cidr` collapses into a single variadic call `cidr_contains(field, '10.0.0.0/8', '172.16.0.0/12')`. |
| Numeric compare (`gt`/`gte`/`lt`/`lte`) | `field > N`, `field >= N`, `field < N`, `field <= N`. |
| `exists: true` / `false` | `field != false` / `field = false` (Fibratus has no `null`; presence is expressed against the field's zero value). |
| `null` value | `field = ''` (Fibratus has no `null` token, so a null comparison is an empty-string comparison). |
| Field reference (`fieldref` modifier) | `field1 = field2` (Fibratus supports field-to-field comparison natively). |
| Boolean `AND`, `OR`, `NOT` | Lowercase tokens; OR groups inside AND are explicitly parenthesized so the standard Sigma precedence is preserved. |
| Keywords (unbound full-text search) | `UnsupportedKeyword` — Sigma keywords have no field, and Fibratus operators require a bound field, so there is no faithful lowering. Bind the search to a field via a pipeline if you need it. |

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
| `process_creation` | `CreateProcess` | `Image -> ps.exe`, `CommandLine -> ps.cmdline`, `ProcessId -> ps.pid`, `User -> ps.username` (on a Fibratus 3.0.0 `CreateProcess` event `ps.*` is the *created* child process); `ParentImage -> ps.parent.exe`, `ParentCommandLine -> ps.parent.cmdline`, `ParentProcessId -> ps.parent.pid` (the spawning process) |
| `process_termination` | `TerminateProcess` | `Image -> ps.exe`, `ProcessId -> ps.pid` |
| `file_event` (file creation) | `CreateFile` with `not (file.operation ~= 'OPEN')` | `TargetFilename -> file.path`, `Image -> ps.exe`. Sigma `file_event` is a file *creation* event, so the disposition guard excludes plain opens (the `create_file` macro semantics) and the rule does not fire on file access. |
| `file_access` (file open) | `open_file` macro (`CreateFile` + `file.operation = 'OPEN'` + `file.status = 'Success'`) | `FileName -> file.path`, `Image -> ps.exe`. Sigma `file_access` (Microsoft-Windows-Kernel-File ETW provider) is a file *open* event, so the disposition guard keeps only opens. |
| `file_delete` | `DeleteFile` | `TargetFilename -> file.path` |
| `network_connection` | `Connect` | `DestinationIp -> net.dip`, `DestinationPort -> net.dport`, `DestinationPortName -> net.dport.name`, `SourceIp -> net.sip`, `Protocol -> net.l4.proto` |
| `dns_query` | `QueryDns` | `QueryName -> dns.name`, `QueryStatus -> dns.rcode`, `QueryResults -> dns.answers` |
| `image_load` | `LoadModule` | `ImageLoaded -> module.path`, `OriginalFileName -> module.path`, `Signed -> module.signature.exists`, `Signature -> module.signature.subject` |
| `registry_set` | `RegSetValue` | `TargetObject -> registry.path`, `Details -> registry.data` |
| `registry_add` | `RegCreateKey` | `TargetObject -> registry.path` |
| `registry_delete` | `RegDeleteKey` | `TargetObject -> registry.path` |
| `create_remote_thread` | `CreateThread` | `SourceImage -> ps.exe`, `SourceProcessId -> ps.pid`, `TargetProcessId -> thread.pid`, `StartAddress -> thread.start_address`, `StartModule -> thread.start_address.module`, `StartFunction -> thread.start_address.symbol` (no `thread.image` field exists on `CreateThread` events; Sigma `TargetImage` rules fail conversion under this logsource) |
| `driver_load` | `LoadModule` | `ImageLoaded -> module.path`, `Signed -> module.signature.exists`, `Signature -> module.signature.subject` |
| `process_access` | `OpenProcess` | `SourceImage -> ps.exe`, `SourceProcessId -> ps.pid` (the caller); `TargetImage -> evt.arg[exe]`, `TargetProcessId -> evt.arg[pid]` (the opened process, exposed as event arguments; the upstream 3.0.0 LSASS-access rule tests `evt.arg[exe] imatches '?:\Windows\System32\lsass.exe'`); `GrantedAccess -> ps.access.mask.names` (named access-right slice) |

Field names target the Fibratus 3.0.0 registry. The legacy `image.*` namespace is deprecated in favor of `module.*` for loaded executables/DLLs, and DNS fields live under `dns.*` (not `net.dns.*`). Sigma fields with no 3.0.0 equivalent (`SignatureStatus`, `Hashes`, `Imphash` under `image_load`/`driver_load`; `DestinationHostname`, `Initiated` under `network_connection`) are intentionally not mapped, so a rule that depends on one fails conversion rather than emitting a field the loader rejects.

The pipeline injects the `evt.name` discriminator as the *first* condition (via `add_condition`'s `prepend: true`), so the emitted rule leads with the cheapest, most selective predicate (`spawn_process and ...`) and Fibratus short-circuits before evaluating the rest of the rule body.

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
  spawn_process and ps.exe iendswith '\\cmd.exe'
  and ps.parent.exe iendswith '\\explorer.exe' and ps.cmdline icontains 'whoami'
min-engine-version: 3.0.0
```

The leading `spawn_process` is the macro recognizer rewriting the raw `evt.name = 'CreateProcess'` clause the pipeline injects first; set `-O use_macros=false` to keep the raw `evt.name = 'CreateProcess'` form.

### `expr`

Filter expression only, no YAML envelope. Useful for piping into ad-hoc Fibratus run commands:

```text
spawn_process and ps.exe iendswith '\\cmd.exe' and ps.parent.exe iendswith '\\explorer.exe' and ps.cmdline icontains 'whoami'
```

## One file per rule

Fibratus loads one YAML rule per file from its `Rules/` directory, so the backend can write a separate file per converted rule instead of a single `---`-separated stream. This happens automatically when `--output` points at a directory: an existing directory, or a path with a trailing separator (which is created on demand). Each rule lands in `<title-slug>.yml`, ready to drop straight into the sensor:

```sh
rsigma backend convert rules/windows/ -t fibratus -p fibratus_windows -o ./Rules/
```

File stems are a snake_case slug of the rule title (`Detect Whoami` becomes `detect_whoami.yml`), matching the upstream rules-library naming style; the rule id and then a `rule` literal are fallbacks when a title slugifies to nothing, and colliding names get a numeric suffix (`same.yml`, `same_2.yml`) so no rule overwrites another. A rule that converts to several documents (a `temporal` correlation expanded with `-O temporal_permute=true`, for example) keeps them together in its one file. Without a directory `--output`, the behavior is unchanged: the whole stream goes to stdout or to the single file you name.

## Correlation rules

Fibratus 1.10+ uses an inline DSL inside `condition:` for stateful sequences; the backend lowers Sigma correlation rules to that DSL. Coverage matrix:

| Sigma correlation type | Fibratus mapping | Notes |
|------------------------|------------------|-------|
| `temporal_ordered` | `sequence` with one `\|...\|` stage per referenced rule in declaration order and a single sequence-level `by <group_by fields>` clause. | First-class. |
| `temporal` (any-order) | Same shape by default (ordered fallback documented in the rule description). With `-O temporal_permute=true` and N <= 3 referenced rules, the backend emits one ordered sequence per permutation (N!: 1, 2, or 6 documents per correlation) so any matching order alerts; permutations get distinct title and id suffixes (`(order: r1 -> r2)`, `-perm-<idx>`). | N > 3 returns `UnsupportedCorrelation`. |
| `rsigma.window: sliding` (default) | Native: the `sequence ... maxspan <duration>` DSL is itself a sliding total-span constraint per stage, so the rule's `timespan` becomes `maxspan` and nothing else changes. | -- |
| `rsigma.window: tumbling` | Unsupported (`UnsupportedCorrelation`): Fibratus has no calendar-aligned bucket primitive. | Drop the attribute (default `sliding`) or convert with `-O correlation_method=sliding`. |
| `rsigma.window: session` (with `rsigma.gap`) | Degraded sliding sequence with a warning: the rule still emits as `sequence ... maxspan <timespan>`, but the per-step gap is NOT enforced because Fibratus has no `maxpause`-style primitive. The warning surfaces on stderr at `rsigma backend convert` time. | A `-O gap=<duration>` provides a default for rules that do not declare their own `rsigma.gap`. |
| `event_count` with `gte`/`gt` threshold up to `-O max_repeated_slots` | `sequence` with N repeated stages of the referenced rule. | Default cap: 5. |
| `value_count` over a single `field:` with the same threshold cap | `sequence` with N stages plus pairwise inequality constraints using positional pattern bindings (`field != $1.field and field != $2.field and ...`). | Single-field only. |
| `event_count` / `value_count` with `lt`/`lte`/`eq`/`neq` predicates, ranges, or thresholds above the cap | `UnsupportedCorrelation` | The bounded-sequence emulation only expresses "at least N occurrences". |
| `value_sum`, `value_avg`, `value_percentile`, `value_median` | `UnsupportedCorrelation` | Fibratus has no running-sum / quantile primitive. |

The `group-by` fields are shared by every referenced rule, so the join is emitted once as a sequence-level `by field1, field2, ...` clause (after `maxspan`, before the stages), matching the upstream rules-library style. No inline `$1.<field> = <field>` bindings are needed for multi-field group-by.

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
  by net.sip
    |evt.name = 'AuthFail'|
    |evt.name = 'AuthFail'|
    |evt.name = 'AuthFail'|
min-engine-version: 3.0.0
```

## Caveats and follow-ups

- **`create_remote_thread.TargetImage`.** The `process_access` logsource's target-process fields map to event arguments (`evt.arg[exe]`, `evt.arg[pid]`), but a bare `CreateThread` event does not expose the target executable path the way `OpenProcess` does. Sigma rules under `create_remote_thread` that reference `TargetImage` fail conversion with an unsupported-field error; pair with a custom pipeline if your Fibratus build exposes it under another name. `TargetProcessId` maps to `thread.pid` (the cross-process pointer the `create_remote_thread` macro itself uses).
- **`|all` multi-value lists.** A Fibratus list right-hand side (`field in (...)`, `field icontains (...)`, ...) carries OR ("any of") semantics, so the AND semantics of Sigma's `|all` modifier cannot collapse into a single list clause; those values stay AND-joined as separate clauses.
- **Named pipes (`pipe_created`).** Fibratus has no visibility into named-pipe events without a dedicated kernel driver, so the `pipe_created` logsource is intentionally not mapped; such rules fall through unmapped (and fail conversion) rather than aliasing to an unrelated event.

## Related material

- [Fibratus documentation](https://www.fibratus.io/) — runtime, rule language, alerting.
- [Fibratus rules library](https://github.com/rabbitstack/fibratus/tree/master/rules) — upstream-hand-authored detection corpus the converter mimics stylistically.
- [Rule Conversion guide](../../guide/rule-conversion.md) — broader workflow including pipeline composition, output handling, and multi-backend strategies.
