# Array Matching

!!! warning "Experimental"
    Array matching is a proposed extension to the Sigma specification, not part of Sigma v2.1.0. It was accepted as a Sigma Enhancement Proposal (see [sigma-specification Discussion #106](https://github.com/SigmaHQ/sigma-specification/discussions/106), [SEP #212](https://github.com/SigmaHQ/sigma-specification/issues/212), and [rsigma #158](https://github.com/timescale/rsigma/issues/158)), but the syntax may still change as the spec text is finalized. rsigma implements it as a reference so the design can be validated against real events and multiple backends.

Many log sources put values in arrays: AWS CloudTrail, GCP, Okta, Azure Activity, Kubernetes audit, and Windows Event Logs all do. rsigma can match against array members in three ways, all expressed with `[...]` selectors on the field path.

## Requires `sigma-version: 3`

Array-matching bracket selectors are gated on the Sigma specification major a document targets, declared with the optional top-level `sigma-version` attribute. They are active only at major `3` or higher:

```yaml
title: Inbound connection to a suspicious network
sigma-version: 3
logsource:
    category: network_connection
detection:
    selection:
        connections[any]:
            protocol: 'TCP'
            ip|cidr: '123.1.0.0/16'
    condition: selection
```

When `sigma-version` is absent, a document resolves to a fixed floor (major `2`, the v2.x line). At the floor a trailing `[...]` is **not** a selector but a literal part of the field name, so an unversioned rule keeps its pre-array-matching meaning and is never silently reinterpreted. Only the major matters (a release string such as `"2.1.0"` is read for its major), since breaking changes occur only at major bumps.

The linter helps catch the mismatch: [`array_matching_without_version`](../reference/lint-rules.md) (warning) flags a rule that uses bracket-selector syntax but resolves below major `3`, and [`unsupported_sigma_version`](../reference/lint-rules.md) (error) flags a declared major newer than rsigma implements. To keep a literal bracket in a field name at major `3`, escape it as `\[` / `\]` (see [Escaping literal brackets](#escaping-literal-brackets)).

## Implicit any-member matching

A plain field expression matches a scalar **or** any member of an array. No special syntax is needed: a scalar is just an array of length one.

```yaml
detection:
    selection:
        # matches if the connections array contains 123.1.1.1
        connections: '123.1.1.1'
    condition: selection
```

This works through dotted paths too. When a path crosses an array of objects, every element is tried (any-member):

```yaml
detection:
    selection:
        # matches if ANY connection's ip is in the CIDR
        connections.ip|cidr: '123.1.0.0/16'
    condition: selection
```

All modifiers (`contains`, `startswith`, `re`, `cidr`, numeric comparisons, ...) compose and are applied per member.

## Object-scope blocks: `[any]`, `[all]`, `[all_or_empty]`, `[none]`

Implicit any-member cannot express **correlation**: "is there a connection that is both TCP *and* in a suspicious CIDR", where both predicates must hold for the **same** element. For that, append a quantifier to the field and give it a nested map. The map is evaluated against a single array element.

```yaml
detection:
    selection:
        connections[any]:        # there exists a member that satisfies BOTH:
            protocol: 'TCP'
            ip|cidr: '123.1.0.0/16'
    condition: selection
```

- `[any]`: at least one member satisfies every item in the block.
- `[all]`: the array is non-empty and every member satisfies every item in the block.
- `[all_or_empty]`: like `[all]`, but an empty or missing array also matches (the vacuously-true reading).
- `[none]`: no member satisfies the block (the dual of `[any]`); an empty or missing array matches.

```yaml
detection:
    selection:
        connections[all]:        # every connection uses TCP
            protocol: 'TCP'
    condition: selection
```

```yaml
detection:
    selection:
        containers[none]:        # no container runs a privileged image
            privileged: 'true'
    condition: selection
```

### Empty and missing arrays

The quantifiers differ only in how they treat an array with zero members (empty `[]`, JSON `null`, or a missing field):

| Quantifier | Non-empty array | Empty or missing array |
|------------|-----------------|------------------------|
| `[any]` | some member matches | no match |
| `[all]` | every member matches | no match (safe detection default) |
| `[all_or_empty]` | every member matches | match (vacuously true) |
| `[none]` | no member matches | match (vacuously true) |

Pick `[all]` when "no data" should not fire, and `[all_or_empty]` when an absent array is acceptable (for example, "every mount is read-only, and no mounts is fine too").

Blocks nest, and the quantifier composes with deeper selectors:

```yaml
detection:
    selection:
        rules[any]:
            type: 'allow'
            ip[all]|startswith: '123.1.1'   # this rule's ip array: all members start with 123.1.1
    condition: selection
```

A scalar value directly under a quantifier matches the member itself:

```yaml
tags[all]|startswith: '123.'   # every member of the tags array starts with "123."
```

### Basic and extended block bodies

The block body shown above is the **basic** form: a map of predicates, ANDed together and evaluated against one element. It covers the common case and is the simplest to convert.

When you need boolean logic beyond a conjunction (disjunction, or per-element negation), use the **extended** form: a full nested detection with named element-scoped sub-selections and its own `condition:`. A `condition:` key in the block body switches it to the extended form.

```yaml
detection:
    selection:
        connections[any]:                 # any connection in the CIDR that is NOT TCP
            condition: in_cidr and not is_tcp
            in_cidr:
                ip|cidr: '123.1.0.0/16'
            is_tcp:
                protocol: 'TCP'
    condition: selection
```

Each array element is treated as a mini-event, so the usual Sigma condition grammar (`and`, `or`, `not`, `1 of x_*`) applies per element, with every predicate bound to the same element. The basic form is exactly the extended form with an implicit `condition:` that ANDs its items. The two mirror Sigma's basic and extended correlation conditions and both are valid; an engine may implement only the basic form.

### Arrays of scalars: the `.` element reference

A block body attaches predicates to inner field names, which works for arrays of objects. For an array of **scalars** there is no inner field, so a standalone `.` references the current element itself, optionally with modifiers (`.|gte`, `.|cidr`). It generalizes the field-less shorthand (`tags[all]: value`) to multiple, named, or negated predicates. For example, "any 5xx response code that is not 504":

```yaml
detection:
    selection:
        rcodes[any]:
            condition: server_error and not gateway_timeout
            server_error:
                .|gte: 500
                .|lte: 599
            gateway_timeout:
                .: 504
    condition: selection
```

`.` denotes only the standalone element; an object element's fields are still referenced by name, so there is no `.foo` mid-path form.

### Pitfall: flattened correlation does not bind to one element

It is tempting to write correlation as two sibling keys sharing a prefix:

```yaml
# WRONG: these do NOT require the same connection to be both TCP and 123.1.1.1
selection:
    connections[any].protocol: 'TCP'
    connections[any].ip: '123.1.1.1'
```

Each key opens its own independent scope, so this matches an event with a TCP connection **and** a (possibly different) connection to 123.1.1.1. The linter flags this as [`flattened_array_correlation`](../reference/lint-rules.md). Use the object-scope block above to correlate on one element, and the extended block body when the correlation needs `or`/`not` (for example "the same connection is in the CIDR and *not* TCP", which the basic conjunction map cannot express).

## Positional indexing: `field[N]`

Some arrays are **ordered**: argument vectors (`args[0]` is the process image, `args[1..]` are parameters), `[source, destination]` pairs, or delimited fields exported as arrays. Here `any` is lossy, it cannot tell which element matched. A zero-based index selects one specific element:

```yaml
detection:
    selection:
        args[0]|endswith: '\powershell.exe'   # the process image, at a fixed position
        args[1]: '-enc'                        # the first parameter, unambiguously
    condition: selection
```

An index resolves to a single, deterministic value. A missing field, a non-array value, or an out-of-range index yields no match. Indexing composes with object paths and quantifiers:

```yaml
connections[0].ip: '10.0.0.1'   # the first connection's ip
rules[any].ip[0]: '10.0.0.1'    # some rule whose first ip is 10.0.0.1
```

Negative indices count from the end: `[-1]` is the last element, `[-k]` the k-th from the end. Out-of-range in either direction yields no match.

```yaml
args[-1]: '-enc'                # the last argument, regardless of vector length
```

Because the position is fixed, sibling keys under the same index correlate correctly (unlike `[any]`/`[all]`): `connections[0].protocol` and `connections[0].ip` both bind to element 0.

### Escaping literal brackets

Only an unescaped trailing `[...]` is a selector. To match a field whose name literally contains brackets, escape them as `\[` and `\]`, the same way `\*` and `\?` escape value wildcards:

```yaml
args\[0\]: 'cmd.exe'   # a field literally named "args[0]", not index 0
```

The evaluator resolves the escaped name to the literal field. Backends that cannot express a literal-bracket field name error rather than emit a divergent query.

## `[all]` is not the `all` modifier

The existing `all` value-list [modifier](rule-conversion.md) and the `[all]` array quantifier are different axes and compose:

```yaml
CommandLine|all:            # field contains BOTH listed values (value-list AND)
    - '/ecp/default.aspx'
    - '__VIEWSTATE='

ports[all]: 443             # EVERY member of the ports array equals 443
```

## Backend support

rsigma's evaluator (`rsigma engine eval` / `engine daemon`) implements all three constructs over ordered JSON arrays and is the reference for the semantics. The converter (`rsigma backend convert`) lowers what each backend can express and errors loudly otherwise, rather than emitting a query with different semantics:

| Construct | Evaluator | PostgreSQL / TimescaleDB (JSONB) | Other backends |
|-----------|-----------|----------------------------------|----------------|
| Implicit any-member | Yes | Yes (`->>` path access) | Backend-dependent (native on Splunk/KQL multivalue fields) |
| `[any]` / `[all]` block | Yes | Yes (`jsonb_array_elements` + `EXISTS` / `NOT EXISTS`, JSONB mode) | Unsupported (`UnsupportedArrayMatching`) |
| `[all_or_empty]` / `[none]` block | Yes | Yes (`CASE`-guarded `NOT EXISTS` so empty/missing matches, JSONB mode) | Unsupported (`UnsupportedArrayMatching`) |
| Extended block body (`condition:` + named sub-selections) | Yes | Yes (same primitive as the basic block, with a boolean inner predicate `OR` / `NOT`) | Unsupported (`UnsupportedArrayMatching`) |
| Positional `[N]`, including `[-N]` | Yes | Yes (`->n` / `->>n`, negative subscripts on PG 11+, JSONB mode) | Unsupported (loud error) until backend-specific lowering lands |

PostgreSQL array matching requires JSONB-backed events (set `json_field`); in flat-column mode there is no array to unnest. The object-scope block and positional indexing both report `UnsupportedArrayMatching` on backends that cannot express them (LynxDB and other text backends today, and PostgreSQL flat-column mode), rather than emitting a query that diverges from the evaluator. A backend advertises positional-index support through `Backend::supports_field_index`. Note that Elasticsearch-style backends cannot express positional indexing at all because Lucene arrays are unordered sets; this is exactly why rsigma evaluates the index directly rather than relying on `any`.

## See also

- [Evaluating Rules](evaluating-rules.md)
- [Linting Rules](linting-rules.md) and the [`flattened_array_correlation`](../reference/lint-rules.md) rule
- [Rule Conversion](rule-conversion.md) and the [PostgreSQL backend reference](../reference/backends/postgres.md)
