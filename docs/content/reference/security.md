---
description: "RSigma security hardening reference: input size caps, resource limits, parsing safeguards, SQL injection prevention, and daemon listener exposure."
---

# Security Hardening

RSigma deliberately bounds every input and every external resource it touches. This page catalogues the hard limits, the parsing safeguards, the operational concerns (process signals, lock primitives, daemon listener exposure), and the dynamic-source protections. None of these are configurable through CLI flags today; they are compile-time constants. Operators wanting different limits should fork and document the deviation locally.

For the SECURITY policy and disclosure process, see [`SECURITY.md`](../security-policy.md).

## Input size and depth caps

| Limit | Constant | Value | Scope | Behaviour on overrun |
|-------|----------|-------|-------|----------------------|
| Single event size | `MAX_LINE_BYTES` | 1 MiB | `engine daemon` stdin, `unix://`, NATS, and `POST /api/v1/events` ingest; `engine eval` stdin | Stdin and `unix://` drop the line as it arrives, without holding it, and count it in `rsigma_input_dropped_total`; a NATS message is terminated and counted; `POST /api/v1/events` refuses the whole request with `413` before forwarding any line; `engine eval` skips the line. Bytes that are not valid UTF-8 are replaced, never fatal. {{ added "unreleased" }} |
| OTLP log records per request | `OtlpLimits::max_records` | 10,000 (`--otlp-max-records`) | `POST /v1/logs` and gRPC `LogsService/Export` (`daemon-otlp`) | Counted from the encoded request before decoding; refused with `413` or `RESOURCE_EXHAUSTED` and counted as `rsigma_otlp_errors_total{reason="too_many_records"}`. {{ added "unreleased" }} |
| Flattened OTLP event | `OtlpLimits::max_record_bytes` | 1 MiB | Same | Record rejected, mostly before its event is built, and reported as a partial success. {{ added "unreleased" }} |
| Flattened OTLP events per request | `OtlpLimits::max_request_bytes` | 64 MiB | Same | That record and the rest of the request are rejected and reported as a partial success. {{ added "unreleased" }} |
| Concurrent OTLP requests | `MAX_CONCURRENT_REQUESTS` | 16 | Both OTLP transports together | Further requests wait for a slot before their bodies are read. {{ added "unreleased" }} |
| Field-key walk | `FieldKeyBudget` | 4,096 paths, 512 bytes per path, 256 KiB per event | Field observer, schema observer shapes, `Event::field_keys` | Longer paths are skipped and the walk stops at the caps; counted in `rsigma_fields_observer_oversized_keys_total` and `rsigma_fields_observer_truncated_events_total`. {{ added "unreleased" }} |
| Decompressed OTLP/HTTP body | `OTLP_HTTP_MAX_DECOMPRESSED_BYTES` | 4 MiB | `POST /v1/logs` with `Content-Encoding: gzip` (`daemon-otlp`) | Request rejected with `413` before decoding; counted as `rsigma_otlp_errors_total{reason="body_too_large"}`. The gRPC transport applies the same 4 MiB decoded-message limit. {{ added "0.25.0" }} |
| Condition expression length | `MAX_CONDITION_LEN` | 64 KiB | Rule parser | Rule rejected at parse time with an `InvalidCondition` error. |
| Condition expression depth | `MAX_CONDITION_DEPTH` | 64 | Rule parser | Same. Parentheses and each `not` in a run of `not` operators count toward the same limit. {{ added "unreleased" }} |
| Condition tree depth | `MAX_CONDITION_TREE_DEPTH` | 256 | Deserializing `ConditionExpr` | Deserialization fails as soon as the tree passes the limit, before the deserializer recurses deeper. {{ added "unreleased" }} |
| HIR tree depth | `MAX_HIR_DEPTH` | 256 | Deserializing `IrCondition`, `IrDetection`, and `IrMatcher`, including the HIR cache | Same. Condition, detection, and matcher levels count together along any path. {{ added "unreleased" }} |
| HIR cache nesting | `CBOR_RECURSION_LIMIT` | 784 CBOR containers | `Engine::load_hir` and `decode_rules` | Blob rejected with a decode error. The limit covers every tree within `MAX_HIR_DEPTH` and bounds custom attribute values, and the blob is decoded on its own 16 MiB stack. {{ added "unreleased" }} |
| Array quantifier scopes | `MAX_ARRAY_SCOPES` | 8 | Rule parser, array matching (`[any]`, `[all]`, `[all_or_empty]`, `[none]`) | Rule rejected at parse time with an `InvalidFieldSpec` error. Quantifiers in the item's key, in the keys of enclosing blocks, and in the path a block body hands down all count. {{ added "unreleased" }} |
| STIX pattern size and depth | `MAX_PATTERN_BYTES`, `MAX_AST_DEPTH` | 64 KiB, 64 | STIX pattern parser | Pattern rejected with `InputTooLarge` or `DepthExceeded`. Parentheses, `NOT`, nested `IN` lists, and `WITHIN`, `REPEATS`, and `START`/`STOP` qualifiers count toward the depth. {{ added "unreleased" }} |
| STIX pattern observations and comparisons | `MAX_OBSERVATIONS`, `MAX_COMPARISONS_PER_OBSERVATION` | 256 each | STIX pattern parser | Pattern rejected while it is parsed, as soon as the count passes the limit. {{ added "unreleased" }} |
| Reverse query length | `MAX_REVERSE_QUERY_LEN` | 64 KiB | `rule reverse` and the MCP `reverse_convert` tool | Query rejected before it is tokenized. {{ added "unreleased" }} |
| Reverse query depth | `MAX_REVERSE_QUERY_DEPTH` | 64 | Same | Query rejected with a parse error. Parentheses and `NOT`, `!`, and `-` prefixes count toward the limit, and the values of a `field:(...)` group start one level down. {{ added "unreleased" }} |
| JSON event traversal depth | `MAX_NESTING_DEPTH` | 64 | Keyword search inside nested JSON | Traversal stops; deeper fields are not matched against keyword detections. |
| Windash expansion | `MAX_WINDASH_VARIANTS_PER_ITEM`, `MAX_WINDASH_VARIANTS_PER_RULE` | 4,096 variants per detection item, 16,384 per rule or filter | `\|windash` modifier (5^k variants for a value with k dash characters, three times as many with `\|base64offset`), in the parser, IR lowering after pipelines, `rule lint`, evaluation, and conversion | The rule is rejected with an error that names it. Evaluation compiles each value with dashes into one regex, so its cost does not depend on the number of variants. {{ added "unreleased" }} |
| Placeholder expansion | `MAX_PLACEHOLDER_COMBINATIONS`, `MAX_PLACEHOLDER_VALUES_PER_RULE` | 4,096 values per value, 65,536 per rule | `value_placeholders` pipeline transformation | Pipeline error naming the rule. {{ added "unreleased" }} |
| One-to-many field mapping | `MAX_FIELD_MAPPING_COMBINATIONS`, `MAX_FIELD_MAPPING_BRANCHES_PER_RULE` | 4,096 branches per selection, 16,384 per rule for one transformation | `field_name_mapping` and other field-name transformations | Pipeline error naming the rule. {{ added "unreleased" }} |
| Correlation chain depth | `MAX_CHAIN_DEPTH` | 10 | Engine | Stops chaining beyond 10 levels; logs at `WARN` (`rsigma_eval::correlation_engine`). Cycle detection at load time does not recurse, so a reference chain of any length loads or fails with `CorrelationCycle` instead of crashing. {{ added "unreleased" }} |
| Correlation state entries | `max_state_entries` | 100,000 | Engine, all correlation rules combined | Hard cap; eviction drops the stalest 10% with a `WARN` log when reached. Watch via `rsigma_correlation_state_entries`; dropped windows count in `rsigma_correlation_state_evictions_total`. {{ added "unreleased" }} |
| Entries per correlation group | `max_group_entries` | 10,000 | Engine, per correlation and group key | Oldest entries are dropped (a session keeps its first entry). For `event_count` and `value_count` the default rises to one more than the largest threshold in the condition. {{ added "unreleased" }} |
| Future event timestamps | `max_future_skew` | 5 minutes | Engine, every event that feeds a correlation and restored state | An event further ahead of the wall clock is skipped for correlation and counted in `rsigma_correlation_future_events_skipped_total`; a smaller lead is clamped to the wall clock. {{ added "unreleased" }} |

These limits are sized so that the engine remains bounded under pathological input (a single rule of unbounded size, a single event of unbounded size, or an attacker-controlled JSON document with multi-megabyte nesting). They were chosen to be larger than every plausible real Sigma rule and well above any legitimate JSON event.

## Dynamic source resource limits

`engine daemon` and `pipeline resolve` enforce additional bounds on dynamic sources:

| Limit | Constant | Value | Per-source override |
|-------|----------|-------|---------------------|
| HTTP body, NATS payload, and command stdout | `MAX_SOURCE_RESPONSE_BYTES` | 10 MiB | `max_body_size` (HTTP), `max_stdout` (command) |
| Command stderr | (hard-coded) | 64 KiB | not configurable |
| HTTP fetch timeout | (default) | 30 s | `timeout` |
| Command execution timeout | `DEFAULT_COMMAND_TIMEOUT` | 30 s | `timeout` |
| Refresh interval minimum | `MIN_REFRESH_INTERVAL` | 1 s | not configurable (clamps with warning) |
| Include nesting depth | `MAX_INCLUDE_DEPTH` | 1 | not configurable |
| Remote include resolution | none | off | `--allow-remote-include` daemon flag |

Each limit produces a `SourceErrorKind::ResourceLimit` failure with a descriptive message. The full source-level catalogue lives at [Dynamic Sources: resource limits](dynamic-sources.md#resource-limits).

### Include directive security model

The `include:` directive resolves to transformation YAML pulled from a source. By default, only local sources (`file`, `command`) are allowed to provide `include:` content. HTTP and NATS sources can serve other pipeline values but not `include:` content; this defends against a compromised CDN or NATS broker injecting transformation logic.

Operators that need remote-included pipelines (for centralised pipeline distribution across many daemons) must opt in explicitly with `--allow-remote-include` on `engine daemon`. The flag is also expected to be paired with mTLS on the upstream HTTP source so an arbitrary network attacker cannot serve content.

### HTTP egress policy (SSRF defense)

The egress policy governs three daemon HTTP clients: dynamic-source resolution (a Sigma rule or pipeline references `type: http`), post-evaluation enrichers (`type: http`), and webhook sinks. Their URLs come from operator-supplied YAML, so a compromised rule or pipeline can otherwise point the daemon at the cloud-metadata IMDS endpoint at `169.254.169.254` and exfiltrate IAM credentials, or at internal admin APIs reachable on link-local addresses.

`rsigma engine daemon` exposes an `--egress-policy <default|strict|permissive>` flag (also `daemon.engine.egress_policy` in the layered YAML config) that selects one of three presets. These clients enforce it at three points, so without a proxy a request never connects to a denied address: {{ added "0.27.0" }}

- **DNS resolution.** Every address a hostname resolves to is filtered, so DNS rebinding (resolving a hostname to a public IP at the host-string check, then switching to a private IP between check and connect) cannot defeat the policy.
- **The request URL.** A URL whose host is an IP literal (`http://169.254.169.254/`, `http://[fd00:ec2::254]/`, or an encoded IPv4 form such as `http://0xa9fea9fe/`) skips DNS, so the URL itself is checked before the request is sent.
- **Every redirect hop.** Each `Location` target is checked the same way before it is followed, so an allowed upstream cannot bounce the request to a denied IP literal. Redirect targets given as hostnames are filtered at resolution as usual. At most 10 redirects are followed.

When `HTTPS_PROXY`, `HTTP_PROXY`, or `ALL_PROXY` is set, the clients send requests through that proxy, and the proxy resolves hostnames, so DNS-resolution filtering does not apply. IP-literal URLs and redirect targets are still checked. Enforce the same deny list on the proxy, or unset the variables for the daemon. The daemon logs a warning at startup when a proxy variable is set and the policy is not `permissive`. {{ added "0.27.0" }}

A denied request fails with the policy's reason (for example `egress policy denied link-local address 169.254.169.254`) in the source, enricher, or webhook error.

| Preset       | Link-local (`169.254/16`, `fe80::/10`) | Cloud metadata (`fd00:ec2::254`, `fd20:ce::254`, `100.100.100.200`) | Loopback (`127/8`, `::1`) | RFC1918 private (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`) |
|--------------|----------------------------------------|----------------------------------|---------------------------|------------------------------------------------------------------|
| `default`    | denied                                 | denied                           | allowed                   | allowed                                                          |
| `strict`     | denied                                 | denied                           | denied                    | denied                                                           |
| `permissive` | allowed                                | allowed                          | allowed                   | allowed                                                          |

The `default` preset balances safety against the common case of internal threat-intel services on private addresses. Pick `strict` if the daemon has no legitimate reason to reach private or loopback addresses; pick `permissive` only in tightly controlled environments where every source and enricher URL has been vetted. The presets are also reachable from library code via `rsigma_runtime::EgressPolicy::{default,strict,permissive}` and `set_default_egress_policy`; per-category builders (`with_block_link_local`, `with_block_cloud_metadata`, `with_block_loopback`, `with_block_private`) cover the in-between cases.

IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) inherit the IPv4 rules: a host that resolves to `::ffff:169.254.169.254` is rejected as link-local just like the bare IPv4 form. {{ added "0.27.0" }} So do IPv4-compatible (`::a.b.c.d`), NAT64 (`64:ff9b::/96`, and `/96` prefixes in `64:ff9b:1::/48`), and 6to4 (`2002::/16`) addresses, which a NAT64 gateway or 6to4 relay forwards to the embedded IPv4 host.

The policy applies only to those three clients. OTLP sinks, the MCP server's daemon client, and one-shot CLI commands such as `rsigma taxii sync` or `engine status` do not go through it, so point them only at endpoints you trust. Local sources (`file`, `command`) and NATS sources do not flow through the resolver and are governed by the include directive and process hygiene controls above.

Webhook sinks (`--webhook`) use the same egress-filtered client, so the policy governs outbound webhook deliveries too: `strict` blocks RFC1918, so a webhook targeting an internal relay needs `default` or `permissive`. Keep webhook secrets in the environment and reference them with `${ENV_VAR}` in the URL or headers; do not store tokens or signing URLs in the webhook YAML. A webhook may carry a per-entry `tls:` block (a custom CA bundle plus an optional client cert/key for mutual TLS) to reach an internal relay over private PKI; PEM files are read and validated at startup. A webhook may also HMAC-sign each request via a `signing:` block so a receiver can verify authenticity, integrity, and (for the timestamped default) replay freshness; the signing key is read from the environment (`signing.secret_env`) at startup, never stored in the YAML, and the default scheme follows the Standard Webhooks convention. See [webhook signing](../guide/webhooks.md#signing-requests).

{{ added "unreleased" }} Webhook and HTTP enricher header templates insert event data as written, so every rendered header value has CR, LF, every other ASCII control character except horizontal tab, and DEL replaced with a space before the request is built. An event value therefore cannot end a header line and inject another header, and a control character in event data cannot make the request fail. Header names are fixed in config and checked at startup: a name that is not a valid HTTP header name, or that repeats another one regardless of case, rejects the daemon. Custom signing templates (`signed_payload`, `value_format`) are expanded in one pass, so an event value that contains `{timestamp}`, `{id}`, or `{body}` is signed as sent.

### STIX indicator sources

{{ added "0.28.0" }} A `type: taxii` source uses the same egress policy. The API root is checked before the first poll, and every address the name resolves to is checked again. An IP literal in the API root, or in an absolute URL the server returns, is rejected before the request. While that filter is set the client follows no redirects and uses no proxy, so a proxy variable cannot move the request off the filtered path. `rsigma taxii sync` is a separate command and is not covered by this filter.

TAXII credentials are environment variable names in the source YAML. The values are read when the resolver is built and are not written into the declaration or into errors. A missing variable fails startup and names the variable.

Each TAXII page is limited to 64 MiB and parsed with a finite depth, string length, and object count. A poll reads at most one page and object budget, then the next refresh continues from just before the last page's added date. The poll fails when the cursor does not advance, when HTTP 416 recovery would repeat the same filter, or when a budget stop cannot move the added-date cursor, so a collection that never ends cannot hold one resolve open. A file or HTTP source with `format: stix` uses the same parser limits. HTTP still stops at its 10 MiB body cap. Indicator values are data: they land in the source cache and can be expanded into a rule or returned to a lookup enricher. They are not executed. Array values escape `\`, `*`, and `?`, so that expansion is an exact comparison. The `indicators` map keys stay raw.

A `stix:` block on a format other than `stix`, `extract` on a STIX source, and `watch` or `push` on `type: taxii` are configuration errors.

{{ added "unreleased" }} A poll is also bounded in time. `poll_timeout` (default `5m`) caps one poll across its pages, preflight requests, and retries, and a server `Retry-After` longer than the client's 60-second retry cap fails the request instead of making it wait. Sources resolve independently, at most eight at once, so a slow or hostile TAXII server holds up only its own source, and a panic in one resolver fails only that source.

### TAXII server trust

{{ added "unreleased" }} The rstix TAXII client behind `type: taxii` and `rsigma taxii sync` verifies servers as follows.

- **DNSSEC.** With DANE and `dane_require_dnssec` (the default for DANE), TLSA and SRV answers are used only when the validating resolver proves them Secure. An Insecure, Bogus, or Indeterminate answer is a trust error before any connection.
- **PKIX-TA (TLSA usage 0).** The record must match an intermediate or the trust anchor of the chain PKIX actually validated. A matching CA certificate the server appends without using it does not satisfy the record.
- **SRV discovery.** Unless the SRV record is DNSSEC-validated, the server certificate must be valid for the queried domain, not for the SRV target, so whoever answers the SRV query cannot redirect the client to a host that only holds a certificate for its own name. Credentials are sent only after that check. A caller can name the expected identity with `server_identity`.
- **Clock skew.** The client shifts only a caller-supplied `added_after` by the server's `Date` offset, ignores an offset over 24 hours, and never shifts a cursor the server returned. Timestamp shifts saturate at the RFC 3339 range instead of overflowing.

### STIX stores

{{ added "0.28.0" }} `rsigma taxii store` and `rsigma taxii sync` write one file per object id under the store's `objects/` directory, and `--allow-custom` accepts any object type. A STIX id parses only when its type name follows the STIX 2.1 rules (3 to 250 characters of `a-z`, `0-9`, and `-`, starting with a letter) and its UUID is in hyphenated form, so a bundle or TAXII collection cannot name a path outside the store with an id such as `../../x--<uuid>` or `/tmp/x--<uuid>`. The store also checks every file name before it writes or deletes, independent of the parser.

{{ added "unreleased" }} A store write parses each object's stored form back under the store's parse options before anything changes, and refuses the write when it would not load. Opening or reloading a store loads each file on its own: a corrupt file, one that does not parse under the current options (for example a custom object opened without `--allow-custom`), or one whose id does not match its file name is skipped and reported, and the rest of the store still loads. `taxii sync` and `taxii store` print a warning per skipped file, and the daemon logs one at startup and on reload. RFC 2047 encoded-words in `email-message` headers are decoded once, on ingest, so a saved message reloads unchanged.

### DNS enricher

{{ added "0.28.0" }} A `type: dns` enricher resolves a name that comes from the event, so that name's authoritative servers see a query from the resolver the daemon uses. That reveals to the authoritative operator that the event was processed and roughly when, even though the answer never reaches them. Reverse lookups for an event-supplied IP address reach the zone that owns the `in-addr.arpa` or `ip6.arpa` range instead.

The egress policy does not apply to the DNS enricher. The enricher sends queries only to the nameservers an operator configured, or to the system resolver when `nameservers` is empty, and it never opens a connection to an address it got back. Filtering the answers would also break common setups, because the AWS VPC resolver at `169.254.169.253` is link-local and the `default` preset denies link-local addresses.

Mitigations: narrow which results trigger the lookup with `scope`, point `nameservers` at an internal resolver when queries should not leave the network, and keep `cache_ttl` and `negative_cache_ttl` at values that bound how often repeated names are re-queried.

### Memory-mapped MMDB databases

{{ added "0.28.0" }} By default the `mmdb` enricher reads each database into memory, so rewriting the file in place cannot crash the daemon: the next check reloads the file once it parses, and keeps the previous reader until then. An entry with `mmap: true` (`mmdb-mmap` feature) memory-maps the file instead, and the mapping is only sound while nothing writes to or truncates the file. Writing to a mapped database in place can crash the daemon with `SIGBUS`. Replace mapped databases by writing a new file next to the old one and renaming it over the old path, as `geoipupdate` does; the daemon keeps reading the old file until it maps the new one. Anyone who can write the database file can crash a daemon that maps it, so keep it writable only by the updater. See [Enrichers](../guide/enrichers.md#mmdb-local-mmdb-lookup).

### Event values in enricher programs and requests

{{ added "unreleased" }} Event and correlation values are attacker-influenced, so every enricher treats them as data where they land:

- `lookup` and `stix` `extract` expressions read a value as a string variable (jq, CEL) or as an escaped string literal (JSONPath), never as expression text. See [Event values in extract expressions](../guide/enrichers.md#event-values-in-extract-expressions).
- Every extract, in enrichers and in dynamic sources, runs without jq's `env`, `$ENV`, `halt`, `halt_error`, and `stderr`, rejects recursive jq definitions, and is bounded by result count, result size, jq generator steps, and time. Enricher extracts run on the blocking pool, at most twice as many at once as the host has CPUs, so a slow program cannot hold an async worker, and the enricher timeout stops a jq program at its next step.
- `http` and webhook bodies give a placeholder outside a JSON string literal one JSON value, and URLs percent-encode each value as one component.
- `command` arguments are never parsed by a shell. The loader rejects a reference in the program, in a shell or interpreter's code argument, and in the program a wrapper runs, and an argument that would start with `-` from an event value is refused unless `--` precedes it. See [`command`](../guide/enrichers.md#command-per-result-local-process-execution).

## Parser robustness

Every external parser rsigma ships uses panic-free libraries:

| Component | Library | Notes |
|-----------|---------|-------|
| Sigma rule YAML | `yaml_serde` 0.10 | The maintained fork of `serde_yaml`. Resists the recursion and aliasing attacks that plagued legacy `serde-yaml`. |
| Sigma condition expression | `pest` grammar and Pratt parser | Bounded by `MAX_CONDITION_LEN` (64 KiB) and `MAX_CONDITION_DEPTH` (64). The nesting is counted over the token stream before the Pratt parser recurses. {{ added "unreleased" }} |
| STIX pattern | hand-written recursive descent | Bounded by `MAX_PATTERN_BYTES` (64 KiB), `MAX_AST_DEPTH` (64), and the observation and comparison counts, so every tree it builds is shallow enough for the type checker, printer, and evaluator to walk. {{ added "unreleased" }} |
| Lucene query (reverse conversion) | hand-written tokenizer and precedence-climbing parser | Bounded by `MAX_REVERSE_QUERY_LEN` (64 KiB) and `MAX_REVERSE_QUERY_DEPTH` (64). {{ added "unreleased" }} |
| Pipeline YAML | `yaml_serde` 0.10 | Same. |
| Input event JSON | `serde_json` | Bounded by `MAX_LINE_BYTES` (1 MiB) for streaming sources. |
| HTTP request bodies | `reqwest` with explicit size limit | Bounded by `MAX_SOURCE_RESPONSE_BYTES` (10 MiB). |
| OTLP requests | `prost` + `tonic` | The OTLP receiver enforces upstream size limits at the HTTP/gRPC layer. Protobuf decoding stops at prost's 100-message recursion limit, which bounds `AnyValue` nesting at about 49 levels before conversion runs; a unit test fails if a dependency disables that limit, and the `fuzz_otlp_logs_decode` harness covers the decode and conversion path. {{ added "0.25.0" }} |
| EVTX records | `evtx` crate | Streaming parse; bounded record-by-record memory usage regardless of file size. |
| CEF | `cef-parser` | Bounded line size via the input format machinery. |

Fuzz testing under `cargo-fuzz` covers parser, condition, pipeline YAML, JSON event, EVTX, syslog, logfmt, CEF, MMDB decoding, DNS answer formatting, named ruleset resolution, enrichers configs, watchlist indicator bodies, silence requests, alert-pipeline snapshots, TAXII envelopes, TAXII response headers, DNS SRV and TLSA records, STIX indicator bundles, STIX pattern evaluation, STIX store text search, `email-message` RFC 2047 round trips, STIX rule drafts, YAML written from event fields by rule drafting and schema discovery, OTLP protobuf and JSON record counting, stream line framing, field-key walks, `Host` and `Origin` header validation, event values in enricher extract programs, the `apply_modifiers` pipeline rewrite, the `windash` expansion budget, directory walks over link trees, PostgreSQL `fields` entries, absence correlation state, and the conversion backends. Forty-nine harnesses run on a scheduled CI workflow; crashes land in the `fuzz/artifacts/` tree and ship as regression fixtures.

## SQL injection prevention

The PostgreSQL backend (`backend convert -t postgres`) generates SQL by:

- Double-quoting field names other than plain lowercase identifiers (`"CommandLine" ILIKE '%whoami%'`), with a `"` inside the name doubled (`"a""b"`). {{ added "0.28.0" }}
- Always single-quoting string literals with SQL-standard escaping (`'don''t'`).
- Validating identifiers (`table`, `schema`, `database`) against `^[A-Za-z_][A-Za-z0-9_$]*$` before insertion. Non-matching identifiers fail conversion with `InvalidIdentifier`.
- Validating `timestamp_field` and `json_field` the same way, and double-quoting any column, table, or schema name that is a reserved PostgreSQL keyword such as `user` or `order`, so it cannot read as a SQL keyword or function. {{ added "unreleased" }}
- Accepting a rule's `fields` entry only as `*`, a field name, or a `count`, `sum`, `avg`, `min`, or `max` call over a field or `*`, each with an optional `AS alias`. Any other entry, such as another function, a sub-select, or text with `;`, quotes, or comments, fails conversion with `InvalidSelectField`. {{ added "unreleased" }}
- Substituting query template placeholders in a single pass, so placeholder text such as `{rule.title}` inside a rule's values is never expanded, and rendering the rule title and ID in a template with single quotes doubled. {{ added "0.28.0" }}
- Never templating user-controlled strings into SQL keywords or structural positions.

This means a Sigma rule that contains a `'` or `;` or `--` in a value still produces safe SQL.

The LynxDB backend (`backend convert -t lynxdb`) double-quotes and escapes string values and regexes, and renders field names bare, because LynxDB has no quoted identifier syntax. A field name outside LynxDB identifier syntax (a letter or `_`, then letters, digits, `_`, `.`, `:`, or `-`) fails conversion instead of reaching the query. Template placeholders are substituted in a single pass, as in the PostgreSQL backend, so placeholder text in a rule's values cannot add pipeline stages. {{ added "0.28.0" }} A pipeline `index` outside LynxDB source-name syntax (`*`, or letters, digits, `_`, `.`, `:`, `-`, and `*`) fails conversion instead of reaching the `FROM` clause. {{ added "unreleased" }}

The Fibratus backend (`backend convert -t fibratus`) renders field names bare. A field name outside Fibratus identifier syntax (a letter or `_`, then letters, digits, `_`, `.`, or `$`, with optional `[...]` index segments) fails conversion instead of reaching the filter expression. Each rule is a YAML document, and any value that a block scalar cannot carry, such as a `\r`, NEL, or U+2028 line break, is written as an escaped double-quoted scalar, so rule content cannot add keys such as `action` to the generated rule. {{ added "0.28.0" }}

See [Backends: PostgreSQL](backends/postgres.md), [Backends: LynxDB](backends/lynxdb.md), and [Backends: Fibratus](backends/fibratus.md).

Custom identifiers passed through `-O table=...` or pipeline `set_state` are validated identically; an `-O table='evil; DROP'` is rejected at conversion time, not at execution time.

## Process and concurrency hygiene

- **SIGTERM/SIGINT**: the daemon installs a Unix signal handler and drains in-flight events bounded by `--drain-timeout` (default 5 s) before exiting. State is snapshotted to SQLite if `--state-db` is set.
- **SIGHUP**: triggers a rules + pipelines reload, equivalent to `POST /api/v1/reload`. Hot-reload swaps the engine via `ArcSwap`, so in-flight evaluations see the previous engine and new events get the new one. No locks are taken on the critical path.
- **Locking primitive**: `parking_lot::Mutex` on the hot engine path (`rsigma-runtime` processor); `std::sync::Mutex` elsewhere (`SourceCache`, the `rsigma-convert` backend registry). `parking_lot` mutexes do not poison on panic, so a panicked thread on the eval path does not deadlock the rest of the system. The trade-off is that a panicked thread cannot be detected by checking the lock state; the daemon relies on `tokio::task` panic propagation for that.
- **Async runtime**: `tokio` with a single multi-threaded scheduler. Source resolution, HTTP serving, and engine evaluation share the runtime; under load they are scheduled by tokio's work-stealing scheduler.
- **No `unsafe` in first-party code**: the rsigma workspace contains zero `unsafe` blocks. Dependencies (notably `tonic`, `rustls`, `tokio`) contain `unsafe` reviewed upstream.

## Daemon network exposure

The `engine daemon` HTTP and gRPC listeners share one socket. With the optional `daemon-tls` build feature the daemon terminates TLS in-process; without it a sidecar reverse proxy is the recommended path. The recommended deployment shape is one of:

- Build with `daemon-tls` and pass `--tls-cert`/`--tls-key` to terminate TLS in-process for HTTP REST, OTLP/HTTP, and OTLP/gRPC on the same `--api-addr`. Add `--tls-client-ca` to require mTLS for agent-to-daemon pinning. See [TLS termination](#tls-termination-for-the-api-listener).
- Bind to loopback (`--api-addr 127.0.0.1:9090`) and access via a reverse proxy that adds TLS and authentication. Nginx, Caddy, and Traefik all work; an example is documented in [Docker deployment](../deployment/docker.md).
- Bind to a private network segment that the SOC controls.
- On Unix, bind a domain socket with `--api-addr unix:///run/rsigma/api.sock`. Access is gated by the socket file's permissions (created `0600`), so it never leaves the host and needs no TLS. This is the simplest hardened shape for a co-located admin/metrics client or a sidecar that proxies the socket.

{{ added "0.25.0" }}

To prevent accidental exposure, every build refuses to start on a non-loopback TCP `--api-addr` in two cases:

- **Plaintext.** Neither `--tls-cert`/`--tls-key` nor `--allow-plaintext` (config `daemon.api.tls.allow_plaintext`) is supplied. A build without `daemon-tls` cannot serve TLS, so it needs `--allow-plaintext` and a TLS-terminating proxy in front.
- **Unauthenticated.** No bearer tokens are configured (`daemon.api.auth` or `--api-token-env`), the listener does not require client certificates (`--tls-client-ca`), and `--allow-unauthenticated` (config `daemon.api.allow_unauthenticated`) is not supplied. TLS without client certificates encrypts the traffic but does not authenticate the caller, so it does not satisfy this check.

Opting out of authentication on a non-loopback address logs a startup warning. Loopback (`127.0.0.0/8`, `::1`) is exempt from both checks. A `unix://` address is treated as local: it is exempt from both checks and, because TLS terminates on TCP only, combining it with `--tls-cert`/`--tls-key` is rejected at startup.

### Browser requests to a local API

{{ added "unreleased" }} An unauthenticated daemon on loopback is reachable from every web page the operator opens. A cross-origin `fetch` can send a `text/plain` POST to `http://127.0.0.1:9090/api/v1/events` without a CORS preflight, and a DNS-rebinding page can point its own name at `127.0.0.1` and read the API. The daemon therefore checks the `Host` and `Origin` headers of every request on a TCP listener, before authentication, routing, and body buffering, OTLP included:

- **Host.** Accepted: `localhost`, `127.0.0.1`, `::1`, a specific bind IP, and each `--api-allowed-host` (config `daemon.api.allowed_hosts`). Other hosts get `403`; a missing or malformed `Host` gets `400`. An authenticated non-loopback listener (bearer tokens or `--tls-client-ca`) accepts every host unless `--api-allowed-host` narrows it, and `*` asks for that explicitly but needs authentication. A project config file cannot set `daemon.api.allowed_hosts`.
- **Origin.** A request with an `Origin` header must come from `http` or `https` on an accepted host, or, when every host is accepted, from the host the request addresses. Everything else, including `Origin: null`, gets `403`. This also covers mTLS listeners, where the browser would present the operator's client certificate on a cross-site request. Requests without `Origin` (curl, log shippers, the `rsigma` client commands, OTLP exporters) are unaffected.
- `GET /healthz` and `GET /readyz` skip the checks so probes by pod address work, and a `unix://` listener skips them because the socket permissions are the boundary.

The MCP HTTP transport applies the same rules from the same code (see [MCP Streamable HTTP](#mcp-streamable-http)).

### Connection limits and timeouts

{{ added "unreleased" }} The daemon API and the MCP HTTP transport bound what one client can hold:

- **Connection cap.** At most `--api-max-connections` (default 1024; `--max-connections` for MCP) connections are served at once; further clients wait in the kernel's listen backlog instead of exhausting file descriptors.
- **Read timeout.** A client must send its first bytes, each HTTP/1 request head, and each chunk of a request body within `--api-read-timeout` (default 30 s; `--read-timeout` for MCP), so a silent or trickling client, or an idle keep-alive connection, is closed. Responses are not time-limited, so the `tap` and `tail` streams keep running. HTTP/2 connections are pinged every 30 s and closed when a ping goes unanswered for 20 s.
- **TLS handshakes off the accept path.** Each handshake runs in its own task with a deadline (`--tls-handshake-timeout`, default 10 s), at most 256 at once, so a client that connects and never sends a `ClientHello` holds one slot until the deadline instead of blocking every new connection. Timeouts and failures count in `rsigma_tls_handshake_failures_total{reason}`, and their warnings are rate-limited.

NATS connections from the daemon (source, sink, DLQ) support five auth methods (creds file, token, user+password, NKey, mTLS) and TLS-required mode. See [NATS Streaming: authentication](../guide/nats-streaming.md#authentication).

### TLS termination for the API listener

Pass any two of the four `--tls-*` flags to enable in-process TLS:

```bash
RSIGMA_API_TOKEN=... rsigma engine daemon -r rules/ \
    --api-addr 0.0.0.0:9090 \
    --tls-cert /etc/rsigma/tls/server.crt \
    --tls-key  /etc/rsigma/tls/server.key \
    --api-token-env RSIGMA_API_TOKEN
```

ALPN advertises both `h2` and `http/1.1` so the same listener serves OTLP/gRPC (HTTP/2 framing) and the REST API (HTTP/1.1) without splitting ports.

For mutual TLS (every agent must present a CA-signed client cert, which also satisfies the authentication check on a public bind):

```bash
rsigma engine daemon -r rules/ \
    --api-addr 0.0.0.0:9090 \
    --tls-cert /etc/rsigma/tls/server.crt \
    --tls-key  /etc/rsigma/tls/server.key \
    --tls-client-ca /etc/rsigma/tls/clients-ca.crt
```

Use `--tls-min-version 1.2` only when a legacy agent cannot negotiate TLS 1.3. The provider is `aws-lc-rs`, matching the NATS client TLS path and inheriting upstream FIPS-mode work.

Hot-reload: cert rotation funnels through the daemon's central debounced reload task, which is triggered by `POST /api/v1/reload` (works on every platform, including Windows), `SIGHUP` (Unix), or a YAML change picked up by the file watcher. All three paths re-read the certificate and key from disk and atomically swap the rustls `ServerConfig` via `Arc<ArcSwap<…>>`. Inflight TLS connections are not dropped. Failed reloads keep the previous certificate active, bump `rsigma_reloads_failed_total`, and log an error so a typo in the cert path cannot black-hole the listener. The same trigger also reloads rules, pipelines, and enrichers, so cert rotation typically piggy-backs on a routine reload.

Observability: `/metrics` exposes `rsigma_tls_certificate_expiry_seconds` (signed; negative once expired), `rsigma_tls_active_connections`, and `rsigma_tls_handshake_failures_total{reason="timeout"|"error"}`. {{ added "unreleased" }} A single WARN is logged at startup (and on every successful reload) when the active cert expires within 30 days; wire that line into the existing log-based alerting.

Out of scope for this feature today: ACME/Let's Encrypt automation. Operators point `--tls-cert` and `--tls-key` at renewed files (cert-manager, certbot, Vault PKI, ...) and send SIGHUP. Encrypted private keys are not supported; `--tls-key-password`/`RSIGMA_TLS_KEY_PASSWORD` is rejected at startup with a clear `openssl rsa` hint. Decrypt the key before loading it.

OTLP receiver authentication has two options: mTLS (`--tls-client-ca`) so every OpenTelemetry agent pins to a known CA, or a bearer token with the `events:ingest` permission (see [Daemon API authentication](#daemon-api-authentication)); the OTLP/gRPC service reads the same `authorization` metadata OpenTelemetry Collector exporters send via the `headers` setting. Both OTLP transports check the token, and with tenancy its tenant binding, before they read the request body, so an unauthenticated request is never decompressed or decoded. {{ added "unreleased" }}

## Daemon API authentication

Bearer-token authentication with `resource:action` permissions gates the daemon API at the application layer. Without a `daemon.api.auth` config block or the `--api-token-env` flag, every route is open. {{ added "0.25.0" }} The daemon accepts that only on loopback, on a `unix://` socket, on a listener that requires client certificates, or with an explicit `--allow-unauthenticated` (see [Daemon network exposure](#daemon-network-exposure)). When enabled, every route except the liveness probes (`GET /healthz`, `GET /readyz`) requires a token whose permission set covers the route's permission; the per-route mapping is in the [HTTP API endpoint summary](http-api.md#endpoint-summary).

Design properties:

- **Secrets are env-only.** The config names an environment variable per token (`token_env`, the same posture as webhook `signing.secret_env`); the value never lives in YAML or on the command line, and a missing or empty variable fails startup before the listener binds.
- **A floor on tenant-bound secrets.** A token bound to a tenant (`tenant` or `all_tenants: true`) needs a secret of at least 32 bytes, or startup fails; generate one with `openssl rand -hex 32`. A shorter secret on any other token logs a warning. {{ added "0.28.0" }}
- **Constant-time comparison.** Every presented token is compared against every configured secret in constant time, so timing cannot leak a matched prefix.
- **Least privilege by role.** Built-in roles `reader`/`operator`/`ingest`/`admin` plus custom roles as permission lists with `*` wildcards. A log shipper's `ingest` token carries only `events:ingest` and cannot create silences or trigger reloads; `reload:execute` is deliberately excluded from `operator` so config-changing control stays with `admin` tokens.
- **Fail-closed route table.** A route added without a permission mapping requires the full `*` grant rather than defaulting open.
- **Aggregating routes get their own resource.** An [incident bundle](http-api-state.md#get-apiv1incidentsidbundle) joins an incident to rule documentation and risk entities, so it requires `incident-bundles:read` rather than the `incidents:read` that gates the incident list. A custom role can hand out the incident list without handing out what the detections look for or which entities are accumulating risk. The built-in `reader` role (`*:read`) covers both.
- **No anonymous fallback for bad tokens.** `anonymous_permissions` applies only to requests with no `Authorization` header; a presented-but-unrecognized token is always rejected with 401.
- **Observable rejections.** `rsigma_api_auth_failures_total{reason="unauthorized"|"forbidden"}` counts rejections, and each is logged at warn level with the route and token name; the secret is never logged. The daemon does not slow down repeated failures, because behind a shared proxy a per-address backoff would lock out every client of that proxy; rate-limit `401` responses at the proxy or load balancer, and alert on the counter.

Authentication complements TLS rather than replacing it: tokens authenticate *who* is calling, TLS protects the token in transit. On a non-loopback TCP listener, pair the auth block with `--tls-cert`/`--tls-key` (or a TLS-terminating proxy) so bearer tokens are never sent in cleartext. On a `unix://` listener the socket file permissions already gate access, and auth adds per-client differentiation on top when several local users share the socket.

A token with `sources:write` can push, replace, and delete watchlist indicators. Those values are matched against events, so treat the token like the ability to change which traffic alerts. Requests are size-capped (4 MiB, 10,000 indicators, and the source's `max_indicators`, or 4096 when a pipeline references the watchlist). When `--state-db` is set, the audit trail also rejects a body larger than `daemon.api.audit.max_body_bytes` (default 64 KiB) and records each accepted change. {{ added "0.28.0" }}

A token with `silences:write`, including one held by an MCP client steered by prompt-injected content, can mute detections. {{ added "0.27.0" }} The daemon therefore bounds API silences: each needs an `ends_at` within `max_silence_duration` (default `720h`) and at least one `=` matcher with a non-empty value on `rule`, `match.<field>`, or `correlation.group_key.<field>`, so a single call cannot mute every rule, or every rule of a severity, indefinitely. API silences created before these limits applied are kept, and the daemon logs their ids at startup and on reload. Silences are refused with `409` when no alert pipeline is loaded, because they would be accepted without effect. See [Alert Pipeline](../guide/alert-pipeline.md#the-silence-api).

The silence API also bounds the work one request can cause. {{ added "unreleased" }} Sizes are checked before anything compiles: a 64 KiB body, 32 matchers, 256-byte selectors, ids, and `created_by`, 1024-byte values, and a 4096-byte comment. Each regex compiles off the async runtime with a 64 KiB size limit and a 64 KiB search cache, and the regexes of all API silences share a 64 MiB budget. A value must be a regex on its own, so it cannot close the full-match anchors and match everything. Silences restored from the state database pass the same checks and the dynamic-silence caps; one that fails is left out and counted.

A token with `dispositions:write` feeds the per-rule false-positive ratio. {{ added "unreleased" }} The daemon refuses a disposition for a rule that is not loaded, so arbitrary rule ids cannot create store entries or metric series, and it counts at most `daemon.dispositions.max_rules` (default 10000) `(tenant, rule)` pairs. A request carries at most 1000 records, identity fields are capped at 256 bytes, and a timestamp more than 5 minutes ahead is refused. Incident-scoped records read only their own incident, and gauge refresh, pruning, and restore take time linear in the rules tracked.

The alert-pipeline snapshot in `--state-db` restores entry by entry. {{ added "unreleased" }} An entry that does not parse is logged, counted in `rsigma_alert_pipeline_restore_skipped_total`, and left out, so one bad dedup alert does not discard the silences, incidents, and other alerts beside it, and it does not abort a batch run. Retained values nest at most 160 levels (deeper subtrees are kept as JSON text), which covers every event ingest parses, so every snapshot the daemon writes reads back.

## Multi-tenancy

Logical tenancy isolates detections, correlation state, incidents, risk entities, dispositions, silences, and capture bundles per tenant in one daemon. The tenant comes only from an operator binding: the bearer token that authenticated an ingest request, the configured tenant of a pull source, or a NATS subscription declared for one tenant. Event fields, client headers, NATS message headers, and OTLP attributes are never identity. {{ added "0.28.0" }}

The model fails closed. With tenancy enabled, the daemon refuses to start without bearer-token auth, refuses anonymous requests, and refuses a token that declares neither `tenant` nor `all_tenants: true`. Every pull source must carry a tenant, and an `all_tenants` token cannot ingest because it has no tenant to bind. A shared untenanted correlation bucket cannot form: the engine skips untenanted events and counts them.

Every stateful key includes the tenant: correlation windows, dedup fingerprints, incident ids and entity join keys, inhibition sources, silences, risk entities, disposition buckets, and capture identities.

Stateful keys compare exact values, not digests. Dedup alerts and `group_by` incidents are keyed on the full tenant, rule, and selector values, and their short ids are SHA-256 display ids that never name two live alerts or incidents; the HTTP enrichment cache keys on the exact request. Composite keys built from several caller-controlled values (inhibition `equal` values, multi-field `value_count` keys, disposition idempotency keys, and capture bundle identities) are encoded so that no value can spill into the next. {{ added "unreleased" }}

API routes have tenancy classes. Tenant tokens get `403` on operator-only routes (`/metrics`, `/api/v1/status`, field and schema observers, dynamic sources, watchlists, STIX sources, reload). A resource id owned by another tenant is `404`, not `403`, so ids do not leak existence.

Dynamic sources, watchlists, STIX indicator sources, MMDB databases, and DNS caches are operator-global and shared. Their values do not depend on the tenant, and their hit or miss state is visible only through operator-only metrics. For per-tenant enrichment data, declare per-tenant source ids and reference them only from that tenant's ruleset.

See [Multi-tenancy](../guide/multi-tenancy.md) for the binding model, the full refusal list, and the YAML shape.

## Control-plane API audit trail

When the daemon runs with `--state-db`, an append-only audit log records every control-plane mutation: who called which endpoint, when, with what outcome, and a SHA-256 digest of the request body (never the body itself). Read the log with `GET /api/v1/audit` (`audit:read` when authentication is enabled). Event ingest and OTLP surfaces are excluded so the log stays small.

- **Auto-enable.** No extra flag: configuring `--state-db` turns the trail on. Set `daemon.api.audit.enabled: false` to disable while keeping correlation state persistence.
- **Bounded digest buffering.** Audited routes buffer at most `max_body_bytes` (default 65536) to compute the digest; larger bodies get `413 Payload Too Large` (before the handler runs) and the rejected attempt is recorded with a `null` digest.
- **Retention.** `max_age` (default 720h) and `max_entries` (default 10000) prune the SQLite table on startup and on each state-save tick.
- **Optional sink.** `daemon.api.audit.sink` mirrors each record as a JSON line; the sink is built with `on_full=drop` so slow downstreams cannot backlog the daemon.
- **Auth denials stay separate.** Failed authentication increments `rsigma_api_auth_failures_total` and is logged at warn; it is not duplicated in the audit table.

See [HTTP API: Audit trail](http-api-state.md#audit-trail) for the audited route list and query parameters.

## Live event tap

The live event tap ([`GET /api/v1/tap`](http-api-observability.md#live-event-tap), [`rsigma engine tap`](../cli/engine/tap.md)) streams a bounded window of the raw event traffic flowing through the engine. Anyone who can reach the admin API can already inject events and read loaded rules; the tap raises the stakes to **reading live production traffic**, so treat it as an exfiltration surface:

- **It is off by default.** The tap is opt-in: enable it with `daemon.tap.enabled: true` (or the `--enable-tap` flag) only when you need it, and prefer leaving it disabled.
- **Expose the admin API only behind mTLS.** The tap inherits the API listener's protections; pair `--tls-cert`/`--tls-key` with `--tls-client-ca` so only pinned clients can open a tap. See [TLS termination](#tls-termination-for-the-api-listener).
- **Redact sensitive fields.** `--redact-fields` (the `redact` query param) is enforced server-side: raw values for redacted fields never leave the daemon, not even to the tapping operator. Redaction uses deterministic per-session salted hashing, so equality relationships survive for replay while the raw value and cross-fixture linkage do not.

The tap can never apply backpressure to detection: each session owns a bounded buffer and drops (and counts) events when full, so opening a tap cannot stall or slow the engine. A dropped client connection tears the session down automatically, so a closed terminal cannot leave a tap recording. The concurrent-session count and capture window are bounded by `daemon.tap.max_sessions` and `daemon.tap.max_duration`.

## Verdict-driven capture

Verdict-driven capture ([Verdict-Driven Corpora](../guide/verdict-to-corpus.md)) retains admitted detection event payloads in memory and writes them to `daemon.capture.spool_dir` after an accepted disposition. Treat that directory as sensitive data at rest: raw events may contain PII, secrets, tokens, or customer payloads, and the feature does not redact them.

- **It is off by default and startup-only.** Enable it with `daemon.capture.enabled: true` or `--enable-capture`. Changing the block requires a restart.
- **HTTP ingest is permission-gated.** When authentication and capture are both enabled, `POST /api/v1/dispositions` requires `dispositions:write` and `capture:write`. Configured pull sources are trusted operator input.
- **Bundle identity comes from the evidence.** {{ added "unreleased" }} A rule, fingerprint, or incident id the disposition names counts toward a bundle's identity only when the captured events show it, so a disposition naming made-up values cannot open new bundles. A disposition whose rules never matched a captured event writes no bundle.
- **The disk budget counts every tenant.** {{ added "unreleased" }} `daemon.capture.max_spool_bytes` covers the untenanted `tp/` and `fp/` directories and each tenant's, and eviction removes the oldest bundles across all of them. With tenancy, `daemon.tenancy.quotas.capture_spool_bytes` caps one tenant's share; a tenant over it evicts its own oldest bundles first.
- **Filesystem policy.** On Unix, spool directories/files are created as `0700`/`0600`. Staging is under the same parent, symlink traversal is refused, abandoned staging is removed at startup, and completed-bundle eviction never follows links.
- **The ring is not persisted.** A restart loses capture for open incidents rather than writing raw payloads into `--state-db`.
- **No read or search API.** The spool is write-only from the daemon.

## Project config files

{{ added "0.27.0" }}

rsigma discovers `./rsigma.yaml` and the nearest `.rsigmarc` above the current directory, so a cloned repository can configure any `rsigma` command run inside it. Project files therefore cannot set the keys that open a gate. Those keys are ignored with a warning, and they resolve from `--config`, the user or system config, `RSIGMA_*` environment variables, or flags instead:

- `mcp.http_addr`, `mcp.allow_unconfined_paths`, and `mcp.allow_sigma_cli`, which expose the MCP server on the network, unconfine its paths, or let it spawn sigma-cli.
- `mcp.daemon_url`, `mcp.daemon_ca`, and `mcp.allow_operate_writes`, which would point the operate tools (and the daemon token) at another server or turn on the mutating tools.
- `mcp.rules_dir` and `mcp.lint_config` when they resolve outside the project file's directory, following symlinks.
- `daemon.sources`, `daemon.enrichers`, and `daemon.dispositions.source`, which can run `command` sources and enrichers and make HTTP requests.
- `daemon.output.sinks`, `daemon.output.dlq`, `daemon.output.webhooks`, `daemon.api.audit`, `daemon.nats.consumer_group`, and a NATS `daemon.input.source`, which send detections, events, or audit lines off the host, or connect with the operator's NATS credentials.
- `daemon.api.auth`, `daemon.api.allowed_hosts`, `daemon.api.allow_unauthenticated`, `daemon.api.tls.allow_plaintext`, and `daemon.api.tls.client_ca`, which decide who can reach the API. `daemon.api.allowed_hosts` is new. {{ added "unreleased" }}
- `daemon.tenancy`, `daemon.input.tenant`, and `daemon.input.nats_tenants`, which decide whether tenancy is on and which tenant each event belongs to. A project file may not turn tenancy off, because that is the dangerous direction. {{ added "0.28.0" }}
- `daemon.tap.enabled`, `daemon.tail.enabled`, `daemon.capture.enabled`, and `daemon.capture.spool_dir`, which expose or retain raw events and detections.
- `daemon.engine.egress_policy` and `daemon.engine.allow_remote_include`, which guard HTTP clients and pipeline includes.
- `daemon.api.addr` unless it is a loopback `host:port` or a `unix://` path inside the project, because client commands send the API token there. A `unix://` `daemon.input.source`, `daemon.state.db`, `eval.output`, and `scorecard.report` outside the project are ignored too, because rsigma creates, truncates, or replaces those paths.
- `backtest.findings`, `convert.defaults.output`, `convert.groups.*.output`, and `rulesets.*.output` outside the project, for the same reason. A conversion output also counts as outside when its `<output>.manifest.json` resolves outside, and `daemon.state.db` when its SQLite `-wal`, `-shm`, or `-journal` file does. "Inside" follows `..`, symlinks, and Windows junctions in every existing component and uses Win32 path normalization on Windows. `backend build` checks a project-sourced output again when it writes and replaces a symlink at the output path instead of following it. {{ added "unreleased" }}

jq event filters run without the `env` builtin, so a filter from a project file (`daemon.input.jq`) cannot copy the environment into detections, and without `halt` and `halt_error`, so an event that reaches one cannot stop the daemon. {{ added "unreleased" }} Binding a `unix://` socket replaces an existing path only when it is a stale socket, never a regular file.

A project file may still turn a boolean opt-in off. See [Project config trust](configuration.md#project-config-trust) for the full table and the warning format.

## MCP server tool surface

The MCP server ([`rsigma mcp serve`](../cli/mcp/serve.md)) treats every tool argument as untrusted, because an agent can be steered by prompt-injected content it is asked to process (a third-party rule set, an issue being summarized).

- **`--rules-dir` is a confinement boundary.** When it is set, every path argument (`path`, `events_path`, `enrichers_path`, and file-based `pipelines` in every tool) is canonicalized and refused if it leaves the directory, whether it is absolute, uses `../`, or resolves through a symlink. A missing file outside the root is refused the same way as an existing one, so callers cannot probe for files. Directory inputs that contain a symlink anywhere in the tree are refused, including inputs passed to sigma-cli. {{ added "0.27.0" }} Without a root, a directory input is walked like any other directory: each real file loads once and links out of it are skipped unless the server runs with `--follow-external-links`. {{ added "unreleased" }} `fix_rules` with `write: true` only writes to files inside the root. Confinement is by path and assumes the tree does not change during a call: a hard link or mount point under the root that leads to content outside it counts as inside.
- **Without `--rules-dir`, paths are unconfined.** The server can read any file its OS user can read. Always set `--rules-dir` when the server is reachable by an agent that processes untrusted content. Without a root, `fix_rules` refuses `write: true`, stdio prints a startup warning, and `--http` refuses to start unless `--allow-unconfined-paths` is set. {{ added "0.25.0" }}
- **No process execution or network egress from enrichers.** `evaluate_events` builds only `template` enrichers. `command`, `http`, `lookup`, and `stix` enrichers are refused; configure them on the daemon instead. {{ added "0.27.0" }} A `template` enricher that references `${ENV_VAR}` in any templated field is refused as well, so a caller cannot read the server's environment variables through the enrichment result.
- **sigma-cli delegation** (`--allow-sigma-cli`, off by default) spawns a subprocess. With `--rules-dir`, every path it receives is canonical and absolute, and it runs in an empty temporary directory, so a bare pipeline name cannot open a file (or a symlink) in the rules root. {{ added "0.27.0" }} Only bare identifiers (letters, digits, `_`, `-`) are passed through as sigma-cli pipeline names; anything else is treated as a path and confined.

### MCP Streamable HTTP

{{ added "0.27.0" }} The HTTP transport (`rsigma mcp serve --http`) exposes every registered tool to whoever reaches the port, so its defaults mirror the daemon's [network exposure](#daemon-network-exposure) checks:

- **Auth is required off loopback.** A non-loopback bind without `--auth-token` refuses to start unless `--allow-unauthenticated` is set. Loopback binds work without a token.
- **Host header validation.** Every request's `Host` must be accepted, or it gets `403`. This stops a DNS-rebinding web page from driving a server bound to loopback through the user's browser. Loopback binds accept `localhost`, `127.0.0.1`, `::1`, and the bind IP. A non-loopback bind with a token accepts any host, because the bearer token is the access control; `--allowed-host` (repeatable) restricts it to named hosts. An unauthenticated non-loopback bind keeps validation on, so clients must use a name passed with `--allowed-host`.
- **Origin header validation.** A request carrying an `Origin` header must name an accepted host over `http` or `https`, or it gets `403`. This stops a web page on another site from sending tool calls to a local server through the user's browser, which the `Host` check alone does not catch because the browser sends the server's real host. Requests without `Origin`, which is how MCP clients connect, are unaffected. {{ added "0.27.0" }} A token-guarded bind that accepts any host accepts an `Origin` only when it names the host the request addresses. {{ added "unreleased" }}
- **Connection limits.** The connection cap, read timeout, and TLS handshake handling described in [Connection limits and timeouts](#connection-limits-and-timeouts) apply to the MCP transport too. {{ added "unreleased" }}
- **Plaintext needs an opt-in.** A non-loopback bind without `--tls-cert`/`--tls-key` needs `--allow-plaintext`, for deployments where a proxy terminates TLS.

## Directory loading

{{ added "unreleased" }}

Every command that loads a directory of rules, ruleset sources or overlays, pipeline source declarations, or a corpus walks it the same way:

- Each real directory is visited once, so a symlink or Windows junction that points at the directory itself or at an ancestor cannot loop, and each real file is read once, however many links lead to it.
- An entry that resolves outside the directory being loaded is neither opened nor descended into. It is reported as a warning that names the entry but not its target, so neither the target's content nor its location reaches diagnostics: a `SkippedPath` parse warning, a `skipped_path` lint finding, or a warning line on stderr. Ruleset overlay directories, pipeline source directories, and `rule migrate-sources` refuse such an entry instead of skipping it.
- `--follow-external-links` follows such links. Cycles are still detected and each file still loads once. It is a command-line flag only, so a project config file cannot turn it on.
- The daemon's file watcher follows links only when `--follow-external-links` is set, so a link to `/` in a rules directory cannot make it watch the whole filesystem.
- The MCP server never follows links out of `--rules-dir`, and with a root it still refuses directory inputs that contain a symlink.

Confinement is by path and assumes the tree does not change during a load: a hard link or bind mount under the directory that leads elsewhere counts as inside.

## Filesystem footprint

The daemon never writes outside the paths it is explicitly given:

- `--state-db <PATH>`: SQLite file written periodically and on shutdown (correlation state, alert pipeline, dispositions, risk, and the control-plane audit log when enabled). Capture ring contents are never stored here.
- `--dlq file://<PATH>`: append-only NDJSON.
- `--output file://<PATH>`: append-only NDJSON of detections.
- `daemon.capture.spool_dir`: versioned TP/FP corpus bundles. Sensitive; classify and protect the path.

Rules and pipeline files are read-only. The `notify` file-watcher does not write. The docmd documentation build is local and never touches `~/`.

Commands that rewrite a tree only touch entries physically inside it. `ruleset build` refuses a generated `rules/`, `correlations/`, or `filters/` directory that is a symlink, and replaces a symlinked rule file or `ruleset.lock.json` with a regular file instead of writing through it. `rule lint --fix` skips files that resolve outside the linted path, such as a symlinked rule or a file under a symlinked directory. `rule fmt --write` skips symlinks while walking a directory. {{ added "unreleased" }}

`rule lint --fix` does write rule files in place. Always commit changes first, then run `--fix`, then diff.

## Dependency policy

The repo uses `cargo audit` in CI on every `Cargo.toml` or `Cargo.lock` change. The audit workflow is in [`.github/workflows/audit.yml`](https://github.com/timescale/rsigma/blob/main/.github/workflows/audit.yml). Dependabot keeps direct dependencies current; transitive fixes are applied via targeted `cargo update -p <crate>` when needed.

Supply-chain signal:

- The `cargo deny` configuration tracks deprecated and yanked crates.
- The Docker image (`ghcr.io/timescale/rsigma`) is signed with keyless cosign via the GitHub OIDC issuer and ships SLSA Build L3 provenance.
- Release archives carry SLSA build provenance attestations (verifiable with `gh attestation verify`).
- The base Docker image is pinned by digest, not tag.
- Grype scans block the Docker push on any critical CVE.

See [`.github/workflows/docker.yml`](https://github.com/timescale/rsigma/blob/main/.github/workflows/docker.yml) and [`.github/workflows/release-binaries.yml`](https://github.com/timescale/rsigma/blob/main/.github/workflows/release-binaries.yml) for the full pipelines.

## Threat model summary

RSigma assumes a trusted operator providing rules, pipelines, and source declarations on disk, plus an event stream from a trusted upstream agent. The hardening here exists to defend against malformed input, unbounded resource consumption (an attacker-controlled JSON event, a rule that recurses without bound, a dynamic source serving 100 GiB of garbage), and supply-chain attacks against dependencies. Daemon HTTP and OTLP listeners validate `Host` and `Origin` against browser-driven requests, cap connections, and time out slow clients and TLS handshakes; they can be hardened further in-process by building with the `daemon-tls` feature and pairing `--tls-cert`/`--tls-key` with `--tls-client-ca` for mTLS, plus opt-in bearer-token authentication with per-token `resource:action` permissions; without TLS, deploy behind a reverse proxy. NATS connections (source, sink, DLQ) support five auth methods plus TLS-required mode.

## See also

- [`SECURITY.md`](../security-policy.md) for the disclosure policy.
- [Dynamic Sources: resource limits](dynamic-sources.md#resource-limits) for the per-source enforcement table.
- [NATS Streaming: authentication](../guide/nats-streaming.md#authentication) for the five NATS auth methods and TLS.
- [`engine daemon` TLS flags](../cli/engine/daemon.md#tls-requires-the-daemon-tls-build-feature) for the user-facing flag table.
- [Prometheus metrics: dynamic sources](metrics.md#dynamic-sources-13-metrics) for observability of limit hits.
- [`rsigma_runtime::sources`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-runtime/src/sources) for the implementation of the resource limits.
- [`rsigma-eval` README: constants and limits](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/README.md#constants-and-limits) for the engine-side enforcement.
