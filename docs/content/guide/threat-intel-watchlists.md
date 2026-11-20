---
description: "Push indicators into a running RSigma daemon and match them from Sigma rules without a rule reload."
---

# Threat intel watchlists

{{ added "unreleased" }}

A watchlist is a dynamic source whose values are pushed over the daemon API instead of fetched from a file or a feed. Use it for indicators that change between rule reloads: a handful of C2 addresses, a short domain list, a hash an analyst just confirmed.

A list that belongs in a rule as `%name%` has to stay under the placeholder expansion limit of 4096 combinations. A watchlist that a pipeline references is capped there: a push past 4096 indicators returns 422 and changes nothing. A watchlist that no pipeline references keeps `max_indicators`, which is how a lookup enricher holds a larger set. A successful reload computes the cap again, so a pipeline edit that starts or stops referencing the watchlist changes it.

## Declare the source

```yaml
sources:
  - id: c2_ips
    type: watchlist
    max_indicators: 100000
    max_value_length: 2048
    default_ttl: 30d
```

`default_ttl` is optional. Leave it out and pushed indicators stay until you delete them. `max_indicators: 0` and `max_value_length: 0` are configuration errors. `refresh`, `format`, `extract`, and `timeout` are not accepted. The ids `resolve` and `cache` are reserved.

Start the daemon with the file and, if the set should survive a restart, a state database:

```bash
rsigma engine daemon -r rules/ -p pipelines/c2.yml \
  --source sources.yml \
  --state-db /var/lib/rsigma/state.db \
  --input http
```

`--clear-state` deletes the saved indicators on startup. A restart that finds more saved indicators than the cap loads the cap and logs how many were left out. Those rows stay in the database until a later write replaces the set.

## Match them from a rule

```yaml
name: c2
priority: 10
vars:
  c2_ips:
    - "${source.c2_ips}"
transformations:
  - type: value_placeholders
```

```yaml
title: C2 destination
logsource:
  category: network_connection
detection:
  selection:
    DestinationIp|expand: '%c2_ips%'
  condition: selection
```

An empty watchlist matches nothing. A value that is pushed, replaced, or deleted rebuilds the rules that reference the source. The HTTP call returns before that rebuild finishes. Expect the new set to be in effect within about a second, and an expiry to take effect within about 10 seconds of the sweeper.

## Push indicators

`sources:write` is required. A reader token can list the set and cannot change it.

```bash
curl -sS -X POST http://127.0.0.1:9090/api/v1/sources/c2_ips/indicators \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"ttl":"7d","indicators":["198.51.100.7",{"value":"bad.example","ttl":"24h"}]}'
```

`PUT` replaces the unexpired set. `DELETE` takes `{"indicators":["198.51.100.7"]}`. `GET` lists values with `added_at` and `expires_at`.

Expiry is chosen in this order: the item's `expires_at` (RFC 3339), the item's `ttl`, the request's `ttl`, the source `default_ttl`. If none is set, the indicator does not expire. An `expires_at` that is not later than the current time is rejected. Values are compared exactly. Whitespace around a value is removed. An empty value, a value over `max_value_length`, and a value with an ASCII control character are rejected with the item's index.

One request may carry 10,000 indicators and 4 MiB. Going past `max_indicators`, or past 4096 on a pipeline-referenced watchlist, returns 422 and changes nothing. A failed state-database write returns 500 and also changes nothing. When `--state-db` is set, the audit trail is on and rejects a body larger than `daemon.api.audit.max_body_bytes` (default 64 KiB) with 413 before this handler runs. Raise that key to push a larger batch.

## Look an indicator up

A lookup enricher reads the same cached array without a placeholder expansion, which is the path for a list that would exceed 4096 values:

```yaml
enrichers:
  - id: c2_hit
    kind: detection
    type: lookup
    inject_field: c2_indicator
    source: c2_ips
    default: absent
```

The enricher does not by itself rebuild rules. A watchlist that no pipeline references still refreshes the cache when you push, so the next detection sees the new array.

## STIX indicator sources

{{ added "unreleased" }}

A watchlist is the list you push. A STIX source is a list the daemon pulls. Both can feed the same `${source.<id>.…}` expansion and the same lookup enricher. STIX sources need the `stix-source` feature.

Use a watchlist when an analyst or another system posts values to the daemon and you want them to survive in `--state-db`. Use `type: taxii` when a TAXII 2.1 collection is the authority and the daemon should poll it. Use `format: stix` on a file when the bundle is already on disk and `refresh: watch` should rebuild on each write, or on HTTP when a feed publishes a bundle. Use `taxii sync` plus a `type: stix` enricher when you want a local store, relationship walks, and lookup by STIX id. That path does not expand indicators into a Sigma placeholder.

A file bundle:

```yaml
sources:
  - id: ti_file
    type: file
    path: ./intel/indicators.json
    format: stix
    refresh: watch
    stix:
      min_confidence: 70
      observables: [ipv4, domain]
```

```yaml
detection:
  selection:
    DestinationIp|expand: '%ti_ips%'
  condition: selection
```

```yaml
vars:
  ti_ips: ["${source.ti_file.ipv4}"]
```

A TAXII collection. `url` is the API root, not the discovery URL. The token stays in the environment:

```yaml
sources:
  - id: ti
    type: taxii
    url: https://taxii.example/api1/
    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116
    refresh: 15m
    auth:
      bearer_token_env: TAXII_TOKEN
    stix:
      observables: [ipv4, domain]
```

`${source.ti.ipv4}` is the sorted address list. Values in those arrays escape `\`, `*`, and `?`, so a Sigma `|expand` comparison stays exact. `${source.ti.indicators}` is the metadata map, keyed by the raw value. A lookup enricher can read one entry with `extract: '.indicators."${detection.fields.DestinationIp}"'`.

The first poll reads the collection. Later polls ask only for objects added since the last page. One poll reads a bounded number of pages. When the collection is larger, the daemon logs a warning and the next refresh continues from the last page's added date, so give a large collection a `refresh` duration rather than `once`. A poll that repeats its cursor, or that answers 416 for the same filter, fails instead of running without a bound. A failed poll keeps the previous value. The cursor is not stored, so a restart reads the collection again. An indicator stays in the value until the refresh after its `valid_until`. Indicators cut by the cap stay in memory up to twice the cap, so a freed slot can be filled from them. Expired and revoked ids are remembered only so an older copy cannot return.

Field-by-field rules, the observable keys, and the JSON shape are in [Dynamic Sources](../reference/dynamic-sources.md#format-stix).

## From a TI report to a rule

{{ added "unreleased" }}

A STIX bundle can also become a Sigma rule, instead of a pipeline value. `rsigma rule draft --from-stix` reads the bundle, or one indicator object, and prints one rule per logsource. Addresses, CIDR ranges, domains, URLs, file hashes, file names, and registry keys are drafted. Email addresses, mutexes, MAC addresses, and ASNs are not. A pattern that is not a simple `=` or `IN` comparison is skipped, and so is a revoked indicator. Expired and not-yet-valid indicators are skipped unless you pass `--include-expired`. A registry key drops its hive and matches `TargetObject` with `|contains`, so a Sysmon event that records the short hive and appends the value name still matches. An IPv6 address is written in the shortened form Sysmon records. `--date` must be `YYYY-MM-DD`. `--observable` and `--include-expired` are rejected when `--from-stix` is absent.

The command needs the `stix-draft` feature. A default `cargo install rsigma` build does not have the flag: `rsigma rule draft --help` will not list it. Release binaries and the Docker image include it. `rsigma --features` prints `stix-draft` when this binary has it.

```bash
rsigma rule draft --from-stix indicators.json --date 2026-06-01 > draft.yml
rsigma rule lint draft.yml
```

`--date` writes that calendar day into the rule. Leave it off and the date is today (UTC), so the file changes on the next day. The rule `id` does not. It is a UUID v5 of the logsource and the indicator ids.

To see which indicators were used and which were skipped, ask for the report. It is JSON with `rules`, `used`, and `skipped`. A file that parses but drafts nothing still prints that JSON and exits 1.

```bash
rsigma rule draft --from-stix indicators.json --emit report --date 2026-06-01
```

`--observable domain` keeps one kind. Repeat the flag for more than one. The field-by-field mapping, the metadata rules, the skip reasons, and the exit codes are on [rule draft](../cli/rule/draft.md#draft-from-a-stix-indicator).

## See also

- [Dynamic Sources](../reference/dynamic-sources.md) for the source declaration.
- [HTTP API](../reference/http-api.md#watchlist-indicators) for status codes and response bodies.
- [Metrics](../reference/metrics.md) for `rsigma_watchlist_indicators`, `rsigma_watchlist_changes_total`, and the `rsigma_stix_source_*` families.
- [Feature Flags](../reference/feature-flags.md) for `stix-source` and `stix-draft`.
- [`rule draft`](../cli/rule/draft.md#draft-from-a-stix-indicator) for drafting Sigma from a bundle.
