---
description: "Push indicators into a running RSigma daemon and match them from Sigma rules without a rule reload."
---

# Threat intel watchlists

{{ added "unreleased" }}

A watchlist is a dynamic source whose values are pushed over the daemon API instead of fetched from a file or a feed. Use it for indicators that change between rule reloads: a handful of C2 addresses, a short domain list, a hash an analyst just confirmed.

A list that belongs in a rule as `%name%` has to stay under the placeholder expansion limit of 4096 combinations. A watchlist that a pipeline references is capped there: a push past 4096 indicators returns 422 and changes nothing. A watchlist that no pipeline references keeps `max_indicators`, which is how a lookup enricher holds a larger set.

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

`--clear-state` deletes the saved indicators on startup.

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

## See also

- [Dynamic Sources](../reference/dynamic-sources.md) for the source declaration.
- [HTTP API](../reference/http-api.md#watchlist-indicators) for status codes and response bodies.
- [Metrics](../reference/metrics.md) for `rsigma_watchlist_indicators` and `rsigma_watchlist_changes_total`.
