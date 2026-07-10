# Disposition Source Recipes

The [triage feedback loop](triage-feedback.md) turns analyst verdicts into a live per-rule false-positive ratio. Its pull path, `--disposition-source`, reads verdicts from wherever they already live: your case system. This page gives copy-paste, tested `--disposition-source` configs for the three most common ones, TheHive, Jira, and GitHub Issues, so you do not have to re-derive the extract expression, the auth wiring, and the idempotency reasoning yourself.

Each recipe is one [dynamic-source](../reference/dynamic-sources.md) file: an HTTP source that polls the case system for recently-closed cases on an interval, and a jq `extract` that reshapes that system's API response into [disposition records](triage-feedback.md#disposition-format). No extra service, no glue script. The exact files below are committed as test fixtures and run against canned API responses in CI, so they cannot silently drift from what the engine accepts.

## How the pull loop works

`--disposition-source <PATH>` loads a standalone dynamic-source file at daemon startup and refreshes it on the source's `refresh:` interval. For each refresh the runtime fetches the response, decodes it per `format:`, and applies the `extract:` expression **before** anything else sees the payload. The extracted value is fed straight to the disposition ingest path, which accepts a single object, a JSON array, or NDJSON. So an `extract` that builds `[{rule_id, verdict, incident_id, ...}]` from a case-system response is the whole integration.

A configured source implies the loop is enabled, so `--disposition-source thehive.yml` alone is enough; you do not also need `--enable-dispositions`.

```bash
rsigma engine daemon --disposition-source /etc/rsigma/thehive.yml
```

## Read this first: the identity round-trip

A verdict only keys back to the right rule if the case carries the alert's identity. Dispositions deduplicate on `(fingerprint or incident_id, verdict, rule_id)`, so the case must know the `incident_id` (or `fingerprint`) the alert was created with, plus the `rule_id`.

That means the integration is a **round-trip**: the alert delivery that opened the case must stamp the identity into it, and the recipe reads it back out. Configure your [webhook sink](webhooks.md) (the carrier that opened the ticket) to template `rule_id` and `incident_id` into the case at creation, as shown in [Closing the loop with delivery](triage-feedback.md#closing-the-loop-with-delivery). Without that, the recipes below have no stable identity to read and the pull path silently mis-keys.

The recipes carry the identity in a label or tag (`incident:<id>`, `rsigma-incident-<id>`, `rsigma-incident:<id>`) because that is the most portable field across case systems. A dedicated custom field works too where you have one.

## GitHub Issues

GitHub has no resolution field, so the recipe defines a label convention: a `verdict:*` label carries the disposition, a `rule:<id>` label carries the rule, and an `incident:<id>` label carries the alert identity. The analyst closes the issue with the right `verdict:` label; the recipe polls closed, `alert`-labeled issues.

**Polling source** (`github.yml`):

```yaml
# Pull analyst verdicts from closed GitHub issues labeled `alert`.
#
# Label convention (defined by this recipe; GitHub has no resolution field):
#   verdict:true-positive | verdict:false-positive | verdict:benign-true-positive
#   rule:<rule_id>      the rule the alert came from
#   incident:<id>       the rsigma incident_id stamped into the issue at creation
#
# Auth: a read-only token in $GITHUB_TOKEN (fine-grained "Issues: read").
# API: https://docs.github.com/en/rest/issues/issues#list-repository-issues
# `since` filters on updated_at (not close time); the issues endpoint also
# returns pull requests, so the extract drops anything with a `pull_request` key.
sources:
  - id: github_dispositions
    type: http
    url: "https://api.github.com/repos/acme/detections/issues?state=closed&labels=alert&since=2026-07-01T00:00:00Z&per_page=100"
    headers:
      Authorization: "Bearer ${GITHUB_TOKEN}"
      Accept: "application/vnd.github+json"
      X-GitHub-Api-Version: "2022-11-28"
    format: json
    refresh: 5m
    extract: |
      [ .[]
        | select(has("pull_request") | not)
        | { l: [.labels[].name], closed: .closed_at, who: (.assignee.login? // null) }
        | select([.l[] | select(startswith("verdict:"))] | length > 0)
        | {
            rule_id: ([.l[] | select(startswith("rule:")) | ltrimstr("rule:")][0]),
            verdict: ([.l[] | select(startswith("verdict:")) | ltrimstr("verdict:")][0] | gsub("-"; "_")),
            incident_id: ([.l[] | select(startswith("incident:")) | ltrimstr("incident:")][0]),
            timestamp: .closed,
            analyst: .who
          }
      ]
```

**Verdict mapping.** GitHub has no resolution vocabulary, so the labels *are* the mapping; `gsub("-"; "_")` turns the label suffix into the wire verdict:

| Label | Verdict |
|-------|---------|
| `verdict:true-positive` | `true_positive` |
| `verdict:false-positive` | `false_positive` |
| `verdict:benign-true-positive` | `benign_true_positive` |

Issues with no `verdict:*` label are skipped (still under triage). The issues endpoint returns pull requests too, so the extract drops anything carrying a `pull_request` key. `closed_at` is RFC 3339, so it is carried as the disposition `timestamp`.

**Outbound-automation variant.** If you prefer push over polling, close the loop with a workflow that POSTs the record when an issue is closed, and skip the source file entirely:

{% raw %}
```yaml
# .github/workflows/rsigma-disposition.yml
name: rsigma disposition
on:
  issues:
    types: [closed]
jobs:
  post:
    if: contains(join(github.event.issue.labels.*.name, ','), 'verdict:')
    runs-on: ubuntu-latest
    steps:
      - name: Post disposition
        env:
          RSIGMA_TOKEN: ${{ secrets.RSIGMA_DISPOSITIONS_TOKEN }}
          LABELS: ${{ join(github.event.issue.labels.*.name, ' ') }}
        run: |
          rule_id=$(printf '%s\n' $LABELS | sed -n 's/^rule://p')
          verdict=$(printf '%s\n' $LABELS | sed -n 's/^verdict://p' | tr '-' '_')
          incident=$(printf '%s\n' $LABELS | sed -n 's/^incident://p')
          curl -sS -X POST https://rsigma.internal/api/v1/dispositions \
            -H "Authorization: Bearer $RSIGMA_TOKEN" \
            -d "{\"rule_id\":\"$rule_id\",\"verdict\":\"$verdict\",\"incident_id\":\"$incident\"}"
```
{% endraw %}

## Jira

Jira carries the disposition in the issue's **resolution**. Add a `False Positive` resolution to your workflow scheme if the default one lacks it, and map your true-positive resolution name. The recipe carries the rule and incident identities in labels.

!!! warning "Use the `search/jql` endpoint"
    The legacy `/rest/api/3/search` endpoint returns `410 Gone` on Jira Cloud. Use `/rest/api/3/search/jql`, which requires an explicit `fields` list and paginates with `nextPageToken` rather than `startAt`.

**Polling source** (`jira.yml`):

```yaml
# Pull analyst verdicts from resolved Jira Cloud issues.
#
# Convention:
#   resolution name "False Positive" / "True Positive" (add a "False Positive"
#     resolution to your workflow scheme if the default one lacks it)
#   label rsigma-rule-<rule_id>     the rule the alert came from
#   label rsigma-incident-<id>      the rsigma incident_id stamped in at creation
#
# Auth: HTTP Basic; $JIRA_BASIC_AUTH is base64("email:api_token") for a
# read-only token. API token docs:
# https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/
# Endpoint: the legacy /rest/api/3/search returns 410 Gone; use search/jql, which
# needs an explicit `fields` list and paginates with nextPageToken (not startAt):
# https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search/#api-rest-api-3-search-jql-get
# `resolutiondate` is not RFC 3339 (offset is +0000, no colon), so the extract
# omits `timestamp` and lets ingest default it; the incident_id keys the record.
sources:
  - id: jira_dispositions
    type: http
    url: "https://your-domain.atlassian.net/rest/api/3/search/jql?jql=resolution%20in%20(%22False%20Positive%22%2C%22True%20Positive%22)%20AND%20updated%20%3E%3D%20-1d&fields=resolution,resolutiondate,labels,assignee&maxResults=100"
    headers:
      Authorization: "Basic ${JIRA_BASIC_AUTH}"
      Accept: "application/json"
    format: json
    refresh: 5m
    extract: |
      [ .issues[]
        | .fields as $f
        | select($f.resolution != null
                 and ($f.resolution.name == "False Positive"
                      or $f.resolution.name == "True Positive"))
        | {
            rule_id: ([$f.labels[] | select(startswith("rsigma-rule-")) | ltrimstr("rsigma-rule-")][0]),
            verdict: (if $f.resolution.name == "False Positive"
                      then "false_positive" else "true_positive" end),
            incident_id: ([$f.labels[] | select(startswith("rsigma-incident-")) | ltrimstr("rsigma-incident-")][0]),
            analyst: ($f.assignee.displayName? // null)
          }
      ]
```

**Verdict mapping.** Resolution names are scheme-dependent, so this is the one you are most likely to adjust:

| Jira resolution | Verdict |
|-----------------|---------|
| `False Positive` | `false_positive` |
| `True Positive` | `true_positive` |
| anything else (`Done`, `Duplicate`, ...) | skipped |

Auth is HTTP Basic, not Bearer: `$JIRA_BASIC_AUTH` is `base64("email:api_token")`. Jira's `resolutiondate` is not RFC 3339 (its offset is `+0000`, without the colon RFC 3339 requires), so the extract omits `timestamp` and lets ingest default it to receive time; the `incident_id` still keys the record, so dedup stays correct.

**Outbound-automation variant.** A Jira Automation rule on "Issue resolved" with a "Send web request" action POSTs the record directly, templating the fields with Jira smart values:

{% raw %}
```json
{
  "rule_id": "{{issue.labels.match("rsigma-rule-(.*)")}}",
  "verdict": "{{#if(equals(issue.resolution.name, "False Positive"))}}false_positive{{else}}true_positive{{/}}",
  "incident_id": "{{issue.labels.match("rsigma-incident-(.*)")}}"
}
```
{% endraw %}

## TheHive

TheHive carries the disposition in each case's `resolutionStatus`. TheHive 5 (StrangeBee) searches cases through `POST /api/v1/query` with a JSON body (there is no GET-with-filters equivalent), so the recipe uses the HTTP source's `body` field.

**Polling source** (`thehive.yml`):

```yaml
# Pull analyst verdicts from resolved TheHive 5 (StrangeBee) cases.
#
# Convention:
#   resolutionStatus  TruePositive | FalsePositive
#     (Indeterminate / Duplicated / Other are skipped in the extract; TheHive
#      has no native benign-true-positive status, so teams that track BTP add a
#      case tag and map it here.)
#   tag rsigma-rule:<rule_id>       the rule the alert came from
#   tag rsigma-incident:<id>        the rsigma incident_id stamped in at creation
#
# Auth: a read-only API key in $THEHIVE_API_KEY.
# API: TheHive 5 case search is POST /api/v1/query with a JSON body (there is no
# GET-with-filters equivalent), so this recipe uses the http-source `body` field.
# https://docs.strangebee.com/thehive/api-docs/
# `_updatedAt` is epoch milliseconds, not RFC 3339, so the extract omits
# `timestamp` and lets ingest default it; the incident_id keys the record.
sources:
  - id: thehive_dispositions
    type: http
    url: "https://thehive.example.com/api/v1/query?name=rsigma-dispositions"
    method: POST
    headers:
      Authorization: "Bearer ${THEHIVE_API_KEY}"
      Content-Type: "application/json"
    body: |
      {"query":[
        {"_name":"listCase"},
        {"_name":"filter","_eq":{"_field":"status","_value":"Resolved"}},
        {"_name":"sort","_fields":[{"_updatedAt":"desc"}]},
        {"_name":"page","from":0,"to":100}
      ]}
    format: json
    refresh: 5m
    extract: |
      [ .[]
        | select(.resolutionStatus == "TruePositive"
                 or .resolutionStatus == "FalsePositive")
        | { tags: (.tags // []), rs: .resolutionStatus, who: (.assignee? // null) }
        | {
            rule_id: ([.tags[] | select(startswith("rsigma-rule:")) | ltrimstr("rsigma-rule:")][0]),
            verdict: (if .rs == "TruePositive" then "true_positive" else "false_positive" end),
            incident_id: ([.tags[] | select(startswith("rsigma-incident:")) | ltrimstr("rsigma-incident:")][0]),
            analyst: .who
          }
      ]
```

**Verdict mapping.** TheHive's `resolutionStatus` enum maps cleanly for the two verdicts that matter, and the rest are triage-inconclusive, so they are skipped:

| TheHive `resolutionStatus` | Verdict |
|----------------------------|---------|
| `TruePositive` | `true_positive` |
| `FalsePositive` | `false_positive` |
| `Indeterminate`, `Duplicated`, `Other` | skipped |

TheHive has no native benign-true-positive status. Teams that track BTP add a case tag (say `rsigma-btp`) and extend the `verdict` branch to emit `benign_true_positive` when that tag is present. `_updatedAt` is epoch milliseconds rather than RFC 3339, so the extract omits `timestamp` and lets ingest default it; the `incident_id` keys the record.

**Outbound-automation variant.** A TheHive notification with a webhook endpoint fires on case resolution; point it at an intermediary that reshapes the notification body into a disposition record and POSTs it, or template it at a SOAR step. TheHive notifications do not template arbitrary JSON at the sender the way Jira Automation does, so polling is the recommended path here.

## Idempotency and windowing

**Re-polls are safe.** Every recipe polls on an interval and returns the same closed cases until they age out of the query window. That is fine: ingestion deduplicates on `(fingerprint or incident_id, verdict, rule_id)`, so a case returned on ten consecutive polls counts once. This is what makes interval polling correct rather than a double-counting hazard.

**Window to bound payload size, not for correctness.** Each recipe filters to recently-updated closed cases (`since=` for GitHub, `updated >= -1d` for Jira, a `_updatedAt` sort plus `page` for TheHive). This keeps each response small; it is not required for correctness because of the dedup above. Pick a window comfortably larger than your poll interval.

**No pagination following.** A source does a single fetch (capped at 10 MiB); it does not follow a `Link` header or a `nextPageToken` cursor. Keep each response inside one page by pairing a tight update window with the page-size cap (`per_page=100`, `maxResults=100`, TheHive's `page` clause). If more cases close in one window than a single page holds, the overflow is picked up on the next poll only if it still matches the window, so size the window and interval so a single page comfortably covers the closures between polls.

**Healthy signal.** A working recipe increments `rsigma_disposition_ingest_total{source="http",result="accepted"}` on first sight of each verdict and `result="duplicate"` on every re-poll thereafter. A recipe whose extract emits a malformed record increments `rsigma_disposition_ingest_errors_total{reason="validation"}`; a broken sources file fails the daemon at boot with `CONFIG_ERROR`, so a recipe either loads and works or stops the daemon loudly.

## Limits and follow-ons

- **No direct raw-webhook ingestion.** A raw TheHive/Jira/GitHub webhook cannot point at `POST /api/v1/dispositions`, because that endpoint parses its body directly as disposition records and applies no transform. Webhook-shaped integrations therefore go through the sender's own templating (the outbound-automation variants above) or a relay. A server-side `extract` option on the POST endpoint would close that gap natively; it is a possible future addition, deliberately not part of this docs-only integration.
- **NATS relay for push without sender templating.** If you want push delivery but your case system cannot template JSON at the sender, publish its webhook to a NATS subject through a thin relay and point a [NATS dynamic source](../reference/dynamic-sources.md) with the same `extract` at that subject. The reshaping is identical; only the transport changes.
- **Other case systems.** Any system with a queryable closed-case API follows the same three parts: an HTTP (or NATS) source, an auth header from `${ENV_VAR}`, and a jq `extract` that emits disposition records. ServiceNow, PagerDuty, and others drop into the same template.

## See also

- [Triage Feedback Loop](triage-feedback.md) for the loop these recipes feed.
- [Dynamic Sources](../reference/dynamic-sources.md) for the full source-file schema (HTTP `body`, `extract` languages, refresh policies, error handling).
- [HTTP API: Dispositions](../reference/http-api.md#dispositions) for the record shape and the `POST` endpoint the outbound variants target.
- [`engine daemon` disposition flags](../cli/engine/daemon.md#triage-feedback-loop) for `--disposition-source` and the `daemon.dispositions` config keys.
