# Webhooks

The webhook sink delivers detections and correlations to any HTTP endpoint as a templated request. It is one generic, template-driven sink rather than a set of bespoke integrations: Slack, Microsoft Teams, Discord, and PagerDuty are field-parametric YAML recipes you paste and adapt (see the catalog below), and the engine stays service-agnostic.

Webhooks compose with the other `--output` sinks. The daemon fans each result into every sink, so you can keep a durable NATS or file record while a webhook posts an alert to chat.

## Reliability model: best-effort, at-most-once

A webhook is a notification channel, not a durable record. It runs in the lossy `on_full=drop` mode of the [async delivery layer](../cli/engine/daemon.md): its acknowledgment fires when the result is enqueued (or dropped, or routed to the DLQ), never when the third-party endpoint actually responds. This is by design: blocking event acknowledgment on a chat or paging service would be the worse failure mode. Keep your durable record on NATS or a file; anything the webhook cannot deliver lands in the `--dlq`.

Because each sink runs its own bounded queue and worker, a slow or flaky webhook endpoint cannot stall the NATS or file sink behind it.

## Enabling webhooks

Declare webhooks in a YAML file and pass it with `--webhook` (repeatable; a file or a directory of `*.yml`/`*.yaml` files):

```bash
rsigma engine daemon -r rules/ --input http \
  --webhook /etc/rsigma/webhooks/slack.yaml \
  --output nats://localhost:4222/detections \
  --dlq file:///var/lib/rsigma/dlq.ndjson
```

Or in the layered config file:

```yaml
daemon:
  output:
    webhooks:
      - /etc/rsigma/webhooks/
```

Webhook configs are loaded and validated once at startup. A config that references the wrong template namespace, declares an unknown `kind`, omits `url`, or sets a malformed retry or rate-limit value rejects the daemon with a clear, field-scoped error. Hot reload is not supported in v1: webhook changes take effect on restart.

## Config reference

```yaml
webhooks:
  - id: slack-critical              # stable id; the metric label
    kind: detection                 # detection | correlation
    url: https://hooks.slack.com/services/${SLACK_WEBHOOK_PATH}
    method: POST                    # default POST
    headers:
      Content-Type: application/json
      Authorization: "Bearer ${SLACK_TOKEN}"
    body: |
      {"text": "Sigma: ${detection.rule.title} (${detection.rule.level})"}
    timeout: 5s                     # per-request; default 10s
    retry:
      attempts: 3                   # total tries; default 3, minimum 1
      backoff: 1s                   # exponential base; default 1s
      max_backoff: 30s              # cap; default 30s
    rate_limit:
      requests: 60                  # default unset (unlimited)
      per: 1m
    scope:                          # all populated axes AND together
      levels: [high, critical]
    queue_size: 1024                # bounded queue; default 1024
    tls:                            # optional; omit for public endpoints
      ca: /etc/rsigma/tls/relay-ca.pem
      client_cert: /etc/rsigma/tls/client.pem
      client_key: /etc/rsigma/tls/client.key
    signing:                        # optional; HMAC-sign each request
      secret_env: RSIGMA_WEBHOOK_SECRET
      scheme: standard              # standard (default) | github | custom
```

| Field | Required | Default | Notes |
|-------|----------|---------|-------|
| `id` | yes | — | Stable identifier; the `webhook_id` metric label and the per-sink delivery label. Must be unique across all webhook files. |
| `kind` | yes | — | `detection` or `correlation`. Filters which result-body variant the webhook fires on. `incident` is reserved for a later release. |
| `url` | yes | — | Target URL template. |
| `method` | no | `POST` | Any valid HTTP method. |
| `headers` | no | — | Header templates. Values are rendered per result. |
| `body` | no | — | Body template, rendered with JSON-string escaping (see below). |
| `timeout` | no | `10s` | Per-request timeout (humantime: `5s`, `500ms`). |
| `retry.attempts` | no | `3` | Total tries, one initial plus retries. |
| `retry.backoff` | no | `1s` | Exponential backoff base. |
| `retry.max_backoff` | no | `30s` | Backoff ceiling. |
| `rate_limit.requests` / `rate_limit.per` | no | unlimited | Token-bucket budget; burst equals `requests`. |
| `scope.rules` / `scope.tags` / `scope.levels` | no | unrestricted | Same axes as enricher [scopes](enrichers.md); each populated axis must match. |
| `queue_size` | no | `1024` | Bounded queue depth between the dispatcher and the worker. |
| `tls.ca` / `tls.client_cert` / `tls.client_key` | no | system roots | PEM file paths. `ca` trusts a private CA in addition to the system roots; `client_cert` and `client_key` (set together) enable mutual TLS. See [TLS to internal endpoints](#tls-to-internal-endpoints). |
| `signing.secret_env` | yes (if signing) | — | Environment variable holding the HMAC key. The secret is never stored in the YAML. |
| `signing.secret_encoding` | no | `utf8` | `utf8` (raw bytes) or `base64` (decoded, stripping an optional `whsec_` prefix) for a svix-issued secret. |
| `signing.scheme` | no | `standard` | `standard` (Standard Webhooks), `github` (`X-Hub-Signature-256`), or `custom`. See [Signing requests](#signing-requests). |
| `signing.rotate_secret_env` | no | — | A second key (another env var) emitted as an extra signature during rotation. Not supported by `github`. |
| `signing.custom.*` | no | — | Custom-scheme knobs: `algorithm`, `encoding`, `signature_header`, `value_format`, `signed_payload`, `timestamp_header`, `id_header`. |

The `retry.*` and `queue_size` settings override the daemon's global `--sink-*` delivery defaults for this webhook only.

## Templating

`url`, every header value, and `body` are templates rendered per result by the same engine the [enrichers](enrichers.md) use:

- `${detection.*}` / `${correlation.*}` for result data, matching the webhook's `kind`. Common paths: `${detection.rule.title}`, `${detection.rule.id}`, `${detection.rule.level}`, `${detection.tags}`, `${detection.fields.<Name>}`, `${detection.event.<dotted.path>}`; `${correlation.type}`, `${correlation.aggregated_value}`, `${correlation.group_key.<field>}`.
- `${ENV_VAR}` (single segment, no dot) for secrets. Resolved from the daemon process environment at render time, so secrets live in the environment, never in the webhook YAML.

The `body` is JSON-string-escaped: interpolated values (rule titles, event field strings) that land inside a JSON string literal have their quotes, backslashes, and control characters escaped, so a rule title containing a quote cannot break the payload. `url` and header values use identity escaping (they are not JSON).

Every templated field is validated at startup against the webhook's `kind`: a `${correlation.*}` reference inside a `kind: detection` webhook rejects the daemon with a pointer at the offending field.

`${detection.event.*}` only resolves when the event is retained. Pass `--include-event` (or set `rsigma.include_event` per rule) for recipes that interpolate raw event fields.

## Delivery, retry, and rate limiting

Each webhook is driven by one bounded queue and worker. The worker owns the queue, the retry schedule, DLQ routing, and drain on shutdown; the webhook owns the per-request behavior:

- **Classification.** Connection and timeout errors, HTTP `429` (honoring a numeric `Retry-After`, capped), and `5xx` are retryable. Other `4xx` are permanent: a misrendered payload will not heal on retry, so it routes straight to the DLQ without spending the retry budget.
- **Backoff.** Retryable failures use capped exponential backoff (`backoff * 2^attempt`, up to `max_backoff`). Retries delay only this webhook's own queue.
- **Rate limiting.** When a per-entry token bucket is configured, the worker waits for a token before each request, so traffic is delayed rather than dropped; the wait shows up as the `rate_limited_wait` outcome.
- **DLQ.** Both retry exhaustion and a full queue route to the daemon's `--dlq`, reusing the same record shape as parse errors and other sink failures, with an error prefixed `webhook <id>:`.

## Egress policy and secrets

Webhooks use the daemon's egress-filtered HTTP client, so they honor `--egress-policy`. The `strict` policy blocks RFC1918 ranges, so a webhook targeting an internal relay needs `default` (the default) or `permissive`. Outbound proxies follow the standard `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment variables. TLS uses rustls with the system root store.

Keep secrets in the environment and reference them with `${ENV_VAR}`; do not put tokens or signing URLs in the webhook YAML. The HMAC signing key follows the same rule: name it with `signing.secret_env` rather than embedding it (see [Signing requests](#signing-requests)).

## TLS to internal endpoints

Public services (Slack, Teams, Discord, PagerDuty) are reached over HTTPS with the system root store, so they need no `tls:` block. For an internal relay served by a private CA, or an endpoint that requires client authentication, add a `tls:` block:

- `tls.ca` is a PEM bundle trusted in addition to the system roots, so a relay whose certificate chains to a private CA verifies.
- `tls.client_cert` and `tls.client_key` (set together) present a client certificate for mutual TLS.

```yaml
webhooks:
  - id: internal-relay
    kind: detection
    url: https://relay.internal:8443/alerts
    body: '{"text": "${detection.rule.title}"}'
    tls:
      ca: /etc/rsigma/tls/relay-ca.pem
      client_cert: /etc/rsigma/tls/client.pem
      client_key: /etc/rsigma/tls/client.key
```

Webhook TLS uses rustls and verifies the endpoint against the URL host. PEM files are read and validated at startup, so a missing file, a malformed certificate, or a `client_cert` without its `client_key` rejects the daemon with a clear error.

## Signing requests

A webhook can HMAC-sign every request so a receiving endpoint can confirm it came from rsigma (authenticity), that the body was not altered in transit (integrity), and, for the timestamped default, that it is not a replay. The signature covers the exact rendered body bytes, which the template engine cannot produce on its own, so signing is a first-class `signing:` block rather than a header recipe.

Signing only helps endpoints you control and write the verifier for, such as an internal relay or a custom receiver. The public services (Slack, Microsoft Teams, Discord, PagerDuty) do not verify a sender HMAC, so it adds nothing there. It complements the `tls:` and `Authorization`-header mechanisms rather than replacing them.

The key always comes from the environment via `signing.secret_env`, resolved once at startup, so a missing key fails the daemon at boot instead of silently shipping unsigned requests.

### Schemes

`signing.scheme` selects one of three conventions:

- **`standard`** (default): the cross-industry [Standard Webhooks](https://www.standardwebhooks.com/) scheme. It emits `webhook-id` (a per-delivery `msg_<uuid>`), `webhook-timestamp` (unix seconds), and `webhook-signature` (`v1,<base64 HMAC-SHA256 of "{id}.{timestamp}.{body}">`). The signed timestamp gives receivers a replay window and the id lets them dedupe, which makes it the most secure default; verification libraries exist in many languages.
- **`github`**: `X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of body>`, the widely recognized GitHub convention. It signs the body only, so it has no replay protection, and rotation is not supported.
- **`custom`**: an operator-defined header name, algorithm (`sha256` or `sha512`), encoding (`hex` or `base64`), value format, and signed-payload template, for receivers like Stripe.

A retry reproduces an identical id, timestamp, and signature, so a receiver can dedupe redeliveries on `webhook-id` and enforce a replay window on `webhook-timestamp`. rsigma only generates signatures; the verifier on the receiving side must compare them in constant time.

### Standard Webhooks (default)

```yaml
webhooks:
  - id: relay-critical
    kind: detection
    url: https://relay.internal/alerts
    body: '{"text": "${detection.rule.title}"}'
    scope:
      levels: [critical]
    signing:
      secret_env: RSIGMA_WEBHOOK_SECRET
```

The key is the raw value of `$RSIGMA_WEBHOOK_SECRET`. If you generated it with a Standard Webhooks library (a `whsec_`-prefixed base64 secret), set `secret_encoding: base64` and rsigma strips the prefix and decodes it before signing. A receiver verifies with any Standard Webhooks library, or directly:

```python
import base64, hashlib, hmac

def verify(secret: bytes, headers: dict, body: bytes) -> bool:
    signed = f"{headers['webhook-id']}.{headers['webhook-timestamp']}.".encode() + body
    expected = "v1," + base64.b64encode(hmac.new(secret, signed, hashlib.sha256).digest()).decode()
    # webhook-signature can carry several space-separated signatures (rotation).
    sent = headers["webhook-signature"].split(" ")
    return any(hmac.compare_digest(expected, s) for s in sent)
```

### GitHub-style

For a receiver that expects the GitHub `X-Hub-Signature-256` header:

```yaml
webhooks:
  - id: github-style
    kind: detection
    url: https://receiver.internal/hook
    body: '{"text": "${detection.rule.title}"}'
    signing:
      secret_env: RSIGMA_WEBHOOK_SECRET
      scheme: github
```

### Custom (Stripe-style)

The custom scheme signs a templated payload and renders a templated header value, which covers schemes like Stripe's `t=<timestamp>,v1=<hex>`:

```yaml
webhooks:
  - id: stripe-style
    kind: detection
    url: https://receiver.internal/hook
    body: '{"text": "${detection.rule.title}"}'
    signing:
      secret_env: RSIGMA_WEBHOOK_SECRET
      scheme: custom
      custom:
        algorithm: sha256
        encoding: hex
        signature_header: X-Signature
        value_format: "t={timestamp},v1={signature}"
        signed_payload: "{timestamp}.{body}"
```

`value_format` accepts the `{signature}`, `{timestamp}`, and `{id}` tokens and must contain `{signature}`; `signed_payload` accepts `{body}`, `{timestamp}`, and `{id}`. Optional `timestamp_header` and `id_header` emit those values as separate headers.

### Key rotation

To rotate a secret without dropping deliveries, set `rotate_secret_env` to the previous key's variable. rsigma emits a signature for each key (space-separated for the `standard` and `custom` schemes), so a receiver that accepts either verifies throughout the rollover. Drop `rotate_secret_env` once every receiver trusts the new key. Rotation is not available for `github`, which carries a single signature value.

## Observability

Per-webhook request metrics:

- `rsigma_webhook_requests_total{webhook_id,outcome}` with outcomes `success`, `permanent_failure`, and `rate_limited_wait`.
- `rsigma_webhook_request_duration_seconds{webhook_id}`.

Queue depth, retries, drops, and DLQ routing are read from the shared per-sink series (`rsigma_sink_queue_depth`, `rsigma_sink_retries_total`, ...), keyed by `sink=<webhook id>` so the two series join one-to-one. Labels are pre-seeded from config at startup, so panels render before any traffic.

## Recipe catalog

These are starting points. Each scopes itself to a severity tier and hardcodes the service-specific styling for that tier (the template engine has no conditionals, so use one webhook per tier rather than branching in a template).

### Slack

A Slack incoming webhook with a Block Kit payload:

```yaml
webhooks:
  - id: slack-critical
    kind: detection
    url: https://hooks.slack.com/services/${SLACK_WEBHOOK_PATH}
    scope:
      levels: [critical]
    body: |
      {"blocks": [
        {"type": "header", "text": {"type": "plain_text", "text": ":rotating_light: ${detection.rule.title}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "*Level:* ${detection.rule.level}\n*Rule:* `${detection.rule.id}`\n*Tags:* ${detection.tags}"}}
      ]}
```

`${SLACK_WEBHOOK_PATH}` is the `T000/B000/XXXX` path segment of your incoming webhook URL, supplied via the environment.

### Microsoft Teams

Teams retired Office 365 connectors; the current shape is a Power Automate "When a Teams webhook request is received" workflow URL with an Adaptive Card:

```yaml
webhooks:
  - id: teams-high
    kind: detection
    url: ${TEAMS_WORKFLOW_URL}
    scope:
      levels: [high, critical]
    body: |
      {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
          "type": "AdaptiveCard",
          "version": "1.4",
          "body": [
            {"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": "${detection.rule.title}"},
            {"type": "TextBlock", "text": "Level ${detection.rule.level}, rule ${detection.rule.id}", "wrap": true}
          ]
        }
      }]}
```

### Discord

A Discord webhook with a colored embed (decimal color; `15158332` is red):

```yaml
webhooks:
  - id: discord-critical
    kind: detection
    url: ${DISCORD_WEBHOOK_URL}
    scope:
      levels: [critical]
    body: |
      {"content": "Sigma detection", "embeds": [{
        "title": "${detection.rule.title}",
        "description": "Level ${detection.rule.level}\nRule ${detection.rule.id}",
        "color": 15158332
      }]}
```

### PagerDuty

PagerDuty Events API v2. The `routing_key` is the integration key for an Events API v2 service; `dedup_key` groups alerts (using the rule id here, which improves once incident grouping supplies stable incident ids):

```yaml
webhooks:
  - id: pagerduty-critical
    kind: detection
    url: https://events.pagerduty.com/v2/enqueue
    scope:
      levels: [critical]
    body: |
      {
        "routing_key": "${PAGERDUTY_ROUTING_KEY}",
        "event_action": "trigger",
        "dedup_key": "${detection.rule.id}",
        "payload": {
          "summary": "${detection.rule.title}",
          "severity": "critical",
          "source": "rsigma"
        }
      }
```

## Looking ahead

`kind` is a closed set today (`detection`, `correlation`). A later release adds `kind: incident` and an `${incident.*}` template namespace so one webhook can fire per grouped incident instead of per raw detection. That will be an additive change: no existing config key changes meaning, and switching a webhook to incident-level alerting becomes a one-line `kind` swap.
