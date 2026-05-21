# Adding an enricher

The four primitives `template`, `lookup`, `http`, and `command` cover almost every operational use case via [recipes](../guide/enrichers.md#composing-enrichers-recipes). When they don't, the runtime ships a bespoke enricher API: implement the `Enricher` trait, register it under a stable `type:` name with `register_builtin(name, factory)`, and operators reference it from their YAML by that name. This page is the recipe for that path.

## Decide whether you actually need a bespoke enricher

A bespoke Rust-coded enricher is justified only when at least one of these holds; the [user-facing guide](../guide/enrichers.md#promoting-a-recipe-to-a-bespoke-enricher) walks through the same criteria from the operator's angle:

1. **It bundles non-trivial data**: a dataset committed to the repo and `include_bytes!`-ed at compile time (a MITRE ATT&CK STIX bundle, a vendored mini-IOC list). Recipes can't express vendored data.
2. **It needs a parser the YAML primitives don't expose**: MaxMind's binary GeoLite2, the STIX 2.1 graph with parent/child resolution, a binary signature database. Adding the parser as a generic source might cost more than just shipping the enricher.
3. **It provides a stable named contract**: downstream consumers reference a specific `enrichments.<field>` shape directly. A recipe-driven approach lets every operator pick their own `inject_field`, which is fine for ad-hoc enrichment but bad for a contract that crosses team or organisational boundaries.
4. **It implements a non-obvious algorithm**: e.g. coalescing per-result hash lookups into one batched-GET request. This is implementable as a recipe but the implementation is fragile.

If none of these apply, ship a recipe under `crates/rsigma-cli/README.md` instead. Promoting a recipe to a bespoke type later does not change the YAML shape, only the `type:` value.

## Walkthrough: a hypothetical `enrich_ip_passive_dns_batched` enricher

This example shipsbatched per-event lookups against a passive DNS API, coalescing repeated calls into one upstream request per `(api_key, ip)` tuple within a sliding 1-second window. The behaviour is fragile to express as a recipe; criterion (4) applies.

The crate layout. Bespoke enrichers usually live in their own external crate so they can be versioned and feature-gated independently of `rsigma-runtime`. The skeleton:

```text
my-enrichers/
├── Cargo.toml
└── src/
    ├── lib.rs              ← public `register()` entry point
    └── passive_dns.rs      ← the enricher impl
```

`Cargo.toml`:

```toml
[package]
name = "my-enrichers"
version = "0.1.0"
edition = "2024"

[dependencies]
rsigma-runtime = "0.12"
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["sync", "time"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }
```

Step 1: implement `Enricher`. The trait surface is small: declare your `kind`, `id`, `inject_field`, optional `timeout` / `scope` / `on_error`, and an `async enrich(&self, &mut EvaluationResult)`.

```rust
// my-enrichers/src/passive_dns.rs
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rsigma_runtime::{
    EnrichError, EnrichErrorKind, Enricher, EnricherKind, OnError, Scope, inject_enrichment,
};
use rsigma_eval::EvaluationResult;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct PassiveDnsConfig {
    pub id: String,
    pub kind: String,             // "detection" | "correlation"
    pub inject_field: String,
    pub api_key_env: String,      // env var holding the API token
    pub key_field: String,        // matched-field name to read the IP from
}

pub struct PassiveDnsEnricher {
    id: String,
    kind: EnricherKind,
    inject_field: String,
    api_key: String,
    key_field: String,
    client: Arc<reqwest::Client>,
    scope: Scope,
}

impl PassiveDnsEnricher {
    pub fn new(cfg: PassiveDnsConfig) -> Result<Self, String> {
        let kind = match cfg.kind.as_str() {
            "detection" => EnricherKind::Detection,
            "correlation" => EnricherKind::Correlation,
            other => return Err(format!("unknown kind '{other}'")),
        };
        let api_key = std::env::var(&cfg.api_key_env)
            .map_err(|_| format!("env var '{}' not set", cfg.api_key_env))?;
        Ok(Self {
            id: cfg.id,
            kind,
            inject_field: cfg.inject_field,
            api_key,
            key_field: cfg.key_field,
            client: Arc::new(reqwest::Client::new()),
            scope: Scope::default(),
        })
    }
}

#[async_trait]
impl Enricher for PassiveDnsEnricher {
    fn kind(&self) -> EnricherKind { self.kind }
    fn id(&self) -> &str { &self.id }
    fn inject_field(&self) -> &str { &self.inject_field }
    fn timeout(&self) -> Duration { Duration::from_secs(5) }
    fn scope(&self) -> &Scope { &self.scope }
    fn on_error(&self) -> OnError { OnError::Skip }

    async fn enrich(&self, result: &mut EvaluationResult) -> Result<(), EnrichError> {
        // Read the IP off `matched_fields` (the same surface
        // `${detection.fields.<name>}` resolves against).
        let ip = result
            .as_detection()
            .and_then(|d| {
                d.matched_fields
                    .iter()
                    .find(|fm| fm.field == self.key_field)
                    .map(|fm| fm.value.as_str().unwrap_or("").to_string())
            })
            .filter(|s| !s.is_empty())
            .ok_or(EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch(format!(
                    "field '{}' missing on detection", self.key_field
                )),
            })?;

        let resp = self
            .client
            .get(format!("https://passive-dns.example/{ip}"))
            .header("authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| EnrichError {
                enricher_id: self.id.clone(),
                kind: if e.is_timeout() {
                    EnrichErrorKind::Timeout
                } else {
                    EnrichErrorKind::Fetch(e.to_string())
                },
            })?;
        let value: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Parse(e.to_string()),
            })?;
        inject_enrichment(result, &self.inject_field, value);
        Ok(())
    }
}
```

A few invariants the runtime guarantees, so you don't have to defend against them in `enrich()`:

- `kind()` matches `result.body`'s variant. The pipeline filters before invoking you, so `result.as_detection()` (or `as_correlation()`) is `Some` whenever `enrich` is called.
- The `Scope` filter has already passed for this result.
- The call is wrapped in `tokio::time::timeout(self.timeout(), …)`. Timeouts surface as `EnrichErrorKind::Timeout` to the pipeline, then `OnError` decides whether to skip / null / drop.
- `result.header.enrichments` is initialised lazily by `inject_enrichment`, so the `skip_serializing_if = "Option::is_none"` contract is preserved if every enricher errors.

Step 2: wire `register_builtin`. The factory takes the raw YAML config block (after `serde_json::to_value`) and returns a `Box<dyn Enricher>`. Names are checked against four reserved primitives (`template`, `lookup`, `http`, `command`); duplicate registrations of the same name are rejected to keep the global registry append-only.

```rust
// my-enrichers/src/lib.rs
mod passive_dns;
use std::sync::Arc;

pub fn register() -> Result<(), String> {
    rsigma_runtime::register_builtin(
        "enrich_ip_passive_dns_batched",
        Arc::new(|raw: &serde_json::Value| -> Result<Box<dyn rsigma_runtime::Enricher>, String> {
            let cfg: passive_dns::PassiveDnsConfig =
                serde_json::from_value(raw.clone()).map_err(|e| e.to_string())?;
            Ok(Box::new(passive_dns::PassiveDnsEnricher::new(cfg)?))
        }),
    )
}
```

Step 3: have the daemon call your `register()` before parsing the enrichers config. There are two patterns:

1. **Linker-init (`ctor`).** Fragile across release toolchains; not recommended.
2. **Explicit init in a CLI fork.** Add a new daemon binary (or a small wrapper around `cmd_daemon`) that calls `my_enrichers::register()` before `rsigma_cli::cmd_daemon(args)`. This is the supported pattern.

```rust
// my-rsigma-cli/src/main.rs
fn main() {
    my_enrichers::register().expect("register bespoke enrichers");
    rsigma::run(); // your wrapper around `rsigma`'s main entry
}
```

## YAML reference

The config block is identical to the four primitives' shape; only `type:` differs. Operators do not need to know whether a type came from the primitive set or from a `register_builtin` call.

```yaml
enrichers:
  - id: pdns_for_attackers
    kind: detection
    type: enrich_ip_passive_dns_batched
    inject_field: passive_dns
    timeout: 3s
    on_error: skip
    scope:
      tags: ["attack.command_and_control"]
    # Bespoke fields read by your factory:
    api_key_env: PASSIVEDNS_API_KEY
    key_field: SourceIp
```

The daemon's loader passes the entire block through to your factory; the factory deserializes whatever shape it needs. The `kind` field is read from the surrounding YAML, but your config struct can re-deserialize it (as in the example above) to keep the constructor self-contained.

## Test it

The unit-test pattern from `crates/rsigma-runtime/src/enrichment/tests.rs` carries over: build the enricher, drive it through `EnrichmentPipeline::new(vec![Box::new(enricher)], 1).run(&mut results).await`, assert the resulting `enrichments` map.

Mock external dependencies. For HTTP, use `wiremock`; the existing `crates/rsigma-runtime/tests/enrichment_integration.rs` is the reference style. For commands, use `/bin/sh -c "echo ..."` with deterministic output.

For the YAML-loader path, exercise `register_builtin` + an `EnrichersFile` with a `type: enrich_my_thing` entry to confirm the factory wires up cleanly. Reset the registry between tests with the test-only `clear_builtin_registry` helper if you `register_builtin` more than once across the same test binary.

## Observability

Per-call metrics are emitted automatically; no extra hook is required. The pipeline records `rsigma_enrichment_total{enricher_id, kind, status}` and `rsigma_enrichment_duration_seconds{enricher_id, kind}` for every non-filtered call; `enricher_id` is the value you set in `Enricher::id()`. The pipeline also pre-registers your label triple at construction (via `MetricsHook::register_enricher`), so your enricher's metrics appear with zero values on `/metrics` from the first scrape, before any event has fired. You don't need to call this hook yourself.

Bespoke types using a private cache or rate-limiter should emit their own counters under a `rsigma_enrichment_<name>_*` prefix to keep the namespace stable for downstream dashboards. If those counters use `IntCounterVec` with per-enricher labels, mirror the built-in pattern: pre-register the label sets at construction (the daemon's `Metrics` impl does this for the HTTP cache via `register_http_enricher_cache`) so operators see all your families on the first scrape.

## Document it

Three places to update when you ship the type:

1. **A reference page** under your crate's docs site (or a README section) documenting the YAML schema your factory consumes, the expected `enrichments.<field>` shape, rate limits, and any required env vars.
2. **The user-facing guide** in this repo's `docs/guide/enrichers.md` if the type is intended to ship as part of `rsigma-runtime` itself rather than as an external crate.
3. **A recipe-vs-bespoke note** explaining which of the four criteria above justified the bespoke path. This avoids repeated debate when the next contributor wonders why a similar feature is not also a Rust type.

## Checklist

- [ ] `Enricher` trait implemented; `kind()` / `id()` / `inject_field()` are stable across reloads.
- [ ] Constructor returns a clear `String` error on bad config (missing env var, unknown `kind`, schema mismatch).
- [ ] `register_builtin(name, factory)` called once at process startup, before the daemon parses the enrichers YAML.
- [ ] No internal locking on the hot path beyond what the pipeline already provides (the `Semaphore` bound, the per-enricher timeout).
- [ ] Unit tests in your crate; integration test that exercises the YAML loader if shipping in-tree.
- [ ] CHANGELOG entry on the crate that ships the type.

## See also

- [Enrichers](../guide/enrichers.md) — the operator-facing guide for the YAML schema, the four primitives, and the recipe catalog.
- [`rsigma-runtime`](../library/runtime.md) — the public surface (`Enricher`, `EnrichmentPipeline`, `register_builtin`).
- [Adding a dynamic source](adding-sources.md) — the analogous walkthrough for new pipeline source types.
