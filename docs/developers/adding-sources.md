# Adding a dynamic source type

Dynamic pipeline sources (`http`, `command`, `file`, `nats`) live behind one trait: `SourceResolver`. Each `DynamicSource` carries a typed `SourceType` plus shared metadata (`id`, refresh policy, error policy, optional extract). The shipped `DefaultSourceResolver` dispatches on `SourceType`, hits the right adapter, and stores the result in a shared `Arc<SourceCache>`. This page walks through adding a new source type (S3, BigQuery, Redis, an internal HTTP endpoint with non-standard auth) and wiring it into the parser, resolver, and CLI.

## Decide on the shape

Two ways to add a new source:

1. **In-tree `SourceType` variant.** Add a variant to `SourceType` in [`crates/rsigma-eval/src/pipeline/sources.rs`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/src/pipeline/sources.rs), parse the YAML into it, and dispatch on it inside `DefaultSourceResolver::resolve`. Use this when the new type is broadly useful (S3, Kafka, JetStream KV bucket) and you want it shipped in the upstream binary.
2. **External `SourceResolver` impl.** Implement the trait in your own crate, wrap or compose with `DefaultSourceResolver`, and pass the wrapper to `RuntimeEngine::set_source_resolver`. Use this when the type is private to your deployment (an internal API with a custom auth scheme, a vendor-specific protocol you can't open-source).

Both paths feed the same `SourceCache`, so `lookup` enrichers and `${source.X}` template references work identically against either.

## Walkthrough: adding an `s3` source type (in-tree)

Step 1: extend the typed `SourceType` enum.

```text
crates/rsigma-eval/src/pipeline/sources.rs
```

```rust
pub enum SourceType {
    File   { path: PathBuf, format: DataFormat, extract: Option<ExtractExpr> },
    Command{ command: Vec<String>, format: DataFormat, extract: Option<ExtractExpr> },
    Http   { url: String, method: Option<String>, headers: HashMap<String,String>,
             format: DataFormat, extract: Option<ExtractExpr> },
    Nats   { url: String, subject: String, format: DataFormat, extract: Option<ExtractExpr> },
    S3     { bucket: String, key: String, region: Option<String>,        // ← new
             format: DataFormat, extract: Option<ExtractExpr> },
}
```

Step 2: parse the YAML. Every existing variant has a `parse_<type>_source` block in [`crates/rsigma-eval/src/pipeline/parsing.rs`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/src/pipeline/parsing.rs); copy one as a template. Keep the same field-name conventions (`format`, `extract`, `refresh`, `on_error`, `required`) so operators only learn one mental model.

```yaml
sources:
  - id: cmdb_snapshot
    type: s3
    bucket: corp-cmdb-prod
    key: snapshot.json
    region: us-east-1
    format: json
    refresh:
      interval: 600s
    on_error: use_cached
```

Step 3: write the resolver adapter.

```text
crates/rsigma-runtime/src/sources/
├── cache.rs
├── command.rs
├── extract.rs
├── file.rs
├── http.rs
├── include.rs
├── mod.rs               ← register the new module + dispatch
├── nats.rs
├── refresh.rs
├── s3.rs                ← new
└── template.rs
```

```rust
// crates/rsigma-runtime/src/sources/s3.rs
use rsigma_eval::pipeline::sources::{DataFormat, ExtractExpr};
use super::{ResolvedValue, SourceError, SourceErrorKind};

pub async fn resolve_s3(
    bucket: &str,
    key: &str,
    region: Option<&str>,
    format: DataFormat,
    extract: Option<&ExtractExpr>,
) -> Result<ResolvedValue, SourceError> {
    // 1. Build an S3 client. Reuse `aws-config` / `aws-sdk-s3`.
    let cfg = aws_config::load_from_env_with_region(region).await;
    let client = aws_sdk_s3::Client::new(&cfg);

    // 2. Hard cap: enforce the same MAX_SOURCE_RESPONSE_BYTES limit
    //    as every other source so a poisoned bucket can't OOM the daemon.
    let body = client.get_object().bucket(bucket).key(key).send().await
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(e.to_string()),
        })?;
    let bytes = body.body.collect().await
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(e.to_string()),
        })?
        .into_bytes();
    if bytes.len() > super::MAX_SOURCE_RESPONSE_BYTES {
        return Err(SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::ResourceLimit(format!(
                "S3 object exceeded {} bytes", super::MAX_SOURCE_RESPONSE_BYTES
            )),
        });
    }

    // 3. Parse + extract.
    let parsed = parse_payload(&bytes, format)?;
    let final_value = match extract {
        Some(expr) => super::extract::apply_extract(&parsed, expr)?,
        None => parsed,
    };

    Ok(ResolvedValue {
        data: final_value,
        resolved_at: std::time::Instant::now(),
        from_cache: false,
    })
}
```

Mirror the existing modules' structure: a single `pub async fn resolve_<type>(...)`, parse via the shared `extract::apply_extract` helper, return a `ResolvedValue`. Keep error mapping consistent with the `SourceErrorKind` taxonomy (`Fetch`, `Parse`, `Extract`, `Timeout`, `ResourceLimit`); the daemon's instrumented resolver buckets metrics on those labels.

Step 4: dispatch in `DefaultSourceResolver`.

```text
crates/rsigma-runtime/src/sources/mod.rs
```

```rust
// In `impl SourceResolver for DefaultSourceResolver`:
async fn resolve(&self, source: &DynamicSource) -> Result<ResolvedValue, SourceError> {
    let result = match &source.source_type {
        // ... existing arms ...
        SourceType::S3 { bucket, key, region, format, extract } => {
            s3::resolve_s3(bucket, key, region.as_deref(), *format, extract.as_ref()).await
        }
    };
    // ... existing cache.store + on_error handling ...
}
```

The `cache.store(&source.id, &value.data)` call in the success arm is shared across every `SourceType`, so your new variant gets cache write + `on_error: use_cached` / `use_default` / `fail` behaviour for free.

Step 5: feature-flag heavy dependencies. The `aws-sdk-s3` crate pulls in tokio-compat I/O, a TLS stack, and a sigv4 implementation; gate it behind a feature so the default daemon binary stays small.

```toml
# crates/rsigma-runtime/Cargo.toml
[features]
s3 = ["dep:aws-sdk-s3", "dep:aws-config"]

[dependencies]
aws-sdk-s3 = { version = "1", optional = true }
aws-config = { version = "1", optional = true }
```

```rust
// crates/rsigma-runtime/src/sources/mod.rs
#[cfg(feature = "s3")]
pub mod s3;

#[cfg(not(feature = "s3"))]
SourceType::S3 { .. } => Err(SourceError {
    source_id: source.id.clone(),
    kind: SourceErrorKind::Fetch(
        "S3 source requires the 's3' feature".into(),
    ),
}),
```

Mirror the `daemon-nats` and `daemon-otlp` propagation pattern: `crates/rsigma-cli/Cargo.toml` adds a passthrough `daemon-s3 = ["rsigma-runtime/s3", "daemon"]` so the binary opts in via one feature.

## Walkthrough: adding a custom resolver out-of-tree

When a source belongs in a private deployment, implementing `SourceResolver` in your own crate is enough; you don't have to touch `rsigma-eval` or `rsigma-runtime`.

```rust
// my-resolver/src/lib.rs
use std::sync::Arc;
use async_trait::async_trait;
use rsigma_eval::pipeline::sources::{DynamicSource, SourceType};
use rsigma_runtime::sources::{
    DefaultSourceResolver, ResolvedValue, SourceCache, SourceError, SourceErrorKind, SourceResolver,
};

pub struct CompositeResolver {
    inner: DefaultSourceResolver,
    extras: Arc<MyVendorClient>,
}

impl CompositeResolver {
    pub fn new(cache: Arc<SourceCache>, extras: Arc<MyVendorClient>) -> Self {
        Self {
            inner: DefaultSourceResolver::with_arc_cache(cache),
            extras,
        }
    }
}

#[async_trait]
impl SourceResolver for CompositeResolver {
    async fn resolve(&self, source: &DynamicSource) -> Result<ResolvedValue, SourceError> {
        // Recognise our private "vendor://..." URLs in the http variant.
        if let SourceType::Http { url, .. } = &source.source_type
            && let Some(rest) = url.strip_prefix("vendor://")
        {
            return self.extras.fetch(rest).await.map(|data| ResolvedValue {
                data,
                resolved_at: std::time::Instant::now(),
                from_cache: false,
            });
        }
        self.inner.resolve(source).await
    }
}
```

Wire it into your daemon via `RuntimeEngine::set_source_resolver(Arc::new(CompositeResolver::new(...)))`. Sharing the cache: pass the same `Arc<SourceCache>` you passed to `DefaultSourceResolver::with_arc_cache` to anything that needs to read pre-resolved data (an enrichment pipeline's `lookup` enrichers, for example).

## Test it

Three layers, mirroring the existing `crates/rsigma-runtime/tests/sources_integration.rs`:

1. **Unit test the parser** (in `crates/rsigma-eval/src/pipeline/tests.rs`). Pin the YAML → typed `SourceType::S3 { … }` mapping, cover required-field-missing errors, default values, and the `extract` plumbing.
2. **Integration test the resolver** against a stub backend. The existing `command.rs` test uses `echo`; the `http.rs` test uses `wiremock`. For S3, use `aws-smithy-http`'s test client or stand up a `LocalStack` container behind `testcontainers` (the daemon NATS tests use this pattern).
3. **End-to-end test in the daemon** (under `crates/rsigma-cli/tests/`). Spawn `rsigma engine daemon` with a pipeline that declares your source, send a triggering event, assert the resulting NDJSON line carries the resolved value (via `${source.X}` template expansion) or a `lookup` enricher hit. The existing `cli_daemon_enrichment.rs` is the reference shape.

## Observability

Three things land automatically when you go through `DefaultSourceResolver::resolve` (the daemon wraps it in `InstrumentedResolver`):

| Metric | Where it bumps |
|---|---|
| `rsigma_source_resolves_total{source_id, source_type}` | Per `resolve()` call. Set `source_type_label(...)` to `"s3"` so dashboards group correctly. |
| `rsigma_source_resolve_errors_total{source_id, error_kind}` | On every `Err` return. `error_kind` is the `SourceErrorKind` variant. |
| `rsigma_source_resolve_seconds` | Histogram, observed regardless of outcome. |

Add the new label value (`"s3"`) to the daemon's `source_type_label` helper in [`crates/rsigma-cli/src/daemon/instrumented_resolver.rs`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-cli/src/daemon/instrumented_resolver.rs). Existing alerts (`RsigmaSourceStale`, `RsigmaBackPressure`) cover the new type without rule changes.

## Document it

1. **Reference page** under [`docs/reference/dynamic-sources.md`](../reference/dynamic-sources.md): YAML schema for the new type, dependency on any feature flag, behaviour of `format`/`extract`/`refresh`/`on_error`, security notes (size cap, timeout, secret handling).
2. **Guide page**: extend [`docs/guide/processing-pipelines.md`](../guide/processing-pipelines.md) with a one-paragraph example that uses the new type.
3. **CHANGELOG** entry under the next release.

## Security checklist

Source resolution touches the network and the filesystem; before merging:

- [ ] The 10 MB `MAX_SOURCE_RESPONSE_BYTES` cap is enforced on the response body.
- [ ] A timeout is enforced on the fetch call (`tokio::time::timeout` or the underlying client's `request_timeout`).
- [ ] Secrets (tokens, signing keys) come from env vars or `${ENV_VAR}` template expansion, not from inline YAML.
- [ ] The new type is opt-in via a Cargo feature if it adds heavy or transitive deps.
- [ ] Path-traversal / SSRF surfaces are bounded (file paths sandboxed if applicable, URL allow-list flag if the type is exposed remotely).

## Checklist

- [ ] `SourceType` variant added in `crates/rsigma-eval/src/pipeline/sources.rs`.
- [ ] Parser block added in `crates/rsigma-eval/src/pipeline/parsing.rs` with required-field validation.
- [ ] Resolver module added under `crates/rsigma-runtime/src/sources/<name>.rs`.
- [ ] Dispatch arm added to `DefaultSourceResolver::resolve`.
- [ ] Feature flag in `rsigma-runtime` and pass-through in `rsigma-cli` if heavy deps.
- [ ] `source_type_label` extended in `instrumented_resolver.rs` so metrics label correctly.
- [ ] Unit + integration + E2E tests in the layers above.
- [ ] Reference + guide docs updated.
- [ ] Security checklist signed off.
- [ ] CHANGELOG entry.

## See also

- [Dynamic Pipeline Sources](../reference/dynamic-sources.md) — operator-facing reference for every shipped source type.
- [`rsigma-runtime`](../library/runtime.md) — the `SourceResolver` trait and `DefaultSourceResolver`.
- [Adding an enricher](adding-enrichers.md) — the analogous walkthrough for bespoke enrichers, which read from the same `SourceCache` via the `lookup` primitive.
