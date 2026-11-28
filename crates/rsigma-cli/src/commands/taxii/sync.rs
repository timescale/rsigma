//! `rsigma taxii sync`: import a TAXII collection into an on-disk [`FsStore`](rstix::store::FsStore).

use std::path::PathBuf;
use std::process;
use std::time::Duration;

use clap::Args;
use rstix::core::StixId;
use rstix::model::ParseOptions;
use rstix::taxii::{
    ApiKeyHeader, BasicAuth, BearerAuth, CapabilityPolicy, ClientCertificate,
    DEFAULT_INGEST_BUNDLE_ID, IngestError, IngestOptions, PostSubmitPolicy, PreflightPolicy,
    TaxiiClient, TaxiiClientConfig, TaxiiError, TaxiiFilter, ingest_collection_with_bundle_id,
};
use serde::Serialize;

use super::store::open_store;
use crate::exit_code;
use crate::output::{OutputCtx, Tabular, render_report};

/// Arguments for `rsigma taxii sync`.
#[derive(Args, Debug)]
pub struct TaxiiSyncArgs {
    /// TAXII server base URL (scheme + host, optional path prefix).
    #[arg(long, value_name = "URL")]
    pub server: String,

    /// TAXII API root URL. When omitted, discovery runs and the server `default` API root is used.
    #[arg(long, value_name = "URL")]
    pub api_root: Option<String>,

    /// TAXII collection id to ingest.
    #[arg(long)]
    pub collection: String,

    /// Local [`FsStore`](rstix::store::FsStore) root directory (created when missing).
    #[arg(long, value_name = "DIR")]
    pub store: PathBuf,

    /// STIX bundle id recorded for [`StixStore::export_bundle`](rstix::store::StixStore::export_bundle).
    #[arg(long = "bundle-id", default_value = DEFAULT_INGEST_BUNDLE_ID)]
    pub bundle_id: String,

    /// TAXII page size (`limit` query parameter).
    #[arg(long, default_value_t = 64)]
    pub limit: usize,

    /// Parse MITRE ATT&CK and other custom SDOs (`x_*` types).
    #[arg(long)]
    pub allow_custom: bool,

    /// Allow `http://` URLs (tests and local wiremock only).
    #[arg(long = "allow-insecure-http")]
    pub allow_insecure_http: bool,

    /// Skip TAXII preflight capability checks (wiremock / minimal test servers).
    #[arg(long = "no-preflight", hide = true)]
    pub no_preflight: bool,

    /// Skip collection capability negotiation (wiremock / minimal test servers).
    #[arg(long = "disable-capability-check", hide = true)]
    pub disable_capability_check: bool,

    /// Exit with code 1 when validation rejects one or more objects.
    #[arg(long, default_value_t = true)]
    pub strict: bool,

    /// Import objects even when validation fails (diagnostics still recorded).
    #[arg(long = "allow-invalid", conflicts_with = "strict")]
    pub allow_invalid: bool,

    /// HTTP timeout (e.g. `30s`, `5m`).
    #[arg(long, default_value = "60s")]
    pub timeout: String,

    /// Bearer token (`Authorization: Bearer …`).
    #[arg(
        long,
        env = "RSIGMA_TAXII_BEARER_TOKEN",
        hide_env_values = true,
        conflicts_with_all = ["basic_user", "api_key"]
    )]
    pub bearer_token: Option<String>,

    /// HTTP Basic username (requires `--basic-password` or `RSIGMA_TAXII_BASIC_PASSWORD`).
    #[arg(
        long,
        requires = "basic_password",
        conflicts_with_all = ["bearer_token", "api_key"]
    )]
    pub basic_user: Option<String>,

    /// HTTP Basic password (requires `--basic-user`).
    #[arg(
        long,
        env = "RSIGMA_TAXII_BASIC_PASSWORD",
        hide_env_values = true,
        requires = "basic_user"
    )]
    pub basic_password: Option<String>,

    /// API key header value.
    #[arg(
        long,
        env = "RSIGMA_TAXII_API_KEY",
        hide_env_values = true,
        conflicts_with_all = ["bearer_token", "basic_user"]
    )]
    pub api_key: Option<String>,

    /// API key header name (default `X-API-Key`).
    #[arg(long = "api-key-header", default_value = "X-API-Key")]
    pub api_key_header: String,

    /// PEM client certificate for mTLS.
    #[arg(long = "client-cert-pem", value_name = "FILE")]
    pub client_cert_pem: Option<PathBuf>,

    /// PEM client private key for mTLS.
    #[arg(long = "client-key-pem", value_name = "FILE")]
    pub client_key_pem: Option<PathBuf>,

    /// PKCS#12 / PFX client identity for mTLS.
    #[arg(long = "client-p12", value_name = "FILE")]
    pub client_p12: Option<PathBuf>,

    /// PKCS#12 decryption password.
    #[arg(
        long = "client-p12-password",
        env = "RSIGMA_TAXII_CLIENT_P12_PASSWORD",
        hide_env_values = true
    )]
    pub client_p12_password: Option<String>,
}

#[derive(Debug, Serialize)]
struct SyncReportEnvelope {
    collection: String,
    store: String,
    api_root: String,
    import: ImportSummary,
    validation: ValidationSummary,
    unresolved_references: usize,
}

#[derive(Debug, Serialize)]
struct ImportSummary {
    objects_added: usize,
    objects_updated: usize,
    objects_deduplicated: usize,
    fingerprint_conflicts: usize,
}

#[derive(Debug, Serialize)]
struct ValidationSummary {
    objects_validated: usize,
    objects_rejected: usize,
    is_valid: bool,
}

#[derive(Debug, Serialize)]
struct SyncMetricRow {
    metric: String,
    value: String,
}

impl SyncMetricRow {
    fn new(metric: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            metric: metric.into(),
            value: value.into(),
        }
    }
}

impl Tabular for SyncMetricRow {
    fn headers() -> &'static [&'static str] {
        &["METRIC", "VALUE"]
    }

    fn row(&self) -> Vec<String> {
        vec![self.metric.clone(), self.value.clone()]
    }
}

pub fn cmd_taxii_sync(args: TaxiiSyncArgs, ctx: OutputCtx) {
    if args.limit == 0 {
        eprintln!("invalid --limit: must be greater than zero");
        process::exit(exit_code::CONFIG_ERROR);
    }

    if args.basic_user.is_some() ^ args.basic_password.is_some() {
        eprintln!("--basic-user and --basic-password must be supplied together");
        process::exit(exit_code::CONFIG_ERROR);
    }

    let (cert_pem, key_pem) = match (&args.client_cert_pem, &args.client_key_pem) {
        (None, None) => (None, None),
        (Some(cert), Some(key)) => (Some(cert), Some(key)),
        _ => {
            eprintln!("--client-cert-pem and --client-key-pem must be supplied together");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    if args.client_p12.is_some() && cert_pem.is_some() {
        eprintln!("supply either PEM client credentials or --client-p12, not both");
        process::exit(exit_code::CONFIG_ERROR);
    }

    if args.client_p12.is_some() && args.client_p12_password.is_none() {
        eprintln!(
            "--client-p12 requires --client-p12-password (or RSIGMA_TAXII_CLIENT_P12_PASSWORD)"
        );
        process::exit(exit_code::CONFIG_ERROR);
    }

    let timeout = parse_timeout(&args.timeout);
    let bundle_id = StixId::parse(&args.bundle_id).unwrap_or_else(|err| {
        eprintln!("invalid --bundle-id: {err}");
        process::exit(exit_code::CONFIG_ERROR);
    });

    let mut config = TaxiiClientConfig::new(&args.server)
        .timeout(timeout)
        .allow_insecure_http(args.allow_insecure_http)
        .parse_options(ParseOptions::default().allow_custom(args.allow_custom));

    if args.no_preflight {
        config = config.preflight(PreflightPolicy::Disabled);
    }
    if args.disable_capability_check {
        config = config
            .capability(CapabilityPolicy::Disabled)
            .post_submit(PostSubmitPolicy::ReturnInitial);
    }

    if let Some(token) = args.bearer_token {
        config = config.auth(BearerAuth::new(token));
    } else if let (Some(user), Some(password)) = (args.basic_user, args.basic_password) {
        config = config.auth(BasicAuth::new(user, password));
    } else if let Some(key) = args.api_key {
        config = config.auth(ApiKeyHeader::new(args.api_key_header, key));
    }

    if let (Some(cert_path), Some(key_path)) = (cert_pem, key_pem) {
        let cert_pem = read_file(cert_path, "client certificate PEM");
        let key_pem = read_file(key_path, "client key PEM");
        let certificate = ClientCertificate::from_pem(&cert_pem, &key_pem).unwrap_or_else(|err| {
            eprintln!("invalid client certificate: {err}");
            process::exit(exit_code::CONFIG_ERROR);
        });
        config = config.client_certificate(certificate);
    } else if let Some(p12_path) = args.client_p12 {
        let der = read_file(&p12_path, "client PKCS#12");
        let password = args.client_p12_password.expect("checked above");
        let certificate = ClientCertificate::from_pkcs12_der(der, password).unwrap_or_else(|err| {
            eprintln!("invalid client PKCS#12: {err}");
            process::exit(exit_code::CONFIG_ERROR);
        });
        config = config.client_certificate(certificate);
    }

    let client = TaxiiClient::new(config).unwrap_or_else(|err| {
        eprintln!("TAXII client configuration failed: {err}");
        process::exit(exit_code::CONFIG_ERROR);
    });

    let store = open_store(&args.store, args.allow_custom);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|err| {
            eprintln!("failed to start async runtime: {err}");
            process::exit(exit_code::CONFIG_ERROR);
        });

    let report = rt.block_on(async {
        let api_root = resolve_api_root(&client, args.api_root.as_deref())
            .await
            .map_err(|err| IngestError::Taxii(*err))?;
        let mut ingest_options = IngestOptions::producer_strict();
        if args.allow_invalid {
            ingest_options = ingest_options.allow_invalid_objects();
        }
        ingest_collection_with_bundle_id(
            &client,
            &store,
            &api_root,
            &args.collection,
            TaxiiFilter::new().limit(args.limit),
            bundle_id,
            ingest_options,
        )
        .await
        .map(|report| (api_root, report))
    });

    let (api_root, report) = report.unwrap_or_else(|err| {
        eprintln!("TAXII sync failed: {err}");
        process::exit(taxii_error_exit_code(&err));
    });

    let envelope = SyncReportEnvelope {
        collection: args.collection.clone(),
        store: args.store.display().to_string(),
        api_root: api_root.clone(),
        import: ImportSummary {
            objects_added: report.import.objects_added,
            objects_updated: report.import.objects_updated,
            objects_deduplicated: report.import.objects_deduplicated,
            fingerprint_conflicts: report.import.fingerprint_conflicts.len(),
        },
        validation: ValidationSummary {
            objects_validated: report.validation.objects_validated,
            objects_rejected: report.validation.objects_rejected,
            is_valid: report.validation.is_valid(),
        },
        unresolved_references: report.import.unresolved_references.len(),
    };

    let rows = vec![
        SyncMetricRow::new("collection", &args.collection),
        SyncMetricRow::new("api_root", &api_root),
        SyncMetricRow::new("store", args.store.display().to_string()),
        SyncMetricRow::new("objects_added", report.import.objects_added.to_string()),
        SyncMetricRow::new("objects_updated", report.import.objects_updated.to_string()),
        SyncMetricRow::new(
            "objects_deduplicated",
            report.import.objects_deduplicated.to_string(),
        ),
        SyncMetricRow::new(
            "objects_validated",
            report.validation.objects_validated.to_string(),
        ),
        SyncMetricRow::new(
            "objects_rejected",
            report.validation.objects_rejected.to_string(),
        ),
        SyncMetricRow::new(
            "unresolved_references",
            report.import.unresolved_references.len().to_string(),
        ),
    ];

    if ctx.show_progress() && !report.validation.failures.is_empty() {
        for failure in &report.validation.failures {
            eprintln!(
                "validation rejected {} (page {}): {} error(s)",
                failure.object_id,
                failure.page,
                failure.report.errors().count()
            );
            for diag in failure.report.errors() {
                eprintln!("  {}: {}", diag.code, diag.message);
            }
        }
    }

    render_report(&ctx, &envelope, &rows);

    if args.strict && !report.validation.is_valid() {
        process::exit(exit_code::FINDINGS);
    }
}

async fn resolve_api_root(
    client: &TaxiiClient,
    explicit: Option<&str>,
) -> Result<String, Box<TaxiiError>> {
    if let Some(url) = explicit {
        return Ok(url.to_string());
    }
    let discovery = client.discover().await.map_err(Box::new)?;
    discovery
        .default_api_root()
        .map(str::to_string)
        .ok_or_else(|| {
            Box::new(TaxiiError::InvalidUrl(
                "discovery response has no default API root; pass --api-root".into(),
            ))
        })
}

fn read_file(path: &PathBuf, label: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|err| {
        eprintln!("failed to read {label} {}: {err}", path.display());
        process::exit(exit_code::CONFIG_ERROR);
    })
}

fn parse_timeout(value: &str) -> Duration {
    humantime::parse_duration(value).unwrap_or_else(|_| {
        eprintln!("invalid --timeout '{value}': expected a duration like 30s, 5m");
        process::exit(exit_code::CONFIG_ERROR);
    })
}

fn taxii_error_exit_code(err: &rstix::taxii::IngestError) -> i32 {
    use rstix::taxii::IngestError;
    match err {
        IngestError::Store(_) => exit_code::CONFIG_ERROR,
        IngestError::Taxii(_) => exit_code::CONFIG_ERROR,
    }
}
