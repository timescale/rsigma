//! `rsigma taxii store`: import a local STIX bundle JSON file into an on-disk [`FsStore`].

use std::fs::File;
use std::io::stdin;
use std::path::{Path, PathBuf};
use std::process;

use clap::Args;
use rstix::core::StixId;
use rstix::model::{Bundle, ParseOptions};
use rstix::store::{FsStore, StixStore};
use rstix::validate::Validator;
use serde::Serialize;

use crate::exit_code;
use crate::output::{OutputCtx, Tabular, render_report};

/// Arguments for `rsigma taxii store`.
#[derive(Args, Debug)]
pub struct TaxiiStoreArgs {
    /// Local STIX bundle JSON file (`-` reads stdin).
    #[arg(long, value_name = "FILE")]
    pub bundle: PathBuf,

    /// Local [`FsStore`] root directory (created when missing).
    #[arg(long, value_name = "DIR")]
    pub store: PathBuf,

    /// STIX bundle id recorded for [`StixStore::export_bundle`].
    ///
    /// Defaults to the `id` in the bundle file when present.
    #[arg(long = "bundle-id")]
    pub bundle_id: Option<String>,

    /// Parse MITRE ATT&CK and other custom SDOs (`x_*` types).
    #[arg(long)]
    pub allow_custom: bool,

    /// Exit with code 1 when validation rejects one or more objects.
    #[arg(long, default_value_t = true)]
    pub strict: bool,

    /// Import objects even when validation fails (diagnostics still recorded).
    #[arg(long = "allow-invalid", conflicts_with = "strict")]
    pub allow_invalid: bool,
}

#[derive(Debug, Serialize)]
struct StoreReportEnvelope {
    bundle: String,
    store: String,
    bundle_id: String,
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
struct StoreMetricRow {
    metric: String,
    value: String,
}

impl StoreMetricRow {
    fn new(metric: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            metric: metric.into(),
            value: value.into(),
        }
    }
}

impl Tabular for StoreMetricRow {
    fn headers() -> &'static [&'static str] {
        &["METRIC", "VALUE"]
    }

    fn row(&self) -> Vec<String> {
        vec![self.metric.clone(), self.value.clone()]
    }
}

#[derive(Debug)]
struct ValidationRun {
    objects_validated: usize,
    objects_rejected: usize,
    failures: Vec<ValidationFailure>,
    objects_to_import: Vec<rstix::model::stix_object::StixObject>,
}

#[derive(Debug)]
struct ValidationFailure {
    object_id: StixId,
    report: rstix::validate::ValidationReport,
}

pub fn cmd_taxii_store(args: TaxiiStoreArgs, ctx: OutputCtx) {
    let parse_options = ParseOptions::default().allow_custom(args.allow_custom);
    let bundle = read_and_parse_bundle(&args.bundle, &parse_options).unwrap_or_else(|err| {
        eprintln!("failed to parse bundle {}: {err}", args.bundle.display());
        process::exit(exit_code::CONFIG_ERROR);
    });

    let wrapper_id = resolve_wrapper_id(&args.bundle_id, &bundle).unwrap_or_else(|err| {
        eprintln!("{err}");
        process::exit(exit_code::CONFIG_ERROR);
    });

    let store = open_store(&args.store, args.allow_custom);

    let validation = validate_for_import(
        &bundle,
        wrapper_id.clone(),
        args.strict && !args.allow_invalid,
    );
    let import_bundle =
        Bundle::from_objects(wrapper_id.clone(), validation.objects_to_import.clone());
    let import_report = store.import_bundle(&import_bundle).unwrap_or_else(|err| {
        eprintln!("store import failed: {err}");
        process::exit(exit_code::CONFIG_ERROR);
    });

    let envelope = StoreReportEnvelope {
        bundle: args.bundle.display().to_string(),
        store: args.store.display().to_string(),
        bundle_id: wrapper_id.to_string(),
        import: ImportSummary {
            objects_added: import_report.objects_added,
            objects_updated: import_report.objects_updated,
            objects_deduplicated: import_report.objects_deduplicated,
            fingerprint_conflicts: import_report.fingerprint_conflicts.len(),
        },
        validation: ValidationSummary {
            objects_validated: validation.objects_validated,
            objects_rejected: validation.objects_rejected,
            is_valid: validation.objects_rejected == 0,
        },
        unresolved_references: import_report.unresolved_references.len(),
    };

    let rows = vec![
        StoreMetricRow::new("bundle", args.bundle.display().to_string()),
        StoreMetricRow::new("store", args.store.display().to_string()),
        StoreMetricRow::new("bundle_id", wrapper_id.to_string()),
        StoreMetricRow::new("objects_added", import_report.objects_added.to_string()),
        StoreMetricRow::new("objects_updated", import_report.objects_updated.to_string()),
        StoreMetricRow::new(
            "objects_deduplicated",
            import_report.objects_deduplicated.to_string(),
        ),
        StoreMetricRow::new(
            "objects_validated",
            validation.objects_validated.to_string(),
        ),
        StoreMetricRow::new("objects_rejected", validation.objects_rejected.to_string()),
        StoreMetricRow::new(
            "unresolved_references",
            import_report.unresolved_references.len().to_string(),
        ),
    ];

    if ctx.show_progress() && !validation.failures.is_empty() {
        for failure in &validation.failures {
            eprintln!(
                "validation rejected {}: {} error(s)",
                failure.object_id,
                failure.report.errors().count()
            );
            for diag in failure.report.errors() {
                eprintln!("  {}: {}", diag.code, diag.message);
            }
        }
    }

    render_report(&ctx, &envelope, &rows);

    if args.strict && validation.objects_rejected > 0 {
        process::exit(exit_code::FINDINGS);
    }
}

/// Open the store with the parse options the command writes with, warning
/// about files that do not load. Exits on an unusable store directory.
pub(super) fn open_store(path: &Path, allow_custom: bool) -> FsStore {
    let store =
        FsStore::open_with_parse_options(path, ParseOptions::default().allow_custom(allow_custom))
            .unwrap_or_else(|err| {
                eprintln!("failed to open store at {}: {err}", path.display());
                process::exit(exit_code::CONFIG_ERROR);
            });
    for skipped in store.load_report().skipped {
        eprintln!(
            "warning: skipped store file {}: {}",
            skipped.path.display(),
            skipped.reason
        );
    }
    store
}

fn read_and_parse_bundle(
    path: &Path,
    options: &ParseOptions,
) -> Result<Bundle, Box<dyn std::error::Error>> {
    if path.as_os_str() == "-" {
        Ok(Bundle::parse_reader_with_options(stdin(), options)?)
    } else {
        let file = File::open(path)?;
        Ok(Bundle::parse_reader_with_options(file, options)?)
    }
}

fn resolve_wrapper_id(explicit: &Option<String>, bundle: &Bundle) -> Result<StixId, String> {
    if let Some(id) = explicit {
        return StixId::parse(id).map_err(|err| format!("invalid --bundle-id: {err}"));
    }
    Ok(bundle.id().clone())
}

fn validate_for_import(bundle: &Bundle, wrapper_id: StixId, reject_invalid: bool) -> ValidationRun {
    let validator = Validator::producer_strict();
    let mut run = ValidationRun {
        objects_validated: 0,
        objects_rejected: 0,
        failures: Vec::new(),
        objects_to_import: Vec::with_capacity(bundle.objects().len()),
    };

    for object in bundle.objects() {
        run.objects_validated += 1;
        let one_object = Bundle::from_objects(wrapper_id.clone(), vec![object.clone()]);
        let report = validator.validate_bundle(&one_object);
        if !report.is_valid() {
            run.failures.push(ValidationFailure {
                object_id: object.id().clone(),
                report,
            });
            if reject_invalid {
                run.objects_rejected += 1;
                continue;
            }
        }
        run.objects_to_import.push(object.clone());
    }

    run
}
