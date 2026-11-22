//! Post-engine alert-processing layer.
//!
//! An optional stage in the daemon sink path, between post-evaluation
//! enrichment and the sinks, modeled on the Alertmanager processing pipeline.
//! It currently runs two stages: fingerprint deduplication (`active ->
//! resolved` lifecycle) and incident grouping (`group_by` equality or an
//! opt-in `entity_graph` union-find). It is the home for the silencing and
//! inhibition stages as they land.
//!
//! The layer is strictly post-engine: it consumes [`EvaluationResult`]s and
//! emits [`EvaluationResult`]s plus [`IncidentResult`]s, so the evaluation hot
//! path is untouched. The immutable, validated config ([`AlertPipeline`]) is
//! built from a YAML file and swapped atomically on hot-reload; the mutable
//! [`DedupStore`] and [`IncidentStore`] are owned by the sink task (the
//! incident store behind an `RwLock` so the admin API can read open incidents).
//!
//! An optional [`CaptureSink`](crate::capture::CaptureSink) can observe
//! detections after inhibition/silencing and before dedup. When the sink is
//! absent, process output is unchanged.

mod config;
mod dedup;
mod grouping;
mod inhibit;
mod matcher;
mod silence;
mod snapshot;
mod state;

pub use crate::selector::{Selector, SelectorParseError};
pub use config::{
    AlertPipelineConfigError, AlertPipelineFile, CapsFile, DEFAULT_MAX_DYNAMIC_SILENCES, DedupFile,
    GroupFile, GroupModeLabel, IncludeLabel, ScopeConfig, build_alert_pipeline,
    load_alert_pipeline_file, parse_alert_pipeline_config,
};
pub use dedup::DedupStore;
pub use grouping::{
    Caps, GroupMode, IncidentRef, IncidentResult, IncidentStore, IncludeMode, SampleMode,
    group_fingerprint,
};
pub use matcher::{MatchOp, Matcher, MatcherError, MatcherSet, MatcherSpec};
pub use silence::{
    DEFAULT_MAX_SILENCE_DURATION, Silence, SilenceError, SilenceLimits, SilenceOrigin,
    SilenceRejection, SilenceRemoval, SilenceSpec, SilenceState, SilenceStore, SilenceView,
};
pub use snapshot::{AlertPipelineSnapshot, SNAPSHOT_VERSION};
pub use state::AlertPipelineState;

use rsigma_eval::{EvaluationResult, ProcessResult};
use serde_json::Value;

use crate::{MetricsHook, Scope};

use dedup::DedupConfig;
use grouping::{GroupConfig, OvermergeGuard};
use inhibit::InhibitConfig;
use silence::Silence as StaticSilence;

/// Output of [`AlertPipeline::tick`]: dedup summary records (re-emit /
/// resolved) and incident emissions.
#[derive(Debug, Default)]
pub struct TickOutput {
    /// Dedup `repeat` / `resolved` summary lines (serialized results with
    /// `dedup_*` keys), dispatched as raw NDJSON.
    pub dedup_lines: Vec<Value>,
    /// Incident emissions, dispatched via the incident path.
    pub incidents: Vec<IncidentResult>,
    /// Detection Finding uids index-aligned with [`Self::incidents`].
    /// Absent from the incident NDJSON.
    pub finding_links: Vec<crate::FindingLinks>,
}

/// A validated, runnable alert-processing pipeline.
///
/// Immutable after construction and cheap to clone behind an `Arc`, so it can
/// be swapped atomically on hot-reload while the sink task keeps a live
/// snapshot for the duration of a batch.
#[derive(Debug)]
pub struct AlertPipeline {
    scope: Scope,
    strip_event: bool,
    dedup: Option<DedupConfig>,
    group: Option<GroupConfig>,
    static_silences: Vec<StaticSilence>,
    inhibit: Option<InhibitConfig>,
    max_silences: usize,
    silence_limits: SilenceLimits,
    tenant_quotas: AlertTenantQuotas,
}

/// Per-tenant caps on alert-pipeline state. `None` leaves only the global cap
/// in force.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AlertTenantQuotas {
    /// Active dedup alerts per tenant; the stalest are evicted at the cap.
    pub active_alerts: Option<usize>,
    /// Open incidents per tenant; the stalest are evicted at the cap.
    pub incidents: Option<usize>,
    /// Dynamic (API) silences per tenant; creation is refused at the cap.
    pub silences: Option<usize>,
    /// Inhibition sources per tenant; new sources are refused at the cap.
    pub inhibition_sources: Option<usize>,
}

impl AlertPipeline {
    /// Construct from validated parts. Prefer [`build_alert_pipeline`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        scope: Scope,
        strip_event: bool,
        dedup: Option<DedupConfig>,
        group: Option<GroupConfig>,
        static_silences: Vec<StaticSilence>,
        inhibit: Option<InhibitConfig>,
        max_silences: usize,
        silence_limits: SilenceLimits,
    ) -> Self {
        AlertPipeline {
            scope,
            strip_event,
            dedup,
            group,
            static_silences,
            inhibit,
            max_silences,
            silence_limits,
            tenant_quotas: AlertTenantQuotas::default(),
        }
    }

    /// Set the per-tenant caps.
    pub fn set_tenant_quotas(&mut self, quotas: AlertTenantQuotas) {
        self.tenant_quotas = quotas;
    }

    /// Ceiling on dynamic (API) silences per tenant, when set.
    pub fn max_dynamic_silences_per_tenant(&self) -> Option<usize> {
        self.tenant_quotas.silences
    }

    /// The bounds the silence API applies to new silences
    /// (`max_silence_duration`, `allow_broad_silences`).
    pub fn silence_limits(&self) -> SilenceLimits {
        self.silence_limits
    }

    /// The static silences declared in the config, for (re-)seeding the store.
    pub fn static_silences(&self) -> &[StaticSilence] {
        &self.static_silences
    }

    /// Ceiling on concurrently-tracked dynamic (API) silences. The silence API
    /// rejects creation past this many.
    pub fn max_dynamic_silences(&self) -> usize {
        self.max_silences
    }

    /// The configured incident include mode, if grouping is enabled.
    pub fn incident_include(&self) -> Option<IncludeMode> {
        self.group.as_ref().map(|g| g.include)
    }

    /// The configured incident NATS subject override, if any.
    pub fn incident_nats_subject(&self) -> Option<&str> {
        self.group.as_ref().and_then(|g| g.nats_subject.as_deref())
    }

    /// The configured grouping mode, if grouping is enabled.
    pub fn group_mode(&self) -> Option<GroupMode> {
        self.group.as_ref().map(|g| g.mode)
    }

    /// The `group.by` selectors when grouping is `group_by`.
    pub fn group_by_selectors(&self) -> Option<&[Selector]> {
        self.group
            .as_ref()
            .and_then(|g| (g.mode == GroupMode::GroupBy).then_some(g.by.as_slice()))
    }

    /// The dedup fingerprint selectors, if dedup is enabled.
    pub fn dedup_selectors(&self) -> Option<&[Selector]> {
        self.dedup.as_ref().map(|d| d.fingerprint.as_slice())
    }

    /// Ceiling on concurrently-open incidents, if grouping is enabled.
    pub fn max_open_incidents(&self) -> Option<usize> {
        self.group.as_ref().map(|g| g.caps.max_open_incidents)
    }

    /// Why this pipeline cannot host capture, or `None` when it can.
    ///
    /// Capture requires `group.mode: group_by`. When dedup is also configured,
    /// every `group.by` selector must appear in `dedup.fingerprint` so a folded
    /// alert cannot span incident identities.
    pub fn capture_incompatibility(&self) -> Option<crate::capture::CaptureIncompatibility> {
        use crate::capture::CaptureIncompatibility;
        match &self.group {
            None => Some(CaptureIncompatibility::MissingGroupBy),
            Some(g) if g.mode == GroupMode::EntityGraph => {
                Some(CaptureIncompatibility::EntityGraph)
            }
            Some(g) => {
                if let Some(d) = &self.dedup {
                    let missing: Vec<String> =
                        g.by.iter()
                            .filter(|sel| !d.fingerprint.contains(*sel))
                            .map(Selector::as_str)
                            .collect();
                    if !missing.is_empty() {
                        return Some(CaptureIncompatibility::DedupSelectorsMissing(missing));
                    }
                }
                None
            }
        }
    }

    /// Process the results produced from one input event: dedup folds
    /// duplicates into `dedup_store`, grouping assigns survivors to incidents
    /// in `incident_store` and annotates them with `incident_id`. Out-of-scope
    /// results pass through untouched.
    pub fn process(
        &self,
        results: ProcessResult,
        state: &mut AlertPipelineState,
        now: i64,
        metrics: &dyn MetricsHook,
    ) -> ProcessResult {
        self.process_with_capture(results, state, now, metrics, None)
    }

    /// [`Self::process`] plus an optional capture sink that observes detections
    /// after inhibition/silencing and before dedup. Process output is unchanged
    /// relative to [`Self::process`] regardless of whether a sink is attached.
    pub fn process_with_capture(
        &self,
        results: ProcessResult,
        state: &mut AlertPipelineState,
        now: i64,
        metrics: &dyn MetricsHook,
        capture: Option<&mut dyn crate::capture::CaptureSink>,
    ) -> ProcessResult {
        self.process_inner(results, None, state, now, metrics, capture)
            .0
    }

    /// [`Self::process_with_capture`] carrying each result's OCSF finding uid.
    ///
    /// `finding_uids` is index-aligned with `results`. The uid of every result
    /// that joins an incident is recorded on its retained sample, so an
    /// Incident Finding can reference the Detection Finding emitted for it.
    /// Returns the kept results and their uids, still index-aligned.
    pub fn process_with_finding_uids(
        &self,
        results: ProcessResult,
        finding_uids: Vec<String>,
        state: &mut AlertPipelineState,
        now: i64,
        metrics: &dyn MetricsHook,
        capture: Option<&mut dyn crate::capture::CaptureSink>,
    ) -> (ProcessResult, Vec<String>) {
        let (kept, uids) =
            self.process_inner(results, Some(finding_uids), state, now, metrics, capture);
        (kept, uids.unwrap_or_default())
    }

    fn process_inner(
        &self,
        results: ProcessResult,
        finding_uids: Option<Vec<String>>,
        state: &mut AlertPipelineState,
        now: i64,
        metrics: &dyn MetricsHook,
        mut capture: Option<&mut dyn crate::capture::CaptureSink>,
    ) -> (ProcessResult, Option<Vec<String>>) {
        let start = std::time::Instant::now();
        let mut kept = Vec::with_capacity(results.len());
        let mut kept_uids = finding_uids
            .as_ref()
            .map(|_| Vec::with_capacity(results.len()));
        let mut uids = finding_uids.map(Vec::into_iter);
        let mut pending = Vec::new();
        let capturing = capture.is_some();
        let capture_ok = capturing && self.capture_incompatibility().is_none();

        for mut result in results {
            let finding_uid = uids.as_mut().and_then(Iterator::next);
            let mut keep = |result: EvaluationResult, finding_uid: Option<String>| {
                kept.push(result);
                if let Some(kept_uids) = kept_uids.as_mut() {
                    kept_uids.push(finding_uid.unwrap_or_default());
                }
            };
            if !self.scope.matches(&result) {
                keep(result, finding_uid);
                continue;
            }

            // Inhibition: an inhibited target is dropped before it can become a
            // source. `evaluate` also records non-inhibited results (including
            // ones about to be silenced) as active sources, so a silenced
            // source still inhibits its targets.
            if let Some(icfg) = self.inhibit.as_ref()
                && let Some(rule) = state.inhibit.evaluate(
                    icfg,
                    &result,
                    now,
                    self.tenant_quotas.inhibition_sources,
                    |rule| {
                        metrics.on_inhibit_source_refused(rule);
                    },
                )
            {
                metrics.on_alert_pipeline_inhibited(&rule);
                continue;
            }

            // Silencing: an active silence mutes the result before dedup, so a
            // silenced result neither emits nor opens an incident.
            if state.silences.active_match(&result, now).is_some() {
                metrics.on_alert_pipeline_silenced();
                continue;
            }

            if capturing {
                self.offer_capture(&result, &state.incidents, capture_ok, &mut pending);
            }

            // Dedup: fold duplicates into the active alert. When the store is at
            // its cap, a first-fire for a new fingerprint passes through
            // un-deduped rather than opening another alert, bounding memory; the
            // store-entries gauge plateauing at the cap signals saturation.
            if let Some(cfg) = self.dedup.as_ref() {
                let fingerprint = dedup::fingerprint(&cfg.fingerprint, &result);
                if state.dedup.contains(&fingerprint) {
                    state.dedup.fold(&fingerprint, now);
                    metrics.on_alert_pipeline_result("folded");
                    continue;
                }
                if state.dedup.len() < cfg.max_active_alerts {
                    if let Some(cap) = self.tenant_quotas.active_alerts
                        && state
                            .dedup
                            .count_for_tenant(result.header.tenant_id.as_ref())
                            >= cap
                        && state
                            .dedup
                            .evict_tenant_oldest(result.header.tenant_id.as_ref())
                    {
                        metrics.on_tenant_quota_eviction("active_alerts");
                    }
                    let fields = dedup::resolve_fields(&cfg.fingerprint, &result);
                    let sample = dedup::sample_of(&result);
                    state.dedup.insert(
                        fingerprint,
                        now,
                        sample,
                        fields,
                        result.header.tenant_id.clone(),
                    );
                }
                metrics.on_alert_pipeline_result("emitted");
            }

            // Grouping: assign the survivor to an incident, reading entity /
            // group-by selectors off the result while the event is still
            // present, then annotate it with the incident id.
            if let Some(gcfg) = self.group.as_ref() {
                let tenant_cap = grouping::TenantCap {
                    max: self.tenant_quotas.incidents,
                    on_evict: || metrics.on_tenant_quota_eviction("incidents"),
                };
                if let Some(id) = state.incidents.assign_with_finding_uid(
                    gcfg,
                    &result,
                    finding_uid.as_deref().filter(|uid| !uid.is_empty()),
                    now,
                    |guard| {
                        metrics.on_alert_pipeline_overmerge(guard_label(guard));
                    },
                    tenant_cap,
                ) {
                    if self.strip_event {
                        strip_event_payloads(&mut result);
                    }
                    annotate_incident(&mut result, id);
                    keep(result, finding_uid);
                    continue;
                }
            }

            if self.strip_event {
                strip_event_payloads(&mut result);
            }
            keep(result, finding_uid);
        }

        if let Some(sink) = capture.as_mut() {
            crate::capture::flush_pending(pending, *sink, now);
        }

        if self.dedup.is_some() {
            metrics.set_alert_pipeline_store_entries(state.dedup.len() as i64);
        }
        if self.group.is_some() {
            metrics.set_incidents_open(state.incidents.len() as i64);
        }
        metrics.observe_alert_pipeline_duration(start.elapsed().as_secs_f64());
        (kept, kept_uids)
    }

    fn offer_capture(
        &self,
        result: &EvaluationResult,
        incidents: &IncidentStore,
        capture_ok: bool,
        pending: &mut Vec<crate::capture::PendingCapture>,
    ) {
        use crate::capture::{AdmittedMatch, CaptureReject, PendingAdmit, PendingCapture};

        if !result.is_detection() {
            pending.push(PendingCapture::Reject(CaptureReject::UnsupportedResultKind));
            return;
        }
        if !capture_ok {
            return;
        }
        let Some(event) = result.as_detection().and_then(|d| d.event.clone()) else {
            pending.push(PendingCapture::Reject(CaptureReject::MissingEvent));
            return;
        };
        let Some(gcfg) = self.group.as_ref() else {
            return;
        };
        let (incident_id, _) = grouping::group_fingerprint(&gcfg.by, result);
        if !incidents.can_assign(&incident_id, gcfg.caps.max_open_incidents) {
            pending.push(PendingCapture::Reject(CaptureReject::NotAssignable));
            return;
        }
        let fingerprint = self
            .dedup
            .as_ref()
            .map(|cfg| dedup::fingerprint(&cfg.fingerprint, result));
        let rule_id = result
            .header
            .rule_id
            .clone()
            .unwrap_or_else(|| result.header.rule_title.clone());
        pending.push(PendingCapture::Admit(PendingAdmit {
            is_fresh_generation: !incidents.contains(&incident_id),
            incident_id,
            tenant: result.header.tenant_id.clone(),
            event,
            match_: AdmittedMatch {
                rule_id,
                rule_title: result.header.rule_title.clone(),
                fingerprint,
            },
        }));
    }

    /// Advance time: emit due dedup `repeat` / `resolved` records and incident
    /// emissions (`group_wait` / `group_interval` / `repeat` / `resolved`).
    pub fn tick(
        &self,
        state: &mut AlertPipelineState,
        now: i64,
        metrics: &dyn MetricsHook,
    ) -> TickOutput {
        let start = std::time::Instant::now();
        let mut out = TickOutput::default();

        if let Some(cfg) = self.dedup.as_ref() {
            for record in state.dedup.tick(cfg, now) {
                metrics.on_alert_pipeline_result(record.state);
                metrics.on_alert_pipeline_summary_emitted();
                if record.state == "resolved" {
                    metrics.on_alert_pipeline_eviction();
                }
                out.dedup_lines.push(record.json);
            }
            metrics.set_alert_pipeline_store_entries(state.dedup.len() as i64);
        }

        if let Some(gcfg) = self.group.as_ref() {
            for emission in state.incidents.tick(gcfg, now) {
                metrics.on_incident_emitted(emission.trigger);
                out.incidents.push(emission.result);
                out.finding_links.push(emission.links);
            }
            metrics.set_incidents_open(state.incidents.len() as i64);
        }

        // Garbage-collect expired silences and refresh the active gauge.
        state.silences.gc(now);
        metrics.set_silences_active(state.silences.active_count(now) as i64);

        // Garbage-collect stale inhibition sources and refresh the gauge.
        if let Some(icfg) = self.inhibit.as_ref() {
            state.inhibit.gc(icfg, now);
            metrics.set_inhibit_sources_active(state.inhibit.active_count(icfg, now) as i64);
        }

        if !out.dedup_lines.is_empty() || !out.incidents.is_empty() {
            metrics.observe_alert_pipeline_duration(start.elapsed().as_secs_f64());
        }
        out
    }

    /// Capture the mutable state into a versioned persistence snapshot.
    pub fn snapshot(&self, state: &AlertPipelineState) -> AlertPipelineSnapshot {
        AlertPipelineSnapshot {
            version: SNAPSHOT_VERSION,
            dedup: state.dedup.snapshot(),
            incidents: state.incidents.export(),
            silences: state.silences.api_snapshot(),
            inhibit_sources: state.inhibit.snapshot(),
        }
    }

    /// Restore a snapshot into `state`, pruning entries past their window at
    /// `now`. Returns `false` on a version mismatch (caller starts fresh).
    pub fn restore(
        &self,
        state: &mut AlertPipelineState,
        snap: AlertPipelineSnapshot,
        now: i64,
        tenancy: bool,
    ) -> bool {
        self.restore_detailed(state, snap, now, tenancy).is_some()
    }

    /// Like [`restore`](Self::restore), returning the restored and discarded
    /// counts. Accepts versions 1 and 2 and applies the tenant attribution rule
    /// to every store: with `tenancy`, untenanted entries are discarded; without
    /// it, tenanted ones are.
    pub fn restore_detailed(
        &self,
        state: &mut AlertPipelineState,
        snap: AlertPipelineSnapshot,
        now: i64,
        tenancy: bool,
    ) -> Option<rsigma_eval::ImportStats> {
        if !matches!(snap.version, 1 | 2) {
            return None;
        }
        let mut stats = rsigma_eval::ImportStats::default();
        let keep = |tenant: Option<&rsigma_eval::TenantId>| {
            if tenancy {
                tenant.is_some()
            } else {
                tenant.is_none()
            }
        };
        let mut count = |tenant: Option<&rsigma_eval::TenantId>| {
            if !keep(tenant) {
                if tenant.is_none() {
                    stats.discarded_untenanted += 1;
                } else {
                    stats.discarded_tenanted += 1;
                }
            }
        };

        // Silences are independent of the configured stages.
        let silences: Vec<_> = snap
            .silences
            .into_iter()
            .filter(|s| {
                count(s.tenant.as_ref());
                keep(s.tenant.as_ref())
            })
            .collect();
        state.silences.restore_api(silences, now);
        self.warn_over_limit_silences(state, now, "restore");

        let dedup: Vec<_> = snap
            .dedup
            .into_iter()
            .filter(|(_, alert)| {
                count(alert.tenant.as_ref());
                keep(alert.tenant.as_ref())
            })
            .collect();
        let incidents: Vec<_> = snap
            .incidents
            .into_iter()
            .filter(|inc| {
                count(inc.tenant.as_ref());
                keep(inc.tenant.as_ref())
            })
            .collect();
        let inhibit_sources: Vec<_> = snap
            .inhibit_sources
            .into_iter()
            .filter(|source| {
                count(source.tenant.as_ref());
                keep(source.tenant.as_ref())
            })
            .collect();

        // Count what lands in the stores after age pruning and every cap.
        let before = (
            state.dedup.len(),
            state.incidents.len(),
            state.inhibit.snapshot().len(),
        );
        let mut trim = CapTrim::default();
        if let Some(cfg) = self.dedup.as_ref() {
            state
                .dedup
                .restore(dedup, now, cfg.resolve_timeout.as_secs() as i64);
            trim.dedup_alerts = state.dedup.enforce_cap(cfg.max_active_alerts);
        }
        if let Some(g) = self.group.as_ref() {
            trim.incidents = state.incidents.restore(
                incidents,
                now,
                g.resolve_timeout.as_secs() as i64,
                &g.caps,
            );
        }
        if let Some(icfg) = self.inhibit.as_ref() {
            state.inhibit.restore(inhibit_sources, icfg, now);
            trim.inhibit_sources = state.inhibit.enforce_cap(icfg.max_sources);
        }
        self.trim_tenants(state, &mut trim);
        stats.restored += state.dedup.len().saturating_sub(before.0)
            + state.incidents.len().saturating_sub(before.1)
            + state.inhibit.snapshot().len().saturating_sub(before.2);
        trim.log("restore");
        Some(stats)
    }

    /// Trim carried-over state to this pipeline's caps: the least recently
    /// seen dedup alerts beyond `max_active_alerts`, incidents beyond
    /// `max_open_incidents`, and inhibition sources beyond
    /// `max_inhibit_sources` are evicted (alerts and incidents without a
    /// `resolved` record), each tenant is cut to its quotas, and each incident
    /// is cut to the per-incident caps. Call it when this pipeline
    /// replaces another on hot-reload, while holding the state lock the
    /// pipeline processes under, so a lowered cap applies at once.
    /// [`restore`](Self::restore) applies the same trim.
    pub fn enforce_caps(&self, state: &mut AlertPipelineState) -> CapTrim {
        let mut trim = CapTrim::default();
        if let Some(cfg) = self.dedup.as_ref() {
            trim.dedup_alerts = state.dedup.enforce_cap(cfg.max_active_alerts);
        }
        if let Some(g) = self.group.as_ref() {
            trim.incidents = state.incidents.enforce_caps(&g.caps);
        }
        if let Some(icfg) = self.inhibit.as_ref() {
            trim.inhibit_sources = state.inhibit.enforce_cap(icfg.max_sources);
        }
        self.trim_tenants(state, &mut trim);
        trim.log("reload");
        self.warn_over_limit_silences(state, chrono::Utc::now().timestamp(), "reload");
        trim
    }

    /// Trim each tenant's dedup alerts, incidents, and inhibition sources to
    /// the per-tenant quotas.
    fn trim_tenants(&self, state: &mut AlertPipelineState, trim: &mut CapTrim) {
        if self.dedup.is_some()
            && let Some(max) = self.tenant_quotas.active_alerts
        {
            trim.dedup_alerts += state.dedup.enforce_tenant_cap(max);
        }
        if self.group.is_some()
            && let Some(max) = self.tenant_quotas.incidents
        {
            trim.incidents += state.incidents.enforce_tenant_cap(max);
        }
        if self.inhibit.is_some()
            && let Some(max) = self.tenant_quotas.inhibition_sources
        {
            trim.inhibit_sources += state.inhibit.enforce_tenant_cap(max);
        }
    }

    /// Log the API silences the current limits would refuse. They stay in
    /// effect until they expire or are deleted, so an operator can review
    /// silences created before the limits applied.
    fn warn_over_limit_silences(&self, state: &AlertPipelineState, now: i64, context: &str) {
        let ids = state.silences.api_over_limits(&self.silence_limits, now);
        if !ids.is_empty() {
            tracing::warn!(
                context,
                count = ids.len(),
                ids = %ids.join(","),
                "API silences exceed max_silence_duration or allow_broad_silences; they stay \
                 active until they expire or are deleted with DELETE /api/v1/silences/{{id}}"
            );
        }
    }
}

/// What [`AlertPipeline::enforce_caps`] evicted.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CapTrim {
    /// Dedup active alerts evicted by `max_active_alerts` or the per-tenant
    /// active-alert quota.
    pub dedup_alerts: usize,
    /// Incidents evicted by `max_open_incidents` or the per-tenant incident
    /// quota.
    pub incidents: usize,
    /// Inhibition sources evicted by `max_inhibit_sources` or the per-tenant
    /// inhibition-source quota.
    pub inhibit_sources: usize,
}

impl CapTrim {
    fn log(&self, context: &str) {
        if self.dedup_alerts > 0 || self.incidents > 0 || self.inhibit_sources > 0 {
            tracing::warn!(
                context,
                dedup_alerts = self.dedup_alerts,
                incidents = self.incidents,
                inhibit_sources = self.inhibit_sources,
                "Evicted the least recently seen alert-pipeline state to fit the configured caps"
            );
        }
    }
}

/// Inject the reserved `incident_id` key into a result's enrichments. The layer
/// wins on a collision with a user enricher.
fn annotate_incident(result: &mut EvaluationResult, id: String) {
    let map = result
        .header
        .enrichments
        .get_or_insert_with(serde_json::Map::new);
    if map.contains_key("incident_id") {
        // Debug, not warn: an upstream enricher setting `incident_id` on every
        // result would otherwise emit one log line per result.
        tracing::debug!("alert pipeline: overwriting a user-set `incident_id` enrichment key");
    }
    map.insert("incident_id".to_string(), Value::String(id));
}

/// Metric label for an entity-graph guard hit.
fn guard_label(guard: OvermergeGuard) -> &'static str {
    match guard {
        OvermergeGuard::StopValue => "stop_value",
        OvermergeGuard::CardinalityCeiling => "cardinality_ceiling",
    }
}

/// Remove raw event payloads from a result. Used for the long-lived dedup
/// sample and, when `strip_event` is set, for pass-through results, so the
/// layer can fingerprint and group on `event.*` without emitting full events.
pub fn strip_event_payloads(result: &mut EvaluationResult) {
    if let Some(detection) = result.as_detection_mut() {
        detection.event = None;
    }
    if let Some(correlation) = result.as_correlation_mut() {
        correlation.events = None;
        correlation.event_refs = None;
        correlation.event_sources = None;
    }
}

/// Remove a detection event that the engine retained for enrichment but
/// nobody asked to deliver.
///
/// Clears [`DetectionBody::event`](rsigma_eval::DetectionBody::event) unless
/// the rule set `rsigma.include_event` to the string `"true"`, the same test
/// the rule compiler applies. Correlation payloads (`events`, `event_refs`,
/// `event_sources`) come from the correlation config and are never touched.
///
/// Callers that turn on engine-wide retention only because
/// [`EnrichmentPipeline::needs_event`](crate::EnrichmentPipeline::needs_event)
/// asked for it call this after the enrichment pipeline runs.
pub fn strip_auto_retained_event(result: &mut EvaluationResult) {
    let rule_asked = result
        .header
        .custom_attributes
        .get("rsigma.include_event")
        .and_then(Value::as_str)
        == Some("true");
    if rule_asked {
        return;
    }
    if let Some(detection) = result.as_detection_mut() {
        detection.event = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoopMetrics;
    use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
    use rsigma_parser::Level;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn pipeline(yaml: &str) -> AlertPipeline {
        let file: AlertPipelineFile = yaml_serde::from_str(yaml).unwrap();
        build_alert_pipeline(file).unwrap()
    }

    fn detection(ip: &str, level: Level) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "Brute force".to_string(),
                rule_id: Some("rule-1".to_string()),
                tenant_id: None,
                level: Some(level),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!(ip))],
                event: Some(serde_json::json!({"raw": "event"})),
            }),
        }
    }

    fn run(
        p: &AlertPipeline,
        ip: &str,
        level: Level,
        state: &mut AlertPipelineState,
        now: i64,
    ) -> ProcessResult {
        p.process(vec![detection(ip, level)], state, now, &NoopMetrics)
    }

    #[test]
    fn dedup_emits_first_fire_and_folds_duplicates() {
        let p = pipeline("dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\n");
        let mut st = AlertPipelineState::default();

        let first = run(&p, "10.0.0.1", Level::High, &mut st, 0);
        assert_eq!(first.len(), 1);
        let dup = run(&p, "10.0.0.1", Level::High, &mut st, 5);
        assert!(dup.is_empty());
    }

    #[test]
    fn kept_finding_uids_stay_aligned_when_results_fold_away() {
        let p = pipeline(
            "dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  group_wait: 0s\n",
        );
        let mut st = AlertPipelineState::default();
        let (kept, uids) = p.process_with_finding_uids(
            vec![
                detection("10.0.0.1", Level::High),
                detection("10.0.0.1", Level::High),
                detection("10.0.0.2", Level::High),
            ],
            vec!["uid-0".into(), "uid-1".into(), "uid-2".into()],
            &mut st,
            0,
            &NoopMetrics,
            None,
        );
        assert_eq!(kept.len(), 2, "the duplicate folds");
        assert_eq!(uids, ["uid-0", "uid-2"]);

        let out = p.tick(&mut st, 0, &NoopMetrics);
        let mut linked: Vec<String> = out
            .finding_links
            .iter()
            .flat_map(|links| links.refs.iter().filter_map(|uid| uid.clone()))
            .collect();
        linked.sort();
        assert_eq!(linked, ["uid-0", "uid-2"]);
        let wire = serde_json::to_string(&out.incidents).unwrap();
        assert!(!wire.contains("uid-"), "{wire}");
    }

    #[test]
    fn out_of_scope_results_bypass_the_layer() {
        let p = pipeline("scope:\n  levels: [critical]\ndedup:\n  fingerprint: [match.SourceIp]\n");
        let mut st = AlertPipelineState::default();
        let a = run(&p, "10.0.0.1", Level::High, &mut st, 0);
        let b = run(&p, "10.0.0.1", Level::High, &mut st, 1);
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert!(st.dedup.is_empty());
    }

    #[test]
    fn grouping_annotates_incident_id_and_opens_on_group_wait() {
        let p =
            pipeline("group:\n  by: [match.SourceIp]\n  group_wait: 30s\n  resolve_timeout: 1h\n");
        let mut st = AlertPipelineState::default();
        let kept = run(&p, "10.0.0.1", Level::High, &mut st, 0);
        assert_eq!(kept.len(), 1);
        let id = kept[0].header.enrichments.as_ref().unwrap()["incident_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!id.is_empty());

        // No incident emission before group_wait; one open emission after.
        assert!(p.tick(&mut st, 10, &NoopMetrics).incidents.is_empty());
        let out = p.tick(&mut st, 40, &NoopMetrics);
        assert_eq!(out.incidents.len(), 1);
        assert_eq!(out.incidents[0].incident_id, id);
        assert_eq!(out.incidents[0].trigger, "group_wait");
    }

    #[test]
    fn dedup_then_group_compose() {
        let p = pipeline(
            "dedup:\n  fingerprint: [rule, match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  group_wait: 0s\n",
        );
        let mut st = AlertPipelineState::default();
        // First fire: deduped (passes) and grouped.
        let a = run(&p, "10.0.0.1", Level::High, &mut st, 0);
        assert_eq!(a.len(), 1);
        assert!(
            a[0].header
                .enrichments
                .as_ref()
                .unwrap()
                .contains_key("incident_id")
        );
        // Duplicate: folded by dedup, never reaches grouping.
        let b = run(&p, "10.0.0.1", Level::High, &mut st, 1);
        assert!(b.is_empty());
        assert_eq!(
            st.incidents.len(),
            1,
            "the duplicate did not open a second incident"
        );
    }

    #[test]
    fn strip_event_drops_payload_after_grouping() {
        let p = pipeline("strip_event: true\ngroup:\n  by: [event.raw]\n  group_wait: 0s\n");
        let mut st = AlertPipelineState::default();
        let kept = run(&p, "10.0.0.1", Level::High, &mut st, 0);
        assert_eq!(kept.len(), 1);
        // Event stripped from the delivered result, but grouping still keyed
        // on event.raw (one incident opened).
        assert!(kept[0].as_detection().unwrap().event.is_none());
        assert_eq!(st.incidents.len(), 1);
    }

    #[test]
    fn strip_event_payloads_drops_correlation_events_and_sources() {
        let mut result = EvaluationResult {
            header: detection("10.0.0.1", Level::High).header,
            body: ResultBody::Correlation(rsigma_eval::CorrelationBody {
                correlation_type: rsigma_parser::CorrelationType::EventCount,
                group_key: vec![],
                aggregated_value: 1.0,
                timespan_secs: 60,
                events: None,
                event_refs: Some(vec![]),
                event_sources: Some(vec![]),
            }),
        };
        strip_event_payloads(&mut result);
        let correlation = result.as_correlation().unwrap();
        assert!(correlation.event_refs.is_none());
        assert!(correlation.event_sources.is_none());
    }

    fn detection_with_include_event(value: Option<Value>) -> EvaluationResult {
        let mut result = detection("10.0.0.1", Level::High);
        if let Some(value) = value {
            result.header.custom_attributes =
                Arc::new(HashMap::from([("rsigma.include_event".to_string(), value)]));
        }
        result
    }

    #[test]
    fn strip_auto_retained_event_drops_an_event_the_rule_did_not_ask_for() {
        let mut result = detection_with_include_event(None);
        strip_auto_retained_event(&mut result);
        assert!(result.as_detection().unwrap().event.is_none());

        let mut result = detection_with_include_event(Some(Value::String("false".into())));
        strip_auto_retained_event(&mut result);
        assert!(result.as_detection().unwrap().event.is_none());
    }

    #[test]
    fn strip_auto_retained_event_keeps_an_event_the_rule_asked_for() {
        let mut result = detection_with_include_event(Some(Value::String("true".into())));
        strip_auto_retained_event(&mut result);
        assert_eq!(
            result.as_detection().unwrap().event,
            Some(serde_json::json!({"raw": "event"}))
        );
    }

    #[test]
    fn strip_auto_retained_event_treats_a_boolean_like_the_compiler() {
        // The compiler attaches the event only for the string "true", so a
        // boolean never asked for it.
        let mut result = detection_with_include_event(Some(Value::Bool(true)));
        strip_auto_retained_event(&mut result);
        assert!(result.as_detection().unwrap().event.is_none());
    }

    #[test]
    fn strip_auto_retained_event_keeps_correlation_payloads() {
        let event_ref = rsigma_eval::EventRef {
            timestamp: 1,
            id: Some("e1".to_string()),
        };
        let mut result = EvaluationResult {
            header: detection("10.0.0.1", Level::High).header,
            body: ResultBody::Correlation(rsigma_eval::CorrelationBody {
                correlation_type: rsigma_parser::CorrelationType::EventCount,
                group_key: vec![],
                aggregated_value: 1.0,
                timespan_secs: 60,
                events: Some(vec![serde_json::json!({"raw": "event"})]),
                event_refs: Some(vec![event_ref]),
                event_sources: Some(vec![rsigma_eval::EventSource {
                    rule: Some("rule-1".to_string()),
                    via: None,
                }]),
            }),
        };
        let before = serde_json::to_value(&result.body).unwrap();
        strip_auto_retained_event(&mut result);
        assert_eq!(serde_json::to_value(&result.body).unwrap(), before);
    }

    #[test]
    fn inhibition_mutes_target_while_source_active() {
        let p = pipeline(
            "inhibit_rules:\n  - name: crit\n    source_match:\n      - selector: level\n        op: \"=\"\n        value: critical\n    target_match:\n      - selector: level\n        op: \"=\"\n        value: high\n    equal: [match.SourceIp]\n    duration: 5m\n",
        );
        let mut st = AlertPipelineState::default();
        // Critical source on 10.0.0.1 passes and registers as a source.
        assert_eq!(run(&p, "10.0.0.1", Level::Critical, &mut st, 0).len(), 1);
        // High target on the same IP is inhibited (dropped).
        assert!(run(&p, "10.0.0.1", Level::High, &mut st, 1).is_empty());
        // High target on a different IP passes.
        assert_eq!(run(&p, "10.0.0.2", Level::High, &mut st, 2).len(), 1);
    }

    #[test]
    fn snapshot_round_trips_and_prunes() {
        let p = pipeline(
            "dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  group_wait: 1h\n  resolve_timeout: 1h\n",
        );
        let mut st = AlertPipelineState::default();
        let _ = run(&p, "10.0.0.1", Level::High, &mut st, 100);
        st.silences.add(
            Silence::build(
                SilenceSpec {
                    matchers: vec![MatcherSpec {
                        selector: "rule".to_string(),
                        op: MatchOp::Eq,
                        value: "other".to_string(),
                    }],
                    ..Default::default()
                },
                SilenceOrigin::Api,
            )
            .unwrap(),
        );
        assert_eq!(st.dedup.len(), 1);
        assert_eq!(st.incidents.len(), 1);

        // Round-trip the snapshot through JSON.
        let json = serde_json::to_string(&p.snapshot(&st)).unwrap();
        let snap: AlertPipelineSnapshot = serde_json::from_str(&json).unwrap();

        // Restore within the window: state comes back.
        let mut fresh = AlertPipelineState::default();
        assert!(p.restore(&mut fresh, snap, 200, false));
        assert_eq!(fresh.dedup.len(), 1, "dedup alert restored");
        assert_eq!(fresh.incidents.len(), 1, "incident restored");
        assert_eq!(
            fresh.silences.api_snapshot().len(),
            1,
            "api silence restored"
        );
        // The restored dedup alert folds a duplicate.
        assert!(run(&p, "10.0.0.1", Level::High, &mut fresh, 250).is_empty());

        // Restore far past the windows: dedup + incident are pruned.
        let snap2: AlertPipelineSnapshot =
            serde_json::from_str(&serde_json::to_string(&p.snapshot(&st)).unwrap()).unwrap();
        let mut aged = AlertPipelineState::default();
        assert!(p.restore(&mut aged, snap2, 100 + 3600 + 5, false));
        assert!(aged.dedup.is_empty(), "stale dedup alert pruned on restore");
        assert!(
            aged.incidents.is_empty(),
            "stale incident pruned on restore"
        );
    }

    const INHIBIT: &str = "inhibit_rules:\n  - name: high\n    source_match:\n      - selector: level\n        op: \"=\"\n        value: high\n    target_match:\n      - selector: level\n        op: \"=\"\n        value: critical\n    equal: [match.SourceIp]\n    duration: 1h\n";
    const UNCAPPED: &str = "dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  group_wait: 1h\n  resolve_timeout: 1h\n";
    const CAPPED: &str = "dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\n  max_active_alerts: 3\ngroup:\n  by: [match.SourceIp]\n  group_wait: 1h\n  resolve_timeout: 1h\n  caps:\n    max_open_incidents: 3\nmax_inhibit_sources: 3\n";

    fn uncapped() -> AlertPipeline {
        pipeline(&format!("{UNCAPPED}{INHIBIT}"))
    }

    fn capped() -> AlertPipeline {
        pipeline(&format!("{CAPPED}{INHIBIT}"))
    }

    fn ip(i: i64) -> String {
        format!("10.0.0.{i}")
    }

    /// Six alerts and incidents, one per IP, with IP `i` last seen at `i`.
    fn six_alerts() -> AlertPipelineState {
        let p = uncapped();
        let mut st = AlertPipelineState::default();
        for i in 0..6 {
            run(&p, &ip(i), Level::High, &mut st, i);
        }
        assert_eq!((st.dedup.len(), st.incidents.len()), (6, 6));
        assert_eq!(st.inhibit.snapshot().len(), 6);
        st
    }

    /// Assert the state holds exactly the three most recently seen IPs.
    fn assert_keeps_newest_three(p: &AlertPipeline, st: &mut AlertPipelineState) {
        let mut grouped: Vec<String> = st
            .incidents
            .snapshot(IncludeMode::Refs)
            .iter()
            .map(|inc| inc.group_by["match.SourceIp"].as_str().unwrap().to_string())
            .collect();
        grouped.sort();
        assert_eq!(grouped, [ip(3), ip(4), ip(5)]);
        assert_eq!(st.dedup.len(), 3);
        let icfg = p.inhibit.as_ref().unwrap();
        assert_eq!(st.inhibit.active_count(icfg, 10), 3);
        for i in 2..6 {
            let target = detection(&ip(i), Level::Critical);
            assert_eq!(
                st.inhibit
                    .evaluate(icfg, &target, 10, None, |_| {})
                    .is_some(),
                i >= 3,
                "only the newest inhibition sources survive: {}",
                ip(i)
            );
        }
        for i in 3..6 {
            assert!(
                run(p, &ip(i), Level::High, st, 10).is_empty(),
                "{} folds",
                ip(i)
            );
        }
        assert_eq!(
            run(p, &ip(2), Level::High, st, 10).len(),
            1,
            "evicted alert emits"
        );
    }

    #[test]
    fn restore_keeps_the_most_recent_entries_within_lowered_caps() {
        let snap = uncapped().snapshot(&six_alerts());
        let capped = capped();
        let mut st = AlertPipelineState::default();
        assert!(capped.restore(&mut st, snap, 10, false));
        assert_keeps_newest_three(&capped, &mut st);
    }

    #[test]
    fn enforce_caps_trims_state_carried_into_a_reloaded_pipeline() {
        let mut st = six_alerts();
        let capped = capped();
        assert_eq!(
            capped.enforce_caps(&mut st),
            CapTrim {
                dedup_alerts: 3,
                incidents: 3,
                inhibit_sources: 3,
            }
        );
        assert_keeps_newest_three(&capped, &mut st);
        assert_eq!(capped.enforce_caps(&mut st), CapTrim::default());
    }

    #[test]
    fn static_silence_mutes_matching_results() {
        let p = pipeline(
            "silences:\n  - matchers:\n      - selector: match.SourceIp\n        op: \"=\"\n        value: 10.0.0.1\ndedup:\n  fingerprint: [match.SourceIp]\n",
        );
        let mut st = AlertPipelineState::default();
        st.silences.set_static(p.static_silences().to_vec());

        // 10.0.0.1 is silenced (dropped); 10.0.0.2 passes through.
        assert!(run(&p, "10.0.0.1", Level::High, &mut st, 0).is_empty());
        assert_eq!(run(&p, "10.0.0.2", Level::High, &mut st, 0).len(), 1);
        // The silenced result never entered the dedup store.
        assert_eq!(st.dedup.len(), 1);
    }

    #[derive(Default)]
    struct RecordingSink {
        admits: Vec<crate::AdmittedEvent>,
        rejects: Vec<crate::CaptureReject>,
    }

    impl crate::CaptureSink for RecordingSink {
        fn admit(&mut self, event: crate::AdmittedEvent, _now: i64) {
            self.admits.push(event);
        }
        fn reject(&mut self, reason: crate::CaptureReject) {
            self.rejects.push(reason);
        }
    }

    fn capture_pipeline() -> AlertPipeline {
        pipeline(
            "dedup:\n  fingerprint: [rule, match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  group_wait: 0s\n",
        )
    }

    #[test]
    fn capture_absent_matches_process_output() {
        let p = capture_pipeline();
        let mut with_hook = AlertPipelineState::default();
        let mut without = AlertPipelineState::default();
        let mut sink = RecordingSink::default();
        let a = p.process(
            vec![detection("10.0.0.1", Level::High)],
            &mut without,
            0,
            &NoopMetrics,
        );
        let b = p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut with_hook,
            0,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            serde_json::to_value(&b).unwrap()
        );
        assert_eq!(sink.admits.len(), 1);
    }

    #[test]
    fn capture_skips_silenced_and_inhibited() {
        let p = pipeline(
            "silences:\n  - matchers:\n      - selector: match.SourceIp\n        op: \"=\"\n        value: 10.0.0.1\ninhibit_rules:\n  - name: crit\n    source_match:\n      - selector: level\n        op: \"=\"\n        value: critical\n    target_match:\n      - selector: level\n        op: \"=\"\n        value: high\n    equal: [match.SourceIp]\n    duration: 5m\ngroup:\n  by: [match.SourceIp]\n",
        );
        let mut st = AlertPipelineState::default();
        st.silences.set_static(p.static_silences().to_vec());
        let mut sink = RecordingSink::default();
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut st,
            0,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert!(
            sink.admits.is_empty(),
            "silenced result must not be captured"
        );

        let mut sink = RecordingSink::default();
        p.process_with_capture(
            vec![detection("10.0.0.2", Level::Critical)],
            &mut st,
            1,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert_eq!(sink.admits.len(), 1);
        p.process_with_capture(
            vec![detection("10.0.0.2", Level::High)],
            &mut st,
            2,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert_eq!(
            sink.admits.len(),
            1,
            "inhibited result must not be captured"
        );
    }

    #[test]
    fn capture_sees_repeats_before_dedup() {
        let p = capture_pipeline();
        let mut st = AlertPipelineState::default();
        let mut sink = RecordingSink::default();
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut st,
            0,
            &NoopMetrics,
            Some(&mut sink),
        );
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut st,
            1,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert_eq!(sink.admits.len(), 2, "folded repeats are still captured");
        assert!(!sink.admits[1].is_fresh_generation);
    }

    #[test]
    fn capture_coalesces_matches_in_one_call() {
        let p = capture_pipeline();
        let mut st = AlertPipelineState::default();
        let mut sink = RecordingSink::default();
        let mut second = detection("10.0.0.1", Level::High);
        second.header.rule_id = Some("rule-2".to_string());
        second.header.rule_title = "Other".to_string();
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High), second],
            &mut st,
            0,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert_eq!(sink.admits.len(), 1);
        assert_eq!(sink.admits[0].matches.len(), 2);
        assert!(sink.admits[0].matches.iter().any(|m| m.rule_id == "rule-1"));
        assert!(sink.admits[0].matches.iter().any(|m| m.rule_id == "rule-2"));
    }

    #[test]
    fn capture_rejects_correlation_results() {
        let p = capture_pipeline();
        let mut st = AlertPipelineState::default();
        let mut sink = RecordingSink::default();
        let correlation = EvaluationResult {
            header: RuleHeader {
                rule_title: "Corr".to_string(),
                rule_id: Some("corr-1".to_string()),
                tenant_id: None,
                level: Some(Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
            },
            body: ResultBody::Correlation(rsigma_eval::CorrelationBody {
                correlation_type: rsigma_parser::CorrelationType::EventCount,
                group_key: vec![],
                aggregated_value: 1.0,
                timespan_secs: 60,
                events: None,
                event_refs: None,
                event_sources: None,
            }),
        };
        p.process_with_capture(vec![correlation], &mut st, 0, &NoopMetrics, Some(&mut sink));
        assert_eq!(
            sink.rejects,
            vec![crate::CaptureReject::UnsupportedResultKind]
        );
        assert!(sink.admits.is_empty());
    }

    #[test]
    fn capture_incompatibility_requires_group_by_and_dedup_coverage() {
        let no_group = pipeline("dedup:\n  fingerprint: [rule]\n");
        assert_eq!(
            no_group.capture_incompatibility(),
            Some(crate::CaptureIncompatibility::MissingGroupBy)
        );

        let entity = pipeline("group:\n  mode: entity_graph\n  entities: [match.SourceIp]\n");
        assert_eq!(
            entity.capture_incompatibility(),
            Some(crate::CaptureIncompatibility::EntityGraph)
        );

        let mismatch = pipeline("dedup:\n  fingerprint: [rule]\ngroup:\n  by: [match.SourceIp]\n");
        match mismatch.capture_incompatibility() {
            Some(crate::CaptureIncompatibility::DedupSelectorsMissing(missing)) => {
                assert_eq!(missing, vec!["match.SourceIp".to_string()]);
            }
            other => panic!("expected missing selectors, got {other:?}"),
        }

        assert!(capture_pipeline().capture_incompatibility().is_none());
    }

    #[test]
    fn capture_refuses_when_incident_store_is_full() {
        let p = pipeline("group:\n  by: [match.SourceIp]\n  caps:\n    max_open_incidents: 1\n");
        let mut st = AlertPipelineState::default();
        let mut sink = RecordingSink::default();
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut st,
            0,
            &NoopMetrics,
            Some(&mut sink),
        );
        p.process_with_capture(
            vec![detection("10.0.0.2", Level::High)],
            &mut st,
            1,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert_eq!(sink.admits.len(), 1);
        assert_eq!(sink.rejects, vec![crate::CaptureReject::NotAssignable]);
    }

    #[test]
    fn capture_fresh_generation_when_incident_is_not_open() {
        let p = capture_pipeline();
        let mut st = AlertPipelineState::default();
        let mut sink = RecordingSink::default();
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut st,
            0,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert!(sink.admits[0].is_fresh_generation);
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut st,
            1,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert!(!sink.admits[1].is_fresh_generation);
    }

    fn tenant_run(
        p: &AlertPipeline,
        ip: &str,
        tenant: &str,
        state: &mut AlertPipelineState,
        now: i64,
    ) -> ProcessResult {
        let mut d = detection(ip, Level::High);
        d.header.tenant_id = Some(rsigma_eval::TenantId::new(tenant).unwrap());
        p.process(vec![d], state, now, &NoopMetrics)
    }

    #[test]
    fn snapshot_attribution_discards_the_other_mode() {
        let p = pipeline(
            "dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  group_wait: 1h\n  resolve_timeout: 1h\n",
        );
        let mut st = AlertPipelineState::default();
        tenant_run(&p, "10.0.0.1", "a", &mut st, 100);
        run(&p, "10.0.0.2", Level::High, &mut st, 100);
        assert_eq!((st.dedup.len(), st.incidents.len()), (2, 2));
        let snap = p.snapshot(&st);

        let mut tenanted = AlertPipelineState::default();
        let stats = p
            .restore_detailed(&mut tenanted, snap.clone(), 100, true)
            .unwrap();
        assert_eq!(stats.restored, 2);
        assert_eq!(stats.discarded_untenanted, 2);
        assert_eq!(tenanted.dedup.len(), 1);
        assert_eq!(tenanted.incidents.len(), 1);

        let mut expired = AlertPipelineState::default();
        let stats = p
            .restore_detailed(&mut expired, snap.clone(), 100 + 7200, true)
            .unwrap();
        assert_eq!(
            stats.restored, 0,
            "entries past resolve_timeout are not restored"
        );

        let mut untenanted = AlertPipelineState::default();
        let stats = p
            .restore_detailed(&mut untenanted, snap, 100, false)
            .unwrap();
        assert_eq!(stats.restored, 2);
        assert_eq!(stats.discarded_tenanted, 2);
        assert_eq!(untenanted.dedup.len(), 1);
        assert_eq!(untenanted.incidents.len(), 1);
    }

    #[test]
    fn tenant_quotas_evict_only_that_tenants_entries() {
        let mut p = pipeline(
            "dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  group_wait: 1h\n  resolve_timeout: 1h\n",
        );
        p.set_tenant_quotas(AlertTenantQuotas {
            active_alerts: Some(2),
            incidents: Some(2),
            ..Default::default()
        });
        let mut st = AlertPipelineState::default();
        let a = rsigma_eval::TenantId::new("a").unwrap();
        let b = rsigma_eval::TenantId::new("b").unwrap();

        for i in 0..3 {
            tenant_run(&p, &ip(i), "a", &mut st, i);
        }
        tenant_run(&p, "10.0.0.9", "b", &mut st, 10);

        assert_eq!(st.dedup.count_for_tenant(Some(&a)), 2);
        assert_eq!(st.dedup.count_for_tenant(Some(&b)), 1);
        assert_eq!(st.incidents.count_for_tenant(Some(&a)), 2);
        assert_eq!(st.incidents.count_for_tenant(Some(&b)), 1);
    }

    #[test]
    fn the_inhibition_source_quota_applies_per_tenant() {
        let mut p = pipeline(
            "inhibit_rules:\n  - name: crit\n    source_match:\n      - selector: level\n        op: \"=\"\n        value: critical\n    target_match:\n      - selector: level\n        op: \"=\"\n        value: high\n    equal: [match.SourceIp]\n    duration: 5m\n",
        );
        p.set_tenant_quotas(AlertTenantQuotas {
            inhibition_sources: Some(1),
            ..Default::default()
        });
        let mut st = AlertPipelineState::default();
        let send = |st: &mut AlertPipelineState, ip: &str, level: Level, tenant: &str| {
            let mut d = detection(ip, level);
            d.header.tenant_id = Some(rsigma_eval::TenantId::new(tenant).unwrap());
            p.process(vec![d], st, 0, &NoopMetrics).len()
        };
        send(&mut st, "10.0.0.1", Level::Critical, "a");
        send(&mut st, "10.0.0.2", Level::Critical, "a");
        send(&mut st, "10.0.0.3", Level::Critical, "b");
        assert_eq!(send(&mut st, "10.0.0.1", Level::High, "a"), 0);
        assert_eq!(
            send(&mut st, "10.0.0.2", Level::High, "a"),
            1,
            "the source over tenant a's quota was refused"
        );
        assert_eq!(send(&mut st, "10.0.0.3", Level::High, "b"), 0);
    }

    #[test]
    fn a_lowered_tenant_quota_trims_carried_over_state() {
        let mut p = pipeline(
            "dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  group_wait: 1h\n  resolve_timeout: 1h\n",
        );
        let mut st = AlertPipelineState::default();
        for i in 0..3 {
            tenant_run(&p, &ip(i), "a", &mut st, i);
        }
        tenant_run(&p, "10.0.0.9", "b", &mut st, 10);

        p.set_tenant_quotas(AlertTenantQuotas {
            active_alerts: Some(2),
            incidents: Some(2),
            ..Default::default()
        });
        let trim = p.enforce_caps(&mut st);
        assert_eq!((trim.dedup_alerts, trim.incidents), (1, 1));
        let a = rsigma_eval::TenantId::new("a").unwrap();
        let b = rsigma_eval::TenantId::new("b").unwrap();
        assert_eq!(st.dedup.count_for_tenant(Some(&a)), 2);
        assert_eq!(st.incidents.count_for_tenant(Some(&a)), 2);
        assert_eq!(st.dedup.count_for_tenant(Some(&b)), 1);
        assert!(
            st.incidents
                .snapshot(IncludeMode::Refs)
                .iter()
                .all(|inc| inc.first_seen != 0),
            "the least recently seen incident of tenant a went first"
        );
    }

    #[test]
    fn joining_an_open_incident_at_the_tenant_cap_evicts_nothing() {
        let mut p =
            pipeline("group:\n  by: [match.SourceIp]\n  group_wait: 1h\n  resolve_timeout: 1h\n");
        p.set_tenant_quotas(AlertTenantQuotas {
            incidents: Some(2),
            ..Default::default()
        });
        let mut st = AlertPipelineState::default();
        tenant_run(&p, &ip(0), "a", &mut st, 0);
        tenant_run(&p, &ip(1), "a", &mut st, 1);
        tenant_run(&p, &ip(0), "a", &mut st, 2);

        let mut incidents = st.incidents.snapshot(IncludeMode::Refs);
        incidents.sort_by_key(|inc| inc.first_seen);
        assert_eq!(incidents.len(), 2);
        assert_eq!(
            incidents[0].first_seen, 0,
            "the joined incident kept its history"
        );
        assert_eq!(incidents[0].result_count, 2);
        assert_eq!(incidents[1].first_seen, 1, "the other incident survived");

        tenant_run(&p, &ip(2), "a", &mut st, 3);
        let mut incidents = st.incidents.snapshot(IncludeMode::Refs);
        incidents.sort_by_key(|inc| inc.first_seen);
        assert_eq!(incidents.len(), 2);
        assert_eq!(
            (incidents[0].first_seen, incidents[1].first_seen),
            (0, 3),
            "a new incident evicts the least recently seen one"
        );
    }
}
