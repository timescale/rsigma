//! Logical multi-tenancy: settings, startup refusals, and API tenant scoping.
#![allow(clippy::items_after_test_module)]

use std::path::PathBuf;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rsigma_eval::TenantId;
use serde::Deserialize;

use crate::config::TenantQuotasPartial;

use super::auth::AuthIdentity;

/// Resolved tenancy settings from operator config and flags.
#[derive(Debug, Clone, Default)]
pub(crate) struct TenancySettings {
    pub enabled: bool,
    pub quotas: TenantQuotas,
    pub metrics_tenant_allowlist: Vec<TenantId>,
}

/// Per-tenant state caps.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TenantQuotas {
    pub correlation_state: Option<usize>,
    pub active_alerts: Option<usize>,
    pub incidents: Option<usize>,
    pub risk_entities: Option<usize>,
    pub silences: Option<usize>,
    pub inhibition_sources: Option<usize>,
    pub stream_sessions: Option<usize>,
}

impl TenantQuotas {
    /// Each quota with its config key.
    fn named(&self) -> [(&'static str, Option<usize>); 7] {
        [
            ("correlation_state", self.correlation_state),
            ("active_alerts", self.active_alerts),
            ("incidents", self.incidents),
            ("risk_entities", self.risk_entities),
            ("silences", self.silences),
            ("inhibition_sources", self.inhibition_sources),
            ("stream_sessions", self.stream_sessions),
        ]
    }

    /// The quotas the alert pipeline enforces.
    pub fn alert_pipeline(&self) -> rsigma_runtime::AlertTenantQuotas {
        rsigma_runtime::AlertTenantQuotas {
            active_alerts: self.active_alerts,
            incidents: self.incidents,
            silences: self.silences,
            inhibition_sources: self.inhibition_sources,
        }
    }
}

impl From<TenantQuotasPartial> for TenantQuotas {
    fn from(partial: TenantQuotasPartial) -> Self {
        TenantQuotas {
            correlation_state: partial.correlation_state,
            active_alerts: partial.active_alerts,
            incidents: partial.incidents,
            risk_entities: partial.risk_entities,
            silences: partial.silences,
            inhibition_sources: partial.inhibition_sources,
            stream_sessions: partial.stream_sessions,
        }
    }
}

/// One tenant-bound NATS subscription.
#[derive(Debug, Clone)]
pub(crate) struct NatsTenantBinding {
    pub subject: String,
    pub tenant: TenantId,
    #[allow(dead_code)]
    pub credentials_file: Option<PathBuf>,
}

/// The inputs the startup refusal checks need.
pub(crate) struct TenancyValidation<'a> {
    pub settings: &'a TenancySettings,
    pub token_specs: &'a [super::auth::TokenSpec],
    pub anonymous_permissions: &'a [String],
    pub api_token_env_used: bool,
    pub auth_configured: bool,
    pub input_source: Option<&'a str>,
    pub input_tenant: Option<&'a str>,
    pub nats_tenants: &'a [NatsTenantBinding],
    pub ruleset_tenants: &'a [(String, Vec<TenantId>)],
    pub project_layer_loaded: bool,
    pub sink_specs: &'a [String],
    pub alert_pipeline_nats_subjects: &'a [String],
    pub scope_tenants: &'a [Vec<String>],
    pub disposition_source: bool,
}

/// Validate tenancy settings against the inputs. Returns the first refusal.
pub(crate) fn validate_tenancy(v: &TenancyValidation<'_>) -> Result<(), String> {
    if v.settings.enabled {
        validate_enabled(v)
    } else {
        validate_disabled(v)
    }
}

fn validate_enabled(v: &TenancyValidation<'_>) -> Result<(), String> {
    // A quota of 0 would evict on every new entry.
    for (name, quota) in v.settings.quotas.named() {
        if quota == Some(0) {
            return Err(format!("daemon.tenancy.quotas.{name} must be at least 1"));
        }
    }
    // 1. The API always serves state reads, so tenancy needs auth.
    if !v.auth_configured || v.token_specs.is_empty() {
        return Err(
            "daemon.tenancy.enabled requires daemon.api.auth with at least one token".to_string(),
        );
    }
    // 2. The implicit `default` admin token has no tenant binding.
    if v.api_token_env_used {
        return Err(
            "daemon.tenancy.enabled cannot use --api-token-env; its implicit 'default' token has no tenant binding".to_string(),
        );
    }
    // 3. Anonymous requests have no tenant to bind.
    if !v.anonymous_permissions.is_empty() {
        return Err(
            "daemon.tenancy.enabled requires daemon.api.auth.anonymous_permissions to be empty"
                .to_string(),
        );
    }
    // 4. Every token declares exactly one of tenant or all_tenants.
    for token in v.token_specs {
        match (&token.tenant, token.all_tenants) {
            (Some(_), true) => {
                return Err(format!(
                    "token '{}' sets both 'tenant' and 'all_tenants: true'; use exactly one",
                    token.name
                ));
            }
            (None, false) => {
                return Err(format!(
                    "token '{}' sets neither 'tenant' nor 'all_tenants: true' while tenancy is enabled",
                    token.name
                ));
            }
            _ => {}
        }
    }
    // 5. Configured ids are parsed as TenantId before validation runs, so
    // only an explicitly empty ruleset binding is left to refuse here.
    for (ruleset, tenants) in v.ruleset_tenants {
        if tenants.is_empty() {
            return Err(format!(
                "ruleset '{ruleset}' has an empty `tenants` binding; omit the key to admit every tenant"
            ));
        }
    }

    let source = v.input_source.unwrap_or("stdin");
    // 6. Every source other than the HTTP push source needs an
    // operator-declared tenant, including a subject-less NATS URL (which
    // subscribes to `>`) without `nats_tenants`.
    if source != "http" && v.input_tenant.is_none() && v.nats_tenants.is_empty() {
        return Err(format!(
            "daemon.input.source '{source}' requires daemon.input.tenant while tenancy is enabled"
        ));
    }
    // A disposition pull source has no tenant binding, and a record's own
    // `tenant` field is not identity.
    if v.disposition_source {
        return Err(
            "daemon.dispositions.source cannot be used while tenancy is enabled; post dispositions to /api/v1/dispositions with a tenant token".to_string(),
        );
    }
    // 7. An HTTP push source gets its tenant from the token, not config.
    if source == "http" && v.input_tenant.is_some() {
        return Err(
            "daemon.input.tenant cannot be set when daemon.input.source is 'http'; the ingest token supplies the tenant".to_string(),
        );
    }
    // 8. `nats_tenants` binds a subject-less NATS URL.
    if !v.nats_tenants.is_empty() {
        if !source.starts_with("nats://") || nats_url_has_subject(source) {
            return Err(
                "daemon.input.nats_tenants requires daemon.input.source to be a subject-less nats://host:port"
                    .to_string(),
            );
        }
        if v.input_tenant.is_some() {
            return Err(
                "daemon.input.nats_tenants and daemon.input.tenant cannot both be set".to_string(),
            );
        }
        // 9. Subjects may not overlap and tenants may not repeat.
        for (index, left) in v.nats_tenants.iter().enumerate() {
            for right in &v.nats_tenants[index + 1..] {
                if subjects_overlap(&left.subject, &right.subject) {
                    return Err(format!(
                        "daemon.input.nats_tenants subjects '{}' and '{}' overlap",
                        left.subject, right.subject
                    ));
                }
                if left.tenant == right.tenant {
                    return Err(format!(
                        "daemon.input.nats_tenants names tenant '{}' more than once",
                        left.tenant.as_str()
                    ));
                }
            }
        }
    }
    // 10. A project layer could replace daemon.rulesets and drop a binding.
    if v.project_layer_loaded {
        return Err(
            "daemon.tenancy.enabled refuses to start with a project config layer loaded; run with --config <PATH> or remove ./rsigma.yaml, ./rsigma.yml, or .rsigmarc".to_string(),
        );
    }
    // 11. A ruleset binding must name a tenant some binding can produce.
    let mut producible: std::collections::HashSet<TenantId> = std::collections::HashSet::new();
    for token in v.token_specs {
        if let Some(tenant) = &token.tenant {
            producible.insert(tenant.clone());
        }
    }
    if let Some(tenant) = v.input_tenant {
        match TenantId::new(tenant) {
            Ok(tenant) => {
                producible.insert(tenant);
            }
            Err(error) => return Err(format!("daemon.input.tenant: {error}")),
        }
    }
    for binding in v.nats_tenants {
        producible.insert(binding.tenant.clone());
    }
    // 12. Ids that differ only by case would share a `{tenant}` file on a
    // case-insensitive filesystem.
    let mut folded: std::collections::HashMap<String, &TenantId> = std::collections::HashMap::new();
    for tenant in &producible {
        if let Some(other) = folded.insert(tenant.as_str().to_ascii_lowercase(), tenant) {
            let (first, second) = if other.as_str() < tenant.as_str() {
                (other, tenant)
            } else {
                (tenant, other)
            };
            return Err(format!(
                "tenants '{}' and '{}' differ only by case; tenant ids must be unique ignoring case",
                first.as_str(),
                second.as_str()
            ));
        }
    }
    for (ruleset, tenants) in v.ruleset_tenants {
        for tenant in tenants {
            if !producible.contains(tenant) {
                return Err(format!(
                    "ruleset '{ruleset}' binds tenant '{}', which no token, input.tenant, or nats_tenants entry can produce",
                    tenant.as_str()
                ));
            }
        }
    }
    Ok(())
}

fn validate_disabled(v: &TenancyValidation<'_>) -> Result<(), String> {
    // Without tenancy every entry is in one bucket, so a quota would act as a
    // second global cap that evicts instead.
    for (name, quota) in v.settings.quotas.named() {
        if quota.is_some() {
            return Err(format!(
                "daemon.tenancy.quotas.{name} (or --max-tenant-state) requires daemon.tenancy.enabled"
            ));
        }
    }
    // 12. No tenant binding may be set while tenancy is off.
    for token in v.token_specs {
        if token.tenant.is_some() || token.all_tenants {
            return Err(format!(
                "token '{}' sets 'tenant' or 'all_tenants' while daemon.tenancy.enabled is false",
                token.name
            ));
        }
    }
    if v.input_tenant.is_some() {
        return Err("daemon.input.tenant requires daemon.tenancy.enabled".to_string());
    }
    if !v.nats_tenants.is_empty() {
        return Err("daemon.input.nats_tenants requires daemon.tenancy.enabled".to_string());
    }
    for (ruleset, tenants) in v.ruleset_tenants {
        if !tenants.is_empty() {
            return Err(format!(
                "ruleset '{ruleset}' sets `tenants` while daemon.tenancy.enabled is false"
            ));
        }
    }
    // 13. `{tenant}` and `tenant=` need tenancy.
    for spec in v.sink_specs {
        if spec.contains("{tenant}") {
            return Err(format!(
                "sink '{spec}' uses '{{tenant}}' while daemon.tenancy.enabled is false"
            ));
        }
        if sink_has_tenant_query(spec) {
            return Err(format!(
                "sink '{spec}' sets 'tenant=' while daemon.tenancy.enabled is false"
            ));
        }
    }
    for subject in v.alert_pipeline_nats_subjects {
        if subject.contains("{tenant}") {
            return Err(format!(
                "alert-pipeline NATS subject '{subject}' uses '{{tenant}}' while daemon.tenancy.enabled is false"
            ));
        }
    }
    // 14. A scoped webhook or enricher needs tenancy.
    for tenants in v.scope_tenants {
        if !tenants.is_empty() {
            return Err(
                "a webhook or enricher scope.tenants is non-empty while daemon.tenancy.enabled is false"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn sink_has_tenant_query(spec: &str) -> bool {
    spec.split_once('?')
        .is_some_and(|(_, query)| query.split('&').any(|pair| pair.starts_with("tenant=")))
}

/// Whether two NATS subjects overlap.
///
/// Walks dot-separated token pairs. `>` on either side overlaps whenever the
/// other side still has a token at that position. Equal tokens or `*` on
/// either side continue; different literals do not overlap. Both sides
/// exhausting together overlaps; one side exhausting first does not.
pub(crate) fn subjects_overlap(a: &str, b: &str) -> bool {
    let left: Vec<&str> = a.split('.').collect();
    let right: Vec<&str> = b.split('.').collect();
    let mut index = 0;
    loop {
        match (left.get(index), right.get(index)) {
            (None, None) => return true,
            (None, Some(_)) | (Some(_), None) => return false,
            (Some(l), Some(r)) => {
                if *l == ">" || *r == ">" {
                    return true;
                }
                if *l == "*" || *r == "*" || l == r {
                    index += 1;
                    continue;
                }
                return false;
            }
        }
    }
}

/// Whether a `nats://` URL names a subject after its authority.
pub(crate) fn nats_url_has_subject(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("nats://") else {
        return false;
    };
    match rest.split_once('/') {
        Some((_, subject)) => !subject.is_empty(),
        None => false,
    }
}

/// The tenant scope resolved for one API read.
#[derive(Debug, Clone)]
pub(crate) enum TenantFilter {
    /// Every tenant (an `all_tenants` token without `?tenant=`).
    All,
    /// Exactly one tenant.
    Only(TenantId),
}

/// The `?tenant=` query parameter.
#[derive(Debug, Deserialize)]
pub(crate) struct TenantQuery {
    pub tenant: Option<String>,
}

/// Resolve the tenant filter for a read. `?tenant=` only narrows: a tenant
/// token may not name another tenant, and `?tenant=` needs tenancy.
#[allow(clippy::result_large_err)]
pub(crate) fn tenant_filter(
    enabled: bool,
    identity: Option<&AuthIdentity>,
    requested: Option<&str>,
) -> Result<TenantFilter, Response> {
    if !enabled {
        if requested.is_some() {
            return Err(bad_request(
                "the ?tenant= query parameter requires daemon.tenancy.enabled",
            ));
        }
        return Ok(TenantFilter::All);
    }
    let Some(identity) = identity else {
        return Err(forbidden(
            "tenancy is enabled but the request has no identity",
        ));
    };
    if identity.all_tenants {
        return match requested {
            None => Ok(TenantFilter::All),
            Some(requested) => parse_tenant(requested).map(TenantFilter::Only),
        };
    }
    let Some(own) = &identity.tenant else {
        return Err(forbidden("the token has no tenant binding"));
    };
    match requested {
        None => Ok(TenantFilter::Only(own.clone())),
        Some(requested) if requested == own.as_str() => Ok(TenantFilter::Only(own.clone())),
        Some(_) => Err(forbidden("the token may not read another tenant")),
    }
}

/// Resolve the tenant a write binds to. A tenant token always binds to its
/// own tenant; an `all_tenants` token must name one in the body.
#[allow(clippy::result_large_err)]
pub(crate) fn write_tenant(
    enabled: bool,
    identity: Option<&AuthIdentity>,
    body_tenant: Option<&str>,
) -> Result<Option<TenantId>, Response> {
    if !enabled {
        return Ok(None);
    }
    let Some(identity) = identity else {
        return Err(forbidden(
            "tenancy is enabled but the request has no identity",
        ));
    };
    if identity.all_tenants {
        let Some(body_tenant) = body_tenant else {
            return Err(bad_request(
                "a token that can see every tenant must send a 'tenant'",
            ));
        };
        return parse_tenant(body_tenant).map(Some);
    }
    let Some(own) = &identity.tenant else {
        return Err(forbidden("the token has no tenant binding"));
    };
    match body_tenant {
        None => Ok(Some(own.clone())),
        Some(body_tenant) if body_tenant == own.as_str() => Ok(Some(own.clone())),
        Some(_) => Err(forbidden("the token may not write another tenant")),
    }
}

#[allow(clippy::result_large_err)]
fn parse_tenant(raw: &str) -> Result<TenantId, Response> {
    TenantId::new(raw).map_err(|error| bad_request(&error.to_string()))
}

fn bad_request(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, message.to_string()).into_response()
}

fn forbidden(message: &str) -> Response {
    (StatusCode::FORBIDDEN, message.to_string()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(id: &str) -> TenantId {
        TenantId::new(id).unwrap()
    }

    #[test]
    fn subjects_overlap_examples() {
        assert!(subjects_overlap("a.>", "a.b"));
        assert!(!subjects_overlap("a.*", "a.b.c"));
        assert!(subjects_overlap("a.*.c", "a.b.*"));
        assert!(!subjects_overlap("a", "a.>"));
        assert!(subjects_overlap(">", "anything.at.all"));
        assert!(subjects_overlap("a.b", "a.b"));
        assert!(!subjects_overlap("a.b", "a.c"));
        assert!(!subjects_overlap("a", "a.b"));
    }

    #[test]
    fn nats_url_subject_detection() {
        assert!(!nats_url_has_subject("nats://host:4222"));
        assert!(!nats_url_has_subject("nats://host:4222/"));
        assert!(nats_url_has_subject("nats://host:4222/tenants.a.>"));
        assert!(!nats_url_has_subject("stdin"));
    }

    #[test]
    fn tenant_filter_branches() {
        let a = tenant("a");
        let b = tenant("b");
        let tenant_identity = AuthIdentity {
            token: Some("t".into()),
            tenant: Some(a.clone()),
            all_tenants: false,
        };
        let admin = AuthIdentity {
            token: Some("admin".into()),
            tenant: None,
            all_tenants: true,
        };

        assert!(matches!(
            tenant_filter(false, Some(&tenant_identity), None).unwrap(),
            TenantFilter::All
        ));
        assert!(tenant_filter(false, Some(&tenant_identity), Some("a")).is_err());
        assert!(matches!(
            tenant_filter(true, Some(&tenant_identity), None).unwrap(),
            TenantFilter::Only(t) if t == a
        ));
        assert!(tenant_filter(true, Some(&tenant_identity), Some("b")).is_err());
        assert!(matches!(
            tenant_filter(true, Some(&admin), None).unwrap(),
            TenantFilter::All
        ));
        assert!(matches!(
            tenant_filter(true, Some(&admin), Some("b")).unwrap(),
            TenantFilter::Only(t) if t == b
        ));
        assert!(tenant_filter(true, Some(&admin), Some("bad/id")).is_err());
    }

    #[test]
    fn write_tenant_branches() {
        let a = tenant("a");
        let tenant_identity = AuthIdentity {
            token: Some("t".into()),
            tenant: Some(a.clone()),
            all_tenants: false,
        };
        let admin = AuthIdentity {
            token: Some("admin".into()),
            tenant: None,
            all_tenants: true,
        };
        assert_eq!(write_tenant(false, Some(&admin), None).unwrap(), None);
        assert_eq!(
            write_tenant(true, Some(&tenant_identity), None).unwrap(),
            Some(a.clone())
        );
        assert_eq!(
            write_tenant(true, Some(&tenant_identity), Some("a")).unwrap(),
            Some(a.clone())
        );
        assert!(write_tenant(true, Some(&tenant_identity), Some("b")).is_err());
        assert!(write_tenant(true, Some(&admin), None).is_err());
        assert_eq!(
            write_tenant(true, Some(&admin), Some("b")).unwrap(),
            Some(tenant("b"))
        );
    }

    #[test]
    fn an_unbound_identity_fails_closed_with_tenancy_on() {
        let unbound = AuthIdentity {
            token: Some("t".into()),
            tenant: None,
            all_tenants: false,
        };
        for identity in [None, Some(&unbound)] {
            let read = tenant_filter(true, identity, None).unwrap_err();
            assert_eq!(read.status(), StatusCode::FORBIDDEN);
            let write = write_tenant(true, identity, None).unwrap_err();
            assert_eq!(write.status(), StatusCode::FORBIDDEN);
        }
        assert!(matches!(
            tenant_filter(false, None, None).unwrap(),
            TenantFilter::All
        ));
        assert_eq!(write_tenant(false, None, None).unwrap(), None);
    }

    fn enabled_validation<'a>(
        settings: &'a TenancySettings,
        tokens: &'a [super::super::auth::TokenSpec],
        source: &'a str,
    ) -> TenancyValidation<'a> {
        TenancyValidation {
            settings,
            token_specs: tokens,
            anonymous_permissions: &[],
            api_token_env_used: false,
            auth_configured: true,
            input_source: Some(source),
            input_tenant: None,
            nats_tenants: &[],
            ruleset_tenants: &[],
            project_layer_loaded: false,
            sink_specs: &[],
            alert_pipeline_nats_subjects: &[],
            scope_tenants: &[],
            disposition_source: false,
        }
    }

    #[test]
    fn every_non_http_source_needs_a_tenant_binding() {
        let settings = TenancySettings {
            enabled: true,
            ..Default::default()
        };
        let tokens = [super::super::auth::TokenSpec {
            name: "admin".into(),
            role: Some("admin".into()),
            permissions: None,
            token_env: "ADMIN".into(),
            tenant: None,
            all_tenants: true,
        }];
        for source in [
            "stdin",
            "unix:///tmp/rsigma.sock",
            "nats://host:4222/events",
            "nats://host:4222",
        ] {
            let error = validate_tenancy(&enabled_validation(&settings, &tokens, source))
                .expect_err(source);
            assert!(error.contains("requires daemon.input.tenant"), "{error}");
        }
        validate_tenancy(&enabled_validation(&settings, &tokens, "http")).unwrap();

        let mut with_tenant = enabled_validation(&settings, &tokens, "nats://host:4222");
        with_tenant.input_tenant = Some("tenant-a");
        validate_tenancy(&with_tenant).unwrap();

        let bindings = [NatsTenantBinding {
            subject: "tenants.a.>".into(),
            tenant: tenant("a"),
            credentials_file: None,
        }];
        let mut with_bindings = enabled_validation(&settings, &tokens, "nats://host:4222");
        with_bindings.nats_tenants = &bindings;
        validate_tenancy(&with_bindings).unwrap();

        let mut disposition_source = enabled_validation(&settings, &tokens, "http");
        disposition_source.disposition_source = true;
        let error = validate_tenancy(&disposition_source).unwrap_err();
        assert!(error.contains("daemon.dispositions.source"), "{error}");
    }

    #[test]
    fn quotas_need_tenancy_and_a_positive_value() {
        let tokens = [super::super::auth::TokenSpec {
            name: "admin".into(),
            role: Some("admin".into()),
            permissions: None,
            token_env: "ADMIN".into(),
            tenant: None,
            all_tenants: true,
        }];
        let mut settings = TenancySettings {
            enabled: true,
            ..Default::default()
        };
        settings.quotas.incidents = Some(0);
        let error = validate_tenancy(&enabled_validation(&settings, &tokens, "http")).unwrap_err();
        assert!(
            error.contains("quotas.incidents must be at least 1"),
            "{error}"
        );

        settings.quotas.incidents = Some(1);
        validate_tenancy(&enabled_validation(&settings, &tokens, "http")).unwrap();

        settings.enabled = false;
        let mut disabled = enabled_validation(&settings, &[], "http");
        disabled.auth_configured = false;
        let error = validate_tenancy(&disabled).unwrap_err();
        assert!(error.contains("requires daemon.tenancy.enabled"), "{error}");
    }

    #[test]
    fn tenants_that_differ_only_by_case_are_refused() {
        let token = |name: &str, tenant: &str| super::super::auth::TokenSpec {
            name: name.into(),
            role: Some("ingest".into()),
            permissions: None,
            token_env: name.to_uppercase(),
            tenant: Some(TenantId::new(tenant).unwrap()),
            all_tenants: false,
        };
        let settings = TenancySettings {
            enabled: true,
            ..Default::default()
        };
        let tokens = [token("one", "Acme"), token("two", "acme")];
        let error = validate_tenancy(&enabled_validation(&settings, &tokens, "http")).unwrap_err();
        assert!(
            error.contains("'Acme' and 'acme' differ only by case"),
            "{error}"
        );

        let tokens = [token("one", "Acme"), token("two", "globex")];
        validate_tenancy(&enabled_validation(&settings, &tokens, "http")).unwrap();
    }
}

/// Resolve tenancy settings, the input tenant, and the NATS tenant bindings
/// from the merged config plus the CLI flags.
pub(crate) fn resolve_tenancy_settings(
    base: &crate::config::RsigmaConfigPartial,
    cli_tenancy: bool,
    cli_max_tenant_state: Option<usize>,
) -> Result<(TenancySettings, Option<TenantId>, Vec<NatsTenantBinding>), String> {
    let daemon = base.daemon.as_ref();
    let tenancy = daemon.and_then(|d| d.tenancy.as_ref());
    let mut settings = TenancySettings {
        enabled: cli_tenancy || tenancy.and_then(|t| t.enabled).unwrap_or(false),
        ..Default::default()
    };
    if let Some(quotas) = tenancy.and_then(|t| t.quotas.clone()) {
        settings.quotas = quotas.into();
    }
    if let Some(max) = cli_max_tenant_state {
        settings.quotas.correlation_state = Some(max);
    }
    for raw in tenancy
        .and_then(|t| t.metrics_tenant_allowlist.clone())
        .unwrap_or_default()
    {
        let tenant = TenantId::new(&raw)
            .map_err(|error| format!("daemon.tenancy.metrics_tenant_allowlist: {error}"))?;
        settings.metrics_tenant_allowlist.push(tenant);
    }

    let input = daemon.and_then(|d| d.input.as_ref());
    let input_tenant = input
        .and_then(|i| i.tenant.as_deref())
        .map(TenantId::new)
        .transpose()
        .map_err(|error| format!("daemon.input.tenant: {error}"))?;

    let mut nats_tenants = Vec::new();
    for entry in input
        .and_then(|i| i.nats_tenants.clone())
        .unwrap_or_default()
    {
        let subject = entry
            .subject
            .ok_or_else(|| "daemon.input.nats_tenants entry missing 'subject'".to_string())?;
        let raw_tenant = entry
            .tenant
            .ok_or_else(|| "daemon.input.nats_tenants entry missing 'tenant'".to_string())?;
        let tenant = TenantId::new(&raw_tenant)
            .map_err(|error| format!("daemon.input.nats_tenants: {error}"))?;
        nats_tenants.push(NatsTenantBinding {
            subject,
            tenant,
            credentials_file: entry.credentials_file,
        });
    }

    Ok((settings, input_tenant, nats_tenants))
}

/// Parse the configured tokens for tenancy validation. Tenant ids are
/// validated here so an invalid one fails startup with its token name.
pub(crate) fn token_specs_for_tenancy(
    base: &crate::config::RsigmaConfigPartial,
    api_token_env_used: bool,
) -> Result<(Vec<super::auth::TokenSpec>, Vec<String>), String> {
    if api_token_env_used {
        return Ok((
            vec![super::auth::TokenSpec {
                name: "default".into(),
                role: Some("admin".into()),
                permissions: None,
                token_env: String::new(),
                tenant: None,
                all_tenants: false,
            }],
            Vec::new(),
        ));
    }
    let auth = base
        .daemon
        .as_ref()
        .and_then(|d| d.api.as_ref())
        .and_then(|a| a.auth.as_ref());
    let Some(auth) = auth else {
        return Ok((Vec::new(), Vec::new()));
    };
    let mut specs = Vec::new();
    for token in auth.tokens.clone().unwrap_or_default() {
        let name = token.name.unwrap_or_default();
        let tenant = token
            .tenant
            .as_deref()
            .map(TenantId::new)
            .transpose()
            .map_err(|error| format!("token '{name}': {error}"))?;
        specs.push(super::auth::TokenSpec {
            name,
            role: token.role,
            permissions: token.permissions,
            token_env: token.token_env.unwrap_or_default(),
            tenant,
            all_tenants: token.all_tenants.unwrap_or(false),
        });
    }
    Ok((
        specs,
        auth.anonymous_permissions.clone().unwrap_or_default(),
    ))
}

/// The daemon inputs after CLI flags are applied over the config files. Tenancy
/// validation reads these rather than the config files alone, so a flag such
/// as `--input` or `--output` cannot bypass a refusal.
pub(crate) struct ResolvedDaemonInputs<'a> {
    pub input_source: &'a str,
    pub sink_specs: &'a [String],
    pub ruleset_tenants: &'a [(String, Vec<TenantId>)],
    pub alert_pipeline: Option<&'a std::path::Path>,
    pub risk: Option<&'a std::path::Path>,
    pub enrichers: Option<&'a std::path::Path>,
    pub webhooks: &'a [PathBuf],
    pub disposition_source: bool,
}

/// Validate tenancy against the merged config and the resolved daemon inputs.
pub(crate) fn validate_tenancy_from_config(
    base: &crate::config::RsigmaConfigPartial,
    settings: &TenancySettings,
    input_tenant: Option<&TenantId>,
    nats_tenants: &[NatsTenantBinding],
    resolved: &ResolvedDaemonInputs<'_>,
    project_layer_loaded: bool,
    api_token_env_used: bool,
) -> Result<(), String> {
    let (token_specs, anonymous) = token_specs_for_tenancy(base, api_token_env_used)?;
    let auth_configured = api_token_env_used
        || base
            .daemon
            .as_ref()
            .and_then(|d| d.api.as_ref())
            .and_then(|a| a.auth.as_ref())
            .is_some();
    let mut alert_pipeline_nats_subjects = Vec::new();
    let mut scope_tenants: Vec<Vec<String>> = Vec::new();
    if let Some(path) = resolved.alert_pipeline
        && let Ok(file) = rsigma_runtime::load_alert_pipeline_file(path)
    {
        if let Some(group) = &file.group
            && let Some(subject) = &group.nats_subject
        {
            alert_pipeline_nats_subjects.push(subject.clone());
        }
        if let Some(scope) = &file.scope {
            scope_tenants.push(scope.tenants.clone());
        }
    }
    if let Some(path) = resolved.risk
        && let Ok(file) = rsigma_runtime::load_risk_file(path)
    {
        if let Some(subject) = &file.nats_subject {
            alert_pipeline_nats_subjects.push(subject.clone());
        }
        if let Some(incident) = &file.incident
            && let Some(subject) = &incident.nats_subject
        {
            alert_pipeline_nats_subjects.push(subject.clone());
        }
        if let Some(scope) = &file.scope {
            scope_tenants.push(scope.tenants.clone());
        }
    }
    if let Some(path) = resolved.enrichers
        && let Ok(file) = rsigma_runtime::load_enrichers_file(path)
    {
        for enricher in &file.enrichers {
            if let Some(scope) = &enricher.scope {
                scope_tenants.push(scope.tenants.clone());
            }
        }
    }
    for webhook in &super::webhook::load_webhook_paths(resolved.webhooks)?.webhooks {
        if let Some(scope) = &webhook.scope {
            scope_tenants.push(scope.tenants.clone());
        }
    }
    let input_tenant_str = input_tenant.map(|t| t.as_str().to_string());
    validate_tenancy(&TenancyValidation {
        settings,
        token_specs: &token_specs,
        anonymous_permissions: &anonymous,
        api_token_env_used,
        auth_configured,
        input_source: Some(resolved.input_source),
        input_tenant: input_tenant_str.as_deref(),
        nats_tenants,
        ruleset_tenants: resolved.ruleset_tenants,
        project_layer_loaded,
        sink_specs: resolved.sink_specs,
        alert_pipeline_nats_subjects: &alert_pipeline_nats_subjects,
        scope_tenants: &scope_tenants,
        disposition_source: resolved.disposition_source,
    })
}
