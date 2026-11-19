//! Logical multi-tenancy: settings, startup refusals, and API tenant scoping.

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
}

impl From<TenantQuotasPartial> for TenantQuotas {
    fn from(partial: TenantQuotasPartial) -> Self {
        TenantQuotas {
            correlation_state: partial.correlation_state,
            active_alerts: partial.active_alerts,
            incidents: partial.incidents,
            risk_entities: partial.risk_entities,
        }
    }
}

/// One tenant-bound NATS subscription.
#[derive(Debug, Clone)]
pub(crate) struct NatsTenantBinding {
    pub subject: String,
    pub tenant: TenantId,
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
    // 5. Configured ids must be valid. TenantId::new already ran for tokens
    // and NATS bindings; validate the remaining string-typed bindings.
    for tenant in &v.settings.metrics_tenant_allowlist {
        let _ = tenant;
    }
    for (ruleset, tenants) in v.ruleset_tenants {
        for tenant in tenants {
            let _ = tenant;
        }
        if tenants.is_empty() {
            return Err(format!(
                "ruleset '{ruleset}' has an empty `tenants` binding; omit the key to admit every tenant"
            ));
        }
    }

    let source = v.input_source.unwrap_or("stdin");
    let nats_subject_source = source.starts_with("nats://") && nats_url_has_subject(source);
    // 6. A pull source needs an operator-declared tenant.
    if (source == "stdin"
        || source.starts_with("stdin://")
        || source.starts_with("unix://")
        || nats_subject_source)
        && v.input_tenant.is_none()
    {
        return Err(format!(
            "daemon.input.source '{source}' requires daemon.input.tenant while tenancy is enabled"
        ));
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
        return Ok(TenantFilter::All);
    };
    if identity.all_tenants {
        return match requested {
            None => Ok(TenantFilter::All),
            Some(requested) => parse_tenant(requested).map(TenantFilter::Only),
        };
    }
    let Some(own) = &identity.tenant else {
        return Ok(TenantFilter::All);
    };
    match requested {
        None => Ok(TenantFilter::Only(own.clone())),
        Some(requested) if requested == own.as_str() => Ok(TenantFilter::Only(own.clone())),
        Some(_) => Err(forbidden("the token may not read another tenant")),
    }
}

/// Resolve the tenant a write binds to. A tenant token always binds to its
/// own tenant; an `all_tenants` token must name one in the body.
pub(crate) fn write_tenant(
    enabled: bool,
    identity: Option<&AuthIdentity>,
    body_tenant: Option<&str>,
) -> Result<Option<TenantId>, Response> {
    if !enabled {
        return Ok(None);
    }
    let Some(identity) = identity else {
        return Ok(None);
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
        return Ok(None);
    };
    match body_tenant {
        None => Ok(Some(own.clone())),
        Some(body_tenant) if body_tenant == own.as_str() => Ok(Some(own.clone())),
        Some(_) => Err(forbidden("the token may not write another tenant")),
    }
}

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
        assert!(subjects_overlap("a.*", "a.b.c"));
        assert!(subjects_overlap("a.*.c", "a.b.*"));
        assert!(subjects_overlap("a", "a.>"));
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
    let mut settings = TenancySettings::default();
    settings.enabled = cli_tenancy || tenancy.and_then(|t| t.enabled).unwrap_or(false);
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

/// Validate tenancy against the merged config and the CLI flags.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_tenancy_from_config(
    base: &crate::config::RsigmaConfigPartial,
    settings: &TenancySettings,
    input_tenant: Option<&TenantId>,
    nats_tenants: &[NatsTenantBinding],
    ruleset_tenants: &[(String, Vec<TenantId>)],
    project_layer_loaded: bool,
    api_token_env_used: bool,
) -> Result<(), String> {
    let (token_specs, anonymous) = token_specs_for_tenancy(base, api_token_env_used)?;
    let auth_configured = base
        .daemon
        .as_ref()
        .and_then(|d| d.api.as_ref())
        .and_then(|a| a.auth.as_ref())
        .is_some();
    let input_source = base
        .daemon
        .as_ref()
        .and_then(|d| d.input.as_ref())
        .and_then(|i| i.source.as_deref());
    let sink_specs = base
        .daemon
        .as_ref()
        .and_then(|d| d.output.as_ref())
        .and_then(|o| o.sinks.clone())
        .unwrap_or_default();
    let input_tenant_str = input_tenant.map(|t| t.as_str().to_string());
    validate_tenancy(&TenancyValidation {
        settings,
        token_specs: &token_specs,
        anonymous_permissions: &anonymous,
        api_token_env_used,
        auth_configured,
        input_source,
        input_tenant: input_tenant_str.as_deref(),
        nats_tenants,
        ruleset_tenants,
        project_layer_loaded,
        sink_specs: &sink_specs,
        alert_pipeline_nats_subjects: &[],
        scope_tenants: &[],
    })
}
