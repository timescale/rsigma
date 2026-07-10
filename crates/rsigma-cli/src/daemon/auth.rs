//! Bearer-token authentication with granular `resource:action` RBAC for the
//! daemon API.
//!
//! Authentication is opt-in: without a `daemon.api.auth` config block (or the
//! `--api-token-env` flag) no middleware is mounted and the API behaves as
//! before. When enabled, every request must present a static bearer token
//! (`Authorization: Bearer <token>`) whose permission set covers the
//! permission required by the route, except `GET /healthz` and `GET /readyz`,
//! which stay open so liveness probes never need secrets.
//!
//! Token secrets follow the `secret_env` posture: the config names an
//! environment variable per token, resolved once at startup, and the value
//! never lives in YAML. Comparison is constant-time per candidate token.
//!
//! Permissions are `resource:action` strings. A granted permission may use
//! `*` as the resource, the action, or both (`*` alone is shorthand for
//! `*:*`); the permission required by a route is always concrete. Named
//! roles are permission sets; the built-in roles are `reader` (`*:read`),
//! `operator` (`*:read` plus every control-plane write except reload),
//! `ingest` (`events:ingest`), and `admin` (`*`).

use std::sync::Arc;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{Method, StatusCode, header::AUTHORIZATION};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::metrics::Metrics;

/// A permission: a resource plus an action, either of which may be the `*`
/// wildcard on the *granted* side. Required permissions are always concrete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permission {
    resource: String,
    action: String,
}

impl Permission {
    /// A concrete permission, used for route requirements.
    pub const fn required(resource: &'static str, action: &'static str) -> RequiredPermission {
        RequiredPermission { resource, action }
    }

    /// Parse a granted permission: `*`, `resource:*`, `*:action`, or
    /// `resource:action`. Resource and action must be lowercase
    /// `[a-z0-9_-]` identifiers (or `*`).
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s == "*" {
            return Ok(Self {
                resource: "*".into(),
                action: "*".into(),
            });
        }
        let (resource, action) = s
            .split_once(':')
            .ok_or_else(|| format!("invalid permission '{s}': expected 'resource:action'"))?;
        for part in [resource, action] {
            let valid = part == "*"
                || (!part.is_empty()
                    && part
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_-".contains(c)));
            if !valid {
                return Err(format!(
                    "invalid permission '{s}': '{part}' must be '*' or a lowercase \
                     [a-z0-9_-] identifier"
                ));
            }
        }
        Ok(Self {
            resource: resource.into(),
            action: action.into(),
        })
    }

    /// Does this granted permission cover the concrete `required` one?
    fn grants(&self, required: &RequiredPermission) -> bool {
        (self.resource == "*" || self.resource == required.resource)
            && (self.action == "*" || self.action == required.action)
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.resource, self.action)
    }
}

/// The concrete permission a route requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredPermission {
    resource: &'static str,
    action: &'static str,
}

impl std::fmt::Display for RequiredPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.resource, self.action)
    }
}

/// Permission required to ingest events (`POST /api/v1/events` and the OTLP
/// surfaces). Exposed for the gRPC handler, which authenticates from Tonic
/// metadata rather than through the axum middleware.
pub const EVENTS_INGEST: RequiredPermission = Permission::required("events", "ingest");

/// What a route demands: nothing (always open) or a concrete permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Always unauthenticated (`/healthz`, `/readyz`).
    Open,
    /// Requires a token (or anonymous grant) covering this permission.
    Require(RequiredPermission),
}

/// Map a method + route pattern (axum `MatchedPath`, e.g.
/// `/api/v1/silences/{id}`) to the permission it requires. Unknown routes
/// fail closed: they require the full `*` grant, so forgetting to extend
/// this table when adding a route locks the route down instead of leaving
/// it open.
pub fn required_access(method: &Method, path: &str) -> Access {
    use Access::{Open, Require};
    const fn req(resource: &'static str, action: &'static str) -> Access {
        Require(Permission::required(resource, action))
    }
    match (method, path) {
        (&Method::GET, "/healthz" | "/readyz") => Open,
        (&Method::GET, "/metrics") => req("metrics", "read"),
        (&Method::GET, "/api/v1/rules") => req("rules", "read"),
        (&Method::GET, "/api/v1/status") => req("status", "read"),
        (&Method::GET, "/api/v1/correlations" | "/api/v1/correlations/state") => {
            req("correlations", "read")
        }
        (&Method::GET, "/api/v1/incidents") => req("incidents", "read"),
        (&Method::GET, "/api/v1/risk") => req("risk", "read"),
        (&Method::GET, "/api/v1/silences") => req("silences", "read"),
        (&Method::POST, "/api/v1/silences") => req("silences", "write"),
        (&Method::DELETE, "/api/v1/silences/{id}") => req("silences", "write"),
        (&Method::GET, "/api/v1/dispositions") => req("dispositions", "read"),
        (&Method::POST, "/api/v1/dispositions") => req("dispositions", "write"),
        (&Method::POST, "/api/v1/reload") => req("reload", "execute"),
        (&Method::POST, "/api/v1/events" | "/v1/logs") => Require(EVENTS_INGEST),
        (&Method::GET, "/api/v1/sources") => req("sources", "read"),
        (&Method::POST, "/api/v1/sources/resolve" | "/api/v1/sources/resolve/{source_id}") => {
            req("sources", "write")
        }
        (&Method::DELETE, "/api/v1/sources/cache/{source_id}") => req("sources", "write"),
        (&Method::GET, "/api/v1/fields" | "/api/v1/fields/unknown" | "/api/v1/fields/missing") => {
            req("fields", "read")
        }
        (&Method::DELETE, "/api/v1/fields/observer") => req("fields", "write"),
        (&Method::GET, "/api/v1/schemas" | "/api/v1/schemas/suggestions") => req("schemas", "read"),
        (&Method::DELETE, "/api/v1/schemas") => req("schemas", "write"),
        (&Method::GET, "/api/v1/tap") => req("tap", "read"),
        (&Method::GET, "/api/v1/detections/stream") => req("detections", "read"),
        _ => req("*", "*"),
    }
}

/// The built-in role names and their permission sets.
pub const BUILTIN_ROLES: &[(&str, &[&str])] = &[
    ("reader", &["*:read"]),
    (
        "operator",
        &[
            "*:read",
            "silences:write",
            "dispositions:write",
            "sources:write",
            "fields:write",
            "schemas:write",
        ],
    ),
    ("ingest", &["events:ingest"]),
    ("admin", &["*"]),
];

/// An unresolved token declaration (from config or the `--api-token-env`
/// flag): a name, exactly one of `role` / inline `permissions`, and the
/// environment variable holding the secret.
#[derive(Debug, Clone)]
pub struct TokenSpec {
    pub name: String,
    pub role: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub token_env: String,
}

/// A resolved token: name, permission set, and the secret bytes.
#[derive(Debug, Clone)]
struct AuthToken {
    name: String,
    permissions: Vec<Permission>,
    secret: Vec<u8>,
}

/// The identity established by the auth middleware, inserted into request
/// extensions so handlers (and a future audit trail) can attribute the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthIdentity {
    /// The token name, or `None` for a request admitted via
    /// `anonymous_permissions`.
    pub token: Option<String>,
}

/// Outcome of checking a request's credentials against a required permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allowed(AuthIdentity),
    /// No credentials (and anonymous permissions do not cover the
    /// requirement), or an unrecognized token.
    Unauthorized,
    /// A recognized token whose permission set does not cover the
    /// requirement.
    Forbidden {
        token: String,
    },
}

/// The resolved authentication table for the daemon API.
#[derive(Debug, Clone, Default)]
pub struct ApiAuth {
    tokens: Vec<AuthToken>,
    anonymous: Vec<Permission>,
}

impl ApiAuth {
    /// Build and validate the auth table. `roles` are the operator-defined
    /// roles (merged over the built-ins, which they may not redefine);
    /// `anonymous` is the permission set granted to unauthenticated
    /// requests; `env` resolves an environment variable name to its value
    /// (injected for testability).
    pub fn build(
        roles: &[(String, Vec<String>)],
        tokens: &[TokenSpec],
        anonymous: &[String],
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, String> {
        let mut role_table: Vec<(String, Vec<Permission>)> = BUILTIN_ROLES
            .iter()
            .map(|(name, perms)| {
                let parsed = perms
                    .iter()
                    .map(|p| Permission::parse(p).expect("built-in role permission"))
                    .collect();
                (name.to_string(), parsed)
            })
            .collect();

        for (name, perms) in roles {
            if BUILTIN_ROLES.iter().any(|(builtin, _)| builtin == name) {
                return Err(format!(
                    "role '{name}' redefines a built-in role (reader, operator, ingest, admin)"
                ));
            }
            if role_table.iter().any(|(existing, _)| existing == name) {
                return Err(format!("duplicate role '{name}'"));
            }
            if perms.is_empty() {
                return Err(format!("role '{name}' has an empty permission list"));
            }
            let parsed = perms
                .iter()
                .map(|p| Permission::parse(p))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("role '{name}': {e}"))?;
            role_table.push((name.clone(), parsed));
        }

        let mut resolved: Vec<AuthToken> = Vec::with_capacity(tokens.len());
        for spec in tokens {
            if spec.name.is_empty() {
                return Err("token with empty name".into());
            }
            if resolved.iter().any(|t| t.name == spec.name) {
                return Err(format!("duplicate token name '{}'", spec.name));
            }
            let permissions = match (&spec.role, &spec.permissions) {
                (Some(role), None) => role_table
                    .iter()
                    .find(|(name, _)| name == role)
                    .map(|(_, perms)| perms.clone())
                    .ok_or_else(|| {
                        format!("token '{}' references unknown role '{role}'", spec.name)
                    })?,
                (None, Some(perms)) => {
                    if perms.is_empty() {
                        return Err(format!(
                            "token '{}' has an empty permission list",
                            spec.name
                        ));
                    }
                    perms
                        .iter()
                        .map(|p| Permission::parse(p))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| format!("token '{}': {e}", spec.name))?
                }
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "token '{}' sets both 'role' and 'permissions'; use exactly one",
                        spec.name
                    ));
                }
                (None, None) => {
                    return Err(format!(
                        "token '{}' needs a 'role' or a 'permissions' list",
                        spec.name
                    ));
                }
            };
            let secret = env(&spec.token_env).unwrap_or_default();
            if secret.is_empty() {
                return Err(format!(
                    "token '{}': environment variable '{}' is unset or empty",
                    spec.name, spec.token_env
                ));
            }
            if let Some(other) = resolved.iter().find(|t| t.secret == secret.as_bytes()) {
                return Err(format!(
                    "tokens '{}' and '{}' resolve to the same secret value",
                    other.name, spec.name
                ));
            }
            resolved.push(AuthToken {
                name: spec.name.clone(),
                permissions,
                secret: secret.into_bytes(),
            });
        }

        let anonymous = anonymous
            .iter()
            .map(|p| Permission::parse(p))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("anonymous_permissions: {e}"))?;

        Ok(Self {
            tokens: resolved,
            anonymous,
        })
    }

    /// Check an `Authorization` header value (if any) against a required
    /// permission. Every configured token is compared in constant time; a
    /// presented-but-unrecognized token is `Unauthorized` (it never falls
    /// back to the anonymous grants).
    pub fn check(&self, authorization: Option<&str>, required: RequiredPermission) -> Decision {
        let bearer = authorization.and_then(|value| value.strip_prefix("Bearer "));
        match bearer {
            Some(presented) => {
                let mut matched: Option<&AuthToken> = None;
                for token in &self.tokens {
                    if constant_time_eq(presented.as_bytes(), &token.secret) {
                        matched = Some(token);
                    }
                }
                match matched {
                    Some(token) => {
                        if token.permissions.iter().any(|p| p.grants(&required)) {
                            Decision::Allowed(AuthIdentity {
                                token: Some(token.name.clone()),
                            })
                        } else {
                            Decision::Forbidden {
                                token: token.name.clone(),
                            }
                        }
                    }
                    None => Decision::Unauthorized,
                }
            }
            None => {
                if self.anonymous.iter().any(|p| p.grants(&required)) {
                    Decision::Allowed(AuthIdentity { token: None })
                } else {
                    Decision::Unauthorized
                }
            }
        }
    }
}

/// State handed to the auth middleware: the resolved table plus the metrics
/// handle for the failure counter.
pub struct AuthLayerState {
    pub auth: ApiAuth,
    pub metrics: Arc<Metrics>,
}

/// Axum middleware enforcing [`ApiAuth`] on every matched route. Mounted via
/// `Router::layer`, so it runs only for requests that matched a route (a 404
/// needs no credentials) and `MatchedPath` carries the route pattern.
pub async fn api_auth_middleware(
    State(state): State<Arc<AuthLayerState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| request.uri().path().to_owned());
    let required = match required_access(request.method(), &path) {
        Access::Open => return next.run(request).await,
        Access::Require(required) => required,
    };

    let authorization = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    match state.auth.check(authorization, required) {
        Decision::Allowed(identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Decision::Unauthorized => {
            state
                .metrics
                .api_auth_failures
                .with_label_values(&["unauthorized"])
                .inc();
            tracing::warn!(path = %path, "API auth failure: missing or invalid bearer token");
            (
                StatusCode::UNAUTHORIZED,
                [("www-authenticate", "Bearer")],
                axum::Json(serde_json::json!({
                    "error": "missing or invalid bearer token"
                })),
            )
                .into_response()
        }
        Decision::Forbidden { token } => {
            state
                .metrics
                .api_auth_failures
                .with_label_values(&["forbidden"])
                .inc();
            tracing::warn!(
                path = %path,
                token = %token,
                required = %required,
                "API auth failure: token lacks required permission"
            );
            (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({
                    "error": format!("token lacks required permission '{required}'")
                })),
            )
                .into_response()
        }
    }
}

/// Constant-time byte comparison so token checks do not leak the matched
/// prefix length via timing. (The overall length is not secret for a bearer
/// token.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    fn spec(name: &str, role: &str, env_var: &str) -> TokenSpec {
        TokenSpec {
            name: name.into(),
            role: Some(role.into()),
            permissions: None,
            token_env: env_var.into(),
        }
    }

    #[test]
    fn permission_parse_accepts_wildcards() {
        assert!(Permission::parse("*").is_ok());
        assert!(Permission::parse("silences:*").is_ok());
        assert!(Permission::parse("*:read").is_ok());
        assert!(Permission::parse("events:ingest").is_ok());
    }

    #[test]
    fn permission_parse_rejects_malformed() {
        for bad in ["", "silences", "Silences:read", "a b:read", "res:", ":act"] {
            assert!(Permission::parse(bad).is_err(), "should reject '{bad}'");
        }
    }

    #[test]
    fn permission_grants_wildcards() {
        let read_all = Permission::parse("*:read").unwrap();
        assert!(read_all.grants(&Permission::required("rules", "read")));
        assert!(!read_all.grants(&Permission::required("silences", "write")));

        let silences = Permission::parse("silences:*").unwrap();
        assert!(silences.grants(&Permission::required("silences", "write")));
        assert!(!silences.grants(&Permission::required("rules", "read")));

        let all = Permission::parse("*").unwrap();
        assert!(all.grants(&Permission::required("reload", "execute")));
    }

    #[test]
    fn builtin_roles_parse() {
        for (name, perms) in BUILTIN_ROLES {
            for p in *perms {
                assert!(Permission::parse(p).is_ok(), "role {name} permission {p}");
            }
        }
    }

    #[test]
    fn every_route_has_a_mapping() {
        // The routes mounted in server.rs. Adding a route without extending
        // required_access fails closed (requires the full '*' grant), but the
        // mapping should still be explicit; this list is the reminder.
        let routes: &[(Method, &str)] = &[
            (Method::GET, "/healthz"),
            (Method::GET, "/readyz"),
            (Method::GET, "/metrics"),
            (Method::GET, "/api/v1/rules"),
            (Method::GET, "/api/v1/status"),
            (Method::GET, "/api/v1/correlations"),
            (Method::GET, "/api/v1/correlations/state"),
            (Method::GET, "/api/v1/incidents"),
            (Method::GET, "/api/v1/risk"),
            (Method::GET, "/api/v1/silences"),
            (Method::POST, "/api/v1/silences"),
            (Method::DELETE, "/api/v1/silences/{id}"),
            (Method::GET, "/api/v1/dispositions"),
            (Method::POST, "/api/v1/dispositions"),
            (Method::POST, "/api/v1/reload"),
            (Method::POST, "/api/v1/events"),
            (Method::GET, "/api/v1/sources"),
            (Method::POST, "/api/v1/sources/resolve"),
            (Method::POST, "/api/v1/sources/resolve/{source_id}"),
            (Method::DELETE, "/api/v1/sources/cache/{source_id}"),
            (Method::GET, "/api/v1/fields"),
            (Method::GET, "/api/v1/fields/unknown"),
            (Method::GET, "/api/v1/fields/missing"),
            (Method::DELETE, "/api/v1/fields/observer"),
            (Method::GET, "/api/v1/schemas"),
            (Method::GET, "/api/v1/schemas/suggestions"),
            (Method::DELETE, "/api/v1/schemas"),
            (Method::GET, "/api/v1/tap"),
            (Method::GET, "/api/v1/detections/stream"),
            (Method::POST, "/v1/logs"),
        ];
        let catch_all = Access::Require(Permission::required("*", "*"));
        for (method, path) in routes {
            let access = required_access(method, path);
            let open = matches!(access, Access::Open);
            assert!(
                access != catch_all || open,
                "route {method} {path} fell through to the fail-closed catch-all"
            );
        }
    }

    #[test]
    fn unknown_route_fails_closed() {
        let access = required_access(&Method::GET, "/api/v1/brand-new");
        assert_eq!(
            access,
            Access::Require(Permission::required("*", "*")),
            "unmapped routes must require the full wildcard grant"
        );
    }

    #[test]
    fn health_routes_are_open() {
        assert_eq!(required_access(&Method::GET, "/healthz"), Access::Open);
        assert_eq!(required_access(&Method::GET, "/readyz"), Access::Open);
    }

    #[test]
    fn build_resolves_roles_and_secrets() {
        let auth = ApiAuth::build(
            &[(
                "triage".into(),
                vec!["*:read".into(), "silences:write".into()],
            )],
            &[
                spec("grafana", "reader", "TOK_A"),
                spec("bot", "triage", "TOK_B"),
            ],
            &[],
            env_of(&[("TOK_A", "secret-a"), ("TOK_B", "secret-b")]),
        )
        .unwrap();

        let read = Permission::required("rules", "read");
        let write = Permission::required("silences", "write");
        assert!(matches!(
            auth.check(Some("Bearer secret-a"), read),
            Decision::Allowed(AuthIdentity { token: Some(name) }) if name == "grafana"
        ));
        assert!(matches!(
            auth.check(Some("Bearer secret-a"), write),
            Decision::Forbidden { token } if token == "grafana"
        ));
        assert!(matches!(
            auth.check(Some("Bearer secret-b"), write),
            Decision::Allowed(_)
        ));
    }

    #[test]
    fn build_rejects_missing_env() {
        let err =
            ApiAuth::build(&[], &[spec("a", "reader", "MISSING")], &[], |_| None).unwrap_err();
        assert!(err.contains("MISSING"), "{err}");
    }

    #[test]
    fn build_rejects_builtin_role_redefinition() {
        let err = ApiAuth::build(&[("admin".into(), vec!["*:read".into()])], &[], &[], |_| {
            None
        })
        .unwrap_err();
        assert!(err.contains("built-in"), "{err}");
    }

    #[test]
    fn build_rejects_duplicate_token_names_and_secrets() {
        let env = env_of(&[("TOK_A", "same"), ("TOK_B", "same")]);
        let err = ApiAuth::build(
            &[],
            &[spec("a", "reader", "TOK_A"), spec("a", "reader", "TOK_B")],
            &[],
            &env,
        )
        .unwrap_err();
        assert!(err.contains("duplicate token name"), "{err}");

        let err = ApiAuth::build(
            &[],
            &[spec("a", "reader", "TOK_A"), spec("b", "reader", "TOK_B")],
            &[],
            &env,
        )
        .unwrap_err();
        assert!(err.contains("same secret"), "{err}");
    }

    #[test]
    fn build_rejects_role_and_permissions_together() {
        let err = ApiAuth::build(
            &[],
            &[TokenSpec {
                name: "a".into(),
                role: Some("reader".into()),
                permissions: Some(vec!["*:read".into()]),
                token_env: "TOK".into(),
            }],
            &[],
            env_of(&[("TOK", "x")]),
        )
        .unwrap_err();
        assert!(err.contains("exactly one"), "{err}");
    }

    #[test]
    fn anonymous_permissions_admit_without_token() {
        let auth = ApiAuth::build(
            &[],
            &[spec("ops", "admin", "TOK")],
            &["metrics:read".to_string()],
            env_of(&[("TOK", "s")]),
        )
        .unwrap();

        assert!(matches!(
            auth.check(None, Permission::required("metrics", "read")),
            Decision::Allowed(AuthIdentity { token: None })
        ));
        assert_eq!(
            auth.check(None, Permission::required("rules", "read")),
            Decision::Unauthorized
        );
    }

    #[test]
    fn invalid_token_never_falls_back_to_anonymous() {
        let auth = ApiAuth::build(
            &[],
            &[spec("ops", "admin", "TOK")],
            &["*:read".to_string()],
            env_of(&[("TOK", "s")]),
        )
        .unwrap();
        // Anonymous may read, but a wrong token is rejected outright.
        assert_eq!(
            auth.check(Some("Bearer wrong"), Permission::required("rules", "read")),
            Decision::Unauthorized
        );
    }

    #[test]
    fn ingest_role_cannot_touch_control_endpoints() {
        let auth = ApiAuth::build(
            &[],
            &[spec("shipper", "ingest", "TOK")],
            &[],
            env_of(&[("TOK", "s")]),
        )
        .unwrap();
        assert!(matches!(
            auth.check(Some("Bearer s"), EVENTS_INGEST),
            Decision::Allowed(_)
        ));
        assert!(matches!(
            auth.check(Some("Bearer s"), Permission::required("silences", "write")),
            Decision::Forbidden { .. }
        ));
        assert!(matches!(
            auth.check(Some("Bearer s"), Permission::required("status", "read")),
            Decision::Forbidden { .. }
        ));
    }

    #[test]
    fn operator_role_excludes_reload() {
        let auth = ApiAuth::build(
            &[],
            &[spec("op", "operator", "TOK")],
            &[],
            env_of(&[("TOK", "s")]),
        )
        .unwrap();
        assert!(matches!(
            auth.check(Some("Bearer s"), Permission::required("silences", "write")),
            Decision::Allowed(_)
        ));
        assert!(matches!(
            auth.check(Some("Bearer s"), Permission::required("reload", "execute")),
            Decision::Forbidden { .. }
        ));
    }

    #[test]
    fn constant_time_eq_matches() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secrey"));
        assert!(!constant_time_eq(b"secret", b"secretx"));
        assert!(!constant_time_eq(b"", b"x"));
    }
}
