use serde::{Deserialize, Serialize};

use crate::event::{Event, EventValue};

/// Synthetic tenant for events missing the tenant field when
/// `MissingTenantPolicy::DefaultTenant` is configured.
pub const DEFAULT_TENANT: &str = "__default__";

/// Opaque tenant identifier extracted from events.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct TenantId(pub String);

impl TenantId {
    pub fn extract(event: &impl Event, tenant_field: &str) -> Option<Self> {
        event.get_field(tenant_field).and_then(|v| match v {
            EventValue::Str(s) => Some(TenantId(s.to_string())),
            EventValue::Int(n) => Some(TenantId(n.to_string())),
            _ => None,
        })
    }

    pub fn default_tenant() -> Self {
        TenantId(DEFAULT_TENANT.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
