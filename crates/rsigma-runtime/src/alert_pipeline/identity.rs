//! Exact identity for dedup alerts and `group_by` incidents.
//!
//! An [`IdentityKey`] holds the tenant, the rule identity (dedup only), and
//! every configured selector with its typed value. The dedup and incident
//! stores key on it directly, so two results share an alert or an incident
//! only when those parts are equal. The short ids carried on the wire
//! (`dedup_fingerprint`, `incident_id`) are display ids derived from the key
//! with SHA-256; a store that finds a display id already held by a different
//! key derives the next candidate instead, so a display id never names two
//! live identities.

use std::fmt::Write as _;
use std::hash::{BuildHasher, Hash, Hasher, RandomState};
use std::sync::{Arc, OnceLock};

use rsigma_eval::{EvaluationResult, TenantId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::selector::Selector;

/// One selector's resolved value inside an [`IdentityKey`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum KeyValue {
    /// The selector resolved to nothing.
    Absent,
    /// The selector resolved to JSON `null`.
    Null,
    Bool(bool),
    /// A number in its JSON text form, so `1` and `1.0` stay distinct.
    Number(String),
    String(String),
    /// An array or object as canonical JSON (object keys sorted).
    Json(String),
}

impl KeyValue {
    fn of(value: Option<Value>) -> Self {
        match value {
            None => KeyValue::Absent,
            Some(Value::Null) => KeyValue::Null,
            Some(Value::Bool(b)) => KeyValue::Bool(b),
            Some(Value::Number(n)) => KeyValue::Number(n.to_string()),
            Some(Value::String(s)) => KeyValue::String(s),
            Some(other) => {
                let mut out = String::new();
                canonical_json(&other, &mut out);
                KeyValue::Json(out)
            }
        }
    }
}

/// The rule half of a dedup identity. A rule id and a rule title are kept
/// apart, so one rule's id never matches another rule's title.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuleIdentity {
    Id(String),
    Title(String),
}

impl RuleIdentity {
    fn of(result: &EvaluationResult) -> Self {
        match &result.header.rule_id {
            Some(id) => RuleIdentity::Id(id.clone()),
            None => RuleIdentity::Title(result.header.rule_title.clone()),
        }
    }
}

/// The exact identity of a dedup alert or a `group_by` incident: the tenant,
/// the rule (dedup only), and every configured selector with its typed value.
///
/// Two keys are equal only when every part is equal, so an absent selector,
/// JSON `null`, the string `"null"`, the string `"123"`, and the number `123`
/// are all different values.
///
/// ```
/// use std::collections::HashMap;
/// use std::sync::Arc;
///
/// use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
/// use rsigma_runtime::{IdentityKey, Selector};
///
/// let result = |value: serde_json::Value| EvaluationResult {
///     header: RuleHeader {
///         rule_title: "Brute force".into(),
///         rule_id: Some("rule-1".into()),
///         tenant_id: None,
///         level: None,
///         tags: vec![],
///         custom_attributes: Arc::new(HashMap::new()),
///         enrichments: None,
///         ruleset: None,
///     },
///     body: ResultBody::Detection(DetectionBody {
///         matched_selections: vec![],
///         matched_fields: vec![FieldMatch::new("Port", value)],
///         event: None,
///     }),
/// };
/// let by = [Selector::parse("match.Port").unwrap()];
/// assert_eq!(
///     IdentityKey::group(&by, &result(serde_json::json!(22))),
///     IdentityKey::group(&by, &result(serde_json::json!(22))),
/// );
/// assert_ne!(
///     IdentityKey::group(&by, &result(serde_json::json!(22))),
///     IdentityKey::group(&by, &result(serde_json::json!("22"))),
/// );
/// ```
#[derive(Debug, Clone)]
pub struct IdentityKey {
    /// `parts` hashed once with a per-process random key, so a store lookup
    /// does not rehash every selector value. Never persisted.
    hash: u64,
    parts: KeyParts,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct KeyParts {
    tenant: Option<TenantId>,
    rule: Option<RuleIdentity>,
    /// Selector names, shared by every key built from one selector list and
    /// index-aligned with `values`.
    names: Arc<[String]>,
    values: Vec<KeyValue>,
}

/// The persisted form of [`KeyParts`], with each name beside its value.
#[derive(Serialize)]
struct KeyPartsRef<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: &'a Option<TenantId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: &'a Option<RuleIdentity>,
    selectors: Vec<(&'a str, &'a KeyValue)>,
}

#[derive(Deserialize)]
struct KeyPartsOwned {
    #[serde(default)]
    tenant: Option<TenantId>,
    #[serde(default)]
    rule: Option<RuleIdentity>,
    selectors: Vec<(String, KeyValue)>,
}

impl KeyParts {
    fn new(
        tenant: Option<TenantId>,
        rule: Option<RuleIdentity>,
        selectors: Vec<(String, KeyValue)>,
    ) -> Self {
        let (names, values): (Vec<String>, Vec<KeyValue>) = selectors.into_iter().unzip();
        KeyParts {
            tenant,
            rule,
            names: names.into(),
            values,
        }
    }
}

impl PartialEq for IdentityKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.parts == other.parts
    }
}

impl Eq for IdentityKey {}

impl Hash for IdentityKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl Serialize for IdentityKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let parts = &self.parts;
        KeyPartsRef {
            tenant: &parts.tenant,
            rule: &parts.rule,
            selectors: parts
                .names
                .iter()
                .map(String::as_str)
                .zip(&parts.values)
                .collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IdentityKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let owned = KeyPartsOwned::deserialize(deserializer)?;
        Ok(IdentityKey::from_parts(KeyParts::new(
            owned.tenant,
            owned.rule,
            owned.selectors,
        )))
    }
}

/// The names of `selectors`, built once per selector list and shared by every
/// key built from it.
pub(crate) fn selector_names(selectors: &[Selector]) -> Arc<[String]> {
    selectors.iter().map(Selector::as_str).collect()
}

impl IdentityKey {
    /// The dedup identity of `result`: its tenant, rule, and the values of
    /// the `dedup.fingerprint` selectors.
    pub fn dedup(selectors: &[Selector], result: &EvaluationResult) -> Self {
        Self::dedup_named(&selector_names(selectors), selectors, result)
    }

    /// [`Self::dedup`] with the names of `selectors` already built.
    pub(crate) fn dedup_named(
        names: &Arc<[String]>,
        selectors: &[Selector],
        result: &EvaluationResult,
    ) -> Self {
        Self::build(Some(RuleIdentity::of(result)), names, selectors, result)
    }

    /// The `group_by` incident identity of `result`: its tenant and the
    /// values of the `group.by` selectors. The rule is left out so one
    /// incident can span rules that share the group values.
    pub fn group(selectors: &[Selector], result: &EvaluationResult) -> Self {
        Self::group_named(&selector_names(selectors), selectors, result)
    }

    /// [`Self::group`] with the names of `selectors` already built.
    pub(crate) fn group_named(
        names: &Arc<[String]>,
        selectors: &[Selector],
        result: &EvaluationResult,
    ) -> Self {
        Self::build(None, names, selectors, result)
    }

    fn build(
        rule: Option<RuleIdentity>,
        names: &Arc<[String]>,
        selectors: &[Selector],
        result: &EvaluationResult,
    ) -> Self {
        Self::from_parts(KeyParts {
            tenant: result.header.tenant_id.clone(),
            rule,
            names: Arc::clone(names),
            values: selectors
                .iter()
                .map(|sel| KeyValue::of(sel.resolve(result)))
                .collect(),
        })
    }

    fn from_parts(parts: KeyParts) -> Self {
        static STATE: OnceLock<RandomState> = OnceLock::new();
        IdentityKey {
            hash: STATE.get_or_init(RandomState::new).hash_one(&parts),
            parts,
        }
    }

    /// The tenant this identity belongs to.
    pub fn tenant(&self) -> Option<&TenantId> {
        self.parts.tenant.as_ref()
    }

    /// The selector names, in configured order.
    pub(crate) fn names(&self) -> &[String] {
        &self.parts.names
    }

    /// The display id for `attempt` (0 for the natural id): the first 128
    /// bits of SHA-256 over a length-prefixed encoding of the key, in hex.
    fn display_id(&self, attempt: u32) -> String {
        #[cfg(test)]
        if let Some(forced) = FORCED_DISPLAY_ID.with(std::cell::Cell::get) {
            return forced(self, attempt);
        }
        let parts = &self.parts;
        let mut hasher = Sha256::new();
        hasher.update(b"rsigma.identity.v1");
        match &parts.tenant {
            None => hasher.update([0]),
            Some(tenant) => put(&mut hasher, 1, tenant.as_str()),
        }
        match &parts.rule {
            None => hasher.update([0]),
            Some(RuleIdentity::Id(id)) => put(&mut hasher, 1, id),
            Some(RuleIdentity::Title(title)) => put(&mut hasher, 2, title),
        }
        hasher.update((parts.values.len() as u64).to_be_bytes());
        for (name, value) in parts.names.iter().zip(&parts.values) {
            put(&mut hasher, 0, name);
            match value {
                KeyValue::Absent => hasher.update([0]),
                KeyValue::Null => hasher.update([1]),
                KeyValue::Bool(b) => hasher.update([2, u8::from(*b)]),
                KeyValue::Number(n) => put(&mut hasher, 3, n),
                KeyValue::String(s) => put(&mut hasher, 4, s),
                KeyValue::Json(j) => put(&mut hasher, 5, j),
            }
        }
        hasher.update(attempt.to_be_bytes());
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut id = String::with_capacity(32);
        for byte in &hasher.finalize()[..16] {
            id.push(char::from(HEX[usize::from(byte >> 4)]));
            id.push(char::from(HEX[usize::from(byte & 0xf)]));
        }
        id
    }

    /// The first display id for this key that `taken` does not report as
    /// held. Callers only ask for keys they do not hold, so a held candidate
    /// always belongs to a different key.
    pub(crate) fn allocate_id(&self, taken: impl Fn(&str) -> bool) -> String {
        let mut attempt = 0u32;
        loop {
            let id = self.display_id(attempt);
            if !taken(&id) {
                return id;
            }
            attempt = attempt.wrapping_add(1);
        }
    }
}

/// A tagged, length-prefixed field, so no field can run into the next.
fn put(hasher: &mut Sha256, tag: u8, s: &str) {
    hasher.update([tag]);
    hasher.update((s.len() as u64).to_be_bytes());
    hasher.update(s.as_bytes());
}

/// JSON text with object keys sorted at every level, so equal values encode
/// identically whatever their key order.
fn canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(out, "{}", Value::String(k.clone()));
                out.push(':');
                canonical_json(v, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out);
            }
            out.push(']');
        }
        other => {
            let _ = write!(out, "{other}");
        }
    }
}

/// The resolved selector values shown on emitted records, under the names
/// of `selectors`. An absent selector shows as `null`.
pub(crate) fn display_values(
    names: &[String],
    selectors: &[Selector],
    result: &EvaluationResult,
) -> Vec<(String, Value)> {
    names
        .iter()
        .zip(selectors)
        .map(|(name, sel)| (name.clone(), sel.resolve(result).unwrap_or(Value::Null)))
        .collect()
}

/// Rebuild the identity of a dedup alert persisted before keys were stored,
/// from its tenant, its sample's rule fields, and its resolved values.
///
/// Those values record an absent selector as `null`. The old fingerprint
/// told the two apart, so for up to 8 `null` values each is resolved to
/// whichever reading reproduces `fingerprint`; otherwise `null` is read as
/// absent.
pub(crate) fn rebuild_dedup_key(
    fingerprint: &str,
    tenant: Option<&TenantId>,
    sample: &Value,
    fields: &[(String, Value)],
) -> Option<IdentityKey> {
    let rule = match sample.get("rule_id").and_then(Value::as_str) {
        Some(id) => RuleIdentity::Id(id.to_string()),
        None => RuleIdentity::Title(sample.get("rule_title")?.as_str()?.to_string()),
    };
    let rule_text = match &rule {
        RuleIdentity::Id(s) | RuleIdentity::Title(s) => s.as_str(),
    };
    let nulls: Vec<usize> = (0..fields.len())
        .filter(|&i| fields[i].1.is_null())
        .collect();
    let mut absent = vec![true; fields.len()];
    if nulls.len() <= 8 {
        for mask in 0u32..(1 << nulls.len()) {
            for (bit, &i) in nulls.iter().enumerate() {
                absent[i] = mask & (1 << bit) == 0;
            }
            if legacy_dedup_fingerprint(tenant, rule_text, fields, &absent) == fingerprint {
                break;
            }
            absent.fill(true);
        }
    }
    Some(IdentityKey::from_parts(KeyParts::new(
        tenant.cloned(),
        Some(rule),
        fields
            .iter()
            .zip(&absent)
            .map(|((name, value), &absent)| {
                let value = (!(absent && value.is_null())).then(|| value.clone());
                (name.clone(), KeyValue::of(value))
            })
            .collect(),
    )))
}

/// Rebuild the identity of a `group_by` incident persisted before keys were
/// stored. Returns `None` when `id` is not the old fingerprint of `values`,
/// which is the case for `entity_graph` incidents. The old fingerprint read
/// an absent selector and `null` alike, so `null` is read as absent.
pub(crate) fn rebuild_group_key(
    id: &str,
    tenant: Option<&TenantId>,
    values: &[(String, Value)],
) -> Option<IdentityKey> {
    if values.is_empty() || legacy_group_fingerprint(tenant, values) != id {
        return None;
    }
    Some(IdentityKey::from_parts(KeyParts::new(
        tenant.cloned(),
        None,
        values
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    KeyValue::of(Some(value.clone()).filter(|v| !v.is_null())),
                )
            })
            .collect(),
    )))
}

/// The dedup fingerprint as computed before keys were stored.
fn legacy_dedup_fingerprint(
    tenant: Option<&TenantId>,
    rule: &str,
    fields: &[(String, Value)],
    absent: &[bool],
) -> String {
    let mut buf = String::new();
    if let Some(tenant) = tenant {
        buf.push_str("tenant=");
        buf.push_str(tenant.as_str());
        buf.push('\u{1f}');
    }
    buf.push_str("rule=");
    buf.push_str(rule);
    for ((name, value), &absent) in fields.iter().zip(absent) {
        buf.push('\u{1f}');
        buf.push_str(name);
        buf.push('=');
        match value {
            Value::Null if absent => buf.push_str("\u{0}null"),
            Value::String(s) => buf.push_str(s),
            other => buf.push_str(&other.to_string()),
        }
    }
    format!("{:016x}", legacy_fnv1a64(buf.as_bytes()))
}

/// The `group_by` incident id as computed before keys were stored.
fn legacy_group_fingerprint(tenant: Option<&TenantId>, values: &[(String, Value)]) -> String {
    let mut buf = String::new();
    if let Some(tenant) = tenant {
        buf.push_str("tenant=");
        buf.push_str(tenant.as_str());
        buf.push('\u{1f}');
    }
    for (name, value) in values {
        buf.push('\u{1f}');
        buf.push_str(name);
        buf.push('=');
        match value {
            Value::String(s) => buf.push_str(s),
            other => buf.push_str(&other.to_string()),
        }
    }
    format!("{:016x}", legacy_fnv1a64(buf.as_bytes()))
}

fn legacy_fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A display-id derivation a test substitutes for SHA-256.
#[cfg(test)]
type DisplayIdFn = fn(&IdentityKey, u32) -> String;

#[cfg(test)]
thread_local! {
    static FORCED_DISPLAY_ID: std::cell::Cell<Option<DisplayIdFn>> =
        const { std::cell::Cell::new(None) };
}

/// Replace display-id derivation on this thread until the guard drops, so a
/// test can make distinct keys share a natural display id.
#[cfg(test)]
pub(crate) fn force_display_id(f: DisplayIdFn) -> ForcedDisplayId {
    FORCED_DISPLAY_ID.with(|cell| cell.set(Some(f)));
    ForcedDisplayId
}

#[cfg(test)]
pub(crate) struct ForcedDisplayId;

#[cfg(test)]
impl Drop for ForcedDisplayId {
    fn drop(&mut self) {
        FORCED_DISPLAY_ID.with(|cell| cell.set(None));
    }
}

#[cfg(test)]
impl IdentityKey {
    /// A `group_by` key over one `match.X` selector.
    pub(crate) fn test_group(tenant: Option<&str>, value: &str) -> Self {
        IdentityKey::from_parts(KeyParts::new(
            tenant.map(|t| TenantId::new(t).unwrap()),
            None,
            vec![("match.X".to_string(), KeyValue::String(value.to_string()))],
        ))
    }
}

/// A display id derivation that maps every key to the same natural id.
#[cfg(test)]
pub(crate) fn colliding_display_id(_: &IdentityKey, attempt: u32) -> String {
    format!("{:032x}", attempt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::{DetectionBody, FieldMatch, ResultBody, RuleHeader};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn result(fields: Vec<(&str, Value)>) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "Brute force".to_string(),
                rule_id: Some("rule-1".to_string()),
                tenant_id: None,
                level: None,
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: fields
                    .into_iter()
                    .map(|(f, v)| FieldMatch::new(f, v))
                    .collect(),
                event: None,
            }),
        }
    }

    fn sels(names: &[&str]) -> Vec<Selector> {
        names.iter().map(|n| Selector::parse(n).unwrap()).collect()
    }

    #[test]
    fn values_that_used_to_encode_alike_are_distinct_keys() {
        let by = sels(&["match.A"]);
        let keys = [
            IdentityKey::dedup(&by, &result(vec![])),
            IdentityKey::dedup(&by, &result(vec![("A", Value::Null)])),
            IdentityKey::dedup(&by, &result(vec![("A", json!("null"))])),
            IdentityKey::dedup(&by, &result(vec![("A", json!("\u{0}null"))])),
            IdentityKey::dedup(&by, &result(vec![("A", json!(123))])),
            IdentityKey::dedup(&by, &result(vec![("A", json!("123"))])),
            IdentityKey::dedup(&by, &result(vec![("A", json!(true))])),
            IdentityKey::dedup(&by, &result(vec![("A", json!("true"))])),
            IdentityKey::dedup(&by, &result(vec![("A", json!(["x"]))])),
            IdentityKey::dedup(&by, &result(vec![("A", json!("[\"x\"]"))])),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b);
                assert_ne!(a.display_id(0), b.display_id(0));
            }
        }
    }

    #[test]
    fn a_separator_inside_a_value_cannot_shift_fields() {
        let by = sels(&["match.A", "match.B"]);
        let a = result(vec![("A", json!("1\u{1f}match.B=2")), ("B", json!("3"))]);
        let b = result(vec![("A", json!("1")), ("B", json!("2\u{1f}match.B=3"))]);
        assert_ne!(IdentityKey::dedup(&by, &a), IdentityKey::dedup(&by, &b));
        assert_ne!(IdentityKey::group(&by, &a), IdentityKey::group(&by, &b));
    }

    #[test]
    fn the_separator_pair_shared_an_old_fingerprint() {
        let a = [
            ("match.A".to_string(), json!("1\u{1f}match.B=2")),
            ("match.B".to_string(), json!("3")),
        ];
        let b = [
            ("match.A".to_string(), json!("1")),
            ("match.B".to_string(), json!("2\u{1f}match.B=3")),
        ];
        let present = [false, false];
        assert_eq!(
            legacy_dedup_fingerprint(None, "r", &a, &present),
            legacy_dedup_fingerprint(None, "r", &b, &present)
        );
        assert_eq!(
            legacy_group_fingerprint(None, &a),
            legacy_group_fingerprint(None, &b)
        );
    }

    #[test]
    fn object_key_order_does_not_change_the_key() {
        let by = sels(&["match.A"]);
        let a: Value = serde_json::from_str(r#"{"x":1,"y":{"b":2,"a":3}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"y":{"a":3,"b":2},"x":1}"#).unwrap();
        let ka = IdentityKey::group(&by, &result(vec![("A", a)]));
        let kb = IdentityKey::group(&by, &result(vec![("A", b)]));
        assert_eq!(ka, kb);
        assert_eq!(ka.display_id(0), kb.display_id(0));
    }

    #[test]
    fn rule_id_and_rule_title_are_distinct() {
        let by = sels(&["match.A"]);
        let with_id = result(vec![("A", json!("x"))]);
        let mut titled = with_id.clone();
        titled.header.rule_id = None;
        titled.header.rule_title = "rule-1".to_string();
        assert_ne!(
            IdentityKey::dedup(&by, &with_id),
            IdentityKey::dedup(&by, &titled)
        );
    }

    #[test]
    fn the_tenant_is_part_of_the_key_and_the_display_id() {
        let by = sels(&["match.A"]);
        let mut a = result(vec![("A", json!("x"))]);
        let mut b = a.clone();
        a.header.tenant_id = Some(TenantId::new("a").unwrap());
        b.header.tenant_id = Some(TenantId::new("b").unwrap());
        let (ka, kb) = (IdentityKey::group(&by, &a), IdentityKey::group(&by, &b));
        assert_ne!(ka, kb);
        assert_ne!(ka.display_id(0), kb.display_id(0));
    }

    #[test]
    fn display_ids_are_stable_128_bit_hex() {
        let by = sels(&["match.A"]);
        let key = IdentityKey::group(&by, &result(vec![("A", json!("10.0.0.1"))]));
        let id = key.display_id(0);
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(id, key.clone().display_id(0));
        assert_ne!(id, key.display_id(1));
    }

    #[test]
    fn allocation_skips_ids_held_by_other_keys() {
        let by = sels(&["match.A"]);
        let key = IdentityKey::group(&by, &result(vec![("A", json!("x"))]));
        let natural = key.display_id(0);
        assert_eq!(key.allocate_id(|_| false), natural);
        assert_eq!(key.allocate_id(|id| id == natural), key.display_id(1));
    }

    #[test]
    fn the_key_round_trips_through_serde() {
        let by = sels(&["match.A", "match.B", "match.C"]);
        let mut r = result(vec![("A", json!({"k": [1, 2.5]})), ("B", Value::Null)]);
        r.header.tenant_id = Some(TenantId::new("t").unwrap());
        let key = IdentityKey::dedup(&by, &r);
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(serde_json::from_str::<IdentityKey>(&json).unwrap(), key);
    }

    #[test]
    fn a_legacy_dedup_entry_rebuilds_the_key_its_fingerprint_names() {
        let by = sels(&["match.A", "match.B"]);
        for fields in [
            vec![("B", json!("y"))],
            vec![("A", Value::Null), ("B", json!("y"))],
            vec![("A", Value::Null)],
        ] {
            let r = result(fields);
            let key = IdentityKey::dedup(&by, &r);
            let values = display_values(&selector_names(&by), &by, &r);
            let absent: Vec<bool> = by.iter().map(|s| s.resolve(&r).is_none()).collect();
            let legacy = legacy_dedup_fingerprint(None, "rule-1", &values, &absent);
            let sample = serde_json::to_value(&r).unwrap();
            assert_eq!(
                rebuild_dedup_key(&legacy, None, &sample, &values),
                Some(key)
            );
        }
    }

    #[test]
    fn a_legacy_group_incident_rebuilds_its_key() {
        let by = sels(&["match.A"]);
        let r = result(vec![("A", json!("10.0.0.1"))]);
        let values = display_values(&selector_names(&by), &by, &r);
        let legacy = legacy_group_fingerprint(None, &values);
        assert_eq!(
            rebuild_group_key(&legacy, None, &values),
            Some(IdentityKey::group(&by, &r))
        );
        assert_eq!(rebuild_group_key("not-the-id", None, &values), None);
    }
}
