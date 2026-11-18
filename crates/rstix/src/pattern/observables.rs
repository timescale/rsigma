//! Exact-match observables from a STIX pattern.
//!
//! A watchlist can use a pattern only when every comparison is an independent
//! equality. Qualifiers and conjunctions describe one event, so they stay unsupported.

use super::ast::{
    Comparison, ComparisonOp, ComparisonTree, ObjectPath, PathStep, PatternAst, PatternConstant,
};
use super::print::render_object_path;

/// Result of reading exact-match observables out of a pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservableExtraction {
    /// Every comparison is an independent `=` or `IN` of a string or integer.
    Simple(Vec<SimpleObservable>),
    /// The pattern describes something a value list cannot represent.
    Unsupported(UnsupportedReason),
}

/// Why a pattern cannot be flattened into independent values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnsupportedReason {
    /// `WITHIN`, `REPEATS`, or `START`/`STOP` qualifies the pattern.
    Qualifier,
    /// `AND` joins observations, or joins comparisons inside one observation.
    And,
    /// `FOLLOWEDBY` orders two observations.
    FollowedBy,
    /// A comparison or a subtree is negated.
    Not,
    /// A comparison uses an operator other than `=` or `IN`.
    Operator,
    /// A constant is not a string or an integer.
    ConstantType,
}

/// One exact value taken from a comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimpleObservable {
    /// SCO type at the root of the object path, such as `ipv4-addr`.
    pub object_type: String,
    /// Canonical object path, such as `file:hashes.'SHA-256'`.
    pub path: String,
    /// Comparison value. Integers are decimal text. Domains, hashes, and MAC addresses are lowercased.
    pub value: String,
    /// Watchlist key when this path is one of the known observable kinds.
    pub kind: Option<ObservableKind>,
}

/// Watchlist key for a known object path.
///
/// Paths outside this set still extract, with [`SimpleObservable::kind`] left unset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ObservableKind {
    /// `ipv4-addr:value` without a prefix length.
    Ipv4,
    /// `ipv4-addr:value` containing `/`.
    Ipv4Cidr,
    /// `ipv6-addr:value` without a prefix length.
    Ipv6,
    /// `ipv6-addr:value` containing `/`.
    Ipv6Cidr,
    /// `domain-name:value`.
    Domain,
    /// `url:value`.
    Url,
    /// `email-addr:value`.
    Email,
    /// `file:hashes.'MD5'`.
    Md5,
    /// `file:hashes.'SHA-1'`.
    Sha1,
    /// `file:hashes.'SHA-256'`.
    Sha256,
    /// `file:hashes.'SHA-512'`.
    Sha512,
    /// `file:name`.
    FileName,
    /// `windows-registry-key:key`.
    RegistryKey,
    /// `mutex:name`.
    Mutex,
    /// `mac-addr:value`.
    Mac,
    /// `autonomous-system:number`.
    Asn,
}

impl ObservableKind {
    /// Stable key used in source values and configuration.
    pub fn key(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv4Cidr => "ipv4_cidr",
            Self::Ipv6 => "ipv6",
            Self::Ipv6Cidr => "ipv6_cidr",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Email => "email",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::FileName => "file_name",
            Self::RegistryKey => "registry_key",
            Self::Mutex => "mutex",
            Self::Mac => "mac",
            Self::Asn => "asn",
        }
    }
}

pub(crate) fn extract(ast: &PatternAst) -> ObservableExtraction {
    match collect(ast) {
        Ok(items) => ObservableExtraction::Simple(items),
        Err(reason) => ObservableExtraction::Unsupported(reason),
    }
}

fn collect(ast: &PatternAst) -> Result<Vec<SimpleObservable>, UnsupportedReason> {
    match ast {
        PatternAst::Observation(expr) => collect_tree(&expr.root),
        PatternAst::Or { left, right, .. } => {
            let mut items = collect(left)?;
            items.extend(collect(right)?);
            Ok(items)
        }
        PatternAst::And { .. } => Err(UnsupportedReason::And),
        PatternAst::FollowedBy { .. } => Err(UnsupportedReason::FollowedBy),
        PatternAst::Within { .. } | PatternAst::Repeats { .. } | PatternAst::StartStop { .. } => {
            Err(UnsupportedReason::Qualifier)
        }
    }
}

fn collect_tree(tree: &ComparisonTree) -> Result<Vec<SimpleObservable>, UnsupportedReason> {
    match tree {
        ComparisonTree::Cmp(comparison) => Ok(collect_comparison(comparison)?),
        ComparisonTree::Or { left, right, .. } => {
            let mut items = collect_tree(left)?;
            items.extend(collect_tree(right)?);
            Ok(items)
        }
        ComparisonTree::And { .. } => Err(UnsupportedReason::And),
        ComparisonTree::Not { .. } => Err(UnsupportedReason::Not),
    }
}

fn collect_comparison(comparison: &Comparison) -> Result<Vec<SimpleObservable>, UnsupportedReason> {
    if comparison.negated {
        return Err(UnsupportedReason::Not);
    }
    let constants = match (&comparison.op, &comparison.value) {
        (ComparisonOp::Eq, Some(constant)) => vec![scalar(constant)?],
        (ComparisonOp::In, Some(PatternConstant::List(items))) => {
            items.iter().map(scalar).collect::<Result<Vec<_>, _>>()?
        }
        (ComparisonOp::Eq | ComparisonOp::In, _) => return Err(UnsupportedReason::ConstantType),
        _ => return Err(UnsupportedReason::Operator),
    };
    let path = render_object_path(&comparison.path);
    let object_type = comparison.path.object_type.type_name().to_owned();
    Ok(constants
        .into_iter()
        .map(|raw| {
            let kind = classify(&comparison.path, &raw);
            let value = normalize(kind, raw);
            SimpleObservable {
                object_type: object_type.clone(),
                path: path.clone(),
                value,
                kind,
            }
        })
        .collect())
}

fn scalar(constant: &PatternConstant) -> Result<String, UnsupportedReason> {
    match constant {
        PatternConstant::String(text) => Ok(text.clone()),
        PatternConstant::Int(number) => Ok(number.to_string()),
        _ => Err(UnsupportedReason::ConstantType),
    }
}

fn classify(path: &ObjectPath, value: &str) -> Option<ObservableKind> {
    let mut parts = Vec::new();
    for step in &path.steps {
        match step {
            PathStep::Property(name) | PathStep::DictKey(name) => parts.push(name.as_str()),
            PathStep::Index(_) | PathStep::AnyIndex | PathStep::Reference => return None,
        }
    }
    match (path.object_type.type_name(), parts.as_slice()) {
        ("ipv4-addr", ["value"]) => Some(if value.contains('/') {
            ObservableKind::Ipv4Cidr
        } else {
            ObservableKind::Ipv4
        }),
        ("ipv6-addr", ["value"]) => Some(if value.contains('/') {
            ObservableKind::Ipv6Cidr
        } else {
            ObservableKind::Ipv6
        }),
        ("domain-name", ["value"]) => Some(ObservableKind::Domain),
        ("url", ["value"]) => Some(ObservableKind::Url),
        ("email-addr", ["value"]) => Some(ObservableKind::Email),
        ("file", ["hashes", "MD5"]) => Some(ObservableKind::Md5),
        ("file", ["hashes", "SHA-1"]) => Some(ObservableKind::Sha1),
        ("file", ["hashes", "SHA-256"]) => Some(ObservableKind::Sha256),
        ("file", ["hashes", "SHA-512"]) => Some(ObservableKind::Sha512),
        ("file", ["name"]) => Some(ObservableKind::FileName),
        ("windows-registry-key", ["key"]) => Some(ObservableKind::RegistryKey),
        ("mutex", ["name"]) => Some(ObservableKind::Mutex),
        ("mac-addr", ["value"]) => Some(ObservableKind::Mac),
        ("autonomous-system", ["number"]) => Some(ObservableKind::Asn),
        _ => None,
    }
}

fn normalize(kind: Option<ObservableKind>, value: String) -> String {
    match kind {
        Some(
            ObservableKind::Domain
            | ObservableKind::Md5
            | ObservableKind::Sha1
            | ObservableKind::Sha256
            | ObservableKind::Sha512
            | ObservableKind::Mac,
        ) => value.to_ascii_lowercase(),
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Pattern;

    fn simple(source: &str) -> Vec<SimpleObservable> {
        match Pattern::parse(source).unwrap().simple_observables() {
            ObservableExtraction::Simple(items) => items,
            ObservableExtraction::Unsupported(reason) => {
                panic!("{source} was unsupported: {reason:?}")
            }
        }
    }

    fn unsupported(source: &str) -> UnsupportedReason {
        match Pattern::parse(source).unwrap().simple_observables() {
            ObservableExtraction::Unsupported(reason) => reason,
            ObservableExtraction::Simple(_) => panic!("{source} was simple"),
        }
    }

    #[test]
    fn maps_every_known_kind_and_normalizes() {
        let items = simple(
            "[ipv4-addr:value = '198.51.100.7'] OR \
             [ipv4-addr:value = '198.51.100.0/24'] OR \
             [ipv6-addr:value = '2001:DB8::1'] OR \
             [ipv6-addr:value = '2001:db8::/32'] OR \
             [domain-name:value = 'Bad.Example.com'] OR \
             [url:value = 'https://Bad.Example/a'] OR \
             [email-addr:value = 'a@bad.example'] OR \
             [file:hashes.'MD5' = 'AABB'] OR \
             [file:hashes.'SHA-1' = 'CCDD'] OR \
             [file:hashes.'SHA-256' = 'EEFF'] OR \
             [file:hashes.'SHA-512' = '0011'] OR \
             [file:name = 'Report.PDF'] OR \
             [windows-registry-key:key = 'HKLM-Software'] OR \
             [mutex:name = 'Global-Lock'] OR \
             [mac-addr:value = 'AA:BB:CC:DD:EE:FF'] OR \
             [autonomous-system:number = 64496]",
        );
        let keys: Vec<_> = items.iter().map(|item| item.kind.unwrap().key()).collect();
        assert_eq!(
            keys,
            [
                "ipv4",
                "ipv4_cidr",
                "ipv6",
                "ipv6_cidr",
                "domain",
                "url",
                "email",
                "md5",
                "sha1",
                "sha256",
                "sha512",
                "file_name",
                "registry_key",
                "mutex",
                "mac",
                "asn",
            ]
        );
        assert_eq!(items[2].value, "2001:DB8::1");
        assert_eq!(items[4].value, "bad.example.com");
        assert_eq!(items[5].value, "https://Bad.Example/a");
        assert_eq!(items[7].value, "aabb");
        assert_eq!(items[8].value, "ccdd");
        assert_eq!(items[9].value, "eeff");
        assert_eq!(items[10].value, "0011");
        assert_eq!(items[11].value, "Report.PDF");
        assert_eq!(items[14].value, "aa:bb:cc:dd:ee:ff");
        assert_eq!(items[15].value, "64496");
        assert_eq!(items[15].object_type, "autonomous-system");
        assert_eq!(items[9].path, "file:hashes.'SHA-256'");
    }

    #[test]
    fn in_list_emits_one_observable_per_element() {
        let items = simple("[domain-name:value IN ('A.Example', 'b.example')]");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].value, "a.example");
        assert_eq!(items[1].value, "b.example");
        assert!(
            items
                .iter()
                .all(|item| item.kind == Some(ObservableKind::Domain))
        );
    }

    #[test]
    fn unmapped_path_stays_simple_without_a_kind() {
        let items = simple("[file:size = 12]");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, None);
        assert_eq!(items[0].value, "12");
        assert_eq!(items[0].path, "file:size");
    }

    #[test]
    fn or_inside_one_observation_flattens() {
        let items =
            simple("[ipv4-addr:value = '198.51.100.7' OR ipv4-addr:value = '198.51.100.8']");
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn rejects_each_unsupported_shape() {
        assert_eq!(
            unsupported("[ipv4-addr:value = '198.51.100.7'] WITHIN 5 SECONDS"),
            UnsupportedReason::Qualifier
        );
        assert_eq!(
            unsupported("[ipv4-addr:value = '198.51.100.7'] REPEATS 2 TIMES"),
            UnsupportedReason::Qualifier
        );
        assert_eq!(
            unsupported(
                "[ipv4-addr:value = '198.51.100.7'] START t'2020-01-01T00:00:00.000Z' STOP t'2020-01-02T00:00:00.000Z'"
            ),
            UnsupportedReason::Qualifier
        );
        assert_eq!(
            unsupported(
                "[ipv4-addr:value = '198.51.100.7'] AND [domain-name:value = 'bad.example']"
            ),
            UnsupportedReason::And
        );
        assert_eq!(
            unsupported("[ipv4-addr:value = '198.51.100.7' AND ipv4-addr:value = '198.51.100.8']"),
            UnsupportedReason::And
        );
        assert_eq!(
            unsupported(
                "[ipv4-addr:value = '198.51.100.7'] FOLLOWEDBY [domain-name:value = 'bad.example']"
            ),
            UnsupportedReason::FollowedBy
        );
        assert_eq!(
            unsupported("[ipv4-addr:value != '198.51.100.7']"),
            UnsupportedReason::Operator
        );
        assert_eq!(
            unsupported("[ipv4-addr:value NOT = '198.51.100.7']"),
            UnsupportedReason::Not
        );
        assert_eq!(
            unsupported("[ipv4-addr:defanged = true]"),
            UnsupportedReason::ConstantType
        );
        assert_eq!(
            unsupported(
                "[file:ctime IN (t'2020-01-01T00:00:00.000Z', t'2020-01-02T00:00:00.000Z')]"
            ),
            UnsupportedReason::ConstantType
        );
    }
}
