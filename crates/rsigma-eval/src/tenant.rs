//! Tenant identifiers.
//!
//! A [`TenantId`] names the isolation boundary an event belongs to. It is
//! produced by an operator binding (an API token, a configured source, or a
//! NATS subscription), never parsed out of event content, and it travels with
//! the event through evaluation and every stateful store.
//!
//! The character set keeps an id safe as a NATS subject token, a path
//! component, and a Prometheus label value.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A validated tenant identifier.
///
/// Ids are 1 to 64 ASCII characters. The first character is `[A-Za-z0-9]`;
/// every following character is `[A-Za-z0-9_-]`. A `.` is refused so an id
/// is always exactly one NATS subject token. Comparison is case-sensitive.
///
/// # Examples
///
/// ```
/// use rsigma_eval::TenantId;
///
/// let tenant = TenantId::new("tenant-a").unwrap();
/// assert_eq!(tenant.as_str(), "tenant-a");
///
/// assert!(TenantId::new("").is_err());
/// assert!(TenantId::new("-leading-dash").is_err());
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(Arc<str>);

impl TenantId {
    /// Validate `id` and wrap it.
    pub fn new(id: &str) -> Result<Self, TenantIdError> {
        if id.is_empty() {
            return Err(TenantIdError::Empty);
        }
        let len = id.chars().count();
        if len > 64 {
            return Err(TenantIdError::TooLong { len });
        }
        for (index, ch) in id.char_indices() {
            let valid = if index == 0 {
                ch.is_ascii_alphanumeric()
            } else {
                ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')
            };
            if !valid {
                return Err(TenantIdError::InvalidChar { ch, index });
            }
        }
        Ok(TenantId(Arc::from(id)))
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for TenantId {
    type Err = TenantIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for TenantId {
    type Error = TenantIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl TryFrom<&str> for TenantId {
    type Error = TenantIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Serialize for TenantId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TenantId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TenantVisitor;

        impl Visitor<'_> for TenantVisitor {
            type Value = TenantId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a tenant id string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<TenantId, E> {
                TenantId::new(value).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(TenantVisitor)
    }
}

/// Why a tenant id was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TenantIdError {
    /// The id is empty.
    #[error("tenant id is empty")]
    Empty,
    /// The id is longer than 64 characters.
    #[error("tenant id is {len} characters; the limit is 64")]
    TooLong {
        /// Observed length.
        len: usize,
    },
    /// The id contains a character outside the allowed set.
    #[error("tenant id has invalid character {ch:?} at index {index}")]
    InvalidChar {
        /// Offending character.
        ch: char,
        /// Byte index of the character.
        index: usize,
    },
}

/// The tenant of event `i`: `None` when `tenants` is empty, else `tenants[i]`.
///
/// An empty slice means tenancy is off and every event is untenanted. A
/// non-empty slice is parallel to the evaluated events.
pub fn tenant_at(tenants: &[Option<TenantId>], i: usize) -> Option<&TenantId> {
    if tenants.is_empty() {
        None
    } else {
        tenants.get(i).and_then(Option::as_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ids_are_accepted() {
        for id in ["a", "tenant-a", "T1-prod_x", &"x".repeat(64)] {
            let tenant = TenantId::new(id).unwrap();
            assert_eq!(tenant.as_str(), id);
        }
    }

    #[test]
    fn empty_id_is_rejected() {
        assert_eq!(TenantId::new(""), Err(TenantIdError::Empty));
    }

    #[test]
    fn too_long_id_is_rejected() {
        let err = TenantId::new(&"x".repeat(65)).unwrap_err();
        assert_eq!(err, TenantIdError::TooLong { len: 65 });
    }

    #[test]
    fn invalid_leading_characters_are_rejected() {
        for id in ["-a", ".a", "_a"] {
            let err = TenantId::new(id).unwrap_err();
            assert!(
                matches!(err, TenantIdError::InvalidChar { index: 0, .. }),
                "{id}: {err:?}"
            );
        }
    }

    #[test]
    fn invalid_characters_are_rejected() {
        for id in ["a/b", "a b", "a{b", "ténant", "a.b"] {
            let err = TenantId::new(id).unwrap_err();
            assert!(
                matches!(err, TenantIdError::InvalidChar { .. }),
                "{id}: {err:?}"
            );
        }
    }

    #[test]
    fn serde_round_trip() {
        let tenant = TenantId::new("tenant-a").unwrap();
        let json = serde_json::to_string(&tenant).unwrap();
        assert_eq!(json, "\"tenant-a\"");
        let parsed: TenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tenant);
    }

    #[test]
    fn deserialize_rejects_an_invalid_id() {
        let err = serde_json::from_str::<TenantId>("\"a/b\"").unwrap_err();
        assert!(err.to_string().contains("invalid character"), "{err}");
    }

    #[test]
    fn tenant_at_reads_the_parallel_slice() {
        let tenants = vec![Some(TenantId::new("a").unwrap()), None];
        assert_eq!(tenant_at(&tenants, 0).map(TenantId::as_str), Some("a"));
        assert!(tenant_at(&tenants, 1).is_none());
        assert!(tenant_at(&tenants, 2).is_none());
        assert!(tenant_at(&[], 0).is_none());
    }
}
