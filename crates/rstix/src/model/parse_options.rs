//! Options controlling STIX bundle and object parsing.

use std::any::Any;
use std::collections::HashMap;

#[cfg(feature = "serde")]
type CustomDeserializeFn =
    fn(serde_json::Value) -> Result<Box<dyn Any + Send + Sync>, crate::ParseError>;
#[cfg(not(feature = "serde"))]
type CustomDeserializeFn = fn() -> Result<Box<dyn Any + Send + Sync>, crate::ParseError>;

/// Registry of custom STIX object type names and their deserializers.
///
/// Deserializers are scoped to a [`ParseOptions`] instance — not global.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TypeRegistry {
    entries: HashMap<String, CustomDeserializeFn>,
}

impl TypeRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a custom STIX object type with a typed deserializer.
    ///
    /// `T` must implement [`serde::Deserialize`] and be `'static` so the bundle
    /// can downcast via [`crate::model::BundleObjectCast`].
    #[cfg(feature = "serde")]
    pub fn register_custom_type<T>(&mut self, type_name: impl Into<String>)
    where
        T: for<'de> serde::Deserialize<'de> + Send + Sync + 'static,
    {
        fn deserialize<T>(
            value: serde_json::Value,
        ) -> Result<Box<dyn Any + Send + Sync>, crate::ParseError>
        where
            T: for<'de> serde::Deserialize<'de> + Send + Sync + 'static,
        {
            let typed = serde_json::from_value::<T>(value).map_err(crate::ParseError::Json)?;
            Ok(Box::new(typed))
        }

        self.entries.insert(type_name.into(), deserialize::<T>);
    }

    /// Returns whether `type_name` has a registered typed deserializer.
    pub fn is_registered(&self, type_name: &str) -> bool {
        self.entries.contains_key(type_name)
    }

    #[cfg(feature = "serde")]
    pub(crate) fn deserialize(
        &self,
        type_name: &str,
        value: serde_json::Value,
    ) -> Option<Result<Box<dyn Any + Send + Sync>, crate::ParseError>> {
        self.entries
            .get(type_name)
            .map(|deserialize| deserialize(value))
    }
}

/// Controls bundle parsing limits and custom-type handling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseOptions {
    /// When true, unknown `type` values deserialize as [`CustomStixObject`](super::CustomStixObject).
    pub allow_custom: bool,
    /// Maximum nesting depth for JSON values in a bundle.
    pub max_nesting_depth: usize,
    /// Maximum number of objects permitted in a single bundle.
    pub max_object_count: usize,
    /// Maximum length of any JSON string value in the bundle.
    pub max_string_length: usize,
    /// Maximum number of bytes read from a bundle stream.
    pub max_bundle_bytes: usize,
    /// Registered custom type deserializers.
    pub type_registry: TypeRegistry,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            allow_custom: false,
            max_nesting_depth: 64,
            max_object_count: usize::MAX,
            max_string_length: 1_048_576,
            max_bundle_bytes: 256 * 1_048_576,
            type_registry: TypeRegistry::new(),
        }
    }
}

impl ParseOptions {
    /// Create options with defaults from the Data Model + Serialization plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable permissive custom-object parsing.
    pub fn allow_custom(mut self, value: bool) -> Self {
        self.allow_custom = value;
        self
    }

    /// Register a custom type on the embedded registry (builder convenience).
    #[cfg(feature = "serde")]
    pub fn register_custom_type<T>(mut self, type_name: impl Into<String>) -> Self
    where
        T: for<'de> serde::Deserialize<'de> + Send + Sync + 'static,
    {
        self.type_registry.register_custom_type::<T>(type_name);
        self
    }

    /// Register a custom type on the embedded registry (mutable convenience).
    #[cfg(feature = "serde")]
    pub fn register_custom_type_mut<T>(&mut self, type_name: impl Into<String>)
    where
        T: for<'de> serde::Deserialize<'de> + Send + Sync + 'static,
    {
        self.type_registry.register_custom_type::<T>(type_name);
    }
}
