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
    /// When true, predefined TLP `marking-definition` ids may be referenced without
    /// being present in the bundle (STIX 2.1 Interoperability §2.3.4).
    pub exempt_predefined_tlp_marking_refs: bool,
    /// When true (the default), RFC 2047 encoded-words in `email-message` header
    /// properties are decoded while parsing (STIX §6.6). Turn this off to read STIX
    /// JSON whose values are already decoded, such as output this crate serialized,
    /// so a value that itself looks like an encoded-word is kept as written.
    pub decode_email_encoded_words: bool,
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
            exempt_predefined_tlp_marking_refs: false,
            decode_email_encoded_words: true,
        }
    }
}

impl ParseOptions {
    /// Create options with default parse limits.
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

    /// Enable interop bundle reference rules (predefined TLP marking exemption).
    pub fn exempt_predefined_tlp_marking_refs(mut self, value: bool) -> Self {
        self.exempt_predefined_tlp_marking_refs = value;
        self
    }

    /// Enable or disable RFC 2047 decoding of `email-message` headers.
    pub fn decode_email_encoded_words(mut self, value: bool) -> Self {
        self.decode_email_encoded_words = value;
        self
    }

    /// Parse options aligned with STIX 2.1 Interoperability bundle closure (§2.3.4).
    pub fn interop_bundle(self) -> Self {
        self.exempt_predefined_tlp_marking_refs(true)
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
