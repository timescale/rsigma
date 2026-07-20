//! Typed views of [`StixObject`] for bundle navigation
//! ([`Bundle::get_typed`](crate::model::Bundle::get_typed),
//! [`Bundle::objects_of_type`](crate::model::Bundle::objects_of_type)).

#[cfg(feature = "serde")]
use crate::model::stix_object::StixObject;

/// Extract a concrete STIX object type from a [`StixObject`] reference.
pub trait BundleObjectCast: 'static {
    #[cfg(feature = "serde")]
    /// Returns `Some` when `object` is the requested concrete type.
    fn cast_from(object: &StixObject) -> Option<&Self>;
}

/// Implement [`BundleObjectCast`] for a built-in STIX object variant.
#[macro_export]
macro_rules! impl_bundle_object_cast {
    (Sdo, $ty:ty, $variant:ident) => {
        impl $crate::model::BundleObjectCast for $ty {
            #[cfg(feature = "serde")]
            fn cast_from(object: &$crate::model::StixObject) -> Option<&Self> {
                match object {
                    $crate::model::StixObject::Sdo($crate::model::SdoObject::$variant(inner)) => {
                        Some(inner)
                    }
                    _ => None,
                }
            }
        }
    };
    (Sco, $ty:ty, $variant:ident) => {
        impl $crate::model::BundleObjectCast for $ty {
            #[cfg(feature = "serde")]
            fn cast_from(object: &$crate::model::StixObject) -> Option<&Self> {
                match object {
                    $crate::model::StixObject::Sco($crate::model::ScoObject::$variant(inner)) => {
                        Some(inner)
                    }
                    _ => None,
                }
            }
        }
    };
    (Sro, $ty:ty, $variant:ident) => {
        impl $crate::model::BundleObjectCast for $ty {
            #[cfg(feature = "serde")]
            fn cast_from(object: &$crate::model::StixObject) -> Option<&Self> {
                match object {
                    $crate::model::StixObject::Sro($crate::model::SroObject::$variant(inner)) => {
                        Some(inner)
                    }
                    _ => None,
                }
            }
        }
    };
    (Meta, $ty:ty, $variant:ident) => {
        impl $crate::model::BundleObjectCast for $ty {
            #[cfg(feature = "serde")]
            fn cast_from(object: &$crate::model::StixObject) -> Option<&Self> {
                match object {
                    $crate::model::StixObject::Meta($crate::model::MetaObject::$variant(inner)) => {
                        Some(inner)
                    }
                    _ => None,
                }
            }
        }
    };
}
