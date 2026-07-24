//! API Root and collection capability checks.
//!
//! With [`CapabilityPolicy::Enforce`](super::policy::CapabilityPolicy::Enforce), verifies collection
//! `media_types` (TAXII and/or STIX 2.1) and API Root `versions` + `max_content_length` (> 0, strict
//! integer JSON). Does not coerce non-conformant server JSON.

use super::TaxiiError;
use super::media::{TAXII_ACCEPT, TAXII_CONTENT_TYPE};
use super::resources::{TaxiiApiRoot, TaxiiCollection};

const STIX_JSON_MEDIA: &str = "application/stix+json;version=2.1";

/// Validate that an API Root advertises TAXII 2.1.
pub fn ensure_api_root_supports_taxii(api: &TaxiiApiRoot) -> Result<(), TaxiiError> {
    if !api
        .versions
        .iter()
        .any(|v| v == TAXII_ACCEPT || v == "application/taxii+json")
    {
        return Err(TaxiiError::UnsupportedApiRoot {
            versions: api.versions.clone(),
        });
    }
    // TAXII 2.1 §4.2.1: max_content_length MUST be a positive integer.
    if api.max_content_length == 0 {
        return Err(TaxiiError::MalformedResponse {
            reason: format!(
                "api root max_content_length must be greater than zero, got {}",
                api.max_content_length
            ),
        });
    }
    Ok(())
}

/// Validate that a collection advertises media types usable for object GET/POST (TAXII 2.1 §5.2.1).
///
/// Real servers may list `application/taxii+json` rather than `application/stix+json` — STIX
/// objects are still returned inside the TAXII envelope.
pub fn ensure_collection_accepts_stix(collection: &TaxiiCollection) -> Result<(), TaxiiError> {
    if collection_supports_stix_objects(collection) {
        Ok(())
    } else {
        Err(TaxiiError::UnsupportedCollectionMedia {
            media_types: collection.media_types.clone(),
        })
    }
}

fn collection_supports_stix_objects(collection: &TaxiiCollection) -> bool {
    collection.effective_media_types().iter().any(|m| {
        m == STIX_JSON_MEDIA
            || m == "application/stix+json"
            || m == TAXII_ACCEPT
            || m == "application/taxii+json"
    })
}

/// Validate POST body content type against collection media types.
pub fn ensure_post_content_type(collection: &TaxiiCollection) -> Result<(), TaxiiError> {
    let _ = collection;
    // TAXII POST always uses the TAXII envelope media type; STIX objects are inside the envelope.
    ensure_collection_accepts_stix(collection)?;
    let _ = TAXII_CONTENT_TYPE;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taxii::resources::TaxiiCollection;

    fn collection_with_media(media_types: Vec<&str>) -> TaxiiCollection {
        TaxiiCollection {
            id: "col1".into(),
            title: "t".into(),
            description: None,
            alias: None,
            can_read: true,
            can_write: false,
            media_types: media_types.into_iter().map(str::to_string).collect(),
            custom: Default::default(),
        }
    }

    #[test]
    fn accepts_stix_json_media_types() {
        ensure_collection_accepts_stix(&collection_with_media(vec![
            "application/stix+json;version=2.1",
        ]))
        .expect("stix media");
    }

    #[test]
    fn accepts_taxii_json_media_types() {
        ensure_collection_accepts_stix(&collection_with_media(vec![
            "application/taxii+json;version=2.1",
            "application/taxii+json",
        ]))
        .expect("taxii media");
    }

    #[test]
    fn absent_media_types_defaults_to_stix_json() {
        ensure_collection_accepts_stix(&collection_with_media(vec![])).expect("§5.2.1 default");
    }

    #[test]
    fn deserializes_collection_without_media_types() {
        let collection: TaxiiCollection = serde_json::from_value(serde_json::json!({
            "id": "col1",
            "title": "t",
            "can_read": true,
            "can_write": false
        }))
        .expect("deserialize");
        assert_eq!(
            collection.effective_media_types(),
            vec!["application/stix+json".to_string()]
        );
        ensure_collection_accepts_stix(&collection).expect("default media types");
    }
}
