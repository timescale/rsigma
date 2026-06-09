use yaml_serde::Value;

use crate::ast::*;
use crate::error::{Result, SigmaParserError};

use super::detection::parse_detections;
use super::{
    collect_custom_attributes, get_str, get_str_list, parse_enum_with_warn, parse_logsource,
    parse_related, parse_sigma_version, val_key,
};

// =============================================================================
// Filter Rule Parsing
// =============================================================================

/// Parse a filter rule from a YAML value.
///
/// `warnings` receives non-fatal issues (invalid `status` / `level`
/// values, malformed `related:` entries); see
/// [`parse_detection_rule`](super::detection::parse_detection_rule).
pub(super) fn parse_filter_rule(value: &Value, warnings: &mut Vec<String>) -> Result<FilterRule> {
    let m = value
        .as_mapping()
        .ok_or_else(|| SigmaParserError::InvalidRule("Expected a YAML mapping".into()))?;

    let title = get_str(m, "title")
        .ok_or_else(|| SigmaParserError::MissingField("title".into()))?
        .to_string();

    let sigma_version = parse_sigma_version(m, warnings);
    let array_matching = crate::version::array_matching_enabled(sigma_version);

    // Get filter section for rules list
    let filter_val = m.get(val_key("filter"));
    let filter_mapping = filter_val.and_then(|v| v.as_mapping());
    let rules = match filter_mapping {
        Some(fm) => match fm.get(val_key("rules")) {
            Some(Value::String(s)) if s.eq_ignore_ascii_case("any") => FilterRuleTarget::Any,
            Some(Value::String(s)) => FilterRuleTarget::Specific(vec![s.clone()]),
            Some(Value::Sequence(seq)) => {
                let list: Vec<String> = seq
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                if list.is_empty() {
                    FilterRuleTarget::Any
                } else {
                    FilterRuleTarget::Specific(list)
                }
            }
            _ => FilterRuleTarget::Any,
        },
        _ => FilterRuleTarget::Any,
    };

    // Parse detection from filter.selection + filter.condition
    // (Sigma filter spec: selection/condition live inside the filter section).
    let detection = if let Some(fm) = filter_mapping {
        let mut det_map = yaml_serde::Mapping::new();
        for (k, v) in fm.iter() {
            let key_str = k.as_str().unwrap_or("");
            if key_str != "rules" {
                det_map.insert(k.clone(), v.clone());
            }
        }
        if det_map.is_empty() {
            return Err(SigmaParserError::MissingField("filter.selection".into()));
        }
        parse_detections(&Value::Mapping(det_map), array_matching)?
    } else {
        return Err(SigmaParserError::MissingField("filter".into()));
    };

    let logsource = m
        .get(val_key("logsource"))
        .map(parse_logsource)
        .transpose()?;

    let standard_filter_keys: &[&str] = &[
        "author",
        "custom_attributes",
        "sigma-version",
        "date",
        "description",
        "falsepositives",
        "fields",
        "filter",
        "id",
        "level",
        "license",
        "logsource",
        "modified",
        "name",
        "references",
        "related",
        "scope",
        "status",
        "tags",
        "taxonomy",
        "title",
    ];
    let custom_attributes = collect_custom_attributes(m, standard_filter_keys);

    Ok(FilterRule {
        title,
        sigma_version,
        id: get_str(m, "id").map(|s| s.to_string()),
        name: get_str(m, "name").map(|s| s.to_string()),
        taxonomy: get_str(m, "taxonomy").map(|s| s.to_string()),
        status: parse_enum_with_warn(get_str(m, "status"), "status", warnings),
        description: get_str(m, "description").map(|s| s.to_string()),
        author: get_str(m, "author").map(|s| s.to_string()),
        date: get_str(m, "date").map(|s| s.to_string()),
        modified: get_str(m, "modified").map(|s| s.to_string()),
        related: parse_related(m.get(val_key("related")), warnings),
        license: get_str(m, "license").map(|s| s.to_string()),
        references: get_str_list(m, "references"),
        tags: get_str_list(m, "tags"),
        fields: get_str_list(m, "fields"),
        falsepositives: get_str_list(m, "falsepositives"),
        level: parse_enum_with_warn(get_str(m, "level"), "level", warnings),
        scope: get_str_list(m, "scope"),
        logsource,
        rules,
        detection,
        custom_attributes,
    })
}
