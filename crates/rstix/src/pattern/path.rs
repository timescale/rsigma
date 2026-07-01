//! Object-path value resolution for pattern evaluation.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::core::{QueryValue, QueryableStixObject, StixId, StixTimestamp};
use crate::model::Bundle;
use crate::model::sco::extensions::WindowsPeBinaryExt;
use crate::model::sco::{EmailMessage, ScoObject, WindowsRegistryKey, X509V3Extensions};
use crate::pattern::ast::{ObjectPath, PathStep};
use crate::pattern::error::PatternMatchError;

/// Resolved field value for comparison (owned for evaluator consumption).
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum FieldValue {
    /// String field value.
    Str(String),
    /// Integer field value.
    Int(i64),
    /// Floating-point field value.
    Float(f64),
    /// Boolean field value.
    Bool(bool),
    /// Timestamp field value.
    Timestamp(StixTimestamp),
    /// Decoded binary payload.
    Bytes(Vec<u8>),
}

enum WalkTarget<'a> {
    Sco(&'a ScoObject),
    Json(&'a serde_json::Value),
    ExtProps(&'a BTreeMap<String, serde_json::Value>),
    Float(f64),
    PendingRef(&'a StixId),
    MultipartPart {
        message: &'a EmailMessage,
        index: usize,
    },
    RegistryValuePart {
        key: &'a WindowsRegistryKey,
        index: usize,
    },
    X509Ext(&'a X509V3Extensions),
}

pub(crate) fn resolve_path_values(
    sco: &ScoObject,
    path: &ObjectPath,
    bundle: Option<&Bundle>,
) -> Result<Vec<FieldValue>, PatternMatchError> {
    let path_str = format_object_path(path);
    walk(
        vec![WalkTarget::Sco(sco)],
        path.steps.as_slice(),
        bundle,
        &path_str,
    )
}

fn walk<'a>(
    targets: Vec<WalkTarget<'a>>,
    steps: &[PathStep],
    bundle: Option<&'a Bundle>,
    path_str: &str,
) -> Result<Vec<FieldValue>, PatternMatchError> {
    if steps.is_empty() {
        return Ok(Vec::new());
    }

    let step = &steps[0];
    let rest = &steps[1..];

    if let PathStep::Property(name) = step {
        if name.ends_with("_refs")
            && let Some(PathStep::Index(idx)) = rest.first()
            && matches!(rest.get(1), Some(PathStep::Reference))
        {
            let mut next = Vec::new();
            for target in targets {
                let WalkTarget::Sco(sco) = target else {
                    continue;
                };
                if let Some(id) = ref_list_ids(sco, name).into_iter().nth(*idx) {
                    next.push(WalkTarget::PendingRef(id));
                }
            }
            return walk(next, &rest[2..], bundle, path_str);
        }
        if name.ends_with("_refs")
            && let Some(PathStep::Index(idx)) = rest.first()
            && rest.len() == 1
        {
            let mut values = Vec::new();
            for target in targets {
                let WalkTarget::Sco(sco) = target else {
                    continue;
                };
                if let Some(id) = ref_list_ids(sco, name).into_iter().nth(*idx) {
                    values.push(FieldValue::Str(id.to_string()));
                }
            }
            return Ok(values);
        }

        if name.ends_with("_refs") && matches!(rest.first(), Some(PathStep::AnyIndex)) {
            let mut next = Vec::new();
            for target in targets {
                let WalkTarget::Sco(sco) = target else {
                    continue;
                };
                for id in ref_list_ids(sco, name) {
                    next.push(WalkTarget::PendingRef(id));
                }
            }
            return walk(next, &rest[1..], bundle, path_str);
        }

        if name.ends_with("_refs") && matches!(rest.first(), Some(PathStep::Reference)) {
            let mut values = Vec::new();
            for target in targets {
                match target {
                    WalkTarget::Sco(sco) => {
                        for resolved in resolve_ref_property(sco, name, bundle, path_str)? {
                            values.extend(walk(
                                vec![WalkTarget::Sco(resolved)],
                                &rest[1..],
                                bundle,
                                path_str,
                            )?);
                        }
                    }
                    WalkTarget::PendingRef(id) => {
                        let Some(bundle) = bundle else {
                            return Err(PatternMatchError::RefResolution {
                                path: path_str.to_owned(),
                                msg: "bundle required for _ref dereference".into(),
                            });
                        };
                        let resolved = resolve_id(bundle, id, path_str)?;
                        values.extend(walk(
                            vec![WalkTarget::Sco(resolved)],
                            &rest[1..],
                            Some(bundle),
                            path_str,
                        )?);
                    }
                    _ => {}
                }
            }
            return Ok(values);
        }

        if is_ref_property(name) {
            if rest.is_empty() {
                let mut values = Vec::new();
                for target in targets {
                    match target {
                        WalkTarget::Sco(sco) => {
                            if let Some(id) = ref_id_for_property(sco, name) {
                                values.push(FieldValue::Str(id.to_string()));
                            }
                        }
                        WalkTarget::MultipartPart { .. } if name == "body_raw_ref" => {
                            values.extend(read_terminal_property(target, name, bundle)?);
                        }
                        _ => {}
                    }
                }
                return Ok(values);
            }
            let Some(PathStep::Reference) = rest.first() else {
                return Ok(Vec::new());
            };
            let mut values = Vec::new();
            for target in targets {
                match target {
                    WalkTarget::Sco(sco) => {
                        for resolved in resolve_ref_property(sco, name, bundle, path_str)? {
                            values.extend(walk(
                                vec![WalkTarget::Sco(resolved)],
                                &rest[1..],
                                bundle,
                                path_str,
                            )?);
                        }
                    }
                    WalkTarget::MultipartPart { message, index } if name == "body_raw_ref" => {
                        let Some(bundle) = bundle else {
                            return Err(PatternMatchError::RefResolution {
                                path: path_str.to_owned(),
                                msg: "bundle required for _ref dereference".into(),
                            });
                        };
                        let Some(id) = message
                            .body_multipart
                            .as_ref()
                            .and_then(|parts| parts.get(index))
                            .and_then(|part| part.body_raw_ref.as_ref())
                            .map(|raw| raw.as_stix_id())
                        else {
                            continue;
                        };
                        let resolved = resolve_id(bundle, id, path_str)?;
                        values.extend(walk(
                            vec![WalkTarget::Sco(resolved)],
                            &rest[1..],
                            Some(bundle),
                            path_str,
                        )?);
                    }
                    WalkTarget::PendingRef(id) => {
                        let Some(bundle) = bundle else {
                            return Err(PatternMatchError::RefResolution {
                                path: path_str.to_owned(),
                                msg: "bundle required for _ref dereference".into(),
                            });
                        };
                        let resolved = resolve_id(bundle, id, path_str)?;
                        values.extend(walk(
                            vec![WalkTarget::Sco(resolved)],
                            &rest[1..],
                            Some(bundle),
                            path_str,
                        )?);
                    }
                    _ => {}
                }
            }
            return Ok(values);
        }

        if name == "body_multipart" {
            if let Some(PathStep::Index(idx)) = rest.first() {
                let mut next = Vec::new();
                for target in targets {
                    let WalkTarget::Sco(ScoObject::EmailMessage(message)) = target else {
                        continue;
                    };
                    if message
                        .body_multipart
                        .as_ref()
                        .is_some_and(|parts| parts.len() > *idx)
                    {
                        next.push(WalkTarget::MultipartPart {
                            message,
                            index: *idx,
                        });
                    }
                }
                return walk(next, &rest[1..], bundle, path_str);
            }
            if matches!(rest.first(), Some(PathStep::AnyIndex)) {
                let mut next = Vec::new();
                for target in targets {
                    let WalkTarget::Sco(ScoObject::EmailMessage(message)) = target else {
                        continue;
                    };
                    if let Some(parts) = &message.body_multipart {
                        for index in 0..parts.len() {
                            next.push(WalkTarget::MultipartPart { message, index });
                        }
                    }
                }
                return walk(next, &rest[1..], bundle, path_str);
            }
        }

        if name == "values"
            && let Some(PathStep::Index(idx)) = rest.first()
        {
            let mut next = Vec::new();
            for target in targets {
                if let WalkTarget::Sco(ScoObject::WindowsRegistryKey(key)) = target
                    && key.values.len() > *idx
                {
                    next.push(WalkTarget::RegistryValuePart { key, index: *idx });
                }
            }
            return walk(next, &rest[1..], bundle, path_str);
        }

        if name == "sections"
            && targets
                .iter()
                .all(|target| matches!(target, WalkTarget::Sco(_)))
        {
            let mut next = Vec::new();
            for target in targets {
                match target {
                    WalkTarget::Sco(sco) => next.extend(pe_section_floats(sco)),
                    WalkTarget::Json(section) => {
                        if let Some(entropy) = section.get("entropy").and_then(|v| v.as_f64()) {
                            next.push(WalkTarget::Float(entropy));
                        }
                    }
                    _ => {}
                }
            }
            return walk(next, rest, bundle, path_str);
        }

        if rest.is_empty() {
            let mut values = Vec::new();
            for target in targets {
                values.extend(read_terminal_property(target, name, bundle)?);
            }
            return Ok(values);
        }

        if name == "extensions" {
            return walk(targets, rest, bundle, path_str);
        }

        if let [PathStep::DictKey(key)] = rest {
            let mut values = Vec::new();
            for target in targets {
                values.extend(read_dict_terminal(target, name, key)?);
            }
            return Ok(values);
        }

        let mut next = Vec::new();
        for target in targets {
            next.extend(navigate_property(target, name)?);
        }
        return walk(next, rest, bundle, path_str);
    }

    match step {
        PathStep::DictKey(key) if rest.is_empty() => {
            let mut values = Vec::new();
            for target in targets {
                match target {
                    WalkTarget::Json(obj) => {
                        if let Some(v) = obj.get(key.as_str()).and_then(json_scalar_to_field) {
                            values.push(v);
                        }
                    }
                    WalkTarget::ExtProps(props) => {
                        if let Some(v) = props.get(key).and_then(json_scalar_to_field) {
                            values.push(v);
                        }
                    }
                    WalkTarget::Sco(sco) => {
                        if let Some(v) = read_dict_key(sco, key) {
                            values.push(v);
                        }
                    }
                    _ => {}
                }
            }
            Ok(values)
        }
        PathStep::DictKey(key) => {
            let mut next = Vec::new();
            for target in targets {
                match target {
                    WalkTarget::Sco(sco) => {
                        if let Some(props) = extension_entry_props(sco, key) {
                            next.push(WalkTarget::ExtProps(props));
                        } else if let ScoObject::Custom(custom) = sco
                            && let Some(v) = custom.common.extra.get(key)
                        {
                            next.push(WalkTarget::Json(v));
                        }
                    }
                    WalkTarget::ExtProps(props) => {
                        if let Some(v) = props.get(key) {
                            next.push(WalkTarget::Json(v));
                        }
                    }
                    WalkTarget::Json(obj) => {
                        if let Some(v) = obj.get(key.as_str()) {
                            next.push(WalkTarget::Json(v));
                        }
                    }
                    _ => {}
                }
            }
            walk(next, rest, bundle, path_str)
        }
        PathStep::Index(idx) => {
            let mut next = Vec::new();
            for target in targets {
                next.extend(index_target(target, *idx));
            }
            walk(next, rest, bundle, path_str)
        }
        PathStep::AnyIndex => {
            let mut next = Vec::new();
            for target in targets {
                match target {
                    WalkTarget::Json(arr) if arr.is_array() => {
                        if let Some(items) = arr.as_array() {
                            next.extend(items.iter().map(WalkTarget::Json));
                        }
                    }
                    other => next.push(other),
                }
            }
            walk(next, rest, bundle, path_str)
        }
        PathStep::Reference => {
            let Some(bundle) = bundle else {
                return Err(PatternMatchError::RefResolution {
                    path: path_str.to_owned(),
                    msg: "bundle required for _ref dereference".into(),
                });
            };
            let mut next = Vec::new();
            for target in targets {
                if let WalkTarget::PendingRef(id) = target {
                    next.push(WalkTarget::Sco(resolve_id(bundle, id, path_str)?));
                }
            }
            walk(next, rest, Some(bundle), path_str)
        }
        _ => Ok(Vec::new()),
    }
}

fn navigate_property<'a>(
    target: WalkTarget<'a>,
    name: &str,
) -> Result<Vec<WalkTarget<'a>>, PatternMatchError> {
    match target {
        WalkTarget::Sco(sco) => {
            if let ScoObject::Custom(custom) = sco
                && let Some(v) = custom.common.extra.get(name)
            {
                return Ok(vec![WalkTarget::Json(v)]);
            }
            if let Some(props) = extension_entry_props(sco, name) {
                return Ok(vec![WalkTarget::ExtProps(props)]);
            }
            if let Some(v) = extension_property_value(sco, name) {
                return Ok(vec![WalkTarget::Json(v)]);
            }
            if let ScoObject::X509Certificate(cert) = sco
                && name == "x509_v3_extensions"
                && let Some(ext) = &cert.x509_v3_extensions
            {
                return Ok(vec![WalkTarget::X509Ext(ext)]);
            }
            Ok(Vec::new())
        }
        WalkTarget::ExtProps(props) => Ok(props
            .get(name)
            .map(|v| vec![WalkTarget::Json(v)])
            .unwrap_or_default()),
        WalkTarget::Json(value) => Ok(value
            .get(name)
            .map(|v| vec![WalkTarget::Json(v)])
            .unwrap_or_default()),
        WalkTarget::MultipartPart { .. }
        | WalkTarget::RegistryValuePart { .. }
        | WalkTarget::X509Ext(_) => Ok(Vec::new()),
        WalkTarget::Float(_) | WalkTarget::PendingRef(_) => Ok(Vec::new()),
    }
}

fn index_target<'a>(target: WalkTarget<'a>, idx: usize) -> Vec<WalkTarget<'a>> {
    match target {
        WalkTarget::Sco(sco) => pe_section_floats(sco)
            .into_iter()
            .nth(idx)
            .into_iter()
            .collect(),
        WalkTarget::Json(value) => value
            .as_array()
            .and_then(|items| items.get(idx))
            .map(|v| vec![WalkTarget::Json(v)])
            .unwrap_or_default(),
        WalkTarget::Float(v) if idx == 0 => vec![WalkTarget::Float(v)],
        _ => Vec::new(),
    }
}

fn read_terminal_property(
    target: WalkTarget<'_>,
    name: &str,
    bundle: Option<&Bundle>,
) -> Result<Vec<FieldValue>, PatternMatchError> {
    match target {
        WalkTarget::Sco(sco) => read_sco_terminal(sco, name, bundle),
        WalkTarget::Json(value) => Ok(value
            .get(name)
            .and_then(json_value_to_field)
            .into_iter()
            .collect()),
        WalkTarget::ExtProps(props) => Ok(props
            .get(name)
            .and_then(json_value_to_field)
            .into_iter()
            .collect()),
        WalkTarget::MultipartPart { message, index } => {
            let part = message
                .body_multipart
                .as_ref()
                .and_then(|parts| parts.get(index));
            Ok(match name {
                "body" => part
                    .and_then(|p| p.body.as_deref())
                    .map(|s| FieldValue::Str(s.to_owned()))
                    .into_iter()
                    .collect(),
                "content_type" => part
                    .and_then(|p| p.content_type.as_deref())
                    .map(|s| FieldValue::Str(s.to_owned()))
                    .into_iter()
                    .collect(),
                "content_disposition" => part
                    .and_then(|p| p.content_disposition.as_deref())
                    .map(|s| FieldValue::Str(s.to_owned()))
                    .into_iter()
                    .collect(),
                "body_raw_ref" => part
                    .and_then(|p| p.body_raw_ref.as_ref())
                    .map(|id| FieldValue::Str(id.as_stix_id().to_string()))
                    .into_iter()
                    .collect(),
                _ => Vec::new(),
            })
        }
        WalkTarget::RegistryValuePart { key, index } => {
            let value = key.values.get(index);
            Ok(match name {
                "name" => value
                    .and_then(|v| v.name.as_deref())
                    .map(|s| FieldValue::Str(s.to_owned()))
                    .into_iter()
                    .collect(),
                "data" => value
                    .and_then(|v| v.data.as_deref())
                    .map(|s| FieldValue::Str(s.to_owned()))
                    .into_iter()
                    .collect(),
                "data_type" => value
                    .and_then(|v| v.data_type.as_deref())
                    .map(|s| FieldValue::Str(s.to_owned()))
                    .into_iter()
                    .collect(),
                _ => Vec::new(),
            })
        }
        WalkTarget::X509Ext(ext) => Ok(x509_ext_field(ext, name).into_iter().collect()),
        WalkTarget::Float(v) if name == "entropy" => Ok(vec![FieldValue::Float(v)]),
        WalkTarget::Float(_) | WalkTarget::PendingRef(_) => Ok(Vec::new()),
    }
}

fn read_sco_terminal(
    sco: &ScoObject,
    name: &str,
    bundle: Option<&Bundle>,
) -> Result<Vec<FieldValue>, PatternMatchError> {
    if name == "type" {
        return Ok(vec![FieldValue::Str(
            QueryableStixObject::type_name(sco).to_owned(),
        )]);
    }
    if name == "id" {
        return Ok(vec![FieldValue::Str(sco.id().to_string())]);
    }
    if name == "spec_version"
        && let Some(version) = sco.spec_version()
    {
        return Ok(vec![FieldValue::Str(version.as_str().to_owned())]);
    }
    if name == "defanged"
        && let Some(defanged) = sco.common_props().defanged
    {
        return Ok(vec![FieldValue::Bool(defanged)]);
    }
    if name == "name"
        && let ScoObject::Process(process) = sco
        && let Some(values) = process_name_values(process, bundle)?
    {
        return Ok(values);
    }
    finish_read_sco_terminal(sco, name)
}

fn finish_read_sco_terminal(
    sco: &ScoObject,
    name: &str,
) -> Result<Vec<FieldValue>, PatternMatchError> {
    if name == "payload_bin" {
        let ScoObject::Artifact(artifact) = sco else {
            return Ok(Vec::new());
        };
        let Some(raw) = &artifact.payload_bin else {
            return Ok(Vec::new());
        };
        let Some(decoded) = decode_payload_bin(raw) else {
            return Ok(Vec::new());
        };
        return Ok(vec![FieldValue::Bytes(decoded)]);
    }
    if name == "values" {
        let ScoObject::WindowsRegistryKey(key) = sco else {
            return Ok(Vec::new());
        };
        if key.values.is_empty() {
            return Ok(Vec::new());
        }
        return Ok(vec![FieldValue::Bool(true)]);
    }
    if name == "extensions" && !sco.common_props().extensions.is_empty() {
        return Ok(vec![FieldValue::Bool(true)]);
    }
    if name == "hashes" && hash_map_nonempty(sco) {
        return Ok(vec![FieldValue::Bool(true)]);
    }
    if name.ends_with("_refs") && !ref_list_ids(sco, name).is_empty() {
        return Ok(vec![FieldValue::Bool(true)]);
    }
    if let Some(value) = QueryableStixObject::get_field(sco, &[name]) {
        return Ok(match value {
            QueryValue::Null => vec![FieldValue::Bool(true)],
            other => query_to_field(other).into_iter().collect(),
        });
    }
    Ok(Vec::new())
}

fn process_name_values(
    process: &crate::model::sco::Process,
    bundle: Option<&Bundle>,
) -> Result<Option<Vec<FieldValue>>, PatternMatchError> {
    if let (Some(image_ref), Some(bundle)) = (&process.image_ref, bundle)
        && let Some(crate::model::StixObject::Sco(ScoObject::File(file))) =
            bundle.get(image_ref.as_stix_id())
        && let Some(name) = &file.name
    {
        return Ok(Some(vec![FieldValue::Str(name.clone())]));
    }
    if let Some(cmd) = &process.command_line
        && let Some(name) = executable_from_command_line(cmd)
    {
        return Ok(Some(vec![FieldValue::Str(name)]));
    }
    Ok(None)
}

fn executable_from_command_line(command_line: &str) -> Option<String> {
    let token = command_line.split_whitespace().next()?;
    let base = token.rsplit(['/', '\\']).next()?.trim();
    if base.is_empty() {
        None
    } else {
        Some(base.to_owned())
    }
}

fn read_dict_terminal(
    target: WalkTarget<'_>,
    property: &str,
    key: &str,
) -> Result<Vec<FieldValue>, PatternMatchError> {
    match target {
        WalkTarget::Sco(sco) => Ok(read_dict_property(sco, property, key).into_iter().collect()),
        WalkTarget::ExtProps(props) => Ok(props
            .get(key)
            .and_then(json_scalar_to_field)
            .into_iter()
            .collect()),
        WalkTarget::Json(obj) => Ok(obj
            .get(key)
            .and_then(json_scalar_to_field)
            .into_iter()
            .collect()),
        _ => Ok(Vec::new()),
    }
}

fn read_dict_key(sco: &ScoObject, key: &str) -> Option<FieldValue> {
    read_dict_property(sco, "hashes", key)
        .or_else(|| read_dict_property(sco, "environment_variables", key))
}

fn read_dict_property(sco: &ScoObject, property: &str, key: &str) -> Option<FieldValue> {
    match (sco, property) {
        (ScoObject::File(file), "hashes") => file.hashes.get(key).cloned().map(FieldValue::Str),
        (ScoObject::Process(process), "environment_variables") => process
            .environment_variables
            .get(key)
            .cloned()
            .map(FieldValue::Str),
        (ScoObject::Artifact(artifact), "hashes") => {
            artifact.hashes.get(key).cloned().map(FieldValue::Str)
        }
        (ScoObject::NetworkTraffic(nt), "ipfix") => nt
            .ipfix
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .map(FieldValue::Str),
        _ => None,
    }
}

fn sco_common(sco: &ScoObject) -> &crate::model::common::ScoCommonProps {
    sco.common_props()
}

fn hash_map_nonempty(sco: &ScoObject) -> bool {
    match sco {
        ScoObject::File(file) => !file.hashes.is_empty(),
        ScoObject::Artifact(artifact) => !artifact.hashes.is_empty(),
        ScoObject::X509Certificate(cert) => !cert.hashes.is_empty(),
        _ => false,
    }
}

fn x509_ext_field(ext: &X509V3Extensions, name: &str) -> Option<FieldValue> {
    match name {
        "basic_constraints" => ext
            .basic_constraints
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "name_constraints" => ext
            .name_constraints
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "policy_constraints" => ext
            .policy_constraints
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "key_usage" => ext
            .key_usage
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "extended_key_usage" => ext
            .extended_key_usage
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "subject_key_identifier" => ext
            .subject_key_identifier
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "authority_key_identifier" => ext
            .authority_key_identifier
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "subject_alternative_name" => ext
            .subject_alternative_name
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "issuer_alternative_name" => ext
            .issuer_alternative_name
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "subject_directory_attributes" => ext
            .subject_directory_attributes
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "crl_distribution_points" => ext
            .crl_distribution_points
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "inhibit_any_policy" => ext
            .inhibit_any_policy
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "certificate_policies" => ext
            .certificate_policies
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "policy_mappings" => ext
            .policy_mappings
            .as_deref()
            .map(|s| FieldValue::Str(s.to_owned())),
        "private_key_usage_period_not_before" => ext
            .private_key_usage_period_not_before
            .as_ref()
            .map(|ts| FieldValue::Timestamp(ts.clone())),
        "private_key_usage_period_not_after" => ext
            .private_key_usage_period_not_after
            .as_ref()
            .map(|ts| FieldValue::Timestamp(ts.clone())),
        _ => None,
    }
}

fn extension_entry_props<'a>(
    sco: &'a ScoObject,
    key: &str,
) -> Option<&'a BTreeMap<String, serde_json::Value>> {
    sco_common(sco)
        .extensions
        .get(key)
        .map(|entry| &entry.properties)
}

fn extension_property_value<'a>(sco: &'a ScoObject, name: &str) -> Option<&'a serde_json::Value> {
    let ScoObject::File(file) = sco else {
        return None;
    };
    file.common
        .extensions
        .get(WindowsPeBinaryExt::KEY)
        .and_then(|entry| entry.properties.get(name))
}

fn json_value_to_field(value: &serde_json::Value) -> Option<FieldValue> {
    if value.is_object() && !value.as_object().is_some_and(|o| o.is_empty()) {
        return Some(FieldValue::Bool(true));
    }
    if value.is_array() && !value.as_array().is_some_and(|a| a.is_empty()) {
        return Some(FieldValue::Bool(true));
    }
    json_scalar_to_field(value)
}

fn json_scalar_to_field(value: &serde_json::Value) -> Option<FieldValue> {
    match value {
        serde_json::Value::String(s) => {
            if let Ok(ts) = StixTimestamp::parse(s) {
                Some(FieldValue::Timestamp(ts))
            } else {
                Some(FieldValue::Str(s.clone()))
            }
        }
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(FieldValue::Int)
            .or_else(|| n.as_f64().map(FieldValue::Float)),
        serde_json::Value::Bool(b) => Some(FieldValue::Bool(*b)),
        serde_json::Value::Null => Some(FieldValue::Bool(true)),
        _ => None,
    }
}

fn pe_section_floats(sco: &ScoObject) -> Vec<WalkTarget<'_>> {
    let ScoObject::File(file) = sco else {
        return Vec::new();
    };
    let Some(entry) = file.common.extensions.get(WindowsPeBinaryExt::KEY) else {
        return Vec::new();
    };
    let Some(sections) = entry.properties.get("sections").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    sections
        .iter()
        .filter_map(|section| section.get("entropy").and_then(|v| v.as_f64()))
        .map(WalkTarget::Float)
        .collect()
}

fn ref_list_ids<'a>(sco: &'a ScoObject, name: &str) -> Vec<&'a StixId> {
    let mut ids = Vec::new();
    let mut i = 0;
    loop {
        let idx = i.to_string();
        match QueryableStixObject::get_field(sco, &[name, idx.as_str()]) {
            Some(QueryValue::Id(id)) => {
                ids.push(id);
                i += 1;
            }
            _ => break,
        }
    }
    ids
}

fn resolve_ref_property<'a>(
    sco: &'a ScoObject,
    name: &str,
    bundle: Option<&'a Bundle>,
    path_str: &str,
) -> Result<Vec<&'a ScoObject>, PatternMatchError> {
    let Some(bundle) = bundle else {
        return Err(PatternMatchError::RefResolution {
            path: path_str.to_owned(),
            msg: "bundle required for _ref dereference".into(),
        });
    };

    if name.ends_with("_refs") {
        return ref_list_ids(sco, name)
            .into_iter()
            .map(|id| resolve_id(bundle, id, path_str))
            .collect::<Result<Vec<_>, _>>();
    }

    let id = ref_id_for_property(sco, name).ok_or_else(|| PatternMatchError::RefResolution {
        path: path_str.to_owned(),
        msg: format!("property `{name}` is absent or not a reference"),
    })?;
    Ok(vec![resolve_id(bundle, id, path_str)?])
}

fn resolve_id<'a>(
    bundle: &'a Bundle,
    id: &StixId,
    path_str: &str,
) -> Result<&'a ScoObject, PatternMatchError> {
    let obj = bundle
        .get(id)
        .ok_or_else(|| PatternMatchError::RefResolution {
            path: path_str.to_owned(),
            msg: format!("object `{id}` not found in bundle"),
        })?;
    match obj {
        crate::model::StixObject::Sco(sco) => Ok(sco),
        _ => Err(PatternMatchError::RefResolution {
            path: path_str.to_owned(),
            msg: format!("object `{id}` is not an SCO"),
        }),
    }
}

fn ref_id_for_property<'a>(sco: &'a ScoObject, name: &str) -> Option<&'a StixId> {
    match QueryableStixObject::get_field(sco, &[name]) {
        Some(QueryValue::Id(id)) => Some(id),
        _ => None,
    }
}

fn query_to_field(value: QueryValue<'_>) -> Option<FieldValue> {
    match value {
        QueryValue::Str(s) => Some(FieldValue::Str(s.to_owned())),
        QueryValue::Int(n) => Some(FieldValue::Int(n)),
        QueryValue::Float(f) => Some(FieldValue::Float(f)),
        QueryValue::Bool(b) => Some(FieldValue::Bool(b)),
        QueryValue::Timestamp(ts) => Some(FieldValue::Timestamp(ts.clone())),
        QueryValue::Bytes(b) => Some(FieldValue::Bytes(b.to_vec())),
        QueryValue::Id(_) | QueryValue::Null => None,
    }
}

fn is_ref_property(name: &str) -> bool {
    name.ends_with("_ref") && !name.ends_with("_refs")
}

pub(crate) fn format_object_path(path: &ObjectPath) -> String {
    let mut out = path.object_type.type_name().to_owned();
    out.push(':');
    for (idx, step) in path.steps.iter().enumerate() {
        if idx > 0 {
            match step {
                PathStep::Property(_) | PathStep::DictKey(_) => out.push('.'),
                PathStep::Index(_) | PathStep::AnyIndex | PathStep::Reference => {}
            }
        }
        match step {
            PathStep::Property(name) => out.push_str(name),
            PathStep::DictKey(key) => {
                out.push('\'');
                out.push_str(key);
                out.push('\'');
            }
            PathStep::Index(i) => {
                out.push('[');
                out.push_str(&i.to_string());
                out.push(']');
            }
            PathStep::AnyIndex => out.push_str("[*]"),
            PathStep::Reference => out.push_str("._ref"),
        }
    }
    out
}

pub(crate) fn cidr_subset(value: &str, network: &str) -> bool {
    let Some(left) = parse_ip_net(value) else {
        return false;
    };
    let Some(right) = parse_ip_net(network) else {
        return false;
    };
    left.prefix_len() >= right.prefix_len() && right.contains(&left.addr())
}

pub(crate) fn cidr_superset(value: &str, network: &str) -> bool {
    cidr_subset(network, value)
}

fn parse_ip_net(value: &str) -> Option<ipnet::IpNet> {
    if let Ok(net) = value.parse::<ipnet::IpNet>() {
        return Some(net);
    }
    let ip = value.parse::<IpAddr>().ok()?;
    Some(match ip {
        IpAddr::V4(v4) => ipnet::IpNet::V4(v4.into()),
        IpAddr::V6(v6) => ipnet::IpNet::V6(v6.into()),
    })
}

pub(crate) fn decode_payload_bin(raw: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::StixId;
    use crate::model::Bundle;

    #[test]
    fn resolve_id_rejects_non_sco_object() {
        let bundle = Bundle::parse(
            r#"{
              "type": "bundle",
              "id": "bundle--00000000-0000-0000-0000-000000000098",
              "objects": [{
                "type": "identity",
                "spec_version": "2.1",
                "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
                "created": "2016-04-06T20:03:00.000Z",
                "modified": "2016-04-06T20:03:00.000Z",
                "name": "John Smith",
                "identity_class": "individual"
              }]
            }"#,
        )
        .expect("bundle with identity");
        let id = StixId::parse("identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e").expect("id");
        let err = resolve_id(&bundle, &id, "process:image_ref._ref.name").unwrap_err();
        assert!(matches!(err, PatternMatchError::RefResolution { .. }));
        assert!(err.to_string().contains("is not an SCO"));
    }
}
