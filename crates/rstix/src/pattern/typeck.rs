//! STIX pattern type-checker (STIX Specification §9.5–§9.6).

use crate::core::ScoKind;
use crate::pattern::ast::{
    Comparison, ComparisonOp, ComparisonTree, ObjectPath, PathStep, PatternAst, PatternConstant,
    PatternScoType,
};
use crate::pattern::error::PatternError;

/// Type-check a parsed STIX pattern AST.
///
/// Validates cyber-observable property paths, `_ref` / `_refs` dereference chains,
/// comparison operators against property types, and constant types on the right-hand side.
///
/// # Errors
///
/// Returns [`PatternError::TypeError`] when a path, operator, or constant is incompatible
/// with the STIX 2.1 SCO schema.
pub fn type_check(ast: &PatternAst) -> Result<(), PatternError> {
    type_check_node(ast)
}

fn type_check_node(node: &PatternAst) -> Result<(), PatternError> {
    match node {
        PatternAst::Observation(obs) => type_check_tree(&obs.root),
        PatternAst::And { left, right, .. }
        | PatternAst::Or { left, right, .. }
        | PatternAst::FollowedBy { left, right, .. } => {
            type_check_node(left)?;
            type_check_node(right)
        }
        PatternAst::Within { inner, .. }
        | PatternAst::Repeats { inner, .. }
        | PatternAst::StartStop { inner, .. } => type_check_node(inner),
    }
}

fn type_check_tree(tree: &ComparisonTree) -> Result<(), PatternError> {
    match tree {
        ComparisonTree::Cmp(cmp) => type_check_comparison(cmp),
        ComparisonTree::And { left, right, .. } | ComparisonTree::Or { left, right, .. } => {
            type_check_tree(left)?;
            type_check_tree(right)
        }
        ComparisonTree::Not { inner, .. } => type_check_tree(inner),
    }
}

fn type_check_comparison(cmp: &Comparison) -> Result<(), PatternError> {
    let path_str = format_object_path(&cmp.path);
    let resolved = resolve_path(&cmp.path)?;
    validate_operator(&path_str, resolved.kind, cmp.op, resolved.via_dict_key)?;
    if cmp.op != ComparisonOp::Exists {
        let value = cmp.value.as_ref().ok_or_else(|| {
            type_error(
                &cmp.path,
                "comparison operator requires a right-hand constant",
            )
        })?;
        validate_constant(&path_str, resolved.kind, cmp.op, value)?;
    }
    Ok(())
}

/// Resolved value kind at the end of an object path.
struct ResolvedType {
    kind: ValueKind,
    via_dict_key: bool,
}

/// Property value kinds for pattern comparisons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum ValueKind {
    String,
    Integer,
    Float,
    Boolean,
    Timestamp,
    Hash,
    ExtensionMap,
    StringList,
    StringListMap,
    IntegerList,
    ObjectList,
    Object,
    Ref,
    RefList,
}

/// Static property metadata.
#[derive(Clone, Copy, Debug)]
struct PropSchema {
    kind: ValueKind,
    ref_targets: &'static [ScoKind],
    nest: NestKind,
}

/// Nested object schema after list indexing or object property access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NestKind {
    None,
    MimePart,
    RegistryValue,
    X509Extensions,
    PeSection,
}

/// Path resolution context (SCO type or union after `_ref`).
#[derive(Clone, Copy, Debug)]
enum PathContext {
    Sco(ScoKind),
    Custom,
    Union(&'static [ScoKind]),
    Nested(NestKind),
    Extension(&'static str),
    ExtensionUnknown,
}

// --- ref target slices -------------------------------------------------------

const REF_ARTIFACT: &[ScoKind] = &[ScoKind::Artifact];
const REF_DIRECTORY: &[ScoKind] = &[ScoKind::Directory];
const REF_EMAIL_ADDR: &[ScoKind] = &[ScoKind::EmailAddr];
const REF_FILE: &[ScoKind] = &[ScoKind::File];
const REF_NETWORK_TRAFFIC: &[ScoKind] = &[ScoKind::NetworkTraffic];
const REF_PROCESS: &[ScoKind] = &[ScoKind::Process];
const REF_USER_ACCOUNT: &[ScoKind] = &[ScoKind::UserAccount];
const REF_MAC_ADDR: &[ScoKind] = &[ScoKind::MacAddr];
const REF_AUTONOMOUS_SYSTEM: &[ScoKind] = &[ScoKind::AutonomousSystem];
const REF_DIR_CONTAINS: &[ScoKind] = &[ScoKind::File, ScoKind::Directory];
const REF_DOMAIN_RESOLVES: &[ScoKind] =
    &[ScoKind::Ipv4Addr, ScoKind::Ipv6Addr, ScoKind::DomainName];
const REF_NT_ENDPOINT: &[ScoKind] = &[
    ScoKind::Ipv4Addr,
    ScoKind::Ipv6Addr,
    ScoKind::MacAddr,
    ScoKind::DomainName,
];
const REF_MIME_BODY_RAW: &[ScoKind] = &[ScoKind::Artifact, ScoKind::File];

const fn prop(kind: ValueKind) -> PropSchema {
    PropSchema {
        kind,
        ref_targets: &[],
        nest: NestKind::None,
    }
}

const fn prop_ref(kind: ValueKind, targets: &'static [ScoKind]) -> PropSchema {
    PropSchema {
        kind,
        ref_targets: targets,
        nest: NestKind::None,
    }
}

const fn prop_object_list(nest: NestKind) -> PropSchema {
    PropSchema {
        kind: ValueKind::ObjectList,
        ref_targets: &[],
        nest,
    }
}

const fn prop_object(nest: NestKind) -> PropSchema {
    PropSchema {
        kind: ValueKind::Object,
        ref_targets: &[],
        nest,
    }
}

fn common_property(name: &str) -> Option<PropSchema> {
    match name {
        // STIX §9.8: `network-traffic:dst_ref.type = 'ipv4-addr'` after `_ref` dereference.
        "type" => Some(prop(ValueKind::String)),
        "defanged" => Some(prop(ValueKind::Boolean)),
        "id" => Some(prop(ValueKind::String)),
        "spec_version" => Some(prop(ValueKind::String)),
        "extensions" => Some(prop(ValueKind::ExtensionMap)),
        _ => None,
    }
}

fn lookup_property(ctx: PathContext, name: &str) -> Result<PropSchema, PatternError> {
    let schema = match ctx {
        PathContext::Custom => common_property(name).or(Some(prop(ValueKind::String))),
        PathContext::ExtensionUnknown => Some(prop(ValueKind::String)),
        PathContext::Extension(key) => extension_property(key, name),
        PathContext::Sco(kind) => sco_property(kind, name),
        PathContext::Union(kinds) => lookup_union(kinds, name),
        PathContext::Nested(nest) => nested_property(nest, name),
    };
    schema.ok_or_else(|| type_error_path_ctx(ctx, name, "unknown property"))
}

fn lookup_union(kinds: &[ScoKind], name: &str) -> Option<PropSchema> {
    kinds.iter().find_map(|&kind| sco_property(kind, name))
}

fn sco_property(kind: ScoKind, name: &str) -> Option<PropSchema> {
    if let Some(common) = common_property(name) {
        return Some(common);
    }
    match kind {
        ScoKind::Artifact => match name {
            "mime_type" | "payload_bin" | "url" | "encryption_algorithm" | "decryption_key" => {
                Some(prop(ValueKind::String))
            }
            "hashes" => Some(prop(ValueKind::Hash)),
            _ => None,
        },
        ScoKind::AutonomousSystem => match name {
            "number" => Some(prop(ValueKind::Integer)),
            "name" | "rir" => Some(prop(ValueKind::String)),
            _ => None,
        },
        ScoKind::Directory => match name {
            "path" | "path_enc" => Some(prop(ValueKind::String)),
            "ctime" | "mtime" | "atime" => Some(prop(ValueKind::Timestamp)),
            "contains_refs" => Some(prop_ref(ValueKind::RefList, REF_DIR_CONTAINS)),
            _ => None,
        },
        ScoKind::DomainName => match name {
            "value" => Some(prop(ValueKind::String)),
            "resolves_to_refs" => Some(prop_ref(ValueKind::RefList, REF_DOMAIN_RESOLVES)),
            _ => None,
        },
        ScoKind::EmailAddr => match name {
            "value" | "display_name" => Some(prop(ValueKind::String)),
            "belongs_to_ref" => Some(prop_ref(ValueKind::Ref, REF_USER_ACCOUNT)),
            _ => None,
        },
        ScoKind::EmailMessage => match name {
            "is_multipart" => Some(prop(ValueKind::Boolean)),
            "date" => Some(prop(ValueKind::Timestamp)),
            "content_type" | "message_id" | "subject" | "subject_enc" | "body" | "body_enc" => {
                Some(prop(ValueKind::String))
            }
            "from_ref" | "sender_ref" => Some(prop_ref(ValueKind::Ref, REF_EMAIL_ADDR)),
            "to_refs" | "cc_refs" | "bcc_refs" => {
                Some(prop_ref(ValueKind::RefList, REF_EMAIL_ADDR))
            }
            "received_lines" => Some(prop(ValueKind::StringList)),
            "additional_header_fields" => Some(prop(ValueKind::StringListMap)),
            "body_multipart" => Some(prop_object_list(NestKind::MimePart)),
            "raw_email_ref" => Some(prop_ref(ValueKind::Ref, REF_ARTIFACT)),
            _ => None,
        },
        ScoKind::File => match name {
            "hashes" => Some(prop(ValueKind::Hash)),
            "size" => Some(prop(ValueKind::Integer)),
            "name" | "name_enc" | "magic_number_hex" | "mime_type" => Some(prop(ValueKind::String)),
            // STIX §9.8 example uses `file:created`; data model property is `ctime`.
            "created" | "ctime" | "mtime" | "atime" => Some(prop(ValueKind::Timestamp)),
            "parent_directory_ref" => Some(prop_ref(ValueKind::Ref, REF_DIRECTORY)),
            "contains_refs" => Some(prop_ref(ValueKind::RefList, REF_DIR_CONTAINS)),
            "content_ref" => Some(prop_ref(ValueKind::Ref, REF_ARTIFACT)),
            _ => None,
        },
        ScoKind::Ipv4Addr | ScoKind::Ipv6Addr => match name {
            "value" => Some(prop(ValueKind::String)),
            "resolves_to_refs" => Some(prop_ref(ValueKind::RefList, REF_MAC_ADDR)),
            "belongs_to_refs" => Some(prop_ref(ValueKind::RefList, REF_AUTONOMOUS_SYSTEM)),
            _ => None,
        },
        ScoKind::MacAddr => match name {
            "value" => Some(prop(ValueKind::String)),
            _ => None,
        },
        ScoKind::Mutex => match name {
            "name" => Some(prop(ValueKind::String)),
            _ => None,
        },
        ScoKind::NetworkTraffic => match name {
            "start" | "end" => Some(prop(ValueKind::Timestamp)),
            "is_active" => Some(prop(ValueKind::Boolean)),
            "src_ref" | "dst_ref" => Some(prop_ref(ValueKind::Ref, REF_NT_ENDPOINT)),
            "src_port" | "dst_port" => Some(prop(ValueKind::Integer)),
            "protocols" => Some(prop(ValueKind::StringList)),
            "src_byte_count" | "dst_byte_count" | "src_packets" | "dst_packets" => {
                Some(prop(ValueKind::Integer))
            }
            "ipfix" => Some(prop(ValueKind::Hash)),
            "src_payload_ref" | "dst_payload_ref" => Some(prop_ref(ValueKind::Ref, REF_ARTIFACT)),
            "encapsulates_refs" => Some(prop_ref(ValueKind::RefList, REF_NETWORK_TRAFFIC)),
            "encapsulated_by_ref" => Some(prop_ref(ValueKind::Ref, REF_NETWORK_TRAFFIC)),
            _ => None,
        },
        ScoKind::Process => match name {
            // STIX §9.8 pattern examples use `process:name`; evaluation resolves via image/command_line.
            "name" | "cwd" | "command_line" => Some(prop(ValueKind::String)),
            "is_hidden" => Some(prop(ValueKind::Boolean)),
            "pid" => Some(prop(ValueKind::Integer)),
            "created_time" => Some(prop(ValueKind::Timestamp)),
            "environment_variables" => Some(prop(ValueKind::Hash)),
            "opened_connection_refs" => Some(prop_ref(ValueKind::RefList, REF_NETWORK_TRAFFIC)),
            "creator_user_ref" => Some(prop_ref(ValueKind::Ref, REF_USER_ACCOUNT)),
            "image_ref" => Some(prop_ref(ValueKind::Ref, REF_FILE)),
            "parent_ref" => Some(prop_ref(ValueKind::Ref, REF_PROCESS)),
            "child_refs" => Some(prop_ref(ValueKind::RefList, REF_PROCESS)),
            _ => None,
        },
        ScoKind::Software => match name {
            "name" | "cpe" | "swid" | "vendor" | "version" => Some(prop(ValueKind::String)),
            "languages" => Some(prop(ValueKind::StringList)),
            _ => None,
        },
        ScoKind::Url => match name {
            "value" => Some(prop(ValueKind::String)),
            _ => None,
        },
        ScoKind::UserAccount => match name {
            "user_id" | "credential" | "account_login" | "account_type" | "display_name" => {
                Some(prop(ValueKind::String))
            }
            "is_service_account" | "is_privileged" | "can_escalate_privs" | "is_disabled" => {
                Some(prop(ValueKind::Boolean))
            }
            "account_created"
            | "account_expires"
            | "credential_last_changed"
            | "account_first_login"
            | "account_last_login" => Some(prop(ValueKind::Timestamp)),
            _ => None,
        },
        ScoKind::WindowsRegistryKey => match name {
            "key" => Some(prop(ValueKind::String)),
            "values" => Some(prop_object_list(NestKind::RegistryValue)),
            "modified_time" => Some(prop(ValueKind::Timestamp)),
            "creator_user_ref" => Some(prop_ref(ValueKind::Ref, REF_USER_ACCOUNT)),
            "number_of_subkeys" => Some(prop(ValueKind::Integer)),
            _ => None,
        },
        ScoKind::X509Certificate => match name {
            "is_self_signed" => Some(prop(ValueKind::Boolean)),
            "hashes" => Some(prop(ValueKind::Hash)),
            "version"
            | "serial_number"
            | "signature_algorithm"
            | "issuer"
            | "subject"
            | "subject_public_key_algorithm"
            | "subject_public_key_modulus" => Some(prop(ValueKind::String)),
            "validity_not_before" | "validity_not_after" => Some(prop(ValueKind::Timestamp)),
            "subject_public_key_exponent" => Some(prop(ValueKind::Integer)),
            "x509_v3_extensions" => Some(prop_object(NestKind::X509Extensions)),
            _ => None,
        },
    }
}

fn nested_property(nest: NestKind, name: &str) -> Option<PropSchema> {
    match nest {
        NestKind::MimePart => match name {
            "body" | "content_type" | "content_disposition" => Some(prop(ValueKind::String)),
            "body_raw_ref" => Some(prop_ref(ValueKind::Ref, REF_MIME_BODY_RAW)),
            _ => None,
        },
        NestKind::RegistryValue => match name {
            "name" | "data" | "data_type" => Some(prop(ValueKind::String)),
            _ => None,
        },
        NestKind::X509Extensions => match name {
            "basic_constraints"
            | "name_constraints"
            | "policy_constraints"
            | "key_usage"
            | "extended_key_usage"
            | "subject_key_identifier"
            | "authority_key_identifier"
            | "subject_alternative_name"
            | "issuer_alternative_name"
            | "subject_directory_attributes"
            | "crl_distribution_points"
            | "inhibit_any_policy"
            | "certificate_policies"
            | "policy_mappings" => Some(prop(ValueKind::String)),
            "private_key_usage_period_not_before" | "private_key_usage_period_not_after" => {
                Some(prop(ValueKind::Timestamp))
            }
            _ => None,
        },
        NestKind::PeSection => match name {
            "name" => Some(prop(ValueKind::String)),
            "size" => Some(prop(ValueKind::Integer)),
            "entropy" => Some(prop(ValueKind::Float)),
            _ => None,
        },
        NestKind::None => None,
    }
}

fn extension_property(key: &str, name: &str) -> Option<PropSchema> {
    match key {
        "windows-pebinary-ext" => match name {
            "pe_type"
            | "imphash"
            | "machine_hex"
            | "pointer_to_symbol_table_hex"
            | "characteristics_hex"
            | "checksum_hex"
            | "subsystem_hex"
            | "dll_characteristics_hex"
            | "loader_flags_hex" => Some(prop(ValueKind::String)),
            "number_of_sections" | "number_of_symbols" | "size_of_optional_header" => {
                Some(prop(ValueKind::Integer))
            }
            "time_date_stamp" => Some(prop(ValueKind::Timestamp)),
            "file_header_hashes" => Some(prop(ValueKind::Hash)),
            "sections" => Some(prop_object_list(NestKind::PeSection)),
            _ => None,
        },
        "raster-image-ext" => match name {
            "image_height" | "image_width" | "bits_per_pixel" | "exif_tags" => {
                Some(prop(ValueKind::String))
            }
            _ => None,
        },
        "archive-ext" => match name {
            "contains_refs" => Some(prop_ref(ValueKind::RefList, REF_DIR_CONTAINS)),
            "comment" => Some(prop(ValueKind::String)),
            _ => None,
        },
        "ntfs-ext" => match name {
            "sid" => Some(prop(ValueKind::String)),
            _ => None,
        },
        "pdf-ext" => match name {
            "version" | "document_info_dict" | "pdfid0" | "pdfid1" => Some(prop(ValueKind::String)),
            _ => None,
        },
        "unix-account-ext" => match name {
            "gid" | "uid" | "home_dir" | "shell" | "groups" => Some(prop(ValueKind::String)),
            _ => None,
        },
        "windows-process-ext"
        | "windows-service-ext"
        | "http-request-ext"
        | "tcp-ext"
        | "socket-ext"
        | "icmp-ext" => Some(prop(ValueKind::String)),
        _ => Some(prop(ValueKind::String)),
    }
}

fn resolve_path(path: &ObjectPath) -> Result<ResolvedType, PatternError> {
    let path_str = format_object_path(path);
    let mut ctx = match path.object_type {
        PatternScoType::Known(kind) => PathContext::Sco(kind),
        PatternScoType::Custom(_) => PathContext::Custom,
    };
    let mut kind = ValueKind::String;
    let mut via_dict_key = false;
    let mut ref_targets: &'static [ScoKind] = &[];
    let mut after_ref = false;
    let mut pending_list_nest = NestKind::None;

    for step in &path.steps {
        match step {
            PathStep::Property(name) => {
                let schema = lookup_property(ctx, name).map_err(|_| PatternError::TypeError {
                    path: path_str.clone(),
                    msg: format!("unknown property `{name}`"),
                })?;
                ref_targets = schema.ref_targets;
                after_ref = false;
                kind = schema.kind;
                via_dict_key = false;
                pending_list_nest = if schema.kind == ValueKind::ObjectList {
                    schema.nest
                } else {
                    NestKind::None
                };
                if schema.kind == ValueKind::Object {
                    ctx = PathContext::Nested(schema.nest);
                }
            }
            PathStep::DictKey(key) => {
                kind = match kind {
                    ValueKind::Hash => {
                        via_dict_key = true;
                        ValueKind::String
                    }
                    ValueKind::ExtensionMap => {
                        ctx = extension_context(key.as_str());
                        ValueKind::Object
                    }
                    ValueKind::StringListMap => ValueKind::StringList,
                    _ => {
                        return Err(PatternError::TypeError {
                            path: path_str,
                            msg: "dictionary key subscript requires a dictionary-typed property"
                                .into(),
                        });
                    }
                };
                after_ref = false;
            }
            PathStep::Index(_) | PathStep::AnyIndex => {
                kind = match kind {
                    ValueKind::StringList => ValueKind::String,
                    ValueKind::StringListMap => ValueKind::StringList,
                    ValueKind::RefList if after_ref => {
                        return Err(PatternError::TypeError {
                            path: path_str,
                            msg: "list index cannot follow `_ref` dereference on a reference list"
                                .into(),
                        });
                    }
                    ValueKind::RefList => {
                        // Index selects an element; next property step dereferences via Reference.
                        ValueKind::Ref
                    }
                    ValueKind::ObjectList => {
                        if pending_list_nest == NestKind::None {
                            return Err(PatternError::TypeError {
                                path: path_str,
                                msg: "object list has no nested schema".into(),
                            });
                        }
                        ctx = PathContext::Nested(pending_list_nest);
                        ValueKind::Object
                    }
                    _ => {
                        return Err(PatternError::TypeError {
                            path: path_str,
                            msg: "list index requires a list-typed property".into(),
                        });
                    }
                };
                after_ref = false;
            }
            PathStep::Reference => match kind {
                ValueKind::Ref | ValueKind::RefList => {
                    if ref_targets.is_empty() {
                        return Err(PatternError::TypeError {
                            path: path_str,
                            msg: "reference property has no resolvable SCO target types".into(),
                        });
                    }
                    ctx = PathContext::Union(ref_targets);
                    after_ref = true;
                }
                _ => {
                    return Err(PatternError::TypeError {
                        path: path_str,
                        msg: "`_ref` dereference requires a reference-typed property".into(),
                    });
                }
            },
        }
    }

    Ok(ResolvedType { kind, via_dict_key })
}

fn extension_context(key: &str) -> PathContext {
    match key {
        "windows-pebinary-ext" => PathContext::Extension("windows-pebinary-ext"),
        "raster-image-ext" => PathContext::Extension("raster-image-ext"),
        "archive-ext" => PathContext::Extension("archive-ext"),
        "ntfs-ext" => PathContext::Extension("ntfs-ext"),
        "pdf-ext" => PathContext::Extension("pdf-ext"),
        "unix-account-ext" => PathContext::Extension("unix-account-ext"),
        "windows-process-ext" => PathContext::Extension("windows-process-ext"),
        "windows-service-ext" => PathContext::Extension("windows-service-ext"),
        "http-request-ext" => PathContext::Extension("http-request-ext"),
        "tcp-ext" => PathContext::Extension("tcp-ext"),
        "socket-ext" => PathContext::Extension("socket-ext"),
        "icmp-ext" => PathContext::Extension("icmp-ext"),
        _ => PathContext::ExtensionUnknown,
    }
}

fn validate_operator(
    path: &str,
    kind: ValueKind,
    op: ComparisonOp,
    via_dict_key: bool,
) -> Result<(), PatternError> {
    let effective = if via_dict_key && kind == ValueKind::String {
        ValueKind::String
    } else {
        kind
    };
    if allowed_operators(effective).contains(&op) {
        Ok(())
    } else {
        Err(PatternError::TypeError {
            path: path.to_owned(),
            msg: format!("operator `{op:?}` is not valid for property type `{effective:?}`"),
        })
    }
}

fn allowed_operators(kind: ValueKind) -> &'static [ComparisonOp] {
    use ComparisonOp::*;
    match kind {
        ValueKind::String => &[Eq, NotEq, Like, Matches, In, Exists, IsSubset, IsSuperset],
        ValueKind::Integer | ValueKind::Float => &[Eq, NotEq, Gt, Lt, Gte, Lte, In, Exists],
        ValueKind::Boolean => &[Eq, NotEq, Exists],
        ValueKind::Timestamp => &[Eq, NotEq, Gt, Lt, Gte, Lte, In, Exists],
        ValueKind::Hash => &[IsSubset, IsSuperset, Exists],
        ValueKind::StringList | ValueKind::StringListMap | ValueKind::IntegerList => &[In, Exists],
        ValueKind::ObjectList | ValueKind::Object | ValueKind::ExtensionMap => &[Exists],
        ValueKind::Ref | ValueKind::RefList => &[Eq, NotEq, In, Exists],
    }
}

fn validate_constant(
    path: &str,
    kind: ValueKind,
    op: ComparisonOp,
    value: &PatternConstant,
) -> Result<(), PatternError> {
    match (kind, op, value) {
        (ValueKind::String, _, PatternConstant::String(_)) => Ok(()),
        (ValueKind::String, _, PatternConstant::Hex(_)) => Ok(()),
        (ValueKind::String, ComparisonOp::In, PatternConstant::List(items)) => {
            validate_homogeneous_list(path, items, PatternConstant::is_string)
        }
        (ValueKind::Integer, _, PatternConstant::Int(_)) => Ok(()),
        (ValueKind::Integer, ComparisonOp::In, PatternConstant::List(items)) => {
            validate_homogeneous_list(path, items, PatternConstant::is_int)
        }
        (ValueKind::Float, _, PatternConstant::Float(_))
        | (ValueKind::Float, _, PatternConstant::Int(_)) => Ok(()),
        (ValueKind::Boolean, _, PatternConstant::Bool(_)) => Ok(()),
        (ValueKind::Timestamp, _, PatternConstant::Timestamp(_)) => Ok(()),
        (ValueKind::Timestamp, ComparisonOp::In, PatternConstant::List(items)) => {
            validate_homogeneous_list(path, items, PatternConstant::is_timestamp)
        }
        (
            ValueKind::Hash,
            ComparisonOp::IsSubset | ComparisonOp::IsSuperset,
            PatternConstant::List(items),
        ) => validate_homogeneous_list(path, items, |c| {
            matches!(c, PatternConstant::String(_) | PatternConstant::Hex(_))
        }),
        (ValueKind::Ref | ValueKind::RefList, _, PatternConstant::String(_)) => Ok(()),
        (ValueKind::Ref | ValueKind::RefList, ComparisonOp::In, PatternConstant::List(items)) => {
            validate_homogeneous_list(path, items, PatternConstant::is_string)
        }
        (ValueKind::StringList, ComparisonOp::In, PatternConstant::List(items)) => {
            validate_homogeneous_list(path, items, PatternConstant::is_string)
        }
        (ValueKind::Object, _, PatternConstant::String(_)) => Ok(()),
        _ => Err(PatternError::TypeError {
            path: path.to_owned(),
            msg: format!(
                "constant type `{value:?}` is incompatible with property type `{kind:?}` and operator `{op:?}`"
            ),
        }),
    }
}

fn validate_homogeneous_list(
    path: &str,
    items: &[PatternConstant],
    pred: fn(&PatternConstant) -> bool,
) -> Result<(), PatternError> {
    if items.is_empty() {
        return Err(PatternError::TypeError {
            path: path.to_owned(),
            msg: "list literal must not be empty".into(),
        });
    }
    if items.iter().all(pred) {
        Ok(())
    } else {
        Err(PatternError::TypeError {
            path: path.to_owned(),
            msg: "list elements have incompatible types for this property".into(),
        })
    }
}

impl PatternConstant {
    fn is_string(c: &PatternConstant) -> bool {
        matches!(c, PatternConstant::String(_))
    }

    fn is_int(c: &PatternConstant) -> bool {
        matches!(c, PatternConstant::Int(_))
    }

    fn is_timestamp(c: &PatternConstant) -> bool {
        matches!(c, PatternConstant::Timestamp(_))
    }
}

fn format_object_path(path: &ObjectPath) -> String {
    let mut out = path.object_type.type_name().to_owned();
    out.push(':');
    for (idx, step) in path.steps.iter().enumerate() {
        if idx > 0 {
            match step {
                PathStep::Property(name) => {
                    out.push('.');
                    out.push_str(name);
                }
                PathStep::DictKey(key) => {
                    out.push('.');
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
        } else if let PathStep::Property(name) = step {
            out.push_str(name);
        }
    }
    out
}

fn type_error(path: &ObjectPath, msg: impl Into<String>) -> PatternError {
    PatternError::TypeError {
        path: format_object_path(path),
        msg: msg.into(),
    }
}

fn type_error_path_ctx(ctx: PathContext, name: &str, msg: &str) -> PatternError {
    let ctx_label = match ctx {
        PathContext::Sco(k) => k.as_str(),
        PathContext::Custom => "custom cyber-observable",
        PathContext::Union(_) => "reference target",
        PathContext::Extension(key) => key,
        PathContext::ExtensionUnknown => "extension",
        PathContext::Nested(NestKind::MimePart) => "email MIME part",
        PathContext::Nested(NestKind::RegistryValue) => "registry value",
        PathContext::Nested(NestKind::X509Extensions) => "x509 v3 extensions",
        PathContext::Nested(NestKind::PeSection) => "PE section",
        PathContext::Nested(NestKind::None) => "object",
    };
    PatternError::TypeError {
        path: String::new(),
        msg: format!("{msg} `{name}` on {ctx_label}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::parser;

    fn check(source: &str) -> Result<(), PatternError> {
        let ast = parser::parse_level1(source).expect("parse");
        type_check(&ast)
    }

    fn check_err(source: &str) -> PatternError {
        check(source).unwrap_err()
    }

    #[test]
    fn accepts_file_hash_path() {
        check("[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']")
            .expect("type-check");
    }

    #[test]
    fn accepts_ipv4_equality() {
        check("[ipv4-addr:value = '198.51.100.1/32']").expect("type-check");
    }

    #[test]
    fn accepts_process_in_list() {
        check("[process:name IN ('proccy', 'proximus', 'badproc')]").expect("type-check");
    }

    #[test]
    fn accepts_exists_on_list_property() {
        check("[EXISTS windows-registry-key:values]").expect("type-check");
    }

    #[test]
    fn accepts_ref_chain_from_ref_value() {
        check("[email-message:from_ref.value = 'sender@example.com']").expect("type-check");
    }

    #[test]
    fn accepts_multipart_ref_chain() {
        check("[email-message:body_multipart[*].body_raw_ref.name = 'payload.bin']")
            .expect("type-check");
    }

    #[test]
    fn accepts_network_traffic_ref_value() {
        check("[network-traffic:src_ref.value = '10.0.0.1']").expect("type-check");
    }

    #[test]
    fn accepts_pe_extension_entropy() {
        check("[file:extensions.'windows-pebinary-ext'.sections[*].entropy > 7.0]")
            .expect("type-check");
    }

    #[test]
    fn accepts_dst_ref_type_filter() {
        check("[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.33/32']")
            .expect("type-check");
    }

    #[test]
    fn accepts_issubset_on_ip_value() {
        check(
            "[network-traffic:dst_ref.value ISSUBSET '2001:0db8:dead:beef:0000:0000:0000:0000/64']",
        )
        .expect("type-check");
    }

    #[test]
    fn accepts_hashes_md5_dot_key() {
        check("[file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4']").expect("type-check");
    }

    #[test]
    fn accepts_custom_sco_type() {
        check("[x-usb-device:usbdrive.serial_number = '575833314133343231313937']")
            .expect("type-check");
    }

    #[test]
    fn accepts_image_ref_name() {
        check("[process:image_ref.name = 'fooproc']").expect("type-check");
    }

    #[test]
    fn rejects_unknown_property() {
        let err = check_err("[file:not_a_property = 'x']");
        assert!(matches!(err, PatternError::TypeError { .. }));
        assert!(err.to_string().contains("unknown property"));
    }

    #[test]
    fn rejects_invalid_operator_for_string() {
        let err = check_err("[file:name > 'a']");
        assert!(err.to_string().contains("operator"));
    }

    #[test]
    fn rejects_invalid_operator_for_integer() {
        let err = check_err("[file:size LIKE '100']");
        assert!(err.to_string().contains("operator"));
    }

    #[test]
    fn rejects_wrong_constant_type() {
        let err = check_err("[file:size = 'not-a-number']");
        assert!(err.to_string().contains("incompatible"));
    }

    #[test]
    fn rejects_property_on_wrong_ref_target() {
        let err = check_err("[network-traffic:src_ref.pid = 1234]");
        assert!(err.to_string().contains("unknown property") || err.to_string().contains("pid"));
    }

    #[test]
    fn rejects_dict_key_on_non_hash() {
        let err = check_err("[file:name.'foo' = 'bar']");
        assert!(err.to_string().contains("dictionary-typed"));
    }
}
