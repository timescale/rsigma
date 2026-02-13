//! Completions for Sigma detection rules.
//!
//! Provides context-aware completions for:
//! - Field modifiers (`|contains`, `|endswith`, etc.)
//! - Top-level keys (`title:`, `status:`, `level:`, etc.)
//! - Enum values (`status:` -> stable/test/experimental/...)
//! - Logsource keys and common values
//! - MITRE ATT&CK tags
//! - Selection names in condition expressions

use tower_lsp::lsp_types::*;

use crate::data;

/// Produce completions for the given cursor position.
pub fn complete(text: &str, position: Position) -> Vec<CompletionItem> {
    let lines: Vec<&str> = text.lines().collect();
    let line_idx = position.line as usize;

    if line_idx >= lines.len() {
        return vec![];
    }

    let line = lines[line_idx];
    let col = (position.character as usize).min(line.len());
    // Snap to char boundary to avoid panics on multi-byte UTF-8
    let col = if line.is_char_boundary(col) {
        col
    } else {
        (0..col)
            .rev()
            .find(|&i| line.is_char_boundary(i))
            .unwrap_or(0)
    };
    let prefix = &line[..col];

    // Determine completion context
    let trimmed = prefix.trim_start();
    let indent = prefix.len() - trimmed.len();

    // 1. Modifier completions — triggered by `|` in a field name
    if let Some(pos) = trimmed.rfind('|') {
        let after_pipe = &trimmed[pos + 1..];
        return modifier_completions(after_pipe);
    }

    // 2. Tag completions — inside `tags:` section
    if is_in_section(&lines, line_idx, "tags") && trimmed.starts_with("- ") {
        let tag_prefix = trimmed.strip_prefix("- ").unwrap_or("");
        return tag_completions(tag_prefix);
    }

    // 3. Condition completions — inside `condition:` value
    if trimmed.starts_with("condition:") || is_in_section(&lines, line_idx, "condition") {
        let cond_text = trimmed
            .strip_prefix("condition:")
            .unwrap_or(trimmed)
            .trim_start();
        return condition_completions(text, cond_text);
    }

    // 4. Value completions for known keys
    if let Some(colon_pos) = trimmed.find(':') {
        let key = trimmed[..colon_pos].trim();
        let value_prefix = trimmed[colon_pos + 1..].trim_start();
        if let Some(items) = value_completions(key, value_prefix) {
            return items;
        }
    }

    // 5. Top-level key completions (indent == 0 and line is empty or partial key)
    if indent == 0 && !trimmed.contains(':') {
        return top_level_key_completions(trimmed);
    }

    // 6. Logsource sub-key completions
    if indent > 0 && is_in_section(&lines, line_idx, "logsource") && !trimmed.contains(':') {
        return logsource_key_completions(trimmed);
    }

    // 7. Detection sub-key completions
    if indent > 0 && is_in_section(&lines, line_idx, "detection") && !trimmed.contains(':') {
        return detection_key_completions(trimmed);
    }

    vec![]
}

/// Check if the current line is inside a given top-level section.
///
/// Accepts pre-split lines to avoid redundant re-splitting.
fn is_in_section(lines: &[&str], current_line: usize, section: &str) -> bool {
    let pattern = format!("{section}:");
    for line in lines[..current_line].iter().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed.len();

        // Found a top-level key
        if indent == 0 && trimmed.ends_with(':') {
            return trimmed == pattern;
        }

        // Found a different top-level key with value
        if indent == 0 && trimmed.contains(':') {
            let key = trimmed.split(':').next().unwrap_or("");
            return key == section;
        }
    }
    false
}

// =============================================================================
// Modifier completions
// =============================================================================

fn modifier_completions(prefix: &str) -> Vec<CompletionItem> {
    data::MODIFIERS
        .iter()
        .filter(|(name, _)| name.starts_with(prefix))
        .map(|(name, doc)| CompletionItem {
            label: name.to_string(),
            kind: Some(CompletionItemKind::ENUM_MEMBER),
            detail: Some(doc.to_string()),
            insert_text: Some(name.to_string()),
            ..Default::default()
        })
        .collect()
}

// =============================================================================
// Tag completions (MITRE ATT&CK tactics + common tags)
// =============================================================================

fn tag_completions(prefix: &str) -> Vec<CompletionItem> {
    /// Non-MITRE tags for completion.
    const EXTRA_TAGS: &[(&str, &str)] = &[
        ("cve.", "CVE identifier (e.g. cve.2024.1234)"),
        ("detection.dfir", "DFIR detection"),
        ("detection.emerging_threats", "Emerging threats detection"),
        ("detection.threat_hunting", "Threat hunting detection"),
        ("tlp.white", "TLP:WHITE \u{2014} Unlimited disclosure"),
        ("tlp.green", "TLP:GREEN \u{2014} Community-wide"),
        ("tlp.amber", "TLP:AMBER \u{2014} Limited disclosure"),
        ("tlp.red", "TLP:RED \u{2014} Named recipients only"),
    ];

    data::MITRE_TACTICS
        .iter()
        .chain(EXTRA_TAGS.iter())
        .filter(|(tag, _)| tag.starts_with(prefix))
        .map(|(tag, doc)| CompletionItem {
            label: tag.to_string(),
            kind: Some(CompletionItemKind::VALUE),
            detail: Some(doc.to_string()),
            ..Default::default()
        })
        .collect()
}

// =============================================================================
// Condition completions (selection names + keywords)
// =============================================================================

fn condition_completions(text: &str, prefix: &str) -> Vec<CompletionItem> {
    let mut items = Vec::new();

    // Extract selection names from the detection block
    let selection_names = extract_selection_names(text);
    for name in &selection_names {
        if name.starts_with(prefix) || prefix.is_empty() {
            items.push(CompletionItem {
                label: name.clone(),
                kind: Some(CompletionItemKind::VARIABLE),
                detail: Some("Detection selection".to_string()),
                ..Default::default()
            });
        }
    }

    // Condition keywords
    let keywords: &[(&str, &str)] = &[
        ("and", "Boolean AND"),
        ("or", "Boolean OR"),
        ("not", "Boolean NOT"),
        ("1 of", "At least one of the matching selections"),
        ("all of", "All matching selections"),
        ("1 of them", "At least one of all selections"),
        ("all of them", "All selections must match"),
    ];

    for (kw, doc) in keywords {
        if kw.starts_with(prefix) || prefix.is_empty() {
            items.push(CompletionItem {
                label: kw.to_string(),
                kind: Some(CompletionItemKind::KEYWORD),
                detail: Some(doc.to_string()),
                ..Default::default()
            });
        }
    }

    items
}

/// Extract selection names from the `detection:` block of a Sigma YAML.
fn extract_selection_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_detection = false;
    let mut detection_indent: Option<usize> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = line.len() - trimmed.len();

        // Enter detection block
        if indent == 0 && (trimmed == "detection:" || trimmed.starts_with("detection:")) {
            in_detection = true;
            detection_indent = None;
            continue;
        }

        // Exit detection block (another top-level key)
        if indent == 0 && trimmed.contains(':') && in_detection {
            in_detection = false;
            continue;
        }

        if in_detection {
            // First indented key sets the detection indent level
            if detection_indent.is_none() && trimmed.ends_with(':') {
                detection_indent = Some(indent);
            }

            if let Some(det_indent) = detection_indent
                && indent == det_indent
                && trimmed.ends_with(':')
            {
                let key = &trimmed[..trimmed.len() - 1];
                if key != "condition" {
                    names.push(key.to_string());
                }
            }
        }
    }

    names
}

// =============================================================================
// Value completions for known keys
// =============================================================================

fn value_completions(key: &str, prefix: &str) -> Option<Vec<CompletionItem>> {
    let values: &[(&str, &str)] = match key {
        "status" => &[
            ("stable", "Confirmed and widely tested"),
            ("test", "Under testing, may have FPs"),
            ("experimental", "New rule, expect FPs"),
            ("deprecated", "No longer maintained"),
            ("unsupported", "Cannot be used as-is"),
        ],
        "level" => &[
            ("informational", "No threat, just informational"),
            ("low", "Rarely interesting"),
            ("medium", "Might warrant investigation"),
            ("high", "Likely malicious activity"),
            ("critical", "Almost certainly malicious"),
        ],
        "product" => &[
            ("windows", "Microsoft Windows"),
            ("linux", "Linux"),
            ("macos", "Apple macOS"),
            ("aws", "Amazon Web Services"),
            ("azure", "Microsoft Azure"),
            ("gcp", "Google Cloud Platform"),
            ("m365", "Microsoft 365"),
            ("okta", "Okta Identity"),
            ("github", "GitHub"),
        ],
        "category" => &[
            ("process_creation", "Process creation events"),
            ("file_event", "File system events"),
            ("file_change", "File change/modification events"),
            ("file_rename", "File rename events"),
            ("file_delete", "File deletion events"),
            ("file_access", "File access events"),
            ("registry_event", "Windows Registry events"),
            ("registry_set", "Registry value set"),
            ("registry_add", "Registry key creation"),
            ("registry_delete", "Registry key/value deletion"),
            ("network_connection", "Network connections"),
            ("dns_query", "DNS queries"),
            ("image_load", "DLL/image load events"),
            ("driver_load", "Driver load events"),
            ("pipe_created", "Named pipe creation"),
            ("ps_script", "PowerShell script execution"),
            ("ps_module", "PowerShell module logging"),
            ("ps_classic_start", "PowerShell classic start"),
            ("wmi_event", "WMI event subscription"),
            ("create_remote_thread", "Remote thread creation"),
            ("create_stream_hash", "Alternate data stream"),
            ("sysmon_error", "Sysmon operational errors"),
            ("sysmon_status", "Sysmon status events"),
            ("clipboard_capture", "Clipboard capture"),
            ("firewall", "Firewall events"),
            ("webserver", "Web server logs"),
            ("proxy", "Proxy logs"),
            ("antivirus", "Antivirus detections"),
        ],
        "service" => &[
            ("sysmon", "Sysmon"),
            ("security", "Windows Security"),
            ("system", "Windows System"),
            ("application", "Windows Application"),
            ("powershell", "PowerShell"),
            ("powershell-classic", "PowerShell Classic"),
            ("windefend", "Windows Defender"),
            ("applocker", "AppLocker"),
            ("firewall-as", "Windows Firewall"),
            ("bits-client", "BITS Client"),
            ("codeintegrity-operational", "Code Integrity"),
            ("dns-server", "DNS Server"),
            ("driver-framework", "Driver Framework"),
            ("msexchange-management", "Exchange Management"),
            ("ntlm", "NTLM Authentication"),
            ("openssh", "OpenSSH"),
            ("printservice-admin", "Print Service Admin"),
            ("printservice-operational", "Print Service Operational"),
            ("smbclient-security", "SMB Client Security"),
            ("taskscheduler", "Task Scheduler"),
            (
                "terminalservices-localsessionmanager",
                "Terminal Services LSM",
            ),
            ("wmi", "WMI"),
        ],
        _ => return None,
    };

    Some(
        values
            .iter()
            .filter(|(val, _)| val.starts_with(prefix) || prefix.is_empty())
            .map(|(val, doc)| CompletionItem {
                label: val.to_string(),
                kind: Some(CompletionItemKind::ENUM_MEMBER),
                detail: Some(doc.to_string()),
                ..Default::default()
            })
            .collect(),
    )
}

// =============================================================================
// Top-level key completions (with snippet placeholders)
// =============================================================================

fn top_level_key_completions(prefix: &str) -> Vec<CompletionItem> {
    let keys: &[(&str, &str, &str)] = &[
        ("title", "title: $0", "Rule title (required)"),
        ("id", "id: $0", "Unique UUID identifier"),
        (
            "related",
            "related:\n    - id: $1\n      type: $0",
            "Related rules",
        ),
        ("status", "status: $0", "Rule maturity status"),
        ("description", "description: $0", "Detailed description"),
        ("references", "references:\n    - $0", "External references"),
        ("author", "author: $0", "Rule author"),
        ("date", "date: $0", "Creation date (YYYY-MM-DD)"),
        (
            "modified",
            "modified: $0",
            "Last modified date (YYYY-MM-DD)",
        ),
        ("tags", "tags:\n    - $0", "Classification tags"),
        (
            "logsource",
            "logsource:\n    category: $1\n    product: $0",
            "Log source definition",
        ),
        (
            "detection",
            "detection:\n    ${1:selection}:\n        ${2:FieldName}: ${3:value}\n    condition: ${1:selection}$0",
            "Detection logic",
        ),
        (
            "falsepositives",
            "falsepositives:\n    - $0",
            "Known false positives",
        ),
        ("level", "level: $0", "Severity level"),
        (
            "fields",
            "fields:\n    - $0",
            "Interesting fields to extract",
        ),
        (
            "correlation",
            "correlation:\n    type: $1\n    rules:\n        - $2\n    group-by:\n        - $3\n    timespan: $4\n    condition:\n        gte: $0",
            "Correlation rule",
        ),
        (
            "filter",
            "filter:\n    rules:\n        - $1\n    ${2:selection}:\n        ${3:FieldName}: ${4:value}\n    condition: ${2:selection}$0",
            "Filter rule",
        ),
    ];

    keys.iter()
        .filter(|(key, _, _)| key.starts_with(prefix) || prefix.is_empty())
        .map(|(key, snippet, doc)| CompletionItem {
            label: key.to_string(),
            kind: Some(CompletionItemKind::PROPERTY),
            detail: Some(doc.to_string()),
            insert_text: Some(snippet.to_string()),
            insert_text_format: Some(InsertTextFormat::SNIPPET),
            ..Default::default()
        })
        .collect()
}

// =============================================================================
// Logsource sub-key completions
// =============================================================================

fn logsource_key_completions(prefix: &str) -> Vec<CompletionItem> {
    let keys: &[(&str, &str)] = &[
        ("category", "Log category (e.g. process_creation)"),
        ("product", "Log product (e.g. windows)"),
        ("service", "Log service (e.g. sysmon)"),
        ("definition", "Logsource definition note"),
    ];

    keys.iter()
        .filter(|(key, _)| key.starts_with(prefix) || prefix.is_empty())
        .map(|(key, doc)| CompletionItem {
            label: format!("{key}: "),
            kind: Some(CompletionItemKind::PROPERTY),
            detail: Some(doc.to_string()),
            ..Default::default()
        })
        .collect()
}

// =============================================================================
// Detection sub-key completions
// =============================================================================

fn detection_key_completions(prefix: &str) -> Vec<CompletionItem> {
    let keys: &[(&str, &str)] = &[
        ("selection", "Detection selection block"),
        ("filter", "Filter block"),
        ("condition", "Boolean condition expression"),
    ];

    keys.iter()
        .filter(|(key, _)| key.starts_with(prefix) || prefix.is_empty())
        .map(|(key, doc)| CompletionItem {
            label: format!("{key}: "),
            kind: Some(CompletionItemKind::PROPERTY),
            detail: Some(doc.to_string()),
            ..Default::default()
        })
        .collect()
}
