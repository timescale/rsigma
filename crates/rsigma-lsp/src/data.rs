//! Shared data constants for Sigma detection rules.
//!
//! Centralises modifier descriptions and MITRE ATT&CK tactic metadata so that
//! hover, completion, and other features stay in sync.

/// Sigma field modifiers: `(name, description)`.
pub const MODIFIERS: &[(&str, &str)] = &[
    ("contains", "Match substring anywhere in the field value"),
    ("startswith", "Match prefix of the field value"),
    ("endswith", "Match suffix of the field value"),
    (
        "all",
        "All values in the list must match (AND logic instead of OR)",
    ),
    ("base64", "Match the base64-encoded form of the value"),
    (
        "base64offset",
        "Match any of the three base64 offset variants",
    ),
    ("wide", "Match the UTF-16LE encoded form"),
    ("utf16le", "Match the UTF-16LE encoded form"),
    ("utf16be", "Match the UTF-16BE encoded form"),
    ("utf16", "Match both UTF-16LE and UTF-16BE encoded forms"),
    (
        "windash",
        "Expand dash variants for Windows CLI (-  /  \u{2013}  \u{2014}  \u{2015})",
    ),
    ("re", "Treat the value as a regular expression"),
    ("cidr", "Match IP addresses against a CIDR range"),
    (
        "cased",
        "Case-sensitive matching (default is case-insensitive)",
    ),
    (
        "exists",
        "Check if the field exists (true) or is absent (false)",
    ),
    ("expand", "Expand placeholders in the value"),
    ("fieldref", "Value references another field name"),
    ("gt", "Field value must be greater than the specified value"),
    ("gte", "Field value must be greater than or equal"),
    ("lt", "Field value must be less than the specified value"),
    ("lte", "Field value must be less than or equal"),
    ("neq", "Field value must not equal the specified value"),
    ("i", "Regex flag: case insensitive"),
    ("m", "Regex flag: multiline"),
    ("s", "Regex flag: dot matches all"),
];

/// MITRE ATT&CK tactics: `(tag, description)`.
pub const MITRE_TACTICS: &[(&str, &str)] = &[
    ("attack.initial_access", "Initial Access (TA0001)"),
    ("attack.execution", "Execution (TA0002)"),
    ("attack.persistence", "Persistence (TA0003)"),
    (
        "attack.privilege_escalation",
        "Privilege Escalation (TA0004)",
    ),
    ("attack.defense_evasion", "Defense Evasion (TA0005)"),
    ("attack.credential_access", "Credential Access (TA0006)"),
    ("attack.discovery", "Discovery (TA0007)"),
    ("attack.lateral_movement", "Lateral Movement (TA0008)"),
    ("attack.collection", "Collection (TA0009)"),
    ("attack.exfiltration", "Exfiltration (TA0010)"),
    ("attack.command_and_control", "Command and Control (TA0011)"),
    ("attack.impact", "Impact (TA0040)"),
    (
        "attack.resource_development",
        "Resource Development (TA0042)",
    ),
    ("attack.reconnaissance", "Reconnaissance (TA0043)"),
];
