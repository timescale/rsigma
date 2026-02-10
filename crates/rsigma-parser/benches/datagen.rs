//! Synthetic Sigma YAML generators for benchmarks.
//!
//! Produces deterministic output when given the same seed, so benchmark runs are
//! reproducible. Each generator returns a `String` of valid Sigma YAML.

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

// ---------------------------------------------------------------------------
// Single-rule generators
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

    // Optionally add a filter
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

/// Generate a single rule with wildcard-heavy patterns.
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

/// Generate a single rule with regex patterns.
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

/// Generate a rule with a complex, deeply nested condition expression.
pub fn gen_complex_condition_rule() -> String {
    // 8 named detections with a complex boolean condition
    let mut yaml = String::from(
        "title: Complex Condition Bench\n\
         id: complex-cond-000001\n\
         logsource:\n\
         \x20   product: windows\n\
         \x20   category: process_creation\n\
         detection:\n",
    );
    for i in 0..8 {
        yaml.push_str(&format!(
            "    sel_{i}:\n        CommandLine|contains: 'val_{i}'\n"
        ));
    }
    yaml.push_str(
        "    condition: (sel_0 or sel_1) and (sel_2 or sel_3) and not (sel_4 and sel_5) or (1 of sel_6 or sel_7)\n\
         level: high\n",
    );
    yaml
}

// ---------------------------------------------------------------------------
// Multi-rule generators
// ---------------------------------------------------------------------------

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
