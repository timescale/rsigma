//! Open vocabulary tables (unknown values are extensions).

/// Account type open vocabulary.
pub static ACCOUNT_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {"facebook", "ldap", "nis", "openid", "radius", "saml", "unix", "windows-local", "windows-domain"};
/// Attack motivation open vocabulary.
pub static ATTACK_MOTIVATION_OV: phf::Set<&'static str> = phf::phf_set! {
    "accidental", "coercion", "dominance", "ideology", "organizational-gain", "personal-gain",
    "personal-satisfaction", "revenge", "unpredictable"
};
/// Attack resource level open vocabulary.
pub static ATTACK_RESOURCE_LEVEL_OV: phf::Set<&'static str> =
    phf::phf_set! {"individual", "club", "contest", "team", "organization", "government"};
/// Grouping context open vocabulary.
pub static GROUPING_CONTEXT_OV: phf::Set<&'static str> =
    phf::phf_set! {"suspicious-activity", "malware-analysis", "incident", "threat-actor"};
/// Identity class open vocabulary.
pub static IDENTITY_CLASS_OV: phf::Set<&'static str> = phf::phf_set! {
    "individual", "group", "organization", "class", "system", "unknown"
};
/// Implementation language open vocabulary.
pub static IMPLEMENTATION_LANGUAGE_OV: phf::Set<&'static str> = phf::phf_set! {
    "applescript", "bash", "c", "c++", "csharp", "go", "java", "javascript",
    "lua", "perl", "php", "powershell", "python", "ruby", "rust", "swift", "typescript", "visualbasic"
};
/// Indicator type open vocabulary.
pub static INDICATOR_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "anomalous-activity", "anonymization", "benign", "compromised", "malicious-activity", "unknown", "attribution"
};
/// Industry sector open vocabulary.
pub static INDUSTRY_SECTOR_OV: phf::Set<&'static str> = phf::phf_set! {
    "aerospace", "agriculture", "automotive", "communications", "construction",
    "education", "energy", "entertainment", "financial-services", "government",
    "healthcare", "hospitality-leisure", "infrastructure", "legal", "manufacturing",
    "mining", "non-profit", "pharmaceuticals", "retail", "technology", "telecommunications", "transportation"
};
/// Infrastructure type open vocabulary.
pub static INFRASTRUCTURE_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "amplification", "anonymization", "botnet", "command-and-control",
    "exfiltration", "hosting-target-lists", "phishing", "reconnaissance",
    "staging", "unknown", "firewall", "load-balancer"
};
/// Malware capabilities open vocabulary.
pub static MALWARE_CAPABILITIES_OV: phf::Set<&'static str> = phf::phf_set! {
    "accesses-remote-machines", "anti-debugging", "anti-disassembly", "anti-emulation",
    "anti-memory-forensics", "anti-sandbox", "anti-vm", "captures-input-peripherals",
    "captures-output-peripherals", "captures-system-state-data", "cleans-traces-of-infection",
    "commits-fraud", "communicates-with-c2", "compromises-data-availability", "compromises-data-integrity",
    "compromises-system-availability", "degrades-security-software", "escalates-privileges", "evades-av",
    "exfiltrates-data", "fingerprints-host", "hides-artifacts", "infects-files", "installs-other-components",
    "persists-after-system-reboot", "prevents-artifact-access", "self-propagates", "steals-authentication-credentials"
};
/// Malware type open vocabulary.
pub static MALWARE_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "adware", "backdoor", "bot", "bootkit", "ddos", "downloader", "dropper",
    "exploit-kit", "keylogger", "ransomware", "remote-access-trojan", "resource-exploitation",
    "rogue-security-software", "rootkit", "screen-capture", "spyware", "trojan", "virus", "worm", "wiper"
};
/// Pattern type open vocabulary.
pub static PATTERN_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "stix", "snort", "suricata", "yara", "sigma"
};
/// Processor architecture open vocabulary.
pub static PROCESSOR_ARCHITECTURE_OV: phf::Set<&'static str> =
    phf::phf_set! {"x86", "x86-64", "arm", "mips", "sparc", "powerpc"};
/// Region open vocabulary.
pub static REGION_OV: phf::Set<&'static str> = phf::phf_set! {
    "africa", "antarctica", "asia", "europe", "north-america", "oceania", "south-america", "caribbean", "middle-east"
};
/// Report type open vocabulary.
pub static REPORT_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "attack-pattern", "campaign", "indicator", "threat-actor", "tool", "vulnerability", "incident"
};
/// Threat actor role open vocabulary.
pub static THREAT_ACTOR_ROLE_OV: phf::Set<&'static str> = phf::phf_set! {
    "agent", "director", "independent", "infrastructure-architect",
    "infrastructure-operator", "malware-author", "sponsor"
};
/// Threat actor sophistication open vocabulary.
pub static THREAT_ACTOR_SOPHISTICATION_OV: phf::Set<&'static str> = phf::phf_set! {
    "none", "minimal", "intermediate", "advanced", "expert", "innovator", "strategic"
};
/// Threat actor type open vocabulary.
pub static THREAT_ACTOR_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "activist", "crime-syndicate", "criminal", "insider-accidental", "insider-disgruntled",
    "nation-state", "sensationalist", "spy", "terrorist", "private-sector", "unknown"
};
/// Tool type open vocabulary.
pub static TOOL_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "credential-exploitation", "denial-of-service", "exploitation", "information-gathering",
    "network-capture", "remote-access", "vulnerability-scanning"
};

/// Open vocabulary value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OpenVocab<T: Clone> {
    /// Known standard value.
    Known(T),
    /// Extension value outside the known set.
    Extension(String),
}
