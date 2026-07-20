//! Closed vocabulary tables used by parse-time and bundle validation.
//!
//! Unknown values are rejected only when the corresponding validator runs.
//! The encryption-algorithm table is a rstix subset, not the full STIX §3.9.1 enum.

/// Encryption algorithm enum.
pub static ENCRYPTION_ALGORITHM_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "AES-256-GCM",
    "ChaCha20-Poly1305",
    "magma",
    "rc4",
    "DES",
    "3DES",
    "Camellia",
};

/// Extension type enum.
pub static EXTENSION_TYPE_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "new-sdo",
    "new-sro",
    "new-sco",
    "property-extension",
    "toplevel-property-extension",
};

/// Hash algorithm enum.
pub static HASH_ALGORITHM_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "MD5", "SHA-1", "SHA-256", "SHA-512", "SHA3-256", "SHA3-512", "SSDEEP", "TLSH", "SM3"
};

/// Network socket address family enum.
pub static NETWORK_SOCKET_ADDRESS_FAMILY_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "AF_INET", "AF_INET6", "AF_UNIX", "AF_PACKET"
};

/// Network socket type enum.
pub static NETWORK_SOCKET_TYPE_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "SOCK_STREAM", "SOCK_DGRAM", "SOCK_RAW"
};

/// Opinion enum from STIX.
pub static OPINION_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "strongly-disagree", "disagree", "neutral", "agree", "strongly-agree"
};

/// Windows integrity level enum.
pub static WINDOWS_INTEGRITY_LEVEL_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "low", "medium", "high", "system", "untrusted"
};

/// Windows PE binary type enum (treated as closed in rstix).
pub static WINDOWS_PE_BINARY_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "exe", "dll", "sys", "driver"
};

/// Windows registry datatype enum.
pub static WINDOWS_REGISTRY_DATATYPE_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REG_DWORD_BIG_ENDIAN",
    "REG_LINK", "REG_MULTI_SZ", "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESCRIPTOR",
    "REG_RESOURCE_REQUIREMENTS_LIST", "REG_QWORD", "REG_DWORD_LITTLE_ENDIAN", "REG_QWORD_LITTLE_ENDIAN"
};

/// Windows service start type enum.
pub static WINDOWS_SERVICE_START_TYPE_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "SERVICE_AUTO_START", "SERVICE_BOOT_START", "SERVICE_DEMAND_START",
    "SERVICE_DISABLED", "SERVICE_SYSTEM_ALERT", "SERVICE_SYSTEM_START"
};

/// Windows service status enum.
pub static WINDOWS_SERVICE_STATUS_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "SERVICE_CONTINUE_PENDING", "SERVICE_PAUSE_PENDING", "SERVICE_PAUSED",
    "SERVICE_RUNNING", "SERVICE_START_PENDING", "SERVICE_STOP_PENDING", "SERVICE_STOPPED"
};

/// Windows service type enum.
pub static WINDOWS_SERVICE_TYPE_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "SERVICE_FILE_SYSTEM_DRIVER", "SERVICE_KERNEL_DRIVER", "SERVICE_WIN32_OWN_PROCESS",
    "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_INTERACTIVE_PROCESS", "SERVICE_USER_OWN_PROCESS"
};

/// Malware analysis result enum.
pub static MALWARE_RESULT_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "malicious", "suspicious", "benign", "unknown"
};

/// Bundle object type enum.
pub static BUNDLE_OBJECT_TYPE_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "bundle"
};

/// Marking definition type enum.
pub static MARKING_DEFINITION_TYPE_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "statement", "tlp"
};

/// Observable container relation enum.
pub static OBSERVABLE_CONTAINER_RELATION_ENUM: phf::Set<&'static str> = phf::phf_set! {
    "contains", "resolves-to", "belongs-to", "related-to"
};

/// Opinion value with stable ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OpinionValue {
    /// Strongly disagree.
    StronglyDisagree = 1,
    /// Disagree.
    Disagree = 2,
    /// Neutral.
    Neutral = 3,
    /// Agree.
    Agree = 4,
    /// Strongly agree.
    StronglyAgree = 5,
}

impl OpinionValue {
    /// The STIX `opinion-enum` string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StronglyDisagree => "strongly-disagree",
            Self::Disagree => "disagree",
            Self::Neutral => "neutral",
            Self::Agree => "agree",
            Self::StronglyAgree => "strongly-agree",
        }
    }

    /// Parse from the STIX `opinion-enum` string.
    pub fn from_str_value(value: &str) -> Option<Self> {
        match value {
            "strongly-disagree" => Some(Self::StronglyDisagree),
            "disagree" => Some(Self::Disagree),
            "neutral" => Some(Self::Neutral),
            "agree" => Some(Self::Agree),
            "strongly-agree" => Some(Self::StronglyAgree),
            _ => None,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for OpinionValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for OpinionValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_str_value(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown opinion value: {raw}")))
    }
}

#[cfg(all(test, feature = "serde"))]
mod opinion_value_tests {
    use super::*;

    #[test]
    fn opinion_value_strings_round_trip() {
        for (variant, text) in [
            (OpinionValue::StronglyDisagree, "\"strongly-disagree\""),
            (OpinionValue::Disagree, "\"disagree\""),
            (OpinionValue::Neutral, "\"neutral\""),
            (OpinionValue::Agree, "\"agree\""),
            (OpinionValue::StronglyAgree, "\"strongly-agree\""),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), text);
            let decoded: OpinionValue = serde_json::from_str(text).unwrap();
            assert_eq!(decoded, variant);
        }
        assert!(serde_json::from_str::<OpinionValue>("\"unknown\"").is_err());
    }
}
