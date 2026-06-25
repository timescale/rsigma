//! STIX Cyber-observable Objects (18 types).
//!
//! Field-level rustdoc for individual SCO properties is deferred to a follow-up
//! documentation pass; see crate README invariant table for enforced rules.

#![allow(missing_docs)]

pub mod extensions;
pub mod ref_types;

mod artifact;
mod autonomous_system;
mod directory;
mod domain_name;
mod email_address;
mod email_message;
mod file;
mod ipv4_addr;
mod ipv6_addr;
mod mac_addr;
mod mutex;
mod network_traffic;
mod process;
mod software;
mod url;
mod user_account;
mod windows_registry_key;
mod x509_certificate;

pub use artifact::Artifact;
pub use autonomous_system::AutonomousSystem;
pub use directory::Directory;
pub use domain_name::DomainName;
pub use email_address::EmailAddr;
pub use email_message::EmailMessage;
pub use file::File;
pub use ipv4_addr::Ipv4Addr;
pub use ipv6_addr::Ipv6Addr;
pub use mac_addr::MacAddr;
pub use mutex::Mutex;
pub use network_traffic::NetworkTraffic;
pub use process::Process;
pub use software::Software;
pub use url::Url;
pub use user_account::UserAccount;
pub use windows_registry_key::WindowsRegistryKey;
pub use x509_certificate::X509Certificate;

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};

/// STIX SCO enum (18 variants).
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum ScoObject {
    /// STIX `artifact` object.
    Artifact(Artifact),
    /// STIX `autonomous-system` object.
    AutonomousSystem(AutonomousSystem),
    /// STIX `directory` object.
    Directory(Directory),
    /// STIX `domain-name` object.
    DomainName(DomainName),
    /// STIX `email-address` object.
    EmailAddr(EmailAddr),
    /// STIX `email-message` object.
    EmailMessage(EmailMessage),
    /// STIX `file` object.
    File(File),
    /// STIX `ipv4-addr` object.
    Ipv4Addr(Ipv4Addr),
    /// STIX `ipv6-addr` object.
    Ipv6Addr(Ipv6Addr),
    /// STIX `mac-addr` object.
    MacAddr(MacAddr),
    /// STIX `mutex` object.
    Mutex(Mutex),
    /// STIX `network-traffic` object.
    NetworkTraffic(NetworkTraffic),
    /// STIX `process` object.
    Process(Process),
    /// STIX `software` object.
    Software(Software),
    /// STIX `url` object.
    Url(Url),
    /// STIX `user-account` object.
    UserAccount(UserAccount),
    /// STIX `windows-registry-key` object.
    WindowsRegistryKey(WindowsRegistryKey),
    /// STIX `x509-certificate` object.
    X509Certificate(X509Certificate),
}

impl QueryableStixObject for ScoObject {
    fn id(&self) -> &StixId {
        match self {
            Self::Artifact(inner) => inner.id(),
            Self::AutonomousSystem(inner) => inner.id(),
            Self::Directory(inner) => inner.id(),
            Self::DomainName(inner) => inner.id(),
            Self::EmailAddr(inner) => inner.id(),
            Self::EmailMessage(inner) => inner.id(),
            Self::File(inner) => inner.id(),
            Self::Ipv4Addr(inner) => inner.id(),
            Self::Ipv6Addr(inner) => inner.id(),
            Self::MacAddr(inner) => inner.id(),
            Self::Mutex(inner) => inner.id(),
            Self::NetworkTraffic(inner) => inner.id(),
            Self::Process(inner) => inner.id(),
            Self::Software(inner) => inner.id(),
            Self::Url(inner) => inner.id(),
            Self::UserAccount(inner) => inner.id(),
            Self::WindowsRegistryKey(inner) => inner.id(),
            Self::X509Certificate(inner) => inner.id(),
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            Self::Artifact(_) => Artifact::TYPE_NAME,
            Self::AutonomousSystem(_) => AutonomousSystem::TYPE_NAME,
            Self::Directory(_) => Directory::TYPE_NAME,
            Self::DomainName(_) => DomainName::TYPE_NAME,
            Self::EmailAddr(_) => EmailAddr::TYPE_NAME,
            Self::EmailMessage(_) => EmailMessage::TYPE_NAME,
            Self::File(_) => File::TYPE_NAME,
            Self::Ipv4Addr(_) => Ipv4Addr::TYPE_NAME,
            Self::Ipv6Addr(_) => Ipv6Addr::TYPE_NAME,
            Self::MacAddr(_) => MacAddr::TYPE_NAME,
            Self::Mutex(_) => Mutex::TYPE_NAME,
            Self::NetworkTraffic(_) => NetworkTraffic::TYPE_NAME,
            Self::Process(_) => Process::TYPE_NAME,
            Self::Software(_) => Software::TYPE_NAME,
            Self::Url(_) => Url::TYPE_NAME,
            Self::UserAccount(_) => UserAccount::TYPE_NAME,
            Self::WindowsRegistryKey(_) => WindowsRegistryKey::TYPE_NAME,
            Self::X509Certificate(_) => X509Certificate::TYPE_NAME,
        }
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        match self {
            Self::Artifact(inner) => inner.spec_version(),
            Self::AutonomousSystem(inner) => inner.spec_version(),
            Self::Directory(inner) => inner.spec_version(),
            Self::DomainName(inner) => inner.spec_version(),
            Self::EmailAddr(inner) => inner.spec_version(),
            Self::EmailMessage(inner) => inner.spec_version(),
            Self::File(inner) => inner.spec_version(),
            Self::Ipv4Addr(inner) => inner.spec_version(),
            Self::Ipv6Addr(inner) => inner.spec_version(),
            Self::MacAddr(inner) => inner.spec_version(),
            Self::Mutex(inner) => inner.spec_version(),
            Self::NetworkTraffic(inner) => inner.spec_version(),
            Self::Process(inner) => inner.spec_version(),
            Self::Software(inner) => inner.spec_version(),
            Self::Url(inner) => inner.spec_version(),
            Self::UserAccount(inner) => inner.spec_version(),
            Self::WindowsRegistryKey(inner) => inner.spec_version(),
            Self::X509Certificate(inner) => inner.spec_version(),
        }
    }

    fn created(&self) -> Option<&StixTimestamp> {
        None
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        None
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match self {
            Self::Artifact(inner) => inner.get_field(path),
            Self::AutonomousSystem(inner) => inner.get_field(path),
            Self::Directory(inner) => inner.get_field(path),
            Self::DomainName(inner) => inner.get_field(path),
            Self::EmailAddr(inner) => inner.get_field(path),
            Self::EmailMessage(inner) => inner.get_field(path),
            Self::File(inner) => inner.get_field(path),
            Self::Ipv4Addr(inner) => inner.get_field(path),
            Self::Ipv6Addr(inner) => inner.get_field(path),
            Self::MacAddr(inner) => inner.get_field(path),
            Self::Mutex(inner) => inner.get_field(path),
            Self::NetworkTraffic(inner) => inner.get_field(path),
            Self::Process(inner) => inner.get_field(path),
            Self::Software(inner) => inner.get_field(path),
            Self::Url(inner) => inner.get_field(path),
            Self::UserAccount(inner) => inner.get_field(path),
            Self::WindowsRegistryKey(inner) => inner.get_field(path),
            Self::X509Certificate(inner) => inner.get_field(path),
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::core::{QueryableStixObject, SpecVersion};

    #[test]
    fn sco_object_delegates_queryable_stix_object() {
        let raw = include_str!("../../../tests/fixtures/spec/sco/url.json");
        let url: Url = serde_json::from_str(raw).expect("parse");
        let sco = ScoObject::Url(url.clone());
        assert_eq!(QueryableStixObject::id(&sco), url.id());
        assert_eq!(QueryableStixObject::type_name(&sco), Url::TYPE_NAME);
        assert_eq!(sco.spec_version(), Some(SpecVersion::V2_1));
        assert_eq!(
            sco.get_field(&["value"]),
            Some(QueryValue::Str("https://example.com/research/index.html"))
        );
        assert!(sco.created().is_none());
        assert!(sco.modified().is_none());
    }
}
