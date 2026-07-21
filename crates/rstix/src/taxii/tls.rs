//! Client TLS identity (mTLS) configuration.

use p12_keystore::{KeyStore, Pkcs12ImportPolicy};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use secrecy::{ExposeSecret, SecretString};

use super::TaxiiError;

/// Client certificate for mutual TLS (spec section 8.3.1).
pub struct ClientCertificate {
    rustls_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
}

impl Clone for ClientCertificate {
    fn clone(&self) -> Self {
        Self {
            rustls_auth: self
                .rustls_auth
                .as_ref()
                .map(|(certs, key)| (certs.clone(), key.clone_key())),
        }
    }
}

impl ClientCertificate {
    /// Load a PKCS#12 (`.p12` / `.pfx`) identity for rustls mTLS.
    pub fn from_pkcs12_der(
        der: impl Into<Vec<u8>>,
        password: impl Into<SecretString>,
    ) -> Result<Self, TaxiiError> {
        let password = password.into();
        let keystore = KeyStore::from_pkcs12(
            &der.into(),
            password.expose_secret(),
            Pkcs12ImportPolicy::Strict,
        )
        .map_err(|err| TaxiiError::InvalidClientCertificate(err.to_string()))?;
        let (_alias, chain) = keystore.private_key_chain().ok_or_else(|| {
            TaxiiError::InvalidClientCertificate("PKCS#12 archive contains no private key".into())
        })?;
        Self::from_rustls_parts(chain.certs(), chain.key().as_der())
    }

    /// Load a PEM certificate + private key pair for rustls mTLS.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, TaxiiError> {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| TaxiiError::InvalidClientCertificate(err.to_string()))?;
        if certs.is_empty() {
            return Err(TaxiiError::InvalidClientCertificate(
                "PEM client certificate chain is empty".into(),
            ));
        }
        let key = PrivateKeyDer::from_pem_slice(key_pem)
            .map_err(|err| TaxiiError::InvalidClientCertificate(err.to_string()))?;
        Ok(Self {
            rustls_auth: Some((certs, key)),
        })
    }

    fn from_rustls_parts(
        certs: &[p12_keystore::Certificate],
        key_der: &[u8],
    ) -> Result<Self, TaxiiError> {
        let certs: Vec<CertificateDer<'static>> = certs
            .iter()
            .map(|cert| CertificateDer::from(cert.as_der().to_vec()))
            .collect();
        if certs.is_empty() {
            return Err(TaxiiError::InvalidClientCertificate(
                "client certificate chain is empty".into(),
            ));
        }
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));
        Ok(Self {
            rustls_auth: Some((certs, key)),
        })
    }

    pub(crate) fn rustls_auth(
        &self,
    ) -> Option<&(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        self.rustls_auth.as_ref()
    }
}

impl std::fmt::Debug for ClientCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCertificate").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs12_live_fixture_parses_for_rustls() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/taxii-live/fixtures/certs/client.p12");
        if !path.exists() {
            return;
        }
        let der = std::fs::read(&path).expect("read client.p12");
        let cert = ClientCertificate::from_pkcs12_der(der, SecretString::new("rstix-live".into()))
            .expect("parse pkcs12");
        assert!(cert.rustls_auth().is_some());
    }
}
