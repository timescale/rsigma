//! Client TLS identity (mTLS) configuration.

use reqwest::Identity;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(not(feature = "taxii-native-tls"))]
use secrecy::SecretString;
#[cfg(feature = "taxii-native-tls")]
use secrecy::{ExposeSecret, SecretString};

use super::TaxiiError;

/// Client certificate for mutual TLS (spec section 8.3.1).
pub struct ClientCertificate {
    identity: Identity,
    rustls_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
}

impl Clone for ClientCertificate {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            rustls_auth: self
                .rustls_auth
                .as_ref()
                .map(|(certs, key)| (certs.clone(), key.clone_key())),
        }
    }
}

impl ClientCertificate {
    /// Load a PKCS#12 identity.
    ///
    /// Requires the [`taxii-native-tls`](crate) feature (native TLS backend).
    #[cfg(feature = "taxii-native-tls")]
    pub fn from_pkcs12_der(
        der: impl Into<Vec<u8>>,
        password: impl Into<SecretString>,
    ) -> Result<Self, TaxiiError> {
        let password = password.into();
        Identity::from_pkcs12_der(&der.into(), password.expose_secret())
            .map(|identity| Self {
                identity,
                rustls_auth: None,
            })
            .map_err(|err| TaxiiError::InvalidClientCertificate(err.to_string()))
    }

    /// Load a PKCS#12 identity.
    #[cfg(not(feature = "taxii-native-tls"))]
    pub fn from_pkcs12_der(
        _der: impl Into<Vec<u8>>,
        _password: impl Into<SecretString>,
    ) -> Result<Self, TaxiiError> {
        Err(TaxiiError::InvalidClientCertificate(
            "PKCS#12 client certificates require the `taxii-native-tls` feature; use `from_pem` with the default rustls backend".into(),
        ))
    }

    /// Load a PEM certificate + private key pair (concatenated for rustls).
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

        let mut buf = Vec::with_capacity(cert_pem.len() + key_pem.len());
        buf.extend_from_slice(cert_pem);
        buf.extend_from_slice(key_pem);
        let identity = Identity::from_pem(&buf)
            .map_err(|err| TaxiiError::InvalidClientCertificate(err.to_string()))?;

        Ok(Self {
            identity,
            rustls_auth: Some((certs, key)),
        })
    }

    #[cfg(feature = "taxii-native-tls")]
    pub(crate) fn identity(&self) -> Identity {
        self.identity.clone()
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
