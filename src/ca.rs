use crate::{extensions::verify, oid::signature_algorithm_from_oid};
use log::{error, trace};
use security_framework::trust_settings::{Domain, TrustSettings};
use thiserror::Error;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};


#[cfg(target_os = "macos")]
pub fn load_native_certs() -> Vec<Vec<u8>> {
    let mut cert_ders = vec![];
    for domain in &[Domain::User, Domain::Admin, Domain::System] {
        let settings = TrustSettings::new(*domain);
        for cert in settings.iter().unwrap() {
            cert_ders.push(cert.to_der());
        }
    }
    cert_ders
}

#[cfg(target_os = "linux")]
pub fn load_native_certs() -> Vec<Vec<u8>> {
    unimplemented!();
}

#[cfg(target_os = "windows")]
pub fn load_native_certs() -> Vec<Vec<u8>> {
    unimplemented!();
}

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("Cannot verify an empty certificate chain")]
    EmptyCertificateChain,

    #[error("Certificate's issuer does not match next certificate's subject")]
    InvalidChainLinking,

    #[error("Certificate missing basic contraints")]
    MissingBasicConstraints,

    #[error("Intermediate has ca=false")]
    InvalidIntermediateCA,

    #[error("A path length constraint was violated")]
    ViolatedPathLengthConstraint,

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("The current datetime does not fall within the certificate's validity")]
    BadCertificateValidity,

    #[error("Certificate chain does not derive from a trusted certificate")]
    UntrustedChain,

    #[error("Failed to verify the end certificate corresponds to the provided server name")]
    BadServerName,
}

pub fn verify_certificate_signature(
    cert: &X509Certificate,
    issuing_cert: &X509Certificate,
) -> Result<(), CertificateError> {
    let signature_algorithm = signature_algorithm_from_oid(cert.signature_algorithm.oid());
    trace!("Used Signature Algorithm: {:?}", signature_algorithm);

    let verified = verify(
        signature_algorithm.signature,
        signature_algorithm.hash,
        issuing_cert.subject_pki.raw,
        cert.tbs_certificate.as_ref(),
        cert.signature_value.as_ref(),
    )
    .map_err(CertificateError::SignatureVerificationFailed)?;

    if !verified {
        return Err(CertificateError::InvalidSignature);
    }

    Ok(())
}

fn matches_hostname(pattern: &str, hostname: &str) -> bool {
    let pat_labels: Vec<&str> = pattern.split('.').collect();
    let host_labels: Vec<&str> = hostname.split('.').collect();

    if pat_labels.len() != host_labels.len() {
        return false;
    }

    for (p, h) in pat_labels.iter().zip(host_labels.iter()) {
        if *p == "*" {
            continue;
        }
        if p.to_lowercase() != h.to_lowercase() {
            return false;
        }
    }
    true
}

// TODO
// Name constraints
// Check root self signed
// Revocation status
// Critical extensions
// Key Usage, Extended Key Usage
pub fn validate_certificate_chain(
    chain: Vec<Vec<u8>>,
    server_name: String,
) -> Result<(), CertificateError> {

    if chain.is_empty() {
        return Err(CertificateError::EmptyCertificateChain);
    }

    let first_cert = X509Certificate::from_der(chain.first().unwrap())
        .unwrap()
        .1;
    if !first_cert.validity().is_valid() {
        return Err(CertificateError::BadCertificateValidity);
    }

    for (intermediate_count, window) in chain.windows(2).enumerate() {
        let curr = X509Certificate::from_der(&window[0]).unwrap().1;
        let next = X509Certificate::from_der(&window[1]).unwrap().1;

        if curr.issuer != next.subject {
            error!("{} != {}", curr.issuer, next.subject);
            return Err(CertificateError::InvalidChainLinking);
        }

        let Ok(Some(constraints)) = next.basic_constraints() else {
            return Err(CertificateError::MissingBasicConstraints);
        };

        if !constraints.value.ca {
            return Err(CertificateError::InvalidIntermediateCA);
        }

        if let Some(max_path_len) = constraints.value.path_len_constraint {
            if intermediate_count > max_path_len as usize {
                return Err(CertificateError::ViolatedPathLengthConstraint);
            }
        }

        if !next.validity().is_valid() {
            return Err(CertificateError::BadCertificateValidity);
        }

        verify_certificate_signature(&curr, &next)?;
    }

    let last_cert = X509Certificate::from_der(chain.last().unwrap()).unwrap().1;
    let mut found_root = false;

    for root_der in load_native_certs() {
        let root_cert = X509Certificate::from_der(&root_der).unwrap().1;
        if last_cert.issuer == root_cert.subject {
            verify_certificate_signature(&last_cert, &root_cert)?;
            if !root_cert.validity().is_valid() {
                return Err(CertificateError::BadCertificateValidity);
            }
            trace!("Trusted Root: {}", root_cert.subject);
            found_root = true;
            break;
        }
    }

    if !found_root {
        return Err(CertificateError::UntrustedChain);
    }

    if let Ok(Some(san)) = first_cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(name) = name {
                if matches_hostname(name, &server_name) {
                    trace!("Server name matches: {:?}", name);
                    return Ok(());
                }
            }
        }
    }

    for attr in first_cert.subject().iter_common_name() {
        let cn = attr.as_str().map_err(|_| CertificateError::BadServerName)?;
        if matches_hostname(cn, &server_name) {
            trace!("Server name matches CN: {:?}", cn);
            return Ok(());
        }
    }

    Err(CertificateError::BadServerName)
}
