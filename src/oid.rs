use crate::{
    client::PublicKeyAlgorithm,
    errors::AnError,
    extensions::{HashType, SignatureAlgorithm},
};
use asn1_rs::Sequence;
use num_bigint::BigUint;
use pkcs8::{
    PrivateKeyInfo,
    der::{Decode, Encode},
};
use x509_cert::Certificate;
use x509_parser::{
    asn1_rs::{FromDer, Integer},
    prelude::X509Certificate,
};

#[derive(Debug)]
pub struct ServerCertificate(Certificate);

impl<'a> ServerCertificate {
    pub fn from_der(bytes: &[u8]) -> Result<Self, AnError> {
        Ok(Self(
            Certificate::from_der(bytes).map_err(|_| AnError::FailedToParseCertificate)?,
        ))
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        return self
            .0
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
    }
}

pub fn get_public_key_algorithm(cert: &X509Certificate) -> PublicKeyAlgorithm {
    match cert.subject_pki.algorithm.oid().to_id_string().as_str() {
        "1.2.840.113549.1.1.1" => PublicKeyAlgorithm::RsaEncryption,
        "1.2.840.10040.4.1" => PublicKeyAlgorithm::DsaEncryption,
        "1.2.840.113549.1.3.1" => PublicKeyAlgorithm::DhKeyAgreement,
        x => unimplemented!("{x}"),
    }
}

pub fn get_signature_algorithm(cert: &X509Certificate) -> SignatureAlgorithm {
    match cert.signature_algorithm.oid().to_id_string().as_str() {
        // RSA
        "1.2.840.113549.1.1.5" => SignatureAlgorithm::rsa_with(HashType::Sha1),
        "1.2.840.113549.1.1.11" => SignatureAlgorithm::rsa_with(HashType::Sha256),
        "1.2.840.113549.1.1.12" => SignatureAlgorithm::rsa_with(HashType::Sha384),
        "1.2.840.113549.1.1.13" => SignatureAlgorithm::rsa_with(HashType::Sha512),
        "1.2.840.113549.1.1.14" => SignatureAlgorithm::rsa_with(HashType::Sha224),
        // "1.2.840.113549.1.1.10", "rsassaPss",
        // ECDSA
        // ("1.2.840.10045.4.1", "ecdsa-with-SHA1"),
        // ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
        // ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
        // ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
        // DSA
        "1.2.840.10040.4.3" => SignatureAlgorithm::dsa_with(HashType::Sha1),
        "2.16.840.1.101.3.4.3.1" => SignatureAlgorithm::dsa_with(HashType::Sha224),
        "2.16.840.1.101.3.4.3.2" => SignatureAlgorithm::dsa_with(HashType::Sha256),
        x => unimplemented!("{x}"),
    }
}

pub fn deconstruct_dh_key(bytes: &[u8]) -> (BigUint, BigUint, BigUint) {
    let pki = PrivateKeyInfo::from_der(bytes).unwrap();
    let bytes = pki.algorithm.parameters.unwrap().to_der().unwrap();
    let (_, seq) = Sequence::from_der(&bytes).unwrap();
    let mut iter = seq.der_iter::<Integer, _>();
    let p = iter.next().unwrap().unwrap();
    let g = iter.next().unwrap().unwrap();

    let p = BigUint::from_bytes_be(p.as_ref());
    let g = BigUint::from_bytes_be(g.as_ref());
    let private_key =
        BigUint::from_bytes_be(Integer::from_der(pki.private_key).unwrap().1.as_ref());
    (p, g, private_key)
}

pub fn extract_dh_params(cert: &ServerCertificate) -> Option<(BigUint, BigUint, BigUint)> {
    let der = cert
        .0
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key.as_bytes().unwrap();

    let public_key = Integer::from_der(&der).unwrap().1;
    let public_key = BigUint::from_bytes_be(public_key.as_ref());

    let Some(bytes) = &cert
        .0
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .parameters
    else {
        return None;
    };
    let Ok((bytes, p_int)) = Integer::from_der(bytes.value()) else {
        return None;
    };
    let Ok((_, g_int)) = Integer::from_der(bytes) else {
        return None;
    };
    let p = BigUint::from_bytes_be(p_int.as_ref());
    let g = BigUint::from_bytes_be(g_int.as_ref());
    Some((p, g, public_key))
}
