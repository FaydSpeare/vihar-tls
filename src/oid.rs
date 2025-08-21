use crate::extensions::{HashAlgo, SignatureAlgorithm};
use asn1_rs::Sequence;
use num_bigint::BigUint;
use pkcs8::{
    PrivateKeyInfo,
    der::{Decode, Encode},
};
use x509_parser::{
    asn1_rs::{FromDer, Integer, Oid},
    prelude::X509Certificate,
};

pub fn signature_algorithm_from_oid(oid: &Oid) -> SignatureAlgorithm {
    match oid.to_id_string().as_str() {
        // RSA
        "1.2.840.113549.1.1.5" => SignatureAlgorithm::rsa_with(HashAlgo::Sha1),
        "1.2.840.113549.1.1.11" => SignatureAlgorithm::rsa_with(HashAlgo::Sha256),
        "1.2.840.113549.1.1.12" => SignatureAlgorithm::rsa_with(HashAlgo::Sha384),
        "1.2.840.113549.1.1.13" => SignatureAlgorithm::rsa_with(HashAlgo::Sha512),
        "1.2.840.113549.1.1.14" => SignatureAlgorithm::rsa_with(HashAlgo::Sha224),
        // "1.2.840.113549.1.1.10", "rsassaPss",
        // ECDSA
        // ("1.2.840.10045.4.1", "ecdsa-with-SHA1"),
        // ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
        // ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
        // ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
        // DSA
        // ("1.2.840.10040.4.3", "dsa-with-sha1"),
        // ("2.16.840.1.101.3.4.3.1", "dsa-with-sha224"),
        // ("2.16.840.1.101.3.4.3.2", "dsa-with-sha256"),
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
    let private_key = BigUint::from_bytes_be(Integer::from_der(pki.private_key).unwrap().1.as_ref());
    (p, g, private_key)
}

pub fn extract_dh_params(cert: &X509Certificate) -> Option<(BigUint, BigUint)> {
    let spki = cert.public_key();
    let Some(bytes) = &spki.algorithm.parameters else {
        return None;
    };
    let Ok((bytes, p_int)) = Integer::from_der(bytes.as_bytes()) else {
        return None;
    };
    let Ok((_, g_int)) = Integer::from_der(bytes) else {
        return None;
    };
    let p = BigUint::from_bytes_be(p_int.as_ref());
    let g = BigUint::from_bytes_be(g_int.as_ref());
    Some((p, g))
}
