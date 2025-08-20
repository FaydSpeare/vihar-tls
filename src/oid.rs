use x509_parser::asn1_rs::Oid;

use crate::extensions::{HashAlgo, SigAlgo, SignatureAlgorithm};

#[allow(dead_code)]
pub fn signature_type_from_oid(oid: &Oid) -> SigAlgo {
    match oid.to_id_string().as_str() {
        "1.2.840.113549.1.1.1" => SigAlgo::Rsa,
        "1.2.840.10040.4.1" => SigAlgo::Dsa,
        x => unimplemented!("{x}"),
    }
}

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
