use crate::TLSResult;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{FromBytes, One};
use rsa::{
    Pkcs1v15Encrypt, RsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
    rand_core::{OsRng, RngCore},
    signature::Verifier,
};
use sha2::Sha256;
use x509_parser::parse_x509_certificate;

pub fn rsa_public_key_from_cert(cert_der: &[u8]) -> TLSResult<RsaPublicKey> {
    let (_, cert) = parse_x509_certificate(cert_der)?;
    Ok(RsaPublicKey::from_public_key_der(
        &cert.tbs_certificate.subject_pki.raw,
    )?)
}

pub fn get_rsa_pre_master_secret(rsa_pubkey: &RsaPublicKey) -> TLSResult<(Vec<u8>, Vec<u8>)> {
    let mut pre_master = [0u8; 48];
    let mut rng = OsRng;
    pre_master[0] = 0x03;
    pre_master[1] = 0x03;
    rng.fill_bytes(&mut pre_master[2..]);

    let encrypted = rsa_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, &pre_master)?;
    Ok((pre_master.to_vec(), encrypted))
}

pub fn get_dhe_pre_master_secret(
    p: &[u8],
    g: &[u8],
    server_public_key: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let p = &BigUint::from_be_bytes(p);
    let g = &BigUint::from_be_bytes(g);
    let server_public_key = &BigUint::from_be_bytes(&server_public_key);

    let mut rng = rand::thread_rng();
    let one = BigUint::one();
    let two = &one + &one;
    let private_key = rng.gen_biguint_range(&two, &(p - &two));
    let public_key = g.modpow(&private_key, p);
    let pre_master_secret = server_public_key.modpow(&private_key, p);
    (pre_master_secret.to_bytes_be(), public_key.to_bytes_be())
}

pub fn rsa_verify(
    rsa_pubkey: &RsaPublicKey,
    signed_data: &[u8],
    signature: &[u8],
) -> TLSResult<bool> {
    let verifying_key = VerifyingKey::<Sha256>::new(rsa_pubkey.clone());
    let signature = &Signature::try_from(signature)?;
    Ok(verifying_key.verify(&signed_data, &signature).is_ok())
}
