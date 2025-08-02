use crate::TlsResult;
use dsa::{
    Signature as DsaSignature, VerifyingKey as DsaVerifyingKey,
    pkcs8::{DecodePublicKey, der::Decode},
    signature::DigestVerifier,
};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{FromBytes, One};
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    rand_core::{OsRng, RngCore},
    signature::Verifier,
};
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;

pub fn public_key_from_cert(cert_der: &[u8]) -> TlsResult<Vec<u8>> {
    let (_, cert) = parse_x509_certificate(cert_der)?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

pub fn get_rsa_pre_master_secret(rsa_pubkey: &RsaPublicKey) -> TlsResult<(Vec<u8>, Vec<u8>)> {
    let mut pre_master = [0u8; 48];
    let mut rng = OsRng;
    pre_master[0] = 0x03;
    pre_master[1] = 0x03;
    rng.fill_bytes(&mut pre_master[2..]);

    let encrypted = rsa_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, &pre_master)?;
    Ok((pre_master.to_vec(), encrypted))
}

pub fn decrypt_rsa_master_secret(
    private_key: &RsaPrivateKey,
    enc_pre_master_secret: &[u8],
) -> TlsResult<Vec<u8>> {
    Ok(private_key.decrypt(Pkcs1v15Encrypt, enc_pre_master_secret)?)
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
) -> TlsResult<bool> {
    let verifying_key = VerifyingKey::<Sha256>::new(rsa_pubkey.clone());
    let signature = &Signature::try_from(signature)?;
    Ok(verifying_key.verify(&signed_data, &signature).is_ok())
}

pub fn dsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> TlsResult<bool> {
    let verifying_key = DsaVerifyingKey::from_public_key_der(public_key)?;
    let signature = DsaSignature::from_der(signature)?;
    let message = Sha256::new_with_prefix(message);
    Ok(verifying_key.verify_digest(message, &signature).is_ok())
}
