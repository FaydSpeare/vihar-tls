use crate::TlsResult;
use aes::cipher::BlockSizeUser;
use dsa::{
    Signature as DsaSignature, SigningKey as DsaSigningKey, VerifyingKey as DsaVerifyingKey,
    pkcs8::{AssociatedOid, DecodePrivateKey, DecodePublicKey, der::Decode},
    signature::{DigestSigner, DigestVerifier},
};
use lazy_static::lazy_static;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{FromBytes, One};
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    rand_core::{OsRng, RngCore},
    signature::SignatureEncoding,
};

use sha2::{Digest, digest::FixedOutputReset};
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

pub fn rsa_verify<D: Digest + AssociatedOid>(
    key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let public_key = RsaPublicKey::from_public_key_der(&key_der)
        .map_err(|e| format!("Failed to parse rsa public key: {e}"))?;
    let verifying_key = VerifyingKey::<D>::new(public_key);
    let signature = &Signature::try_from(signature)
        .map_err(|e| format!("Failed to parse rsa signature: {e}"))?;
    let message = D::new_with_prefix(message);
    Ok(verifying_key.verify_digest(message, &signature).is_ok())
}

pub fn dsa_verify<D: Digest>(
    key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let verifying_key = DsaVerifyingKey::from_public_key_der(key_der)
        .map_err(|e| format!("Failed to parse dsa public key: {e}"))?;
    let signature = DsaSignature::from_der(signature)
        .map_err(|e| format!("Failed to parse dsa signature: {e}"))?;
    let message = D::new_with_prefix(message);
    Ok(verifying_key.verify_digest(message, &signature).is_ok())
}

pub fn dsa_sign<D: Digest + BlockSizeUser + FixedOutputReset>(
    key_der: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let key = DsaSigningKey::from_pkcs8_der(&key_der)
        .map_err(|e| format!("Failed to parse dsa private key: {e}"))?;
    let data = D::new_with_prefix(data);
    Ok(key.sign_digest(data).to_vec())
}

pub fn rsa_sign<D: Digest + AssociatedOid>(key_der: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let key = RsaPrivateKey::from_pkcs1_der(&key_der)
        .map_err(|e| format!("Failed to parse rsa private key: {e}"))?;
    let signing_key = SigningKey::<D>::new(key.clone());
    let data = D::new_with_prefix(data);
    Ok(signing_key.sign_digest(data).to_vec())
}

lazy_static! {
    pub static ref P: BigUint = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
      29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
      EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
      E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
      EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
      C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
      83655D23DCA3AD961C62F356208552BB9ED529077096966D\
      670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
      E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
      DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
      15728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16
    )
    .unwrap();
}

pub fn generate_dh_keypair() -> (BigUint, BigUint, BigUint, BigUint) {
    let g = BigUint::from(2u32);
    let mut rng = rand::thread_rng();
    // private key: random in [1, p-1)
    let priv_key = rng.gen_biguint_range(&BigUint::from(1u32), &P);
    // public key: g^priv_key mod p
    let pub_key = g.modpow(&priv_key, &P);
    (P.clone(), g, priv_key, pub_key)
}
