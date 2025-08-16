use rand::Rng;
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Slices must be the same length");
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

pub fn get_unix_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as u32
}

pub fn get_random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.r#gen::<u8>()).collect()
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

#[allow(unused)]
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    // Remove whitespace and newlines
    let clean_hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();

    // Convert every 2 hex chars into a u8
    (0..clean_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean_hex[i..i + 2], 16).expect("Invalid hex"))
        .collect()
}

pub fn read_pem<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read_to_string(path)?;
    let parsed = pem::parse(bytes)?;
    Ok(parsed.into_contents())
}
