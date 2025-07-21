use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

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

pub fn u24_be_bytes(value: usize) -> [u8; 3] {
    [
        ((value >> 16) & 0xFF) as u8,
        ((value >> 8) & 0xFF) as u8,
        (value & 0xFF) as u8,
    ]
}
