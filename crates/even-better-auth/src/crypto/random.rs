use rand::RngExt;

const ALPHANUMERIC: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const URL_SAFE: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";

/// A uniformly random string over `alphabet`.
pub fn random_string(len: usize, alphabet: &[u8]) -> String {
    let mut rng = rand::rng();
    (0..len).map(|_| alphabet[rng.random_range(0..alphabet.len())] as char).collect()
}

/// `N` cryptographically random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b[..]);
    b
}

/// Random id over `a-zA-Z0-9`, 32 chars by default (`generateId`).
pub fn generate_id(len: Option<usize>) -> String {
    random_string(len.unwrap_or(32), ALPHANUMERIC)
}

/// Random string over `a-z0-9A-Z-_` (`generateRandomString`).
pub fn generate_random_string(len: usize) -> String {
    random_string(len, URL_SAFE)
}
