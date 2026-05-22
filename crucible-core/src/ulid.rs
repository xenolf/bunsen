use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Generate a ULID: 10-byte timestamp + 16-byte random, encoded as 26 base32 chars.
pub fn generate() -> String {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_millis() as u64;

    let mut rng = rand::thread_rng();
    let rand_hi: u64 = rng.gen::<u64>() & 0xFFFF_FFFF_FFFF;
    let rand_lo: u64 = rng.gen::<u64>();

    // 128-bit value: 48 bits ts | 80 bits random
    let hi: u64 = (ts_ms << 16) | (rand_hi >> 32);
    let lo: u64 = (rand_hi << 32) | (rand_lo >> 32);

    encode_26(hi, lo)
}

fn encode_26(hi: u64, lo: u64) -> String {
    // 128 bits in 26 × 5-bit groups (130 bits: upper 2 bits of hi are 0)
    let mut bits: u128 = ((hi as u128) << 64) | (lo as u128);
    // Shift to align 130 bits: we only use 128, pad with 2 leading zero bits
    // Actually: 26 * 5 = 130 bits. Pack our 128 into the low 128 bits.
    let mut chars = [b'0'; 26];
    for i in (0..26).rev() {
        chars[i] = CROCKFORD[(bits & 0x1f) as usize];
        bits >>= 5;
    }
    String::from_utf8(chars.to_vec()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn ulid_is_26_chars() {
        let id = generate();
        assert_eq!(id.len(), 26, "ULID must be 26 chars, got: {id}");
    }

    #[test]
    fn ulid_only_crockford_chars() {
        let valid: std::collections::HashSet<char> =
            "0123456789ABCDEFGHJKMNPQRSTVWXYZ".chars().collect();
        for _ in 0..20 {
            for ch in generate().chars() {
                assert!(valid.contains(&ch), "invalid char: {ch}");
            }
        }
    }

    #[test]
    fn ulids_sort_chronologically() {
        let a = generate();
        thread::sleep(Duration::from_millis(2));
        let b = generate();
        assert!(a < b, "ULIDs must sort by creation time: {a} >= {b}");
    }
}
