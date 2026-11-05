use regex::Regex;
use sha2::{Digest, Sha256};

pub fn normalize_for_fingerprint(text: &str) -> String {
    let lower = text.to_lowercase();
    let re_paths = Regex::new(r"[a-z]:\\[^\s]+|/[^\s]+").expect("valid regex");
    let replaced_paths = re_paths.replace_all(&lower, "<PATH>");
    let re_numbers = Regex::new(r"\b\d+\b").expect("valid regex");
    let replaced_nums = re_numbers.replace_all(&replaced_paths, "<NUM>");
    let re_whitespace = Regex::new(r"\s+").expect("valid regex");
    re_whitespace
        .replace_all(&replaced_nums, " ")
        .trim()
        .to_string()
}

pub fn compute_exact_hash(text: &str) -> String {
    let norm = normalize_for_fingerprint(text);
    let mut hasher = Sha256::new();
    hasher.update(norm.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn compute_simhash64(text: &str) -> u64 {
    let norm = normalize_for_fingerprint(text);
    let words: Vec<&str> = norm.split_whitespace().collect();

    if words.is_empty() {
        return 0;
    }

    let mut shingles = Vec::new();
    if words.len() < 3 {
        shingles.push(norm.clone());
    } else {
        for i in 0..=words.len() - 3 {
            shingles.push(format!("{} {} {}", words[i], words[i + 1], words[i + 2]));
        }
    }

    let mut v = [0i32; 64];
    for shingle in &shingles {
        let h = fnv1a_64(shingle.as_bytes());
        for i in 0..64 {
            let bit = (h >> i) & 1;
            if bit == 1 {
                v[i] += 1;
            } else {
                v[i] -= 1;
            }
        }
    }

    let mut fingerprint: u64 = 0;
    for (i, count) in v.iter().enumerate().take(64) {
        if *count > 0 {
            fingerprint |= 1 << i;
        }
    }
    fingerprint
}

pub fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

pub fn is_near_duplicate(shingle_a: u64, shingle_b: u64, threshold: u32) -> bool {
    hamming_distance(shingle_a, shingle_b) <= threshold
}
