//! Proof-of-work: find a nonce so a tagged SHA-256 hash has enough leading
//! zero bits. Used instead of payment to claim names and to rate-limit spam.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::crypto::Hash;

/// Searches nonces in parallel until `hash(nonce)` has at least `bits`
/// leading zero bits. `hash` must be a pure function of the nonce.
pub fn solve<F>(bits: u32, hash: F) -> u64
where
    F: Fn(u64) -> Hash + Sync,
{
    if bits == 0 {
        return 0;
    }
    let threads = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(1);
    let found = AtomicBool::new(false);
    let result = AtomicU64::new(0);
    std::thread::scope(|s| {
        for t in 0..threads {
            let (found, result, hash) = (&found, &result, &hash);
            s.spawn(move || {
                let mut nonce = t;
                while !found.load(Ordering::Relaxed) {
                    if hash(nonce).leading_zero_bits() >= bits {
                        if !found.swap(true, Ordering::SeqCst) {
                            result.store(nonce, Ordering::SeqCst);
                        }
                        return;
                    }
                    nonce = nonce.wrapping_add(threads);
                }
            });
        }
    });
    result.load(Ordering::SeqCst)
}

/// Rough number of hashes needed on average, for progress messages.
pub fn expected_hashes(bits: u32) -> f64 {
    2f64.powi(bits as i32)
}
