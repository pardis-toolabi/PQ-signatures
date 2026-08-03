//! Hashing, the Fiat-Shamir transcript, and challenge expansion.
//!
//! The reference implementation (LoquatPy) collapses every hash input by
//! *summing* the field elements into one value before hashing, and does
//! not chain the previous challenge into the FRI round hashes. Both are
//! proof-of-concept shortcuts that break Fiat-Shamir soundness. This
//! module follows the paper instead: every input is absorbed in order,
//! with domain separation, and every challenge chains the previous one.

use crate::field::{Fp, Fp2};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};

pub type Hash = [u8; 32];

pub fn fp_to_bytes(value: Fp) -> [u8; 16] {
    value.value().to_le_bytes()
}

pub fn fp2_to_bytes(value: Fp2) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&fp_to_bytes(value.c0));
    out[16..].copy_from_slice(&fp_to_bytes(value.c1));
    out
}

/// Hashes a run of field elements into one digest, length-prefixed so that
/// different groupings cannot collide.
pub fn hash_fp2_slice(domain: &[u8], values: &[Fp2]) -> Hash {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, domain);
    Digest::update(&mut hasher, (values.len() as u64).to_le_bytes());
    for value in values {
        Digest::update(&mut hasher, fp2_to_bytes(*value));
    }
    hasher.finalize().into()
}

pub fn hash_pair(domain: &[u8], left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, domain);
    Digest::update(&mut hasher, left);
    Digest::update(&mut hasher, right);
    hasher.finalize().into()
}

pub fn hash_many(domain: &[u8], items: &[Hash]) -> Hash {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, domain);
    Digest::update(&mut hasher, (items.len() as u64).to_le_bytes());
    for item in items {
        Digest::update(&mut hasher, item);
    }
    hasher.finalize().into()
}

/// A running Fiat-Shamir transcript.
///
/// Each `challenge` call folds everything absorbed so far, plus the
/// previous challenge, into a fresh digest. Carrying the previous
/// challenge forward is what stops a prover from rewinding to an earlier
/// round and trying again with different data.
pub struct Transcript {
    state: Hash,
}

impl Transcript {
    pub fn new(domain: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        Digest::update(&mut hasher, b"loquat-v1");
        Digest::update(&mut hasher, domain);
        Transcript { state: hasher.finalize().into() }
    }

    pub fn absorb_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        let mut hasher = Sha3_256::new();
        Digest::update(&mut hasher, b"absorb");
        Digest::update(&mut hasher, self.state);
        Digest::update(&mut hasher, (label.len() as u64).to_le_bytes());
        Digest::update(&mut hasher, label);
        Digest::update(&mut hasher, (bytes.len() as u64).to_le_bytes());
        Digest::update(&mut hasher, bytes);
        self.state = hasher.finalize().into();
    }

    pub fn absorb_hash(&mut self, label: &[u8], hash: &Hash) {
        self.absorb_bytes(label, hash);
    }

    pub fn absorb_fp2_slice(&mut self, label: &[u8], values: &[Fp2]) {
        let mut bytes = Vec::with_capacity(values.len() * 32);
        for value in values {
            bytes.extend_from_slice(&fp2_to_bytes(*value));
        }
        self.absorb_bytes(label, &bytes);
    }

    pub fn absorb_bits(&mut self, label: &[u8], bits: &[u8]) {
        self.absorb_bytes(label, bits);
    }

    /// Squeezes `len` bytes, advancing the transcript so repeated calls
    /// give independent output.
    pub fn challenge_bytes(&mut self, label: &[u8], len: usize) -> Vec<u8> {
        let mut shake = Shake256::default();
        Update::update(&mut shake, b"challenge");
        Update::update(&mut shake, &self.state);
        Update::update(&mut shake, &(label.len() as u64).to_le_bytes());
        Update::update(&mut shake, label);

        let mut output = vec![0u8; len + 32];
        shake.finalize_xof().read(&mut output);

        // The first 32 bytes become the new state; the rest is the challenge.
        self.state.copy_from_slice(&output[..32]);
        output[32..].to_vec()
    }

    /// Uniform `F_p` elements by rejection sampling.
    ///
    /// A 128-bit draw is retried when it lands on or above `p`, which keeps
    /// the distribution exactly uniform rather than slightly biased.
    pub fn challenge_fp_vec(&mut self, label: &[u8], count: usize) -> Vec<Fp> {
        let mut result = Vec::with_capacity(count);
        let mut round = 0u32;
        while result.len() < count {
            let needed = count - result.len();
            let bytes = self.challenge_bytes(
                &[label, b"-fp-", &round.to_le_bytes()].concat(),
                needed * 16 * 2,
            );
            for chunk in bytes.chunks_exact(16) {
                if result.len() == count {
                    break;
                }
                let candidate = u128::from_le_bytes(chunk.try_into().unwrap());
                if candidate < crate::field::P {
                    result.push(Fp::new(candidate));
                }
            }
            round += 1;
        }
        result
    }

    pub fn challenge_fp2_vec(&mut self, label: &[u8], count: usize) -> Vec<Fp2> {
        let parts = self.challenge_fp_vec(label, count * 2);
        parts.chunks_exact(2).map(|pair| Fp2::new(pair[0], pair[1])).collect()
    }

    pub fn challenge_fp2(&mut self, label: &[u8]) -> Fp2 {
        self.challenge_fp2_vec(label, 1)[0]
    }

    /// Uniform indices in `[0, bound)`, rejection sampled.
    pub fn challenge_indices(&mut self, label: &[u8], count: usize, bound: usize) -> Vec<usize> {
        assert!(bound > 0);
        let bits = usize::BITS - (bound - 1).leading_zeros();
        let bytes_each = bits.div_ceil(8).max(1) as usize;
        let limit = 1usize << bits;

        let mut result = Vec::with_capacity(count);
        let mut round = 0u32;
        while result.len() < count {
            let needed = count - result.len();
            let bytes = self.challenge_bytes(
                &[label, b"-idx-", &round.to_le_bytes()].concat(),
                needed * bytes_each * 2 + bytes_each,
            );
            for chunk in bytes.chunks_exact(bytes_each) {
                if result.len() == count {
                    break;
                }
                let mut value = 0usize;
                for (i, byte) in chunk.iter().enumerate() {
                    value |= (*byte as usize) << (8 * i);
                }
                value %= limit;
                if value < bound {
                    result.push(value);
                }
            }
            round += 1;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_deterministic() {
        let mut a = Transcript::new(b"test");
        let mut b = Transcript::new(b"test");
        a.absorb_bytes(b"x", b"hello");
        b.absorb_bytes(b"x", b"hello");
        assert_eq!(a.challenge_bytes(b"c", 32), b.challenge_bytes(b"c", 32));
    }

    #[test]
    fn different_absorbs_give_different_challenges() {
        let mut a = Transcript::new(b"test");
        let mut b = Transcript::new(b"test");
        a.absorb_bytes(b"x", b"hello");
        b.absorb_bytes(b"x", b"hellp");
        assert_ne!(a.challenge_bytes(b"c", 32), b.challenge_bytes(b"c", 32));
    }

    #[test]
    fn absorbs_are_order_sensitive() {
        let mut a = Transcript::new(b"test");
        let mut b = Transcript::new(b"test");
        a.absorb_bytes(b"x", b"one");
        a.absorb_bytes(b"x", b"two");
        b.absorb_bytes(b"x", b"two");
        b.absorb_bytes(b"x", b"one");
        assert_ne!(a.challenge_bytes(b"c", 32), b.challenge_bytes(b"c", 32));
    }

    #[test]
    fn repeated_challenges_differ() {
        let mut t = Transcript::new(b"test");
        let first = t.challenge_bytes(b"c", 32);
        let second = t.challenge_bytes(b"c", 32);
        assert_ne!(first, second, "transcript must advance between challenges");
    }

    #[test]
    fn length_prefixing_prevents_concatenation_collisions() {
        // "ab" + "c" must not collide with "a" + "bc".
        let mut a = Transcript::new(b"test");
        let mut b = Transcript::new(b"test");
        a.absorb_bytes(b"l", b"ab");
        a.absorb_bytes(b"l", b"c");
        b.absorb_bytes(b"l", b"a");
        b.absorb_bytes(b"l", b"bc");
        assert_ne!(a.challenge_bytes(b"c", 16), b.challenge_bytes(b"c", 16));
    }

    #[test]
    fn challenge_indices_stay_in_range() {
        let mut t = Transcript::new(b"test");
        let indices = t.challenge_indices(b"q", 200, 4096 / 4);
        assert_eq!(indices.len(), 200);
        assert!(indices.iter().all(|i| *i < 1024));
    }

    #[test]
    fn challenge_fields_are_reduced_and_varied() {
        let mut t = Transcript::new(b"test");
        let values = t.challenge_fp_vec(b"lambda", 64);
        assert_eq!(values.len(), 64);
        assert!(values.iter().all(|v| v.value() < crate::field::P));
        let distinct: std::collections::HashSet<_> = values.iter().map(|v| v.value()).collect();
        assert!(distinct.len() > 60, "challenges should not repeat");
    }
}
