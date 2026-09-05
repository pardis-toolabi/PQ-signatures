//! Key generation.
//!
//! The secret is a single field element `K`. The public key is what the
//! Legendre PRF keyed by `K` outputs on the `L` public indices:
//!
//! ```text
//! pk_l = L_0(K + I_l)   for l = 1..L
//! ```
//!
//! where `L_0(a)` is 1 when `a` is a quadratic non-residue and 0 when it
//! is a residue. Recovering `K` from these bits is the Legendre PRF
//! key-recovery problem, which is believed hard even for a quantum
//! adversary — that is the whole security foundation.
//!
//! Reference: paper §3.1 (the Legendre PRF and its keyed form) and
//! Algorithm 3 (key generation), with the `K + I_l != 0` requirement
//! stated in §4.2 just above it.

use crate::field::{Fp, P};
use crate::params::Params;
use rand::RngCore;

// No Debug: a derived one would print the key on any `{:?}`.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey {
    pub k: Fp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// One bit per public index, packed eight to a byte.
    bits: Vec<u8>,
    length: usize,
}

impl PublicKey {
    pub fn bit(&self, index: usize) -> u8 {
        debug_assert!(index < self.length);
        (self.bits[index / 8] >> (index % 8)) & 1
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn size_bytes(&self) -> usize {
        self.bits.len()
    }

    /// The packed bits, for absorbing the key into a transcript.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Test-only: flip one bit, to build a key that agrees with the real
    /// one everywhere except a chosen index.
    #[cfg(test)]
    pub(crate) fn flip_bit(&mut self, index: usize) {
        self.bits[index / 8] ^= 1 << (index % 8);
    }
}

fn random_fp() -> Fp {
    let mut bytes = [0u8; 16];
    loop {
        rand::thread_rng().fill_bytes(&mut bytes);
        let candidate = u128::from_le_bytes(bytes) & ((1u128 << 127) - 1);
        if candidate < P && candidate != 0 {
            return Fp::new(candidate);
        }
    }
}

/// Derives the public key from a secret.
pub fn public_key_from(params: &Params, secret: &SecretKey) -> PublicKey {
    let length = params.l;
    let mut bits = vec![0u8; length.div_ceil(8)];
    for (index, public_index) in params.indices.iter().enumerate() {
        let symbol = (secret.k + *public_index).legendre_bit();
        bits[index / 8] |= symbol << (index % 8);
    }
    PublicKey { bits, length }
}

/// Generates a key pair.
///
/// `K` is drawn from `F_p*` excluding `{-I_1, .., -I_L}`, so that
/// `K + I_l` is never zero. The paper requires this because a zero would
/// have no meaningful Legendre symbol; it costs nothing since `L` is tiny
/// next to `p`.
pub fn generate(params: &Params) -> (SecretKey, PublicKey) {
    let forbidden: std::collections::HashSet<u128> =
        params.indices.iter().map(|index| (-*index).value()).collect();

    let k = loop {
        let candidate = random_fp();
        if !forbidden.contains(&candidate.value()) {
            break candidate;
        }
    };

    let secret = SecretKey { k };
    let public = public_key_from(params, &secret);
    (secret, public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_is_a_deterministic_function_of_the_secret() {
        let params = Params::testing();
        let (secret, public) = generate(&params);
        assert_eq!(public_key_from(&params, &secret), public);
    }

    #[test]
    fn public_key_bits_match_legendre_symbols() {
        let params = Params::testing();
        let (secret, public) = generate(&params);
        for (index, public_index) in params.indices.iter().enumerate() {
            assert_eq!(public.bit(index), (secret.k + *public_index).legendre_bit());
        }
    }

    #[test]
    fn different_secrets_give_different_public_keys() {
        let params = Params::testing();
        let (_, a) = generate(&params);
        let (_, b) = generate(&params);
        assert_ne!(a, b);
    }

    #[test]
    fn public_key_bits_look_balanced() {
        // Roughly half the indices should be non-residues.
        let params = Params::testing();
        let (_, public) = generate(&params);
        let ones: usize = (0..public.len()).map(|i| public.bit(i) as usize).sum();
        let ratio = ones as f64 / public.len() as f64;
        assert!(ratio > 0.3 && ratio < 0.7, "unbalanced: {ratio}");
    }

    #[test]
    fn secret_never_zeroes_a_public_index() {
        let params = Params::testing();
        let (secret, _) = generate(&params);
        for index in &params.indices {
            assert!(!(secret.k + *index).is_zero());
        }
    }
}
