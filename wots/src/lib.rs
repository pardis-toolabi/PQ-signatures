//! Winternitz one-time signatures (plain, pedagogical WOTS).
//!
//! References:
//! - R. Merkle, "A Certified Digital Signature", CRYPTO '89. §5 ("The
//!   Winternitz Improvement") introduces hash-chain signing — publish
//!   y = F^16(x), reveal F^digit(x); §4's count-of-zeros trick is the
//!   ancestor of the checksum below.
//!   https://www.ralphmerkle.com/papers/Certified1979.pdf
//! - A. Hülsing, "W-OTS+ — Shorter Signatures for Hash-Based Signature
//!   Schemes", AFRICACRYPT 2013. https://eprint.iacr.org/2017/965
//! - RFC 8391 (XMSS), §3: the standardized WOTS+.
//!   https://www.rfc-editor.org/rfc/rfc8391.html
//!
//! This crate is the plain scheme: chains iterate raw SHA-256, with none of
//! the per-chain, per-step keys and bitmasks that WOTS+ (RFC 8391 §3.1.2)
//! adds for tighter security. The digit-plus-checksum layout matches
//! RFC 8391 §3.1.5.

use rand::RngCore;
use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;
pub const W: u32 = 16;
const CHAIN_STEPS: u32 = W - 1;

const MESSAGE_DIGITS: usize = HASH_LEN * 2;
const CHECKSUM_DIGITS: usize = 3;
pub const CHAIN_COUNT: usize = MESSAGE_DIGITS + CHECKSUM_DIGITS;

fn hash(data: &[u8]) -> [u8; HASH_LEN] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

fn random_block() -> [u8; HASH_LEN] {
    let mut block = [0u8; HASH_LEN];
    rand::thread_rng().fill_bytes(&mut block);
    block
}

// RFC 8391 §3.1.2 calls this the chaining function (its F is keyed and
// bitmasked per step; here it is raw SHA-256 — see the module notes).
fn chain(start: [u8; HASH_LEN], steps: u32) -> [u8; HASH_LEN] {
    let mut value = start;
    for _ in 0..steps {
        value = hash(&value);
    }
    value
}

fn digits_of(message: &[u8]) -> [u8; CHAIN_COUNT] {
    let digest = hash(message);
    let mut digits = [0u8; CHAIN_COUNT];
    for (i, byte) in digest.iter().enumerate() {
        digits[i * 2] = byte >> 4;
        digits[i * 2 + 1] = byte & 0x0F;
    }

    // RFC 8391 §3.1.5 checksum (Merkle '89 §4-§5 in spirit): raising any
    // message digit lowers this sum, so a forger would have to walk a
    // checksum chain backward. Max value 64 * 15 = 960 < 16^3, so three
    // base-16 digits always suffice.
    let checksum: u32 = digits[..MESSAGE_DIGITS]
        .iter()
        .map(|&d| CHAIN_STEPS - d as u32)
        .sum();
    for i in 0..CHECKSUM_DIGITS {
        let shift = (CHECKSUM_DIGITS - 1 - i) * 4;
        digits[MESSAGE_DIGITS + i] = ((checksum >> shift) & 0x0F) as u8;
    }
    digits
}

#[derive(Clone)]
pub struct PrivateKey {
    chains: Vec<[u8; HASH_LEN]>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    chains: Vec<[u8; HASH_LEN]>,
}

pub struct Signature {
    chains: Vec<[u8; HASH_LEN]>,
}

impl PrivateKey {
    pub fn generate() -> Self {
        let chains = (0..CHAIN_COUNT).map(|_| random_block()).collect();
        PrivateKey { chains }
    }

    pub fn public_key(&self) -> PublicKey {
        let chains = self.chains.iter().map(|&start| chain(start, CHAIN_STEPS)).collect();
        PublicKey { chains }
    }

    /// Consumes the key: like Lamport, a WOTS key pair is only safe to use
    /// for a single message. Signing reveals partial hash chains, and a
    /// second signature would reveal enough to forge new ones.
    ///
    /// Merkle '89 §5: the signature value for digit d is F^d(x).
    pub fn sign(self, message: &[u8]) -> Signature {
        let digits = digits_of(message);
        let chains = self
            .chains
            .into_iter()
            .zip(digits.iter())
            .map(|(start, &digit)| chain(start, digit as u32))
            .collect();
        Signature { chains }
    }
}

/// Rebuilds the public key a valid signature must have come from. XMSS uses
/// this directly, since it never stores WOTS public keys on their own.
///
/// RFC 8391 §3.1.6 calls this WOTS_pkFromSig: finish each chain's remaining
/// 15 - d steps and see where it lands.
pub fn recover_public_key(message: &[u8], signature: &Signature) -> PublicKey {
    let digits = digits_of(message);
    let chains = signature
        .chains
        .iter()
        .zip(digits.iter())
        .map(|(&partial, &digit)| chain(partial, CHAIN_STEPS - digit as u32))
        .collect();
    PublicKey { chains }
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    if signature.chains.len() != CHAIN_COUNT {
        return false;
    }
    recover_public_key(message, signature) == *public_key
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.chains.iter().flatten().copied().collect()
    }

    pub fn size_bytes(&self) -> usize {
        self.chains.len() * HASH_LEN
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.chains.iter().flatten().copied().collect()
    }

    pub fn size_bytes(&self) -> usize {
        self.chains.len() * HASH_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        let message = b"post quantum signatures";
        let signature = sk.sign(message);
        assert!(verify(&pk, message, &signature));
    }

    #[test]
    fn tampered_message_fails() {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        let signature = sk.sign(b"original message");
        assert!(!verify(&pk, b"different message", &signature));
    }

    #[test]
    fn raised_digit_fails_checksum() {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        let message = b"original message";
        let mut signature = sk.sign(message);
        signature.chains[0] = chain(signature.chains[0], 1);
        assert!(!verify(&pk, message, &signature));
    }
}
