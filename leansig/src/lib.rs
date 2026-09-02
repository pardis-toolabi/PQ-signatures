//! leanSig: target-sum Winternitz signatures over Poseidon2.
//!
//! This is the one-time signature Ethereum's post-quantum research settled
//! on. It changes two things about plain WOTS, both aimed at making
//! verification cheap inside a zero-knowledge circuit:
//!
//! 1. The hash is Poseidon2 instead of SHA-256, so every hash call becomes
//!    field arithmetic a circuit can express directly.
//! 2. The checksum chains are replaced by a "target sum": the signer
//!    searches for randomness that makes the message digits add up to a
//!    fixed total. This removes chains entirely and lets the total be
//!    tuned so verification walks fewer chain steps.

use poseidon2::F;
use rand::RngCore;

/// Winternitz parameter: digits are base 16.
pub const W: u32 = 16;
const CHAIN_STEPS: u32 = W - 1;

/// Number of hash chains (one per message digit). No checksum chains are
/// needed, unlike plain WOTS.
pub const DIGITS: usize = 56;

/// The digit sum every signed message must hit exactly.
///
/// Digits are close to uniform over 0..=15, so the sum over 56 of them
/// would nominally centre on 420 with a standard deviation near 34. The
/// top nibble of each digest element is slightly biased (see
/// `derive_digits`), which pulls the true centre down to about 418.
/// Picking a target above the centre makes verification cheaper (it walks
/// `DIGITS * 15 - TARGET_SUM` steps in total) but makes the signer search
/// longer to find matching randomness. This value sits about 1.1 standard
/// deviations high, costing the signer ~150 tries on average.
pub const TARGET_SUM: u32 = 455;

/// Signer gives up after this many tries; reaching it means the parameters
/// are wrong, not that the message is unsignable.
const MAX_ATTEMPTS: u64 = 1 << 22;

type ChainValue = [F; poseidon2::OUT];

fn chain(start: ChainValue, steps: u32) -> ChainValue {
    let mut value = start;
    for _ in 0..steps {
        value = poseidon2::compress(value);
    }
    value
}

/// Derives the message digits for a given randomness value.
///
/// The digits come from the low 28 bits of each field element. Because
/// P = 15 * 2^27 + 1, the low 24 bits of a uniform field element are
/// essentially unbiased (P ≡ 1 mod 2^24), but the seventh nibble — bits
/// 24..28 — is not: bit 27 is 0 with probability 8/15, so that nibble
/// favours 0..=7 over 8..=15 at odds 8:7 and has mean ~7.23 instead of
/// 7.5. With eight such nibbles among the 56 digits, the digit sum
/// centres on ~418 rather than 420. Harmless here (the target-sum search
/// absorbs it), but worth knowing the bias exists.
fn derive_digits(message_hash: &[F], randomness: u64) -> [u8; DIGITS] {
    let mut input = message_hash.to_vec();
    input.push(F::from_u64(randomness & 0xFFFF_FFFF));
    input.push(F::from_u64(randomness >> 32));
    let digest = poseidon2::hash(&input);

    let mut digits = [0u8; DIGITS];
    let mut index = 0;
    for element in digest.iter() {
        let value = element.as_u32();
        for nibble in 0..7 {
            if index == DIGITS {
                break;
            }
            digits[index] = ((value >> (nibble * 4)) & 0x0F) as u8;
            index += 1;
        }
    }
    digits
}

fn digit_sum(digits: &[u8; DIGITS]) -> u32 {
    digits.iter().map(|&d| d as u32).sum()
}

/// Expands a short seed into the chain starting points, so the private key
/// is one 32-byte seed rather than 56 separate secrets.
fn chain_start(seed: &[u8; 32], index: usize) -> ChainValue {
    let mut input = poseidon2::hash_bytes(seed).to_vec();
    input.push(F::from_u64(index as u64));
    poseidon2::hash(&input)
}

pub struct PrivateKey {
    seed: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
    digest: ChainValue,
}

pub struct Signature {
    randomness: u64,
    chains: Vec<ChainValue>,
}

/// Hashes all chain tops down to a single short public key.
fn compress_tops(tops: &[ChainValue]) -> ChainValue {
    let flattened: Vec<F> = tops.iter().flatten().copied().collect();
    poseidon2::hash(&flattened)
}

impl PrivateKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        PrivateKey { seed }
    }

    pub fn public_key(&self) -> PublicKey {
        let tops: Vec<ChainValue> =
            (0..DIGITS).map(|i| chain(chain_start(&self.seed, i), CHAIN_STEPS)).collect();
        PublicKey { digest: compress_tops(&tops) }
    }

    /// Signs, consuming the key: like every Winternitz-style scheme this is
    /// one-time only. Also returns how many randomness values had to be
    /// tried, which is the cost the target-sum trick trades away in
    /// exchange for cheaper verification.
    pub fn sign_counting(self, message: &[u8]) -> Option<(Signature, u64)> {
        let message_hash = poseidon2::hash_bytes(message);

        for attempt in 0..MAX_ATTEMPTS {
            let digits = derive_digits(&message_hash, attempt);
            if digit_sum(&digits) != TARGET_SUM {
                continue;
            }
            let chains = digits
                .iter()
                .enumerate()
                .map(|(i, &digit)| chain(chain_start(&self.seed, i), digit as u32))
                .collect();
            return Some((Signature { randomness: attempt, chains }, attempt + 1));
        }
        None
    }

    pub fn sign(self, message: &[u8]) -> Option<Signature> {
        self.sign_counting(message).map(|(signature, _)| signature)
    }
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    if signature.chains.len() != DIGITS {
        return false;
    }
    let message_hash = poseidon2::hash_bytes(message);
    let digits = derive_digits(&message_hash, signature.randomness);

    // The target-sum check is what replaces WOTS's checksum. An attacker can
    // only walk chains forward, so any forged message would need digits no
    // smaller than these — which would push the sum above the target.
    if digit_sum(&digits) != TARGET_SUM {
        return false;
    }

    let tops: Vec<ChainValue> = signature
        .chains
        .iter()
        .zip(digits.iter())
        .map(|(&partial, &digit)| chain(partial, CHAIN_STEPS - digit as u32))
        .collect();
    compress_tops(&tops) == public_key.digest
}

impl Signature {
    pub fn size_bytes(&self) -> usize {
        // 8 bytes of randomness, then four bytes per field element.
        8 + self.chains.len() * poseidon2::OUT * 4
    }

    /// Total chain steps a verifier walks. This is the number that matters
    /// for circuit cost, since each step is one Poseidon2 permutation.
    pub fn verify_hash_steps(&self) -> u32 {
        DIGITS as u32 * CHAIN_STEPS - TARGET_SUM
    }
}

impl PublicKey {
    pub fn size_bytes(&self) -> usize {
        poseidon2::OUT * 4
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
        let signature = sk.sign(message).expect("signing should find randomness");
        assert!(verify(&pk, message, &signature));
    }

    #[test]
    fn signed_digits_hit_the_target_sum() {
        let sk = PrivateKey::generate();
        let message = b"check the target sum";
        let signature = sk.sign(message).unwrap();
        let digits = derive_digits(&poseidon2::hash_bytes(message), signature.randomness);
        assert_eq!(digit_sum(&digits), TARGET_SUM);
    }

    #[test]
    fn tampered_message_fails() {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        let signature = sk.sign(b"original message").unwrap();
        assert!(!verify(&pk, b"different message", &signature));
    }

    #[test]
    fn wrong_randomness_fails() {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        let message = b"original message";
        let mut signature = sk.sign(message).unwrap();
        signature.randomness = signature.randomness.wrapping_add(1);
        assert!(!verify(&pk, message, &signature));
    }

    #[test]
    fn walking_a_chain_forward_fails() {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        let message = b"original message";
        let mut signature = sk.sign(message).unwrap();
        signature.chains[0] = poseidon2::compress(signature.chains[0]);
        assert!(!verify(&pk, message, &signature));
    }

    #[test]
    fn different_keys_do_not_verify() {
        let sk = PrivateKey::generate();
        let other_pk = PrivateKey::generate().public_key();
        let message = b"original message";
        let signature = sk.sign(message).unwrap();
        assert!(!verify(&other_pk, message, &signature));
    }
}
