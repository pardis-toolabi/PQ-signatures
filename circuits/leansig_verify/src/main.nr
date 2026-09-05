//! leanSig verification, in-circuit.
//!
//! Two things change versus `../wots_verify`: there are no checksum chains
//! (the target sum replaces them), and there are fewer chains overall.
//!
//! Worth being precise about what the target sum does and does not buy
//! here. Natively it makes the verifier walk exactly 385 steps instead of
//! WOTS's ~500. In-circuit it buys none of that, because the circuit still
//! has to budget the full 15 hashes for every chain. What it does buy is
//! the removal of the checksum chains and a smaller chain count, which is
//! a real but smaller saving. See ../README.md.
//!
//! # References
//!
//! - J. Drake, D. Khovratovich, M. Kudinov, B. Wagner, "Hash-Based
//!   Multi-Signatures for Post-Quantum Ethereum", ePrint 2025/055. The
//!   scheme verified here is the target-sum Winternitz instantiation of
//!   that paper's generalized XMSS framework.
//!   https://eprint.iacr.org/2025/055
//! - The same authors' "Technical Note: LeanSig for Post-Quantum
//!   Ethereum", ePrint 2025/1332, names and instantiates the concrete
//!   scheme. https://eprint.iacr.org/2025/1332
//! - Mirrors `leansig::verify` (../../../leansig/src/lib.rs) at
//!   circuit-adjusted parameters: 254-bit digests and Poseidon2 over
//!   BN254 here versus BabyBear there. See ../../README.md,
//!   "Conventions these circuits share".

use poseidon::poseidon2::Poseidon2;

global DIGITS: u32 = 56;
global MAX_STEPS: u32 = 15;
/// Every signed message's digits must add up to exactly this.
global TARGET_SUM: u32 = 455;

/// Walks a chain, always paying MAX_STEPS hashes. Same shape as the WOTS
/// version: the branch selects a value, it does not skip work.
fn walk_chain(start: Field, steps: u32) -> Field {
    let mut value = start;
    for step in 0..MAX_STEPS {
        let hashed = Poseidon2::hash([value], 1);
        value = if step < steps { hashed } else { value };
    }
    value
}

/// Re-derives the digits from the message and the signer's randomness.
fn derive_digits(message_digest: Field, randomness: Field) -> [u32; DIGITS] {
    let mixed = Poseidon2::hash([message_digest, randomness], 2);
    let bits: [bool; 254] = mixed.to_le_bits();

    let mut digits: [u32; DIGITS] = [0; DIGITS];
    for i in 0..DIGITS {
        let mut digit: u32 = 0;
        digit += bits[4 * i] as u32;
        digit += (bits[4 * i + 1] as u32) * 2;
        digit += (bits[4 * i + 2] as u32) * 4;
        digit += (bits[4 * i + 3] as u32) * 8;
        digits[i] = digit;
    }
    digits
}

fn main(
    message_digest: pub Field,
    pk_digest: pub Field,
    randomness: Field,
    signature: [Field; DIGITS],
) {
    let digits = derive_digits(message_digest, randomness);

    // This single check replaces WOTS's checksum chains. Chains only walk
    // forward, so a forger can only raise digits, which would push the sum
    // past the target and fail here. This is the target-sum Winternitz
    // encoding of ePrint 2025/055.
    let mut sum: u32 = 0;
    for i in 0..DIGITS {
        sum += digits[i];
    }
    assert(sum == TARGET_SUM);

    let mut tops: [Field; DIGITS] = [0; DIGITS];
    for i in 0..DIGITS {
        tops[i] = walk_chain(signature[i], MAX_STEPS - digits[i]);
    }

    assert(Poseidon2::hash(tops, DIGITS) == pk_digest);
}
