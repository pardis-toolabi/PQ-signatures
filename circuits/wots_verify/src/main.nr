//! WOTS signature verification, in-circuit.
//!
//! The important lesson lives in `walk_chain` below: a circuit has a fixed
//! shape, so it cannot "stop early" when a chain is short. Every chain
//! costs the full 15 hashes no matter what its digit is. Natively WOTS
//! walks about 500 steps on average; in-circuit it always pays 990.
//!
//! # References
//!
//! - R. Merkle, "A Certified Digital Signature", CRYPTO '89, section 5
//!   introduces hash-chain (Winternitz) signing.
//!   https://www.ralphmerkle.com/papers/Certified1979.pdf
//! - RFC 8391 (XMSS), section 3.1 is the standardized WOTS+; the
//!   digit-plus-checksum layout below is its section 3.1.5.
//!   https://www.rfc-editor.org/rfc/rfc8391.html
//! - Mirrors `wots::verify` (../../../wots/src/lib.rs) at circuit-adjusted
//!   parameters: 63 message digits and Poseidon2 over BN254 here versus 64
//!   digits and SHA-256 there. See ../../README.md,
//!   "Conventions these circuits share".

use poseidon::poseidon2::Poseidon2;

/// 63 message digits (4 bits each, from BN254's 254-bit field) plus 3
/// checksum digits.
global MESSAGE_DIGITS: u32 = 63;
global CHECKSUM_DIGITS: u32 = 3;
global CHAINS: u32 = MESSAGE_DIGITS + CHECKSUM_DIGITS;
global MAX_STEPS: u32 = 15;

/// Walks a hash chain `steps` times, but always costs MAX_STEPS hashes.
///
/// The `if` does not save any work: both sides are computed and a
/// multiplexer picks one. This is the single biggest difference between
/// native cost and circuit cost for every Winternitz-style scheme.
fn walk_chain(start: Field, steps: u32) -> Field {
    let mut value = start;
    for step in 0..MAX_STEPS {
        let hashed = Poseidon2::hash([value], 1);
        value = if step < steps { hashed } else { value };
    }
    value
}

/// Splits the message digest into base-16 digits and appends the checksum.
fn message_to_digits(message_digest: Field) -> [u32; CHAINS] {
    let bits: [bool; 254] = message_digest.to_le_bits();
    let mut digits: [u32; CHAINS] = [0; CHAINS];

    for i in 0..MESSAGE_DIGITS {
        let mut digit: u32 = 0;
        digit += bits[4 * i] as u32;
        digit += (bits[4 * i + 1] as u32) * 2;
        digit += (bits[4 * i + 2] as u32) * 4;
        digit += (bits[4 * i + 3] as u32) * 8;
        digits[i] = digit;
    }

    // The checksum moves opposite to the digits, so raising any digit
    // forces a checksum digit down, which a forger cannot do. This is
    // RFC 8391 section 3.1.5's checksum: the sum of (w - 1 - digit).
    let mut checksum: u32 = 0;
    for i in 0..MESSAGE_DIGITS {
        checksum += MAX_STEPS - digits[i];
    }
    // Three base-16 digits, most significant first. The checksum tops out
    // at 63 * 15 = 945, which fits comfortably in three digits.
    digits[MESSAGE_DIGITS] = (checksum / 256) % 16;
    digits[MESSAGE_DIGITS + 1] = (checksum / 16) % 16;
    digits[MESSAGE_DIGITS + 2] = checksum % 16;

    digits
}

fn main(message_digest: pub Field, pk_digest: pub Field, signature: [Field; CHAINS]) {
    let digits = message_to_digits(message_digest);

    let mut tops: [Field; CHAINS] = [0; CHAINS];
    for i in 0..CHAINS {
        tops[i] = walk_chain(signature[i], MAX_STEPS - digits[i]);
    }

    assert(Poseidon2::hash(tops, CHAINS) == pk_digest);
}
