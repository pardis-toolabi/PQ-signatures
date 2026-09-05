//! XMSS verification, in-circuit.
//!
//! This is the WOTS circuit plus a Merkle path walk. The interesting
//! result is how little the tree costs: one hash per level, so a
//! height-10 tree adds only 10 hashes on top of WOTS's 990. Going from a
//! one-time signature to a 1024-time one is nearly free inside a proof.
//!
//! # References
//!
//! - RFC 8391, "XMSS: eXtended Merkle Signature Scheme", section 4 is the
//!   standardized scheme; verification is section 4.1.10, whose
//!   Algorithm 13 (XMSS_rootFromSig) is the Merkle climb in `main`.
//!   https://www.rfc-editor.org/rfc/rfc8391.html
//! - R. Merkle, "A Certified Digital Signature", CRYPTO '89, section 6 is
//!   the original tree authentication path.
//!   https://www.ralphmerkle.com/papers/Certified1979.pdf
//! - Mirrors `xmss::verify` (../../../xmss/src/lib.rs) at circuit-adjusted
//!   parameters (63 message digits, Poseidon2 over BN254). See
//!   ../../README.md, "Conventions these circuits share".

use poseidon::poseidon2::Poseidon2;

global MESSAGE_DIGITS: u32 = 63;
global CHECKSUM_DIGITS: u32 = 3;
global CHAINS: u32 = MESSAGE_DIGITS + CHECKSUM_DIGITS;
global MAX_STEPS: u32 = 15;
/// Tree height: 2^10 = 1024 signatures per key pair.
global HEIGHT: u32 = 10;

fn walk_chain(start: Field, steps: u32) -> Field {
    let mut value = start;
    for step in 0..MAX_STEPS {
        let hashed = Poseidon2::hash([value], 1);
        value = if step < steps { hashed } else { value };
    }
    value
}

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

    let mut checksum: u32 = 0;
    for i in 0..MESSAGE_DIGITS {
        checksum += MAX_STEPS - digits[i];
    }
    digits[MESSAGE_DIGITS] = (checksum / 256) % 16;
    digits[MESSAGE_DIGITS + 1] = (checksum / 16) % 16;
    digits[MESSAGE_DIGITS + 2] = checksum % 16;

    digits
}

fn main(
    message_digest: pub Field,
    root: pub Field,
    leaf_index: Field,
    signature: [Field; CHAINS],
    auth_path: [Field; HEIGHT],
) {
    // Step 1: rebuild the one-time public key straight from the signature.
    let digits = message_to_digits(message_digest);
    let mut tops: [Field; CHAINS] = [0; CHAINS];
    for i in 0..CHAINS {
        tops[i] = walk_chain(signature[i], MAX_STEPS - digits[i]);
    }

    // Step 2: hash it into a leaf and climb to the root -- RFC 8391's
    // XMSS_rootFromSig (section 4.1.10, Algorithm 13), minus its keyed
    // bitmasked hashing.
    let mut node = Poseidon2::hash(tops, CHAINS);
    let index_bits: [bool; 254] = leaf_index.to_le_bits();

    for level in 0..HEIGHT {
        let sibling = auth_path[level];
        let go_right = index_bits[level] as Field;

        // An even index means this node is the left child. Rather than
        // branching, swap the pair arithmetically.
        let left = (1 - go_right) * node + go_right * sibling;
        let right = go_right * node + (1 - go_right) * sibling;
        node = Poseidon2::hash([left, right], 2);
    }

    assert(node == root);
}
