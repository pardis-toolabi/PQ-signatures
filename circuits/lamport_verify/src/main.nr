//! Lamport signature verification, in-circuit.
//!
//! One hash per message bit, with no chains and no branching, which makes
//! this the cheapest of the schemes here to verify inside a proof despite
//! having by far the largest signature.
//!
//! The public key is committed as a single Poseidon2 digest over all 508
//! entries. The circuit is given the 254 entries the signature does not
//! reveal, rebuilds the full list, and re-hashes it. Committing the key
//! this way keeps the public input to one field element, and every scheme
//! in this directory uses the same convention so the comparison is fair.

use poseidon::poseidon2::Poseidon2;

/// One bit per chain. BN254's field holds 254 bits, so that is the natural
/// message size here (the Rust version uses 256 bits over BabyBear).
global BITS: u32 = 254;
global PK_LEN: u32 = 508;

fn main(
    message_digest: pub Field,
    pk_digest: pub Field,
    signature: [Field; BITS],
    unrevealed_pk: [Field; BITS],
) {
    let bits: [bool; BITS] = message_digest.to_le_bits();
    let mut full_pk: [Field; PK_LEN] = [0; PK_LEN];

    for i in 0..BITS {
        // Hashing the revealed secret must land on the public key entry for
        // whichever bit the message actually has.
        let revealed = Poseidon2::hash([signature[i]], 1);
        let bit = bits[i] as Field;

        // Place the revealed hash in the slot the bit selects, and the
        // supplied entry in the other slot. No branching: a bit of 0 or 1
        // just swaps which slot each value lands in.
        full_pk[2 * i] = (1 - bit) * revealed + bit * unrevealed_pk[i];
        full_pk[2 * i + 1] = bit * revealed + (1 - bit) * unrevealed_pk[i];
    }

    assert(Poseidon2::hash(full_pk, PK_LEN) == pk_digest);
}
