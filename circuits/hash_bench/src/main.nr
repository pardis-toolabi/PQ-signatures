//! Measures what a single hash call costs inside a circuit.
//!
//! This is the benchmark behind the central claim of this directory: the
//! choice of hash function matters more than the choice of signature
//! scheme. Change HASH_COUNT, or switch the body to the SHA-256 version
//! below, then run `nargo compile && bb gates -b target/hash_bench.json`.
//!
//! Measured on UltraHonk, subtracting the 36-gate empty-circuit baseline:
//!   Poseidon2  ->    ~73 gates per call
//!   SHA-256    -> ~36000 gates per call
//!
//! That is roughly a 490x difference for the same job.

use poseidon::poseidon2::Poseidon2;

global HASH_COUNT: u32 = 10;

fn main(x: Field, y: pub Field) {
    let mut h = x;
    for _ in 0..HASH_COUNT {
        h = Poseidon2::hash([h], 1);
    }
    assert(h == y);
}

// The SHA-256 comparison point. Swap this in as `main` to measure it:
//
//     use sha256::sha256_var;
//
//     fn main(x: [u8; 32], y: pub Field) {
//         let h = sha256_var(x, 32);
//         assert(h[0] as Field == y);
//     }
