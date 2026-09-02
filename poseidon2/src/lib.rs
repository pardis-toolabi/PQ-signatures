//! Poseidon2 over the BabyBear field.
//!
//! SHA-256 is cheap on a CPU but expensive inside a zero-knowledge circuit,
//! because its bit rotations and XORs do not map onto field arithmetic.
//! Poseidon2 is built the other way round: it is made only of field
//! additions, multiplications, and the S-box `x^7`, so a circuit can
//! express it directly. That makes it the hash of choice for the
//! ZK-friendly signature schemes in this workspace.

use std::ops::{Add, Mul, Sub};

/// BabyBear prime: 2^31 - 2^27 + 1.
pub const P: u32 = 2013265921;

/// Permutation width, in field elements.
pub const WIDTH: usize = 16;
/// How many elements are absorbed per permutation call.
pub const RATE: usize = 8;
/// How many elements a hash returns.
pub const OUT: usize = 8;

const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 13;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, PartialOrd, Ord, Hash)]
pub struct F(u32);

impl F {
    pub const ZERO: F = F(0);
    pub const ONE: F = F(1);

    pub fn from_u32(value: u32) -> F {
        F(value % P)
    }

    pub fn from_u64(value: u64) -> F {
        F((value % P as u64) as u32)
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }

    pub fn pow(self, mut exponent: u64) -> F {
        let mut result = F::ONE;
        let mut base = self;
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exponent >>= 1;
        }
        result
    }

    /// The Poseidon2 S-box. `x^7` is used for BabyBear because 7 is the
    /// smallest exponent coprime to `P - 1`, which makes the map a
    /// bijection on the field.
    fn sbox(self) -> F {
        let x2 = self * self;
        let x3 = x2 * self;
        let x4 = x2 * x2;
        x4 * x3
    }
}

impl Add for F {
    type Output = F;
    fn add(self, other: F) -> F {
        // Both operands are < P < 2^31, so the sum fits in u32 and needs at
        // most one conditional subtraction.
        let sum = self.0 + other.0;
        F(if sum >= P { sum - P } else { sum })
    }
}

impl Sub for F {
    type Output = F;
    fn sub(self, other: F) -> F {
        F(if self.0 >= other.0 { self.0 - other.0 } else { self.0 + P - other.0 })
    }
}

impl Mul for F {
    type Output = F;
    fn mul(self, other: F) -> F {
        F(((self.0 as u64 * other.0 as u64) % P as u64) as u32)
    }
}

/// Deterministic round constants.
///
/// The reference Poseidon2 specification derives these with a Grain LFSR.
/// This implementation uses a simpler documented generator instead: the
/// constants only need to be fixed, public, and unstructured, which this
/// achieves, but it does mean these are NOT the standard reference
/// constants and will not interoperate with other Poseidon2 libraries.
fn round_constants() -> &'static ([[F; WIDTH]; FULL_ROUNDS], [F; PARTIAL_ROUNDS]) {
    static CONSTANTS: std::sync::OnceLock<([[F; WIDTH]; FULL_ROUNDS], [F; PARTIAL_ROUNDS])> =
        std::sync::OnceLock::new();
    CONSTANTS.get_or_init(build_round_constants)
}

fn build_round_constants() -> ([[F; WIDTH]; FULL_ROUNDS], [F; PARTIAL_ROUNDS]) {
    let mut state = 0x9E3779B97F4A7C15u64;
    let mut next = || {
        // splitmix64, rejection-sampled into the field.
        loop {
            state = state.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^= z >> 31;
            let candidate = (z >> 32) as u32;
            if candidate < P {
                return F(candidate);
            }
        }
    };

    let mut full = [[F::ZERO; WIDTH]; FULL_ROUNDS];
    for round in full.iter_mut() {
        for value in round.iter_mut() {
            *value = next();
        }
    }
    let mut partial = [F::ZERO; PARTIAL_ROUNDS];
    for value in partial.iter_mut() {
        *value = next();
    }
    (full, partial)
}

/// Diagonal of the internal (partial-round) matrix.
///
/// Poseidon2 replaces Poseidon's dense partial-round matrix with
/// `ones_matrix + diag(d)`, which needs only `WIDTH` multiplications
/// instead of `WIDTH^2`. This is the main reason Poseidon2 is cheaper
/// than Poseidon, both natively and in a circuit.
///
/// Like the round constants above, this diagonal is invented, not the
/// vetted reference BabyBear-16 diagonal, and no invariant-subspace
/// check has been run on it — another reason this permutation will not
/// interoperate with (and is weaker than) standard Poseidon2.
const INTERNAL_DIAGONAL: [u32; WIDTH] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 20, 24, 32, 64, 128,
];

/// Applies the 4x4 MDS matrix used by the Poseidon2 external layer.
fn apply_m4(chunk: &mut [F]) {
    let t0 = chunk[0] + chunk[1];
    let t1 = chunk[2] + chunk[3];
    let t2 = chunk[1] + chunk[1] + t1;
    let t3 = chunk[3] + chunk[3] + t0;
    let t4 = t1 + t1 + t1 + t1 + t3;
    let t5 = t0 + t0 + t0 + t0 + t2;
    chunk[0] = t3 + t5;
    chunk[1] = t5;
    chunk[2] = t2 + t4;
    chunk[3] = t4;
}

/// External linear layer: apply M4 to each group of four, then mix the
/// groups together so every element influences every other.
fn external_layer(state: &mut [F; WIDTH]) {
    for chunk in state.chunks_mut(4) {
        apply_m4(chunk);
    }
    let mut sums = [F::ZERO; 4];
    for (i, value) in state.iter().enumerate() {
        sums[i % 4] = sums[i % 4] + *value;
    }
    for (i, value) in state.iter_mut().enumerate() {
        *value = *value + sums[i % 4];
    }
}

/// Internal linear layer: `state[i] = sum(state) + diagonal[i] * state[i]`.
fn internal_layer(state: &mut [F; WIDTH]) {
    let mut sum = F::ZERO;
    for value in state.iter() {
        sum = sum + *value;
    }
    for (i, value) in state.iter_mut().enumerate() {
        *value = sum + F::from_u32(INTERNAL_DIAGONAL[i]) * *value;
    }
}

/// The Poseidon2 permutation.
///
/// Structure: half the full rounds, then all partial rounds, then the
/// other half of the full rounds. Full rounds apply the S-box to every
/// element (strong mixing, expensive); partial rounds apply it to only
/// the first element (cheap, and enough to keep the algebraic degree
/// climbing). This split is what keeps the total multiplication count low.
pub fn permute(state: &mut [F; WIDTH]) {
    let (full_constants, partial_constants) = round_constants();

    external_layer(state);

    let half = FULL_ROUNDS / 2;
    for round in full_constants.iter().take(half) {
        for (value, constant) in state.iter_mut().zip(round.iter()) {
            *value = (*value + *constant).sbox();
        }
        external_layer(state);
    }

    for constant in partial_constants.iter() {
        state[0] = (state[0] + *constant).sbox();
        internal_layer(state);
    }

    for round in full_constants.iter().skip(half) {
        for (value, constant) in state.iter_mut().zip(round.iter()) {
            *value = (*value + *constant).sbox();
        }
        external_layer(state);
    }
}

/// Fixed-length compression: absorb eight elements, return eight.
///
/// Hash chains in leanSig call this over and over, so it avoids the
/// padding work a variable-length sponge would repeat every step.
pub fn compress(input: [F; OUT]) -> [F; OUT] {
    let mut state = [F::ZERO; WIDTH];
    state[..OUT].copy_from_slice(&input);
    permute(&mut state);
    let mut output = [F::ZERO; OUT];
    output.copy_from_slice(&state[..OUT]);
    output
}

/// Variable-length sponge hash over field elements.
pub fn hash(input: &[F]) -> [F; OUT] {
    let mut state = [F::ZERO; WIDTH];
    // Length goes in the capacity as domain separation, so that inputs of
    // different lengths cannot collide by padding alone.
    state[WIDTH - 1] = F::from_u64(input.len() as u64);

    if input.is_empty() {
        permute(&mut state);
    } else {
        for chunk in input.chunks(RATE) {
            for (i, value) in chunk.iter().enumerate() {
                state[i] = state[i] + *value;
            }
            permute(&mut state);
        }
    }

    let mut output = [F::ZERO; OUT];
    output.copy_from_slice(&state[..OUT]);
    output
}

/// Packs bytes into field elements (three bytes each, since 2^24 < P) and
/// hashes them.
pub fn hash_bytes(bytes: &[u8]) -> [F; OUT] {
    let mut elements = Vec::with_capacity(bytes.len() / 3 + 2);
    elements.push(F::from_u64(bytes.len() as u64));
    for chunk in bytes.chunks(3) {
        let mut packed = 0u32;
        for (i, byte) in chunk.iter().enumerate() {
            packed |= (*byte as u32) << (8 * i);
        }
        elements.push(F::from_u32(packed));
    }
    hash(&elements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_arithmetic_wraps_correctly() {
        let a = F::from_u32(P - 1);
        assert_eq!(a + F::ONE, F::ZERO);
        assert_eq!(F::ZERO - F::ONE, F::from_u32(P - 1));
    }

    #[test]
    fn sbox_is_a_bijection_on_samples() {
        // x^7 is invertible, so distinct inputs must give distinct outputs.
        let mut seen = std::collections::HashSet::new();
        for i in 0..1000u32 {
            assert!(seen.insert(F::from_u32(i).sbox()));
        }
    }

    #[test]
    fn permutation_is_deterministic_and_mixes() {
        let mut a = [F::ZERO; WIDTH];
        let mut b = [F::ZERO; WIDTH];
        permute(&mut a);
        permute(&mut b);
        assert_eq!(a, b, "permutation must be deterministic");

        let mut c = [F::ZERO; WIDTH];
        c[0] = F::ONE;
        permute(&mut c);
        assert_ne!(a, c, "a one-element change must change the output");
        assert!(a.iter().filter(|x| **x == F::ZERO).count() < WIDTH / 2);
    }

    #[test]
    fn hash_is_sensitive_to_input() {
        assert_ne!(hash_bytes(b"message one"), hash_bytes(b"message two"));
        assert_eq!(hash_bytes(b"same"), hash_bytes(b"same"));
        // Length separation: "a" and "a\0" must not collide.
        assert_ne!(hash_bytes(b"a"), hash_bytes(b"a\0"));
    }
}
