//! The Anemoi permutation over Goldilocks.
//!
//! Reference: Bouvier et al., "Anemoi Permutations and Jive Compression
//! Mode" (ePrint 2022/840, CRYPTO 2023) — the Flystel is their Section 4
//! (odd-characteristic instance Section 4.4, open/closed duality
//! Corollary 2), the round function (constants, diffusion, PHT, S-box
//! layer) Section 5.1, and the round-count rule Section 5.2, Eq. (2):
//! their Table 1a gives 11 rounds for `alpha = 7`, `l = 4` at 128-bit
//! security, which is the count used here. CAPSS (ePrint 2025/061,
//! Section 2.1) picks this permutation as its single symmetric primitive.
//!
//! Parameters match the CAPSS reference C configuration: `alpha = 7`,
//! state width `t = 8`, 11 rounds, so `l = t/2 = 4` Flystel pairs per
//! round. CAPSS uses one permutation for all three of its primitives —
//! the one-way function (a truncated single call), the XOF (a sponge),
//! and Merkle compression (Jive). None of those are built here; this
//! module is only the permutation itself.
//!
//! ## What Anemoi is doing
//!
//! Each round is: add round constants, diffuse, then apply the *open*
//! Flystel to each of the four `(x, y)` pairs. The open Flystel is
//!
//! ```text
//! x <- x - Q_gamma(y)
//! y <- y - x^(1/alpha)      // the inverse S-box
//! x <- x + Q_delta(y)
//! ```
//!
//! with `Q_gamma(y) = beta*y^2 + gamma` and `Q_delta(y) = beta*y^2 + delta`.
//!
//! The point of this shape is the closed/open Flystel duality. Evaluating
//! it forwards costs an expensive `x^(1/alpha)` — a full exponentiation.
//! But *verifying* a claimed input/output pair does not: the closed form
//! rearranges into two constraints of degree `alpha` only, with no
//! inverse anywhere. So the prover pays a little and the circuit pays
//! almost nothing, which is the whole reason CAPSS picks Anemoi. Two
//! degree-7 constraints per pair is what the PACS arithmetization
//! consumes. We implement the forward direction, since that is what
//! keygen and hashing need.
//!
//! ## What is NOT faithful to the reference
//!
//! **The round constants and the diffusion matrix here are invented, not
//! the reference ones.** The Anemoi specification derives its constants
//! from the digits of pi and uses a specific small-entry matrix; the
//! CAPSS C implementation reproduces those byte-exactly. We cannot
//! reproduce them here without the reference builder, and guessing would
//! be worse than being honest, so instead:
//!
//! - Round constants come from a documented splitmix64 generator,
//!   rejection-sampled into the field — the same approach and the same
//!   caveat as `poseidon2` in this workspace. They only need to be
//!   fixed, public, and unstructured, which this achieves.
//! - The diffusion matrix is a fixed 4x4 Cauchy matrix. Cauchy matrices
//!   are provably MDS (every square submatrix of a Cauchy matrix is
//!   itself Cauchy, hence non-singular), so branch number is guaranteed
//!   rather than hoped for. The reference matrix is cheaper to evaluate
//!   but not stronger.
//!
//! **This will not interoperate with the CAPSS reference implementation
//! or with any other Anemoi library.** Nothing here is validated against
//! a published test vector, because none exist for CAPSS.
//!
//! One further deviation, this one deliberate and shared with the
//! reference: the final linear layer after the last round is omitted.
//! `notes/capss-spec.md` records that the CAPSS Anemoi code carries a
//! comment saying it "does not implement the final Anemoi linear layer
//! yet", consistently in both the permutation and its arithmetization.
//! Adding it here would put us further from the reference, not closer.

use crate::field::{Fp, ALPHA_INVERSE, GENERATOR};
use std::sync::OnceLock;

/// Number of Flystel pairs per round; `l` in the Anemoi paper.
pub const L: usize = 4;
/// State width `t = 2*l`. The first `L` elements are `x`, the rest `y`.
pub const WIDTH: usize = 2 * L;
/// Round count from the reference C configuration.
pub const ROUNDS: usize = 11;

/// `beta` in the Flystel's quadratic. Anemoi takes it to be a generator
/// of `F_p^*`; for Goldilocks that is 7.
const BETA: u64 = GENERATOR;

struct Parameters {
    /// Round constants for the `x` half, `c_i^(r)` in the paper.
    constants_x: [[Fp; L]; ROUNDS],
    /// Round constants for the `y` half, `d_i^(r)`.
    constants_y: [[Fp; L]; ROUNDS],
    diffusion: [[Fp; L]; L],
    beta: Fp,
    /// `gamma = 0` and `delta = beta^-1`. The Anemoi paper's Flystel_p
    /// (Section 4.4, Fig. 4b) puts the constants the other way around —
    /// `Q_gamma = g*x^2 + g^-1`, `Q_delta = g*x^2`, i.e. `gamma = g^-1`,
    /// `delta = 0`. This crate's swap is a documented deviation, applied
    /// consistently here and in the arithmetization; additive constants
    /// cancel in differentials, and `Q_gamma != Q_delta` (all Section 4.4
    /// needs to avoid its invariant subset) still holds.
    gamma: Fp,
    delta: Fp,
}

fn parameters() -> &'static Parameters {
    static PARAMETERS: OnceLock<Parameters> = OnceLock::new();
    PARAMETERS.get_or_init(build_parameters)
}

fn build_parameters() -> Parameters {
    let mut state = 0xA11E_3701_C0DE_5EEDu64;
    let mut next = || {
        // splitmix64, rejection-sampled into the field so the constants
        // are uniform rather than biased by a modular reduction.
        loop {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            if z < crate::field::P {
                return Fp::new(z);
            }
        }
    };

    let mut constants_x = [[Fp::ZERO; L]; ROUNDS];
    let mut constants_y = [[Fp::ZERO; L]; ROUNDS];
    for round in 0..ROUNDS {
        for i in 0..L {
            constants_x[round][i] = next();
            constants_y[round][i] = next();
        }
    }

    // Cauchy matrix M[i][j] = 1/(u_i + v_j) with u = (0,1,2,3) and
    // v = (4,5,6,7): the two sets are disjoint, so no denominator is
    // zero and the matrix is MDS.
    let mut diffusion = [[Fp::ZERO; L]; L];
    for (i, row) in diffusion.iter_mut().enumerate() {
        for (j, entry) in row.iter_mut().enumerate() {
            let denominator = Fp::new((i + L + j) as u64);
            *entry = denominator.inverse().expect("Cauchy denominators are non-zero");
        }
    }

    let beta = Fp::new(BETA);
    Parameters {
        constants_x,
        constants_y,
        diffusion,
        beta,
        gamma: Fp::ZERO,
        delta: beta.inverse().expect("the generator is invertible"),
    }
}

fn apply_diffusion(matrix: &[[Fp; L]; L], vector: [Fp; L]) -> [Fp; L] {
    let mut result = [Fp::ZERO; L];
    for (i, row) in matrix.iter().enumerate() {
        let mut sum = Fp::ZERO;
        for (j, entry) in row.iter().enumerate() {
            sum = sum + *entry * vector[j];
        }
        result[i] = sum;
    }
    result
}

/// Anemoi's linear layer: diffuse each half, then a pseudo-Hadamard
/// transform to couple them (the paper's `M` and `P` layers,
/// Section 5.1).
///
/// The `y` half is rotated by one position before diffusion. That is how
/// Anemoi gets two different matrices out of one: `M_y = M_x . rho`. The
/// PHT afterwards is what makes the two halves talk to each other at all
/// — without it the Flystel would be the only coupling.
fn linear_layer(x: &mut [Fp; L], y: &mut [Fp; L]) {
    let matrix = &parameters().diffusion;
    let rotated = [y[1], y[2], y[3], y[0]];

    *x = apply_diffusion(matrix, *x);
    *y = apply_diffusion(matrix, rotated);

    for i in 0..L {
        y[i] = y[i] + x[i];
        x[i] = x[i] + y[i];
    }
}

/// The open Flystel (Anemoi paper Section 4.2, Fig. 4b). `x^(1/alpha)`
/// is the expensive part: a full exponentiation by `alpha^-1 mod (p-1)`,
/// about 64 squarings. Its low-degree verification twin, the closed
/// Flystel, is what the arithmetization uses (Corollary 2 there).
fn flystel(x: Fp, y: Fp) -> (Fp, Fp) {
    let parameters = parameters();
    let quadratic = |value: Fp, offset: Fp| parameters.beta * value.square() + offset;

    let x = x - quadratic(y, parameters.gamma);
    let y = y - x.pow(ALPHA_INVERSE);
    let x = x + quadratic(y, parameters.delta);
    (x, y)
}

/// The affine part of a round: add that round's constants, then the
/// linear layer. Everything before the Flystel, in other words.
///
/// Exposed on its own because the PACS arithmetization states the
/// Flystel identity over the *post-linear* values rather than over the
/// raw witness. This map is degree 1 in the state, so folding it into
/// the identity leaves the constraint at degree `alpha` — which is the
/// only reason the arithmetization can afford to do it that way.
pub fn affine_layer(state: &[Fp; WIDTH], round: usize) -> [Fp; WIDTH] {
    let parameters = parameters();
    let mut x: [Fp; L] = state[..L].try_into().expect("state splits evenly");
    let mut y: [Fp; L] = state[L..].try_into().expect("state splits evenly");

    for i in 0..L {
        x[i] = x[i] + parameters.constants_x[round][i];
        y[i] = y[i] + parameters.constants_y[round][i];
    }
    linear_layer(&mut x, &mut y);

    let mut result = [Fp::ZERO; WIDTH];
    result[..L].copy_from_slice(&x);
    result[L..].copy_from_slice(&y);
    result
}

/// `(beta, gamma, delta)`, the three constants of the Flystel's two
/// quadratics. The arithmetization needs them to write the closed-form
/// identity down.
pub fn flystel_constants() -> (Fp, Fp, Fp) {
    let parameters = parameters();
    (parameters.beta, parameters.gamma, parameters.delta)
}

/// Every intermediate state of the permutation: `x_0` (the input)
/// through `x_ROUNDS` (the output).
///
/// This is the prover's execution trace — the PACS witness is nothing
/// but this array reshaped into columns.
pub fn permutation_trace(state: &[Fp; WIDTH]) -> [[Fp; WIDTH]; ROUNDS + 1] {
    let mut trace = [[Fp::ZERO; WIDTH]; ROUNDS + 1];
    trace[0] = *state;

    for round in 0..ROUNDS {
        let mut next = affine_layer(&trace[round], round);
        for i in 0..L {
            (next[i], next[L + i]) = flystel(next[i], next[L + i]);
        }
        trace[round + 1] = next;
    }
    trace
}

/// The Anemoi permutation, in place.
pub fn permute(state: &mut [Fp; WIDTH]) {
    *state = *permutation_trace(state).last().expect("the trace ends at the output");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{ALPHA, P};

    fn pseudorandom(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn random_state(seed: &mut u64) -> [Fp; WIDTH] {
        let mut state = [Fp::ZERO; WIDTH];
        for value in state.iter_mut() {
            *value = Fp::new(pseudorandom(seed) % P);
        }
        state
    }

    #[test]
    fn permutation_is_deterministic() {
        let mut a = [Fp::ZERO; WIDTH];
        let mut b = [Fp::ZERO; WIDTH];
        permute(&mut a);
        permute(&mut b);
        assert_eq!(a, b);

        let mut seed = 42u64;
        let start = random_state(&mut seed);
        let (mut first, mut second) = (start, start);
        permute(&mut first);
        permute(&mut second);
        assert_eq!(first, second);
    }

    #[test]
    fn one_element_change_avalanches() {
        let mut seed = 7u64;
        for _ in 0..20 {
            let start = random_state(&mut seed);
            for position in 0..WIDTH {
                let mut changed = start;
                changed[position] = changed[position] + Fp::ONE;

                let (mut a, mut b) = (start, changed);
                permute(&mut a);
                permute(&mut b);

                let differing = (0..WIDTH).filter(|i| a[*i] != b[*i]).count();
                assert_eq!(differing, WIDTH, "a single input change must reach every output");
            }
        }
    }

    #[test]
    fn permutation_is_a_bijection_on_a_sample() {
        // A permutation cannot map two inputs to the same output. Each
        // piece is individually invertible — constant addition, an MDS
        // matrix with a PHT, and the Flystel — so this is a check that
        // the composition was wired correctly.
        let mut inputs = Vec::new();
        let mut seed = 0xBEEFu64;
        for i in 0..300u64 {
            // Half structured (adjacent inputs, the hardest case for a
            // weak permutation), half random.
            let mut state = [Fp::ZERO; WIDTH];
            state[0] = Fp::new(i);
            inputs.push(state);
            inputs.push(random_state(&mut seed));
        }

        let distinct_inputs: std::collections::HashSet<_> =
            inputs.iter().map(|s| s.map(|v| v.value())).collect();
        assert_eq!(distinct_inputs.len(), inputs.len(), "test inputs must be distinct");

        let mut outputs = std::collections::HashSet::new();
        for mut state in inputs {
            permute(&mut state);
            assert!(outputs.insert(state.map(|v| v.value())), "two inputs collided");
        }
    }

    #[test]
    fn output_is_not_sparse() {
        // A wiring mistake that left part of the state untouched would
        // show up as zeros or as an unchanged input value.
        let mut state = [Fp::ZERO; WIDTH];
        permute(&mut state);
        assert!(state.iter().all(|v| !v.is_zero()));
        assert!(state.iter().all(|v| v.value() > u32::MAX as u64));
    }

    #[test]
    fn flystel_round_trips() {
        let parameters = parameters();
        let mut seed = 123u64;
        for _ in 0..200 {
            let x = Fp::new(pseudorandom(&mut seed) % P);
            let y = Fp::new(pseudorandom(&mut seed) % P);
            let (u, v) = flystel(x, y);

            // Undo the three steps in reverse.
            let intermediate = u - (parameters.beta * v.square() + parameters.delta);
            let recovered_y = v + intermediate.pow(ALPHA_INVERSE);
            let recovered_x = intermediate + parameters.beta * recovered_y.square() + parameters.gamma;
            assert_eq!((recovered_x, recovered_y), (x, y));
        }
    }

    #[test]
    fn closed_flystel_verifies_the_open_one() {
        // The duality the arithmetization depends on (Anemoi paper,
        // Corollary 2 in Section 4.2). Given input (x, y)
        // and output (u, v), the relation holds with no inverse S-box
        // anywhere — just two constraints of degree alpha:
        //
        //   (y - v)^alpha = x - beta*y^2 - gamma
        //   (y - v)^alpha = u - beta*v^2 - delta
        //
        // Degree 7 to check instead of an exponentiation to compute is
        // the entire reason CAPSS uses Anemoi.
        let parameters = parameters();
        let mut seed = 456u64;
        for _ in 0..200 {
            let x = Fp::new(pseudorandom(&mut seed) % P);
            let y = Fp::new(pseudorandom(&mut seed) % P);
            let (u, v) = flystel(x, y);

            let common = (y - v).pow(ALPHA);
            assert_eq!(common, x - parameters.beta * y.square() - parameters.gamma);
            assert_eq!(common, u - parameters.beta * v.square() - parameters.delta);
        }
    }

    #[test]
    fn diffusion_matrix_is_mds() {
        // MDS means every square submatrix is non-singular. For 4x4 that
        // is 1 + 36 + 16 + 1 determinants, all cheap to check directly.
        let matrix = &parameters().diffusion;
        for size in 1..=L {
            for rows in combinations(L, size) {
                for columns in combinations(L, size) {
                    let submatrix: Vec<Vec<Fp>> =
                        rows.iter().map(|r| columns.iter().map(|c| matrix[*r][*c]).collect()).collect();
                    assert!(!determinant(&submatrix).is_zero(), "singular {size}x{size} submatrix");
                }
            }
        }
    }

    fn combinations(n: usize, size: usize) -> Vec<Vec<usize>> {
        (0..(1u32 << n))
            .filter(|mask| mask.count_ones() as usize == size)
            .map(|mask| (0..n).filter(|i| mask >> i & 1 == 1).collect())
            .collect()
    }

    /// Gaussian elimination; only used by the MDS test.
    fn determinant(matrix: &[Vec<Fp>]) -> Fp {
        let mut work: Vec<Vec<Fp>> = matrix.to_vec();
        let size = work.len();
        let mut result = Fp::ONE;
        for column in 0..size {
            let pivot = match (column..size).find(|row| !work[*row][column].is_zero()) {
                Some(row) => row,
                None => return Fp::ZERO,
            };
            if pivot != column {
                work.swap(pivot, column);
                result = -result;
            }
            result = result * work[column][column];
            let scale = work[column][column].inverse().unwrap();
            for row in (column + 1)..size {
                let factor = work[row][column] * scale;
                let pivot_row = work[column].clone();
                for (entry, above) in work[row].iter_mut().zip(pivot_row).skip(column) {
                    *entry = *entry - factor * above;
                }
            }
        }
        result
    }

    #[test]
    fn round_constants_are_distinct_and_in_range() {
        let parameters = parameters();
        let mut seen = std::collections::HashSet::new();
        for round in 0..ROUNDS {
            for i in 0..L {
                assert!(seen.insert(parameters.constants_x[round][i].value()));
                assert!(seen.insert(parameters.constants_y[round][i].value()));
            }
        }
        assert_eq!(seen.len(), 2 * L * ROUNDS);
        assert!(seen.iter().all(|value| *value < P));
    }
}
