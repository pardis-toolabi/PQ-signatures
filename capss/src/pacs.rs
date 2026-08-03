//! The PACS / RegRounds arithmetization of a keygen execution.
//!
//! This is the bridge between "I know the secret `x`" and "here is a
//! matrix satisfying a fixed set of low-degree polynomial constraints".
//! Everything above it in CAPSS — DECS, LVCS, PCS, the PIOP — only ever
//! sees the matrix and the constraints, never the permutation.
//!
//! ## The shape
//!
//! The witness is an `n x s` matrix. Column `k` holds a slice of the
//! execution: `b + 1` consecutive permutation states, so `b` rounds'
//! worth of work, laid out one state per block of `t` rows. Adjacent
//! columns overlap by one state — column `k`'s last state is column
//! `k+1`'s first — and that overlap is stitched shut by an explicit
//! wiring constraint. RegRounds ("regular rounds") is the name for this
//! layout: it works because every Anemoi round has the same shape, so
//! one constraint template covers them all.
//!
//! ```text
//! s  = ceil(n_r / b)              columns
//! n  = (b+1)*t + b*|v|            rows
//! m1 = b*(t + |v|)                parallel constraints
//! m2 = (s-1)*t + |iv| + |y|       aggregated constraints
//! d  = alpha                      constraint degree
//! ```
//!
//! ## Two constraint families
//!
//! **Parallel** constraints hold at every column independently. They are
//! the round verifications: for each packed round, check that the output
//! state really is the round applied to the input state. For Anemoi this
//! is where the arithmetization earns its keep — the forward round needs
//! `x^(1/alpha)`, a 64-squaring exponentiation, but *verifying* a round
//! needs only the closed Flystel, two identities of degree `alpha` per
//! pair and no inverse anywhere. See `round_constraints` for the exact
//! form.
//!
//! **Aggregated** constraints tie the columns to each other and to the
//! public key: wiring, `Tr_{|iv|}(x_0) = iv`, and `Tr_{|y|}(x_{n_r}) = y`.
//!
//! ## Where this differs from the paper
//!
//! In the full PIOP the two families are not checked the way they are
//! here. Both get folded into a single polynomial `Q` over the domain
//! `Omega = {0..s-1}`; parallel constraints must vanish at every `omega`
//! individually, aggregated ones only have to *sum* to zero over the
//! whole domain. What this module does is evaluate the underlying
//! identities directly, one at a time. That is strictly stronger than
//! the summed check — the sum of a set of zeros is zero — so an honest
//! witness passing here would also pass there. It is not a substitute
//! for the PIOP, which is what makes the check succinct and
//! zero-knowledge; it is the statement the PIOP is about.
//!
//! One detail the "parallel" name hides: the round constants differ from
//! round to round, so the constraint at column `k` is not literally the
//! same polynomial as at column `k+1`. In the paper these public
//! constants ride along as coefficient polynomials evaluated at
//! `omega = k` (the `l'` in `deg_q = d*(l' + s - 1) + s`). Here they are
//! just looked up by round index.

use crate::anemoi::{self, ROUNDS, WIDTH};
use crate::field::{Fp, ALPHA};
use crate::keys::{PublicKey, IV_SIZE, OUTPUT_SIZE, SECRET_SIZE};

/// `b`, the number of rounds packed into one witness column.
///
/// Anemoi over Goldilocks has 11 rounds, and 11 is prime, so the only
/// `b` that divide it are 1 and 11. `b = 11` collapses the matrix to a
/// single column: no wiring, no aggregation, and a 96-row witness — the
/// arithmetization degenerates into "one giant constraint". `b = 1` is
/// therefore the only non-degenerate exact divisor, and it needs no
/// padding rounds, which a non-divisor would (the last column would
/// otherwise have to hold rounds that do not exist). Everything below is
/// written in terms of this constant rather than assuming 1.
pub const BATCHING: usize = 1;

/// `t`, the permutation state width.
pub const STATE: usize = WIDTH;

/// `|v|`, the per-round auxiliary witness.
///
/// Zero for Anemoi: the closed Flystel expresses a round purely in terms
/// of the states on either side of it, so there is nothing extra to
/// commit to. Permutations whose round cannot be written that way (the
/// paper's Rescue and Poseidon instances) need `|v| > 0`, which is why
/// the formulas carry the term at all.
pub const ROUND_WITNESS: usize = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dimensions {
    /// `s`
    pub columns: usize,
    /// `n`
    pub rows: usize,
    /// `m1`
    pub parallel: usize,
    /// `m2`
    pub aggregated: usize,
    /// `d`
    pub degree: u64,
}

pub const fn dimensions() -> Dimensions {
    let columns = ROUNDS.div_ceil(BATCHING);
    Dimensions {
        columns,
        rows: (BATCHING + 1) * STATE + BATCHING * ROUND_WITNESS,
        parallel: BATCHING * (STATE + ROUND_WITNESS),
        aggregated: (columns - 1) * STATE + IV_SIZE + OUTPUT_SIZE,
        degree: ALPHA,
    }
}

/// The witness matrix.
///
/// Stored column-major because every consumer above this layer treats a
/// column as the unit — the PCS commits to columns, the PIOP indexes
/// them by `omega`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matrix {
    rows: usize,
    columns: usize,
    entries: Vec<Fp>,
}

impl Matrix {
    pub fn new(rows: usize, columns: usize) -> Matrix {
        Matrix { rows, columns, entries: vec![Fp::ZERO; rows * columns] }
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn columns(&self) -> usize {
        self.columns
    }

    pub fn get(&self, row: usize, column: usize) -> Fp {
        self.entries[column * self.rows + row]
    }

    pub fn set(&mut self, row: usize, column: usize, value: Fp) {
        self.entries[column * self.rows + row] = value;
    }

    /// The `j`-th state held by a column, `j` in `0..=b`.
    fn state(&self, column: usize, slot: usize) -> [Fp; STATE] {
        let mut state = [Fp::ZERO; STATE];
        for (i, value) in state.iter_mut().enumerate() {
            *value = self.get(slot * STATE + i, column);
        }
        state
    }
}

/// Runs the permutation and lays its trace out as an `n x s` matrix.
///
/// The trace has `n_r + 1` states and the matrix has `s * (b + 1)`
/// slots, so states get written twice — once as a column's output and
/// once as the next column's input. The duplication is deliberate: it is
/// what lets the parallel constraints look only inside a single column.
pub fn secret_to_witness(iv: &[Fp; IV_SIZE], x: &[Fp; SECRET_SIZE]) -> Matrix {
    let dimensions = dimensions();
    let trace = anemoi::permutation_trace(&crate::keys::initial_state(iv, x));
    let mut witness = Matrix::new(dimensions.rows, dimensions.columns);

    for column in 0..dimensions.columns {
        for slot in 0..=BATCHING {
            for (i, value) in trace[column * BATCHING + slot].iter().enumerate() {
                witness.set(slot * STATE + i, column, *value);
            }
        }
    }
    witness
}

/// One round verification: `2*l = t` identities of degree `alpha`,
/// checking that `output` is round `round` applied to `input`.
///
/// The round is constants, then the linear layer, then a Flystel per
/// pair. The first two are affine, so fold them in and let `(a, b)` be
/// the pair the Flystel actually sees. The open Flystel computes
///
/// ```text
/// a' = a - (beta*b^2 + gamma)
/// v  = b - a'^(1/alpha)
/// u  = a' + beta*v^2 + delta
/// ```
///
/// Eliminate `a'` — it appears in the first line as `a - beta*b^2 -
/// gamma` and in the third as `u - beta*v^2 - delta`, and the second
/// line says `a' = (b - v)^alpha`. So with
///
/// ```text
/// common = a - beta*b^2 - gamma
/// val1   = (b - v)^alpha - common
/// val2   = (u - beta*v^2 - delta) - common
/// ```
///
/// both must vanish, and neither mentions `x^(1/alpha)`. `val1` is
/// degree `alpha` in the witness and `val2` is degree 2, so the family
/// sits exactly at `d = alpha`.
///
/// `notes/capss-spec.md` writes this with `delta` inside `common` and
/// none in `val2`; that placement does not cancel against the Flystel as
/// implemented in `anemoi.rs` (`gamma = 0`, `delta = beta^-1`), so the
/// constants are taken from the permutation itself. The consequence of
/// getting this wrong is an honest trace failing its own constraints,
/// which is what `honest_witness_satisfies_every_constraint` catches.
fn round_constraints(input: &[Fp; STATE], output: &[Fp; STATE], round: usize) -> Vec<Fp> {
    let (beta, gamma, delta) = anemoi::flystel_constants();
    let affine = anemoi::affine_layer(input, round);
    let pairs = STATE / 2;

    let mut values = Vec::with_capacity(STATE);
    for i in 0..pairs {
        let (a, b) = (affine[i], affine[pairs + i]);
        let (u, v) = (output[i], output[pairs + i]);

        let common = a - beta * b.square() - gamma;
        values.push((b - v).pow(ALPHA) - common);
        values.push(u - beta * v.square() - delta - common);
    }
    values
}

/// The `m1` parallel constraints at one column: one round verification
/// per packed round.
pub fn parallel_constraints(witness: &Matrix, column: usize) -> Vec<Fp> {
    let mut values = Vec::with_capacity(dimensions().parallel);
    for packed in 0..BATCHING {
        values.extend(round_constraints(
            &witness.state(column, packed),
            &witness.state(column, packed + 1),
            column * BATCHING + packed,
        ));
    }
    values
}

/// The `m2` aggregated constraints: wiring, then the two bindings to the
/// public key.
///
/// Wiring is `w_{b*t+i,k} - w_{i,k+1} = 0` — the last state of column
/// `k` is the first state of column `k+1`. Without it a prover could put
/// an unrelated execution in each column.
pub fn aggregated_constraints(witness: &Matrix, public: &PublicKey) -> Vec<Fp> {
    let dimensions = dimensions();
    let mut values = Vec::with_capacity(dimensions.aggregated);

    for column in 0..dimensions.columns - 1 {
        for i in 0..STATE {
            values.push(witness.get(BATCHING * STATE + i, column) - witness.get(i, column + 1));
        }
    }

    // Tr_{|iv|}(x_0) = iv. The rest of x_0 is the secret and stays free.
    for i in 0..IV_SIZE {
        values.push(witness.get(i, 0) - public.iv[i]);
    }

    // Tr_{|y|}(x_{n_r}) = y, read off the last state of the last column.
    for i in 0..OUTPUT_SIZE {
        values.push(witness.get(BATCHING * STATE + i, dimensions.columns - 1) - public.y[i]);
    }

    values
}

/// Evaluates every constraint and reports whether they all vanish.
pub fn constraints_are_satisfied(witness: &Matrix, public: &PublicKey) -> bool {
    let dimensions = dimensions();
    if witness.rows() != dimensions.rows || witness.columns() != dimensions.columns {
        return false;
    }
    let vanishes = |values: Vec<Fp>| values.iter().all(|value| value.is_zero());
    (0..dimensions.columns).all(|column| vanishes(parallel_constraints(witness, column)))
        && vanishes(aggregated_constraints(witness, public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;

    fn pseudorandom(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn key_pair(seed: &mut u64) -> (keys::KeyPair, [Fp; IV_SIZE], [Fp; SECRET_SIZE]) {
        let mut iv = [Fp::ZERO; IV_SIZE];
        let mut x = [Fp::ZERO; SECRET_SIZE];
        for value in iv.iter_mut().chain(x.iter_mut()) {
            *value = Fp::new(pseudorandom(seed) % crate::field::P);
        }
        (keys::from_parts(&iv, &x), iv, x)
    }

    #[test]
    fn dimensions_match_the_spec_formulas() {
        let dimensions = dimensions();
        assert_eq!(dimensions.columns, ROUNDS.div_ceil(BATCHING));
        // Equivalent to `b` dividing the round count exactly. If it did
        // not, the last column would be short and would have to be
        // padded with rounds that never happen.
        assert_eq!(BATCHING * dimensions.columns, ROUNDS);
        assert_eq!(dimensions.rows, (BATCHING + 1) * STATE + BATCHING * ROUND_WITNESS);
        assert_eq!(dimensions.parallel, BATCHING * (STATE + ROUND_WITNESS));
        assert_eq!(dimensions.aggregated, (dimensions.columns - 1) * STATE + IV_SIZE + OUTPUT_SIZE);
        assert_eq!(dimensions.degree, ALPHA);

        // The concrete numbers for b = 1, t = 8, 11 rounds.
        assert_eq!((dimensions.columns, dimensions.rows), (11, 16));
        assert_eq!((dimensions.parallel, dimensions.aggregated), (8, 88));

        // m1 is stated as b*(t + |v|), and the round verification emits
        // two identities per Flystel pair, so b*2*l. Those agree only
        // because t = 2*l — worth pinning down.
        assert_eq!(dimensions.parallel, BATCHING * 2 * (STATE / 2));
    }

    #[test]
    fn witness_has_the_right_shape_and_holds_the_trace() {
        let mut seed = 11u64;
        let (pair, iv, x) = key_pair(&mut seed);
        let witness = secret_to_witness(&iv, &x);
        let dimensions = dimensions();

        assert_eq!((witness.rows(), witness.columns()), (dimensions.rows, dimensions.columns));

        let trace = anemoi::permutation_trace(&keys::initial_state(&iv, &x));
        for column in 0..dimensions.columns {
            for slot in 0..=BATCHING {
                assert_eq!(witness.state(column, slot), trace[column * BATCHING + slot]);
            }
        }

        // The two ends of the chain are the things the public key pins.
        assert_eq!(witness.state(0, 0)[..IV_SIZE], pair.public.iv[..]);
        assert_eq!(witness.state(dimensions.columns - 1, BATCHING)[..OUTPUT_SIZE], pair.public.y[..]);
    }

    #[test]
    fn honest_witness_satisfies_every_constraint() {
        // The headline: if the closed-Flystel identity is wrong, the
        // prover's own trace fails here.
        let mut seed = 12u64;
        for _ in 0..25 {
            let (pair, iv, x) = key_pair(&mut seed);
            let witness = secret_to_witness(&iv, &x);

            for column in 0..dimensions().columns {
                for (index, value) in parallel_constraints(&witness, column).iter().enumerate() {
                    assert!(value.is_zero(), "parallel constraint {index} failed at column {column}");
                }
            }
            for (index, value) in aggregated_constraints(&witness, &pair.public).iter().enumerate() {
                assert!(value.is_zero(), "aggregated constraint {index} failed");
            }
            assert!(constraints_are_satisfied(&witness, &pair.public));
        }
    }

    #[test]
    fn perturbing_any_single_entry_breaks_a_constraint() {
        let mut seed = 13u64;
        let (pair, iv, x) = key_pair(&mut seed);
        let witness = secret_to_witness(&iv, &x);

        for row in 0..witness.rows() {
            for column in 0..witness.columns() {
                for delta in [Fp::ONE, -Fp::ONE, Fp::new(pseudorandom(&mut seed) % crate::field::P)] {
                    let mut corrupted = witness.clone();
                    corrupted.set(row, column, corrupted.get(row, column) + delta);
                    assert!(
                        !constraints_are_satisfied(&corrupted, &pair.public),
                        "corrupting ({row}, {column}) went undetected"
                    );
                }
            }
        }
    }

    #[test]
    fn a_witness_for_another_key_is_rejected() {
        let mut seed = 14u64;
        let (first, iv, x) = key_pair(&mut seed);
        let (second, other_iv, other_x) = key_pair(&mut seed);

        let witness = secret_to_witness(&iv, &x);
        assert!(constraints_are_satisfied(&witness, &first.public));
        assert!(!constraints_are_satisfied(&witness, &second.public));

        let other_witness = secret_to_witness(&other_iv, &other_x);
        assert!(!constraints_are_satisfied(&other_witness, &first.public));
    }

    #[test]
    fn a_broken_chain_is_caught_by_the_wiring_constraints() {
        // Each column on its own is a valid round; only the joins are
        // wrong. Nothing but the aggregated family can see this.
        let mut seed = 15u64;
        let (pair, iv, x) = key_pair(&mut seed);
        let (_, other_iv, other_x) = key_pair(&mut seed);

        let honest = secret_to_witness(&iv, &x);
        let other = secret_to_witness(&other_iv, &other_x);

        let mut spliced = honest.clone();
        let column = dimensions().columns / 2;
        for row in 0..spliced.rows() {
            spliced.set(row, column, other.get(row, column));
        }

        for check in 0..dimensions().columns {
            assert!(
                parallel_constraints(&spliced, check).iter().all(|value| value.is_zero()),
                "every column is still an honest round"
            );
        }
        assert!(aggregated_constraints(&spliced, &pair.public).iter().any(|value| !value.is_zero()));
        assert!(!constraints_are_satisfied(&spliced, &pair.public));
    }

    #[test]
    fn a_wrong_shaped_witness_is_rejected() {
        let mut seed = 16u64;
        let (pair, _, _) = key_pair(&mut seed);
        let dimensions = dimensions();
        assert!(!constraints_are_satisfied(&Matrix::new(dimensions.rows + 1, dimensions.columns), &pair.public));
        assert!(!constraints_are_satisfied(&Matrix::new(dimensions.rows, dimensions.columns + 1), &pair.public));
    }
}
