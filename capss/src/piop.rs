//! The SmallWood polynomial IOP — the layer that turns "here is a witness
//! matrix satisfying the PACS constraints" into something a verifier can
//! check from a handful of opened points.
//!
//! Reference: SmallWood (ePrint 2025/1085), Section 5.2, "The PACS
//! Polynomial IOP" (Protocol 6). The row interpolation with `l'` blinding
//! points is their LVCS idea (Section 4.1); `Q_k` below is their
//! Eq. (10), the sum-over-Omega check their Eq. (13), and the masks
//! summing to zero over Omega are stated just above Eq. (10). CAPSS
//! (ePrint 2025/061, Section 2.2) restates the same protocol.
//!
//! ## The identity
//!
//! Every row of the `n x s` witness matrix is lifted into a polynomial.
//! With `Omega = {0, 1, ..., s-1}` the column supports, row `i` becomes a
//! polynomial `P_i` with `P_i(omega) = w[i][omega]`, plus `l'` extra
//! interpolation points carrying pure randomness. Those `l'` spare
//! degrees of freedom are the zero knowledge: the proof opens exactly
//! `l'` points outside `Omega`, and at those points every `P_i` is
//! uniformly random and independent of the witness. That "outside
//! `Omega`" is load-bearing and is enforced by `decs::EVALUATION_OFFSET`:
//! the committed evaluation points start at `2^32`, far above every
//! interpolation point, so no opening can land on a witness column.
//!
//! ```text
//! input_degree = l' + s - 1
//! deg_q        = d * input_degree + s
//!
//! Q_k(X) = sum_j gamma_{k,j}(X) * C_j^para(X)
//!        + sum_j gamma'_{k,j}    * C_j^aggr(X)
//!        + Mask_k(X)
//! ```
//!
//! and the verifier checks, for each `k` in `[1, rho]`,
//!
//! ```text
//! sum over omega in Omega of Q_k(omega) = 0
//! ```
//!
//! (SmallWood Eq. (13); their `deg_q` bound is Eq. (9), which reads
//! `d*(l' + s - 1) + s - 1` for the parallel family — the `+ s` here is
//! one looser, which only over-provisions the degree.)
//!
//! ## Why the two constraint families are weighted differently
//!
//! (These are SmallWood Eq. (10)'s two weight kinds: polynomials
//! `Gamma'_{i,j}(X)` of degree `s-1` for parallel constraints, scalars
//! `gamma'_{i,j}` for aggregated ones.)
//!
//! A **parallel** constraint has to vanish at *every* `omega`
//! individually — it is the round verification, and a round that is wrong
//! in column 3 is wrong full stop. A single scalar coefficient per
//! constraint would only force the *sum* over columns to vanish, letting
//! a prover pay for a violation at one column with a compensating
//! violation at another. So `gamma_{k,j}` is not a scalar but a
//! **polynomial of degree `s-1` interpolating `s` independent challenge
//! coefficients over `Omega`**. Then
//!
//! ```text
//! sum_omega gamma_{k,j}(omega) * C_j^para(omega)
//!   = sum_omega r_{k,j,omega} * C_j^para(omega)
//! ```
//!
//! is a random linear combination of the `s` per-column values, which
//! vanishes only if every one of them does (up to `1/p`).
//!
//! An **aggregated** constraint is the opposite: it is a statement about
//! the columns taken together — wiring column `k`'s output to column
//! `k+1`'s input, and pinning the two ends of the chain to the public
//! key — so it only has to *sum* to zero over `Omega`, and a single
//! scalar `gamma'_{k,j}` is the right weight. Each is written as
//! `sum_i c_i(X) * P_i(X) + c(X)` for public degree-`s-1` coefficient
//! polynomials, which is the form a verifier can evaluate at one point
//! knowing only that point's row values.
//!
//! The **mask** must itself sum to zero over `Omega`, otherwise it would
//! shift the very quantity being tested. It is sampled uniformly from the
//! subspace of degree-`deg_q` polynomials with that property: pick every
//! coefficient above the constant freely, then let the constant absorb
//! the sum. That subspace is exactly the set of legal masks, so `Q_k` is
//! uniform on the coset it lives in and the transmitted coefficients
//! carry no information about the witness.
//!
//! ## What is sent
//!
//! Only the coefficients of `Q_k` of degree `>= l'`. The verifier learns
//! `Q_k` at the `l'` opened points — every ingredient is in the opened
//! leaf — subtracts the transmitted high part, and interpolates the
//! remaining degree-`< l'` polynomial through those `l'` points. That is
//! `l'` unknowns against `l'` interpolation equations; the sum-to-zero
//! condition is then the one equation left over, and it is the check.
//!
//! It matters which of the `l' + 1` available equations is spent on
//! reconstruction and which is kept as a test. Reconstructing from all
//! `l' + 1` would leave a square system that is always solvable, so
//! nothing would ever fail. Keeping the sum as a test is what makes the
//! protocol prove anything.
//!
//! ## Soundness, honestly
//!
//! Two things stand between a false statement and an accepting proof.
//! First, the challenge coefficients: if any PACS constraint is violated
//! then `sum_omega Q_k(omega)` is a non-zero field element except with
//! probability `1/p` over the challenges, independently for each `k`.
//! Second, the opening indices are squeezed from a hash of the
//! transmitted high coefficients, so a prover who wants to steer the
//! reconstruction has to grind: each attempt changes the indices, and
//! each attempt lands on zero with probability about `p^{-rho}`. Both
//! terms are `rho * log2(p)` bits, which is why `rho = 2` is the smallest
//! sensible choice over a 64-bit field. Neither is a proof — see the
//! crate README and the report for what is and is not established here.

use crate::anemoi;
use crate::decs::{self, evaluate, interpolate};
use crate::field::{Fp, ALPHA};
use crate::keys::{PublicKey, IV_SIZE, OUTPUT_SIZE};
use crate::merkle::node_width;
use crate::pacs::{dimensions, Matrix, BATCHING, STATE};
use crate::transcript::{xof, Digest, Transcript};

/// Everything that is not already fixed by the arithmetization.
///
/// `columns`, `rows`, `degree` and the two constraint counts all come
/// from `pacs::dimensions()` and are not tunable — they are properties of
/// Anemoi over Goldilocks. What is left is the size of the commitment and
/// how much of it gets opened.
#[derive(Clone, Copy, Debug)]
pub struct Parameters {
    /// `l'`: the number of extra random interpolation points on each row
    /// polynomial, which is also the number of Merkle leaves opened. The
    /// two must be equal — fewer pads than openings would leak witness
    /// information, more would waste degree.
    pub opened_count: usize,
    /// `N`: the number of evaluation points the commitment covers. The
    /// paper's trade-off knob, and nothing else.
    pub leaf_count: usize,
    /// Merkle arity. Only 2 gives `2*lambda`-bit nodes at `t = 8` (see
    /// `merkle::node_width`), so only 2 is safe here.
    pub arity: usize,
    /// `rho`: how many independent `Q_k` are formed. Each one is an
    /// independent `1/p` chance for a cheating prover, so this is the
    /// scheme's repetition count.
    pub combination_count: usize,
    /// `eta`: DECS's own masking polynomials.
    pub decs_mask_count: usize,
}

impl Parameters {
    /// A toy instance, sized so the whole test suite runs in seconds
    /// under `cargo test` (which builds without optimisation). Signing
    /// cost is dominated by hashing `N` leaves, so `N` is the knob.
    ///
    /// **Not a security level.** Roughly `2 * 64 = 128` bits from the
    /// challenge terms but only `log2(N / deg_q) * l' = 6` bits from the
    /// opening term, so a determined prover can cheat this instance.
    pub const fn testing() -> Parameters {
        Parameters {
            opened_count: 6,
            leaf_count: 256,
            arity: 2,
            combination_count: 2,
            decs_mask_count: 2,
        }
    }

    /// The instance the numbers in the README and the report are measured
    /// at. `N = 2^14` is the paper's "Short" trade-off from Table 2; the
    /// rest is chosen here.
    pub const fn level_128() -> Parameters {
        Parameters {
            opened_count: 20,
            leaf_count: 1 << 14,
            arity: 2,
            combination_count: 2,
            decs_mask_count: 2,
        }
    }

    /// `s`.
    pub fn columns(&self) -> usize {
        dimensions().columns
    }

    /// `l' + s - 1`, the degree of a row polynomial.
    pub fn input_degree(&self) -> usize {
        self.opened_count + self.columns() - 1
    }

    /// `deg_q = d * (l' + s - 1) + s`.
    pub fn q_degree(&self) -> usize {
        dimensions().degree as usize * self.input_degree() + self.columns()
    }

    /// The witness rows plus one mask per combination.
    pub fn polynomial_count(&self) -> usize {
        dimensions().rows + self.combination_count
    }

    /// Coefficients `l'..=deg_q` of each `Q_k`.
    pub fn sent_q_coefficients(&self) -> usize {
        self.q_degree() + 1 - self.opened_count
    }

    /// The DECS instance underneath.
    ///
    /// The degree bound is set by the *masks*, which are the
    /// highest-degree polynomials committed; the row polynomials sit far
    /// below it at `input_degree`. A faithful implementation would split
    /// each mask into `ceil((deg_q + 1) / (input_degree + 1))` chunks so
    /// that every committed polynomial shares the row bound — that is the
    /// paper's Brakedown-style "chunked and stacked" coefficient matrix.
    /// We do not, because it would multiply the leaf width and the
    /// signing cost by about eight, and in this composition the DECS
    /// degree bound is not load-bearing: DECS reconstructs exactly as many
    /// low coefficients as it opens points, so its reconstruction is
    /// self-consistent by construction and contributes no standalone
    /// check. This is a simplification, and it is called out in the report
    /// rather than hidden.
    pub fn decs(&self) -> decs::Parameters {
        decs::Parameters {
            polynomial_count: self.polynomial_count(),
            degree_bound: self.q_degree(),
            mask_count: self.decs_mask_count,
            leaf_count: self.leaf_count,
            opened_count: self.opened_count,
            arity: self.arity,
        }
    }
}

/// The proof. `salt` and `root` are the commitment, `q_high` is the PIOP
/// message, and `opening` is everything DECS sends.
#[derive(Clone, Debug)]
pub struct Proof {
    pub salt: Digest,
    pub root: Vec<Fp>,
    /// Coefficients `l'..=deg_q` of each `Q_k`, lowest first.
    pub q_high: Vec<Vec<Fp>>,
    pub opening: decs::Opening,
}

impl Proof {
    /// Serialised size at 8 bytes per field element.
    ///
    /// The opening's `indices` are not counted: the verifier re-derives
    /// them from the transcript and rejects if they disagree, so they are
    /// carried for inspection rather than transmitted.
    pub fn size_bytes(&self) -> usize {
        let element = 8;
        let high: usize = self.q_high.iter().map(|c| c.len()).sum::<usize>()
            + self.opening.high_coefficients.iter().map(|c| c.len()).sum::<usize>();
        let leaves: usize = self
            .opening
            .leaves
            .iter()
            .map(|leaf| leaf.polynomial_values.len() + leaf.mask_values.len())
            .sum();
        let paths: usize = self
            .opening
            .paths
            .iter()
            .map(|path| path.siblings.iter().map(|level| level.len()).sum::<usize>())
            .sum();
        (self.salt.len() + self.root.len() + high + leaves + paths) * element
    }
}

/// The points a row polynomial interpolates through: `Omega` first, then
/// `l'` points carrying randomness.
///
/// The pads sit immediately above `Omega` rather than anywhere else only
/// because they have to be somewhere; nothing depends on the choice
/// except that they be distinct from `Omega`.
fn interpolation_points(columns: usize, opened_count: usize) -> Vec<Fp> {
    (0..columns + opened_count).map(|index| Fp::new(index as u64)).collect()
}

fn omega_points(columns: usize) -> Vec<Fp> {
    (0..columns).map(|index| Fp::new(index as u64)).collect()
}

fn expand(domain: &[u8], seed: &Digest, index: usize, count: usize) -> Vec<Fp> {
    let mut input = seed.to_vec();
    input.push(Fp::new(index as u64));
    xof(domain, &input, count)
}

/// Lifts each witness row into a polynomial of degree `l' + s - 1`
/// (SmallWood Section 4.1's LVCS row encoding: witness values on `Omega`,
/// `l'` random points for zero knowledge).
fn row_polynomials(parameters: &Parameters, witness: &Matrix, seed: &Digest) -> Vec<Vec<Fp>> {
    let dimensions = dimensions();
    let points = interpolation_points(dimensions.columns, parameters.opened_count);

    (0..dimensions.rows)
        .map(|row| {
            let mut values: Vec<Fp> =
                (0..dimensions.columns).map(|column| witness.get(row, column)).collect();
            values.extend(expand(b"capss-piop-pad", seed, row, parameters.opened_count));
            interpolate(&points, &values).expect("interpolation points are distinct")
        })
        .collect()
}

/// Masks of degree `deg_q`, uniform subject to summing to zero over
/// `Omega` — SmallWood's `M_1..M_rho` with `sum_{omega} M_i(omega) = 0`
/// (Section 5.2, just above Eq. (10)).
fn mask_polynomials(parameters: &Parameters, seed: &Digest) -> Vec<Vec<Fp>> {
    let columns = parameters.columns();
    let scale = Fp::new(columns as u64).inverse().expect("s is far below p");

    (0..parameters.combination_count)
        .map(|k| {
            let mut coefficients = vec![Fp::ZERO];
            coefficients.extend(expand(b"capss-piop-mask", seed, k, parameters.q_degree()));
            let sum = omega_points(columns)
                .iter()
                .fold(Fp::ZERO, |total, point| total + evaluate(&coefficients, *point));
            coefficients[0] = -sum * scale;
            coefficients
        })
        .collect()
}

/// The round-independent part of `anemoi::affine_layer`.
///
/// The affine layer is `L(state + c_r)` for a round-constant vector
/// `c_r`, and `L` is linear, so it splits as `L(state) + L(c_r)`. The
/// PIOP needs the split because `L(state)` is the same at every column
/// while `L(c_r)` varies with the round and therefore has to travel as a
/// coefficient polynomial in `X`.
fn linear_part(state: &[Fp; STATE]) -> [Fp; STATE] {
    let base = anemoi::affine_layer(&[Fp::ZERO; STATE], 0);
    let shifted = anemoi::affine_layer(state, 0);
    let mut result = [Fp::ZERO; STATE];
    for (slot, (value, offset)) in result.iter_mut().zip(shifted.iter().zip(base.iter())) {
        *slot = *value - *offset;
    }
    result
}

/// `L(c_r)` for every packed round slot, as degree-`s-1` polynomials in
/// the column index.
fn round_constant_polynomials(columns: usize) -> Vec<Vec<Vec<Fp>>> {
    let points = omega_points(columns);
    (0..BATCHING)
        .map(|packed| {
            (0..STATE)
                .map(|position| {
                    let values: Vec<Fp> = (0..columns)
                        .map(|column| {
                            anemoi::affine_layer(
                                &[Fp::ZERO; STATE],
                                column * BATCHING + packed,
                            )[position]
                        })
                        .collect();
                    interpolate(&points, &values).expect("Omega has distinct points")
                })
                .collect()
        })
        .collect()
}

/// Everything public that goes into `Q_k`, ready to be evaluated at a
/// point.
///
/// Both sides build this identically — the prover to construct `Q_k` and
/// the verifier to recompute it at the opened points — so keeping it in
/// one place is what guarantees they agree.
struct Combination {
    /// `gamma_{k,j}(X)`, degree `s-1`.
    parallel: Vec<Vec<Vec<Fp>>>,
    /// The aggregated family collapsed into one coefficient polynomial
    /// per row, plus a constant polynomial holding the public-key terms.
    aggregated_rows: Vec<Vec<Vec<Fp>>>,
    aggregated_constant: Vec<Vec<Fp>>,
    round_constants: Vec<Vec<Vec<Fp>>>,
}

impl Combination {
    /// Squeezes the challenges and folds them into coefficient
    /// polynomials.
    fn draw(parameters: &Parameters, public: &PublicKey, transcript: &mut Transcript) -> Combination {
        let dimensions = dimensions();
        let columns = dimensions.columns;
        let points = omega_points(columns);
        let per_combination = dimensions.parallel * columns + dimensions.aggregated;
        let challenges = transcript.challenge_field_vec(
            b"capss-piop-gamma",
            parameters.combination_count * per_combination,
        );

        let mut parallel = Vec::with_capacity(parameters.combination_count);
        let mut aggregated_rows = Vec::with_capacity(parameters.combination_count);
        let mut aggregated_constant = Vec::with_capacity(parameters.combination_count);

        for chunk in challenges.chunks(per_combination) {
            let (parallel_part, aggregated_part) = chunk.split_at(dimensions.parallel * columns);

            parallel.push(
                parallel_part
                    .chunks(columns)
                    .map(|values| {
                        interpolate(&points, values).expect("Omega has distinct points")
                    })
                    .collect(),
            );

            let (rows, constant) = aggregated_coefficients(aggregated_part, public, columns);
            aggregated_rows.push(rows);
            aggregated_constant.push(constant);
        }

        Combination {
            parallel,
            aggregated_rows,
            aggregated_constant,
            round_constants: round_constant_polynomials(columns),
        }
    }

    /// `Q_k(point)` without its mask, given every row polynomial's value
    /// at that point.
    fn value_at(&self, k: usize, point: Fp, row_values: &[Fp]) -> Fp {
        let (beta, gamma, delta) = anemoi::flystel_constants();
        let pairs = STATE / 2;
        let mut total = Fp::ZERO;
        let mut constraint = 0;

        for packed in 0..BATCHING {
            let input: [Fp; STATE] = row_values[packed * STATE..(packed + 1) * STATE]
                .try_into()
                .expect("a column holds b+1 whole states");
            let output = &row_values[(packed + 1) * STATE..(packed + 2) * STATE];
            let linear = linear_part(&input);
            let constants = &self.round_constants[packed];

            for i in 0..pairs {
                // The closed Flystel of `pacs::round_constraints`, with the
                // round constants read off a polynomial instead of a table
                // because the round index is now the variable `X`.
                let a = linear[i] + evaluate(&constants[i], point);
                let b = linear[pairs + i] + evaluate(&constants[pairs + i], point);
                let (u, v) = (output[i], output[pairs + i]);
                let common = a - beta * b.square() - gamma;

                for value in [(b - v).pow(ALPHA) - common, u - beta * v.square() - delta - common] {
                    total = total + evaluate(&self.parallel[k][constraint], point) * value;
                    constraint += 1;
                }
            }
        }

        for (coefficients, value) in self.aggregated_rows[k].iter().zip(row_values) {
            total = total + evaluate(coefficients, point) * *value;
        }
        total + evaluate(&self.aggregated_constant[k], point)
    }
}

/// Turns the `m2` aggregated constraints into `sum_i c_i(X) P_i(X) + c(X)`.
///
/// Each aggregated constraint contributes to exactly one or two columns,
/// so the fold is a scatter over `Omega` followed by an interpolation.
/// Written out, the three families are the ones in
/// `pacs::aggregated_constraints`:
///
/// ```text
/// wiring   w[b*t+i][k] - w[i][k+1]      at columns k and k+1
/// iv bind  w[i][0] - iv_i               at column 0
/// y bind   w[b*t+i][s-1] - y_i          at column s-1
/// ```
fn aggregated_coefficients(
    challenges: &[Fp],
    public: &PublicKey,
    columns: usize,
) -> (Vec<Vec<Fp>>, Vec<Fp>) {
    let dimensions = dimensions();
    let points = omega_points(columns);
    let mut row_values = vec![vec![Fp::ZERO; columns]; dimensions.rows];
    let mut constant_values = vec![Fp::ZERO; columns];

    let mut next = challenges.iter();
    for column in 0..columns - 1 {
        for i in 0..STATE {
            let weight = *next.next().expect("one challenge per aggregated constraint");
            row_values[BATCHING * STATE + i][column] = row_values[BATCHING * STATE + i][column] + weight;
            row_values[i][column + 1] = row_values[i][column + 1] - weight;
        }
    }
    for (slot, pinned) in row_values.iter_mut().take(IV_SIZE).zip(&public.iv) {
        let weight = *next.next().expect("one challenge per aggregated constraint");
        slot[0] = slot[0] + weight;
        constant_values[0] = constant_values[0] - weight * *pinned;
    }
    for (slot, pinned) in
        row_values[BATCHING * STATE..].iter_mut().take(OUTPUT_SIZE).zip(&public.y)
    {
        let weight = *next.next().expect("one challenge per aggregated constraint");
        slot[columns - 1] = slot[columns - 1] + weight;
        constant_values[columns - 1] = constant_values[columns - 1] - weight * *pinned;
    }

    let rows = row_values
        .iter()
        .map(|values| interpolate(&points, values).expect("Omega has distinct points"))
        .collect();
    let constant = interpolate(&points, &constant_values).expect("Omega has distinct points");
    (rows, constant)
}

fn absorb_q(q_high: &[Vec<Fp>], transcript: &mut Transcript) {
    for (index, coefficients) in q_high.iter().enumerate() {
        transcript.absorb_field_slice(
            &[b"capss-piop-q-".as_slice(), &(index as u32).to_le_bytes()].concat(),
            coefficients,
        );
    }
}

/// Builds the proof.
///
/// `witness` is **not** checked against the constraints — a caller may
/// hand in a bogus one deliberately, which is how the "a wrong witness is
/// rejected" test works. `salt` and `seed` must be fresh and secret: the
/// seed expands into the row pads and the masks, which are the only
/// things hiding the witness.
pub fn prove(
    parameters: &Parameters,
    public: &PublicKey,
    witness: &Matrix,
    salt: Digest,
    seed: Digest,
    mask_seed: Digest,
    transcript: &mut Transcript,
) -> Proof {
    let dimensions = dimensions();
    assert_eq!(witness.rows(), dimensions.rows, "witness has the wrong height");
    assert_eq!(witness.columns(), dimensions.columns, "witness has the wrong width");

    let rows = row_polynomials(parameters, witness, &seed);
    let masks = mask_polynomials(parameters, &seed);
    let mut committed = rows.clone();
    committed.extend(masks.iter().cloned());

    let decs_parameters = parameters.decs();
    // `mask_seed` hides the committed polynomials inside the DECS batches;
    // it is drawn fresh by the caller, independent of the pad seed, so no
    // single secret is a single point of failure.
    let commitment = decs::Commitment::new(decs_parameters, &committed, salt, mask_seed);
    let root = commitment.root();

    // h2: the commitment, which fixes the challenges.
    let gammas = decs::challenge_gammas(&decs_parameters, &salt, &root, transcript);
    let combination = Combination::draw(parameters, public, transcript);

    // Q_k is built by evaluating the whole right-hand side at deg_q + 1
    // points and interpolating, rather than by multiplying polynomials
    // out. Same answer, and it reuses the very expression the verifier
    // runs at the opened points.
    let q_degree = parameters.q_degree();
    let points: Vec<Fp> = (0..=q_degree).map(|index| Fp::new(index as u64)).collect();
    let q_high: Vec<Vec<Fp>> = (0..parameters.combination_count)
        .map(|k| {
            let values: Vec<Fp> = points
                .iter()
                .map(|point| {
                    let row_values: Vec<Fp> =
                        rows.iter().map(|polynomial| evaluate(polynomial, *point)).collect();
                    combination.value_at(k, *point, &row_values) + evaluate(&masks[k], *point)
                })
                .collect();
            let q = interpolate(&points, &values).expect("the points are distinct");
            q[parameters.opened_count..].to_vec()
        })
        .collect();

    // h3: the PIOP message, then h4 and the opening indices inside DECS.
    absorb_q(&q_high, transcript);
    let opening = commitment.open(&gammas, transcript);

    Proof { salt, root, q_high, opening }
}

/// Checks a proof.
///
/// This is CAPSS Section 5.1's verification style: recompute the
/// transcript from the signature and compare, rather than check
/// constraints explicitly.
/// Note what is *not* here: the witness matrix is never rebuilt and
/// `pacs::constraints_are_satisfied` is never called. The verifier
/// replays the Fiat-Shamir chain, checks `l'` Merkle paths, evaluates the
/// constraint combination at those `l'` points only, and tests one
/// algebraic identity per `k`. That is the whole of it, and it is why the
/// R1CS encoding of this verifier is small: its cost is `l' * depth`
/// hash compressions plus a fixed amount of field arithmetic, not the
/// `m1 * s + m2` constraint evaluations a direct re-check would need.
pub fn verify(
    parameters: &Parameters,
    public: &PublicKey,
    proof: &Proof,
    transcript: &mut Transcript,
) -> bool {
    let dimensions = dimensions();
    let decs_parameters = parameters.decs();
    let opened = parameters.opened_count;

    if proof.root.len() != node_width(parameters.arity)
        || proof.q_high.len() != parameters.combination_count
        || proof.q_high.iter().any(|c| c.len() != parameters.sent_q_coefficients())
    {
        return false;
    }

    let gammas = decs::challenge_gammas(&decs_parameters, &proof.salt, &proof.root, transcript);
    let combination = Combination::draw(parameters, public, transcript);
    absorb_q(&proof.q_high, transcript);

    // Rejects a wrong root, a broken path, a tampered leaf, tampered DECS
    // coefficients, and any opening whose indices do not match the ones
    // the replayed transcript squeezes out.
    if decs::verify(
        &decs_parameters,
        &proof.salt,
        &proof.root,
        &gammas,
        &proof.opening,
        transcript,
    )
    .is_none()
    {
        return false;
    }

    let points: Vec<Fp> =
        proof.opening.indices.iter().map(|index| decs::evaluation_point(*index)).collect();
    let omega = omega_points(dimensions.columns);

    for (k, high) in proof.q_high.iter().enumerate() {
        let residuals: Vec<Fp> = proof
            .opening
            .leaves
            .iter()
            .zip(&points)
            .map(|(leaf, point)| {
                let row_values = &leaf.polynomial_values[..dimensions.rows];
                let mask = leaf.polynomial_values[dimensions.rows + k];
                let value = combination.value_at(k, *point, row_values) + mask;
                value - point.pow(opened as u64) * evaluate(high, *point)
            })
            .collect();

        let mut coefficients = match interpolate(&points, &residuals) {
            Some(low) => low,
            None => return false,
        };
        coefficients.resize(opened, Fp::ZERO);
        coefficients.extend_from_slice(high);

        let sum = omega
            .iter()
            .fold(Fp::ZERO, |total, point| total + evaluate(&coefficients, *point));
        if !sum.is_zero() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::P;
    use crate::keys;
    use crate::pacs;
    use crate::transcript::xof_digest;

    fn pseudorandom(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn key_pair(seed: &mut u64) -> (keys::KeyPair, Matrix) {
        let mut iv = [Fp::ZERO; IV_SIZE];
        let mut x = [Fp::ZERO; keys::SECRET_SIZE];
        for value in iv.iter_mut().chain(x.iter_mut()) {
            *value = Fp::new(pseudorandom(seed) % P);
        }
        (keys::from_parts(&iv, &x), pacs::secret_to_witness(&iv, &x))
    }

    fn digest(seed: u64) -> Digest {
        xof_digest(b"piop-test", &[Fp::new(seed)])
    }

    fn run(parameters: &Parameters, public: &PublicKey, witness: &Matrix, seed: u64) -> Proof {
        let mut transcript = Transcript::new(b"piop-test");
        prove(
            parameters,
            public,
            witness,
            digest(seed),
            digest(seed + 1),
            digest(seed + 2),
            &mut transcript,
        )
    }

    fn check(parameters: &Parameters, public: &PublicKey, proof: &Proof) -> bool {
        let mut transcript = Transcript::new(b"piop-test");
        verify(parameters, public, proof, &mut transcript)
    }

    #[test]
    fn decs_points_stay_outside_the_interpolation_domain() {
        // The row polynomials carry the witness at points 0..s and the ZK
        // pads at s..s+l'. A committed leaf landing on any of those points
        // would open a raw witness column — an earlier offset of 2 did
        // exactly that in ~1% of level_128 signatures. Every committed
        // point must clear the whole interpolation domain, for both
        // parameter sets.
        for parameters in [Parameters::testing(), Parameters::level_128()] {
            let points =
                interpolation_points(dimensions().columns, parameters.opened_count);
            let lowest_leaf_point = crate::decs::evaluation_point(0).value();
            assert!(points.iter().all(|point| point.value() < lowest_leaf_point));
        }
    }

    #[test]
    fn parameter_formulas_match_the_specification() {
        let parameters = Parameters::testing();
        let dimensions = dimensions();
        assert_eq!(parameters.columns(), dimensions.columns);
        assert_eq!(parameters.input_degree(), parameters.opened_count + dimensions.columns - 1);
        assert_eq!(
            parameters.q_degree(),
            dimensions.degree as usize * parameters.input_degree() + dimensions.columns
        );
        // The transmitted part plus the reconstructed part is all of Q_k.
        assert_eq!(
            parameters.sent_q_coefficients() + parameters.opened_count,
            parameters.q_degree() + 1
        );
        assert_eq!(parameters.polynomial_count(), dimensions.rows + parameters.combination_count);
    }

    #[test]
    fn the_affine_layer_splits_into_a_linear_map_and_round_constants() {
        // Everything in the PIOP's parallel constraint rests on this: if
        // the split were wrong the round constants would be applied at the
        // wrong place and an honest witness would fail its own identity.
        let mut seed = 40u64;
        for round in 0..crate::anemoi::ROUNDS {
            let mut state = [Fp::ZERO; STATE];
            for value in state.iter_mut() {
                *value = Fp::new(pseudorandom(&mut seed) % P);
            }
            let constants = anemoi::affine_layer(&[Fp::ZERO; STATE], round);
            let split = linear_part(&state);
            let expected = anemoi::affine_layer(&state, round);
            for i in 0..STATE {
                assert_eq!(split[i] + constants[i], expected[i], "round {round} position {i}");
            }
        }
    }

    #[test]
    fn the_constraint_polynomial_reproduces_the_pacs_constraints_on_omega() {
        // The bridge between this module and `pacs`. At omega the row
        // polynomials take the witness values, so `value_at` must come out
        // as the same random linear combination `pacs` would give.
        let parameters = Parameters::testing();
        let mut seed = 41u64;
        let (pair, witness) = key_pair(&mut seed);

        let mut transcript = Transcript::new(b"combination-test");
        let combination = Combination::draw(&parameters, &pair.public, &mut transcript);

        for column in 0..parameters.columns() {
            let point = Fp::new(column as u64);
            let row_values: Vec<Fp> =
                (0..dimensions().rows).map(|row| witness.get(row, column)).collect();
            let parallel = pacs::parallel_constraints(&witness, column);
            for k in 0..parameters.combination_count {
                let value = combination.value_at(k, point, &row_values);
                let expected: Fp = parallel
                    .iter()
                    .enumerate()
                    .fold(Fp::ZERO, |total, (j, constraint)| {
                        total + evaluate(&combination.parallel[k][j], point) * *constraint
                    })
                    + combination.aggregated_rows[k]
                        .iter()
                        .zip(&row_values)
                        .fold(Fp::ZERO, |total, (c, w)| total + evaluate(c, point) * *w)
                    + evaluate(&combination.aggregated_constant[k], point);
                assert_eq!(value, expected);
            }
        }
    }

    #[test]
    fn the_aggregated_family_sums_to_the_weighted_pacs_constraints() {
        // Aggregated constraints are only required to sum to zero across
        // columns, so the fold has to reproduce exactly that sum — not the
        // per-column values, which are meaningless on their own.
        let parameters = Parameters::testing();
        let mut seed = 42u64;
        let (pair, witness) = key_pair(&mut seed);
        let columns = parameters.columns();

        let mut transcript = Transcript::new(b"aggregated-test");
        let weights = transcript.challenge_field_vec(b"w", dimensions().aggregated);
        let (rows, constant) = aggregated_coefficients(&weights, &pair.public, columns);

        let mut total = Fp::ZERO;
        for column in 0..columns {
            let point = Fp::new(column as u64);
            for (row, coefficients) in rows.iter().enumerate() {
                total = total + evaluate(coefficients, point) * witness.get(row, column);
            }
            total = total + evaluate(&constant, point);
        }

        let expected = pacs::aggregated_constraints(&witness, &pair.public)
            .iter()
            .zip(&weights)
            .fold(Fp::ZERO, |sum, (value, weight)| sum + *value * *weight);
        assert_eq!(total, expected);
        assert!(total.is_zero(), "an honest witness makes every aggregated constraint vanish");
    }

    #[test]
    fn masks_sum_to_zero_over_omega_and_are_full_degree() {
        let parameters = Parameters::testing();
        let masks = mask_polynomials(&parameters, &digest(7));
        for mask in &masks {
            assert_eq!(mask.len(), parameters.q_degree() + 1);
            let sum = omega_points(parameters.columns())
                .iter()
                .fold(Fp::ZERO, |total, point| total + evaluate(mask, *point));
            assert!(sum.is_zero(), "a mask that shifts the sum would break the check");
        }
        assert_ne!(masks[0], masks[1], "each combination needs its own mask");
        assert_ne!(masks, mask_polynomials(&parameters, &digest(8)));
    }

    #[test]
    fn row_polynomials_carry_the_witness_and_randomise_everywhere_else() {
        let parameters = Parameters::testing();
        let mut seed = 43u64;
        let (_, witness) = key_pair(&mut seed);
        let rows = row_polynomials(&parameters, &witness, &digest(9));

        assert_eq!(rows.len(), dimensions().rows);
        for (row, polynomial) in rows.iter().enumerate() {
            assert_eq!(polynomial.len(), parameters.input_degree() + 1);
            for column in 0..parameters.columns() {
                assert_eq!(evaluate(polynomial, Fp::new(column as u64)), witness.get(row, column));
            }
        }

        // The pads are what make the opened points carry no witness
        // information, so a different seed must move them.
        let other = row_polynomials(&parameters, &witness, &digest(10));
        assert_ne!(rows, other);
        for (first, second) in rows.iter().zip(&other) {
            for column in 0..parameters.columns() {
                let point = Fp::new(column as u64);
                assert_eq!(evaluate(first, point), evaluate(second, point));
            }
        }
    }

    #[test]
    fn an_honest_proof_verifies() {
        let parameters = Parameters::testing();
        let mut seed = 44u64;
        for _ in 0..3 {
            let (pair, witness) = key_pair(&mut seed);
            let proof = run(&parameters, &pair.public, &witness, seed);
            assert!(check(&parameters, &pair.public, &proof));
        }
    }

    #[test]
    fn a_witness_that_breaks_the_constraints_is_rejected() {
        // The test that says the proof system proves something. Each
        // corruption keeps the matrix well formed and only breaks the
        // arithmetization, so nothing but the PIOP identity can catch it.
        let parameters = Parameters::testing();
        let mut seed = 45u64;
        let (pair, witness) = key_pair(&mut seed);
        assert!(pacs::constraints_are_satisfied(&witness, &pair.public));

        for (row, column) in [(0usize, 0usize), (7, 5), (15, 10), (8, 3), (3, 7)] {
            let mut forged = witness.clone();
            forged.set(row, column, forged.get(row, column) + Fp::ONE);
            assert!(!pacs::constraints_are_satisfied(&forged, &pair.public));

            let proof = run(&parameters, &pair.public, &forged, seed);
            assert!(
                !check(&parameters, &pair.public, &proof),
                "a proof from a witness broken at ({row}, {column}) must not verify"
            );
        }
    }

    #[test]
    fn a_witness_for_another_key_is_rejected() {
        let parameters = Parameters::testing();
        let mut seed = 46u64;
        let (first, witness) = key_pair(&mut seed);
        let (second, _) = key_pair(&mut seed);

        let proof = run(&parameters, &first.public, &witness, seed);
        assert!(check(&parameters, &first.public, &proof));
        assert!(!check(&parameters, &second.public, &proof));
    }

    #[test]
    fn tampering_with_any_proof_component_is_caught() {
        let parameters = Parameters::testing();
        let mut seed = 47u64;
        let (pair, witness) = key_pair(&mut seed);
        let proof = run(&parameters, &pair.public, &witness, seed);
        assert!(check(&parameters, &pair.public, &proof));

        let mut tampered = proof.clone();
        tampered.root[0] = tampered.root[0] + Fp::ONE;
        assert!(!check(&parameters, &pair.public, &tampered));

        let mut tampered = proof.clone();
        tampered.salt[0] = tampered.salt[0] + Fp::ONE;
        assert!(!check(&parameters, &pair.public, &tampered));

        let mut tampered = proof.clone();
        tampered.q_high[0][0] = tampered.q_high[0][0] + Fp::ONE;
        assert!(!check(&parameters, &pair.public, &tampered));

        let mut tampered = proof.clone();
        let last = tampered.q_high[1].len() - 1;
        tampered.q_high[1][last] = tampered.q_high[1][last] + Fp::ONE;
        assert!(!check(&parameters, &pair.public, &tampered));

        let mut tampered = proof.clone();
        tampered.opening.leaves[0].polynomial_values[0] =
            tampered.opening.leaves[0].polynomial_values[0] + Fp::ONE;
        assert!(!check(&parameters, &pair.public, &tampered));

        let mut tampered = proof.clone();
        tampered.opening.leaves[1].mask_values[0] =
            tampered.opening.leaves[1].mask_values[0] + Fp::ONE;
        assert!(!check(&parameters, &pair.public, &tampered));

        let mut tampered = proof.clone();
        tampered.opening.high_coefficients[0][0] =
            tampered.opening.high_coefficients[0][0] + Fp::ONE;
        assert!(!check(&parameters, &pair.public, &tampered));

        let mut tampered = proof.clone();
        tampered.opening.paths[0].siblings[0][0] =
            tampered.opening.paths[0].siblings[0][0] + Fp::ONE;
        assert!(!check(&parameters, &pair.public, &tampered));

        let mut tampered = proof.clone();
        tampered.opening.indices[0] = (tampered.opening.indices[0] + 1) % parameters.leaf_count;
        assert!(!check(&parameters, &pair.public, &tampered));

        // Malformed shapes must be refused rather than panic.
        let mut tampered = proof.clone();
        tampered.q_high[0].pop();
        assert!(!check(&parameters, &pair.public, &tampered));
        let mut tampered = proof.clone();
        tampered.root.pop();
        assert!(!check(&parameters, &pair.public, &tampered));
        let mut tampered = proof.clone();
        tampered.opening.leaves.pop();
        assert!(!check(&parameters, &pair.public, &tampered));
    }

    #[test]
    fn the_sum_to_zero_check_is_what_rejects() {
        // Pins down *which* check does the work. Reconstruct Q_k the way
        // the verifier does, from an honest proof and from a forged one,
        // and show the honest sum vanishes while the forged one does not
        // — so the failure above is the PIOP identity and not, say, a
        // Merkle path that happened to break.
        let parameters = Parameters::testing();
        let mut seed = 48u64;
        let (pair, witness) = key_pair(&mut seed);
        let mut forged = witness.clone();
        forged.set(4, 6, forged.get(4, 6) + Fp::ONE);

        for (matrix, expected) in [(&witness, true), (&forged, false)] {
            let proof = run(&parameters, &pair.public, matrix, seed);
            let mut transcript = Transcript::new(b"piop-test");
            let decs_parameters = parameters.decs();
            let gammas = decs::challenge_gammas(
                &decs_parameters,
                &proof.salt,
                &proof.root,
                &mut transcript,
            );
            let combination = Combination::draw(&parameters, &pair.public, &mut transcript);
            absorb_q(&proof.q_high, &mut transcript);
            assert!(decs::verify(
                &decs_parameters,
                &proof.salt,
                &proof.root,
                &gammas,
                &proof.opening,
                &mut transcript
            )
            .is_some());

            let points: Vec<Fp> = proof
                .opening
                .indices
                .iter()
                .map(|index| decs::evaluation_point(*index))
                .collect();
            for (k, high) in proof.q_high.iter().enumerate() {
                let residuals: Vec<Fp> = proof
                    .opening
                    .leaves
                    .iter()
                    .zip(&points)
                    .map(|(leaf, point)| {
                        let rows = &leaf.polynomial_values[..dimensions().rows];
                        let mask = leaf.polynomial_values[dimensions().rows + k];
                        combination.value_at(k, *point, rows) + mask
                            - point.pow(parameters.opened_count as u64) * evaluate(high, *point)
                    })
                    .collect();
                let mut coefficients = interpolate(&points, &residuals).unwrap();
                coefficients.resize(parameters.opened_count, Fp::ZERO);
                coefficients.extend_from_slice(high);
                let sum = omega_points(parameters.columns())
                    .iter()
                    .fold(Fp::ZERO, |total, point| total + evaluate(&coefficients, *point));
                assert_eq!(sum.is_zero(), expected, "combination {k}");
            }
        }
    }

    #[test]
    fn a_proof_does_not_replay_under_a_different_transcript() {
        let parameters = Parameters::testing();
        let mut seed = 49u64;
        let (pair, witness) = key_pair(&mut seed);
        let proof = run(&parameters, &pair.public, &witness, seed);

        let mut transcript = Transcript::new(b"a-different-context");
        assert!(!verify(&parameters, &pair.public, &proof, &mut transcript));
    }
}
