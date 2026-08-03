//! DECS — the degree-enforcing commitment scheme, the bottom layer of the
//! SmallWood stack CAPSS is built on (`notes/capss-spec.md`, section 3.2).
//!
//! A plain Merkle commitment to `N` evaluations says nothing about the
//! degree of the polynomial those evaluations came from. DECS adds that
//! guarantee, and does it without a second commitment:
//!
//! ```text
//! 1. sample eta masking polynomials M_1..M_eta of degree d_decs
//! 2. leaf u_i  = XOF(salt_i, P_1(e_i)..P_n(e_i), M_1(e_i)..M_eta(e_i))
//! 3. root      = MerkleTree(u_1..u_N),  h_mt = XOF(salt, root)
//! 4. gamma_k   = XOF(h_mt)                                    eta elements
//! 5. R_k(X)    = M_k(X) + sum_i gamma_k^i * P_i(X)            powers batching
//! ```
//!
//! `R_k` is a random linear combination of the committed polynomials,
//! hidden by a fresh mask, and it is *sent*. Because the prover fixes the
//! `gamma`s from the Merkle root before seeing them, the only way a
//! degree-`d_decs` `R_k` can agree with the committed evaluations
//! everywhere is for the committed polynomials to have been degree
//! `d_decs` too — Schwartz-Zippel over the `gamma`s does the rest. Note
//! the batching uses *powers* of a single `gamma_k`, not `eta * n`
//! independent coefficients; that is one of the four SNARK-friendliness
//! tweaks in section 4.4 of the paper, and it is why `gamma_k^i` appears
//! rather than `gamma_{k,i}`.
//!
//! ## The compression that saves the bytes
//!
//! Only the **high `d_decs + 1 - l` coefficients** of each `R_k` are sent.
//! The verifier learns `R_k` at the `l` opened points — every ingredient
//! of `R_k(e_j)` is in the opened leaf — subtracts the known high part,
//! and interpolates the remaining degree-`< l` polynomial through those
//! `l` points. So the low coefficients cost nothing to transmit.
//!
//! Worth being precise about what this does to the argument. Those `l`
//! evaluation equations are no longer *checks*: reconstruction makes them
//! hold by definition. What they become is a fingerprint. A prover who
//! committed something of degree above `d_decs` cannot make one degree-
//! `d_decs` polynomial match at all `N` points, so the polynomial the
//! verifier reconstructs depends on *which* `l` points were opened — and
//! the layers above DECS then use that reconstructed `R_k`, where the
//! discrepancy surfaces. `degree_enforcement_catches_an_over_degree_
//! polynomial` below demonstrates exactly this.
//!
//! ## Polynomials
//!
//! Coefficients lowest-degree first, as in `loquat/src/poly.rs`.
//! Evaluation is Horner and interpolation is Lagrange via the master
//! polynomial, both `O(l^2)` — no FFT. Goldilocks has 2-adicity 32 so an
//! FFT is available, but DECS interpolates through `l` points where `l` is
//! a few dozen, and the points `e_i = i + 1` are consecutive integers, not
//! a multiplicative coset, so an FFT would not apply without changing the
//! evaluation domain the paper specifies.

use crate::field::Fp;
use crate::merkle::{node_width, MerklePath, MerkleTree};
use crate::transcript::{xof, Digest, Transcript};

#[derive(Clone, Copy, Debug)]
pub struct Parameters {
    /// `n_decs`, the number of committed polynomials.
    pub polynomial_count: usize,
    /// `d_decs`, the degree every committed polynomial must respect.
    pub degree_bound: usize,
    /// `eta`, the number of masking polynomials and of batched `R_k`.
    pub mask_count: usize,
    /// `N`, the number of evaluation points and Merkle leaves.
    pub leaf_count: usize,
    /// `l`, the number of leaves opened.
    pub opened_count: usize,
    pub arity: usize,
}

impl Parameters {
    fn check(&self) {
        assert!(self.polynomial_count > 0, "nothing to commit to");
        assert!(self.mask_count > 0, "DECS needs at least one mask");
        assert!(self.opened_count > 0, "an opening of nothing enforces nothing");
        assert!(
            self.opened_count <= self.degree_bound + 1,
            "cannot reconstruct more low coefficients than R_k has"
        );
        assert!(self.opened_count <= self.leaf_count, "cannot open more leaves than exist");
        // Without spare points there is no redundancy for the degree bound
        // to bite on: any evaluation vector of length N is consistent with
        // some polynomial of degree N - 1.
        assert!(
            self.degree_bound < self.leaf_count,
            "degree bound must be below the number of evaluation points"
        );
    }

    /// Number of `R_k` coefficients actually transmitted.
    pub fn sent_coefficient_count(&self) -> usize {
        self.degree_bound + 1 - self.opened_count
    }
}

/// The evaluation points. The spec writes `e_i = i + 1` for `i` in
/// `1..=N`, so the zero-based leaf `j` sits at `j + 2`. The point of the
/// offset is that neither 0 nor 1 is an evaluation point — the layers
/// above DECS evaluate there.
pub fn evaluation_point(leaf_index: usize) -> Fp {
    Fp::new(leaf_index as u64 + 2)
}

/// What one opened leaf reveals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafOpening {
    pub polynomial_values: Vec<Fp>,
    pub mask_values: Vec<Fp>,
}

/// Everything the prover sends.
#[derive(Clone, Debug)]
pub struct Opening {
    /// Coefficients `l..=d_decs` of each `R_k`, lowest first.
    pub high_coefficients: Vec<Vec<Fp>>,
    /// Re-derived by the verifier; carried so a caller can inspect the
    /// opening on its own, and checked rather than trusted.
    pub indices: Vec<usize>,
    pub leaves: Vec<LeafOpening>,
    pub paths: Vec<MerklePath>,
}

pub struct Commitment {
    parameters: Parameters,
    salt: Digest,
    polynomials: Vec<Vec<Fp>>,
    masks: Vec<Vec<Fp>>,
    tree: MerkleTree,
}

impl Commitment {
    /// Steps 1-3. Pure: no transcript, because the root has to exist
    /// before the Fiat-Shamir chain can absorb it.
    ///
    /// `mask_seed` must be secret and freshly random — the masks are the
    /// only thing hiding the committed polynomials in `R_k`, and they are
    /// expanded from this seed with the XOF. Expanding rather than
    /// sampling directly is deliberate: the permutation is already the
    /// scheme's only assumption, so it may as well be the PRG too.
    pub fn new(
        parameters: Parameters,
        polynomials: &[Vec<Fp>],
        salt: Digest,
        mask_seed: Digest,
    ) -> Commitment {
        assert!(
            polynomials.iter().all(|p| p.len() <= parameters.degree_bound + 1),
            "an honest prover never commits above the degree bound"
        );
        Commitment::new_unchecked(parameters, polynomials, salt, mask_seed)
    }

    /// The same, with the degree assertion dropped so a cheating prover
    /// can be modelled. Nothing outside the tests should call this.
    fn new_unchecked(
        parameters: Parameters,
        polynomials: &[Vec<Fp>],
        salt: Digest,
        mask_seed: Digest,
    ) -> Commitment {
        parameters.check();
        assert_eq!(polynomials.len(), parameters.polynomial_count, "wrong number of polynomials");

        let mask_length = parameters.degree_bound + 1;
        let expanded = xof(b"capss-decs-mask", &mask_seed, parameters.mask_count * mask_length);
        let masks: Vec<Vec<Fp>> = expanded.chunks(mask_length).map(|c| c.to_vec()).collect();

        let width = node_width(parameters.arity);
        let leaves: Vec<Vec<Fp>> = (0..parameters.leaf_count)
            .map(|index| {
                let point = evaluation_point(index);
                let mut input = salt.to_vec();
                // The leaf index is bound in as well, which is what the
                // spec's per-leaf salt_i achieves: two leaves carrying the
                // same values still hash differently.
                input.push(Fp::new(index as u64));
                input.extend(polynomials.iter().map(|p| evaluate(p, point)));
                input.extend(masks.iter().map(|m| evaluate(m, point)));
                xof(b"capss-decs-leaf", &input, width)
            })
            .collect();

        let tree = MerkleTree::build(&leaves, parameters.arity);
        Commitment {
            parameters,
            salt,
            polynomials: polynomials.to_vec(),
            masks,
            tree,
        }
    }

    pub fn root(&self) -> Vec<Fp> {
        self.tree.root()
    }

    pub fn salt(&self) -> Digest {
        self.salt
    }

    /// Step 5 and the opening. `gammas` must be the output of
    /// [`challenge_gammas`] for this root.
    ///
    /// In the full protocol the opening indices come from `h4`, after `Q`
    /// and the message have also been absorbed. Here they follow directly
    /// from `R`; a caller building the whole scheme should absorb its own
    /// `h3`/`h4` material into `transcript` before calling this, which is
    /// sound for the same reason — the indices are drawn strictly after
    /// the high coefficients are committed.
    pub fn open(&self, gammas: &[Fp], transcript: &mut Transcript) -> Opening {
        let parameters = self.parameters;
        assert_eq!(gammas.len(), parameters.mask_count, "one gamma per mask");

        let batched = self.batched_polynomials(gammas);
        let high_coefficients: Vec<Vec<Fp>> =
            batched.iter().map(|r| r[parameters.opened_count..].to_vec()).collect();

        absorb_high_coefficients(&high_coefficients, transcript);
        let indices = transcript.challenge_distinct_indices(
            b"capss-decs-open",
            parameters.opened_count,
            parameters.leaf_count,
        );

        let leaves = indices
            .iter()
            .map(|index| {
                let point = evaluation_point(*index);
                LeafOpening {
                    polynomial_values: self.polynomials.iter().map(|p| evaluate(p, point)).collect(),
                    mask_values: self.masks.iter().map(|m| evaluate(m, point)).collect(),
                }
            })
            .collect();
        let paths = indices.iter().map(|index| self.tree.open(*index)).collect();

        Opening { high_coefficients, indices, leaves, paths }
    }

    /// `R_k(X) = M_k(X) + sum_i gamma_k^i * P_i(X)`, padded to exactly
    /// `d_decs + 1` coefficients.
    ///
    /// The padding is where a cheating prover's excess degree gets
    /// silently dropped: coefficients above `d_decs` simply have nowhere
    /// to go in the message, which is the whole mechanism this scheme
    /// relies on.
    fn batched_polynomials(&self, gammas: &[Fp]) -> Vec<Vec<Fp>> {
        gammas
            .iter()
            .zip(&self.masks)
            .map(|(gamma, mask)| {
                let mut batched = vec![Fp::ZERO; self.parameters.degree_bound + 1];
                for (slot, value) in batched.iter_mut().zip(mask) {
                    *slot = *slot + *value;
                }
                let mut power = *gamma;
                for polynomial in &self.polynomials {
                    for (slot, value) in batched.iter_mut().zip(polynomial) {
                        *slot = *slot + power * *value;
                    }
                    power = power * *gamma;
                }
                batched
            })
            .collect()
    }
}

/// Steps 3-4: `h_mt = XOF(salt, root)` then `gamma_k = XOF(h_mt)`.
///
/// The transcript *is* the XOF, so absorbing and squeezing is that chain
/// written out; the running state carries the role of `h_mt`.
pub fn challenge_gammas(
    parameters: &Parameters,
    salt: &Digest,
    root: &[Fp],
    transcript: &mut Transcript,
) -> Vec<Fp> {
    transcript.absorb_field_slice(b"capss-decs-salt", salt);
    transcript.absorb_field_slice(b"capss-decs-root", root);
    transcript.challenge_field_vec(b"capss-decs-gamma", parameters.mask_count)
}

fn absorb_high_coefficients(high_coefficients: &[Vec<Fp>], transcript: &mut Transcript) {
    for (index, coefficients) in high_coefficients.iter().enumerate() {
        transcript.absorb_field_slice(
            &[b"capss-decs-high-".as_slice(), &(index as u32).to_le_bytes()].concat(),
            coefficients,
        );
    }
}

/// Checks an opening and returns the reconstructed `R_k` polynomials,
/// each with exactly `d_decs + 1` coefficients.
///
/// The return value is the useful output, not a bare `bool`: the layers
/// above DECS consume these polynomials, and a caller that only wants a
/// yes/no answer can test for `Some`.
pub fn verify(
    parameters: &Parameters,
    salt: &Digest,
    root: &[Fp],
    gammas: &[Fp],
    opening: &Opening,
    transcript: &mut Transcript,
) -> Option<Vec<Vec<Fp>>> {
    let opened = parameters.opened_count;
    if opening.high_coefficients.len() != parameters.mask_count
        || gammas.len() != parameters.mask_count
        || opening.leaves.len() != opened
        || opening.paths.len() != opened
        || opening.indices.len() != opened
    {
        return None;
    }
    if opening
        .high_coefficients
        .iter()
        .any(|c| c.len() != parameters.sent_coefficient_count())
    {
        return None;
    }

    absorb_high_coefficients(&opening.high_coefficients, transcript);
    let indices = transcript.challenge_distinct_indices(
        b"capss-decs-open",
        opened,
        parameters.leaf_count,
    );
    if indices != opening.indices {
        return None;
    }

    let width = node_width(parameters.arity);
    let mut points = Vec::with_capacity(opened);
    for (position, index) in indices.iter().enumerate() {
        let leaf = &opening.leaves[position];
        if leaf.polynomial_values.len() != parameters.polynomial_count
            || leaf.mask_values.len() != parameters.mask_count
        {
            return None;
        }

        let mut input = salt.to_vec();
        input.push(Fp::new(*index as u64));
        input.extend_from_slice(&leaf.polynomial_values);
        input.extend_from_slice(&leaf.mask_values);
        let recomputed = xof(b"capss-decs-leaf", &input, width);

        if !crate::merkle::verify(
            root,
            &recomputed,
            *index,
            &opening.paths[position],
            parameters.arity,
        ) {
            return None;
        }
        points.push(evaluation_point(*index));
    }

    let mut reconstructed = Vec::with_capacity(parameters.mask_count);
    for (k, high) in opening.high_coefficients.iter().enumerate() {
        // R_k(e_j) is recomputable from the opened leaf; subtracting the
        // transmitted high part leaves a polynomial of degree < l, which
        // l points pin down uniquely.
        let residuals: Vec<Fp> = opening
            .leaves
            .iter()
            .zip(&points)
            .map(|(leaf, point)| {
                let mut value = leaf.mask_values[k];
                let mut power = gammas[k];
                for evaluation in &leaf.polynomial_values {
                    value = value + power * *evaluation;
                    power = power * gammas[k];
                }
                value - point.pow(opened as u64) * evaluate(high, *point)
            })
            .collect();

        let mut coefficients = interpolate(&points, &residuals)?;
        coefficients.resize(opened, Fp::ZERO);
        coefficients.extend_from_slice(high);
        reconstructed.push(coefficients);
    }
    Some(reconstructed)
}

/// Horner evaluation.
pub fn evaluate(coefficients: &[Fp], x: Fp) -> Fp {
    coefficients.iter().rev().fold(Fp::ZERO, |result, coefficient| result * x + *coefficient)
}

/// Lagrange interpolation through distinct points, returning coefficients
/// lowest-degree first.
///
/// Built from the master polynomial `Z(X) = prod_j (X - x_j)`: dividing
/// `Z` by `(X - x_j)` by synthetic division gives the `j`-th basis
/// numerator in `O(n)`, so the whole thing is `O(n^2)` rather than the
/// `O(n^3)` of multiplying each basis polynomial out from scratch.
/// `None` if two points coincide.
pub fn interpolate(points: &[Fp], values: &[Fp]) -> Option<Vec<Fp>> {
    assert_eq!(points.len(), values.len(), "one value per point");
    let count = points.len();
    if count == 0 {
        return Some(Vec::new());
    }

    let mut master = vec![Fp::ZERO; count + 1];
    master[0] = Fp::ONE;
    for (degree, point) in points.iter().enumerate() {
        for index in (1..=degree + 1).rev() {
            master[index] = master[index - 1] - *point * master[index];
        }
        master[0] = -*point * master[0];
    }

    let mut result = vec![Fp::ZERO; count];
    for (j, point) in points.iter().enumerate() {
        // Synthetic division of `master` by (X - point).
        let mut basis = vec![Fp::ZERO; count];
        basis[count - 1] = master[count];
        for index in (0..count - 1).rev() {
            basis[index] = master[index + 1] + *point * basis[index + 1];
        }
        let scale = (values[j] * evaluate(&basis, *point).inverse()?).value();
        for (slot, coefficient) in result.iter_mut().zip(&basis) {
            *slot = *slot + Fp::new(scale) * *coefficient;
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::xof_digest;

    const PARAMETERS: Parameters = Parameters {
        polynomial_count: 3,
        degree_bound: 8,
        mask_count: 2,
        leaf_count: 16,
        opened_count: 4,
        arity: 2,
    };

    fn sample_polynomials(parameters: &Parameters, seed: u64, extra_degree: usize) -> Vec<Vec<Fp>> {
        (0..parameters.polynomial_count)
            .map(|i| {
                xof(
                    b"decs-test-polynomial",
                    &[Fp::new(seed), Fp::new(i as u64)],
                    parameters.degree_bound + 1 + extra_degree,
                )
            })
            .collect()
    }

    fn salt(seed: u64) -> Digest {
        xof_digest(b"decs-test-salt", &[Fp::new(seed)])
    }

    /// What one prover/verifier exchange produces: the root, the opening,
    /// the verifier's reconstruction of `R_k` (absent if it rejected), and
    /// the prover's own `R_k` to compare against.
    type Exchange = (Vec<Fp>, Opening, Option<Vec<Vec<Fp>>>, Vec<Vec<Fp>>);

    /// One full prover/verifier exchange. `nonce` stands in for the `h3`
    /// and `h4` material of the real Fiat-Shamir chain: it changes the
    /// opening indices without touching the root or the gammas, which is
    /// what the degree test needs.
    fn exchange(parameters: &Parameters, polynomials: &[Vec<Fp>], nonce: &[u8]) -> Exchange {
        let commitment =
            Commitment::new_unchecked(*parameters, polynomials, salt(1), salt(2));
        let root = commitment.root();

        let mut prover = Transcript::new(b"decs-test");
        let gammas = challenge_gammas(parameters, &commitment.salt(), &root, &mut prover);
        prover.absorb_bytes(b"nonce", nonce);
        let opening = commitment.open(&gammas, &mut prover);

        let mut verifier = Transcript::new(b"decs-test");
        let verifier_gammas =
            challenge_gammas(parameters, &commitment.salt(), &root, &mut verifier);
        assert_eq!(verifier_gammas, gammas, "both sides must derive the same gammas");
        verifier.absorb_bytes(b"nonce", nonce);
        let reconstructed = verify(
            parameters,
            &commitment.salt(),
            &root,
            &verifier_gammas,
            &opening,
            &mut verifier,
        );

        (root, opening, reconstructed, commitment.batched_polynomials(&gammas))
    }

    fn verify_tampered(
        parameters: &Parameters,
        root: &[Fp],
        opening: &Opening,
        nonce: &[u8],
    ) -> Option<Vec<Vec<Fp>>> {
        let mut verifier = Transcript::new(b"decs-test");
        let gammas = challenge_gammas(parameters, &salt(1), root, &mut verifier);
        verifier.absorb_bytes(b"nonce", nonce);
        verify(parameters, &salt(1), root, &gammas, opening, &mut verifier)
    }

    #[test]
    fn horner_and_interpolation_are_inverse() {
        let points: Vec<Fp> = (2..10u64).map(Fp::new).collect();
        let polynomial = xof(b"poly", &[Fp::new(3)], points.len());
        let values: Vec<Fp> = points.iter().map(|x| evaluate(&polynomial, *x)).collect();
        assert_eq!(interpolate(&points, &values).unwrap(), polynomial);

        // Repeated points have no unique interpolant.
        assert!(interpolate(&[Fp::new(2), Fp::new(2)], &[Fp::ONE, Fp::ZERO]).is_none());
        // A constant is the degree-zero case.
        assert_eq!(interpolate(&[Fp::new(5)], &[Fp::new(9)]).unwrap(), vec![Fp::new(9)]);
    }

    #[test]
    fn honest_commitment_opens_and_verifies() {
        let polynomials = sample_polynomials(&PARAMETERS, 10, 0);
        let (_, opening, reconstructed, batched) = exchange(&PARAMETERS, &polynomials, b"A");

        let reconstructed = reconstructed.expect("an honest opening must verify");
        assert_eq!(reconstructed, batched, "R_k must be recovered exactly");
        assert!(reconstructed.iter().all(|r| r.len() == PARAMETERS.degree_bound + 1));
        // Only the high coefficients travel; the rest come back for free.
        assert_eq!(opening.high_coefficients[0].len(), PARAMETERS.sent_coefficient_count());
        assert_eq!(PARAMETERS.sent_coefficient_count(), 5);
        assert_eq!(opening.indices.len(), PARAMETERS.opened_count);
    }

    #[test]
    fn verification_works_at_other_parameter_sets() {
        for parameters in [
            Parameters { opened_count: 1, ..PARAMETERS },
            // l = d + 1: nothing is transmitted at all.
            Parameters { opened_count: 9, ..PARAMETERS },
            Parameters { mask_count: 1, polynomial_count: 1, ..PARAMETERS },
            Parameters { arity: 4, leaf_count: 64, ..PARAMETERS },
            Parameters { arity: 8, leaf_count: 64, degree_bound: 20, opened_count: 6, ..PARAMETERS },
        ] {
            let polynomials = sample_polynomials(&parameters, 11, 0);
            let (_, opening, reconstructed, batched) = exchange(&parameters, &polynomials, b"A");
            assert_eq!(
                reconstructed.as_ref(),
                Some(&batched),
                "arity={} l={}",
                parameters.arity,
                parameters.opened_count
            );
            assert_eq!(
                opening.high_coefficients[0].len(),
                parameters.sent_coefficient_count()
            );
        }
    }

    #[test]
    fn degree_enforcement_catches_an_over_degree_polynomial() {
        // The single most important test here. One committed polynomial
        // has degree d_decs + 1, so the true R_k does too — but only
        // coefficients up to d_decs can be transmitted, and the verifier
        // reconstructs the low ones from whichever l points were opened.
        let parameters = PARAMETERS;
        let mut polynomials = sample_polynomials(&parameters, 12, 0);
        polynomials[1].push(Fp::new(7));
        assert_eq!(polynomials[1].len(), parameters.degree_bound + 2);

        let (root, opening, first, _) = exchange(&parameters, &polynomials, b"A");
        let (_, _, second, _) = exchange(&parameters, &polynomials, b"B");
        let first = first.expect("the Merkle and transcript checks still pass");
        let second = second.expect("the Merkle and transcript checks still pass");

        // The opening challenge must actually have moved, or this proves
        // nothing.
        let (_, other_opening, _, _) = exchange(&parameters, &polynomials, b"B");
        assert_ne!(opening.indices, other_opening.indices);

        assert_ne!(
            first, second,
            "an over-degree commitment must reconstruct differently per opening"
        );

        // And the stronger statement: the reconstructed R_k does not agree
        // with what was committed at the points that were not opened.
        let mut verifier = Transcript::new(b"decs-test");
        let gammas = challenge_gammas(&parameters, &salt(1), &root, &mut verifier);
        let masks = {
            let commitment =
                Commitment::new_unchecked(parameters, &polynomials, salt(1), salt(2));
            commitment.masks.clone()
        };
        let mut disagreements = 0;
        for leaf in 0..parameters.leaf_count {
            let point = evaluation_point(leaf);
            for k in 0..parameters.mask_count {
                let mut committed = evaluate(&masks[k], point);
                let mut power = gammas[k];
                for polynomial in &polynomials {
                    committed = committed + power * evaluate(polynomial, point);
                    power = power * gammas[k];
                }
                if evaluate(&first[k], point) != committed {
                    disagreements += 1;
                }
            }
        }
        assert_eq!(
            disagreements,
            parameters.mask_count * (parameters.leaf_count - parameters.opened_count),
            "R_k should match exactly at the opened points and nowhere else"
        );

        // The honest case, for contrast: zero disagreements.
        let honest = sample_polynomials(&parameters, 12, 0);
        let (honest_root, _, honest_reconstructed, _) = exchange(&parameters, &honest, b"A");
        let honest_reconstructed = honest_reconstructed.unwrap();
        let mut verifier = Transcript::new(b"decs-test");
        let honest_gammas =
            challenge_gammas(&parameters, &salt(1), &honest_root, &mut verifier);
        let honest_masks =
            Commitment::new_unchecked(parameters, &honest, salt(1), salt(2)).masks.clone();
        for leaf in 0..parameters.leaf_count {
            let point = evaluation_point(leaf);
            for k in 0..parameters.mask_count {
                let mut committed = evaluate(&honest_masks[k], point);
                let mut power = honest_gammas[k];
                for polynomial in &honest {
                    committed = committed + power * evaluate(polynomial, point);
                    power = power * honest_gammas[k];
                }
                assert_eq!(evaluate(&honest_reconstructed[k], point), committed);
            }
        }
    }

    #[test]
    fn tampered_leaf_values_are_rejected() {
        let polynomials = sample_polynomials(&PARAMETERS, 13, 0);
        let (root, opening, _, _) = exchange(&PARAMETERS, &polynomials, b"A");

        let mut tampered = opening.clone();
        tampered.leaves[2].polynomial_values[0] = tampered.leaves[2].polynomial_values[0] + Fp::ONE;
        assert!(verify_tampered(&PARAMETERS, &root, &tampered, b"A").is_none());

        let mut tampered = opening.clone();
        tampered.leaves[0].mask_values[0] = tampered.leaves[0].mask_values[0] + Fp::ONE;
        assert!(verify_tampered(&PARAMETERS, &root, &tampered, b"A").is_none());
    }

    #[test]
    fn tampered_paths_indices_and_root_are_rejected() {
        let polynomials = sample_polynomials(&PARAMETERS, 14, 0);
        let (root, opening, _, _) = exchange(&PARAMETERS, &polynomials, b"A");
        assert!(verify_tampered(&PARAMETERS, &root, &opening, b"A").is_some());

        let mut tampered = opening.clone();
        tampered.paths[1].siblings[0][0] = tampered.paths[1].siblings[0][0] + Fp::ONE;
        assert!(verify_tampered(&PARAMETERS, &root, &tampered, b"A").is_none());

        // Claiming a different index for an opened leaf.
        let mut tampered = opening.clone();
        tampered.indices[0] = (tampered.indices[0] + 1) % PARAMETERS.leaf_count;
        assert!(verify_tampered(&PARAMETERS, &root, &tampered, b"A").is_none());

        // Swapping two opened leaves keeps the index set but breaks the
        // pairing between index and value.
        let mut tampered = opening.clone();
        tampered.leaves.swap(0, 1);
        assert!(verify_tampered(&PARAMETERS, &root, &tampered, b"A").is_none());

        let mut wrong_root = root.clone();
        wrong_root[0] = wrong_root[0] + Fp::ONE;
        assert!(verify_tampered(&PARAMETERS, &wrong_root, &opening, b"A").is_none());

        // Replaying an opening against a different challenge.
        assert!(verify_tampered(&PARAMETERS, &root, &opening, b"B").is_none());
    }

    #[test]
    fn tampered_high_coefficients_are_rejected() {
        // The high coefficients are absorbed before the opening indices
        // are drawn, so changing them moves the challenge and the sent
        // indices no longer match.
        let polynomials = sample_polynomials(&PARAMETERS, 15, 0);
        let (root, opening, _, _) = exchange(&PARAMETERS, &polynomials, b"A");

        let mut tampered = opening.clone();
        tampered.high_coefficients[0][0] = tampered.high_coefficients[0][0] + Fp::ONE;
        assert!(verify_tampered(&PARAMETERS, &root, &tampered, b"A").is_none());

        // Malformed shapes must be refused, not panic.
        let mut tampered = opening.clone();
        tampered.high_coefficients[1].pop();
        assert!(verify_tampered(&PARAMETERS, &root, &tampered, b"A").is_none());
        let mut tampered = opening.clone();
        tampered.leaves.pop();
        assert!(verify_tampered(&PARAMETERS, &root, &tampered, b"A").is_none());
    }

    #[test]
    fn masks_hide_the_committed_polynomials() {
        // Two different mask seeds must give different R_k, otherwise the
        // batched polynomial would leak the witness directly.
        let parameters = PARAMETERS;
        let polynomials = sample_polynomials(&parameters, 16, 0);
        let first = Commitment::new(parameters, &polynomials, salt(1), salt(2));
        let second = Commitment::new(parameters, &polynomials, salt(1), salt(3));
        assert_ne!(first.masks, second.masks);
        assert_ne!(first.root(), second.root(), "the masks are committed too");

        let gammas = vec![Fp::new(5), Fp::new(9)];
        assert_ne!(first.batched_polynomials(&gammas), second.batched_polynomials(&gammas));
        assert!(first.masks.iter().all(|m| m.len() == parameters.degree_bound + 1));
    }

    #[test]
    fn powers_batching_uses_one_gamma_per_mask() {
        // R_k = M_k + sum_i gamma_k^i P_i, checked directly against the
        // definition rather than against the implementation's loop.
        let parameters = PARAMETERS;
        let polynomials = sample_polynomials(&parameters, 17, 0);
        let commitment = Commitment::new(parameters, &polynomials, salt(1), salt(2));
        let gammas = vec![Fp::new(11), Fp::new(13)];
        let batched = commitment.batched_polynomials(&gammas);

        for (k, gamma) in gammas.iter().enumerate() {
            for point in [Fp::new(2), Fp::new(37), Fp::new(1 << 40)] {
                let mut expected = evaluate(&commitment.masks[k], point);
                for (i, polynomial) in polynomials.iter().enumerate() {
                    expected = expected + gamma.pow(i as u64 + 1) * evaluate(polynomial, point);
                }
                assert_eq!(evaluate(&batched[k], point), expected);
            }
        }
    }
}
