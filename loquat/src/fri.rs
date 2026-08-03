//! FRI: the low-degree test.
//!
//! FRI answers "is this list of values really the evaluations of a
//! low-degree polynomial?" without reading all of it. Each round folds the
//! domain by `2^eta`, halving-and-halving the degree along with it, until
//! what is left is small enough to send outright.
//!
//! The fold: group the domain into fibers of `2^eta` points that all map
//! to the same point one level down, interpolate the (tiny) polynomial
//! through them, and evaluate it at a verifier-chosen challenge. A genuine
//! low-degree polynomial folds consistently no matter which challenge is
//! picked; a codeword that is far from low-degree does not, and each query
//! catches it with constant probability.

use crate::field::Fp2;
use crate::merkle::{verify_with_cap, MerklePath, MerkleTree};
use crate::params::Params;
use crate::poly::{evaluate_at, interpolate_over_coset};
use crate::transcript::{hash_fp2_slice, Hash, Transcript};

#[derive(Clone, Debug)]
pub struct LayerOpening {
    /// The queried fiber, minus anything the verifier can rebuild itself.
    /// Round 0 carries all `2^eta` values; from round 1 on, one slot is
    /// already fixed by the previous round's fold, so it is left out and
    /// the verifier puts it back before checking the leaf.
    pub coset_values: Vec<Fp2>,
    pub path: MerklePath,
}

#[derive(Clone, Debug)]
pub struct Query {
    /// One opening per committed layer.
    pub layers: Vec<LayerOpening>,
}

#[derive(Clone, Debug)]
pub struct Proof {
    pub roots: Vec<Hash>,
    pub caps: Vec<Vec<Hash>>,
    /// Coefficients of the final, fully folded polynomial.
    pub final_coefficients: Vec<Fp2>,
    pub queries: Vec<Query>,
}

impl Proof {
    pub fn size_bytes(&self, _params: &Params) -> usize {
        let per_query: usize = self
            .queries
            .first()
            .map(|q| {
                q.layers
                    .iter()
                    .map(|layer| layer.coset_values.len() * 32 + layer.path.siblings.len() * 32)
                    .sum()
            })
            .unwrap_or(0);
        self.roots.len() * 32
            + self.caps.iter().map(|c| c.len() * 32).sum::<usize>()
            + self.final_coefficients.len() * 32
            + self.queries.len() * per_query
    }
}

/// Groups a codeword into Merkle leaves, one per fiber.
///
/// Fiber `k` of a domain of size `n` is `{k, k + n/f, k + 2n/f, ...}`,
/// because those are exactly the points sharing the same `x^f`.
fn leaves_for(codeword: &[Fp2], fiber: usize) -> Vec<Hash> {
    let n = codeword.len();
    let count = n / fiber;
    (0..count)
        .map(|k| {
            let values: Vec<Fp2> = (0..fiber).map(|t| codeword[k + t * count]).collect();
            hash_fp2_slice(b"fri-leaf", &values)
        })
        .collect()
}

fn fiber_values(codeword: &[Fp2], fiber: usize, k: usize) -> Vec<Fp2> {
    let count = codeword.len() / fiber;
    (0..fiber).map(|t| codeword[k + t * count]).collect()
}

/// Folds one layer into the next using the round challenge.
fn fold(params: &Params, codeword: &[Fp2], challenge: Fp2, log_size: u32) -> Vec<Fp2> {
    let fiber = 1usize << params.eta;
    let n = codeword.len();
    let count = n / fiber;
    let generator = crate::field::subgroup_generator(log_size);

    (0..count)
        .map(|k| {
            // The fiber is the coset `w^k * <w^count>`, so interpolating it
            // is a size-`fiber` inverse FFT on that coset.
            let values = fiber_values(codeword, fiber, k);
            let shift = generator.pow(k as u128);
            let coefficients = interpolate_over_coset(&values, shift, params.eta);
            evaluate_at(&coefficients, challenge)
        })
        .collect()
}

/// Runs the commit-and-fold phase, then answers the sampled queries.
///
/// Also returns the sampled fiber indices, because the caller needs to
/// open its own commitments at exactly the same positions.
pub fn prove(
    params: &Params,
    codeword: Vec<Fp2>,
    transcript: &mut Transcript,
) -> (Proof, Vec<usize>) {
    let fiber = 1usize << params.eta;
    let mut layers: Vec<Vec<Fp2>> = vec![codeword];
    let mut trees: Vec<MerkleTree> = Vec::new();
    let mut roots: Vec<Hash> = Vec::new();
    let mut caps: Vec<Vec<Hash>> = Vec::new();

    for round in 0..params.rounds {
        let current = layers.last().unwrap().clone();
        let tree = MerkleTree::build(leaves_for(&current, fiber), params.cap_log);
        let root = tree.root();
        transcript.absorb_hash(b"fri-root", &root);
        roots.push(root);
        caps.push(tree.cap().to_vec());
        trees.push(tree);

        let challenge = transcript.challenge_fp2(b"fri-fold");
        let log_size = params.u_log - params.eta * round as u32;
        layers.push(fold(params, &current, challenge, log_size));
    }

    // The last layer is small enough to send in the clear.
    let final_layer = layers.last().unwrap();
    let final_log = params.u_log - params.eta * params.rounds as u32;
    let mut final_coefficients = interpolate_over_coset(final_layer, Fp2::ONE, final_log);
    let degree_bound = params.rate_numerator * final_layer.len() / params.u_size;
    final_coefficients.truncate(degree_bound.max(1));
    transcript.absorb_fp2_slice(b"fri-final", &final_coefficients);

    // Queries pick fibers of the *first* layer; each one determines a
    // position in every later layer.
    let indices = transcript.challenge_indices(b"fri-query", params.kappa, params.u_size / fiber);

    let queries = indices
        .iter()
        .map(|start| {
            let mut position = *start;
            let mut openings = Vec::with_capacity(params.rounds);
            for round in 0..params.rounds {
                let codeword = &layers[round];
                let count = codeword.len() / fiber;
                let k = position % count;
                let mut values = fiber_values(codeword, fiber, k);
                if round > 0 {
                    // `position` is the previous layer's fiber index, so it
                    // is also the index *within this layer* of that fiber's
                    // folded value. Dropping it costs nothing: the verifier
                    // recomputes the fold anyway.
                    values.remove(position / count);
                }
                openings.push(LayerOpening { coset_values: values, path: trees[round].open(k) });
                position = k;
            }
            Query { layers: openings }
        })
        .collect();

    (Proof { roots, caps, final_coefficients, queries }, indices)
}

/// Replays the folding and checks every layer agrees.
///
/// Returns the layer-0 fiber openings so the caller can cross-check them
/// against whatever it expected the batched codeword to be — in Loquat
/// that link is what ties the FRI to the sumcheck codewords.
pub fn verify(
    params: &Params,
    proof: &Proof,
    transcript: &mut Transcript,
) -> Option<Vec<(usize, Vec<Fp2>)>> {
    let fiber = 1usize << params.eta;
    if proof.roots.len() != params.rounds || proof.caps.len() != params.rounds {
        return None;
    }

    // Replay the transcript to recover the same challenges the prover used.
    let mut challenges = Vec::with_capacity(params.rounds);
    for round in 0..params.rounds {
        if crate::transcript::hash_many(b"cap", &proof.caps[round]) != proof.roots[round] {
            return None;
        }
        transcript.absorb_hash(b"fri-root", &proof.roots[round]);
        challenges.push(transcript.challenge_fp2(b"fri-fold"));
    }
    transcript.absorb_fp2_slice(b"fri-final", &proof.final_coefficients);
    let indices = transcript.challenge_indices(b"fri-query", params.kappa, params.u_size / fiber);

    if proof.queries.len() != params.kappa {
        return None;
    }

    let final_log = params.u_log - params.eta * params.rounds as u32;
    let final_generator = crate::field::subgroup_generator(final_log);
    let mut layer0 = Vec::with_capacity(params.kappa);

    for (query, start) in proof.queries.iter().zip(indices.iter()) {
        if query.layers.len() != params.rounds {
            return None;
        }

        let mut position = *start;
        let mut carried: Option<Fp2> = None;

        for (round, (opening, challenge)) in query.layers.iter().zip(challenges.iter()).enumerate() {
            let size = params.domain_size_at(round);
            let count = size / fiber;
            let k = position % count;

            // From round 1 on, one value in this fiber is already pinned
            // down by the previous fold, so the prover omits it and we
            // rebuild it. Putting it back *before* the leaf hash is what
            // keeps the chain of layers binding: a fold that disagrees with
            // what the prover committed to produces a different leaf, and
            // the Merkle check fails.
            let coset_values = match carried {
                Some(expected) => {
                    let slot = position / count;
                    if opening.coset_values.len() + 1 != fiber || slot >= fiber {
                        return None;
                    }
                    let mut values = opening.coset_values.clone();
                    values.insert(slot, expected);
                    values
                }
                None => {
                    if opening.coset_values.len() != fiber {
                        return None;
                    }
                    opening.coset_values.clone()
                }
            };

            // The opening must be a genuine leaf of this layer's tree.
            let leaf = hash_fp2_slice(b"fri-leaf", &coset_values);
            if !verify_with_cap(&proof.caps[round], leaf, k, &opening.path) {
                return None;
            }

            if round == 0 {
                layer0.push((k, coset_values.clone()));
            }

            let log_size = params.u_log - params.eta * round as u32;
            let generator = crate::field::subgroup_generator(log_size);
            let shift = generator.pow(k as u128);
            let coefficients = interpolate_over_coset(&coset_values, shift, params.eta);
            carried = Some(evaluate_at(&coefficients, *challenge));
            position = k;
        }

        // Finally, the folded value must match the polynomial that was
        // sent in the clear.
        let expected = carried?;
        let point = final_generator.pow((position % params.domain_size_at(params.rounds)) as u128);
        if evaluate_at(&proof.final_coefficients, point) != expected {
            return None;
        }
    }

    Some(layer0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fp;
    use crate::poly::evaluate_over_coset;

    fn low_degree_codeword(params: &Params, degree: usize) -> Vec<Fp2> {
        let coefficients: Vec<Fp2> = (0..degree)
            .map(|i| Fp2::new(Fp::new(i as u128 * 31 + 7), Fp::new(i as u128 * 17 + 3)))
            .collect();
        evaluate_over_coset(&coefficients, Fp2::ONE, params.u_log)
    }

    #[test]
    fn honest_low_degree_codeword_passes() {
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (proof, _) = prove(&params, codeword, &mut prover_transcript);

        let mut verifier_transcript = Transcript::new(b"fri-test");
        assert!(verify(&params, &proof, &mut verifier_transcript).is_some());
    }

    #[test]
    fn high_degree_codeword_is_rejected() {
        // The whole point of FRI: a polynomial above the degree bound must
        // not pass, even though it is a perfectly valid polynomial.
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.u_size);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (proof, _) = prove(&params, codeword, &mut prover_transcript);

        let mut verifier_transcript = Transcript::new(b"fri-test");
        assert!(verify(&params, &proof, &mut verifier_transcript).is_none());
    }

    #[test]
    fn random_codeword_is_rejected() {
        let params = Params::testing();
        let codeword: Vec<Fp2> = (0..params.u_size)
            .map(|i| Fp2::new(Fp::new((i as u128).wrapping_mul(6364136223846793005)), Fp::new(i as u128)))
            .collect();

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (proof, _) = prove(&params, codeword, &mut prover_transcript);

        let mut verifier_transcript = Transcript::new(b"fri-test");
        assert!(verify(&params, &proof, &mut verifier_transcript).is_none());
    }

    #[test]
    fn tampered_final_coefficients_are_rejected() {
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (mut proof, _) = prove(&params, codeword, &mut prover_transcript);
        proof.final_coefficients[0] = proof.final_coefficients[0] + Fp2::ONE;

        let mut verifier_transcript = Transcript::new(b"fri-test");
        assert!(verify(&params, &proof, &mut verifier_transcript).is_none());
    }

    #[test]
    fn tampered_query_value_is_rejected() {
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (mut proof, _) = prove(&params, codeword, &mut prover_transcript);
        proof.queries[0].layers[0].coset_values[0] =
            proof.queries[0].layers[0].coset_values[0] + Fp2::ONE;

        let mut verifier_transcript = Transcript::new(b"fri-test");
        assert!(verify(&params, &proof, &mut verifier_transcript).is_none());
    }

    #[test]
    fn later_rounds_omit_the_value_the_fold_determines() {
        let params = Params::testing();
        let fiber = 1usize << params.eta;
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (proof, _) = prove(&params, codeword, &mut prover_transcript);

        let layers = &proof.queries[0].layers;
        assert_eq!(layers[0].coset_values.len(), fiber);
        for later in &layers[1..] {
            assert_eq!(later.coset_values.len(), fiber - 1);
        }
    }

    #[test]
    fn a_reinstated_full_fiber_is_rejected() {
        // A prover who sends the omitted value back would shift every other
        // value one slot along, so the reconstructed fiber — and its leaf —
        // would no longer be the one that was committed to.
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (mut proof, _) = prove(&params, codeword, &mut prover_transcript);
        proof.queries[0].layers[1].coset_values.push(Fp2::ONE);

        let mut verifier_transcript = Transcript::new(b"fri-test");
        assert!(verify(&params, &proof, &mut verifier_transcript).is_none());
    }

    #[test]
    fn the_reconstructed_value_must_land_in_its_own_slot() {
        // Rotating the values that *are* sent keeps the same multiset but
        // drops the reconstructed one into a different place. The leaf hash
        // covers the fiber in order, so this must be caught — which is what
        // shows the verifier rebuilds the exact fiber the prover committed
        // to rather than merely some permutation of it.
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (mut proof, _) = prove(&params, codeword, &mut prover_transcript);
        proof.queries[0].layers[1].coset_values.rotate_left(1);

        let mut verifier_transcript = Transcript::new(b"fri-test");
        assert!(verify(&params, &proof, &mut verifier_transcript).is_none());
    }

    #[test]
    fn tampering_a_later_round_opening_is_rejected() {
        // Before the omission this was caught by comparing the carried
        // value against the opening; now the leaf hash is the only thing
        // holding it, so it is worth testing on its own.
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (mut proof, _) = prove(&params, codeword, &mut prover_transcript);
        proof.queries[0].layers[1].coset_values[0] =
            proof.queries[0].layers[1].coset_values[0] + Fp2::ONE;

        let mut verifier_transcript = Transcript::new(b"fri-test");
        assert!(verify(&params, &proof, &mut verifier_transcript).is_none());
    }

    #[test]
    fn wrong_transcript_is_rejected() {
        // Fiat-Shamir binding: challenges must depend on the transcript.
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (proof, _) = prove(&params, codeword, &mut prover_transcript);

        let mut verifier_transcript = Transcript::new(b"different-domain");
        assert!(verify(&params, &proof, &mut verifier_transcript).is_none());
    }
}
