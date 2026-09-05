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
//!
//! Reference: FRI is Ben-Sasson, Bentov, Horesh, Riabzev (ICALP 2018), the
//! paper's [8]. This module implements the paper's Algorithm 6 (Sign Part
//! III: Phase 6 folding, Phase 7 query) and the LDT side of Algorithm 7,
//! with one documented deviation: layer 0 is virtual (see `Proof`), where
//! the paper ships `rootf^(0)`.

use crate::field::Fp2;
use crate::merkle::{verify_with_cap, MerklePath, MerkleTree};
use crate::params::Params;
use crate::poly::{evaluate_at, interpolate_over_coset};
use crate::transcript::{hash_fp2_slice, Hash, Transcript};

#[derive(Clone, Debug)]
pub struct LayerOpening {
    /// The queried fiber, minus the one slot the previous round's fold
    /// already fixes — the verifier reinserts that before hashing.
    pub coset_values: Vec<Fp2>,
    pub path: MerklePath,
}

#[derive(Clone, Debug)]
pub struct Query {
    /// One opening per *committed* layer — that is rounds 1 onward.
    /// Layer 0 is virtual: see the note on `Proof`.
    pub layers: Vec<LayerOpening>,
}

/// A FRI proof over a **virtual first layer**.
///
/// The layer-0 codeword is never committed here. In Loquat it is a public
/// linear combination of oracles that were each Merkle-committed *before*
/// any challenge was drawn (`c`, `s`, `h`), so a separate commitment to
/// the combination adds bytes but no binding. The verifier computes the
/// layer-0 values at the queried positions from those openings, folds
/// them, and checks the result against layer 1's commitment — which is how
/// production FRI deployments (Fractal, Plonky2, Winterfell) handle their
/// composition polynomial. The Loquat paper itself ships `rootf^(0)`; this
/// is a deliberate, documented deviation that saves ~6.7 KB per signature.
#[derive(Clone, Debug)]
pub struct Proof {
    /// Roots of layers 1 .. rounds-1.
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
///
/// Paper Alg. 6, Phase 6: interpolate `P_y` through each fiber `S_y` and
/// evaluate it at the round challenge `x^(i)`.
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
        // Layer 0 is virtual — it is already pinned by the commitments the
        // caller absorbed before reaching here, so the first challenge can
        // be drawn with nothing new to absorb. Layers produced by folding
        // are fresh and must be committed before their challenge.
        if round > 0 {
            let current = layers.last().unwrap();
            let tree = MerkleTree::build(leaves_for(current, fiber), params.cap_log);
            let root = tree.root();
            transcript.absorb_hash(b"fri-root", &root);
            roots.push(root);
            caps.push(tree.cap().to_vec());
            trees.push(tree);
        }

        let current = layers.last().unwrap().clone();
        let challenge = transcript.challenge_fp2(b"fri-fold");
        let log_size = params.u_log - params.eta * round as u32;
        layers.push(fold(params, &current, challenge, log_size));
    }

    // The last layer is small enough to send in the clear. Paper Alg. 6
    // lines 13-14: only the first d + 1 = rho* * |U^(r)| coefficients.
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
            // Round 0 contributes nothing to the proof: its values are
            // computed by the verifier from the constituent oracles, and
            // there is no tree to open. Openings start at round 1.
            let mut position = *start;
            let mut openings = Vec::with_capacity(params.rounds.saturating_sub(1));
            for round in 1..params.rounds {
                let codeword = &layers[round];
                let count = codeword.len() / fiber;
                let k = position % count;
                let mut values = fiber_values(codeword, fiber, k);
                // `position` is the previous layer's fiber index, so it is
                // also the index *within this layer* of that fiber's folded
                // value. Dropping it costs nothing: the verifier recomputes
                // the fold anyway.
                values.remove(position / count);
                openings.push(LayerOpening {
                    coset_values: values,
                    path: trees[round - 1].open(k),
                });
                position = k;
            }
            Query { layers: openings }
        })
        .collect();

    (Proof { roots, caps, final_coefficients, queries }, indices)
}

/// The challenges and query positions a proof commits to, recovered by
/// replaying the Fiat-Shamir transcript.
///
/// Verification is split in two because of who knows what: the layer-0
/// codeword is never sent — in Loquat it is the batched combination of the
/// sumcheck oracles, which only the caller can evaluate — but the caller
/// cannot evaluate it at the right positions until the transcript has been
/// replayed to reveal them. So `replay_transcript` first, compute the
/// layer-0 fibers at `plan.indices`, then `check_queries`.
pub struct QueryPlan {
    pub challenges: Vec<Fp2>,
    pub indices: Vec<usize>,
}

/// Phase one: check the commitments hash together, replay the transcript,
/// and recover the fold challenges and query positions.
pub fn replay_transcript(
    params: &Params,
    proof: &Proof,
    transcript: &mut Transcript,
) -> Option<QueryPlan> {
    let fiber = 1usize << params.eta;
    if proof.roots.len() + 1 != params.rounds || proof.caps.len() + 1 != params.rounds {
        return None;
    }

    // The degree bound is the whole point of FRI, and the final polynomial
    // is where it is enforced: the honest prover truncates to this length,
    // and a verifier that accepts more coefficients accepts *any* function
    // on the final domain — every fold check then passes vacuously and the
    // low-degree test proves nothing. This is the paper's d = rho* *
    // |U^(r)| - 1 bound from Alg. 6 line 13.
    let final_size = params.domain_size_at(params.rounds);
    let final_bound = (params.rate_numerator * final_size / params.u_size).max(1);
    if proof.final_coefficients.len() > final_bound {
        return None;
    }

    let mut challenges = Vec::with_capacity(params.rounds);
    // The first fold challenge absorbs nothing new: layer 0 is a public
    // combination of oracles whose roots the caller already absorbed, so
    // everything it depends on is in the transcript by the time we get
    // here. Committing it again would add bytes, not binding.
    challenges.push(transcript.challenge_fp2(b"fri-fold"));
    for round in 1..params.rounds {
        let committed = round - 1;
        // The cap width is a parameter; a prover-chosen width would let the
        // proof describe a differently-shaped tree than the one committed.
        if proof.caps[committed].len() != 1usize << params.cap_log {
            return None;
        }
        if crate::transcript::hash_many(b"cap", &proof.caps[committed]) != proof.roots[committed] {
            return None;
        }
        transcript.absorb_hash(b"fri-root", &proof.roots[committed]);
        challenges.push(transcript.challenge_fp2(b"fri-fold"));
    }
    transcript.absorb_fp2_slice(b"fri-final", &proof.final_coefficients);
    let indices = transcript.challenge_indices(b"fri-query", params.kappa, params.u_size / fiber);

    if proof.queries.len() != params.kappa {
        return None;
    }

    Some(QueryPlan { challenges, indices })
}

/// Phase two: check every query against the committed layers.
///
/// `layer0_values[q]` must be the full fiber of the layer-0 codeword at
/// position `plan.indices[q]`, computed by the caller. Layer 0 has no
/// Merkle check of its own — its binding is that the caller derived these
/// values from openings of oracles committed before any challenge was
/// drawn. What holds the chain together is the fold: these values must
/// fold into what layer 1 committed to, and so on down to the final
/// polynomial sent in the clear.
pub fn check_queries(
    params: &Params,
    proof: &Proof,
    plan: &QueryPlan,
    layer0_values: &[Vec<Fp2>],
) -> bool {
    let fiber = 1usize << params.eta;
    if layer0_values.len() != params.kappa {
        return false;
    }

    let final_log = params.u_log - params.eta * params.rounds as u32;
    let final_generator = crate::field::subgroup_generator(final_log);

    for ((query, start), supplied) in
        proof.queries.iter().zip(plan.indices.iter()).zip(layer0_values.iter())
    {
        if query.layers.len() + 1 != params.rounds || supplied.len() != fiber {
            return false;
        }

        // Round 0: fold the virtual fiber the caller computed.
        let mut position = *start % (params.u_size / fiber);
        let generator = crate::field::subgroup_generator(params.u_log);
        let shift = generator.pow(position as u128);
        let coefficients = interpolate_over_coset(supplied, shift, params.eta);
        let mut carried = evaluate_at(&coefficients, plan.challenges[0]);

        for (round, (opening, challenge)) in
            query.layers.iter().zip(plan.challenges[1..].iter()).enumerate()
        {
            let round = round + 1;
            let size = params.domain_size_at(round);
            let count = size / fiber;
            let k = position % count;

            // One slot of this fiber is the previous round's fold, so it
            // never travelled; rebuild it *before* the leaf hash. Values
            // that disagree with what was committed produce a different
            // leaf, and the Merkle check fails — that is what makes the
            // chain of layers binding.
            let slot = position / count;
            // Pin the path to this round's real tree depth: `count` leaves
            // minus the cap layers. Any other length describes a tree of a
            // different shape than the one the parameters commit to.
            let expected_depth = (count.ilog2() - params.cap_log) as usize;
            if opening.coset_values.len() + 1 != fiber
                || slot >= fiber
                || opening.path.siblings.len() != expected_depth
            {
                return false;
            }
            let mut coset_values = opening.coset_values.clone();
            coset_values.insert(slot, carried);

            // The opening must be a genuine leaf of this layer's tree.
            let leaf = hash_fp2_slice(b"fri-leaf", &coset_values);
            if !verify_with_cap(&proof.caps[round - 1], leaf, k, &opening.path) {
                return false;
            }

            let log_size = params.u_log - params.eta * round as u32;
            let generator = crate::field::subgroup_generator(log_size);
            let shift = generator.pow(k as u128);
            let coefficients = interpolate_over_coset(&coset_values, shift, params.eta);
            carried = evaluate_at(&coefficients, *challenge);
            position = k;
        }

        // Finally, the folded value must match the polynomial that was
        // sent in the clear.
        let point = final_generator.pow((position % params.domain_size_at(params.rounds)) as u128);
        if evaluate_at(&proof.final_coefficients, point) != carried {
            return false;
        }
    }

    true
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

    /// Runs both verification phases the way a real caller would: replay
    /// the transcript, evaluate the layer-0 codeword at the revealed
    /// positions, then check the queries.
    fn run_verify(params: &Params, proof: &Proof, domain: &[u8], codeword: &[Fp2]) -> bool {
        let mut transcript = Transcript::new(domain);
        match replay_transcript(params, proof, &mut transcript) {
            Some(plan) => {
                let fiber = 1usize << params.eta;
                let layer0: Vec<Vec<Fp2>> =
                    plan.indices.iter().map(|k| fiber_values(codeword, fiber, *k)).collect();
                check_queries(params, proof, &plan, &layer0)
            }
            None => false,
        }
    }

    #[test]
    fn honest_low_degree_codeword_passes() {
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (proof, _) = prove(&params, codeword.clone(), &mut prover_transcript);

        assert!(run_verify(&params, &proof, b"fri-test", &codeword));
    }

    #[test]
    fn high_degree_codeword_is_rejected() {
        // The whole point of FRI: a polynomial above the degree bound must
        // not pass, even though it is a perfectly valid polynomial.
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.u_size);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (proof, _) = prove(&params, codeword.clone(), &mut prover_transcript);

        assert!(!run_verify(&params, &proof, b"fri-test", &codeword));
    }

    #[test]
    fn random_codeword_is_rejected() {
        let params = Params::testing();
        let codeword: Vec<Fp2> = (0..params.u_size)
            .map(|i| Fp2::new(Fp::new((i as u128).wrapping_mul(6364136223846793005)), Fp::new(i as u128)))
            .collect();

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (proof, _) = prove(&params, codeword.clone(), &mut prover_transcript);

        assert!(!run_verify(&params, &proof, b"fri-test", &codeword));
    }

    #[test]
    fn tampered_final_coefficients_are_rejected() {
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (mut proof, _) = prove(&params, codeword.clone(), &mut prover_transcript);
        proof.final_coefficients[0] = proof.final_coefficients[0] + Fp2::ONE;

        assert!(!run_verify(&params, &proof, b"fri-test", &codeword));
    }

    #[test]
    fn wrong_supplied_layer0_values_are_rejected() {
        // Layer 0 is virtual: no tree, no leaf check. What catches a wrong
        // supplied value is the fold — it lands on something layer 1 never
        // committed to, so the reconstructed round-1 leaf fails its Merkle
        // check. This test is what shows the chain still binds the virtual
        // layer.
        let params = Params::testing();
        let fiber = 1usize << params.eta;
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (proof, _) = prove(&params, codeword.clone(), &mut prover_transcript);

        let mut transcript = Transcript::new(b"fri-test");
        let plan = replay_transcript(&params, &proof, &mut transcript).unwrap();
        let mut layer0: Vec<Vec<Fp2>> =
            plan.indices.iter().map(|k| fiber_values(&codeword, fiber, *k)).collect();
        layer0[0][0] = layer0[0][0] + Fp2::ONE;

        assert!(!check_queries(&params, &proof, &plan, &layer0));
    }

    #[test]
    fn later_rounds_omit_the_value_the_fold_determines() {
        let params = Params::testing();
        let fiber = 1usize << params.eta;
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (proof, _) = prove(&params, codeword, &mut prover_transcript);

        let layers = &proof.queries[0].layers;
        assert_eq!(layers.len(), params.rounds - 1, "layer 0 is virtual, so no opening for it");
        for opening in layers {
            assert_eq!(opening.coset_values.len(), fiber - 1);
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
        let (mut proof, _) = prove(&params, codeword.clone(), &mut prover_transcript);
        proof.queries[0].layers[0].coset_values.push(Fp2::ONE);

        assert!(!run_verify(&params, &proof, b"fri-test", &codeword));
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
        let (mut proof, _) = prove(&params, codeword.clone(), &mut prover_transcript);
        proof.queries[0].layers[0].coset_values.rotate_left(1);

        assert!(!run_verify(&params, &proof, b"fri-test", &codeword));
    }

    #[test]
    fn tampering_a_later_round_opening_is_rejected() {
        // Before the omission this was caught by comparing the carried
        // value against the opening; now the leaf hash is the only thing
        // holding it, so it is worth testing on its own.
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (mut proof, _) = prove(&params, codeword.clone(), &mut prover_transcript);
        proof.queries[0].layers[0].coset_values[0] =
            proof.queries[0].layers[0].coset_values[0] + Fp2::ONE;

        assert!(!run_verify(&params, &proof, b"fri-test", &codeword));
    }

    /// A dishonest `prove` that skips the final truncation, sending the
    /// full interpolation of the last layer instead of only the first
    /// `degree_bound` coefficients.
    fn malicious_prove_untruncated(
        params: &Params,
        codeword: Vec<Fp2>,
        transcript: &mut Transcript,
    ) -> Proof {
        let fiber = 1usize << params.eta;
        let mut layers: Vec<Vec<Fp2>> = vec![codeword];
        let mut trees: Vec<MerkleTree> = Vec::new();
        let mut roots: Vec<Hash> = Vec::new();
        let mut caps: Vec<Vec<Hash>> = Vec::new();

        for round in 0..params.rounds {
            if round > 0 {
                let current = layers.last().unwrap();
                let tree = MerkleTree::build(leaves_for(current, fiber), params.cap_log);
                let root = tree.root();
                transcript.absorb_hash(b"fri-root", &root);
                roots.push(root);
                caps.push(tree.cap().to_vec());
                trees.push(tree);
            }
            let current = layers.last().unwrap().clone();
            let challenge = transcript.challenge_fp2(b"fri-fold");
            let log_size = params.u_log - params.eta * round as u32;
            layers.push(fold(params, &current, challenge, log_size));
        }

        // The attack: no `truncate`, so the coefficients interpolate the
        // final layer exactly and every fold-consistency check passes no
        // matter what the layer-0 codeword was.
        let final_layer = layers.last().unwrap();
        let final_log = params.u_log - params.eta * params.rounds as u32;
        let final_coefficients = interpolate_over_coset(final_layer, Fp2::ONE, final_log);
        transcript.absorb_fp2_slice(b"fri-final", &final_coefficients);

        let indices =
            transcript.challenge_indices(b"fri-query", params.kappa, params.u_size / fiber);
        let queries = indices
            .iter()
            .map(|start| {
                let mut position = *start;
                let mut openings = Vec::with_capacity(params.rounds.saturating_sub(1));
                for round in 1..params.rounds {
                    let codeword = &layers[round];
                    let count = codeword.len() / fiber;
                    let k = position % count;
                    let mut values = fiber_values(codeword, fiber, k);
                    values.remove(position / count);
                    openings.push(LayerOpening {
                        coset_values: values,
                        path: trees[round - 1].open(k),
                    });
                    position = k;
                }
                Query { layers: openings }
            })
            .collect();

        Proof { roots, caps, final_coefficients, queries }
    }

    #[test]
    fn untruncated_final_coefficients_are_rejected() {
        // Without the length bound in `replay_transcript`, this proof of a
        // maximally high-degree codeword verifies: the untruncated final
        // polynomial matches the final layer at every point, so all fold
        // checks pass and the degree bound is never enforced.
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.u_size);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let proof = malicious_prove_untruncated(&params, codeword.clone(), &mut prover_transcript);

        assert!(!run_verify(&params, &proof, b"fri-test", &codeword));
    }

    #[test]
    fn wrong_transcript_is_rejected() {
        // Fiat-Shamir binding: challenges must depend on the transcript.
        let params = Params::testing();
        let codeword = low_degree_codeword(&params, params.rate_numerator);

        let mut prover_transcript = Transcript::new(b"fri-test");
        let (proof, _) = prove(&params, codeword.clone(), &mut prover_transcript);

        assert!(!run_verify(&params, &proof, b"different-domain", &codeword));
    }
}
