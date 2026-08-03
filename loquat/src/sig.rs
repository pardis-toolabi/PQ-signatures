//! Signing and verification.
//!
//! The idea in one paragraph. Proving `L_0(K + I) = pk_I` directly would
//! mean proving a Legendre symbol in zero knowledge, which is expensive.
//! Instead the signer publishes `o = (K + I) * r` for a secret random `r`,
//! along with `T = L_0(r)`. Because the Legendre symbol is multiplicative,
//! the verifier can check
//!
//! ```text
//! L_0(o) = L_0(K + I) + L_0(r) = pk_I + T   (mod 2)
//! ```
//!
//! with one cheap symbol evaluation. All that is left to prove is that
//! every `o` was built from the *same* `K` — and that is a linear-algebra
//! claim, which the univariate sumcheck plus FRI handle.

use crate::field::{Fp, Fp2};
use crate::fri;
use crate::keys::{PublicKey, SecretKey};
use crate::merkle::{verify_with_cap, MerklePath, MerkleTree};
use crate::params::Params;
use crate::poly::{self, evaluate_at};
use crate::transcript::{hash_fp2_slice, hash_many, Hash, Transcript};
use rand::RngCore;

pub struct Signature {
    /// `T_{i,j} = L_0(r_{i,j})`, one bit each.
    t_bits: Vec<u8>,
    /// `o_{i,j} = (K + I_{i,j}) * r_{i,j}`.
    o_values: Vec<Fp>,
    root_c: Hash,
    cap_c: Vec<Hash>,
    root_s: Hash,
    cap_s: Vec<Hash>,
    root_h: Hash,
    cap_h: Vec<Hash>,
    /// `S = sum of the ZK mask over H`.
    sum_mask: Fp2,
    open_c: Vec<(Vec<Fp2>, MerklePath)>,
    open_s: Vec<(Vec<Fp2>, MerklePath)>,
    /// Paths only. The `h` values themselves are determined by everything
    /// else at the same point, so the verifier solves for them.
    open_h: Vec<MerklePath>,
    fri: fri::Proof,
}

impl Signature {
    pub fn size_bytes(&self, params: &Params) -> usize {
        let openings: usize = [&self.open_c, &self.open_s]
            .iter()
            .map(|set| {
                set.iter()
                    .map(|(values, path)| values.len() * 32 + path.siblings.len() * 32)
                    .sum::<usize>()
            })
            .sum::<usize>()
            + self.open_h.iter().map(|path| path.siblings.len() * 32).sum::<usize>();
        self.t_bits.len().div_ceil(8)
            + self.o_values.len() * 16
            + 3 * 32
            + (self.cap_c.len() + self.cap_s.len() + self.cap_h.len()) * 32
            + 32
            + openings
            + self.fri.size_bytes(params)
    }
}

fn random_fp2() -> Fp2 {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap()) & ((1u128 << 127) - 1);
    let hi = u128::from_le_bytes(bytes[16..].try_into().unwrap()) & ((1u128 << 127) - 1);
    Fp2::new(Fp::new(lo), Fp::new(hi))
}

fn random_nonzero_fp() -> Fp {
    loop {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        let candidate = u128::from_le_bytes(bytes) & ((1u128 << 127) - 1);
        if candidate != 0 && candidate < crate::field::P {
            return Fp::new(candidate);
        }
    }
}

fn random_poly(degree: usize) -> Vec<Fp2> {
    (0..=degree).map(|_| random_fp2()).collect()
}

/// Multiplies by `x^shift`, used to lift a codeword to the common rate.
fn shift_poly(coefficients: &[Fp2], shift: usize) -> Vec<Fp2> {
    let mut result = vec![Fp2::ZERO; shift];
    result.extend_from_slice(coefficients);
    result
}

/// Evaluates a polynomial at the points of a coset, by Horner. Used where
/// the polynomial's degree exceeds the coset size, so an FFT will not do.
fn evaluate_on_coset_points(coefficients: &[Fp2], shift: Fp2, generator: Fp2, count: usize) -> Vec<Fp2> {
    let mut point = shift;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(evaluate_at(coefficients, point));
        point = point * generator;
    }
    values
}

/// The fiber of `U` that Merkle leaf `k` covers.
fn fiber_indices(u_size: usize, fiber: usize, k: usize) -> Vec<usize> {
    let count = u_size / fiber;
    (0..fiber).map(|t| k + t * count).collect()
}

/// Interpolates the challenge vector `q_j` over `H`.
fn build_q_polynomials(params: &Params, lambda: &[Fp], index_choices: &[usize]) -> Vec<Vec<Fp2>> {
    (0..params.n)
        .map(|j| {
            let mut values = Vec::with_capacity(2 * params.m);
            for i in 0..params.m {
                let b = j * params.m + i;
                let lam = lambda[b];
                let public_index = params.indices[index_choices[b]];
                values.push(Fp2::from_base(lam));
                values.push(Fp2::from_base(lam * public_index));
            }
            poly::interpolate_over_coset(&values, params.h_shift, params.h_log())
        })
        .collect()
}

/// Rebuilds the batched codeword value at one point of `U`.
///
/// Both signer and verifier must agree on this exactly; keeping it in one
/// function is what guarantees they do.
#[allow(clippy::too_many_arguments)]
fn batched_value_at(
    params: &Params,
    e: &[Fp2],
    point: Fp2,
    c_values: &[Fp2],
    s_value: Fp2,
    h_value: Fp2,
    p_value: Fp2,
) -> Fp2 {
    let bounds = params.degree_bounds();
    let mut components: Vec<(Fp2, usize)> = Vec::with_capacity(params.n + 3);
    for value in c_values.iter() {
        components.push((*value, bounds[0]));
    }
    components.push((s_value, bounds[1]));
    components.push((h_value, bounds[2]));
    components.push((p_value, bounds[3]));

    let mut total = Fp2::ZERO;
    for (index, (value, bound)) in components.iter().enumerate() {
        let shift = params.rate_numerator - bound;
        total = total + e[2 * index] * *value;
        total = total + e[2 * index + 1] * point.pow(shift as u128) * *value;
    }
    total
}

pub fn sign(params: &Params, secret: &SecretKey, message: &[u8]) -> Signature {
    let fiber = 1usize << params.eta;
    let leaf_count = params.leaf_count();
    let h_generator = params.h_generator();
    let u_generator = params.u_generator();
    let vanishing_offset = params.vanishing_offset();
    let masked_degree = params.kappa * fiber;

    let mut transcript = Transcript::new(b"loquat-signature");

    // --- Phase 1: commit to the key blinded by fresh randomness ---------
    let mut r_values: Vec<Fp> = Vec::with_capacity(params.b);
    let mut t_bits: Vec<u8> = Vec::with_capacity(params.b);
    let mut c_prime: Vec<Vec<Fp2>> = Vec::with_capacity(params.n);

    for j in 0..params.n {
        let mut values = Vec::with_capacity(2 * params.m);
        for _ in 0..params.m {
            let r = random_nonzero_fp();
            r_values.push(r);
            t_bits.push(r.legendre_bit());
            // Interleaving K*r with r is what makes the later inner
            // product collapse to sum(lambda * (K + I) * r).
            values.push(Fp2::from_base(secret.k * r));
            values.push(Fp2::from_base(r));
        }
        let c_hat = poly::interpolate_over_coset(&values, params.h_shift, params.h_log());

        // Mask with Z_H * r_hat: this vanishes on H, so it changes nothing
        // the sumcheck sees, but it randomises every point of U that a
        // query could reveal.
        let mask = random_poly(masked_degree);
        let mut vanishing = vec![Fp2::ZERO; params.h_size + 1];
        vanishing[params.h_size] = Fp2::ONE;
        vanishing[0] = -vanishing_offset;
        c_prime.push(poly::add(&c_hat, &poly::multiply(&vanishing, &mask)));
        let _ = j;
    }

    let c_evaluations: Vec<Vec<Fp2>> = c_prime
        .iter()
        .map(|p| poly::evaluate_over_coset(p, Fp2::ONE, params.u_log))
        .collect();

    let leaves_c: Vec<Hash> = (0..leaf_count)
        .map(|k| {
            let mut values = Vec::with_capacity(params.n * fiber);
            for evaluations in &c_evaluations {
                for index in fiber_indices(params.u_size, fiber, k) {
                    values.push(evaluations[index]);
                }
            }
            hash_fp2_slice(b"loquat-c", &values)
        })
        .collect();
    let tree_c = MerkleTree::build(leaves_c, params.cap_log);
    let root_c = tree_c.root();

    transcript.absorb_hash(b"root-c", &root_c);
    transcript.absorb_bits(b"T", &t_bits);
    transcript.absorb_bytes(b"msg", message);

    // --- Phase 2: reveal the blinded residuosity values ------------------
    let index_choices = transcript.challenge_indices(b"I", params.b, params.l);
    let o_values: Vec<Fp> = (0..params.b)
        .map(|b| (secret.k + params.indices[index_choices[b]]) * r_values[b])
        .collect();

    let o_lifted: Vec<Fp2> = o_values.iter().map(|o| Fp2::from_base(*o)).collect();
    transcript.absorb_fp2_slice(b"o", &o_lifted);

    // --- Phase 3: fold the claim into one polynomial ---------------------
    let lambda = transcript.challenge_fp_vec(b"lambda", params.b);
    let epsilon = transcript.challenge_fp2_vec(b"epsilon", params.n);

    let q_polynomials = build_q_polynomials(params, &lambda, &index_choices);

    let mut f_hat: Vec<Fp2> = Vec::new();
    for j in 0..params.n {
        let product = poly::multiply(&c_prime[j], &q_polynomials[j]);
        f_hat = poly::add(&f_hat, &poly::scale(&product, epsilon[j]));
    }

    // The claimed sum, computed directly from public values.
    let mut mu = Fp2::ZERO;
    for (j, epsilon_j) in epsilon.iter().enumerate() {
        let mut inner = Fp2::ZERO;
        for i in 0..params.m {
            let b = j * params.m + i;
            inner = inner + Fp2::from_base(lambda[b] * o_values[b]);
        }
        mu = mu + *epsilon_j * inner;
    }

    let mask_poly = random_poly(4 * params.m + masked_degree - 1);
    let mask_on_h =
        evaluate_on_coset_points(&mask_poly, params.h_shift, h_generator, params.h_size);
    let sum_mask = mask_on_h.iter().fold(Fp2::ZERO, |acc, v| acc + *v);

    let s_evaluations = poly::evaluate_over_coset(&mask_poly, Fp2::ONE, params.u_log);
    let leaves_s: Vec<Hash> = (0..leaf_count)
        .map(|k| {
            let values: Vec<Fp2> = fiber_indices(params.u_size, fiber, k)
                .into_iter()
                .map(|index| s_evaluations[index])
                .collect();
            hash_fp2_slice(b"loquat-s", &values)
        })
        .collect();
    let tree_s = MerkleTree::build(leaves_s, params.cap_log);
    let root_s = tree_s.root();

    transcript.absorb_hash(b"root-s", &root_s);
    transcript.absorb_fp2_slice(b"S", &[sum_mask]);

    // --- Phase 4: the sumcheck split -------------------------------------
    let z = transcript.challenge_fp2(b"z");
    let f_prime = poly::add(&poly::scale(&f_hat, z), &mask_poly);
    let (h_poly, g_poly) = poly::divide_by_vanishing(&f_prime, params.h_size, vanishing_offset);

    let h_evaluations = poly::evaluate_over_coset(&h_poly, Fp2::ONE, params.u_log);
    let leaves_h: Vec<Hash> = (0..leaf_count)
        .map(|k| {
            let values: Vec<Fp2> = fiber_indices(params.u_size, fiber, k)
                .into_iter()
                .map(|index| h_evaluations[index])
                .collect();
            hash_fp2_slice(b"loquat-h", &values)
        })
        .collect();
    let tree_h = MerkleTree::build(leaves_h, params.cap_log);
    let root_h = tree_h.root();

    transcript.absorb_hash(b"root-h", &root_h);

    // --- Phase 5: batch every codeword into one -------------------------
    let e = transcript.challenge_fp2_vec(b"e", 2 * (params.n + 3));

    // Byott-Chapman: for a coset H and deg(g) < |H|, the sum over H is
    // |H| * g(0). So the constant term of g is pinned by the claimed sum,
    // and p_hat = (g(x) - g(0)) / x is exactly the paper's rational
    // constraint after the |H| factors cancel.
    let p_poly: Vec<Fp2> = if g_poly.len() > 1 { g_poly[1..].to_vec() } else { Vec::new() };

    let bounds = params.degree_bounds();
    let mut f0: Vec<Fp2> = Vec::new();
    let mut components: Vec<(&[Fp2], usize)> = Vec::new();
    for polynomial in &c_prime {
        components.push((polynomial, bounds[0]));
    }
    components.push((&mask_poly, bounds[1]));
    components.push((&h_poly, bounds[2]));
    components.push((&p_poly, bounds[3]));

    for (index, (polynomial, bound)) in components.iter().enumerate() {
        let shift = params.rate_numerator - bound;
        f0 = poly::add(&f0, &poly::scale(polynomial, e[2 * index]));
        f0 = poly::add(&f0, &poly::scale(&shift_poly(polynomial, shift), e[2 * index + 1]));
    }

    let codeword = poly::evaluate_over_coset(&f0, Fp2::ONE, params.u_log);

    // --- Phases 6 and 7: low-degree test, then open at its queries -------
    let (fri_proof, query_indices) = fri::prove(params, codeword, &mut transcript);

    let open_c = query_indices
        .iter()
        .map(|k| {
            let mut values = Vec::with_capacity(params.n * fiber);
            for evaluations in &c_evaluations {
                for index in fiber_indices(params.u_size, fiber, *k) {
                    values.push(evaluations[index]);
                }
            }
            (values, tree_c.open(*k))
        })
        .collect();

    let open_s = query_indices
        .iter()
        .map(|k| {
            let values: Vec<Fp2> = fiber_indices(params.u_size, fiber, *k)
                .into_iter()
                .map(|index| s_evaluations[index])
                .collect();
            (values, tree_s.open(*k))
        })
        .collect();

    let open_h = query_indices.iter().map(|k| tree_h.open(*k)).collect();

    let _ = u_generator;

    Signature {
        t_bits,
        o_values,
        root_c,
        cap_c: tree_c.cap().to_vec(),
        root_s,
        cap_s: tree_s.cap().to_vec(),
        root_h,
        cap_h: tree_h.cap().to_vec(),
        sum_mask,
        open_c,
        open_s,
        open_h,
        fri: fri_proof,
    }
}

pub fn verify(params: &Params, public: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    let fiber = 1usize << params.eta;
    let u_generator = params.u_generator();
    let vanishing_offset = params.vanishing_offset();

    if signature.t_bits.len() != params.b || signature.o_values.len() != params.b {
        return false;
    }
    if hash_many(b"cap", &signature.cap_c) != signature.root_c
        || hash_many(b"cap", &signature.cap_s) != signature.root_s
        || hash_many(b"cap", &signature.cap_h) != signature.root_h
    {
        return false;
    }

    // --- Replay the transcript exactly as the signer built it ------------
    let mut transcript = Transcript::new(b"loquat-signature");
    transcript.absorb_hash(b"root-c", &signature.root_c);
    transcript.absorb_bits(b"T", &signature.t_bits);
    transcript.absorb_bytes(b"msg", message);

    let index_choices = transcript.challenge_indices(b"I", params.b, params.l);

    // --- The Legendre check, the only place the public key is used -------
    for (b, index_choice) in index_choices.iter().enumerate() {
        let o = signature.o_values[b];
        if o.is_zero() {
            return false;
        }
        let expected = public.bit(*index_choice) ^ signature.t_bits[b];
        if o.legendre_bit() != expected {
            return false;
        }
    }

    let o_lifted: Vec<Fp2> = signature.o_values.iter().map(|o| Fp2::from_base(*o)).collect();
    transcript.absorb_fp2_slice(b"o", &o_lifted);

    let lambda = transcript.challenge_fp_vec(b"lambda", params.b);
    let epsilon = transcript.challenge_fp2_vec(b"epsilon", params.n);

    transcript.absorb_hash(b"root-s", &signature.root_s);
    transcript.absorb_fp2_slice(b"S", &[signature.sum_mask]);
    let z = transcript.challenge_fp2(b"z");

    transcript.absorb_hash(b"root-h", &signature.root_h);
    let e = transcript.challenge_fp2_vec(b"e", 2 * (params.n + 3));

    // --- Recompute the claimed sum from public values --------------------
    let mut mu = Fp2::ZERO;
    for (j, epsilon_j) in epsilon.iter().enumerate() {
        let mut inner = Fp2::ZERO;
        for i in 0..params.m {
            let b = j * params.m + i;
            inner = inner + Fp2::from_base(lambda[b] * signature.o_values[b]);
        }
        mu = mu + *epsilon_j * inner;
    }
    let claimed_sum = z * mu + signature.sum_mask;

    // --- Check the low-degree test --------------------------------------
    let layer0 = match fri::verify(params, &signature.fri, &mut transcript) {
        Some(openings) => openings,
        None => return false,
    };

    if signature.open_c.len() != params.kappa
        || signature.open_s.len() != params.kappa
        || signature.open_h.len() != params.kappa
    {
        return false;
    }

    let q_polynomials = build_q_polynomials(params, &lambda, &index_choices);
    let h_size_field = Fp2::from_base(Fp::new(params.h_size as u128));

    // --- Tie the opened codewords to the batched one FRI tested ---------
    for (query, (k, batched_values)) in layer0.iter().enumerate() {
        let (c_values, c_path) = &signature.open_c[query];
        let (s_values, s_path) = &signature.open_s[query];
        let h_path = &signature.open_h[query];

        if c_values.len() != params.n * fiber || s_values.len() != fiber {
            return false;
        }
        if !verify_with_cap(&signature.cap_c, hash_fp2_slice(b"loquat-c", c_values), *k, c_path)
            || !verify_with_cap(&signature.cap_s, hash_fp2_slice(b"loquat-s", s_values), *k, s_path)
        {
            return false;
        }

        let mut h_values = Vec::with_capacity(fiber);
        for (slot, index) in fiber_indices(params.u_size, fiber, *k).into_iter().enumerate() {
            let point = u_generator.pow(index as u128);

            // Rebuild f_hat at this point from the opened witness values.
            let mut f_value = Fp2::ZERO;
            let mut c_at_point = Vec::with_capacity(params.n);
            for j in 0..params.n {
                let c_value = c_values[j * fiber + slot];
                c_at_point.push(c_value);
                let q_value = evaluate_at(&q_polynomials[j], point);
                f_value = f_value + epsilon[j] * c_value * q_value;
            }

            let s_value = s_values[slot];
            let f_prime_value = z * f_value + s_value;
            let vanishing_value = point.pow(params.h_size as u128) - vanishing_offset;
            let denominator = match (h_size_field * point).inverse() {
                Some(inverse) => inverse,
                None => return false,
            };

            // What the batched codeword would be for a given `h`. The
            // rational constraint `p` is never sent either; the verifier
            // derives it, which is what keeps the proof small.
            let batched_for = |h_value: Fp2| {
                let numerator = h_size_field * f_prime_value
                    - h_size_field * vanishing_value * h_value
                    - claimed_sum;
                let p_value = numerator * denominator;
                batched_value_at(params, &e, point, &c_at_point, s_value, h_value, p_value)
            };

            // That map is affine in `h`, and FRI has already fixed the
            // batched value, so `h` is solved for rather than sent. Nothing
            // is taken on trust: the solved values still have to reproduce
            // the leaf the signer committed `h` to, below.
            let at_zero = batched_for(Fp2::ZERO);
            let slope = batched_for(Fp2::ONE) - at_zero;
            let h_value = match slope.inverse() {
                Some(inverse) => (batched_values[slot] - at_zero) * inverse,
                None => return false,
            };
            h_values.push(h_value);
        }

        if !verify_with_cap(&signature.cap_h, hash_fp2_slice(b"loquat-h", &h_values), *k, h_path) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;

    #[test]
    fn honest_signature_verifies() {
        let params = Params::testing();
        let (secret, public) = keys::generate(&params);
        let signature = sign(&params, &secret, b"hello loquat");
        assert!(verify(&params, &public, b"hello loquat", &signature));
    }

    #[test]
    fn signature_does_not_verify_for_a_different_message() {
        let params = Params::testing();
        let (secret, public) = keys::generate(&params);
        let signature = sign(&params, &secret, b"original");
        assert!(!verify(&params, &public, b"tampered", &signature));
    }

    #[test]
    fn signature_does_not_verify_under_a_different_key() {
        let params = Params::testing();
        let (secret, _) = keys::generate(&params);
        let (_, other_public) = keys::generate(&params);
        let signature = sign(&params, &secret, b"hello");
        assert!(!verify(&params, &other_public, b"hello", &signature));
    }

    #[test]
    fn tampering_with_o_values_is_caught() {
        let params = Params::testing();
        let (secret, public) = keys::generate(&params);
        let mut signature = sign(&params, &secret, b"hello");
        signature.o_values[0] = signature.o_values[0] + Fp::new(1);
        assert!(!verify(&params, &public, b"hello", &signature));
    }

    #[test]
    fn tampering_with_t_bits_is_caught() {
        let params = Params::testing();
        let (secret, public) = keys::generate(&params);
        let mut signature = sign(&params, &secret, b"hello");
        signature.t_bits[3] ^= 1;
        assert!(!verify(&params, &public, b"hello", &signature));
    }

    #[test]
    fn zero_o_value_is_rejected() {
        // A zero would make the Legendre symbol meaningless, so it must be
        // refused outright rather than silently treated as a residue.
        let params = Params::testing();
        let (secret, public) = keys::generate(&params);
        let mut signature = sign(&params, &secret, b"hello");
        signature.o_values[0] = Fp::ZERO;
        assert!(!verify(&params, &public, b"hello", &signature));
    }

    #[test]
    fn tampering_with_openings_is_caught() {
        let params = Params::testing();
        let (secret, public) = keys::generate(&params);
        let mut signature = sign(&params, &secret, b"hello");
        signature.open_c[0].0[0] = signature.open_c[0].0[0] + Fp2::ONE;
        assert!(!verify(&params, &public, b"hello", &signature));
    }

    #[test]
    fn tampering_with_the_mask_opening_is_caught() {
        let params = Params::testing();
        let (secret, public) = keys::generate(&params);
        let mut signature = sign(&params, &secret, b"hello");
        signature.open_s[0].0[0] = signature.open_s[0].0[0] + Fp2::ONE;
        assert!(!verify(&params, &public, b"hello", &signature));
    }

    /// The `h` openings are solved for rather than sent, so the only thing
    /// binding them is the Merkle path they are checked against. Breaking
    /// that path must be caught, otherwise the solved values would be
    /// accepted without ever being tied to what the signer committed to.
    #[test]
    fn tampering_with_the_h_path_is_caught() {
        let params = Params::testing();
        let (secret, public) = keys::generate(&params);
        let mut signature = sign(&params, &secret, b"hello");
        signature.open_h[0].siblings[0][0] ^= 1;
        assert!(!verify(&params, &public, b"hello", &signature));
    }

    #[test]
    fn a_restitched_h_commitment_is_caught() {
        // Repairing the root after editing the cap gets past the
        // cap-to-root check, but `root_h` also feeds the later challenges,
        // so Fiat-Shamir catches it instead.
        let params = Params::testing();
        let (secret, public) = keys::generate(&params);
        let mut signature = sign(&params, &secret, b"hello");
        signature.cap_h[0][0] ^= 1;
        signature.root_h = hash_many(b"cap", &signature.cap_h);
        assert!(!verify(&params, &public, b"hello", &signature));
    }

    #[test]
    fn tampering_with_the_mask_sum_is_caught() {
        let params = Params::testing();
        let (secret, public) = keys::generate(&params);
        let mut signature = sign(&params, &secret, b"hello");
        signature.sum_mask = signature.sum_mask + Fp2::ONE;
        assert!(!verify(&params, &public, b"hello", &signature));
    }

    /// The claim the whole protocol reduces to.
    ///
    /// Interleaving `c = (K*r_1, r_1, ...)` against `q = (lam_1, lam_1*I_1, ...)`
    /// makes their inner product over H collapse to `sum lam_i (K + I_i) r_i`,
    /// which is `sum lam_i o_i` — a value the verifier can compute from
    /// public data alone. If this identity is wrong, nothing above it means
    /// anything, so it is worth checking directly rather than only through
    /// a passing signature.
    #[test]
    fn sumcheck_identity_matches_the_public_inner_product() {
        let params = Params::testing();
        let (secret, _) = keys::generate(&params);
        let h_generator = params.h_generator();
        let vanishing_offset = params.vanishing_offset();
        let masked_degree = params.kappa * (1usize << params.eta);

        // Build one instance exactly as the signer does.
        let mut r_values = Vec::new();
        let mut values = Vec::new();
        for _ in 0..params.m {
            let r = random_nonzero_fp();
            r_values.push(r);
            values.push(Fp2::from_base(secret.k * r));
            values.push(Fp2::from_base(r));
        }
        let c_hat = poly::interpolate_over_coset(&values, params.h_shift, params.h_log());

        let mask = random_poly(masked_degree);
        let mut vanishing = vec![Fp2::ZERO; params.h_size + 1];
        vanishing[params.h_size] = Fp2::ONE;
        vanishing[0] = -vanishing_offset;
        let c_prime = poly::add(&c_hat, &poly::multiply(&vanishing, &mask));

        let lambda: Vec<Fp> = (0..params.m).map(|_| random_nonzero_fp()).collect();
        let chosen: Vec<usize> = (0..params.m).collect();
        let mut q_values = Vec::new();
        for i in 0..params.m {
            let public_index = params.indices[chosen[i]];
            q_values.push(Fp2::from_base(lambda[i]));
            q_values.push(Fp2::from_base(lambda[i] * public_index));
        }
        let q_hat = poly::interpolate_over_coset(&q_values, params.h_shift, params.h_log());

        // Sum the product over H.
        let product = poly::multiply(&c_prime, &q_hat);
        let on_h = evaluate_on_coset_points(&product, params.h_shift, h_generator, params.h_size);
        let sum = on_h.iter().fold(Fp2::ZERO, |acc, v| acc + *v);

        // Compare against the public-side value.
        let mut expected = Fp2::ZERO;
        for i in 0..params.m {
            let o = (secret.k + params.indices[chosen[i]]) * r_values[i];
            expected = expected + Fp2::from_base(lambda[i] * o);
        }

        assert_eq!(sum, expected, "the arithmetisation of the Legendre relation is wrong");
    }

    /// The masking polynomial must not disturb the sum, because `Z_H`
    /// vanishes on every point of `H`.
    #[test]
    fn zk_mask_does_not_change_the_sum_over_h() {
        let params = Params::testing();
        let h_generator = params.h_generator();
        let vanishing_offset = params.vanishing_offset();

        let base: Vec<Fp2> = (0..params.h_size).map(|_| random_fp2()).collect();
        let base_poly = poly::interpolate_over_coset(&base, params.h_shift, params.h_log());

        let mask = random_poly(params.kappa * (1usize << params.eta));
        let mut vanishing = vec![Fp2::ZERO; params.h_size + 1];
        vanishing[params.h_size] = Fp2::ONE;
        vanishing[0] = -vanishing_offset;
        let masked = poly::add(&base_poly, &poly::multiply(&vanishing, &mask));

        let sum_of = |p: &[Fp2]| {
            evaluate_on_coset_points(p, params.h_shift, h_generator, params.h_size)
                .iter()
                .fold(Fp2::ZERO, |acc, v| acc + *v)
        };
        assert_eq!(sum_of(&base_poly), sum_of(&masked));
    }

    #[test]
    fn signatures_are_randomised() {
        // Fresh randomness each time, so two signatures over the same
        // message must differ while both verifying.
        let params = Params::testing();
        let (secret, public) = keys::generate(&params);
        let a = sign(&params, &secret, b"same message");
        let b = sign(&params, &secret, b"same message");
        assert_ne!(a.o_values, b.o_values);
        assert!(verify(&params, &public, b"same message", &a));
        assert!(verify(&params, &public, b"same message", &b));
    }
}
