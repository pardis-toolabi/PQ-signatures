//! Signing and verification.
//!
//! Reference: CAPSS (ePrint 2025/061), Section 5.1, "Description of the
//! Signature Scheme" — the sign/verify algorithms, the four-hash
//! Fiat-Shamir chain (with its optional grinding, not implemented here),
//! and verification as transcript recomputation. Unforgeability is their
//! Section 5.2.
//!
//! The whole signature is one non-interactive proof of the statement
//! "I know an `x` with `Tr_{|y|}( P(iv, x) ) = y`", where `(iv, y)` is the
//! public key. There is no separate response phase, no key-dependent
//! algebra beyond that, and no assumption anywhere except the
//! permutation itself.
//!
//! ```text
//! sign   : x  ->  trace  ->  witness matrix  ->  PIOP proof
//! verify : replay the transcript over the proof
//! ```
//!
//! ## The Fiat-Shamir chain
//!
//! Four sequential hashes, each folding the previous state in:
//!
//! ```text
//! h1 <- (message, public key)
//! h2 <- (h1, salt, root)        -> the DECS gammas and the PIOP challenges
//! h3 <- (h2, Q high coefficients)
//! h4 <- (h3, R high coefficients) -> the l' opening indices
//! ```
//!
//! `notes/capss-spec.md` writes the chain as `(salt, root)`, `(R)`, `(Q)`,
//! `(v, msg)`, with the message absorbed last. Two things move here. The
//! message and public key go first, which is the usual thing to do in a
//! signature and costs nothing. And `R` — the DECS batched high
//! coefficients — is absorbed after `Q` rather than before, because
//! `decs::open` couples absorbing `R` to squeezing the opening indices
//! and we did not want to reach into that module to split them. What
//! matters for soundness is unchanged and is the same in both orders:
//! *every* prover message is bound into the transcript before the opening
//! indices are drawn.
//!
//! ## Why verification is a transcript replay
//!
//! `verify` never rebuilds the witness matrix and never calls
//! `pacs::constraints_are_satisfied`. It re-derives every challenge from
//! the signature's own bytes, checks the `l'` Merkle paths, and tests one
//! algebraic identity per combination. Re-checking the constraints
//! directly would need the witness — which is secret — and would cost
//! `m1 * s + m2` degree-7 constraint evaluations. The replay costs
//! `l' * log2(N)` hash compressions plus a fixed amount of field
//! arithmetic. That difference is the entire reason CAPSS's verifier is
//! cheap to express as an R1CS, and implementing `verify` as an explicit
//! constraint re-check would throw the property away while still passing
//! every happy-path test.

use crate::field::Fp;
use crate::keys::{KeyPair, PublicKey};
use crate::pacs::{self, Matrix};
use crate::piop::{self, Parameters};
use crate::transcript::{Digest, Transcript, CAPACITY};
use rand::RngCore;

#[derive(Clone, Debug)]
pub struct Signature {
    proof: piop::Proof,
}

impl Signature {
    pub fn size_bytes(&self) -> usize {
        self.proof.size_bytes()
    }

    /// Exposed so tests can tamper with individual components.
    pub fn proof_mut(&mut self) -> &mut piop::Proof {
        &mut self.proof
    }
}

fn random_digest() -> Digest {
    let mut digest = [Fp::ZERO; CAPACITY];
    let mut bytes = [0u8; 16];
    for value in digest.iter_mut() {
        rand::thread_rng().fill_bytes(&mut bytes);
        *value = Fp::from_random_bytes(bytes);
    }
    digest
}

/// `h1`: the message and the public key, before anything the prover
/// chooses.
fn opening_transcript(public: &PublicKey, message: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(b"capss-signature-v1");
    transcript.absorb_bytes(b"message", message);
    transcript.absorb_field_slice(b"public-iv", &public.iv);
    transcript.absorb_field_slice(b"public-y", &public.y);
    transcript
}

/// Proves against a caller-supplied witness.
///
/// Split out from `sign` so a cheating prover can be modelled: hand in a
/// matrix that does not satisfy the PACS constraints and the proof will
/// be built anyway, which is exactly what the forgery test needs.
fn sign_with_witness(
    parameters: &Parameters,
    public: &PublicKey,
    witness: &Matrix,
    message: &[u8],
) -> Signature {
    let mut transcript = opening_transcript(public, message);
    // The salt separates two signatures over the same message so that
    // repeated signing does not reuse leaf hashes; the seed expands into
    // the row pads and the PIOP masks, and is the only thing hiding the
    // witness. Both have to be fresh, and the seed has to stay secret.
    let proof = piop::prove(
        parameters,
        public,
        witness,
        random_digest(),
        random_digest(),
        &mut transcript,
    );
    Signature { proof }
}

pub fn sign(parameters: &Parameters, pair: &KeyPair, message: &[u8]) -> Signature {
    let witness = pacs::secret_to_witness(&pair.public.iv, &pair.secret.x);
    sign_with_witness(parameters, &pair.public, &witness, message)
}

pub fn verify(
    parameters: &Parameters,
    public: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> bool {
    let mut transcript = opening_transcript(public, message);
    piop::verify(parameters, public, &signature.proof, &mut transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::P;
    use crate::keys::{self, IV_SIZE, SECRET_SIZE};

    fn pseudorandom(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn key_pair(seed: &mut u64) -> (KeyPair, Matrix) {
        let mut iv = [Fp::ZERO; IV_SIZE];
        let mut x = [Fp::ZERO; SECRET_SIZE];
        for value in iv.iter_mut().chain(x.iter_mut()) {
            *value = Fp::new(pseudorandom(seed) % P);
        }
        (keys::from_parts(&iv, &x), pacs::secret_to_witness(&iv, &x))
    }

    #[test]
    fn an_honest_signature_verifies() {
        let parameters = Parameters::testing();
        for _ in 0..2 {
            let pair = keys::generate();
            let signature = sign(&parameters, &pair, b"hello capss");
            assert!(verify(&parameters, &pair.public, b"hello capss", &signature));
        }
    }

    #[test]
    fn two_signatures_over_the_same_message_differ_but_both_verify() {
        // The salt and the mask seed are fresh per signature, so the
        // scheme is randomised rather than deterministic.
        let parameters = Parameters::testing();
        let pair = keys::generate();
        let first = sign(&parameters, &pair, b"same message");
        let second = sign(&parameters, &pair, b"same message");
        assert_ne!(first.proof.root, second.proof.root);
        assert!(verify(&parameters, &pair.public, b"same message", &first));
        assert!(verify(&parameters, &pair.public, b"same message", &second));
    }

    #[test]
    fn a_tampered_message_does_not_verify() {
        let parameters = Parameters::testing();
        let pair = keys::generate();
        let signature = sign(&parameters, &pair, b"original");
        assert!(!verify(&parameters, &pair.public, b"tampered", &signature));
        assert!(!verify(&parameters, &pair.public, b"original ", &signature));
        assert!(!verify(&parameters, &pair.public, b"", &signature));
    }

    #[test]
    fn a_signature_does_not_verify_under_a_different_public_key() {
        let parameters = Parameters::testing();
        let pair = keys::generate();
        let other = keys::generate();
        let signature = sign(&parameters, &pair, b"hello");
        assert!(verify(&parameters, &pair.public, b"hello", &signature));
        assert!(!verify(&parameters, &other.public, b"hello", &signature));

        // Moving either half of the key alone must also break it.
        let mut shifted = pair.public;
        shifted.iv[0] = shifted.iv[0] + Fp::ONE;
        assert!(!verify(&parameters, &shifted, b"hello", &signature));
        let mut shifted = pair.public;
        shifted.y[3] = shifted.y[3] + Fp::ONE;
        assert!(!verify(&parameters, &shifted, b"hello", &signature));
    }

    #[test]
    fn tampering_with_any_proof_component_is_caught() {
        let parameters = Parameters::testing();
        let pair = keys::generate();
        let signature = sign(&parameters, &pair, b"hello");

        let mut tampered = signature.clone();
        tampered.proof_mut().root[0] = tampered.proof.root[0] + Fp::ONE;
        assert!(!verify(&parameters, &pair.public, b"hello", &tampered));

        let mut tampered = signature.clone();
        tampered.proof_mut().q_high[0][2] = tampered.proof.q_high[0][2] + Fp::ONE;
        assert!(!verify(&parameters, &pair.public, b"hello", &tampered));

        let mut tampered = signature.clone();
        tampered.proof_mut().opening.leaves[0].polynomial_values[5] =
            tampered.proof.opening.leaves[0].polynomial_values[5] + Fp::ONE;
        assert!(!verify(&parameters, &pair.public, b"hello", &tampered));

        let mut tampered = signature.clone();
        tampered.proof_mut().opening.paths[2].siblings[1][0] =
            tampered.proof.opening.paths[2].siblings[1][0] + Fp::ONE;
        assert!(!verify(&parameters, &pair.public, b"hello", &tampered));

        let mut tampered = signature.clone();
        tampered.proof_mut().salt[1] = tampered.proof.salt[1] + Fp::ONE;
        assert!(!verify(&parameters, &pair.public, b"hello", &tampered));
    }

    #[test]
    fn a_signature_forged_from_a_wrong_witness_fails() {
        // The test that shows the proof system proves something rather
        // than merely being self-consistent. The forger runs the honest
        // prover on a matrix that does not satisfy the arithmetization,
        // so every hash, every Merkle path and every reconstruction is
        // internally consistent — the only thing wrong is the statement.
        let parameters = Parameters::testing();
        let mut seed = 90u64;
        let (pair, witness) = key_pair(&mut seed);
        assert!(pacs::constraints_are_satisfied(&witness, &pair.public));
        assert!(verify(
            &parameters,
            &pair.public,
            b"honest",
            &sign_with_witness(&parameters, &pair.public, &witness, b"honest")
        ));

        // A witness that breaks the round verification.
        for (row, column) in [(0usize, 0usize), (9, 4), (15, 10)] {
            let mut forged = witness.clone();
            forged.set(row, column, forged.get(row, column) + Fp::ONE);
            assert!(!pacs::constraints_are_satisfied(&forged, &pair.public));
            let signature = sign_with_witness(&parameters, &pair.public, &forged, b"forged");
            assert!(
                !verify(&parameters, &pair.public, b"forged", &signature),
                "a forgery broken at ({row}, {column}) verified"
            );
        }

        // A witness that is entirely someone else's honest execution.
        // Every parallel constraint holds; only the bindings to this
        // public key fail, which is the aggregated family's job.
        let (_, other_witness) = key_pair(&mut seed);
        let signature = sign_with_witness(&parameters, &pair.public, &other_witness, b"forged");
        assert!(!verify(&parameters, &pair.public, b"forged", &signature));

        // A witness spliced from two executions: each column is a valid
        // round, so only the wiring constraints can see it.
        let mut spliced = witness.clone();
        let column = pacs::dimensions().columns / 2;
        for row in 0..spliced.rows() {
            spliced.set(row, column, other_witness.get(row, column));
        }
        for check in 0..pacs::dimensions().columns {
            assert!(pacs::parallel_constraints(&spliced, check).iter().all(|v| v.is_zero()));
        }
        let signature = sign_with_witness(&parameters, &pair.public, &spliced, b"forged");
        assert!(!verify(&parameters, &pair.public, b"forged", &signature));

        // And a witness with no structure at all.
        let mut noise = Matrix::new(spliced.rows(), spliced.columns());
        for row in 0..noise.rows() {
            for column in 0..noise.columns() {
                noise.set(row, column, Fp::new(pseudorandom(&mut seed) % P));
            }
        }
        let signature = sign_with_witness(&parameters, &pair.public, &noise, b"forged");
        assert!(!verify(&parameters, &pair.public, b"forged", &signature));
    }

    #[test]
    fn the_signature_size_is_what_the_parameters_predict() {
        let parameters = Parameters::testing();
        let pair = keys::generate();
        let signature = sign(&parameters, &pair, b"hello");
        let proof = &signature.proof;
        let decs = parameters.decs();

        let expected = 8 * (proof.salt.len()
            + proof.root.len()
            + parameters.combination_count * parameters.sent_q_coefficients()
            + decs.mask_count * decs.sent_coefficient_count()
            + parameters.opened_count * (parameters.polynomial_count() + decs.mask_count)
            + proof.opening.paths.iter().map(|p| p.siblings.iter().map(|s| s.len()).sum::<usize>()).sum::<usize>());
        assert_eq!(signature.size_bytes(), expected);
    }

    /// The instance the report quotes. Skipped by default because signing
    /// hashes 2^14 leaves, which is seconds of work in an unoptimised
    /// build. Run with `cargo test --release -p capss -- --ignored
    /// --nocapture`.
    #[test]
    #[ignore]
    fn level_128_signs_and_verifies() {
        let parameters = Parameters::level_128();
        let pair = keys::generate();

        let start = std::time::Instant::now();
        let signature = sign(&parameters, &pair, b"hello capss");
        let signing = start.elapsed();

        let start = std::time::Instant::now();
        let accepted = verify(&parameters, &pair.public, b"hello capss", &signature);
        let verifying = start.elapsed();

        println!(
            "level_128: {} bytes, sign {:.3?}, verify {:.3?}",
            signature.size_bytes(),
            signing,
            verifying
        );
        assert!(accepted);
        assert!(!verify(&parameters, &pair.public, b"tampered", &signature));
    }
}
