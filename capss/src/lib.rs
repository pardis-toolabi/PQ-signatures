//! CAPSS: a SNARK-friendly post-quantum signature framework
//! (Feneuil & Rivain, IACR ePrint 2025/061).
//!
//! References used throughout the crate (all verified against the texts):
//! - CAPSS: T. Feneuil, M. Rivain, "CAPSS: A Framework for SNARK-Friendly
//!   Post-Quantum Signatures", ePrint 2025/061.
//! - SmallWood: T. Feneuil, M. Rivain, "SmallWood: Hash-Based Polynomial
//!   Commitments and Zero-Knowledge Arguments for Relatively Small
//!   Instances", ePrint 2025/1085.
//! - Anemoi: C. Bouvier, P. Briaud, P. Chaidos, L. Perrin, R. Salen,
//!   V. Velichkov, D. Willems, "New Design Techniques for Efficient
//!   Arithmetization-Oriented Hash Functions: Anemoi Permutations and
//!   Jive Compression Mode", ePrint 2022/840, CRYPTO 2023.
//!
//! The crate signs and verifies. The stack, bottom up: the Goldilocks
//! field and the Anemoi permutation; the one-way function and key pair;
//! the RegRounds arithmetization; a sponge transcript and Jive-compressed
//! Merkle trees; the degree-enforcing commitment; the polynomial IOP; and
//! `sign`/`verify` on top. See `notes/capss-spec.md`.
//!
//! Two things to be clear about. There are **no published test vectors
//! for CAPSS**, and this implementation is deliberately not byte-
//! compatible with the reference C build (see `anemoi` and `transcript`
//! for the specific deviations), so nothing external confirms it — the
//! tests show self-consistency and that forged witnesses are rejected,
//! and no more. And the `piop` module's soundness argument is a heuristic
//! written down in that module's header, not a proof; `piop::Parameters`
//! records which numbers come from the paper and which were picked here.
//!
//! Note that CAPSS is **not** MPC-in-the-head, however often it is
//! described that way. It is SmallWood: a hash-based polynomial
//! commitment stack in the Ligero lineage. There are no parties, no
//! repetitions, and no Beaver triples anywhere in it.
//!
//! The permutation is the only assumption. It supplies all three
//! primitives — the one-way function (truncated), the XOF (sponge mode),
//! and Merkle compression (Jive) — which is what gives CAPSS its "zero
//! security gap" property.

pub mod anemoi;
pub mod decs;
pub mod field;
pub mod keys;
pub mod merkle;
pub mod pacs;
pub mod piop;
pub mod sig;
pub mod transcript;
