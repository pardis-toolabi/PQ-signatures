//! CAPSS: a SNARK-friendly post-quantum signature framework
//! (IACR ePrint 2025/061).
//!
//! **Incomplete — this crate cannot sign or verify yet.** What is here:
//! the Goldilocks field, the Anemoi permutation, the one-way function and
//! key pair, the RegRounds arithmetization, a sponge transcript, and
//! Jive-compressed Merkle trees. What is missing: the DECS/LVCS/PCS/PIOP
//! stack that turns the arithmetization into a proof, and the signing and
//! verification algorithms on top of it. See `notes/capss-spec.md`.
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
pub mod field;
pub mod keys;
pub mod merkle;
pub mod pacs;
pub mod transcript;
