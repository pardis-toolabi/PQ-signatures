//! CAPSS: a SNARK-friendly post-quantum signature framework
//! (IACR ePrint 2025/061).
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
