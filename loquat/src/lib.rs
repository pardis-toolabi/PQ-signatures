//! Loquat: a SNARK-friendly post-quantum signature built on the Legendre
//! PRF (IACR ePrint 2024/868).
//!
//! Work in progress. See README.md for exactly which parts are
//! implemented and validated, and which are not.

pub mod field;
pub mod fri;
pub mod keys;
pub mod merkle;
pub mod params;
pub mod poly;
pub mod sig;
pub mod transcript;
