//! Parameter sets and domain construction.
//!
//! The concrete Loquat-128 numbers come from the paper's Table 3 and the
//! authors' reference implementation (`Setup.py`), since several of them
//! appear only in the code.

use crate::field::{subgroup_generator, Fp, Fp2};
use crate::transcript::Transcript;

#[derive(Clone)]
pub struct Params {
    /// Number of public indices in the parameter set.
    pub l: usize,
    /// Total residuosity symbols checked per signature.
    pub b: usize,
    /// Symbols per parallel instance.
    pub m: usize,
    /// Number of parallel instances; `m * n == b`.
    pub n: usize,
    /// `|H| = 2m`, the sumcheck domain.
    pub h_size: usize,
    pub u_log: u32,
    /// `|U|`, the Reed-Solomon evaluation domain.
    pub u_size: usize,
    /// FRI localisation: each round folds `2^eta` points into one.
    pub eta: u32,
    /// FRI query count.
    pub kappa: usize,
    /// FRI folding rounds.
    pub rounds: usize,
    /// `rho_star * |U|` — the degree bound every codeword is lifted to.
    pub rate_numerator: usize,
    /// Merkle cap width, as a power of two.
    pub cap_log: u32,
    /// Multiplicative shift defining `H = {shift * w^i}`.
    pub h_shift: Fp2,
    /// The public indices `I_1..I_L`.
    pub indices: Vec<Fp>,
}

/// Builds a coset shift guaranteed to be disjoint from `U`.
///
/// `U` holds elements whose order divides a power of two. Raising any
/// element to `2^128` kills its entire 2-power component, leaving
/// something of odd order. Any non-identity element of odd order therefore
/// cannot sit in `U`, and neither can `shift * w^i` for `w` in a 2-power
/// subgroup. That is exactly the `H ∩ U = ∅` condition the protocol needs.
fn odd_order_shift() -> Fp2 {
    let mut candidate = Fp2::new(Fp::new(3), Fp::new(1));
    loop {
        let mut shift = candidate;
        for _ in 0..128 {
            shift = shift.square();
        }
        if shift != Fp2::ONE && !shift.is_zero() {
            return shift;
        }
        candidate = candidate + Fp2::ONE;
    }
}

/// Derives the `L` public indices from a fixed seed.
///
/// The paper only says `I_l <- F_p` at random and leaves the derivation
/// open; storing them outright would cost 512 KB. Deriving them from a
/// published seed gives the same distribution while keeping the public
/// parameters to one string, and lets anyone recompute them.
fn derive_indices(count: usize) -> Vec<Fp> {
    let mut transcript = Transcript::new(b"loquat-public-indices");
    transcript.absorb_bytes(b"count", &(count as u64).to_le_bytes());
    transcript.challenge_fp_vec(b"I", count)
}

impl Params {
    /// The paper's Loquat-128 set (conjectured FRI soundness).
    pub fn loquat_128() -> Params {
        Params::build(32768, 128, 32, 12, 32, 4)
    }

    /// A deliberately small set, so tests run in milliseconds instead of
    /// seconds. Not secure; it exists to exercise the same code paths.
    pub fn testing() -> Params {
        Params::build(256, 8, 4, 9, 4, 2)
    }

    fn build(l: usize, b: usize, m: usize, u_log: u32, kappa: usize, rounds: usize) -> Params {
        let eta = 2u32;
        let n = b / m;
        let h_size = 2 * m;
        let u_size = 1usize << u_log;
        // rho* = 1/16 throughout, so the shared degree bound is |U|/16.
        let rate_numerator = u_size / 16;

        assert_eq!(m * n, b, "m * n must equal B");
        assert!(
            4 * m + kappa * (1 << eta) <= rate_numerator,
            "degree budget {} exceeds the rate bound {rate_numerator}",
            4 * m + kappa * (1 << eta)
        );
        assert!(
            rounds as u32 * eta <= u_log - 4,
            "too many folding rounds for this domain"
        );

        Params {
            l,
            b,
            m,
            n,
            h_size,
            u_log,
            u_size,
            eta,
            kappa,
            rounds,
            rate_numerator,
            // floor(log2(kappa)) - 1; the paper's Fractal-style formula is
            // ceil(log2(kappa) - 1), which differs when kappa is not a
            // power of two (e.g. Loquat-80's kappa = 20: 3 here vs 4).
            // Equal for both parameter sets shipped.
            cap_log: (kappa.ilog2()).saturating_sub(1),
            h_shift: odd_order_shift(),
            indices: derive_indices(l),
        }
    }

    pub fn h_log(&self) -> u32 {
        self.h_size.ilog2()
    }

    /// Generator of the subgroup underlying `H`.
    pub fn h_generator(&self) -> Fp2 {
        subgroup_generator(self.h_log())
    }

    /// Generator of `U` itself (an unshifted subgroup).
    pub fn u_generator(&self) -> Fp2 {
        subgroup_generator(self.u_log)
    }

    /// `Z_H(x) = x^|H| - h_shift^|H|`.
    pub fn vanishing_offset(&self) -> Fp2 {
        self.h_shift.pow(self.h_size as u128)
    }

    /// Degree bounds of the four committed codeword families, in the order
    /// they are batched: witness, ZK mask, sumcheck quotient, rational
    /// constraint.
    pub fn degree_bounds(&self) -> [usize; 4] {
        let masked = self.kappa * (1 << self.eta);
        [
            2 * self.m + masked + 1, // c'_j
            4 * self.m + masked,     // s
            2 * self.m + masked,     // h
            2 * self.m - 1,          // p
        ]
    }

    /// Number of Merkle leaves per codeword: coset points are hashed
    /// together, so there are `|U| / 2^eta` of them.
    pub fn leaf_count(&self) -> usize {
        self.u_size >> self.eta
    }

    /// Size of the folded domain after `round` FRI rounds.
    pub fn domain_size_at(&self, round: usize) -> usize {
        self.u_size >> (self.eta * round as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loquat_128_matches_the_paper() {
        let p = Params::loquat_128();
        assert_eq!(p.l, 32768);
        assert_eq!(p.b, 128);
        assert_eq!(p.m, 32);
        assert_eq!(p.n, 4);
        assert_eq!(p.h_size, 64);
        assert_eq!(p.u_size, 4096);
        assert_eq!(p.kappa, 32);
        assert_eq!(p.rounds, 4);
        // rho* |U| = 256, and the degree budget saturates it exactly.
        assert_eq!(p.rate_numerator, 256);
        assert_eq!(4 * p.m + p.kappa * (1 << p.eta), 256);
        // Final FRI domain: 4096 >> 8 = 16, so one coefficient is sent.
        assert_eq!(p.domain_size_at(4), 16);
        assert_eq!(p.rate_numerator * p.domain_size_at(4) / p.u_size, 1);
        // Tree cap from the paper: ceil(log2(kappa) - 1) = 4.
        assert_eq!(p.cap_log, 4);
        assert_eq!(p.leaf_count(), 1024);
    }

    #[test]
    fn degree_bounds_fit_under_the_rate() {
        for p in [Params::testing(), Params::loquat_128()] {
            for bound in p.degree_bounds() {
                assert!(bound <= p.rate_numerator, "bound {bound} exceeds rate");
            }
        }
    }

    #[test]
    fn h_and_u_are_disjoint() {
        let p = Params::testing();
        // Collect U.
        let mut u = std::collections::HashSet::new();
        let mut point = Fp2::ONE;
        for _ in 0..p.u_size {
            u.insert((point.c0.value(), point.c1.value()));
            point = point * p.u_generator();
        }
        // No element of H may appear in U.
        let mut h_point = p.h_shift;
        for _ in 0..p.h_size {
            assert!(!u.contains(&(h_point.c0.value(), h_point.c1.value())));
            h_point = h_point * p.h_generator();
        }
    }

    #[test]
    fn indices_are_deterministic_and_varied() {
        let a = derive_indices(64);
        let b = derive_indices(64);
        assert_eq!(a, b, "public parameters must be reproducible");
        let distinct: std::collections::HashSet<_> = a.iter().map(|f| f.value()).collect();
        assert_eq!(distinct.len(), 64);
    }
}
