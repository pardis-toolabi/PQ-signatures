//! Arithmetic over `F_p` with `p = 2^127 - 1`, and its quadratic extension
//! `F_p2 = F_p[i]/(i^2 + 1)`.
//!
//! Two facts drive this whole design:
//!
//! 1. `p` is a Mersenne prime, so reduction after a multiply is a shift and
//!    an add rather than a division.
//! 2. `p - 1 = 2 * (2^126 - 1)` is only divisible by 2 once, so `F_p` has
//!    **no** power-of-two subgroups worth speaking of, and an FFT cannot
//!    run there. But `p + 1 = 2^127`, so `F_p2` has subgroups of order up
//!    to `2^128`. That is why Loquat does its polynomial work in the
//!    extension field even though the Legendre PRF itself lives in `F_p`.
//!
//! Reference: paper §6.1 "Choice of the field" (p = 2^127 - 1 as in
//! LegRoast; F_p2 for its smooth multiplicative subgroups) and Algorithm 2
//! line 9, which fixes F = F_p2.

use std::ops::{Add, Mul, Neg, Sub};

pub const P: u128 = (1u128 << 127) - 1;
const MASK127: u128 = (1u128 << 127) - 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, PartialOrd, Ord, Hash)]
pub struct Fp(u128);

/// Splits a 128x128 product into its high and low 128-bit halves.
fn wide_mul(a: u128, b: u128) -> (u128, u128) {
    let (a_lo, a_hi) = (a as u64 as u128, a >> 64);
    let (b_lo, b_hi) = (b as u64 as u128, b >> 64);

    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;

    let mut lo = ll;
    let mut hi = hh;

    let (sum, carry) = lo.overflowing_add(lh << 64);
    lo = sum;
    hi += (lh >> 64) + carry as u128;

    let (sum, carry) = lo.overflowing_add(hl << 64);
    lo = sum;
    hi += (hl >> 64) + carry as u128;

    (hi, lo)
}

/// Folds a value into `[0, P)` using `2^127 = 1 (mod P)`.
fn fold(mut value: u128) -> u128 {
    value = (value & MASK127) + (value >> 127);
    value = (value & MASK127) + (value >> 127);
    if value >= P {
        value -= P;
    }
    value
}

impl Fp {
    pub const ZERO: Fp = Fp(0);
    pub const ONE: Fp = Fp(1);

    pub fn new(value: u128) -> Fp {
        Fp(fold(value))
    }

    pub fn value(self) -> u128 {
        self.0
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub fn square(self) -> Fp {
        self * self
    }

    pub fn pow(self, exponent: u128) -> Fp {
        let mut result = Fp::ONE;
        let mut base = self;
        let mut e = exponent;
        while e > 0 {
            if e & 1 == 1 {
                result = result * base;
            }
            base = base.square();
            e >>= 1;
        }
        result
    }

    /// Inverse via Fermat: `a^(p-2) = a^-1`.
    pub fn inverse(self) -> Option<Fp> {
        if self.is_zero() {
            None
        } else {
            Some(self.pow(P - 2))
        }
    }

    /// The Legendre symbol as a bit, matching the paper's
    /// `L_0(a) = (1 - (a|p)) / 2`: **1 when `a` is a non-residue**, 0 when
    /// it is a residue (and 0 for `a = 0`, which is why signing rejects
    /// zero values).
    pub fn legendre_bit(self) -> u8 {
        if self.is_zero() {
            return 0;
        }
        // a^((p-1)/2) is +1 for residues and -1 for non-residues.
        if self.pow((P - 1) / 2) == Fp::ONE {
            0
        } else {
            1
        }
    }
}

impl Add for Fp {
    type Output = Fp;
    fn add(self, other: Fp) -> Fp {
        // Both are < 2^127, so the sum fits in u128 and needs at most one
        // conditional subtraction.
        let sum = self.0 + other.0;
        Fp(if sum >= P { sum - P } else { sum })
    }
}

impl Sub for Fp {
    type Output = Fp;
    fn sub(self, other: Fp) -> Fp {
        Fp(if self.0 >= other.0 { self.0 - other.0 } else { self.0 + P - other.0 })
    }
}

impl Neg for Fp {
    type Output = Fp;
    fn neg(self) -> Fp {
        Fp(if self.0 == 0 { 0 } else { P - self.0 })
    }
}

impl Mul for Fp {
    type Output = Fp;
    fn mul(self, other: Fp) -> Fp {
        let (hi, lo) = wide_mul(self.0, other.0);
        // value = hi * 2^128 + lo = a * 2^127 + b, and 2^127 = 1 (mod P).
        let a = (hi << 1) | (lo >> 127);
        let b = lo & MASK127;
        Fp(fold(a + b))
    }
}

/// `F_p2 = F_p[i]/(i^2 + 1)`, written `c0 + c1*i`.
///
/// `-1` is a valid non-residue because `p = 3 (mod 4)`, so this really is
/// a field rather than a ring with zero divisors.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl Fp2 {
    pub const ZERO: Fp2 = Fp2 { c0: Fp::ZERO, c1: Fp::ZERO };
    pub const ONE: Fp2 = Fp2 { c0: Fp::ONE, c1: Fp::ZERO };

    pub fn new(c0: Fp, c1: Fp) -> Fp2 {
        Fp2 { c0, c1 }
    }

    /// Lifts an `F_p` element into the extension. Loquat commits to values
    /// that live in `F_p` but does its polynomial arithmetic here.
    pub fn from_base(value: Fp) -> Fp2 {
        Fp2 { c0: value, c1: Fp::ZERO }
    }

    pub fn is_zero(self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    pub fn conjugate(self) -> Fp2 {
        Fp2 { c0: self.c0, c1: -self.c1 }
    }

    /// `norm(a + bi) = a^2 + b^2`, always an element of `F_p`.
    pub fn norm(self) -> Fp {
        self.c0.square() + self.c1.square()
    }

    pub fn square(self) -> Fp2 {
        self * self
    }

    pub fn pow(self, exponent: u128) -> Fp2 {
        let mut result = Fp2::ONE;
        let mut base = self;
        let mut e = exponent;
        while e > 0 {
            if e & 1 == 1 {
                result = result * base;
            }
            base = base.square();
            e >>= 1;
        }
        result
    }

    /// Raises to a power given as bytes, big-endian. Needed because the
    /// exponents used to find subgroup generators exceed 128 bits.
    pub fn pow_bytes(self, exponent_be: &[u8]) -> Fp2 {
        let mut result = Fp2::ONE;
        for byte in exponent_be {
            for bit in (0..8).rev() {
                result = result.square();
                if (byte >> bit) & 1 == 1 {
                    result = result * self;
                }
            }
        }
        result
    }

    /// `1/(a + bi) = (a - bi) / (a^2 + b^2)`.
    pub fn inverse(self) -> Option<Fp2> {
        let norm_inverse = self.norm().inverse()?;
        let conjugate = self.conjugate();
        Some(Fp2 { c0: conjugate.c0 * norm_inverse, c1: conjugate.c1 * norm_inverse })
    }
}

impl Add for Fp2 {
    type Output = Fp2;
    fn add(self, other: Fp2) -> Fp2 {
        Fp2 { c0: self.c0 + other.c0, c1: self.c1 + other.c1 }
    }
}

impl Sub for Fp2 {
    type Output = Fp2;
    fn sub(self, other: Fp2) -> Fp2 {
        Fp2 { c0: self.c0 - other.c0, c1: self.c1 - other.c1 }
    }
}

impl Neg for Fp2 {
    type Output = Fp2;
    fn neg(self) -> Fp2 {
        Fp2 { c0: -self.c0, c1: -self.c1 }
    }
}

impl Mul for Fp2 {
    type Output = Fp2;
    fn mul(self, other: Fp2) -> Fp2 {
        // (a + bi)(c + di) = (ac - bd) + (ad + bc)i, using i^2 = -1.
        Fp2 {
            c0: self.c0 * other.c0 - self.c1 * other.c1,
            c1: self.c0 * other.c1 + self.c1 * other.c0,
        }
    }
}

/// `p^2 - 1 = 2^128 * (2^126 - 1)`, so the odd part is `2^126 - 1`.
/// Raising any element to this power lands in the 2^128-order subgroup.
const ODD_PART: u128 = (1u128 << 126) - 1;

/// Returns an element of multiplicative order exactly `2^128`.
///
/// This avoids having to factor `p^2 - 1`: raise a candidate to the odd
/// part of the group order, which forces the result into the 2-power
/// subgroup, then confirm the order is maximal by checking that squaring
/// it 127 times has not yet reached one.
pub fn two_adic_generator_root() -> Fp2 {
    let mut candidate = Fp2::new(Fp::new(2), Fp::new(1));
    loop {
        let element = candidate.pow(ODD_PART);
        if !element.is_zero() {
            // Order divides 2^128; it is exactly 2^128 unless squaring 127
            // times already gives one.
            let mut check = element;
            for _ in 0..127 {
                check = check.square();
            }
            if check != Fp2::ONE {
                return element;
            }
        }
        candidate = candidate + Fp2::ONE;
    }
}

/// Returns a generator of the subgroup of order `2^log_size`.
pub fn subgroup_generator(log_size: u32) -> Fp2 {
    assert!(log_size <= 128, "no subgroup of order 2^{log_size} exists");
    let mut generator = two_adic_generator_root();
    for _ in 0..(128 - log_size) {
        generator = generator.square();
    }
    generator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_field_arithmetic() {
        let a = Fp::new(P - 1);
        assert_eq!(a + Fp::ONE, Fp::ZERO);
        assert_eq!(Fp::ZERO - Fp::ONE, Fp::new(P - 1));
        assert_eq!(Fp::new(P), Fp::ZERO, "P must reduce to zero");
    }

    #[test]
    fn multiplication_matches_schoolbook_on_small_values() {
        for a in 1..50u128 {
            for b in 1..50u128 {
                assert_eq!(Fp::new(a) * Fp::new(b), Fp::new(a * b));
            }
        }
    }

    #[test]
    fn multiplication_wraps_correctly_at_the_top() {
        // (p-1)^2 = p^2 - 2p + 1 = 1 (mod p)
        let a = Fp::new(P - 1);
        assert_eq!(a * a, Fp::ONE);
        // 2^127 = 1 (mod p), so 2^126 * 2 = 1
        assert_eq!(Fp::new(1u128 << 126) * Fp::new(2), Fp::ONE);
    }

    #[test]
    fn inverses_round_trip() {
        for value in [1u128, 2, 3, 12345, (1 << 100) + 7, P - 2] {
            let a = Fp::new(value);
            assert_eq!(a * a.inverse().unwrap(), Fp::ONE);
        }
        assert!(Fp::ZERO.inverse().is_none());
    }

    #[test]
    fn legendre_bit_matches_squares() {
        // Any non-zero square is a residue, so its bit must be 0.
        for value in 1..200u128 {
            let square = Fp::new(value).square();
            assert_eq!(square.legendre_bit(), 0, "{value}^2 should be a residue");
        }
        // p = 3 (mod 4) means -1 is a non-residue.
        assert_eq!((-Fp::ONE).legendre_bit(), 1);
    }

    #[test]
    fn legendre_is_multiplicative() {
        // L(ab) = L(a) + L(b) over Z_2 — the property the whole scheme rests on.
        for a in 2..40u128 {
            for b in 2..40u128 {
                let (x, y) = (Fp::new(a), Fp::new(b));
                let combined = (x * y).legendre_bit();
                assert_eq!(combined, x.legendre_bit() ^ y.legendre_bit());
            }
        }
    }

    #[test]
    fn extension_field_arithmetic() {
        let i = Fp2::new(Fp::ZERO, Fp::ONE);
        assert_eq!(i * i, -Fp2::ONE, "i^2 must be -1");

        let a = Fp2::new(Fp::new(3), Fp::new(5));
        assert_eq!(a * a.inverse().unwrap(), Fp2::ONE);
        assert_eq!(a - a, Fp2::ZERO);
    }

    #[test]
    fn extension_inverse_round_trips_widely() {
        for c0 in 0..15u128 {
            for c1 in 0..15u128 {
                let a = Fp2::new(Fp::new(c0), Fp::new(c1));
                if a.is_zero() {
                    assert!(a.inverse().is_none());
                } else {
                    assert_eq!(a * a.inverse().unwrap(), Fp2::ONE);
                }
            }
        }
    }

    #[test]
    fn two_power_subgroups_have_the_right_order() {
        // This is the property that makes the FFT possible at all.
        for log_size in [1u32, 6, 12, 13] {
            let generator = subgroup_generator(log_size);
            let size = 1u128 << log_size;

            let mut power = generator;
            for _ in 1..log_size {
                power = power.square();
            }
            assert_ne!(power, Fp2::ONE, "order must not be smaller than 2^{log_size}");
            assert_eq!(power.square(), Fp2::ONE, "order must be exactly 2^{log_size}");

            // Walking the whole subgroup must return to one, and not before.
            let mut walk = Fp2::ONE;
            for _ in 0..size {
                walk = walk * generator;
            }
            assert_eq!(walk, Fp2::ONE);
        }
    }

    #[test]
    fn subgroup_elements_are_distinct() {
        let log_size = 6;
        let generator = subgroup_generator(log_size);
        let mut seen = std::collections::HashSet::new();
        let mut element = Fp2::ONE;
        for _ in 0..(1 << log_size) {
            assert!(seen.insert((element.c0.value(), element.c1.value())));
            element = element * generator;
        }
    }
}
