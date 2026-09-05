//! Arithmetic over the Goldilocks field, `p = 2^64 - 2^32 + 1`.
//!
//! Reference: the field was popularised (and named) by the Plonky2 proof
//! system — Polygon Zero Team, "Plonky2: Fast Recursive Arguments with
//! PLONK and FRI" (2022), which credits the modulus to Hamish Ivey-Law.
//! CAPSS (ePrint 2025/061, Section 6) benchmarks its C implementation
//! over this field.
//!
//! The CAPSS paper's headline parameter sets use the BN254 scalar field,
//! but its C reference implementation ships a Goldilocks build (Anemoi,
//! `alpha = 7`, `t = 8`, 11 rounds) and the paper reports Goldilocks as
//! roughly 25x faster than BN254. We follow the C build for two reasons:
//! the speed, and the fact that 64-bit modular arithmetic is far easier
//! to get right than 256-bit — every multiply here fits in a `u128`, so
//! there is no hand-rolled bignum to be subtly wrong.
//!
//! The price is that at 64 bits the soundness margins are thinner: the
//! paper notes that with powers batching `sec_fpp` drops to 114 bits over
//! Goldilocks, so a Goldilocks build needs `RLCChallengeType::HYBRID` and
//! PIOP-opening grinding. That is a concern for the proof system layer,
//! not for this file.
//!
//! ## Why the S-box exponent is 7
//!
//! `x^alpha` is a bijection on `F_p` exactly when `gcd(alpha, p - 1) = 1`.
//! Here
//!
//! ```text
//! p - 1 = 2^64 - 2^32 = 2^32 * (2^32 - 1)
//!       = 2^32 * 3 * 5 * 17 * 257 * 65537
//! ```
//!
//! so `alpha = 3` does **not** work (3 divides `2^32 - 1`), and neither
//! does `alpha = 5` (5 divides it too). Both are the usual cheap choices
//! and both are unavailable here. The smallest usable odd exponent is
//! `alpha = 7`: `2^32 - 1 = 3 * 5 * 17 * 257 * 65537` has no factor of 7,
//! and `2^32` is a power of two, so `gcd(7, p - 1) = 1`. That is exactly
//! why the reference C build uses `alpha = 7` while the BN254 parameter
//! sets in the paper use 3 or 5. The factorisation above is checked in
//! `p_minus_one_factorisation_is_as_documented`.

use std::ops::{Add, Mul, Neg, Sub};

/// `p = 2^64 - 2^32 + 1`.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// `2^64 - p = 2^32 - 1`. Every reduction step below is an application of
/// `2^64 = EPSILON (mod p)`.
const EPSILON: u64 = 0xFFFF_FFFF;

/// The S-box exponent. See the module comment for why it is not 3 or 5.
pub const ALPHA: u64 = 7;

/// `alpha^-1 mod (p - 1)`, so `(x^alpha)^ALPHA_INVERSE = x` for every `x`.
///
/// Derived as `(4 * (p - 1) + 1) / 7`, since `p - 1 = 5 (mod 7)` and
/// `4 * 5 = 1 (mod 7)`. Checked in `alpha_inverse_undoes_the_sbox`.
pub const ALPHA_INVERSE: u64 = 10_540_996_611_094_048_183;

/// Smallest generator of `F_p^*`. Anemoi's Flystel needs one for `beta`,
/// and it is the standard choice for Goldilocks. Checked in
/// `seven_generates_the_multiplicative_group`.
pub const GENERATOR: u64 = 7;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, PartialOrd, Ord, Hash)]
pub struct Fp(u64);

/// Reduces a 128-bit product into `[0, p)`.
///
/// Write the product as `hi * 2^64 + lo`, then split `hi` into its own
/// halves `hi = hi_hi * 2^32 + hi_lo`. Two identities do all the work:
/// `2^64 = 2^32 - 1 (mod p)` and `2^96 = -1 (mod p)`. So the `hi_hi` part
/// is *subtracted* and the `hi_lo` part is multiplied by `2^32 - 1`,
/// which is a shift and a subtract rather than a real multiply. This is
/// the standard Goldilocks reduction; it replaces a 128-by-64 division
/// with a handful of adds.
fn reduce128(value: u128) -> u64 {
    let low = value as u64;
    let high = (value >> 64) as u64;
    let (high_high, high_low) = (high >> 32, high & EPSILON);

    // 2^96 = -1 (mod p), so this term is subtracted. A borrow means we
    // implicitly added 2^64, corrected by subtracting EPSILON.
    let (mut folded, borrow) = low.overflowing_sub(high_high);
    if borrow {
        folded = folded.wrapping_sub(EPSILON);
    }

    // 2^64 = EPSILON (mod p). The product fits in u64 because
    // high_low < 2^32 and EPSILON < 2^32.
    let (sum, carry) = folded.overflowing_add(high_low * EPSILON);
    let mut result = if carry { sum.wrapping_add(EPSILON) } else { sum };

    // Anything left over is below 2^64, and 2^64 - p = 2^32 - 1, so one
    // subtraction is always enough.
    if result >= P {
        result -= P;
    }
    result
}

impl Fp {
    pub const ZERO: Fp = Fp(0);
    pub const ONE: Fp = Fp(1);

    /// `u64` values in `[p, 2^64)` exist, so this cannot just wrap the
    /// input — but the gap is only `2^32 - 1` wide, so one subtraction
    /// suffices.
    pub fn new(value: u64) -> Fp {
        Fp(if value >= P { value - P } else { value })
    }

    pub fn from_u128(value: u128) -> Fp {
        Fp(reduce128(value))
    }

    /// Builds a field element from 16 bytes of randomness, little-endian.
    ///
    /// Reducing 128 uniform bits into a 64-bit field leaves a bias below
    /// `2^-64`, which is why this takes 16 bytes rather than 8.
    pub fn from_random_bytes(bytes: [u8; 16]) -> Fp {
        Fp::from_u128(u128::from_le_bytes(bytes))
    }

    pub fn value(self) -> u64 {
        self.0
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub fn square(self) -> Fp {
        self * self
    }

    pub fn pow(self, exponent: u64) -> Fp {
        let mut result = Fp::ONE;
        let mut base = self;
        let mut remaining = exponent;
        while remaining > 0 {
            if remaining & 1 == 1 {
                result = result * base;
            }
            base = base.square();
            remaining >>= 1;
        }
        result
    }

    /// Inverse via Fermat: `a^(p-2) = a^-1`.
    ///
    /// An addition chain would be about a third faster, but this is not
    /// on any hot path — Anemoi's inverse S-box uses `pow`, not this.
    pub fn inverse(self) -> Option<Fp> {
        if self.is_zero() {
            None
        } else {
            Some(self.pow(P - 2))
        }
    }
}

impl Add for Fp {
    type Output = Fp;
    fn add(self, other: Fp) -> Fp {
        // Both are < p < 2^63.99, so the sum can overflow u64; the
        // overflowing form handles it via 2^64 = EPSILON (mod p).
        let (sum, carry) = self.0.overflowing_add(other.0);
        let mut result = if carry { sum.wrapping_add(EPSILON) } else { sum };
        if result >= P {
            result -= P;
        }
        Fp(result)
    }
}

impl Sub for Fp {
    type Output = Fp;
    fn sub(self, other: Fp) -> Fp {
        // `self.0 + P - other.0` would overflow u64, so borrow instead:
        // the wrapped difference is short by exactly 2^64, and adding P
        // wraps a second time to leave the right value.
        let (difference, borrow) = self.0.overflowing_sub(other.0);
        Fp(if borrow { difference.wrapping_add(P) } else { difference })
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
        Fp(reduce128(self.0 as u128 * other.0 as u128))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// splitmix64, used only to generate test inputs.
    fn pseudorandom(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    #[test]
    fn addition_wraps_at_the_modulus() {
        assert_eq!(Fp::new(P - 1) + Fp::ONE, Fp::ZERO);
        assert_eq!(Fp::ZERO - Fp::ONE, Fp::new(P - 1));
        assert_eq!(Fp::new(P), Fp::ZERO, "p must reduce to zero");
        assert_eq!(Fp::new(P + 5), Fp::new(5));
        // u64::MAX = p + (2^32 - 2)
        assert_eq!(Fp::new(u64::MAX), Fp::new(EPSILON - 1));
        // The one case where the addition carry path fires.
        assert_eq!(Fp::new(P - 1) + Fp::new(P - 1), Fp::new(P - 2));
    }

    #[test]
    fn negation_round_trips() {
        assert_eq!(-Fp::ZERO, Fp::ZERO);
        for value in [1u64, 2, 1 << 40, P - 1] {
            let a = Fp::new(value);
            assert_eq!(a + (-a), Fp::ZERO);
            assert_eq!(-(-a), a);
        }
    }

    #[test]
    fn multiplication_matches_schoolbook_on_small_values() {
        for a in 1..60u64 {
            for b in 1..60u64 {
                assert_eq!(Fp::new(a) * Fp::new(b), Fp::new(a * b));
            }
        }
    }

    #[test]
    fn multiplication_matches_a_naive_reference() {
        // The fast reduction is the one place a subtle bug would hide, so
        // check it against a plain u128 remainder on many values.
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..20_000 {
            let a = Fp::new(pseudorandom(&mut state) % P);
            let b = Fp::new(pseudorandom(&mut state) % P);
            let expected = (a.value() as u128 * b.value() as u128) % P as u128;
            assert_eq!((a * b).value() as u128, expected);
        }
        // Plus the extremes, which random sampling will not hit.
        for a in [0u64, 1, 2, EPSILON, 1 << 32, P - 2, P - 1] {
            for b in [0u64, 1, 2, EPSILON, 1 << 32, P - 2, P - 1] {
                let expected = (a as u128 * b as u128) % P as u128;
                assert_eq!((Fp::new(a) * Fp::new(b)).value() as u128, expected);
            }
        }
    }

    #[test]
    fn multiplication_wraps_correctly_at_the_top() {
        // (p-1)^2 = p^2 - 2p + 1 = 1 (mod p)
        assert_eq!(Fp::new(P - 1).square(), Fp::ONE);
        // 2^64 = 2^32 - 1 (mod p), the identity the reduction is built on.
        assert_eq!(Fp::new(1 << 32).square(), Fp::new(EPSILON));
        // 2^96 = -1 (mod p)
        assert_eq!(Fp::new(1 << 32) * Fp::new(1 << 32) * Fp::new(1 << 32), -Fp::ONE);
        // and so 2^192 = 1 (mod p)
        assert_eq!(Fp::new(2).pow(192), Fp::ONE);
    }

    #[test]
    fn inverses_round_trip() {
        for value in [1u64, 2, 3, 7, 12345, 1 << 32, EPSILON, P - 2, P - 1] {
            let a = Fp::new(value);
            assert_eq!(a * a.inverse().unwrap(), Fp::ONE);
        }
        let mut state = 0xDEAD_BEEF_CAFE_F00Du64;
        for _ in 0..500 {
            let a = Fp::new(pseudorandom(&mut state) % P);
            if let Some(inverse) = a.inverse() {
                assert_eq!(a * inverse, Fp::ONE);
            } else {
                assert!(a.is_zero());
            }
        }
        assert!(Fp::ZERO.inverse().is_none());
    }

    #[test]
    fn fermat_holds() {
        let mut state = 99u64;
        for _ in 0..200 {
            let a = Fp::new(pseudorandom(&mut state) % P);
            if !a.is_zero() {
                assert_eq!(a.pow(P - 1), Fp::ONE);
            }
        }
    }

    #[test]
    fn p_minus_one_factorisation_is_as_documented() {
        // p - 1 = 2^32 * 3 * 5 * 17 * 257 * 65537. This is the fact that
        // rules out alpha = 3 and alpha = 5.
        let product: u64 = (1u64 << 32) * 3 * 5 * 17 * 257 * 65537;
        assert_eq!(product, P - 1);
        assert_eq!((P - 1) % 3, 0, "alpha = 3 is not coprime to p - 1");
        assert_eq!((P - 1) % 5, 0, "alpha = 5 is not coprime to p - 1");
        assert_ne!((P - 1) % 7, 0, "alpha = 7 must be coprime to p - 1");
    }

    #[test]
    fn alpha_inverse_undoes_the_sbox() {
        assert_eq!((ALPHA as u128 * ALPHA_INVERSE as u128) % (P - 1) as u128, 1);
        let mut state = 0xA5A5_5A5A_A5A5_5A5Au64;
        for _ in 0..300 {
            let a = Fp::new(pseudorandom(&mut state) % P);
            assert_eq!(a.pow(ALPHA).pow(ALPHA_INVERSE), a);
            assert_eq!(a.pow(ALPHA_INVERSE).pow(ALPHA), a);
        }
    }

    #[test]
    fn sbox_is_a_bijection_on_a_sample() {
        // Follows from gcd(7, p - 1) = 1; distinct inputs must map to
        // distinct outputs.
        let mut inputs: std::collections::HashSet<Fp> = (0..5_000u64).map(Fp::new).collect();
        let mut state = 7u64;
        for _ in 0..5_000 {
            inputs.insert(Fp::new(pseudorandom(&mut state) % P));
        }
        let images: std::collections::HashSet<Fp> = inputs.iter().map(|a| a.pow(ALPHA)).collect();
        assert_eq!(images.len(), inputs.len(), "x^7 must not collide");
    }

    #[test]
    fn seven_generates_the_multiplicative_group() {
        // A generator has order p - 1, so g^((p-1)/q) != 1 for every prime
        // factor q. Anemoi's beta is this generator.
        let generator = Fp::new(GENERATOR);
        for prime in [2u64, 3, 5, 17, 257, 65537] {
            assert_ne!(generator.pow((P - 1) / prime), Fp::ONE, "order divides (p-1)/{prime}");
        }
    }

    #[test]
    fn distributivity_and_associativity_hold() {
        let mut state = 0x0F0F_0F0F_1234_5678u64;
        for _ in 0..2_000 {
            let a = Fp::new(pseudorandom(&mut state) % P);
            let b = Fp::new(pseudorandom(&mut state) % P);
            let c = Fp::new(pseudorandom(&mut state) % P);
            assert_eq!(a * (b + c), a * b + a * c);
            assert_eq!((a * b) * c, a * (b * c));
            assert_eq!((a + b) + c, a + (b + c));
            assert_eq!(a - b, -(b - a));
        }
    }

    #[test]
    fn random_bytes_land_in_the_field() {
        let mut state = 0x1111_2222_3333_4444u64;
        for _ in 0..1_000 {
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&pseudorandom(&mut state).to_le_bytes());
            bytes[8..].copy_from_slice(&pseudorandom(&mut state).to_le_bytes());
            assert!(Fp::from_random_bytes(bytes).value() < P);
        }
        assert_eq!(Fp::from_random_bytes([0u8; 16]), Fp::ZERO);
    }
}
