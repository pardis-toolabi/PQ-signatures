//! The one-way function and the key pair.
//!
//! CAPSS keys are a single call to the permutation with part of the
//! input and part of the output pinned down:
//!
//! ```text
//! OWF(x) = Tr_{|y|}( P(iv, x) )
//!
//! sk = (pk, x)      x random
//! pk = (iv, y)      iv random, y = the truncated permutation output
//! ```
//!
//! ## What the security rests on
//!
//! Recovering `x` from `(iv, y)` is exactly the **CICO** problem —
//! constrained input, constrained output: find a permutation input whose
//! first `|iv|` elements are the given `iv` and whose output starts with
//! the given `y`. There is **no algebraic assumption underneath this**.
//! No Legendre PRF, no lattice, no code, no isogeny. The permutation is
//! the only thing being trusted, which is what the paper calls a "zero
//! security gap": the signature is as strong as the hash function it is
//! already committed to using everywhere else.
//!
//! That also means the security argument is only as good as the
//! permutation's resistance to algebraic attacks, and the round count is
//! chosen to make Groebner-basis solving of the CICO system infeasible.
//! Nothing in this file checks that; it is a property of `anemoi.rs`.

use crate::anemoi::{permute, WIDTH};
use crate::field::Fp;
use rand::RngCore;

/// `|iv|`, and by the paper's `|x| = |y| = |iv|` also the length of the
/// secret and of the truncated output.
///
/// The paper's formula is `ceil(lambda / log2 q)`, which for Goldilocks
/// at `lambda = 128` gives 2. We use 4, the CAPSS reference C build's
/// choice at `t = 8`, for two reasons:
///
/// - 2 is internally inconsistent at this state width. The paper also
///   says `x` is drawn from `F_q^{t - |iv|}`, so `|iv| = 2` would force
///   `|x| = 6`, contradicting `|x| = |iv|`. At `t = 8` the only value
///   satisfying both is `|iv| = |x| = |y| = t/2 = 4`.
/// - It is strictly more conservative. Four pinned elements at each end
///   is 256 bits of constraint rather than 128, so the CICO instance an
///   attacker faces has fewer free variables, not more.
///
/// The cost is nothing: the state is 8 elements either way.
pub const IV_SIZE: usize = 4;

/// `|x|`. The secret fills whatever the `iv` does not.
pub const SECRET_SIZE: usize = WIDTH - IV_SIZE;

/// `|y|`, the number of output elements kept.
pub const OUTPUT_SIZE: usize = IV_SIZE;

/// 4 field elements at 8 bytes each.
pub const SECRET_KEY_BYTES: usize = SECRET_SIZE * 8;

/// `iv` and `y` together, 8 field elements.
pub const PUBLIC_KEY_BYTES: usize = (IV_SIZE + OUTPUT_SIZE) * 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretKey {
    pub x: [Fp; SECRET_SIZE],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub iv: [Fp; IV_SIZE],
    pub y: [Fp; OUTPUT_SIZE],
}

/// The paper's `sk` carries `pk` alongside `x`, so a signer never has to
/// recompute the permutation just to know what it is proving about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

/// The permutation input `iv || x`, which is also the first column of
/// the PACS witness.
pub fn initial_state(iv: &[Fp; IV_SIZE], x: &[Fp; SECRET_SIZE]) -> [Fp; WIDTH] {
    let mut state = [Fp::ZERO; WIDTH];
    state[..IV_SIZE].copy_from_slice(iv);
    state[IV_SIZE..].copy_from_slice(x);
    state
}

/// `OWF(x) = Tr_{|y|}( P(iv, x) )`.
pub fn one_way_function(iv: &[Fp; IV_SIZE], x: &[Fp; SECRET_SIZE]) -> [Fp; OUTPUT_SIZE] {
    let mut state = initial_state(iv, x);
    permute(&mut state);
    state[..OUTPUT_SIZE].try_into().expect("the output is at least |y| long")
}

pub fn public_key_from(iv: &[Fp; IV_SIZE], secret: &SecretKey) -> PublicKey {
    PublicKey { iv: *iv, y: one_way_function(iv, &secret.x) }
}

/// Builds the pair implied by a given `(iv, x)`. Keygen is a pure
/// function of those two, which is what the tests lean on.
pub fn from_parts(iv: &[Fp; IV_SIZE], x: &[Fp; SECRET_SIZE]) -> KeyPair {
    let secret = SecretKey { x: *x };
    KeyPair { public: public_key_from(iv, &secret), secret }
}

fn random_field_element() -> Fp {
    // 128 bits reduced into a 64-bit field leaves a bias below 2^-64.
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    Fp::from_random_bytes(bytes)
}

/// Generates a key pair. Both `iv` and `x` are uniform; the paper puts
/// no structure on either.
pub fn generate() -> KeyPair {
    let mut iv = [Fp::ZERO; IV_SIZE];
    let mut x = [Fp::ZERO; SECRET_SIZE];
    for value in iv.iter_mut() {
        *value = random_field_element();
    }
    for value in x.iter_mut() {
        *value = random_field_element();
    }
    from_parts(&iv, &x)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudorandom(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fixed_parts(seed: &mut u64) -> ([Fp; IV_SIZE], [Fp; SECRET_SIZE]) {
        let mut iv = [Fp::ZERO; IV_SIZE];
        let mut x = [Fp::ZERO; SECRET_SIZE];
        for value in iv.iter_mut().chain(x.iter_mut()) {
            *value = Fp::new(pseudorandom(seed) % crate::field::P);
        }
        (iv, x)
    }

    #[test]
    fn keygen_is_deterministic_given_iv_and_x() {
        let mut seed = 1u64;
        for _ in 0..20 {
            let (iv, x) = fixed_parts(&mut seed);
            assert_eq!(from_parts(&iv, &x), from_parts(&iv, &x));
        }
    }

    #[test]
    fn public_key_is_the_truncated_permutation_of_iv_and_x() {
        let mut seed = 2u64;
        for _ in 0..20 {
            let (iv, x) = fixed_parts(&mut seed);
            let pair = from_parts(&iv, &x);

            let mut state = [Fp::ZERO; WIDTH];
            state[..IV_SIZE].copy_from_slice(&iv);
            state[IV_SIZE..].copy_from_slice(&x);
            crate::anemoi::permute(&mut state);

            assert_eq!(pair.public.iv, iv, "the iv is carried through unchanged");
            assert_eq!(pair.public.y[..], state[..OUTPUT_SIZE]);
            assert_eq!(pair.secret.x, x);
        }
    }

    #[test]
    fn different_secrets_give_different_public_keys() {
        let mut seed = 3u64;
        let (iv, x) = fixed_parts(&mut seed);
        let base = from_parts(&iv, &x);

        // Every single-element change to the secret must move y.
        for position in 0..SECRET_SIZE {
            let mut changed = x;
            changed[position] = changed[position] + Fp::ONE;
            assert_ne!(from_parts(&iv, &changed).public, base.public);
        }

        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let (iv, x) = fixed_parts(&mut seed);
            let public = from_parts(&iv, &x).public;
            assert!(seen.insert(public.y.map(|value| value.value())), "two secrets collided");
        }
    }

    #[test]
    fn the_iv_changes_the_public_key_too() {
        // Otherwise one secret would give the same y under every iv, and
        // the iv would be doing no work.
        let mut seed = 4u64;
        let (iv, x) = fixed_parts(&mut seed);
        let base = from_parts(&iv, &x).public.y;
        for position in 0..IV_SIZE {
            let mut changed = iv;
            changed[position] = changed[position] + Fp::ONE;
            assert_ne!(from_parts(&changed, &x).public.y, base);
        }
    }

    #[test]
    fn generated_pairs_are_self_consistent() {
        for _ in 0..10 {
            let pair = generate();
            assert_eq!(one_way_function(&pair.public.iv, &pair.secret.x), pair.public.y);
        }
    }

    #[test]
    fn key_sizes_are_as_documented() {
        assert_eq!(IV_SIZE + SECRET_SIZE, WIDTH, "iv and x must fill the state exactly");
        assert_eq!((IV_SIZE, SECRET_SIZE, OUTPUT_SIZE), (4, 4, 4));
        assert_eq!(SECRET_KEY_BYTES, 32);
        assert_eq!(PUBLIC_KEY_BYTES, 64);
    }
}
