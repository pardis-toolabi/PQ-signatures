//! The XOF and the Fiat-Shamir transcript, both built from Anemoi in
//! sponge mode.
//!
//! CAPSS's selling point is a "zero security gap": the permutation is the
//! only assumption, and it supplies all three primitives — the one-way
//! function, Merkle compression (Jive, in `merkle`), and the extendable
//! output function here. Reaching for SHA3 would reintroduce a second
//! assumption and, worse, would be ruinous in-circuit, since the whole
//! point of the scheme is that verification is cheap inside a SNARK.
//!
//! ## Sponge parameters
//!
//! `notes/capss-spec.md` fixes the capacity at `c = ceil(2*lambda / log2 q)`
//! — enough capacity to hold `2*lambda` bits, which is what a sponge needs
//! for `lambda`-bit collision resistance. For Goldilocks at `lambda = 128`
//! that is `ceil(256 / 64) = 4` elements, so with `t = 8` the rate is also
//! 4. A digest is therefore 4 field elements, or 256 bits.
//!
//! ## Deliberate deviations from the Python reference
//!
//! `notes/capss-spec.md` records that the Python prototype's XOF domain
//! labels "are effectively no-ops", and the same authors' Loquat prototype
//! has the matching problem of summing hash inputs into a single field
//! element. Both are proof-of-concept shortcuts that break Fiat-Shamir.
//! We do the sound thing instead, exactly as `loquat/src/transcript.rs`
//! does:
//!
//! - every absorbed run is length-prefixed, so `"ab" || "c"` cannot be
//!   confused with `"a" || "bc"`;
//! - the domain label is part of the hashed input, not decoration;
//! - each challenge folds in the previous transcript state and replaces
//!   it, so a prover cannot rewind to an earlier round and retry.
//!
//! None of this is byte-compatible with the CAPSS C implementation, which
//! `notes/capss-spec.md` names as the authority on serialisation. No test
//! vectors exist for either.

use crate::anemoi::{permute, WIDTH};
use crate::field::Fp;

/// Sponge capacity, `ceil(2*lambda / log2 q)` = 4 for Goldilocks at
/// lambda = 128. Also the digest width: a hash output is `CAPACITY`
/// field elements.
pub const CAPACITY: usize = 4;

/// Sponge rate, `t - c`.
pub const RATE: usize = WIDTH - CAPACITY;

/// A digest: `2*lambda` bits worth of field elements.
pub type Digest = [Fp; CAPACITY];

/// Packs bytes into field elements, injectively.
///
/// Seven bytes per element keeps every chunk below `2^56 < p`, so no
/// reduction can fold two different chunks together. The leading length
/// element is what makes the whole encoding injective — without it a
/// trailing zero byte would be indistinguishable from padding.
pub fn encode_bytes(bytes: &[u8]) -> Vec<Fp> {
    let mut encoded = Vec::with_capacity(1 + bytes.len().div_ceil(7));
    encoded.push(Fp::new(bytes.len() as u64));
    for chunk in bytes.chunks(7) {
        let mut buffer = [0u8; 8];
        buffer[..chunk.len()].copy_from_slice(chunk);
        encoded.push(Fp::new(u64::from_le_bytes(buffer)));
    }
    encoded
}

/// Anemoi in sponge mode: absorb `input`, then squeeze `output_len`
/// elements.
///
/// Padding follows the Hirose tweak the CAPSS notes call for. An input
/// that is not a whole number of blocks gets the usual `10*` padding; an
/// input that *is* a whole number of blocks skips the padding block and
/// instead adds one to the last capacity element before the final
/// permutation. That distinguishes the two cases without ever paying for
/// an extra permutation, and it is why `[a, b, c, 1]` and `[a, b, c]`
/// land in different states.
fn sponge(input: &[Fp], output_len: usize) -> Vec<Fp> {
    let mut state = [Fp::ZERO; WIDTH];

    let use_hirose_tweak = !input.is_empty() && input.len().is_multiple_of(RATE);
    let mut padded = input.to_vec();
    if !use_hirose_tweak {
        padded.push(Fp::ONE);
        while !padded.len().is_multiple_of(RATE) {
            padded.push(Fp::ZERO);
        }
    }

    let block_count = padded.len() / RATE;
    for (number, block) in padded.chunks(RATE).enumerate() {
        for (slot, value) in state[..RATE].iter_mut().zip(block) {
            *slot = *slot + *value;
        }
        if use_hirose_tweak && number + 1 == block_count {
            state[WIDTH - 1] = state[WIDTH - 1] + Fp::ONE;
        }
        permute(&mut state);
    }

    let mut output = Vec::with_capacity(output_len);
    while output.len() < output_len {
        let take = RATE.min(output_len - output.len());
        output.extend_from_slice(&state[..take]);
        if output.len() < output_len {
            permute(&mut state);
        }
    }
    output
}

/// The XOF. `domain` separates unrelated uses; `input` is the message.
///
/// Both are length-prefixed before they reach the sponge, so no pair of
/// distinct `(domain, input)` arguments can produce the same absorbed
/// string.
pub fn xof(domain: &[u8], input: &[Fp], output_len: usize) -> Vec<Fp> {
    let mut absorbed = encode_bytes(domain);
    absorbed.push(Fp::new(input.len() as u64));
    absorbed.extend_from_slice(input);
    sponge(&absorbed, output_len)
}

/// The XOF squeezed to one digest, which is what Merkle leaves and the
/// Fiat-Shamir state are made of.
pub fn xof_digest(domain: &[u8], input: &[Fp]) -> Digest {
    xof(domain, input, CAPACITY).try_into().expect("squeezed exactly CAPACITY elements")
}

/// A running Fiat-Shamir transcript.
///
/// The state is one digest — `2*lambda` bits, matching the sponge
/// capacity. Every absorb and every challenge folds the current state
/// into a fresh XOF call and replaces it, so the transcript is a hash
/// chain rather than a set of independent hashes.
pub struct Transcript {
    state: Digest,
}

impl Transcript {
    pub fn new(domain: &[u8]) -> Transcript {
        Transcript { state: xof_digest(b"capss-v1-transcript", &encode_bytes(domain)) }
    }

    /// The chained absorb. `tag` distinguishes the kind of thing being
    /// absorbed so a byte string and a field vector with the same encoding
    /// cannot be swapped for one another.
    fn absorb_tagged(&mut self, tag: &[u8], label: &[u8], values: &[Fp]) {
        let mut input = self.state.to_vec();
        input.extend_from_slice(&encode_bytes(label));
        input.push(Fp::new(values.len() as u64));
        input.extend_from_slice(values);
        self.state = xof_digest(tag, &input);
    }

    pub fn absorb_field_slice(&mut self, label: &[u8], values: &[Fp]) {
        self.absorb_tagged(b"capss-absorb-field", label, values);
    }

    pub fn absorb_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        self.absorb_tagged(b"capss-absorb-bytes", label, &encode_bytes(bytes));
    }

    pub fn absorb_digest(&mut self, label: &[u8], digest: &Digest) {
        self.absorb_field_slice(label, digest);
    }

    /// Squeezes `count` field elements and advances the state.
    ///
    /// No rejection sampling is needed: the sponge already emits field
    /// elements, so the output is uniform over `F_p` by construction. This
    /// is one of the small wins of an algebraic hash over a byte-oriented
    /// one, where 128 bits have to be drawn and reduced to avoid bias.
    pub fn challenge_field_vec(&mut self, label: &[u8], count: usize) -> Vec<Fp> {
        let mut input = self.state.to_vec();
        input.extend_from_slice(&encode_bytes(label));
        let squeezed = xof(b"capss-challenge", &input, CAPACITY + count);
        self.state.copy_from_slice(&squeezed[..CAPACITY]);
        squeezed[CAPACITY..].to_vec()
    }

    pub fn challenge_field(&mut self, label: &[u8]) -> Fp {
        self.challenge_field_vec(label, 1)[0]
    }

    /// Uniform indices in `[0, bound)`, rejection sampled.
    ///
    /// Each squeezed element is masked down to the smallest number of bits
    /// that covers `bound` and retried if it lands too high. Masking rather
    /// than reducing modulo `bound` is what keeps the distribution flat;
    /// the residual bias comes only from `p` not being a power of two, and
    /// is below `2^-32` for any bound that fits in 32 bits.
    pub fn challenge_indices(&mut self, label: &[u8], count: usize, bound: usize) -> Vec<usize> {
        assert!(bound > 0, "index bound must be positive");
        let bits = usize::BITS - (bound - 1).leading_zeros();
        let mask = if bits == 0 { 0 } else { (1u64 << bits) - 1 };

        let mut result = Vec::with_capacity(count);
        let mut round = 0u32;
        while result.len() < count {
            let needed = count - result.len();
            // Draw twice what is needed so the common case is one call:
            // the acceptance rate is above 1/2 by construction.
            let draws = self.challenge_field_vec(
                &[label, b"-idx-", &round.to_le_bytes()].concat(),
                needed * 2 + 1,
            );
            for draw in draws {
                if result.len() == count {
                    break;
                }
                let candidate = (draw.value() & mask) as usize;
                if candidate < bound {
                    result.push(candidate);
                }
            }
            round += 1;
        }
        result
    }

    /// Indices in `[0, bound)` with no repeats.
    ///
    /// DECS opens `l` *distinct* leaves, and the spec derives them by
    /// rejection sampling until the challenge decodes to `l` distinct
    /// indices — the rejection rate doubling as the scheme's proof of
    /// work. We reject per index rather than per whole challenge, which
    /// gives the same distribution over sets but does not provide the
    /// grinding side effect.
    pub fn challenge_distinct_indices(
        &mut self,
        label: &[u8],
        count: usize,
        bound: usize,
    ) -> Vec<usize> {
        assert!(count <= bound, "cannot draw {count} distinct indices below {bound}");
        let mut chosen = Vec::with_capacity(count);
        let mut round = 0u32;
        while chosen.len() < count {
            let needed = count - chosen.len();
            let batch = self.challenge_indices(
                &[label, b"-distinct-", &round.to_le_bytes()].concat(),
                needed * 2,
                bound,
            );
            for candidate in batch {
                if chosen.len() == count {
                    break;
                }
                if !chosen.contains(&candidate) {
                    chosen.push(candidate);
                }
            }
            round += 1;
        }
        chosen
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::P;

    #[test]
    fn sponge_parameters_match_the_specification() {
        // c = ceil(2*lambda / log2 q) = ceil(256 / 64) for Goldilocks.
        assert_eq!(CAPACITY, (2 * 128usize).div_ceil(64));
        assert_eq!(RATE, WIDTH - CAPACITY);
        assert_eq!(RATE, 4);
    }

    #[test]
    fn transcript_is_deterministic() {
        let mut a = Transcript::new(b"test");
        let mut b = Transcript::new(b"test");
        a.absorb_bytes(b"x", b"hello");
        b.absorb_bytes(b"x", b"hello");
        assert_eq!(a.challenge_field_vec(b"c", 8), b.challenge_field_vec(b"c", 8));
    }

    #[test]
    fn different_absorbs_give_different_challenges() {
        let mut a = Transcript::new(b"test");
        let mut b = Transcript::new(b"test");
        a.absorb_bytes(b"x", b"hello");
        b.absorb_bytes(b"x", b"hellp");
        assert_ne!(a.challenge_field_vec(b"c", 8), b.challenge_field_vec(b"c", 8));

        let mut c = Transcript::new(b"test");
        let mut d = Transcript::new(b"test");
        c.absorb_field_slice(b"x", &[Fp::new(1), Fp::new(2)]);
        d.absorb_field_slice(b"x", &[Fp::new(1), Fp::new(3)]);
        assert_ne!(c.challenge_field_vec(b"c", 8), d.challenge_field_vec(b"c", 8));
    }

    #[test]
    fn domains_and_labels_separate() {
        let mut a = Transcript::new(b"one");
        let mut b = Transcript::new(b"two");
        assert_ne!(a.challenge_field_vec(b"c", 4), b.challenge_field_vec(b"c", 4));

        let mut c = Transcript::new(b"test");
        let mut d = Transcript::new(b"test");
        c.absorb_bytes(b"label-a", b"payload");
        d.absorb_bytes(b"label-b", b"payload");
        assert_ne!(c.challenge_field_vec(b"c", 4), d.challenge_field_vec(b"c", 4));

        // A field vector and the byte string with the same encoding must
        // not be interchangeable.
        let mut e = Transcript::new(b"test");
        let mut f = Transcript::new(b"test");
        e.absorb_bytes(b"x", b"abc");
        f.absorb_field_slice(b"x", &encode_bytes(b"abc"));
        assert_ne!(e.challenge_field_vec(b"c", 4), f.challenge_field_vec(b"c", 4));
    }

    #[test]
    fn absorbs_are_order_sensitive() {
        let mut a = Transcript::new(b"test");
        let mut b = Transcript::new(b"test");
        a.absorb_bytes(b"x", b"one");
        a.absorb_bytes(b"x", b"two");
        b.absorb_bytes(b"x", b"two");
        b.absorb_bytes(b"x", b"one");
        assert_ne!(a.challenge_field_vec(b"c", 8), b.challenge_field_vec(b"c", 8));
    }

    #[test]
    fn repeated_challenges_differ() {
        let mut transcript = Transcript::new(b"test");
        let first = transcript.challenge_field_vec(b"c", 8);
        let second = transcript.challenge_field_vec(b"c", 8);
        assert_ne!(first, second, "transcript must advance between challenges");
    }

    #[test]
    fn length_prefixing_prevents_concatenation_collisions() {
        // "ab" + "c" must not collide with "a" + "bc".
        let mut a = Transcript::new(b"test");
        let mut b = Transcript::new(b"test");
        a.absorb_bytes(b"l", b"ab");
        a.absorb_bytes(b"l", b"c");
        b.absorb_bytes(b"l", b"a");
        b.absorb_bytes(b"l", b"bc");
        assert_ne!(a.challenge_field_vec(b"c", 4), b.challenge_field_vec(b"c", 4));

        // The same for field runs, which is where the sponge padding does
        // the work rather than a byte length prefix.
        let one = [Fp::new(1)];
        let two = [Fp::new(2), Fp::new(3)];
        let all = [Fp::new(1), Fp::new(2), Fp::new(3)];
        let mut c = Transcript::new(b"test");
        let mut d = Transcript::new(b"test");
        c.absorb_field_slice(b"l", &one);
        c.absorb_field_slice(b"l", &two);
        d.absorb_field_slice(b"l", &all);
        assert_ne!(c.challenge_field_vec(b"c", 4), d.challenge_field_vec(b"c", 4));
    }

    #[test]
    fn sponge_padding_separates_block_aligned_inputs() {
        // The Hirose tweak exists precisely so that an input ending in the
        // padding pattern cannot be confused with a shorter padded one.
        let padded_shape = [Fp::new(9), Fp::new(8), Fp::new(7), Fp::ONE];
        let short = [Fp::new(9), Fp::new(8), Fp::new(7)];
        assert_ne!(
            xof(b"d", &padded_shape, CAPACITY),
            xof(b"d", &short, CAPACITY),
            "10* padding must not be forgeable as message content"
        );
        // Empty input is still absorbed, not silently skipped.
        assert_ne!(xof(b"d", &[], CAPACITY), xof(b"d", &[Fp::ZERO], CAPACITY));
    }

    #[test]
    fn xof_output_is_long_and_varied() {
        // Squeezing past one rate block must keep producing fresh output
        // rather than repeating the first block.
        let output = xof(b"long", &[Fp::new(42)], 40);
        assert_eq!(output.len(), 40);
        let distinct: std::collections::HashSet<u64> = output.iter().map(|v| v.value()).collect();
        assert_eq!(distinct.len(), 40, "squeezed blocks must not repeat");
        assert!(output.iter().all(|v| v.value() < P));
    }

    #[test]
    fn challenge_fields_are_reduced_and_varied() {
        let mut transcript = Transcript::new(b"test");
        let values = transcript.challenge_field_vec(b"gamma", 64);
        assert_eq!(values.len(), 64);
        assert!(values.iter().all(|v| v.value() < P));
        let distinct: std::collections::HashSet<u64> = values.iter().map(|v| v.value()).collect();
        assert!(distinct.len() > 60, "challenges should not repeat");
    }

    #[test]
    fn challenge_indices_stay_in_range() {
        let mut transcript = Transcript::new(b"test");
        for bound in [1usize, 2, 3, 17, 1024, 4095, 16384] {
            let indices = transcript.challenge_indices(b"q", 200, bound);
            assert_eq!(indices.len(), 200);
            assert!(indices.iter().all(|i| *i < bound), "bound={bound}");
        }
    }

    #[test]
    fn challenge_indices_cover_their_range() {
        // A masking bug that dropped the high bit would still stay in
        // range, so also check the whole range is reachable.
        let mut transcript = Transcript::new(b"test");
        let indices = transcript.challenge_indices(b"q", 4000, 100);
        let distinct: std::collections::HashSet<usize> = indices.into_iter().collect();
        assert_eq!(distinct.len(), 100, "every index in range should appear");
    }

    #[test]
    fn distinct_indices_have_no_repeats() {
        let mut transcript = Transcript::new(b"test");
        let indices = transcript.challenge_distinct_indices(b"open", 60, 64);
        assert_eq!(indices.len(), 60);
        let distinct: std::collections::HashSet<usize> = indices.iter().copied().collect();
        assert_eq!(distinct.len(), 60);
        assert!(indices.iter().all(|i| *i < 64));
    }
}
