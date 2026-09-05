# Poseidon2 (over BabyBear)

A small educational implementation of the Poseidon2 permutation and a
sponge hash built on it, over the BabyBear prime field
(`P = 2^31 - 2^27 + 1`). This is the hash every ZK-friendly signature
scheme in this workspace is built on.

## Why circuit-friendly hashes exist

A zero-knowledge proof circuit computes with **field arithmetic**:
additions and multiplications of numbers modulo a large prime. That is its
entire vocabulary.

SHA-256 speaks a completely different language — bit rotations, XORs, ANDs
on 32-bit words. A circuit can only express those by simulating every bit
as its own field element, which is ruinously expensive. Measured in this
repo (see [`../circuits/README.md`](../circuits/README.md)):

| Hash | Gates per call |
|------|----------------|
| Poseidon2 | ~73 |
| SHA-256 | ~36,000 |

About **490x**. Poseidon2 gets there by being designed backwards from the
circuit: it is made *only* of field additions, multiplications, and the
S-box `x^7`, so a circuit writes it down almost verbatim. On a CPU it is
unremarkable; inside a proof it is the difference between practical and
hopeless. That gap — not any signature-scheme cleverness — is the single
biggest number in this repository.

## The sponge, in one picture

The permutation shuffles a fixed-size state of 16 field elements. To hash
an input of any length, the sponge splits the state into a **rate** part
(8 elements, where input is absorbed) and a **capacity** part (8 elements
the input never touches directly — that hidden half is where the security
lives):

```
state: [ r r r r r r r r | c c c c c c c c ]     rate | capacity

absorb 8 input elements into the rate
        permute
absorb the next 8
        permute
        ...
read the output from the rate
```

This implementation also writes the input length into the capacity before
absorbing, so inputs of different lengths can never collide by padding
alone (`hash` in `src/lib.rs`). For the fixed-width hashing that leanSig's
chains do millions of times, `compress` skips the sponge machinery and
does a single permutation call.

## The permutation at a glance

Poseidon2 (ePrint 2023/323, Section 6 and Fig. 1) is a sandwich:

```
multiply by external matrix          <- Poseidon2's new initial layer
4 full rounds     (S-box on all 16 elements, external matrix)
13 partial rounds (S-box on 1 element only, internal matrix)
4 full rounds     (S-box on all 16 elements, external matrix)
```

- **Full (external) rounds** apply `x^7` to every element and mix with a
  matrix built from a 4x4 MDS block `M4` arranged in a circulant
  (Section 5.1 of the paper). They provide the brute mixing strength.
- **Partial (internal) rounds** apply `x^7` to just one element, then mix
  with the cheapest useful matrix there is: all-ones plus a diagonal, so
  the whole layer costs 16 multiplications instead of 256 (Section 5.2).
  These rounds exist to keep the algebraic degree climbing at minimal
  cost, and this cheaper internal matrix is the headline improvement of
  Poseidon2 over the original Poseidon.
- `x^7` is used because 7 is the smallest exponent that is invertible mod
  `P - 1` for BabyBear (the paper's rule: smallest `d >= 3` with
  `gcd(d, p - 1) = 1`).
- Round counts here are 8 full + 13 partial, the width-16 BabyBear
  instance used by production libraries (e.g. Plonky3), derived by the
  paper's instance-generation procedure.

## This instance is NOT standard Poseidon2

Two ingredients here are deliberately home-grown, and both are documented
in `src/lib.rs`:

1. **The round constants are invented.** The reference specification
   derives them with a Grain LFSR; this implementation uses a simpler
   documented generator (splitmix64, rejection-sampled into the field).
   The constants only need to be fixed, public, and unstructured, which
   this achieves — but they are not the reference constants.
2. **The internal diagonal is invented.** The `ones + diag` shape is the
   paper's, but the diagonal values are not the vetted reference
   BabyBear-16 diagonal, and no invariant-subspace check (the paper's
   Section 5.3 requirement) has been run on them. That makes this
   permutation *weaker* than standard Poseidon2, not just different.

The consequence: hashes produced here will **not interoperate** with any
other Poseidon2 library, and this code must not be used for anything but
learning. The structure is faithful; the constants are not.

## References

- Lorenzo Grassi, Dmitry Khovratovich, Markus Schofnegger. *Poseidon2: A
  Faster Version of the Poseidon Hash Function.* IACR ePrint 2023/323.
  <https://eprint.iacr.org/2023/323> — the design implemented here.
  Sponge and compression modes: Section 3.1; external matrix and `M4`:
  Section 5.1; internal matrix: Section 5.2; subspace-trail requirement on
  the diagonal: Section 5.3; permutation spec, S-box rule, and round-count
  table: Section 6.
- Lorenzo Grassi, Dmitry Khovratovich, Christian Rechberger, Arnab Roy,
  Markus Schofnegger. *Poseidon: A New Hash Function for Zero-Knowledge
  Proof Systems.* USENIX Security 2021. IACR ePrint 2019/458.
  <https://eprint.iacr.org/2019/458> — the original design, including the
  full/partial round strategy and the Grain LFSR constant generation that
  Poseidon2 inherits.
- Justin Drake, Dmitry Khovratovich, Mikhail Kudinov, Benedikt Wagner.
  *Hash-Based Multi-Signatures for Post-Quantum Ethereum.* IACR ePrint
  2025/055. <https://eprint.iacr.org/2025/055> — why Ethereum's
  post-quantum signatures hash with Poseidon2 over a 31-bit field
  (its Section 7.3); the consumer of this crate, in `../leansig`.
