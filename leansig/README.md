# leanSig (target-sum Winternitz over Poseidon2)

**What problem does this solve?** Today's digital signatures (like the BLS
signatures Ethereum validators use) rely on math problems that a large
quantum computer could solve, which would let an attacker forge signatures.
Hash-based signatures avoid that entirely: their only ingredient is a hash
function, and hashes are believed to survive quantum computers. The catch is
that hash-based signatures are bigger and slower to verify — and Ethereum
needs to verify thousands of them per slot, ideally compressed inside a
zero-knowledge proof. leanSig is the design that came out of that pressure:
a hash-based one-time signature rearranged so that *verifying* it takes as
few hash calls as possible, and every one of those calls is a hash a proof
circuit can compute cheaply.

leanSig is the one-time signature Ethereum's post-quantum research settled
on for replacing BLS in consensus. It starts from WOTS (see `../wots`) and
changes two things, both aimed at making **verification cheap inside a
zero-knowledge circuit**:

1. The hash becomes **Poseidon2** instead of SHA-256.
2. The **checksum chains are replaced by a target sum**.

Everything else — hash chains, walking them partway, one-time use — works
exactly like WOTS. If you haven't read `../wots/README.md` yet, read that
first; this document only explains what changes.

## Change 1: an algebraic hash

SHA-256 is fast on a CPU but painful in a circuit. A circuit expresses
computation as additions and multiplications over a field, and SHA-256 is
built from bit rotations, XORs, and ANDs, which have to be simulated
bit-by-bit. A single SHA-256 call can cost tens of thousands of constraints.

Poseidon2 is designed backwards from that problem: it is made only of field
additions, multiplications, and the S-box `x^7`. A circuit can write those
down directly. The same hash that looks unremarkable on a CPU becomes
dramatically cheaper once you are proving things about it.

This library implements Poseidon2 over **BabyBear** (the prime
`2^31 - 2^27 + 1`), in `../poseidon2`.

## Change 2: the target sum

Recall WOTS's problem: hash chains only walk forward, so an attacker can
freely *raise* any digit. WOTS fixes this with checksum chains — extra
chains whose digits move the opposite way.

leanSig fixes it differently. Pick a fixed number `T` — the **target sum**.
The signer then searches for a randomness value `r` such that the digits of
`H(message, r)` add up to *exactly* `T`:

```
digits = H(message, r)  broken into base-16 digits
signer searches r = 0, 1, 2, ... until sum(digits) == T
```

The signature includes `r`. The verifier recomputes the digits and checks
the sum is exactly `T` before doing anything else. (It also rejects any
`r` whose 32-bit halves are not already reduced mod P — the encoding
into field elements is otherwise not injective, and `r + P` would yield
a second valid signature for the same message.)

Now raising a digit is useless: it pushes the sum above `T`, and the check
fails. Lowering a digit would keep the sum wrong too, *and* would require
walking a chain backward, which is hard. So the attacker is stuck — with no
checksum chains needed at all.

### A tiny worked example

Shrink everything down: **4 digits in base 4** (each digit is 0..3), with
target sum `T = 8`.

- `(3, 2, 2, 1)` sums to `3+2+2+1 = 8`. ✔ The signer can use this — it
  reveals chain values at heights 3, 2, 2, 1.
- `(1, 2, 2, 1)` sums to `6 ≠ 8`. ✘ The signer throws this away and tries
  the next randomness value until the digits hit 8.

Now suppose an attacker takes the valid signature for `(3, 2, 2, 1)` and
wants to forge a different message. Chains only walk forward, so from the
revealed values the attacker can only *raise* digits — say turn the last
`1` into a `3`, giving `(3, 2, 2, 3)`. But that sums to `10`, and the
verifier rejects anything that isn't exactly 8. Raising any digit breaks
the sum; lowering one would need walking a hash backward. Every digit
vector that sums to exactly `T` is "incomparable" with every other — no one
dominates another — which is the property the checksum used to provide
(this is Definition 13 and Lemma 7 of the leanSig paper; see References).

### Why this is faster to verify

Verification walks each chain from the signer's stopping point up to the
top. The total number of steps is:

```
total steps = (number of digits x 15) - sum(digits)
            = (number of digits x 15) - T
```

Because the sum is *pinned* to `T`, this total is **fixed and known in
advance** — it does not vary by message. And the bigger you make `T`, the
fewer steps the verifier walks.

That is the real trick: `T` is a dial that trades signer work against
verifier work. Push `T` up and verification gets cheaper, but the signer has
to search longer to find randomness that hits a higher sum.

### The parameters here

This implementation uses 56 digits in base 16, with `T = 455`.

Digits are close to uniform over 0..15, so their sum would nominally
centre on `56 x 7.5 = 420` with a standard deviation of about 34. (In
truth the top nibble of each digest element is slightly biased toward
0..7 — BabyBear's modulus is `15 x 2^27 + 1`, so bit 27 is 0 with
probability 8/15 — which pulls the real centre down to about 418; see
`derive_digits` in the source.) Setting `T = 455` puts the target about
1.1 standard deviations above centre. Measured results:

- **~150 tries** on average for the signer to find matching randomness
  (it fluctuates run to run)
- **385 chain steps** for the verifier, fixed for every message

Compare that to plain WOTS, which needs about 510 steps *and* 67 chains
instead of 56. So leanSig is cheaper to verify and has a smaller signature,
paid for by the signer's search. That trade is worth it whenever
verification happens far more often than signing — which is exactly the
situation in a blockchain, and even more so inside a proof.

## Small extra: seeded keys

The private key here is a single 32-byte seed. The 56 chain starting points
are derived from it on demand:

```
chain_start[i] = H(seed, i)
```

This is what real implementations do. It keeps the private key tiny and
makes backups simple, instead of storing 56 separate secrets.

## Still one-time

None of this changes the core limitation: **one key pair, one signature.**
Signing twice reveals two different points on the same chains, which is
enough to forge. Real leanSig deployments put many of these key pairs under
a Merkle tree, exactly like XMSS does with WOTS, to get a many-time scheme.

## Cost

- Private key: 32 bytes (a seed)
- Public key: 32 bytes (8 field elements)
- Signature: 8 bytes of randomness + 56 x 32 bytes ≈ 1.8 KB
- Signing: ~150 hash calls to find randomness, then up to 56 x 15 chain steps
- Verifying: exactly 385 chain steps, plus ~60 more Poseidon2 permutations
  of overhead (56 to compress the chain tops into the public key, and a
  few to hash the message and derive the digits)

The number that matters for ZK is the chain-step count: **385 algebraic
hash calls, fixed**. That combination — a small, predictable count of circuit-friendly
hashes — is what makes this design practical to verify inside a proof.

## Where this lives in the code

| What | Where |
|------|-------|
| Parameters: base 16, 56 chains, target 455 | `W`, `DIGITS`, `TARGET_SUM` in `src/lib.rs` |
| Message → digits (and the digit-bias caveat) | `derive_digits` in `src/lib.rs` |
| The target-sum search loop | `PrivateKey::sign_counting` in `src/lib.rs` |
| Hash-chain walking | `chain` in `src/lib.rs` |
| Seed → chain starting points | `chain_start` in `src/lib.rs` |
| The sum check and chain completion | `verify` in `src/lib.rs` |
| Measuring the signer's search cost | `examples/trials.rs` (`cargo run --example trials`) |
| The hash itself | `../poseidon2/src/lib.rs` |

## References

- Justin Drake, Dmitry Khovratovich, Mikhail Kudinov, Benedikt Wagner.
  *Hash-Based Multi-Signatures for Post-Quantum Ethereum.* IACR ePrint
  2025/055. <https://eprint.iacr.org/2025/055> — the leanSig design.
  The target-sum encoding is Construction 6 (Section 5.2), hash chains are
  Construction 2 (Section 4.2), incomparable encodings are Definition 13
  (Section 4.1), and the parameter discussion (target `T = ceil(δE)`,
  chunk-size trade-offs) is in Sections 6 and 8.
- Andreas Hülsing, Mikhail Kudinov, Eyal Ronen, Eylon Yogev. *SPHINCS+C:
  Compressing SPHINCS+ With (Almost) No Cost.* IEEE S&P 2023. IACR ePrint
  2022/778. <https://eprint.iacr.org/2022/778> — introduced dropping the
  Winternitz checksum in favour of a fixed-sum encoding, the idea leanSig
  adopts (credited in ePrint 2025/055, Section 2.2).
- Kaiyi Zhang, Hongrui Cui, Yu Yu. *Revisiting the Constant-Sum Winternitz
  One-Time Signature with Applications to SPHINCS+ and XMSS.* CRYPTO 2023.
  IACR ePrint 2023/850. <https://eprint.iacr.org/2023/850> — analysis of
  the constant-sum encoding; showed the best encoding *rate* sits at half
  the maximum sum, which is why leanSig deliberately aims *above* half to
  buy cheaper verification instead.
- Lorenzo Grassi, Dmitry Khovratovich, Markus Schofnegger. *Poseidon2: A
  Faster Version of the Poseidon Hash Function.* IACR ePrint 2023/323.
  <https://eprint.iacr.org/2023/323> — the hash; see `../poseidon2`.
