# leanSig (target-sum Winternitz over Poseidon2)

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
the sum is exactly `T` before doing anything else.

Now raising a digit is useless: it pushes the sum above `T`, and the check
fails. Lowering a digit would keep the sum wrong too, *and* would require
walking a chain backward, which is hard. So the attacker is stuck — with no
checksum chains needed at all.

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
