# Circuits

Noir implementations of the verification side of each signature scheme,
so we can measure what it actually costs to check a signature **inside a
zero-knowledge proof** rather than on a CPU.

This is a different question from the one the root README answers, and it
has different answers. A scheme that is fast natively can be expensive
in-circuit, and the other way round.

## Running them

```
cd lamport_verify        # or wots_verify, xmss_verify, leansig_verify,
nargo compile            #    loquat_verify, capss_verify
bb gates -b target/lamport_verify.json
nargo test               # loquat_verify and capss_verify carry satisfiability tests
```

`circuit_size` is the number to look at — that is the real gate count
under UltraHonk, not the ACIR opcode count (Poseidon2 is a builtin, so it
shows up as a single opcode while really costing ~73 gates).

## The result that matters most

Before comparing schemes at all, compare hash functions. From
`hash_bench`, measured the same way and with the 36-gate empty-circuit
baseline subtracted:

| Hash | Gates per call |
|------|----------------|
| Poseidon2 | ~73 |
| SHA-256 | ~36,000 |

**About 490x.** Every scheme in this repo is built out of hash calls, so
this single choice dominates everything else. Swapping SHA-256 for
Poseidon2 in any of these schemes matters far more than switching between
the schemes themselves. That is the whole reason Ethereum's post-quantum
work is built on Poseidon2.

The reason is structural: a circuit computes with field additions and
multiplications. Poseidon2 is *made* of those. SHA-256 is made of bit
rotations, XORs, and modular additions on 32-bit words, all of which have
to be rebuilt bit by bit out of field arithmetic.

## Circuit sizes

All of these circuits use Poseidon2 and the same conventions (see below),
so they are directly comparable:

| Circuit | Gates | Hash calls | Notes |
|---------|-------|------------|-------|
| `lamport_verify` | 33,756 | 254 + key commit | One hash per bit, no chains |
| `leansig_verify` | 72,304 | 56 x 15 | 56 chains, target sum |
| `wots_verify` | 84,582 | 66 x 15 | 66 chains incl. checksum |
| `xmss_verify` | 86,596 | 66 x 15 + 10 | WOTS + height-10 Merkle path |
| `capss_verify` | 97,199 | ~488 | SmallWood PIOP: openings + full FS replay — see below |
| `loquat_verify` | 100,937 | ~916 | FRI queries + Fiat-Shamir + residuosity — see below |

### Lamport wins, which is not what the native numbers suggest

Natively Lamport looks wasteful: an 8 KB signature and a 16 KB public key.
In-circuit it is the **cheapest of the four**, at less than half the cost
of WOTS.

The reason is branching. Lamport has no chains — every bit costs exactly
one hash, known in advance. Winternitz-style schemes walk a chain a
variable number of steps, and **a circuit cannot stop early**. Its shape is
fixed before it knows any input, so a chain that might need up to 15 hashes
costs 15 hashes every time. The `if` inside `walk_chain` does not skip
work; it computes the hash and then selects whether to keep it.

So WOTS's advertised saving — smaller signatures because chains pack more
information per value — is exactly what makes it expensive here. Packing
more per value means variable-length work, and variable-length work is
what circuits are worst at.

### What the target sum does and does not buy

leanSig comes out ~15% cheaper than WOTS, but not for the reason it is
cheaper natively.

Natively, the target sum pins the verifier's total to exactly 385 chain
steps instead of WOTS's ~500. In-circuit that saving vanishes: the circuit
still budgets the full 15 steps per chain, so it pays 56 x 15 = 840
regardless of what the digits actually are.

What leanSig does buy in-circuit is **fewer chains** — 56 instead of 66,
because the target sum replaces the three checksum chains and the encoding
is tighter. 56/66 is almost exactly the 15% we measure. Real, but a
different mechanism than the native win.

(A more sophisticated circuit could recover the rest by flattening all
chains into one loop of exactly 385 steps and having the prover supply
which chain each step belongs to. That is more complex than these
educational circuits, and is left out on purpose.)

### A proof-system verifier is shaped differently

`loquat_verify` is the odd one out. Instead of walking hash chains it
checks a FRI low-degree proof: 32 queries, each opening a 4-point fiber at
every one of 4 folding rounds, verifying a Merkle path for each, checking
that consecutive layers agree, and finally matching the fully folded value
against the polynomial sent in the clear.

It also replays **Fiat-Shamir in-circuit**: the fold challenges are not
taken as inputs but derived inside the circuit, by recomputing each
round's Merkle root from its cap, absorbing it into a running transcript
state, and squeezing the challenge back out. A prover who wants a
friendlier challenge has to change a cap, and the caps are what the Merkle
openings are checked against.

It also carries Loquat's **128 Legendre residuosity checks**, the part of
the verifier that actually uses the public key. Computed naively each one
is an exponentiation, ~380 gates. Instead the circuit uses the paper's own
trick (its Algorithm 8): the prover supplies a square root `w`, and the
circuit checks `w * w == o` when the claimed bit says "residue" and
`w * w == 5 * o` when it says "non-residue" (5 is a fixed non-residue of
BN254's scalar field, checked by Euler's criterion). With an inverse check
pinning `o != 0`, all 128 checks together cost **896 gates — 7 per check
instead of ~380**.

At the Rust crate's real Loquat-128 parameters that lands at **100,937
gates** — roughly the same ballpark as XMSS, reached by completely
different means.

Where the gates go is the interesting part:

- Merkle paths: 32 queries x 4 rounds x 6 levels = **768 hashes**
- Leaf hashes: 32 x 4 = **128 hashes**
- Total: 896 Poseidon2 calls, about **65,000 gates, or ~64% of the
  circuit**
- Fiat-Shamir replay: only **3,135 gates (+3.3%)**, about 20 more hash
  calls
- All 128 residuosity checks: **896 gates (+0.9%)**, thanks to the
  witness-square-root trick

So a FRI verifier is still, overwhelmingly, a *Merkle path verifier*. The
polynomial arithmetic — Lagrange-interpolating each fiber and evaluating
it at the round challenge, divisions and all — is the minority of the
cost. This matches what the CAPSS authors report for their own system,
where Merkle verification is 41-63% of all constraints.

That Fiat-Shamir number is worth dwelling on. Making a verifier
*non-interactive and sound* — rather than trusting challenges handed to it
— cost 3% here. The expensive part of a proof-system verifier is not the
clever cryptography; it is hashing Merkle paths.

**Two caveats, and they matter:**

1. This is still **not a complete verifier**. The residuosity checks are
   here now, but their inputs (`o_values`, `t_bits`) are not absorbed into
   the same transcript that yields the FRI challenges — the real scheme's
   h1/h2 phases. The FRI query indices are pinned as public input rather
   than squeezed from the transcript, and the sumcheck opening consistency
   the Rust `sig.rs` verifies is absent. It is a shape-measurement.
2. **This number is not comparable to the paper's 148,825 R1CS.** That
   figure assumes the algebraic Griffin hash and the real field (`F_p2`
   over `p = 2^127 - 1`). This circuit runs Poseidon2 over BN254, because
   emulating a 127-bit extension field inside BN254 would swamp the
   measurement. Different hash, different field, different scope — treat
   the two as unrelated numbers.

The circuit carries eight Noir tests (`nargo test`): one that builds a
consistent opening and seven that break it — a severed layer link, a
tampered Merkle commitment, a tampered final polynomial, a tampered
cap entry that **no query's path even touches** (that one only fails
because the whole cap feeds the derived challenge, so it is the test that
actually demonstrates Fiat-Shamir binding), an opening pointed at the
wrong cap slot, a flipped residuosity bit, and a zero Legendre symbol. A
circuit that can never be satisfied still compiles and still reports a
gate count, so those tests are what make the number meaningful.

### CAPSS: the "cheap in-circuit verifier" claim, measured

CAPSS's whole selling point is cheap in-circuit verification — the paper
reports ~20-35K R1CS for its verifier. `capss_verify` measures the shape
of that verifier under this repo's conventions: **97,199 gates**, within
2% of `loquat_verify`. At these parameters and with Poseidon2 over BN254,
the headline claim does **not** survive: the two proof-based schemes cost
essentially the same to check in-circuit.

The circuit mirrors `capss::piop::verify` at the Rust crate's `level_128`
parameters (l' = 20 opened leaves out of N = 2^14, rho = 2, s = 11,
16 witness rows, 8 parallel + 88 aggregated constraints, deg_q = 221). It
checks all four things that verifier checks: a full Fiat-Shamir replay
(message and key in, then cap, then the 404 transmitted Q_k coefficients,
with all 352 challenge coefficients *and* the 20 opening indices squeezed
back out in-circuit — nothing is pinned as a public input), 20 Merkle
openings against a 16-wide cap through depth-10 paths, the corrected
Flystel constraint combination at each opened point, and the load-bearing
identity: reconstruct each Q_k's low 20 coefficients by interpolation
through the 20 opened evaluations, then require
`sum over omega of Q_k(omega) == 0`.

Where the gates go, measured by compiling stripped variants (the pieces
sum exactly to 97,199):

| Component | Gates | Share |
|-----------|-------|-------|
| Opening-index derivation (20 canonical bit decompositions) | 35,703 | 37% |
| Merkle openings (20 leaf hashes + 200 path hashes) | 25,746 | 26% |
| Constraint combination at the 20 points (Flystel + weights) | 13,521 | 14% |
| Q_k reconstruction + sum-to-zero (Horner + interpolation) | 12,065 | 12% |
| Transcript sponge (~268 Poseidon2 permutations) | 9,421 | 10% |
| Key digest + plumbing | 743 | 1% |

Two findings in there:

- **The single most expensive thing is not hashing — it is turning
  squeezed field elements into leaf indices.** Each of the 20 opening
  indices needs a canonical 254-bit decomposition of a challenge
  (~1,250-1,800 gates each) before its low 14 bits can drive a Merkle
  path. `loquat_verify` never pays this because its query indices stay
  pinned as public inputs — which is listed there as a gap. This is what
  closing that gap costs.
- Counting everything hash-and-transcript-shaped together (sponge +
  index derivation + Merkle), **73% of the circuit is Fiat-Shamir and
  Merkle work**; the actual polynomial algebra — the Flystel evaluations,
  two 20-point Lagrange interpolations (divisions and all), and the sum
  checks — is 26%. The CAPSS authors report Merkle verification alone at
  41-63% of their constraints; same shape.

Why this lands nowhere near the paper's ~24K: the paper's BN254 instances
use an algebraic hash (Griffin/Anemoi) *natively over BN254*, with rho = 1
and far fewer challenge coefficients, because their field is 254 bits
wide. This circuit inherits the Rust crate's Goldilocks-shaped parameter
set (rho = 2, 352 challenges, 404 transmitted coefficients — needed
because a 64-bit field is too small for one shot), and hashes with
Poseidon2. Different hash, different field, different parameter set:
**treat 97,199 and ~24K as unrelated numbers.** What the measurement does
say is that under the *same* conventions as every other row in the table,
CAPSS verification is FRI-verification-priced, not magically cheaper.

What is omitted relative to `capss::piop::verify`: the DECS batched
polynomials R_k (their reconstruction is self-consistent by construction
in the Rust composition and contributes no independent check — documented
in `capss/src/piop.rs`), the salt, and the index binding inside the leaf
hash (the path position binds it instead, as in `loquat_verify`). The
Flystel identity is the real corrected one from `notes/capss-spec.md`,
with invented constants and a placeholder linear layer — cost-neutral,
since fixed linear maps are nearly free in-circuit.

The circuit carries six Noir tests. `build_instance` is an unconstrained
honest prover: it runs the Flystel forward over the constraint columns
(seventh roots are cheap natively), commits real degree-30 row
polynomials over all 2^14 leaves, replays the transcript, and opens
whatever indices it derives. One test accepts that instance; five break
it — a commitment that disagrees with the transmitted Q_k (every hash,
path, and transcript step stays valid, so only the sum-to-zero identity
can and does catch it — that is the test that shows which check does the
work), a tampered cap entry, a tampered transmitted high coefficient
(caught because Fiat-Shamir moves the opening indices), a tampered mask
opening, and a tampered message.

### The Merkle tree is nearly free

XMSS costs only ~2,000 gates more than WOTS, for a tree of height 10 — one
hash per level, 10 hashes, plus decomposing the leaf index into bits.

That is a striking trade: **going from a one-time signature to a
1024-time one costs about 2% more circuit.** Native keygen for that tree
takes most of a second, but the verifier — the part that has to run inside
the proof — barely notices. When verification happens inside a proof,
Merkle trees are close to the best deal available.

## Conventions these circuits share

So the comparison is apples-to-apples:

- **The public key is one field element**, a Poseidon2 digest over the
  underlying key material. The circuit rebuilds that material from the
  signature and re-hashes it. This is realistic (it is how you would store
  a key on-chain) and keeps public inputs equal across schemes.
- **The message is passed pre-hashed**, as a single field element, so the
  circuits measure signature verification rather than message hashing.
- **Everything hashes with Poseidon2** over BN254, Noir's native field.

### These do not interoperate with the Rust crates

The Rust implementations run Poseidon2 over **BabyBear** (a 31-bit field);
these circuits run Noir's Poseidon2 over **BN254** (a 254-bit field). A
signature produced by the Rust code will not verify in these circuits.

That is deliberate. The Rust side exists to measure native speed and
signature size; the circuit side exists to measure gate counts. Making
them byte-compatible would mean emulating BabyBear arithmetic inside
BN254, which is slow and would distort exactly the numbers we are trying
to measure. Sizes differ slightly for the same reason — BN254 holds 254
bits, so Lamport uses 254 chains here versus 256 in Rust, and WOTS uses 63
message digits versus 64.

## Bottom line

- Pick the hash first. Poseidon2 over SHA-256 is a ~490x difference and
  dwarfs every other decision here.
- Fixed-shape beats compact when you are paying per gate. Lamport's
  "wasteful" one-hash-per-bit design is its in-circuit advantage, because
  there is no variable-length work to pad out.
- Merkle trees cost almost nothing in-circuit, so there is little reason
  to accept a one-time scheme when a many-time one is ~2% more.
- Native benchmarks will actively mislead you here. Lamport is the biggest
  signature and the cheapest circuit; leanSig's headline native saving
  does not survive arithmetization at all.
- Paper claims about in-circuit cost are parameter- and hash-bound. CAPSS
  is advertised as the scheme with the cheap verifier; measured under the
  same conventions as everything else, it prices within 2% of Loquat.
