# Circuits

Noir implementations of the verification side of each signature scheme,
so we can measure what it actually costs to check a signature **inside a
zero-knowledge proof** rather than on a CPU.

This is a different question from the one the root README answers, and it
has different answers. A scheme that is fast natively can be expensive
in-circuit, and the other way round.

## Running them

```
cd lamport_verify        # or wots_verify, xmss_verify, leansig_verify, loquat_verify
nargo compile
bb gates -b target/lamport_verify.json
nargo test               # loquat_verify carries satisfiability tests
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

All four circuits use Poseidon2 and the same conventions (see below), so
these are directly comparable:

| Circuit | Gates | Hash calls | Notes |
|---------|-------|------------|-------|
| `lamport_verify` | 33,756 | 254 + key commit | One hash per bit, no chains |
| `leansig_verify` | 72,304 | 56 x 15 | 56 chains, target sum |
| `wots_verify` | 84,582 | 66 x 15 | 66 chains incl. checksum |
| `xmss_verify` | 86,596 | 66 x 15 + 10 | WOTS + height-10 Merkle path |
| `loquat_verify` | 98,633 | ~916 | FRI queries + Fiat-Shamir — see below |

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

At the Rust crate's real Loquat-128 parameters that lands at **98,633
gates** — roughly the same ballpark as XMSS, reached by completely
different means.

Where the gates go is the interesting part:

- Merkle paths: 32 queries x 4 rounds x 6 levels = **768 hashes**
- Leaf hashes: 32 x 4 = **128 hashes**
- Total: 896 Poseidon2 calls, about **65,000 gates, or ~66% of the
  circuit**
- Fiat-Shamir replay: only **3,135 gates (+3.3%)**, about 20 more hash
  calls

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

1. This is still **not a complete verifier**. The 128 Legendre symbol
   checks (`L_0(o) == pk_I + T`) are not here, and a Legendre symbol is an
   exponentiation, so they are not cheap. The FRI query indices are also
   pinned as public input rather than squeezed from the transcript.
2. **This number is not comparable to the paper's 148,825 R1CS.** That
   figure assumes the algebraic Griffin hash and the real field (`F_p2`
   over `p = 2^127 - 1`). This circuit runs Poseidon2 over BN254, because
   emulating a 127-bit extension field inside BN254 would swamp the
   measurement. Different hash, different field, different scope — treat
   the two as unrelated numbers.

The circuit carries five Noir tests (`nargo test`): one that builds a
consistent opening and four that break it — a severed layer link, a
tampered Merkle commitment, a tampered final polynomial, and a tampered
cap entry that **no query's path even touches** (that last one only fails
because the whole cap feeds the derived challenge, so it is the test that
actually demonstrates Fiat-Shamir binding). A circuit that can never be
satisfied still compiles and still reports a gate count, so those tests
are what make the number meaningful.

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
