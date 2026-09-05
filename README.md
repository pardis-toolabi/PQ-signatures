# PQ-signatures

Post-quantum signature schemes implemented in Rust as readable libraries,
with Noir circuits measuring what each one costs to verify **inside a
zero-knowledge proof**.

Everything here resists quantum attack for the same underlying reason:
none of it relies on factoring or discrete logs, which is what Shor's
algorithm breaks. Instead the schemes are built from hash functions, the
Legendre PRF, or a single permutation.

**New to cryptography?** Start with [`LEARN.md`](LEARN.md) — a from-zero
walkthrough of every scheme here, assuming no background beyond
multiplication and remainders.

## The schemes

Each builds on the last, so reading them in order works well.

| Crate | What it is |
|-------|------------|
| [`lamport`](lamport/) | The simplest hash-based signature. One hash per message bit. |
| [`wots`](wots/) | Winternitz: hash *chains* instead of one secret per bit, ~4x smaller. |
| [`xmss`](xmss/) | A Merkle tree over many WOTS keys, turning one-time into many-time. |
| [`leansig`](leansig/) | What Ethereum is actually building: Winternitz with a target sum, over Poseidon2. |
| [`loquat`](loquat/) | A different foundation entirely — the Legendre PRF, proved with a univariate sumcheck and FRI. |
| [`capss`](capss/) | One permutation doing all three jobs (Anemoi over Goldilocks), proved with SmallWood. |
| [`poseidon2`](poseidon2/) | The circuit-friendly hash leanSig and the circuits depend on. |
| [`circuits`](circuits/) | Noir verification circuits and their measured gate counts. |

## Finding your way around

Pick the path that matches why you are here:

- **"I want to learn how these schemes work."** Read
  [`LEARN.md`](LEARN.md) top to bottom, then the crates in the table's
  order — each crate's README re-explains its own maths in more depth,
  with small worked examples, and each source file cites the paper
  section it implements.
- **"I need to pick a scheme."** Jump to the two tables below, then to
  [Which one should I pick?](#which-one-should-i-pick) for what they mean
  in practice.
- **"I want to check the claims."** Every number comes from a command:
  `cargo test --workspace`, `cargo run --release -p compare`, and
  `bb gates` per circuit ([`circuits/README.md`](circuits/README.md) has
  the exact steps). The papers each crate implements are linked in its
  README's References section.
- **"What is left out / how honest is this?"** The [Status](#status)
  section, each README's caveats, and [`HANDOFF.md`](HANDOFF.md)'s
  production-readiness list.

## Running it

```
cargo test --workspace          # 173 tests
cargo run --release -p compare  # the table below
cargo run --release -p loquat --example loquat128
```

For the circuits, see [`circuits/README.md`](circuits/README.md).

## Native performance

Measured with `cargo run --release -p compare`. Keygen includes deriving
the public key.

| Scheme | Keygen | Sign | Verify | Signature | Public key | Messages per key |
|--------|--------|------|--------|-----------|------------|------------------|
| Lamport | 116 µs | 0.6 µs | 47 µs | 8.0 KB | 16 KB | **1** |
| WOTS | 176 µs | 82 µs | 90 µs | 2.1 KB | 2.1 KB | **1** |
| XMSS (h=4) | 2.6 ms | 72 µs | 83 µs | 2.2 KB | 32 B | 16 |
| XMSS (h=10) | 125 ms | 55 µs | 63 µs | 2.4 KB | 32 B | 1024 |
| leanSig | 768 µs | 694 µs | 308 µs | 1.8 KB | 32 B | **1** |
| Loquat-128 | 26 ms | 18 ms | 2.9 ms | 62.3 KB | 4 KB | **unlimited** |
| CAPSS-128 | 21 µs | **1.63 s** | 8.7 ms | 18.3 KB | **64 B** | **unlimited** |

## In-circuit cost

Same verification algorithms written in Noir, measured as UltraHonk gates
with `bb gates`. This is a *different question* with different answers.

| Circuit | Gates | Why |
|---------|-------|-----|
| `lamport_verify` | 33,756 | One hash per bit, no branching |
| `leansig_verify` | 72,304 | 56 chains x 15 worst-case steps |
| `wots_verify` | 84,582 | 66 chains x 15 |
| `xmss_verify` | 86,596 | WOTS + a height-10 Merkle path |
| `capss_verify` | 97,199 | SmallWood openings + full Fiat-Shamir replay (see caveats below) |
| `loquat_verify` | 100,937 | FRI queries + Fiat-Shamir + residuosity (see caveats below) |

`loquat_verify` covers the FRI query checks — Merkle openings, fold
consistency, final polynomial check — plus **in-circuit Fiat-Shamir**: the
fold challenges are derived inside the circuit from the Merkle caps rather
than trusted as inputs. That replay cost only **3,135 gates (+3.3%)**,
because it adds 17 hash calls against the 896 already spent on Merkle
paths.

It now also carries the **128 Legendre residuosity checks**, done the way
the paper itself arithmetizes them — a prover-supplied square root rather
than an exponentiation — for **896 gates total, 7 per check instead of
~380**. It is still not a complete verifier: the residuosity inputs are
not absorbed into the transcript that yields the FRI challenges, the query
indices are pinned rather than derived, and the sumcheck opening
consistency is absent. It remains **not comparable to the paper's 148,825
R1CS**, which assumes the Griffin hash and the real field. Details in
[`circuits/README.md`](circuits/README.md).

`capss_verify` puts CAPSS's headline claim — cheap in-circuit
verification, ~24K R1CS in the paper — under the same measurement, and
the claim does not survive it: **97,199 gates, within 4% of Loquat**. The
circuit mirrors `capss::piop::verify` at the Rust crate's parameters,
including a *complete* Fiat-Shamir replay (all 352 challenge coefficients
and all 20 opening indices are squeezed in-circuit — nothing pinned), 20
Merkle openings, the real corrected Flystel constraint combination, and
the load-bearing sum-to-zero identity. The single largest cost is not
hashing but deriving the opening indices: 20 canonical bit decompositions
at ~36K gates, the price `loquat_verify` avoids by pinning its query
indices. The paper's ~24K assumes Griffin/Anemoi natively over BN254 with
rho = 1; this circuit inherits the Goldilocks-shaped parameter set
(rho = 2, 352 challenges) and hashes with Poseidon2, so the two numbers
are **not comparable** — but the row above is measured under the same
conventions as every other row, and that comparison is fair.

## What the numbers actually say

**1. The hash matters more than the scheme.** Measured in the same proof
system, one Poseidon2 call costs ~73 gates and one SHA-256 call costs
~36,000 — roughly **490x**. Every scheme here is made of hash calls, so
this single choice dwarfs every other decision. It is why Ethereum's
post-quantum work is built on Poseidon2 rather than SHA-256.

**2. Native speed predicts circuit cost badly — sometimes backwards.**
Lamport has the largest signature (8 KB) and the largest public key
(16 KB), yet it is the **cheapest circuit here**, at under half
WOTS's cost. The reason is branching: a circuit's shape is fixed before it
sees any input, so a hash chain that *might* need 15 steps costs 15 steps
every time. Lamport has no chains, so it wastes nothing. WOTS's compactness
comes precisely from variable-length chains, which is exactly what circuits
handle worst.

**3. The target sum does not buy in-circuit what it buys natively.**
leanSig's target sum pins the verifier to exactly 385 chain steps instead
of WOTS's ~510 — a real native win. In-circuit that saving vanishes, since
the circuit still budgets 15 steps per chain regardless. What survives is
the smaller chain *count* (56 vs 66), which is the ~15% actually measured.

**4. Merkle trees are nearly free in a circuit.** XMSS costs only ~2,000
gates more than WOTS while signing 1024 messages instead of one — about 2%.
Native keygen for that tree takes 125 ms, but the verifier barely notices.
When verification happens inside a proof, there is little reason to accept
a one-time scheme.

**4b. Even a FRI verifier is mostly a Merkle verifier.** Of
`loquat_verify`'s 100,937 gates, ~75,000 (about 74%) are the 896 Poseidon2
calls — 1,024 permutations, since leaf hashes take two each — verifying
Merkle paths and leaves. The polynomial arithmetic that
makes FRI *interesting* — interpolating each fiber, evaluating at the
round challenge, divisions included — is the minority of the cost, and
Fiat-Shamir replay is only 3%. The CAPSS authors report the same shape in
their own system, at 41-63%.

**5. Poseidon2 is slower on a CPU and that is fine.** leanSig verifies in
308 µs against WOTS's 90 µs, because SHA-256 has dedicated CPU
instructions and Poseidon2 does not. It is the wrong trade for a laptop
and the right one for a proof.

**6. Statefulness is the real deployment cost.** Lamport, WOTS, and leanSig
are strictly one-time — signing twice with one key makes forgery possible.
XMSS is many-time but must *remember* which leaf it has used; restoring
from a backup without that counter breaks it. Loquat and CAPSS are
stateless and unlimited, which is what their much larger signatures buy.

**7. The two proof-based schemes trade in opposite directions.** Loquat
signs in 18 ms with a 62.3 KB signature; CAPSS signs in **1.63 seconds**
with an 18.3 KB one. CAPSS also has the smallest public key here by a wide
margin — **64 bytes**, against Loquat's 4 KB and Lamport's 16 KB — because
its key is just the public half of one permutation input plus the
truncated output (the other half of the input *is* the secret key).

That slow signing is not an accident of this implementation. It is
inherent: signing commits `2^14` polynomial evaluations and hashes that
many Merkle leaves. The paper reports 0.7–9.9 s for its own BN254 build,
so 1.63 s over Goldilocks sits inside the expected range. **The cost is
paid once at signing so that verification stays cheap**, which is the
right trade when a signature is verified far more often than it is made —
and even more so when verification happens inside a proof.

## Which one should I pick?

Based purely on what is measured above — read this as a map, not as
deployment advice (see the note at the bottom):

- **Signatures checked inside a ZK proof, one-time keys are fine** →
  the fixed-shape hash schemes win: **Lamport** if signature size does
  not matter (cheapest circuit here at 33,756 gates), **leanSig** if it
  does (1.8 KB, 72,304 gates, and it is the design Ethereum is building).
- **Signatures checked inside a proof, many messages per key** →
  **XMSS**: the Merkle tree adds ~2% circuit cost over WOTS and turns
  one signature into 1024. The cost is state — the signer must remember
  which leaf it used.
- **No state, unlimited messages** → the proof-based pair. **Loquat**
  signs fast (18 ms) with a big signature (62.3 KB); **CAPSS** signs
  slowly (1.63 s) with a smaller signature (18.3 KB) and a 64-byte key.
  Pick by which side of that trade you verify more often.
- **Fast verification on a normal CPU, no ZK anywhere** → none of
  these; that is what the NIST lattice standards (ML-DSA/Falcon) are
  for. `LEARN.md` Part 12 explains why they are absent here and what
  this repo's selection is biased toward.

**None of this code is deployable** — it exists to make the schemes and
their real measured trade-offs legible. Use it to *choose a direction*,
then reach for an audited implementation of the standardized version.

## Status

**Implemented, tested, and measured:** Lamport, WOTS, XMSS, leanSig,
Loquat, CAPSS, and six Noir circuits. **173 Rust tests plus 14 Noir tests
pass, and `cargo clippy --workspace` is clean.**

**Loquat** is a full implementation of ePrint 2024/868 at the paper's real
Loquat-128 parameters, including the univariate sumcheck and FRI. It is
validated component by component (the FFT against naive evaluation, FRI
rejecting high-degree and random codewords, the arithmetisation identity
checked directly) and end to end. But there are **no published test
vectors for Loquat**, so passing its own tests is genuinely weaker than
being correct, and it has not been audited. See
[`loquat/README.md`](loquat/README.md) for the full list of deviations.

**CAPSS signs and verifies.** Reading the spec (ePrint 2025/061) showed it
is not the MPC-in-the-head design it is often described as — it is built on
SmallWood, a hash-based polynomial commitment stack in the Ligero lineage.
Anemoi over Goldilocks supplies the one-way function, the sponge XOF, and
Jive Merkle compression, so nothing rests on an assumption the permutation
does not already make.

Two honest caveats, both documented in the code rather than buried:

- **The load-bearing check is the PIOP's sum-to-zero identity alone.** In
  this composition the degree-enforcing commitment reconstructs exactly as
  many low coefficients as it opens points, so its reconstruction is
  self-consistent by construction and contributes no independent check.
  That is a real simplification against the paper.
- **The soundness estimate is a heuristic, not a proof.** It is written out
  in `capss/src/piop.rs`. Zero knowledge is argued informally too.

What *is* demonstrated: a forged signature built from a wrong witness is
rejected — including one spliced from two genuine executions, which passes
every per-round constraint and is caught only by the wiring. See
[`capss/README.md`](capss/README.md).

**`loquat_verify` is partial by design.** It covers the FRI query checks,
in-circuit Fiat-Shamir, and the 128 Legendre residuosity checks, and
carries its own satisfiability tests, but it does not absorb the
residuosity inputs into the FRI transcript, derive the query indices, or
check the sumcheck opening consistency; it models a simplified uniform
tree geometry (four 1024-leaf trees) rather than the crate's virtual
layer 0 and shrinking layers; and it uses Poseidon2/BN254 rather
than Griffin over `F_p2`. Its 100,937 gates and the paper's 148,825 R1CS
are **not** the same measurement.

**`capss_verify` covers the whole PIOP verifier shape** — full Fiat-Shamir
replay with in-circuit index derivation, Merkle openings, the constraint
combination, and the sum-to-zero identity, with six satisfiability tests
driven by an honest in-test prover. What it omits: the DECS batched
polynomials (not load-bearing in this composition, see
`capss/src/piop.rs`), the salt, and index binding inside the leaf hash.
Its 97,199 gates and the paper's ~24K R1CS are **not** the same
measurement either — different hash, field, and parameter set.

## The papers

Every crate implements a published design, and every source file cites
the paper section it implements. The full citations (with what each one
contributes) live in each crate README's References section; this is the
map:

| Scheme | Primary paper | Builds on |
|--------|---------------|-----------|
| Lamport | [Lamport, SRI CSL-98, 1979](https://lamport.azurewebsites.net/pubs/dig-sig.pdf) | the per-bit form as written down in [Merkle, CRYPTO '89](https://www.ralphmerkle.com/papers/Certified1979.pdf) §3 |
| WOTS | [Merkle, CRYPTO '89](https://www.ralphmerkle.com/papers/Certified1979.pdf) §5 (the Winternitz improvement) | [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html) §3, [W-OTS+ (ePrint 2017/965)](https://eprint.iacr.org/2017/965) |
| XMSS | [Buchmann–Dahmen–Hülsing, PQCrypto 2011 (ePrint 2011/484)](https://eprint.iacr.org/2011/484) | [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html) §4, Merkle '89 §6 (tree authentication) |
| leanSig | [Drake–Khovratovich–Kudinov–Wagner (ePrint 2025/055)](https://eprint.iacr.org/2025/055) | target sum from [SPHINCS+C (ePrint 2022/778)](https://eprint.iacr.org/2022/778); named in the [LeanSig note (ePrint 2025/1332)](https://eprint.iacr.org/2025/1332) |
| Poseidon2 | [Grassi–Khovratovich–Schofnegger (ePrint 2023/323)](https://eprint.iacr.org/2023/323) | [Poseidon (ePrint 2019/458)](https://eprint.iacr.org/2019/458) |
| Loquat | [Zhang–Steinfeld–Esgin–Liu–Liu–Ruj, CRYPTO 2024 (ePrint 2024/868)](https://eprint.iacr.org/2024/868) | [FRI (ICALP 2018)](https://doi.org/10.4230/LIPIcs.ICALP.2018.14), Aurora's univariate sumcheck (EUROCRYPT 2019) |
| CAPSS | [Feneuil–Rivain (ePrint 2025/061)](https://eprint.iacr.org/2025/061) | [SmallWood (ePrint 2025/1085)](https://eprint.iacr.org/2025/1085), [Anemoi, CRYPTO 2023 (ePrint 2022/840)](https://eprint.iacr.org/2022/840) |

Every section number cited in this repo was checked against the actual
paper text, not quoted from memory — where a section could not be
verified, the code cites the paper without one.

## A note on scope

These are written to be read and understood, not deployed. Corners are
simplified on purpose and documented where it matters — for example the
Poseidon2 round constants here are generated deterministically rather than
by the reference Grain LFSR, and its internal-matrix diagonal is invented
rather than the vetted reference one, so it will not interoperate with
other Poseidon2 libraries. **Do not use any of this to protect anything real.**
