# PQ-signatures

Post-quantum signature schemes implemented in Rust as readable libraries,
with Noir circuits measuring what each one costs to verify **inside a
zero-knowledge proof**.

Everything here resists quantum attack for the same underlying reason:
none of it relies on factoring or discrete logs, which is what Shor's
algorithm breaks. Instead the schemes are built from hash functions or
from the Legendre PRF.

## The schemes

Each builds on the last, so reading them in order works well.

| Crate | What it is |
|-------|------------|
| [`lamport`](lamport/) | The simplest hash-based signature. One hash per message bit. |
| [`wots`](wots/) | Winternitz: hash *chains* instead of one secret per bit, ~4x smaller. |
| [`xmss`](xmss/) | A Merkle tree over many WOTS keys, turning one-time into many-time. |
| [`leansig`](leansig/) | What Ethereum is actually building: Winternitz with a target sum, over Poseidon2. |
| [`loquat`](loquat/) | A different foundation entirely — the Legendre PRF, proved with a univariate sumcheck and FRI. |
| [`capss`](capss/) | In progress — an AO permutation (Anemoi over Goldilocks) proved with SmallWood. |
| [`poseidon2`](poseidon2/) | The circuit-friendly hash leanSig and the circuits depend on. |
| [`circuits`](circuits/) | Noir verification circuits and their measured gate counts. |

## Running it

```
cargo test --workspace          # 104 tests
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
| Loquat-128 | 27 ms | 19 ms | 2.9 ms | 68.8 KB | 4 KB | **unlimited** |

## In-circuit cost

Same verification algorithms written in Noir, measured as UltraHonk gates
with `bb gates`. This is a *different question* with different answers.

| Circuit | Gates | Why |
|---------|-------|-----|
| `lamport_verify` | 33,756 | One hash per bit, no branching |
| `leansig_verify` | 72,304 | 56 chains x 15 worst-case steps |
| `wots_verify` | 84,582 | 66 chains x 15 |
| `xmss_verify` | 86,596 | WOTS + a height-10 Merkle path |
| `loquat_verify` | 98,633 | FRI queries + Fiat-Shamir (see caveats below) |

`loquat_verify` covers the FRI query checks — Merkle openings, fold
consistency, final polynomial check — plus **in-circuit Fiat-Shamir**: the
fold challenges are derived inside the circuit from the Merkle caps rather
than trusted as inputs. That replay cost only **3,135 gates (+3.3%)**,
because it adds ~20 hash calls against the 896 already spent on Merkle
paths.

It still leaves out the 128 Legendre symbol checks, so it is not a
complete verifier, and it is **not comparable to the paper's 148,825
R1CS**, which assumes the Griffin hash and the real field. Details in
[`circuits/README.md`](circuits/README.md).

## What the numbers actually say

**1. The hash matters more than the scheme.** Measured in the same proof
system, one Poseidon2 call costs ~73 gates and one SHA-256 call costs
~36,000 — roughly **490x**. Every scheme here is made of hash calls, so
this single choice dwarfs every other decision. It is why Ethereum's
post-quantum work is built on Poseidon2 rather than SHA-256.

**2. Native speed predicts circuit cost badly — sometimes backwards.**
Lamport has the largest signature (8 KB) and the largest public key
(16 KB), yet it is the **cheapest circuit of the four**, at under half
WOTS's cost. The reason is branching: a circuit's shape is fixed before it
sees any input, so a hash chain that *might* need 15 steps costs 15 steps
every time. Lamport has no chains, so it wastes nothing. WOTS's compactness
comes precisely from variable-length chains, which is exactly what circuits
handle worst.

**3. The target sum does not buy in-circuit what it buys natively.**
leanSig's target sum pins the verifier to exactly 385 chain steps instead
of WOTS's ~500 — a real native win. In-circuit that saving vanishes, since
the circuit still budgets 15 steps per chain regardless. What survives is
the smaller chain *count* (56 vs 66), which is the ~15% actually measured.

**4. Merkle trees are nearly free in a circuit.** XMSS costs only ~2,000
gates more than WOTS while signing 1024 messages instead of one — about 2%.
Native keygen for that tree takes 125 ms, but the verifier barely notices.
When verification happens inside a proof, there is little reason to accept
a one-time scheme.

**4b. Even a FRI verifier is mostly a Merkle verifier.** Of
`loquat_verify`'s 98,633 gates, ~65,000 (about 66%) are the 896 Poseidon2
calls verifying Merkle paths and leaves. The polynomial arithmetic that
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
from a backup without that counter breaks it. Loquat alone is stateless
and unlimited, which is what its 68.8 KB signature is buying.

## Status

**Implemented, tested, and measured:** Lamport, WOTS, XMSS, leanSig,
Loquat, and five Noir circuits. 104 Rust tests plus 5 Noir tests pass.

**Loquat** is a full implementation of ePrint 2024/868 at the paper's real
Loquat-128 parameters, including the univariate sumcheck and FRI. It is
validated component by component (the FFT against naive evaluation, FRI
rejecting high-degree and random codewords, the arithmetisation identity
checked directly) and end to end. But there are **no published test
vectors for Loquat**, so passing its own tests is genuinely weaker than
being correct, and it has not been audited. See
[`loquat/README.md`](loquat/README.md) for the full list of deviations.

**CAPSS is partially built.** Reading the spec (ePrint 2025/061) showed it
is not the MPC-in-the-head design it is often described as — it is built on
SmallWood, a four-layer polynomial commitment stack (DECS → LVCS → PCS →
PIOP) over an arithmetization-oriented permutation. The `capss/` crate
currently has the Goldilocks field and the Anemoi permutation, with the
arithmetization and commitment layers in progress. **It cannot sign or
verify yet.** See `HANDOFF.md` for exactly what is done.

**`loquat_verify` is partial by design.** It covers the FRI query checks
and in-circuit Fiat-Shamir, and carries its own satisfiability tests, but
it does not check the Legendre symbols, and it uses Poseidon2/BN254 rather
than Griffin over `F_p2`. Its 98,633 gates and the paper's 148,825 R1CS are
**not** the same measurement. There is no CAPSS circuit at all.

## A note on scope

These are written to be read and understood, not deployed. Corners are
simplified on purpose and documented where it matters — for example the
Poseidon2 round constants here are generated deterministically rather than
by the reference Grain LFSR, so they will not interoperate with other
Poseidon2 libraries. **Do not use any of this to protect anything real.**
