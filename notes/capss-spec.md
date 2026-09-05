# CAPSS specification notes

Condensed from IACR ePrint [2025/061](https://eprint.iacr.org/2025/061)
("CAPSS: A Framework for SNARK-Friendly Post-Quantum Signatures",
Thibauld Feneuil and Matthieu Rivain), so a future session does not have
to re-fetch the paper. Companion papers, both verified: **SmallWood** is
ePrint [2025/1085](https://eprint.iacr.org/2025/1085) ("SmallWood:
Hash-Based Polynomial Commitments and Zero-Knowledge Arguments for
Relatively Small Instances", same authors — DECS is its §3, LVCS §4.1,
PACS §5.1, the PIOP §5.2); **Anemoi** is ePrint
[2022/840](https://eprint.iacr.org/2022/840) (Bouvier, Briaud, Chaidos,
Perrin, Salen, Velichkov, Willems, CRYPTO 2023 — sponge §3.1, Jive §3.2,
Flystel §4, round function §5.1, round-count rule §5.2 Eq. (2)).

**Use paper v3 (Oct 2025), not v1.** v1 and the authors' marketing page
claim "9–13.3 KB / 19K–29K R1CS"; v3 corrects this to **9.5–15.5 KB /
24K–35K**.

`eprint.iacr.org/*.pdf` is Cloudflare-blocked to automated fetches. The
Wayback `id_` raw-content URLs work:
`web.archive.org/web/20251125040848id_/https://eprint.iacr.org/2025/061.pdf`

Reference implementations:
- Python: https://github.com/CryptoExperts/smallwood-python (needs SageMath)
- C: https://github.com/CryptoExperts/smallwood (byte-exact authority)
- Aggregation: https://github.com/CryptoExperts/capss-aggregation

**No KAT / test vectors are published in either repo.** Both carry
"not audited, not for production" warnings.

---

## The correction that matters

CAPSS is **not** MPC-in-the-head. It is commonly described that way and
that is wrong. There are no parties `N`, no repetitions `tau`, no Beaver
triples, no sacrificing, no additive or Shamir sharing, and no GGM seed
tree.

It is **SmallWood** (ePrint 2025/1085): the Merkle-tree variant of TCitH
extended into a full polynomial commitment scheme using Brakedown
techniques — a polynomial IOP compiled with hash-based commitments, in the
Ligero lineage. Non-linear S-box checks are handled by **degree-bounded
polynomial constraints** verified by random linear combination and
evaluation at random points (Schwartz-Zippel), plus a degree-enforcing
commitment.

Why Merkle rather than GGM: GGM nodes are λ bits and degree enforcement is
free, but verification is `O(N)`. Merkle nodes are 2λ bits and need
explicit degree enforcement, but verification is `O(log N)` and nodes carry
no secrets — which is exactly what makes in-circuit verification cheap.

---

## The one-way function and keys

```
OWF(x) = Tr_{|y|}( P(iv, x) )
|x| = |y| = |iv| = ceil(lambda / log2 q)

sk = (pk, x)      x random in F_q^{t-|iv|}
pk = (iv, y)      iv random, y = truncated permutation output
```

Security rests on **CICO** (constrained-input constrained-output), not on
any algebraic assumption — the permutation is the only assumption, giving
a "zero security gap". For BN254 at λ=128: `ceil(128/254) = 1`, so
**sk = 1 field element (32 B), pk = 2 field elements (64 B)**.

---

## Permutation instances

All 256-bit instances use BN254 scalar fields. Note α=3 and α=5 use
*different* primes (α must be coprime to p−1).

| Instance | Perm | S-box α | State t | Rounds |
|---|---|---|---|---|
| A256-3 | Anemoi | 3 | 2 | 21 |
| A256-5 | Anemoi | 5 | 2 | 21 |
| G256-3 | Griffin | 3 | 3 | 16 |
| G256-5 | Griffin | 5 | 3 | 14 |
| R256-3 | RescuePrime | 3 | 3 | 18 |
| R256-5 | RescuePrime | 5 | 3 | 14 |
| P256-3/5 | Poseidon | 3 / 5 | 3 | R_F=8, R_P=57 |
| (C impl) | Anemoi | 7 | 8 | 11 (Goldilocks) |

Poseidon needs a different "S-box-centric" arithmetization because
full/partial rounds break round-regularity; this inflates the witness
(180 coefficients vs 48–75) and makes Poseidon instances ~60% larger.

The permutation supplies all three primitives:
1. **OWF** — truncated single call.
2. **XOF** — Sponge with the Hirose tweak, capacity `c = ceil(2*lambda / log2 q)`.
3. **Merkle compression** — **Jive**, not Sponge:
   `Jive(x) = sum_i P'_i(x)` where `P'(x) = P(x) + x`.

---

## Arithmetization (PACS / RegRounds)

Witness is an `n x s` matrix with two constraint families: **parallel**
(applied per column, degree ≤ d) and **aggregated** (summed across
columns).

```
s  = ceil(n_r / b)                    witness columns (b = batching factor)
n  = (b+1)*t + b*|v|                  witness rows
m1 = b*(t + |v|)                      parallel constraints
m2 = (s-1)*t + |iv| + |y|             aggregated constraints
d  = alpha
```

Column `k` holds the state chain plus round witnesses. Aggregated
constraints do wiring between columns, IV binding, and output binding.

### The Flystel round-verification identity — corrected

The form circulated for Anemoi's round verification,

```
common = x[i] - (beta*y[i]^2 + delta)
val1   = (y[i] - v[i])^alpha - common
val2   = (u[i] - beta*v[i]^2) - common
```

**does not cancel** against the Flystel as implemented in
`capss/src/anemoi.rs` — it is off by `2*delta`. The form that actually
holds on an honest trace, verified against 25 real executions, is:

```
common = a - beta*b^2 - gamma
val1   = (b - v)^alpha - common
val2   = (u - beta*v^2 - delta) - common
```

where `(a, b)` are the **post-affine** values, i.e. after round constants
and the linear layer have been applied. Note `gamma` in the first line and
`delta` in the third — mixing them up is exactly the `2*delta` error.

Two consequences worth knowing:

- **`|v| = 0` for Anemoi.** The affine layer is degree 1, so it can be
  folded into the constraint instead of committing to intermediate values,
  and the constraint still comes out at degree `alpha`. No auxiliary
  witness is needed per round.
- **`m1 = b*(t + |v|)` lands exactly on the identity count**, because
  `t = 2l` and the round verification emits 2 identities per Flystel pair.

Also note `|iv| = 4`, not the formula's `ceil(lambda / log2 q) = 2`. At
`t = 8`, taking `|iv| = 2` would force `|x| = 6` and contradict the
paper's own `|x| = |iv|`. `t/2 = 4` is the only consistent value, and it
is what the reference C build uses.

---

## Proof system layers

**DECS** (degree-enforcing commitment): sample η masking polys, hash
leaves `u_i = XOF(salt_i, P(e_i), M(e_i))`, Merkle root, derive γ, form
`R_k = M_k + sum_i γ_k^i * P_i` (powers batching). Only the **high
coefficients of R_k** ship; the verifier reconstructs the low ones from
the opened evaluations.

**LVCS**: rows extended with ℓ random values, proves `v_k = sum_j c_kj r_j`.

**PCS**: Brakedown-style coefficient matrix, chunked and stacked.

**PIOP**: the core identity. With `Omega = {0..s-1}`, the verifier checks

```
sum over omega in Omega of Q_k(omega) = 0     for each k in [1, rho]
deg_q = d * (l' + s - 1) + s
```

Parallel constraints vanish at every ω individually; aggregated ones only
sum to zero; masks sum to zero.

**Fiat-Shamir**: four sequential hashes, each optionally with grinding.
`h1 <- (salt, root)`, `h2 <- (h1, R)`, `h3 <- (h2, Q)`, `h4 <- (h3, v, msg)`.
The DECS opening challenge uses **rejection sampling** — grind until the
challenge decodes to ℓ distinct leaf indices; the rejection rate doubles
as the proof of work.

Verification is a **transcript-recomputation equality check**, not an
explicit constraint check. That is what makes the R1CS encoding compact.

---

## Parameters and performance (v3, Table 2)

| Perm | Trade-off | Sig size | R1CS |
|---|---|---|---|
| Anemoi-3 | Short | 9,504 B | 24,671 |
| Anemoi-3 | Default | 12,640 B | 23,484 |
| Anemoi-3 | Fast | 14,368 B | 29,086 |
| Griffin-3 | Short | 10,720 B | **20,717** |
| Griffin-5 | Short | 11,168 B | 21,994 |
| Poseidon-3 | Short→Fast | 16,448–25,056 B | 39,790–60,223 |
| Rescue-3 | Short→Fast | 11,232–16,608 B | 40,128–54,643 |

Trade-off is Merkle tree size only: Short `N≈2^14`, Default `N≈2^12`,
Fast `N≈2^10`.

Measured timings (Anemoi-5, BN254): keygen 0.1 ms, **sign 0.7–9.9 s**,
verify 29–41 ms. Signing is genuinely slow — dominated by DECS committing
`N` polynomial evaluations and `N` leaf hashes. Goldilocks is ~25x faster
than BN254.

**R1CS breakdown (Anemoi-3):** Merkle path verification is **41–63% of all
constraints** — 13,116 of 24,671 in the Short variant. Leaf hashing is
another 4,368.

Comparison: SPHINCS+s 8 KB / ~460K R1CS; Picnic3 12 KB / ~21.6M;
Rainier 8 KB / ~26.1M; FAEST 5 KB but ≥10M; Loquat-128 57 KB / ~148K.
CAPSS's whole point is accepting ~10 KB signatures to get a ~500x
constraint reduction.

---

## If implementing

**Fully specified:** OWF/keygen; PACS arithmetization and all dimension
formulas; the four-layer protocol; sign/verify steps; the FS chain;
security formulas; all parameter sets; round-count derivation.

**You must pin down yourself:**
- Byte-exact serialization and XOF domain separation. The Python prototype
  uses string labels that are effectively no-ops; the C implementation is
  the authority. **The two are not guaranteed interoperable** — pick one.
- MDS matrices and round constants, reproduced byte-identically from the
  builders.
- The Anemoi code carries a comment that it "does not implement the final
  Anemoi linear layer yet" — a deliberate deviation shared consistently by
  both the permutation and its arithmetization. Do not unilaterally "fix"
  it.
- `RLCChallengeType::HYBRID` and PIOP-opening grinding are mandatory for
  64-bit fields (with powers batching, `sec_fpp` is only 114 bits for
  Goldilocks).

**Four SNARK-friendliness tweaks** (§4.1–4.4: Merkle trade-off, trimmed
paths, challenge decomposition, powers batching), worth ~−34% constraints for
+19% size: Merkle parameter trade-off (arity > 2); trimmed authentication
paths; opening-challenge decomposition into one-hot selector bits; powers
batching.
