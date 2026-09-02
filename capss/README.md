# CAPSS

CAPSS (IACR ePrint [2025/061](https://eprint.iacr.org/2025/061)) takes a
different route to a post-quantum signature than anything else in this
repo. Lamport, WOTS, XMSS and leanSig are built from hash chains. Loquat is
built from the Legendre PRF. CAPSS is built from **one permutation** — and
that permutation does all three jobs the scheme needs.

Read `../leansig/README.md` first if you want the gentle version, and
`../loquat/README.md` if you want to see a proof-system-based signature
explained more slowly. This one assumes both.

## The first correction

CAPSS is very often described as MPC-in-the-head, like Picnic. **It is
not.** There are no parties, no repetitions, no Beaver triples, and no
secret sharing anywhere in it.

It is built on **SmallWood**: a hash-based polynomial commitment scheme in
the Ligero/Brakedown lineage, compiled into a signature by Fiat-Shamir.
Getting this wrong sends you down completely the wrong implementation
path, which is why it is the first thing said here.

## One permutation, three jobs

The design goal is a **zero security gap**: nothing in the scheme rests on
an assumption the permutation does not already make. So the permutation
supplies everything:

1. **The one-way function** — run the permutation, throw half the output
   away.
2. **The hash / XOF** — the same permutation in sponge mode.
3. **Merkle compression** — the same permutation again, in **Jive** mode.

Jive is worth a note because it is not a sponge. It is a plain
feed-forward construction (Miyaguchi-style, not Davies-Meyer — nothing is
keyed):

```
P'(x) = P(x) + x
Jive(x) = sum of the pieces of P'(x)
```

which maps `t` field elements down to `t / arity` in one shot.

## The one-way function

```
sk = x                       4 field elements (32 bytes)
pk = (iv, y)                 8 field elements (64 bytes)

y = first 4 elements of P(iv || x)
```

That is the whole key pair. Inverting it means finding an input that
produces a fixed part of the output while a different part is also fixed —
the **CICO** problem (constrained-input constrained-output). No number
theory, no lattice, no extra assumption.

Those key sizes are the smallest of any scheme in this repo. What CAPSS
pays instead is signature size and signing time.

## The hard part: proving you know the preimage

You cannot just reveal `x`. You have to prove you know it. And the
permutation is 11 rounds of nonlinear work, so the statement "I know an
`x` whose permutation output starts with `y`" is not something you can
check with one equation.

The trick is to lay the **entire execution** out as a table and constrain
it, then prove things about the table.

### The witness table

Run the permutation and record every intermediate state. Arrange them into
a matrix with `n = 16` rows and `s = 11` columns — one column per round.
Each column holds the state going into that round and the state coming out.

### Two kinds of constraint

**Parallel constraints** — applied to each column *independently*. These
say "this column really is one correct round of the permutation." There
are 8 of them per column.

**Aggregated constraints** — applied *across* columns. There are 88, and
they do three jobs:

- **Wiring**: the state leaving column `k` must equal the state entering
  column `k+1`. Without this, a cheat could stitch together rounds from
  different executions.
- **IV binding**: the very first state must start with the public `iv`.
- **Output binding**: the very last state must start with the public `y`.

That split matters later: parallel constraints must hold *everywhere*,
aggregated ones only need to *sum* to zero. The proof system treats them
differently for exactly that reason.

### Why the round constraint is degree 7, and not worse

Anemoi's S-box (the "Flystel") is built so that verifying a round never
requires computing an inverse S-box — there is an equivalent identity in
the forward direction. That is what "arithmetization-oriented" means in
practice.

The round's affine part (constants plus the linear layer) is degree 1, so
it folds into the constraint for free. The result is that a whole round
verifies at degree `alpha = 7` with **no auxiliary witness values at all**.

A warning for anyone re-deriving this: the commonly circulated form of the
Flystel identity is **wrong by `2*delta`**. The corrected version, checked
against 25 real execution traces, is in `../notes/capss-spec.md`.

## Why `alpha = 7`

The S-box is `x^alpha`, and for that to be a bijection `alpha` must be
coprime to `p - 1`. Over Goldilocks:

```
p - 1 = 2^32 * 3 * 5 * 17 * 257 * 65537
```

So `alpha = 3` fails, and **`alpha = 5` fails too**. Seven is the smallest
odd exponent that works, and that is exactly why the reference C build
uses it. There is a test asserting this rather than just a comment
claiming it.

## Degree-enforcing commitments (DECS)

The proof rests on committing to polynomials and later opening them at a
few points. But a cheating prover could commit to something that is *not*
a low-degree polynomial at all and try to slip through.

DECS blocks that. The prover commits, the verifier sends random `gamma`,
and the prover returns a batched combination:

```
R_k(X) = M_k(X) + sum over i of gamma_k^i * P_i(X)
```

Only the **high coefficients** of `R_k` are sent. The verifier rebuilds the
low ones from the handful of opened evaluations. If the committed
polynomials were genuinely within the degree bound, that reconstruction is
consistent no matter which points were opened. If one was over-degree, the
reconstruction **changes depending on which points you open** — and it gets
caught.

`decs.rs` tests exactly that: it commits a polynomial one degree too high
and shows the reconstruction differs between two different opening sets.

## The proof itself

The witness table has `n = 16` rows and `s = 11` columns, one column per
Anemoi round. Take a row and read its 11 entries as the values of a
polynomial at the points `0, 1, ..., 10`. Add `l'` more points carrying
nothing but fresh randomness, and interpolate. Now each row is a
polynomial of degree `l' + 10`, it still says what the witness said at
`0..10`, and at any other point it says nothing at all — which is where
the zero knowledge comes from, because the proof only ever opens points
outside `0..10`. That guarantee is enforced by an offset on the committed
evaluation points (`decs::EVALUATION_OFFSET`, `2^32`): an earlier version
used an offset of 2, which put committed leaves *on* the witness points —
about 1% of signatures opened a raw witness column, and Anemoi states
invert layer by layer, so one leaked column is full key recovery. A
regression test now pins the two domains apart.

Both constraint families are then folded into one polynomial per
combination:

```
Q_k(X) = sum_j gamma_k,j(X) * (parallel constraint j)
       + sum_j gamma'_k,j   * (aggregated constraint j)
       + Mask_k(X)
```

and the verifier checks one thing:

```
Q_k(0) + Q_k(1) + ... + Q_k(10) = 0
```

The two families are weighted differently, and the reason matters. A
**parallel** constraint is a round check, so it has to fail if it fails at
*any single column* — a plain scalar weight would only force the total
across columns to vanish, letting a prover cancel a violation in column 3
against one in column 7. So `gamma_k,j` is not a scalar but a degree-10
polynomial passing through 11 independent random values. At the 11 column
points it therefore acts as 11 independent random weights, and a random
weighted sum of numbers is zero only if all of them are.

An **aggregated** constraint is the opposite. Wiring column `k`'s output
to column `k+1`'s input, and pinning the two ends of the chain to `iv` and
`y`, are statements about the columns *together*, so summing to zero is
exactly right and one scalar weight is enough.

The **mask** hides everything. It is random except for one property: it
sums to zero over `0..10` as well, so it cannot move the quantity being
tested. Sample every coefficient above the constant freely and let the
constant absorb whatever the sum came to.

Only the coefficients of `Q_k` of degree `l'` and above are sent. The
verifier works out `Q_k` at the `l'` opened points — every ingredient is
in the opened leaf — subtracts the part it was given, and interpolates the
rest. That is `l'` unknowns against `l'` equations, which leaves the
sum-to-zero as the one condition still to be tested. Spending it on
reconstruction instead would leave a square system that always solves, and
then nothing would ever fail.

## Signing and verifying

Signing is: run the permutation on `iv || x`, lay the trace out as the
witness table, and prove. Four hashes chain the whole thing together, each
folding in the one before it:

```
h1 <- (message, public key)
h2 <- (h1, salt, Merkle root)   -> the challenges
h3 <- (h2, the sent part of Q)
h4 <- (h3, the sent part of R)  -> which l' leaves get opened
```

Verifying **replays that chain**. It never rebuilds the witness table and
never re-checks the arithmetization — it could not, since the witness is
secret. It re-derives every challenge from the signature's own bytes,
checks `l'` Merkle paths, evaluates the constraint expression at those
`l'` points only, and tests the sum. That is the difference that makes
CAPSS cheap to verify *inside* a SNARK: the work is hashing and a fixed
amount of field arithmetic, not `m1 * s + m2` degree-7 constraints.

## Status

Signs and verifies. 87 tests.

| Module | What it does |
|--------|--------------|
| `field.rs` | Goldilocks arithmetic |
| `anemoi.rs` | The Anemoi permutation |
| `keys.rs` | The one-way function and key pair |
| `pacs.rs` | The witness table and both constraint families |
| `transcript.rs` | Anemoi in sponge mode |
| `merkle.rs` | Jive-compressed Merkle trees |
| `decs.rs` | Degree-enforcing commitments |
| `piop.rs` | The polynomial IOP — the `Q_k` identity above |
| `sig.rs` | `sign` and `verify`, and the Fiat-Shamir chain |

Measured at `piop::Parameters::level_128()` (`l' = 20`, `N = 2^14`), on
this machine, release build:

| | |
|---|---|
| Signature | 18,688 B |
| Sign | 1.6 s |
| Verify | 8.7 ms |
| Secret key | 32 B |
| Public key | 64 B |

Merkle paths are **48% of the signature** (8,960 B of 18,688). The paper
reports the same shape for the R1CS side — path verification is 41–63% of
all its constraints. For comparison the paper's Anemoi-3 "Short" figure is
9,504 B, signing 0.7–9.9 s, verifying 29–41 ms; we are about twice its
size and inside its timing range.

Only `N = 2^14` comes from the paper (Table 2's "Short" trade-off).
Everything else — `l' = 20`, `rho = 2`, `eta = 2`, arity 2 — was chosen
here. `rho = 2` because each combination is worth one `1/p` chance to a
cheating prover, and over a 64-bit field two is the fewest that pushes
the *challenge* term to 128 bits. The opening term is weaker: by this
crate's own heuristic it is `l' * log2(N / deg_q) ≈ 124` bits, and the
spec's countermeasures for 64-bit fields (proof-of-work grinding and the
HYBRID challenge type, which it calls mandatory there) are not
implemented — so `level_128` is at most ~124 bits even by its own
estimate. The name describes the target, not a proven level. Arity 2 because at `t = 8` only arity 2 gives Merkle nodes of
`2*lambda` bits.

The default test suite runs at `Parameters::testing()` (`l' = 6`,
`N = 256`), which is a toy and is **not a security level** — its opening
term is worth about 6 bits. It exists so the tests finish in a second in
an unoptimised build.

The strongest evidence so far is from `pacs.rs`: an honest execution trace
satisfies **all 176 constraints** across 25 independent key pairs, and
corrupting any single one of the 176 witness entries (528 cases tried)
breaks at least one constraint. A witness spliced from two different
executions passes every parallel constraint and is caught only by the
wiring — which is precisely what wiring exists to catch.

## Fidelity — read this before trusting anything

**Faithful to the paper:** the one-way function and key structure; all the
arithmetization dimension formulas; the column layout; wiring, IV and
output binding; `d = alpha`; Jive rather than sponge for Merkle
compression; the sponge capacity.

**Invented here, and therefore not interoperable:**

- **All 88 Anemoi round constants.** The reference derives them from digits
  of pi; these come from a documented splitmix64 generator.
- **The diffusion matrix** — a 4x4 Cauchy matrix, chosen because Cauchy
  matrices are provably MDS. The reference's is cheaper but this one is not
  weaker.
- **Batching factor `b = 1`.** 11 rounds is prime, so only 1 and 11 divide
  it exactly, and 11 collapses the arithmetization to a single column with
  no wiring at all.

**Simplified here, and said out loud rather than buried:**

- **The masks are not chunked.** The paper stacks every committed
  polynomial into chunks that share one degree bound; we let the DECS
  degree bound be set by the masks, which are the tallest thing committed.
  It costs about 800 bytes and buys simpler code. It buys no soundness
  either way, because of the next point.
- **DECS's degree enforcement carries no weight in this composition.** It
  reconstructs exactly as many low coefficients as it opens points, so the
  reconstruction always succeeds and there is nothing left over to fail.
  The load-bearing check is the PIOP's sum-to-zero, not DECS.
- **The Fiat-Shamir order differs.** The paper absorbs the message last;
  we absorb it first, and `R` after `Q` rather than before. What matters
  is the same in both: every prover message is bound before the opening
  indices are drawn.
- **The spec's mandatory 64-bit-field countermeasures are absent.** For
  fields this small the spec requires proof-of-work grinding on the
  opening indices and its HYBRID challenge batching; neither is
  implemented (see the note in `transcript.rs`), which is why `level_128`
  tops out around 124 bits by this crate's own estimate.
- **The soundness estimate is a heuristic, not a proof.** It is written
  out at the top of `piop.rs`. Nobody has done the real analysis.
- **Sizes are element counts, not a wire format.** There is no byte
  serializer; `size_bytes` multiplies field-element counts by 8. The
  18,688 B figure is honest arithmetic, but a real encoding (indices,
  length framing) has never been round-tripped.

Consequence: **this will not interoperate with the CAPSS reference
implementation**, and there are **no published test vectors for CAPSS**
against which any of it could be checked. Everything above is
self-consistency and negative testing. That is weaker than correctness.

**Do not use this to protect anything.**
