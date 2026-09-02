# Loquat

Loquat (IACR ePrint [2024/868](https://eprint.iacr.org/2024/868)) is a
post-quantum signature designed to be cheap to verify **inside a SNARK**.
The other schemes in this repo are built from hash chains; Loquat is built
from a completely different one-way function — the **Legendre PRF** — and
wraps a real proof system around it.

It is the most involved thing in this repository by a wide margin. Read
`../leansig/README.md` first if you want the gentle version.

## The one-way function

Pick a prime `p`. For any non-zero `a`, ask a single yes/no question: **is
`a` a square modulo `p`?** Write the answer as a bit:

```
L_0(a) = 0 if a is a square (a "residue")
L_0(a) = 1 if it is not (a "non-residue")
```

Now key it with a secret `K`:

```
L_K(a) = L_0(K + a)
```

The public key is this function's output on `L = 32768` fixed public
inputs `I_1 .. I_L`:

```
pk = ( L_0(K + I_1), L_0(K + I_2), ..., L_0(K + I_L) )
```

That is 32768 bits, or 4 KB. Recovering `K` from those bits is the
**Legendre PRF key-recovery problem**, believed hard even with a quantum
computer. Unlike hash-based schemes, this key can sign an unlimited number
of messages — there is no state and no "one-time" restriction.

## The trick that makes it provable

Proving "I know `K` such that `L_0(K + I) = pk_I`" directly would mean
proving a Legendre symbol in zero knowledge, which is expensive — it is
essentially an exponentiation.

Loquat sidesteps it using the fact that the Legendre symbol is
**multiplicative**: `L_0(a*b) = L_0(a) + L_0(b)` (mod 2). The signer picks
a secret random `r`, and publishes two things:

```
o = (K + I) * r        the blinded value
T = L_0(r)             the symbol of the blinder
```

Now the verifier computes one symbol, `L_0(o)`, and checks:

```
L_0(o)  =  L_0(K + I) + L_0(r)  =  pk_I + T   (mod 2)
```

`r` hides `K` completely, and the check costs a single symbol evaluation.
This is the only place the public key is touched.

But there is a hole: nothing so far stops a cheater from using a
*different* `K` for each of the 128 values it publishes. Closing that hole
is what the rest of the protocol does.

## Proving one consistent K

The signer commits, **before seeing which indices will be challenged**, to
a vector that interleaves the secret with the blinders:

```
c = ( K*r_1, r_1, K*r_2, r_2, ..., K*r_m, r_m )
```

Then the verifier sends random weights `lambda_i`, and the signer forms:

```
q = ( lam_1, lam_1*I_1, lam_2, lam_2*I_2, ..., lam_m, lam_m*I_m )
```

Take the inner product of `c` and `q`, and watch it collapse:

```
sum_i ( K*r_i * lam_i  +  r_i * lam_i*I_i )
  = sum_i lam_i * (K + I_i) * r_i
  = sum_i lam_i * o_i
```

The right-hand side is computable from **public data only**. So the whole
"same `K` everywhere" question becomes a single claim: *this committed
vector has this inner product*. Because `lambda` is chosen after `o` is
fixed, a cheater who used inconsistent keys fails this with overwhelming
probability.

(`sumcheck_identity_matches_the_public_inner_product` in `sig.rs` checks
this identity directly — it is the hinge the entire scheme turns on.)

## Turning the claim into polynomials

Both vectors get interpolated into polynomials over a domain `H`, so the
inner product becomes a **sum over `H`**:

```
sum over a in H of  c'(a) * q(a)  =  mu
```

This is the **univariate sumcheck** problem. It rests on a neat fact
(Byott–Chapman): if `H` is a multiplicative coset and `deg(g) < |H|`, then

```
sum over a in H of g(a)  =  |H| * g(0)
```

So the signer splits `f` by the vanishing polynomial `Z_H` (which is zero
everywhere on `H`):

```
f(x) = g(x) + Z_H(x) * h(x),   deg(g) < |H|
```

The sum over `H` only depends on `g`, and by the fact above it is pinned
entirely by `g`'s constant term. Rearranging gives a polynomial that must
be low-degree exactly when the claimed sum is right:

```
p(x) = ( g(x) - g(0) ) / x
```

Now everything has been reduced to: **are these committed things really
low-degree polynomials?**

## FRI: the low-degree test

FRI answers that without reading the whole polynomial. Each round groups
the evaluation domain into small fibers, interpolates the tiny polynomial
through each one, and evaluates it at a random challenge — folding the
domain (and the degree) by a factor of 4 each time. After 4 rounds the
remainder is a single coefficient, small enough to send outright.

A genuine low-degree polynomial folds consistently for any challenge. A
codeword far from low-degree does not, and each of the 32 random queries
catches it with constant probability.

`fri.rs` tests this from both sides: honest low-degree codewords pass,
while high-degree codewords, random junk, and tampered openings are all
rejected.

## Parameters (Loquat-128)

From the paper's Table 3 and the authors' reference code:

| Thing | Value |
|-------|-------|
| Prime `p` | `2^127 - 1` |
| Proof field | `F_p2` (see below) |
| Public indices `L` | 32768 |
| Symbols per signature `B` | 128 (as `m = 32` by `n = 4`) |
| Sumcheck domain `\|H\|` | 64 |
| RS domain `\|U\|` | 4096 |
| Rate | 1/16 |
| FRI queries | 32, folding by 4 over 4 rounds |

**Why the extension field?** The FFT needs a domain whose size is a power
of two. For `p = 2^127 - 1`, `p - 1 = 2 * (2^126 - 1)` is divisible by two
only *once*, so `F_p` has no usable power-of-two subgroups at all. But
`p + 1 = 2^127`, so `F_p2` has them up to `2^128`. The Legendre PRF stays
in `F_p`; only the polynomial machinery moves up. `field.rs` verifies the
subgroup orders are exactly right.

## Measured here

Run `cargo run --release -p loquat --example loquat128`:

| | This implementation | Paper |
|---|---|---|
| Public key | 4096 B | 4 KB |
| Signature | 62.3 KB | 57 KB |
| Keygen | 36 ms | 0.1 s |
| Sign | 19 ms | 5.04 s |
| Verify | 2.9 ms | 0.21 s |

The timings are much faster than the paper's because the paper's prototype
is written in Python/SageMath and this is optimised Rust — that is a
language gap, not a disagreement about the scheme.

The **signature is about 9% larger** than the paper's. Two savings are
implemented, both the same idea — never send what the verifier can work
out for itself:

- After the first FRI round, one value in each queried fiber is already
  determined by the previous round's fold, so it is left out and the
  verifier rebuilds it before hashing the leaf. This one is the paper's
  own. Worth ~3 KB.
- **FRI's first layer is virtual.** The batched codeword is a public
  linear combination of oracles (`c`, `s`, `h`) that were each
  Merkle-committed *before* any challenge was drawn, so committing the
  combination again adds bytes but no binding. The verifier computes the
  layer-0 values from the openings it already checked, folds them, and
  tests the result against layer 1's commitment. No layer-0 tree, no
  layer-0 paths, no layer-0 values. Worth ~6.7 KB.

The second saving **deviates from the paper**, which does ship
`rootf^(0)` — but it is exactly how production FRI deployments (Fractal,
Plonky2, Winterfell) treat their composition polynomial, and the binding
argument is the standard one: everything layer 0 depends on was committed
before the first fold challenge existed. An earlier revision instead
solved the `h` openings from the layer-0 values (saving the same bytes
from the other side); that was our own invention, and it was replaced by
this standard construction when the two turned out to be mutually
exclusive — one of `h` or the batched value must be sent, and sending `h`
is what the paper does.

What remains of the ~5 KB gap is not accounted for. The `c`/`s`/`h`
openings dominate what is left. Merging their three trees into one would
save most of it, but it is **not possible**: the roots are absorbed at
different points in the transcript, because later challenges depend on
earlier roots.

## Honest status

**What is implemented:** the full scheme end to end — keygen, all seven
signing phases, and all three verification steps, including the univariate
sumcheck, FRI with tree-capped Merkle commitments, and a domain-separated
Fiat-Shamir transcript.

**What is validated (65 tests):** field arithmetic against schoolbook and
known identities; the FFT against naive Horner evaluation; Legendre
multiplicativity; the arithmetisation identity directly; that the ZK mask
does not disturb the sum; Merkle openings and every tampering variant; FRI
accepting low-degree and rejecting high-degree, random, and tampered
codewords — including a *malicious* prover that ships the final layer's
full interpolation instead of truncating to the degree bound, which an
earlier version of the verifier accepted (the length check in
`replay_transcript` is what rejects it, and without that check the
low-degree test enforces nothing); that a value the verifier rebuilds
still has to land in the right slot of the right leaf; and end-to-end
signing with eleven distinct tamper tests.

**Deliberate deviations from the reference implementation.** The authors'
LoquatPy is an explicit proof-of-concept and has shortcuts that are not
sound; this follows the paper instead:

- LoquatPy hashes by *summing* all inputs into one field element. Here
  every input is absorbed in order with domain separation and length
  prefixes.
- LoquatPy does not chain the previous challenge into the FRI round
  hashes. The paper does, and so does this.
- LoquatPy draws challenge indices from overlapping 15-bit windows. This
  uses proper rejection sampling.
- The `L` public indices are derived from a fixed seed. The paper says
  only "sample them at random" and leaves the derivation open; deriving
  them keeps the public parameters to one string instead of 512 KB.
- Each witness polynomial gets its own ZK mask rather than sharing one,
  which is the safer reading.
- The FRI batching stacks all seven committed polynomials (`c'_1..c'_4`,
  `s`, `h`, `p`) as separate rows with a challenge vector `e` of 14
  extension elements; the paper's Algorithm 5 stacks four rows with
  `e` of 8. Per-row is the more conservative reading (each polynomial
  keeps its own degree bound) and costs no signature bytes.
- Sizes are computed from the struct layout (`size_bytes`), not from a
  byte serializer — none exists. The arithmetic is honest, but no wire
  format has ever been round-tripped.

**What this is not.** It has no reference test vectors to check against —
none are published for Loquat, so "passes its own tests" is genuinely
weaker than "correct". It has not been audited. It is not byte-compatible
with LoquatPy (different serialisation and Fiat-Shamir). It uses SHA3 and
SHAKE rather than the algebraic Griffin hash, so it cannot reproduce the
paper's 148,825 R1CS figure — that number assumes Griffin, and it is the
whole reason Loquat is interesting for SNARKs.

**Do not use this to protect anything.** It is here to make the scheme
legible.
