# Learn: signatures, from zero

This assumes you know nothing about cryptography. No maths beyond
multiplication and remainders. Every new idea is built from the one
before it, and where a worked example helps you can do it on paper.

Read it in order. Each section earns the next one.

---

## Part 0: What a signature even is

Forget computers for a second. A signature has to do three things:

1. **Only you can make it.** Nobody else can produce your signature.
2. **Anyone can check it.** No secret needed to verify.
3. **It is glued to the message.** A signature on "pay Bob $5" must not
   also work on "pay Bob $5000".

So there are always two keys:

- a **private key** you keep and never show anyone,
- a **public key** you hand out freely.

You sign with the private one. The world verifies with the public one.
The whole game is making it easy to go from private to public, and
impossible to go backwards.

That "impossible backwards" is the entire subject.

---

## Part 1: One-way functions

A **one-way function** is easy forwards and hard backwards.

Real-life version: mixing paint. Blue plus yellow gives green instantly.
Given green, tell me the exact two shades that made it. Good luck.

Mathematical version: multiply 104729 by 105929. A moment's work with a
calculator: 11093766241. Now go the other way — I give you 11093766241
and you find the two numbers. Much harder. Same operation, wildly
different difficulty depending on direction.

**This asymmetry is what every signature scheme is made of.** Your
private key is the input. Your public key is the output. Publishing the
output tells nobody the input.

---

## Part 2: Hash functions

A **hash function** takes any input and produces a fixed-size scrambled
output — a "digest".

```
H("hello")        -> 2cf24dba5fb0a30e...   (32 bytes)
H("hellp")        -> 7d4f8c1e9a2b6f03...   (32 bytes, completely different)
H(a 4GB movie)    -> 1a2b3c4d5e6f7890...   (32 bytes, still)
```

Three properties matter:

- **One-way.** Given the digest, you cannot find the input.
- **Deterministic.** Same input, same digest, always.
- **Avalanche.** Change one bit of input, about half the output bits
  flip. There is no "close" — outputs are either identical or unrelated.

Hash functions are the cheapest one-way function we have, and **four of
the schemes in this repo are built from nothing else.**

### Why this matters for quantum

You have heard "quantum computers will break encryption". Be precise
about what breaks.

Today's common signatures (RSA, ECDSA — the ones in your browser and
your Bitcoin wallet) rest on factoring and discrete logarithms. In 1994
Peter Shor found a quantum algorithm that solves both **efficiently**.
Not "a bit faster" — it collapses them. A big enough quantum computer
ends those schemes outright.

Hash functions are different. The best known quantum attack (Grover's
algorithm) gives a **square-root** speedup: 2^256 work becomes 2^128.
Annoying, not fatal — you double the hash size and you are back where
you started.

That is the entire logic of this repo. **Build signatures out of hash
functions and you inherit their quantum resistance.**

---

## Part 3: Lamport — the simplest possible signature

Start with signing a **single bit**: one yes-or-no answer.

**Setup.** Pick two random secret numbers. Hash each. Publish the two
hashes.

```
secret_0 = "apple"      public_0 = H("apple")   <- published
secret_1 = "banana"     public_1 = H("banana")  <- published
```

**Signing.** To sign the bit `0`, reveal `"apple"`. To sign `1`, reveal
`"banana"`.

**Verifying.** Hash what you were given. If it matches `public_0`, the
signer said 0. If `public_1`, they said 1.

That is a complete, working, quantum-resistant signature for one bit.

Why can't a forger fake it? To claim "the signer said 0" they must
produce something hashing to `public_0` — and reversing a hash is the
thing we said is impossible.

### Scaling to real messages

Hash your message to 256 bits, then do the above **256 times over** —
one secret pair per bit position.

```
private key: 512 random values (2 per bit x 256 bits)
public key:  512 hashes of those values
signature:   256 values — one revealed per bit
```

For each bit of the digest, reveal the "0" secret or the "1" secret.
The verifier hashes each revealed value and checks it against the right
slot.

### The catch: strictly one use

Sign once and you reveal half your secrets — the other half stays
hidden. Sign a *second, different* message and you reveal a different
half. Between the two signatures an attacker now holds **both** secrets
at many positions, and can mix and match to forge a message you never
signed.

**One key, one signature, then burn the key.** This library enforces it
in the type system: `sign` consumes the key, so signing twice is a
compile error, not a runtime mistake.

Cost: 8 KB signature, 16 KB public key. Enormous by classical standards
(ECDSA is 64 bytes). Remember this — it comes back in a surprising way.

---

## Part 4: Winternitz (WOTS) — trading time for space

Lamport is wasteful: one hash value per *bit*. Winternitz asks — what if
one value covered several bits?

### Hash chains

Instead of hashing once, hash repeatedly:

```
x -> H(x) -> H(H(x)) -> H(H(H(x))) -> ...
```

Call `chain(x, k)` the result of hashing `x` exactly `k` times.

The key asymmetry: **going forward is free, going back is impossible.**
Given `chain(x, 5)` anyone can compute `chain(x, 7)` — just hash twice
more. But getting from `chain(x, 5)` back to `chain(x, 3)` means
reversing a hash.

### Signing with position on a chain

Work in base 16 — each "digit" is 0 to 15. Private key: a random chain
start per digit. Public key: each chain walked all 15 steps to the end.

To sign digit `d`, walk the chain `d` steps and reveal where you landed.
The verifier walks the remaining `15 - d` steps and checks they arrive
at the published endpoint.

*Your position on the chain encodes the digit.*

### The checksum, and why it must exist

There is a hole. Chains only walk forward — so a forger can take your
value for digit 5, hash it twice, and claim digit 7. They can **raise**
any digit for free.

Fix: add a **checksum** that moves the opposite way. Compute
`sum of (15 - each digit)` and append it as extra digits.

Now raising a message digit *lowers* the checksum. To keep the forgery
consistent the attacker must lower a checksum digit — walk a chain
**backwards** — which is exactly what they cannot do. Every forgery
breaks somewhere.

Result: 2.1 KB instead of Lamport's 8 KB. Roughly 4x smaller, paid for
with more hashing (up to 15 per chain instead of 1). Still **one-time
only** — for the same reason as Lamport.

---

## Part 5: Merkle trees and XMSS — many signatures, one key

Both schemes so far die after one use. Real keys need to sign
repeatedly. The fix is one of the most useful structures in all of
cryptography.

### The tree

Take 8 values. Hash them in pairs. Hash those results in pairs. Keep
going until one value remains — the **root**.

```
        ROOT
       /    \
     AB      CD
    /  \    /  \
   A    B  C    D        <- each is H(some data)
```

The root is 32 bytes and depends on **every** leaf. Change any leaf and
the root changes completely.

### Proving membership cheaply

Here is the magic. To prove leaf `A` is in the tree, you do **not** send
all the leaves. You send `A`, plus `B`, plus `CD` — and the verifier
recomputes:

```
H(A, B)   -> AB
H(AB, CD) -> ROOT       and checks it matches the published root
```

That list of siblings is an **authentication path**. For a tree of a
million leaves it is only 20 hashes. **Logarithmic, not linear** — that
is why Merkle trees are everywhere.

### XMSS

Now combine: generate 1024 one-time WOTS keys, make each one a leaf,
build the tree, publish only the root.

- **Public key: 32 bytes.** Regardless of how many signatures it covers.
- **To sign:** use the next unused WOTS key, and attach its
  authentication path proving it belongs to your tree.
- **To verify:** check the WOTS signature, then check the path reaches
  the known root.

One tiny public key, 1024 signatures.

### Statefulness — the real-world footgun

Each leaf is still one-time. Reuse a leaf and WOTS breaks exactly as
before. So an XMSS signer must **remember which leaves it has used.**

This sounds trivial and is the single most dangerous thing about XMSS in
practice. Restore a server from last night's backup and it will happily
re-sign with leaves it already spent — silently destroying the key's
security. It is a *state management* problem masquerading as a
cryptography problem.

---

## Part 6: leanSig — what Ethereum is actually building

Two changes to WOTS. Both aimed at one goal: **making verification cheap
inside a zero-knowledge proof** (Part 8 explains why anyone wants that).

### Change 1: a circuit-friendly hash

SHA-256 is fast on a CPU and *terrible* inside a proof, for reasons
Part 8 makes concrete. **Poseidon2** is built from field arithmetic
instead of bit-twiddling, which makes it hundreds of times cheaper in
that setting.

### Change 2: the target sum replaces the checksum

Recall the checksum exists to stop digit-raising. leanSig does it
differently.

Fix a number `T` in advance. The signer searches for a random value `r`
such that the digits of `H(message, r)` add up to **exactly** `T`. The
signature includes `r`; the verifier checks the sum hits `T` before
anything else.

Raising a digit now pushes the sum past `T` and fails immediately. No
checksum chains needed at all.

The measured trade in this repo: the signer tries ~150 random values
before finding one that works, and in exchange the verifier walks a
**fixed** 385 chain steps instead of WOTS's ~510. Signing got harder,
verifying got cheaper and perfectly predictable.

Still one-time. Real deployments put these under a Merkle tree, exactly
like XMSS.

---

## Part 7: Fields, and a completely different foundation

The last two schemes need one new idea.

### Modular arithmetic

Clock arithmetic. On a 12-hour clock, 10 + 5 = 3, because you wrap
around. Written `10 + 5 = 3 (mod 12)`.

When the wrap-around number is **prime** (7, 11, 2^127 - 1), something
special happens: every non-zero number has a reciprocal, so you can
divide as well as add, subtract and multiply. That structure is a
**finite field** — ordinary arithmetic in a finite world.

Everything from here lives in one.

### Squares, and the Legendre symbol

Work mod 7. Square everything:

```
1x1=1    2x2=4    3x3=2    4x4=2    5x5=4    6x6=1
```

The reachable values are {1, 2, 4}. So mod 7:

- 1, 2, 4 are **squares** (also called quadratic residues)
- 3, 5, 6 are **not squares**

Every non-zero number is one or the other. That single yes/no fact is
the **Legendre symbol** — write it as a bit: 0 for square, 1 for
non-square.

For a small prime you find out by checking. For a 127-bit prime you
cannot check, but there is a fast formula. Crucially, the answer looks
**random**: knowing whether 12345 is a square tells you nothing about
12346.

### The Legendre PRF

Pick a secret `K`. Now ask, for many public values `a`:

> is `K + a` a square?

The answers form a string of bits that looks like noise. Publishing
thousands of them reveals no efficient path back to `K`. That is the
**Legendre PRF**, and it is a one-way function of a completely different
flavour from hashing.

**Loquat** is built on it.

### The multiplication trick

One beautiful property makes Loquat possible. Squareness is
*multiplicative*:

```
square    x square    = square
square    x non-square = non-square
non-square x non-square = square
```

(Just like signs in multiplication.) Write the bits as 0/1 and it is
XOR.

So the signer takes the secret quantity `K + a`, multiplies it by a
random blinder `r`, and publishes:

```
o = (K + a) * r          the blinded product
T = the bit for r        the blinder's own answer
```

The verifier computes the bit for `o` and checks:

```
bit(o) = bit(K + a) XOR bit(r) = published_public_key_bit XOR T
```

**`r` hides `K` completely, yet the check still goes through.** One cheap
test, no secret revealed.

### The remaining hole, and the enormous machine built to plug it

Nothing above stops a cheater from using a *different* `K` for each of
the 128 published values. Each one checks out individually.

Closing that hole is where Loquat's complexity lives: proving all 128
values came from **one consistent secret** — without revealing it. That
requires a proof system.

---

## Part 8: Zero-knowledge proofs, circuits, and why gates are the currency

### The idea

A **zero-knowledge proof** lets you prove a statement is true while
revealing nothing beyond its truth.

Colour-blind friend, two balls — one red, one green, identical
otherwise. They cannot tell them apart; you can. They hide the balls
behind their back, maybe swap them, show you again, and ask "did I
swap?" You answer correctly. Once could be luck. Twenty times in a row
could not. **You have proven the balls differ without ever saying which
is which.**

### Circuits

To prove something about a computation, you first rewrite it as a
**circuit** — a giant list of additions and multiplications over a
finite field. The count of those operations is the count of **gates**,
and gates are what you pay for: proving time, memory, verification cost.

Two consequences dominate everything in this repo:

**1. Bit operations are brutal.** A circuit natively speaks field
arithmetic. SHA-256 speaks XOR, rotate, and AND on 32-bit words — every
one of which must be rebuilt bit by bit. Measured here: **SHA-256 costs
~36,000 gates. Poseidon2 costs ~73.** About 490x. This single fact is
why Ethereum's post-quantum work is built on Poseidon2 and why leanSig
exists.

**2. Circuits cannot branch.** A circuit's shape is fixed *before* it
sees any input. There is no "stop early". A hash chain that *might* need
15 steps costs 15 steps **every time** — the `if` computes both sides
and throws one away.

That second point produces the most counterintuitive result in this
repo. Lamport — biggest signature, biggest public key, seemingly the
most wasteful design — is the **cheapest to verify inside a proof**
(33,756 gates, less than half of WOTS). It has no chains, so it has
nothing to pad out. WOTS's compactness comes precisely from
variable-length chains, which is exactly what circuits handle worst.

**Native benchmarks actively mislead you here.**

### Why anyone wants this

Ethereum has ~1 million validators signing constantly. Verifying every
signature individually is impossible at that scale. Instead: verify them
all inside one proof, then everyone checks that single small proof.
Signature verification cost moves from "per node, per signature" to
"once, in gates" — so gate count becomes *the* design constraint.

---

## Part 9: Loquat — proving one consistent secret

Back to the hole from Part 7. Here is how it closes, in four moves.

### Move 1: commit before you know the questions

The signer publishes a locked box containing an interleaved list:

```
c = ( K*r1, r1, K*r2, r2, ..., K*rm, rm )
```

Locked **first**, before seeing any challenge. That ordering is the
whole trick — you cannot tailor an answer to a question you have not
heard.

### Move 2: a random weighted sum

The verifier sends random weights `lam_1 ... lam_m`. The signer forms:

```
q = ( lam_1, lam_1*a_1, lam_2, lam_2*a_2, ... )
```

Multiply the two lists elementwise and add it all up. Watch it collapse:

```
sum of ( K*r_i * lam_i  +  r_i * lam_i*a_i )
  = sum of lam_i * (K + a_i) * r_i
  = sum of lam_i * o_i
```

The right-hand side is built **entirely from public values**. So "did
you use one consistent `K`?" has become one number that both sides can
check. Because the weights arrived *after* the box was locked, a cheater
with inconsistent secrets cannot make it balance.

### Move 3: turn the sum into a polynomial claim

A **polynomial** is just `3x^2 + 5x + 1` — a curve through points. Two
useful facts:

- A degree-`d` polynomial is pinned by `d+1` points. Fewer and it is
  undetermined; more and the extras must agree.
- Two different polynomials of degree `d` can agree in at most `d`
  places. So if they match at a **random** point, they are almost
  certainly the same everywhere.

That second fact is the engine: **check one random point instead of
everything.**

The lists become polynomials, and the sum becomes a claim about a sum
over a set of points — a **sumcheck**. Standard machinery reduces it to:
"is this committed thing really a low-degree polynomial?"

### Move 4: FRI, the low-degree test

**FRI** answers that without reading the whole thing.

Group the evaluation points into small clusters. Interpolate the tiny
polynomial through each cluster, evaluate it at a random challenge — one
value out per cluster. The list shrinks by 4x, and so does the degree.
Repeat until what remains is small enough to send outright.

A genuine low-degree polynomial folds consistently no matter which
challenge appears. Something that is not folds inconsistently, and each
random spot-check catches it with constant probability. Do 32 checks and
cheating becomes hopeless.

### The result

Loquat signs an **unlimited** number of messages with no state to
manage — no one-time keys, no leaf counter, no backup footgun. That is a
real advantage over every hash-based scheme above.

The price: 62 KB signatures, against leanSig's 1.8 KB.

---

## Part 10: CAPSS — one permutation doing everything

Loquat mixes ingredients: Legendre PRF for the one-way function, a hash
for the transcript, another for the tree. Each is a separate assumption
that could fail separately.

CAPSS asks: what if **one** building block did all three jobs?

### A permutation

A **permutation** shuffles inputs to outputs reversibly — same values
out, different order. CAPSS uses **Anemoi**, built (like Poseidon2) from
field arithmetic, so it is circuit-friendly by construction.

Three jobs, one primitive:

1. **The one-way function.** Run the permutation, then **throw half the
   output away**. Reversing needs the discarded half — that truncation
   is the one-way step.
2. **The hash.** Same permutation in "sponge" mode: absorb input, stir,
   squeeze output.
3. **Tree compression.** Same permutation again, in a mode called Jive.

The keys are tiny:

```
private key: 4 field elements  (32 bytes)
public key:  8 field elements  (64 bytes)   <- smallest in this repo
```

Nothing rests on an assumption the permutation does not already make.
The authors call this a **zero security gap**.

### Proving you know the preimage

You cannot reveal your private key, so you must prove knowledge of it.
The permutation is 11 rounds of nonlinear work — no single equation
covers it.

So: write the **whole execution down as a table**. Each column is one
round: the state going in, the state coming out. Then constrain the
table two ways:

- **Per-column checks** — "this column really is one correct round".
  These must hold in *every* column, individually.
- **Across-column checks** — the state leaving column 3 must equal the
  state entering column 4 (**wiring**), the first column must start with
  the public value, the last must end with it.

Wiring earns its keep in a specific way this repo tests directly: a
witness **spliced together from two genuine executions** satisfies every
per-column check perfectly. Only wiring notices the seam.

Those constraints become polynomials, and the verifier checks a single
identity: a certain combination sums to zero over the columns. Per-column
and across-column constraints are weighted *differently* — the per-column
ones get polynomial weights so a violation in column 3 cannot be
cancelled against one in column 7.

### What it costs

Signing takes **1.6 seconds** — genuinely slow, and inherent: it commits
16,384 polynomial evaluations and hashes that many tree leaves. But
verification is 8.7 ms, and the signature is 18.3 KB with a 64-byte
public key.

That trade is deliberate: pay once at signing so verification stays
cheap — the right way round when a signature is checked far more often
than it is made.

---

## Part 11: What actually happened when we measured

Numbers from this repo, on one laptop.

### Native

| Scheme | Sign | Verify | Signature | Public key | Messages per key |
|---|---|---|---|---|---|
| Lamport | 0.6 µs | 47 µs | 8.0 KB | 16 KB | 1 |
| WOTS | 82 µs | 90 µs | 2.1 KB | 2.1 KB | 1 |
| XMSS (h=10) | 55 µs | 63 µs | 2.4 KB | 32 B | 1024 |
| leanSig | 694 µs | 308 µs | 1.8 KB | 32 B | 1 |
| Loquat | 18 ms | 2.9 ms | 62.3 KB | 4 KB | unlimited |
| CAPSS | 1.63 s | 8.7 ms | 18.3 KB | 64 B | unlimited |

### In-circuit (gates — the ZK currency)

| Circuit | Gates |
|---|---|
| Lamport | 33,756 |
| leanSig | 72,304 |
| WOTS | 84,582 |
| XMSS | 86,596 |
| CAPSS | 97,199 |
| Loquat | 100,937 |

### Five things worth carrying away

**1. The hash matters more than the scheme.** Poseidon2 ~73 gates,
SHA-256 ~36,000. Every scheme here is made of hash calls, so this one
choice dwarfs all the others.

**2. Native speed predicts circuit cost badly — sometimes backwards.**
Lamport is the biggest and clumsiest natively, and the cheapest circuit.
Because circuits cannot branch, "wasteful but fixed-shape" beats
"compact but variable-length".

**3. Merkle trees are nearly free in a circuit.** XMSS costs ~2% more
than WOTS while signing 1024 messages instead of 1. When verification
happens inside a proof, there is little reason to accept a one-time
scheme.

**4. Even a proof-system verifier is mostly hashing.** ~74% of Loquat's
circuit is Merkle path hashing. The elegant polynomial mathematics is the
*minority* of the cost. And making the verifier properly
non-interactive — the Fiat-Shamir step — cost only 3%.

**5. Papers describe designs; measurements describe implementations.**
CAPSS's headline claim is cheap in-circuit verification (~24K in the
paper). Our shape measurement came out at 97,199 — within 4% of Loquat.
Not because the paper is wrong, but because it assumes a different hash,
field, and parameters. **This is why the READMEs repeatedly say our
numbers are not comparable to the papers'** — a number is only meaningful
alongside what produced it.

---

## Part 12: Why these six, and not the others

There are dozens of post-quantum signature schemes. Six are here. This
section is about the ones that are not, because the omissions teach as
much as the inclusions.

### How the choice actually got made

Honestly: this was not a systematic survey. It started from a question —
*what post-quantum signatures is Ethereum actually talking about?* — and
then narrowed to a second one: *which are cheap to verify inside a
zero-knowledge proof?* Everything here follows from those two questions,
and a different pair of questions would have produced a different repo.

That produced two groups with different purposes.

**Group 1, the teaching ladder: Lamport, WOTS, XMSS.** Chosen because
each is the *minimum possible change* from the one before. Lamport is the
whole idea at its simplest. WOTS changes one thing (chains instead of
pairs). XMSS changes one thing (a tree over many WOTS keys). Nothing is
here because it is a good deployment choice — Lamport in particular is
not — they are here because the ladder is climbable.

Then Lamport turned out to matter for a completely different reason: it
is the **cheapest circuit in the repo**. That was not why it was picked,
and finding it out was one of the more interesting results.

**Group 2, the ZK candidates: leanSig, Loquat, CAPSS.** Chosen to be
three genuinely *different* answers to "make verification cheap in a
circuit", not three variations on one:

- **leanSig** — keep hash chains, swap in a circuit-friendly hash and a
  better encoding. Evolution.
- **Loquat** — abandon hashing as the one-way function entirely
  (Legendre PRF), then prove consistency with FRI.
- **CAPSS** — build everything from one permutation, and prove with a
  polynomial commitment instead.

Three different foundations. If they had all been Winternitz variants the
comparison would have taught much less.

### The full landscape

| Family | Examples | Why not here |
|---|---|---|
| Hash-based | Lamport, WOTS, XMSS, LMS, **SPHINCS+** | Mostly *are* here. SPHINCS+ is a real gap — see below |
| Lattice | **Dilithium/ML-DSA**, Falcon, HAWK, Raccoon | The actual NIST standards, and bad in-circuit — see below |
| MPC-in-the-head | Picnic, FAEST, Banquet, Rainier, AIMer | Sound ZK-native, are the *worst* in-circuit — see below |
| Multivariate | MAYO, SNOVA, UOV, (Rainbow) | Rough security history; Rainbow was broken outright in 2022 |
| Code-based | CROSS, Wave | Less mature, large keys or signatures |
| Isogeny | SQIsign | Beautiful, tiny signatures, brutally slow and hard to arithmetize |

Three of those deserve real explanations.

### The counterintuitive one: MPC-in-the-head

Picnic, FAEST, Banquet, Rainier. These build a signature *out of a
zero-knowledge proof*. The name alone suggests they should be the
obvious choice for a ZK-friendly signature.

They are the worst option available, by orders of magnitude. Constraint
counts for verifying one, from the Loquat paper's own comparison table:

```
Loquat        ~148,000
SPHINCS+s     ~460,000
Banquet    ~11,800,000
Picnic3    ~21,600,000
Rainier    ~26,100,000
```

Loquat is **7 to 175x** smaller than the MPC-in-the-head family.

Why? Because those schemes are built on **AES and LowMC** — block
ciphers designed to be fast on CPUs, made of bit operations. Part 8's
lesson applies with full force: bit operations are catastrophic inside a
circuit. Being "made of a proof" does not help if the thing you are
proving is bitwise.

The lesson generalises: **"ZK-friendly" is not a property you can read
off a family name.** It comes from the *primitive underneath* being
arithmetic rather than bitwise. That is the single thread connecting
Poseidon2, Anemoi, Griffin, and everything in Group 2.

### The one that will actually be deployed: lattices

If you are shipping post-quantum signatures in production, the answer is
almost certainly **Dilithium** (standardised by NIST as ML-DSA), or
**Falcon** (FN-DSA) where signature size matters more than simplicity.
Those are the standards. They are fast, well-analysed, have mature
libraries, and are what browsers and protocols are adopting.

**Neither is in this repo, and that is a real limitation to be aware
of.** Two reasons:

1. **They are hostile to circuits.** Falcon needs Gaussian sampling over
   lattices; both need rejection sampling and number-theoretic
   transforms over specific rings. None of that arithmetises cleanly, so
   they lose badly on the exact axis this repo measures.
2. **Implementing them safely is a different project.** Falcon's
   floating-point Gaussian sampler is notoriously easy to get subtly
   wrong in ways that leak the key through timing. A from-scratch
   teaching implementation would be *actively misleading* about the
   difficulty.

So: if your question is "what should I deploy", this repo does not
answer it, and no amount of reading it will. If your question is "what
does verification cost inside a proof", it does.

### The genuine gap: SPHINCS+

**SPHINCS+** (standardised as SLH-DSA) is the strongest candidate for
something that arguably *should* be here.

It is hash-based, like half this repo. It is a NIST standard. And it
solves XMSS's worst practical problem — statefulness — by going
**stateless**: instead of a counter tracking which leaf you have used, it
picks a leaf pseudorandomly from a tree so enormous that collisions are
negligible. It layers a hypertree of XMSS-like trees plus a few-time
scheme (FORS) to make that work.

Structurally it is "XMSS, plus the machinery to stop needing the
counter". It would have slotted directly onto the teaching ladder after
XMSS, and it would have made the statefulness discussion in Part 5 land
harder by showing the alternative.

Its in-circuit cost (~460,000 constraints) is far above Loquat's and
CAPSS's, which is exactly why the ZK-focused papers use it as their
baseline to beat rather than their answer. But that is a reason to
*measure* it, not to skip it.

**If you want to extend this repo, SPHINCS+ is the most defensible
addition.**

### The rest, briefly

- **LMS/HSS** — hash-based, an RFC standard, and close enough to XMSS in
  structure that it would mostly duplicate what is already here.
- **Multivariate** (MAYO, UOV, SNOVA) — very small signatures, very
  large public keys. The family's problem is its track record: Rainbow
  was a NIST finalist and was broken outright in 2022. The survivors may
  well be fine; the history argues for caution rather than a teaching
  example.
- **Code-based** (CROSS, Wave) — long-studied assumptions, but the
  schemes are younger and the sizes awkward.
- **SQIsign** — isogeny-based, with signatures around 177 bytes. That is
  *smaller than ECDSA*, which is remarkable for anything post-quantum.
  The costs are brutal signing times and mathematics (isogenies between
  elliptic curves) that is both hard to implement and hard to
  arithmetise. Worth knowing exists. Not a first implementation.

### What this selection optimises for — and its bias

Stated plainly, so you can correct for it:

**Optimised for:** understanding the ideas, and measuring in-circuit
verification cost. Every scheme here was picked because it teaches
something the others do not, or because it is a live candidate for
verification inside a proof.

**Not optimised for:** deployment. The NIST standards are
underrepresented — one of the five (SPHINCS+) is missing entirely and
the lattice family is absent by choice. A repo built to answer "what
should I ship" would contain Dilithium, Falcon and SPHINCS+, and might
contain none of Loquat or CAPSS.

**The bias to watch:** because the ZK question drove the selection,
this repo makes ZK-friendliness look more central to post-quantum
signature design than it currently is. For most of the world, the
important properties are signature size, verification speed on a normal
CPU, and standardisation status — on all three of which the schemes here
do *worse* than Dilithium. Ethereum's situation, where a million
signatures must be verified inside a proof, is a genuinely unusual one.
It is the situation this repo was built around, and it is not the
default.

---

## Part 13: Where to go next

Read the code in this order — each crate builds on the last:

1. `lamport/` — the whole idea in ~130 lines
2. `wots/` — hash chains and the checksum
3. `xmss/` — Merkle trees
4. `leansig/` — the target sum, and Poseidon2
5. `circuits/` — the same verifications as circuits, with gate counts
6. `loquat/` — read `field.rs`, then `poly.rs`, then `fri.rs`, then
   `sig.rs`
7. `capss/` — read `keys.rs`, then `pacs.rs`, then `piop.rs`

Each has a README explaining its own maths at more depth than here, a
"Where this lives in the code" map, and a References section linking the
actual papers — and each source file cites the paper section it
implements, so you can read the code and the paper side by side. The
root README's "The papers" table collects all of them in one place.

Every crate's tests are worth reading as documentation — especially the
**negative** ones. `tampering_with_the_h_path_is_caught` and
`a_signature_forged_from_a_wrong_witness_fails` show you precisely which
check is load-bearing, which the happy path never reveals.

### One last, important thing

**None of this code should protect anything real.** It exists to be
understood. Constants were invented rather than taken from
specifications, nothing has been audited, nothing is hardened against
timing attacks, and there are no reference test vectors for the two
proof-based schemes — so "all tests pass" genuinely means less than it
sounds.

`HANDOFF.md` has a full production-readiness TODO spelling out the
distance between this and something usable. That distance is much larger
than a passing test suite suggests, and knowing *why* is itself one of
the more valuable things in this repository.
