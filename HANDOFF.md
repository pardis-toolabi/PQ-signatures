# Handoff

Working notes for whoever picks this up next. Read this before touching
anything.

**Repo:** `git@github.com:pardis-toolabi/PQ-signatures.git`
**Local path:** `/Users/pardis/Documents/pardis/PQ-signatures`

---

## Hard rules

1. **Do not commit or push.** The user has asked for this explicitly and
   repeatedly. Everything is intentionally left untracked/modified. Do not
   `git add`, `git commit`, or `git push` unless the user says so in a new
   message.
2. **Do not overstate correctness.** This is cryptography with no
   reference test vectors for the hard parts. "My tests pass" is not
   "correct". When reporting, say plainly what is validated, what is
   merely self-consistent, and what is unverified. The user values this —
   it has shaped several decisions already.
3. **Do not fabricate comparison numbers.** Every number in a README must
   come from a command that was actually run on this machine, or be
   clearly attributed to a paper. If a figure cannot be measured honestly,
   leave it out and say why. This is exactly why `loquat_verify`'s gate
   count is stated as **not** comparable to the paper's 148,825 R1CS, and
   why `capss_verify`'s is stated as not comparable to CAPSS's ~24K.
4. **Match the existing code style.** See "House style" below. The user
   asked for "human readable but efficient" and explicitly did **not**
   want dense or hard-to-follow commenting.

---

## What this project is

A teaching repository of post-quantum signature schemes, in two halves:

- **Rust crates** — each scheme implemented as a readable library with
  keygen / sign / verify, plus a per-crate README explaining the maths
  step by step in plain language.
- **Noir circuits** (`circuits/`) — the *verification* side of each
  scheme, so we can measure what it costs to check a signature inside a
  zero-knowledge proof. This is the part the user cares most about.

The user's framing: they want the "hottest / most applicable" PQ signature
schemes, and specifically how they behave for ZK.

---

## Current state

`cargo test --workspace` → **173 tests passing** (plus 1 ignored). Clippy: **clean.**
`cargo run --release -p compare` → the native table in the root README.
`cd circuits/loquat_verify && nargo test` → 8 tests passing.
`cd circuits/capss_verify && nargo test` → 6 tests passing.

### Done

| Crate | Status |
|-------|--------|
| `lamport` | Complete, 3 tests, README |
| `wots` | Complete, 3 tests, README |
| `xmss` | Complete, 5 tests, README |
| `poseidon2` | Complete (BabyBear), 4 tests. Clippy clean. |
| `leansig` | Complete, 6 tests, README. Faithful to Ethereum's design. |
| `loquat` | **Complete**, 65 tests, README. Full ePrint 2024/868 at real Loquat-128 params. Signature 62.3 KB. |
| `capss` | **Signs and verifies**, 87 tests (plus 1 ignored), README. See caveats below. |
| `compare` | Benchmarks all seven schemes |
| `circuits/` | 6 circuits + `hash_bench`, all measured, README |

### Noir circuits measured (UltraHonk gates via `bb gates`)

| Circuit | Gates |
|---------|-------|
| `lamport_verify` | 33,756 |
| `leansig_verify` | 72,304 |
| `wots_verify` | 84,582 |
| `xmss_verify` | 86,596 |
| `capss_verify` | 97,199 |
| `loquat_verify` | 100,937 |
| Poseidon2 (per call) | ~73 |
| SHA-256 (per call) | ~36,000 |

`loquat_verify` runs at the real Loquat-128 parameters (kappa=32,
4 rounds, Merkle depth 6, cap 16), derives its fold challenges in-circuit
via Fiat-Shamir, performs the 128 Legendre residuosity checks via the
paper's witness-square-root trick (Algorithm 8), and carries 8 Noir tests
— one consistent opening plus seven tampering cases. Run them with
`nargo test`; they matter because an unsatisfiable circuit still compiles
and still reports a gate count.

Three findings worth keeping:

- **~74% of `loquat_verify`'s gates are Merkle hashing** (896 Poseidon2
  calls = 1,024 permutations, ~75,000 gates; the Merkle-opening blocks in
  total measure 86,274, 85% — stripping them leaves 14,663 gates). Even a
  FRI verifier is mostly a Merkle-path
  verifier. The CAPSS paper reports 41-63% for the same reason.
- **In-circuit Fiat-Shamir cost only 3,135 gates (+3.3%).** Making the
  verifier sound rather than trusting handed-in challenges is cheap; the
  hashing is what costs.
- **All 128 residuosity checks cost 896 gates (7 per check).** A naive
  Legendre symbol is an exponentiation by (p-1)/2, ~380 gates; the
  prover-supplied square root (`w*w == o` for a residue, `w*w == 5*o` for
  a non-residue, plus an inverse check for `o != 0`) replaces it. 5 was
  verified to be a non-residue of BN254's scalar field by Euler's
  criterion and cross-checked by quadratic reciprocity.

`capss_verify` (97,199 gates, 6 tests) is the shape of
`capss::piop::verify` at the `level_128` parameters: complete Fiat-Shamir
replay (352 challenge coefficients and 20 opening indices all squeezed
in-circuit, nothing pinned), 20 Merkle openings against a 16-wide cap
through depth-10 paths, the corrected Flystel combination at each opened
point, and the reconstruct-l'-then-check-sum-to-zero identity. Omitted:
the DECS R_k layer (not load-bearing in this composition), the salt, and
index-in-leaf binding (the path position binds instead). Component
breakdown, measured by compiling stripped variants (sums exactly):
index derivation 35,703 + Merkle 25,746 + constraint combination 13,521 +
Q_k reconstruction 12,065 + transcript sponge 9,421 + key digest 743.

Two findings from it worth keeping:

- **CAPSS's cheap-verifier claim does not survive the shape
  measurement**: 97,199 gates is within 4% of `loquat_verify`. The
  paper's ~24K R1CS assumes Griffin/Anemoi natively over BN254 with
  rho = 1; this circuit inherits the Goldilocks-shaped rho = 2 / 352
  challenges / 404 transmitted coefficients and hashes with Poseidon2,
  so the paper's number and this one are not comparable — but the
  cross-scheme row is, and it says FRI-priced, not cheaper.
- **Deriving opening indices in-circuit is the biggest single cost**:
  each squeezed challenge needs a canonical 254-bit decomposition
  (~1,250-1,800 gates) before its low 14 bits can drive a Merkle path —
  35,703 gates for 20 of them, more than the Merkle paths themselves.
  This is exactly the cost `loquat_verify` avoids by keeping its query
  indices as public inputs (listed there as a gap).

### CAPSS: complete, with caveats

**It signs and verifies.** Measured at `level_128`: signature **18,688 B**,
sign **1.63 s**, verify **8.7 ms**, public key **64 B** (the smallest in
the repo). The paper's Anemoi-3 Short is 9,504 B / 0.7–9.9 s / 29–41 ms —
so ~2x the size and inside the timing range.

**Two caveats that must not be dropped from any summary:**

1. **The DECS degree bound is not load-bearing in this composition.** It
   reconstructs exactly as many low coefficients as it opens points, so its
   reconstruction is self-consistent by construction and contributes no
   independent check. The only load-bearing check is the PIOP's
   sum-to-zero identity. Documented at `capss/src/piop.rs:196`.
2. **The soundness estimate is a heuristic, not a proof** (~124 bits from
   the opening term, ~128 from the challenge term; the spec's grinding
   and HYBRID batching for 64-bit fields are NOT implemented, so ~124 is
   the ceiling by the crate's own estimate). Written out in `piop.rs`'s
   header. Zero knowledge is argued informally too.

**What is genuinely demonstrated:** a forged signature built from a wrong
witness is rejected — single-entry corruptions, another key's honest
execution, pure noise, and a witness *spliced from two real executions*
(which satisfies every per-round constraint and is caught only by wiring).
`piop::tests::the_sum_to_zero_check_is_what_rejects` goes further and
reconstructs `Q_k` by hand to show the DECS/Merkle layer accepts both
honest and forged, and it is the sum-to-zero identity that separates them.
That rules out the rejection being an incidental hash mismatch.

**A design subtlety worth preserving.** The brief originally said to
rebuild the low coefficients from the sum-to-zero condition *plus* the
`l'` opened evaluations — `l'+1` unknowns against `l'+1` equations. That is
wrong: the system is then square and always solvable, so nothing can ever
reject. The implementation reconstructs `l'` coefficients from the `l'`
evaluations and **keeps sum-to-zero as the check**. Do not "simplify" this
back.

`notes/capss-spec.md` has the full specification.

| Module | Status |
|--------|--------|
| `capss/src/field.rs` | Done. Goldilocks `p = 2^64 - 2^32 + 1`, 13 tests incl. 20k random muls against a naive `u128` reference. |
| `capss/src/anemoi.rs` | Done. Anemoi alpha=7, t=8, l=4, 11 rounds. MDS verified by every square submatrix determinant. |
| `capss/src/keys.rs` | Done. OWF + keypair, `sk` 32 B, `pk` 64 B. 6 tests. |
| `capss/src/pacs.rs` | Done. RegRounds arithmetization, `b = 1`. 7 tests. |
| `capss/src/transcript.rs` | Done. Anemoi sponge XOF. |
| `capss/src/merkle.rs` | Done. Jive compression, not sponge. |
| `capss/src/decs.rs` | Done. Degree-enforcing commitment, 747 lines, 9 tests. |
| `capss/src/piop.rs` | Done. The SmallWood PIOP, 1012 lines. |
| `capss/src/sig.rs` | Done. `sign`/`verify` + the Fiat-Shamir chain. |
| LVCS / PCS as separate layers | Folded into `piop.rs` rather than split out. |

**87 tests** pass in `capss` (plus 1 ignored); **173** across the
workspace. Clippy is clean workspace-wide.

Parameters at `level_128`: from the paper, `s = 11`, `n = 16`, `m1 = 8`,
`m2 = 88`, `d = 7`, `N = 2^14` (the "Short" trade-off). Chosen here:
`l' = 20`, `rho = 2` (fewest that reaches 128 bits over a 64-bit field),
`eta = 2`, **arity 2** — at `t = 8` only arity 2 gives `2*lambda`-bit
Merkle nodes, since `merkle::node_width` is `t/arity`, so arity 4 would
silently halve node security. `Parameters::testing()` is a fast toy for
the default suite and says so.

`decs.rs`'s degree-enforcement test is the one to trust: it commits a
polynomial of degree `d_decs + 1` and shows the verifier's reconstruction
of `R_k` **differs depending on which points were opened** — which is
exactly the property that makes the commitment degree-enforcing, and is
much stronger than merely checking a tampered opening fails.

`capss/src/lib.rs` is owned by the integrator, not by the module authors —
agents were told to create files and let it be wired in, to avoid
collisions. Wire new modules there yourself.

**Headline result from the arithmetization:** an honest execution trace
satisfies all 88 parallel and 88 aggregated constraints across 25
independent key pairs, and corrupting any one of the 176 witness entries
(528 cases tried) breaks at least one constraint. A witness spliced from
two different executions passes every *parallel* constraint and is caught
only by the wiring family — which is exactly what wiring is for.

**Correction now recorded in `notes/capss-spec.md`:** the Flystel
round-verification identity as commonly transcribed is wrong by `2*delta`.
The corrected form, and why `|v| = 0` and `|iv| = 4`, are written up
there. Do not re-derive it from the bad version.

Chosen, not from the paper: **batching factor `b = 1`**. 11 rounds is
prime, so only `b = 1` and `b = 11` divide it exactly, and `b = 11`
degenerates to `s = 1` (no wiring at all). The code is written against the
constant rather than hardcoded, so it can change if the round count does.

**Invented, not faithful** (must stay documented as such): all 88 Anemoi
round constants (splitmix64, seed `0xA11E3701C0DE5EED`; the reference uses
digits of pi) and the diffusion matrix (a 4x4 Cauchy matrix, chosen
because Cauchy is provably MDS; the reference's is cheaper). This will
**not** interoperate with the CAPSS reference implementation.

Also worth knowing: over Goldilocks, `alpha = 3` **and** `alpha = 5` are
both invalid (`p - 1 = 2^32 * 3 * 5 * 17 * 257 * 65537`), which is why 7
is used. There is a test asserting this rather than only prose.

### Explicitly not done, and why

- **A real degree-enforcing role for DECS.** See caveat 1 above. Making it
  load-bearing means implementing the paper's Brakedown-style chunking so
  every committed polynomial shares one degree bound — roughly 8x the leaf
  width and signing cost, which is why it was skipped.
- **The rest of Loquat's signature-size gap.** Now 68.8 KB against the
  paper's 57 KB, down from 75.8 KB. The two derivable-value savings are
  implemented (see task 1 below, now done). Where the remaining ~21% comes
  from is **not diagnosed** — the paper does not break its 57 KB down far
  enough to say.

---

## In flight right now

| Work | Files owned | Status |
|------|-------------|--------|
| Fix `loquat_verify` cap/position wart + add the 128 residuosity checks (witness-square-root gadget, measured 7 gates/check) | `circuits/loquat_verify/` | **done, 98,633 → 100,937 gates, 8 tests** |
| Build `circuits/capss_verify/` (Merkle openings + FS replay + Q_k reconstruction + sum-to-zero) | `circuits/capss_verify/` (new) | **done, 97,199 gates, 6 tests** |

Both agents also update their own rows/sections in `circuits/README.md`,
root `README.md`, and this file's gates table — the edits target disjoint
text, but if you find a half-updated table, that is why; reconcile against
`bb gates` output rather than guessing.

Design note recorded at dispatch: the residuosity checks use the paper's
own SNARK trick (Algorithm 8) — prover-supplied square root `w` with
`w^2 == o` for a residue or `w^2 == ALPHA * o` for a non-residue, ALPHA a
fixed public non-residue — instead of the naive `(p-1)/2` exponentiation.
Estimated ~3 gates per check at dispatch; measured 7 per check with
`bb gates`. This trick is also exactly why keygen
excludes `K = -I_l` (honest `o` is never zero).

**Completed and verified so far:**

- Loquat signature-size fix, 75.8 → 68.8 KB.
- CAPSS foundation (Goldilocks field + Anemoi), arithmetization + keys,
  transcript + Merkle + DECS. All wired into `lib.rs` and passing.
- In-circuit Fiat-Shamir for `loquat_verify`, 94,602 → 98,633 gates.
  (That +4,031 bundled other edits; the FS replay alone measures 3,135
  gates — re-verified by compiling a challenge-pinned variant of the
  final circuit, 100,937 → 97,802.)
- `poseidon2` refactored to `std::ops` traits; `loquat` loop-index
  warnings cleared. **Clippy is now clean workspace-wide.** Both refactors
  confirmed behaviour-neutral (leanSig still 147 tries / 385 steps;
  Loquat signature was 70,448 B at that point; it is 63,760 B now).

One note on the DECS agent: it hit an API session limit and died *before
reporting*, but its work had already landed on disk and is complete and
tested. Worth remembering that a failed agent does not always mean lost
work — check the files before redoing anything.

### Note on git state

The user has committed and pushed some of this themselves (`main` is in
sync with `origin/main`, two commits authored by them). That was their
doing, not the agents' — the no-commit rule still stands for you. Do not
infer from the existing commits that committing is now acceptable.

CAPSS parameter decision, made when dispatching: **Goldilocks**
(`p = 2^64 - 2^32 + 1`) with **Anemoi, alpha = 7, t = 8, 11 rounds**,
matching the reference C configuration — not BN254. Reasons: 64-bit
modular arithmetic is far less error-prone than 256-bit, the paper's own C
build uses this configuration, and it is ~25x faster.

## Production-readiness TODO

Everything the user originally asked for is built. What follows is the
honest distance between "teaching repo, all tests green" and "usable in
production, bug free". It is long on purpose: signature code guards keys,
and the bar is an audit, not a passing test suite. Items are ordered so
that each phase makes the next one meaningful — there is no point
hardening constants-time behaviour in code whose constants are wrong.

### Phase 1 — Correctness against the outside world

The single biggest risk in this repo is that nothing external confirms
it. Everything below reduces that risk.

- [ ] **Replace every invented constant with the reference one.**
      `poseidon2`: Grain-LFSR round constants from the Poseidon2 spec, not
      splitmix64. `capss/anemoi.rs`: pi-derived round constants and the
      reference MDS, not Cauchy (port from `anemoi-rust` /
      `hash_f64_benchmarks`; see `capss/external` notes in the spec).
      Loquat: pin the `I_1..I_L` derivation to something agreed with
      upstream, or adopt whatever LoquatPy's maintainers standardise.
- [ ] **Generate or obtain test vectors and check against them.**
      Poseidon2 has published vectors — start there, it is the cheapest
      win and validates the whole leanSig stack. For Loquat, run LoquatPy
      (needs SageMath) on fixed inputs and match intermediate values
      (digits, sumcheck mu, FRI layers), accepting that full
      byte-compatibility also needs their Fiat-Shamir quirks replicated
      behind a compatibility flag. For CAPSS, the C implementation is the
      byte-exact authority.
- [ ] **Differential-test the field layers.** `loquat::field` and
      `capss::field` against a bigint reference (`num-bigint`) across
      billions of random and structured inputs (0, 1, p-1, powers of two,
      carry boundaries). The Goldilocks reduction and the Mersenne fold
      are exactly the kind of code where a one-in-2^40 carry bug lives.
- [ ] **Cross-validate XMSS/WOTS against RFC 8391 vectors** after
      swapping in standard parameter conventions, or clearly rename them
      as pedagogical variants so nobody mistakes them for the RFC.
- [ ] **Fuzz all deserialization and verification paths** (cargo-fuzz):
      verifiers must reject, never panic, on arbitrary bytes. Today the
      structs are in-memory only, which hides this whole class of bugs —
      see Phase 5.

### Phase 2 — Complete the verifiers (currently partial by design)

- [ ] `loquat_verify`: absorb `o_values`/`t_bits` into the transcript
      that yields the FRI challenges (the real h1/h2 phases); derive the
      query indices in-circuit (measured cost estimate: ~35K gates, see
      the capss_verify finding); add the sumcheck opening-consistency
      checks that `sig.rs::verify` performs natively. Only then may the
      "shape measurement" caveat be softened.
- [ ] `capss_verify`: add the DECS R_k layer once (and only once) DECS
      is made load-bearing natively — see Phase 4. Add salt handling and
      index-in-leaf binding.
- [ ] **Rust-circuit interop**: today the circuits deliberately do not
      verify real signatures (different fields/hashes). Production use of
      "verify a signature inside a proof" needs one consistent
      instantiation end to end — realistically: pick the target proof
      system first, then re-instantiate the Rust side over its field
      rather than emulating a foreign field in-circuit.

### Phase 3 — Key-handling and side-channel hardening

None of this exists today, anywhere in the repo.

- [ ] **Constant-time secret paths.** Legendre symbol on secret-derived
      values (`loquat`), hash-chain walks whose lengths derive from
      digits (`wots`/`leansig`/`xmss`), Anemoi on `iv||x` (`capss`), and
      all field arithmetic under secrets. Use `subtle`-style primitives;
      add `dudect`-style statistical timing tests to CI.
- [ ] **Zeroization.** Secret keys, seeds, blinders `r`, witnesses, and
      every intermediate holding them: `zeroize` + `Drop`, and no
      `Debug`/`Clone` leaking secrets into logs.
- [ ] **RNG discipline.** Everything secret-bearing must draw from a CSPRNG
      passed in by the caller (`rand_core::CryptoRng` bound), not
      `thread_rng()` grabbed internally — auditable and testable.
      Consider derandomized signing (RFC 6979-style) where the scheme
      allows it; note Loquat's blinders MUST stay unpredictable.
- [ ] **One-time/stateful key misuse resistance.** Lamport/WOTS consume
      `self` (good, keep); XMSS needs persistent, crash-safe index state
      (write-ahead before signing, not after) and an explicit API story
      for backups — this is *the* classic deployment footgun, currently
      just a README warning.

### Phase 4 — Soundness and parameters (the cryptography itself)

- [ ] **Make CAPSS's DECS degree bound load-bearing**: implement the
      paper's Brakedown-style chunking so all committed polynomials share
      one row bound (~8x leaf width and signing cost). Until then the
      scheme's security argument leans entirely on the PIOP sum-to-zero
      heuristic.
- [ ] **Replace heuristic soundness estimates with worked analyses.**
      Loquat: map our deviations (virtual FRI layer 0 above all) onto the
      paper's soundness accounting and confirm the query budget still
      reaches the target level; the virtual-layer argument is standard
      but must be *written down against this construction*. CAPSS: the
      grinding/uniformity assumptions flagged in `piop.rs` need real
      treatment.
- [ ] **Parameter review by a cryptographer.** kappa/eta/rate for
      Loquat; l'/rho/eta/arity for CAPSS; leanSig's TARGET_SUM trade-off.
      All currently chosen by reading the papers, not by independent
      analysis.
- [ ] **Zero-knowledge review**: mask degrees vs query budgets in both
      proof schemes were set from the papers; confirm the simulators
      actually go through for this exact code (Loquat's shared-vs-per-poly
      mask choice, CAPSS's pad construction).

### Phase 5 — Engineering quality

- [ ] **Serialization.** Canonical, versioned, length-checked encodings
      for keys/signatures with strict decode-reject rules (non-canonical
      field elements, trailing bytes, mismatched lengths). Today
      `size_bytes()` *estimates* what serialization would cost; nothing
      actually round-trips through bytes. This blocks fuzzing, interop,
      and any real use.
- [ ] **No panics on untrusted input.** Audit every `unwrap`/`expect`/
      slice-index reachable from `verify` with attacker-controlled data;
      verifiers return `false` or typed errors, never abort.
- [ ] **API redesign for misuse resistance**: typed errors instead of
      `bool` from verify (but constant-shaped rejection reasons —
      distinguishable errors can be an oracle); sign/verify over
      pre-hashed vs raw messages made explicit; domain-separation strings
      as part of the public API.
- [ ] **CI**: build + test + clippy + fmt on every change, plus the Noir
      circuits compiled and `nargo test`ed, plus timing-leak and fuzz
      smoke jobs. Nothing is automated today; the numbers in the READMEs
      are hand-run.
- [ ] **Property tests** (proptest): sign/verify round-trips, serialize/
      deserialize round-trips, arbitrary-tamper-always-rejects, across
      random parameter sets where cheap.

### Phase 6 — Process, the part that cannot be skipped

- [ ] **Independent security audit** of whatever subset is meant to ship
      — after Phases 1-5, not before, or the audit money buys findings
      this list already contains.
- [ ] **Spec documents** per scheme: exact byte-level description of what
      this code implements, including every deviation from the papers
      (they are currently scattered across READMEs and module docs —
      collect them, they are load-bearing for the audit).
- [ ] **Decide what this repo is.** Honest fork in the road: either it
      stays a teaching repo (in which case Phases 3-6 are out of scope
      and the READMEs already say "do not use") or a subset is hardened
      into a real library — in which case pick ONE scheme first
      (leanSig is the strongest candidate: simplest, standard-adjacent,
      an active ecosystem converging on it) rather than hardening all
      seven at once.

### Known sharp edges to fix regardless (small, concrete)

- [ ] `leansig::sign` can fail (`Option`) after MAX_ATTEMPTS; callers
      must handle it — make the error typed and document the probability.
- [ ] `loquat` setup re-derives 32,768 indices per `Params` construction
      (~2-4 ms) — cache or make explicit.
- [ ] CAPSS `sign` at 1.6 s is single-threaded; the DECS leaf loop is
      embarrassingly parallel (rayon would cut it several-fold).
- [ ] The circuits' `Prover.toml`-style inputs are only exercised through
      Noir tests; provide a real witness-generation path from the Rust
      side if interop (Phase 2) ever lands.
- [ ] `xmss` keygen at h=10 takes 125 ms and all of it is recomputable
      from a seed — implement seed-based key derivation like `leansig`'s
      (currently it stores every WOTS key).

## Next tasks, roughly in order of value

Nothing is half-finished — the repo is coherent as it stands. Pick
whichever of these the user wants. (The production TODO above supersedes
this list where they overlap; this is kept for continuity.)

### 1. Loquat's signature-size gap — **done, 75.8 → 68.8 → 62.3 KB**

Now **63,760 B** against the paper's 57 KB (~9% over). Two savings live
in the code:

- **From the paper:** after FRI round 1, the value the previous fold pins
  down is omitted; `verify` reinserts it *before* hashing the leaf, so
  the Merkle check still sees the complete fiber. Worth ~3 KB.
- **FRI's first layer is virtual** (see the `Proof` doc in `fri.rs`). The
  batched codeword is a public combination of `c`/`s`/`h`, all committed
  before any challenge was drawn, so it is never committed itself: no
  layer-0 tree, paths, or values. `fri::verify` became two phases —
  `replay_transcript` then `check_queries` — because the caller computes
  the layer-0 fibers at the queried positions in between. Worth ~6.7 KB.
  **Deviates from the paper** (which ships `rootf^(0)`) in the direction
  of standard practice: Fractal/Plonky2/Winterfell treat their
  composition polynomial exactly this way.

History note: an earlier revision instead solved the `h` openings from
sent layer-0 values. The two optimizations are **mutually exclusive** —
per queried point there are two unknowns (`h`, batched value) and one
affine relation, so exactly one must travel. The virtual-layer route
saves 6.7 KB where the h-solve saved 4 KB, and sending `h` is what the
paper does. Do not reintroduce the h-solve on top; it cannot compose.

Still open: the remaining ~5 KB. Note the three codeword trees (`c`, `s`,
`h`) **cannot** be merged into one to share a Merkle path — each is
committed at a different point in the transcript because later challenges
depend on the earlier roots.

### 2. Extend `loquat_verify` toward a complete verifier

**In-circuit Fiat-Shamir is now done** — fold challenges are derived from
the Merkle caps inside the circuit, at a cost of 3,135 gates (+3.3%).
94,602 → 98,633.

**The 128 Legendre residuosity checks are now done** — via the paper's
Algorithm 8 witness-square-root trick rather than the naive `(p-1)/2`
exponentiation: 896 gates for all 128 (7 per check, against ~380 naive).
ALPHA = 5, verified a non-residue of BN254's scalar field by Euler's
criterion and cross-checked by reciprocity. 98,633 → 100,937 including
the geometry fix below.

**The modelling wart is fixed** — `fold_to_cap` used to build a 6-bit
position while `select` indexed a 16-entry cap, so positions 16..63 were
unreachable. Leaf indices are now the real 10 bits: the low 6 walk the
path below the cap and the high 4 name the cap slot, matching
`loquat/src/merkle.rs::fold_to_cap` where the position left after the
walk IS the cap index. A negative test (`rejects_a_wrong_cap_slot`)
covers it.

What is still missing:

- **Query indices are pinned, not squeezed.** They are a public input.
  Deriving them would also require deriving `domain_points` from a domain
  generator and modelling the per-round domain shrink, neither of which
  the circuit does.
- **The residuosity inputs are outside the transcript.** `o_values` and
  `t_bits` are not absorbed into the transcript that yields the FRI
  challenges (the real scheme's h1/h2 phases), and the sumcheck opening
  consistency `sig.rs::verify` checks is absent. The circuit is still a
  shape-measurement, not comparable to the paper's 148,825 R1CS.

### 3. CAPSS — finish the proof system

Foundation, arithmetization and commitment layers are done or in flight
(see the table above). What remains, in dependency order:

1. **LVCS** — rows extended with `l` random values, proving
   `v_k = sum_j c_kj r_j`.
2. **PCS** — Brakedown-style coefficient matrix, chunked and stacked.
3. **PIOP** — the core identity: `sum over omega in Omega of Q_k(omega) = 0`
   for each `k` in `[1, rho]`, with `deg_q = d * (l' + s - 1) + s`.
   Parallel constraints vanish at every omega individually; aggregated
   ones only sum to zero.
4. **The four-hash Fiat-Shamir chain** and `sign`/`verify`. Note
   verification is a **transcript-recomputation equality check**, not an
   explicit constraint check — that is what makes CAPSS's R1CS compact,
   and it is easy to implement wrongly as the latter.
5. A `capss/README.md` in the house style, and a row in `compare`.

Section 6 of `notes/capss-spec.md` has the parameter sets. Note the
paper's own numbers: signing is genuinely slow (0.03–10 s), and Merkle
path verification is 41–63% of its R1CS.

### 4. Housekeeping

- Clippy is **clean** for `poseidon2`, `leansig`, `lamport`, `wots`, and
  `xmss`. `poseidon2::F` was refactored from inherent `add`/`sub`/`mul`
  methods to proper `std::ops` trait impls (matching `loquat/src/field.rs`),
  and the permutation loops now iterate the round constants directly.
  Verified behaviour-neutral: leanSig still measures 147 target-sum tries
  and 385 verifier chain steps, exactly as before.
- **`cargo clippy --workspace` is now completely clean.** `loquat`'s
  loop-index warnings were fixed by iterating/zipping rather than indexing;
  63 tests passed at that point and the signature was 70,448 B, so the change
  was behaviour-neutral.
- Superseded note, kept so nobody re-reads it as current: `loquat` used to
  have loop-index style warnings, left alone because an
  agent was editing that crate at the time. Clean them when it is free.
- The `compare` binary does not include a Loquat *setup* timing (deriving
  the 32768 public indices, ~2 ms); it is deliberately outside the
  per-key numbers since it is shared across all users.

---

## House style

Both languages:

- Comments explain **why**, not what. Do not narrate the code.
- No comment blocks at the top of every function. Reserve doc comments for
  things that need context (a protocol step, a non-obvious constraint, a
  deviation from a paper).
- Descriptive names over short ones: `message_digest`, not `md`.
- Every non-obvious constant gets a sentence saying where it came from.

READMEs (this is a strong user preference):

- Plain language. **No big words.** The user asked for READMEs that are
  "really easy to follow and not too long — just long enough to cover the
  complete understanding of how the signature works".
- Explain the maths step by step, with small worked fragments.
- State the honest cost and the honest limitations at the end.

Rust:

- Unit tests live in the same file under `#[cfg(test)] mod tests`.
- Always include *negative* tests: tampered message, tampered signature,
  wrong key, out-of-range index. These carry most of the real assurance.
- One-time schemes take `self` by value in `sign()` so the type system
  enforces single use. Preserve that.

Noir:

- All circuits share conventions so the comparison is fair:
  the public key is a **single field element** (a Poseidon2 digest that
  the circuit recomputes), the message is passed **pre-hashed** as one
  field element, and everything hashes with **Poseidon2**.
- Dependencies are `poseidon` v0.3.0 and `sha256` v0.2.0 from
  `noir-lang` (v0.1.2 of sha256 does **not** compile on this toolchain).
- Gate counts come from `nargo compile && bb gates -b target/<name>.json`.
  Use `circuit_size`, not `acir_opcodes` — Poseidon2 is a builtin, so
  opcode counts badly understate it.

Toolchain on this machine: `nargo` 1.0.0-beta.20, `bb` 5.0.0-nightly,
`cargo` 1.92.0. Noir API notes: `u1` was removed, use `bool`; shift
operands must share a bit width (use `/` and `%` instead); `Poseidon2`
moved out of stdlib into the `poseidon` crate.

---

## Key decisions already made (do not silently reverse)

- **Rust and Noir do not interoperate, on purpose.** Rust runs Poseidon2
  over BabyBear; Noir runs it over BN254. Rust measures native speed and
  signature size; Noir measures gate counts. Making them byte-compatible
  would mean emulating BabyBear inside BN254 and would ruin the numbers.
  This is documented in `circuits/README.md` — keep it documented.
- **Poseidon2 round constants** are generated by a documented splitmix64
  PRG, not the reference Grain LFSR. So this will not interoperate with
  other Poseidon2 libraries. Called out in the code and root README.
- **Loquat follows the paper, not the authors' `LoquatPy`** where the two
  disagree. LoquatPy is an explicit proof-of-concept with real
  Fiat-Shamir problems: it sums all hash inputs into one field element, it
  does not chain the previous challenge into FRI round hashes, and it
  draws challenge indices from overlapping 15-bit windows. We do the sound
  thing in all three cases. Documented in `loquat/README.md`.
- **Loquat public indices** are derived from a fixed seed via the
  transcript. The paper leaves this open; storing them outright would be
  512 KB.

---

## Validation status — be precise about this

**Independently validated:** field arithmetic against schoolbook
identities; the FFT against naive Horner evaluation; Legendre symbol
multiplicativity; FRI accepting low-degree and rejecting high-degree,
random, and tampered codewords; Merkle openings under every tampering
variant; the Loquat arithmetisation identity checked directly
(`sig.rs::sumcheck_identity_matches_the_public_inner_product`) — this is
the hinge the whole scheme turns on.

**Self-consistent only:** the end-to-end Loquat signature. There are **no
published test vectors for Loquat**, and we are deliberately not
byte-compatible with LoquatPy, so nothing external confirms it.

**Not done at all:** any security audit; constant-time behaviour (nothing
here is side-channel hardened); formal soundness verification.

None of this should be used to protect anything real, and the READMEs say
so.

---

## Useful commands

```
cargo test --workspace                              # 170 tests
cargo run --release -p compare                      # native comparison table
cargo run --release -p loquat --example loquat128   # real Loquat-128 params
cargo run --release -p leansig --example trials     # target-sum search cost

cd circuits/<name> && nargo compile && bb gates -b target/<name>.json
cd circuits/loquat_verify && nargo test              # 8 satisfiability tests
cd circuits/capss_verify && nargo test               # 6 satisfiability tests
```

Benchmarks are sensitive to machine load — if background agents or builds
are running, the numbers drift by 2-4x. Re-run on an idle machine before
putting any timing into a README.

---

## Scratch artefacts from research

Fetched by subagents earlier, under the session scratchpad
(`/private/tmp/claude-501/-Users-pardis-Documents-pardis/<session>/scratchpad/`):
`loquat.pdf`, `loquat.txt` (52 pages of extracted text), and a clone of
`LoquatPy`. These may be gone in a new session; both papers are on IACR
ePrint (2024/868 and 2025/061), reachable via Wayback `id_` raw URLs when
Cloudflare blocks direct fetches.
