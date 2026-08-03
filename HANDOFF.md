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
   leave it out and say why (this is exactly why Loquat/CAPSS are missing
   from the circuits table).
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

`cargo test --workspace` → **104 tests passing.**
`cargo run --release -p compare` → the native table in the root README.
`cd circuits/loquat_verify && nargo test` → 5 tests passing.

### Done

| Crate | Status |
|-------|--------|
| `lamport` | Complete, 3 tests, README |
| `wots` | Complete, 3 tests, README |
| `xmss` | Complete, 4 tests, README |
| `poseidon2` | Complete (BabyBear), 4 tests. Clippy clean. |
| `leansig` | Complete, 6 tests, README. Faithful to Ethereum's design. |
| `loquat` | **Complete**, 63 tests, README. Full ePrint 2024/868 at real Loquat-128 params. Signature 68.8 KB. |
| `capss` | **Partial** — see below. Cannot sign or verify yet. |
| `compare` | Benchmarks all six working schemes |
| `circuits/` | 5 circuits + `hash_bench`, all measured, README |

### Noir circuits measured (UltraHonk gates via `bb gates`)

| Circuit | Gates |
|---------|-------|
| `lamport_verify` | 33,756 |
| `leansig_verify` | 72,304 |
| `wots_verify` | 84,582 |
| `xmss_verify` | 86,596 |
| `loquat_verify` | 98,633 |
| Poseidon2 (per call) | ~73 |
| SHA-256 (per call) | ~36,000 |

`loquat_verify` runs at the real Loquat-128 parameters (kappa=32,
4 rounds, Merkle depth 6, cap 16), derives its fold challenges in-circuit
via Fiat-Shamir, and carries 5 Noir tests — one consistent opening plus
four tampering cases. Run them with `nargo test`; they matter because an
unsatisfiable circuit still compiles and still reports a gate count.

Two findings worth keeping:

- **~66% of `loquat_verify`'s gates are Merkle hashing** (896 Poseidon2
  calls, ~65,000 gates). Even a FRI verifier is mostly a Merkle-path
  verifier. The CAPSS paper reports 41-63% for the same reason.
- **In-circuit Fiat-Shamir cost only 3,135 gates (+3.3%).** Making the
  verifier sound rather than trusting handed-in challenges is cheap; the
  hashing is what costs.

### CAPSS: what exists so far

Being built now. `notes/capss-spec.md` has the full specification.

| Module | Status |
|--------|--------|
| `capss/src/field.rs` | Done. Goldilocks `p = 2^64 - 2^32 + 1`, 21 tests incl. 20k random muls against a naive `u128` reference. |
| `capss/src/anemoi.rs` | Done. Anemoi alpha=7, t=8, l=4, 11 rounds. MDS verified by every square submatrix determinant. |
| `capss/src/keys.rs` | Done. OWF + keypair, `sk` 32 B, `pk` 64 B. 6 tests. |
| `capss/src/pacs.rs` | Done. RegRounds arithmetization, `b = 1`. 7 tests. |
| `capss/src/transcript.rs` | Done. Anemoi sponge XOF. |
| `capss/src/merkle.rs` | Done. Jive compression, not sponge. |
| `capss/src/decs.rs` | In progress (degree-enforcing commitment). |
| LVCS / PCS / PIOP / sign / verify | **Not started.** |

**58 tests** pass in `capss` as of the modules wired in so far.

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

- **CAPSS sign/verify.** The foundation and (in flight) the
  arithmetization and commitment layers exist, but LVCS, PCS, PIOP and the
  signing/verification algorithms do not. The crate **cannot produce a
  signature yet**, and must not be described as if it can.
- **The rest of Loquat's signature-size gap.** Now 68.8 KB against the
  paper's 57 KB, down from 75.8 KB. The two derivable-value savings are
  implemented (see task 1 below, now done). Where the remaining ~21% comes
  from is **not diagnosed** — the paper does not break its 57 KB down far
  enough to say.

---

## In flight right now

Two parallel agents are working on CAPSS. If you are picking this up
mid-stream, check whether these landed before touching the same files.

| Work | Files owned | Status |
|------|-------------|--------|
| CAPSS arithmetization + keys | `capss/src/pacs.rs`, `capss/src/keys.rs` | running |
| CAPSS commitment layer | `capss/src/transcript.rs`, `capss/src/merkle.rs`, `capss/src/decs.rs` | running |

Neither may edit `capss/src/lib.rs` — the integrator wires modules in, so
the two cannot collide there.

**Completed and verified this round:** Loquat signature-size fix
(75.8 → 68.8 KB), CAPSS field + Anemoi, in-circuit Fiat-Shamir for
`loquat_verify` (94,602 → 98,633 gates), and a `poseidon2` clippy refactor
to `std::ops` traits (behaviour-neutral, confirmed by leanSig still
measuring 147 tries / 385 steps).

CAPSS parameter decision, made when dispatching: **Goldilocks**
(`p = 2^64 - 2^32 + 1`) with **Anemoi, alpha = 7, t = 8, 11 rounds**,
matching the reference C configuration — not BN254. Reasons: 64-bit
modular arithmetic is far less error-prone than 256-bit, the paper's own C
build uses this configuration, and it is ~25x faster.

## Next tasks, roughly in order of value

Nothing is half-finished — the repo is coherent as it stands. Pick
whichever of these the user wants.

### 1. Close Loquat's signature-size gap — **done, 75.8 KB → 68.8 KB**

Two values are now derived rather than sent, both on the same principle:

- **FRI.** `prove` drops the fiber value the previous round's fold pins
  down (rounds >= 1); `verify` reinserts it *before* hashing the leaf, so
  the Merkle check still sees the complete fiber. Worth 3072 B.
- **The `h` openings.** These are *not* a carried value — layer 0 has no
  previous fold — but they are still derivable: the batched codeword FRI
  tested is affine in `h`, so `verify` solves for `h` by evaluating that
  map at 0 and 1, then checks the solved values against `h`'s Merkle
  commitment. `open_h` is now paths only. Worth 4096 B.

Both are soundness-neutral: the omitted values are recomputed and must
still reproduce what was committed to. The `h` derivation additionally
rejects if the affine map is degenerate (slope zero), which happens with
negligible probability over the Fiat-Shamir challenges.

Still open: nobody has explained the remaining ~21%. Note the three
codeword trees (`c`, `s`, `h`) **cannot** be merged into one to share a
Merkle path — each is committed at a different point in the transcript
because later challenges depend on the earlier roots.

### 2. Extend `loquat_verify` toward a complete verifier

**In-circuit Fiat-Shamir is now done** — fold challenges are derived from
the Merkle caps inside the circuit, at a cost of 3,135 gates (+3.3%).
94,602 → 98,633.

What is still missing:

- **The 128 Legendre symbol checks** — `L_0(o) == pk_I + T`. Expensive in
  a circuit (a Legendre symbol is an exponentiation), which is precisely
  why the paper's arithmetization works so hard to avoid doing them
  naively. Read the paper's Algorithm 8 before attempting this. This is
  the main thing standing between the circuit and being a real verifier.
- **Query indices are pinned, not squeezed.** They are a public input.
  Deriving them would also require deriving `domain_points` from a domain
  generator and modelling the per-round domain shrink, neither of which
  the circuit does.
- **A known modelling wart:** `fold_to_cap` builds a 6-bit position while
  `select` indexes a 16-entry cap, so positions 16..63 are unreachable.
  Harmless for the current measurement, but fix it before trusting the
  circuit for anything else.

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
  63 tests still pass and the signature is still 70,448 B, so the change
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
cargo test --workspace                              # 104 tests
cargo run --release -p compare                      # native comparison table
cargo run --release -p loquat --example loquat128   # real Loquat-128 params
cargo run --release -p leansig --example trials     # target-sum search cost

cd circuits/<name> && nargo compile && bb gates -b target/<name>.json
cd circuits/loquat_verify && nargo test              # 5 satisfiability tests
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
