//! Loquat's FRI query checks, in-circuit.
//!
//! # What this measures, and what it does not
//!
//! This is **not** a complete Loquat verifier, and its gate count must not
//! be compared against the paper's 148,825 R1CS figure. Two reasons:
//!
//! 1. That figure assumes the algebraic **Griffin** hash and the real
//!    field (`F_p2` over `p = 2^127 - 1`). This circuit uses Poseidon2
//!    over BN254, because emulating a 127-bit extension field inside
//!    BN254 would dominate the measurement and teach us nothing.
//! 2. This covers the FRI **query-checking core** plus the Fiat-Shamir
//!    replay that produces the fold challenges, plus the 128 Legendre
//!    residuosity checks (via the paper's witness-square-root trick, see
//!    `main`). What it still does NOT do: absorb `o_values` and `t_bits`
//!    into the same transcript that yields the FRI challenges (the real
//!    scheme's h1/h2 phases), derive the query indices in-circuit, or
//!    verify the sumcheck opening consistency that `sig.rs::verify` does.
//!    It remains a shape-measurement, not a complete verifier.
//!
//! # Fiat-Shamir
//!
//! The fold challenges are **derived inside the circuit**, not taken as
//! inputs: each round's Merkle root is recomputed from its cap, absorbed
//! into a running transcript state, and the challenge squeezed back out.
//! A prover who wants a friendlier challenge has to change a cap, and the
//! cap is what the Merkle openings are checked against.
//!
//! The query indices are still a public input rather than squeezed from
//! the transcript -- see `main` for why.
//!
//! What it is good for: showing how a proof-system verifier is shaped
//! differently from a hash-chain verifier, and where its gates go.
//!
//! Ported from `loquat/src/fri.rs::verify`, which is the tested reference.

use poseidon::poseidon2::Poseidon2;

/// FRI queries, matching the Rust crate's Loquat-128 set.
global KAPPA: u32 = 32;
/// Folding rounds.
global ROUNDS: u32 = 4;
/// Points per fiber, `2^eta` with eta = 2.
global FIBER: u32 = 4;
/// Merkle path length below the cap: log2(1024 leaves) - 4 cap levels.
global DEPTH: u32 = 6;
/// Cap width in nodes, from the paper's `ceil(log2(kappa) - 1) = 4`.
global CAP: u32 = 16;
/// Bits needed to name a cap slot: log2(CAP).
global CAP_BITS: u32 = 4;
/// A full leaf index in the 1024-leaf tree: the low DEPTH bits walk the
/// path below the cap, the high CAP_BITS bits name the cap entry.
global INDEX_BITS: u32 = DEPTH + CAP_BITS;
/// The fully folded polynomial is a constant at these parameters.
global FINAL_COEFFS: u32 = 1;
/// Legendre residuosity symbols per signature, Loquat-128's B.
global B: u32 = 128;
/// A fixed quadratic non-residue of the BN254 scalar field, needed by the
/// residuosity gadget. Checked two independent ways before use: Euler's
/// criterion, 5^((r-1)/2) == r - 1 (computed with big-integer arithmetic),
/// and quadratic reciprocity (r ends in 7, so r = 2 mod 5, and 2 is a
/// non-residue mod 5; 5 = 1 mod 4 makes the reciprocity sign +1).
global ALPHA: Field = 5;

// Transcript domain separators. The Rust transcript tags its hashes with
// byte strings; distinct field constants do the same job here. The two are
// deliberately not byte-compatible (different field, different hash), so
// only distinctness and ordering carry over.
global TAG_INIT: Field = 1;
global TAG_ABSORB: Field = 2;
global TAG_SQUEEZE: Field = 3;
global TAG_CAP: Field = 4;
global LABEL_FRI_ROOT: Field = 5;
global LABEL_FRI_FOLD: Field = 6;

/// The Rust verifier checks each round's root against `hash_many(b"cap",
/// cap)` and absorbs the root. Recomputing it the same way here is what
/// makes the challenge depend on the commitment the openings are pinned to,
/// including cap entries no query happens to touch.
fn root_from_cap(cap: [Field; CAP]) -> Field {
    let mut preimage: [Field; CAP + 1] = [0; CAP + 1];
    preimage[0] = TAG_CAP;
    for i in 0..CAP {
        preimage[i + 1] = cap[i];
    }
    Poseidon2::hash(preimage, CAP + 1)
}

fn absorb_root(state: Field, root: Field) -> Field {
    Poseidon2::hash([TAG_ABSORB, state, LABEL_FRI_ROOT, root], 4)
}

/// Squeezes a challenge and the next state from the same call, the way the
/// Rust transcript reads both out of one XOF stream. The state has to
/// advance, or two challenges drawn in a row would be identical.
fn squeeze(state: Field, label: Field) -> (Field, Field) {
    let next_state = Poseidon2::hash([TAG_SQUEEZE, state, label, 0], 4);
    let challenge = Poseidon2::hash([TAG_SQUEEZE, state, label, 1], 4);
    (next_state, challenge)
}

/// Replays the FRI half of the Fiat-Shamir transcript: absorb round `i`'s
/// root, then squeeze round `i`'s fold challenge, chaining the state
/// throughout. Round `i`'s challenge therefore depends on caps `0..=i` and
/// on nothing after them, matching `fri::verify`.
///
/// `fri::verify` carries on from here by absorbing the final coefficients
/// and squeezing the query indices. Those absorbs are omitted because the
/// indices stay a public input, so nothing would consume them.
fn derive_fold_challenges(caps: [[Field; CAP]; ROUNDS]) -> [Field; ROUNDS] {
    let mut state = Poseidon2::hash([TAG_INIT], 1);
    let mut challenges: [Field; ROUNDS] = [0; ROUNDS];

    for round in 0..ROUNDS {
        state = absorb_root(state, root_from_cap(caps[round]));
        let (next_state, challenge) = squeeze(state, LABEL_FRI_FOLD);
        state = next_state;
        challenges[round] = challenge;
    }
    challenges
}

/// Picks `array[index]` without branching, by summing each entry against
/// an equality selector. A circuit cannot index by a runtime value, so
/// every entry is touched and all but one is multiplied by zero.
fn select(array: [Field; CAP], index: Field) -> Field {
    let mut chosen = 0;
    for i in 0..CAP {
        let is_match = (index == i as Field) as Field;
        chosen += is_match * array[i];
    }
    chosen
}

fn select_fiber(values: [Field; FIBER], index: Field) -> Field {
    let mut chosen = 0;
    for i in 0..FIBER {
        let is_match = (index == i as Field) as Field;
        chosen += is_match * values[i];
    }
    chosen
}

/// Walks a Merkle path up to the cap layer, returning the node reached and
/// the cap slot it lands on. The low DEPTH bits of the leaf index steer the
/// walk and are consumed by it; the remaining high bits are the position in
/// the cap layer -- in the Rust `merkle::fold_to_cap`, `position` halves
/// once per level and ends up as exactly `index >> DEPTH`.
fn fold_to_cap(
    leaf: Field,
    index_bits: [bool; INDEX_BITS],
    siblings: [Field; DEPTH],
) -> (Field, Field) {
    let mut node = leaf;

    for level in 0..DEPTH {
        let go_right = index_bits[level] as Field;
        let sibling = siblings[level];

        // Even position means this node is the left child. Swap
        // arithmetically rather than branching.
        let left = (1 - go_right) * node + go_right * sibling;
        let right = go_right * node + (1 - go_right) * sibling;
        node = Poseidon2::hash([left, right], 2);
    }

    let mut position = 0;
    let mut weight = 1;
    for level in DEPTH..INDEX_BITS {
        position += index_bits[level] as Field * weight;
        weight *= 2;
    }
    (node, position)
}

/// Lagrange interpolation through the fiber, evaluated at the round
/// challenge. This is the fold.
///
/// Each term needs a division, and those divisions are a real part of the
/// cost -- they are why a FRI verifier does not look like a hash-chain
/// verifier. The loop bounds are compile-time constants, so `u != t`
/// resolves during unrolling and costs nothing at proving time.
fn fold_fiber(xs: [Field; FIBER], ys: [Field; FIBER], challenge: Field) -> Field {
    let mut total = 0;
    for t in 0..FIBER {
        let mut numerator = 1;
        let mut denominator = 1;
        for u in 0..FIBER {
            if u != t {
                numerator *= challenge - xs[u];
                denominator *= xs[t] - xs[u];
            }
        }
        total += ys[t] * (numerator / denominator);
    }
    total
}

fn evaluate(coefficients: [Field; FINAL_COEFFS], point: Field) -> Field {
    let mut result = 0;
    for i in 0..FINAL_COEFFS {
        result = result * point + coefficients[FINAL_COEFFS - 1 - i];
    }
    result
}

fn main(
    // Public: what the verifier is pinned to.
    caps: pub [[Field; CAP]; ROUNDS],
    final_coefficients: pub [Field; FINAL_COEFFS],
    // Public: the evaluation-domain points each fiber sits on. In a
    // deployed verifier these are fixed constants derived from the domain
    // generator; they are inputs here so the circuit needs no hardcoded
    // field constants, and public so a prover cannot choose them.
    domain_points: pub [[[Field; FIBER]; ROUNDS]; KAPPA],
    final_points: pub [Field; KAPPA],
    // Public: which leaf each query opens, and which fiber slot the previous
    // fold lands in. `fri::verify` squeezes these from the transcript, but
    // doing that here would mean also deriving `domain_points` from a
    // generator and modelling the domain shrinking each round, neither of
    // which this circuit does. Left public so a prover still cannot choose
    // them, and flagged as the remaining gap in the Fiat-Shamir replay.
    index_bits: pub [[[bool; INDEX_BITS]; ROUNDS]; KAPPA],
    carried_slots: pub [[Field; ROUNDS]; KAPPA],
    // Public: the key bits the Legendre checks compare against. In the real
    // scheme pk_bits are read out of the public key at challenge-derived
    // indices and t_bits come from the signature.
    pk_bits: pub [bool; B],
    t_bits: pub [bool; B],
    // Private: the opening the prover supplies.
    coset_values: [[[Field; FIBER]; ROUNDS]; KAPPA],
    siblings: [[[Field; DEPTH]; ROUNDS]; KAPPA],
    // Private: the Legendre symbols and their residuosity witnesses.
    o_values: [Field; B],
    o_inverses: [Field; B],
    square_roots: [Field; B],
) {
    // The 128 residuosity checks, one per public-key symbol: the Rust
    // verifier requires o != 0 and L_0(o) == pk_bit XOR t_bit. Computing a
    // Legendre symbol in-circuit would be an exponentiation by (p-1)/2,
    // roughly 380 gates per symbol. The paper's own arithmetization
    // (Algorithm 8) proves residuosity instead with a prover-supplied
    // square root: w with w*w == o when the claimed bit is 0 (residue),
    // or w*w == ALPHA * o when it is 1 (ALPHA is a fixed non-residue, so
    // ALPHA * o is a residue exactly when o is not). One squaring, one
    // inverse check and one XOR are ~3 multiplication constraints; measured
    // with `bb gates`, the 128 checks cost 896 gates, 7 per symbol, against
    // ~380 each for the exponentiation. This witness-square-root trick is
    // also exactly why the Loquat
    // paper excludes K = -I_l at keygen: it keeps o away from 0 for honest
    // signers, so a square root always exists on one side or the other.
    for i in 0..B {
        let o = o_values[i];
        // o != 0, constrained by exhibiting an inverse.
        assert(o * o_inverses[i] == 1);

        // Expected residuosity bit is pk XOR t, arithmetically a + b - 2ab.
        let pk = pk_bits[i] as Field;
        let t = t_bits[i] as Field;
        let bit = pk + t - 2 * pk * t;

        let w = square_roots[i];
        assert(w * w == (1 - bit) * o + bit * (ALPHA * o));
    }

    let challenges = derive_fold_challenges(caps);

    for query in 0..KAPPA {
        let mut carried = 0;
        let mut has_carry = false;

        for round in 0..ROUNDS {
            let values = coset_values[query][round];

            // 1. The opening must be a genuine leaf of this layer's tree.
            let leaf = Poseidon2::hash(values, FIBER);
            let (node, position) =
                fold_to_cap(leaf, index_bits[query][round], siblings[query][round]);
            assert(select(caps[round], position) == node);

            // 2. From round 1 on, one value in this fiber is already
            //    pinned by the previous fold. This check binds the layers
            //    into a chain; without it each layer could be an unrelated
            //    low-degree polynomial.
            if has_carry {
                assert(select_fiber(values, carried_slots[query][round]) == carried);
            }

            // 3. Fold this fiber into the next layer's value.
            carried = fold_fiber(domain_points[query][round], values, challenges[round]);
            has_carry = true;
        }

        // 4. The fully folded value must match the polynomial that was
        //    sent in the clear.
        assert(evaluate(final_coefficients, final_points[query]) == carried);
    }
}

// ---------------------------------------------------------------------
// Tests
//
// A circuit that can never be satisfied still compiles and still reports a
// gate count, so these are what show the constraints above are solvable
// and wired together correctly. They are written against the globals
// rather than hardcoded sizes, so they survive parameter changes.
// ---------------------------------------------------------------------

struct Instance {
    caps: [[Field; CAP]; ROUNDS],
    final_coefficients: [Field; FINAL_COEFFS],
    domain_points: [[[Field; FIBER]; ROUNDS]; KAPPA],
    final_points: [Field; KAPPA],
    index_bits: [[[bool; INDEX_BITS]; ROUNDS]; KAPPA],
    carried_slots: [[Field; ROUNDS]; KAPPA],
    pk_bits: [bool; B],
    t_bits: [bool; B],
    coset_values: [[[Field; FIBER]; ROUNDS]; KAPPA],
    siblings: [[[Field; DEPTH]; ROUNDS]; KAPPA],
    o_values: [Field; B],
    o_inverses: [Field; B],
    square_roots: [Field; B],
}

impl Instance {
    fn run(self) {
        main(
            self.caps,
            self.final_coefficients,
            self.domain_points,
            self.final_points,
            self.index_bits,
            self.carried_slots,
            self.pk_bits,
            self.t_bits,
            self.coset_values,
            self.siblings,
            self.o_values,
            self.o_inverses,
            self.square_roots,
        );
    }
}

/// Builds an opening that is consistent by construction.
///
/// `link_offset` perturbs the value carried between layers: zero gives a
/// valid instance, anything else breaks the layer-binding check.
fn build_instance(link_offset: Field) -> Instance {
    let zero_bits: [bool; INDEX_BITS] = [false; INDEX_BITS];
    let zero_siblings: [Field; DEPTH] = [0; DEPTH];

    // Domain points must be distinct within a round so the interpolation
    // denominators are non-zero.
    let mut points: [[Field; FIBER]; ROUNDS] = [[0; FIBER]; ROUNDS];
    for round in 0..ROUNDS {
        for t in 0..FIBER {
            points[round][t] = (round * FIBER + t + 1) as Field;
        }
    }

    // Walk the rounds forward, feeding each fold into the next fiber. The
    // transcript is replayed in step with the construction: round `r`'s
    // challenge needs caps `0..=r` only, and cap `r` is settled before the
    // challenge is drawn, so there is no circularity.
    let mut caps: [[Field; CAP]; ROUNDS] = [[0; CAP]; ROUNDS];
    let mut round_values: [[Field; FIBER]; ROUNDS] = [[0; FIBER]; ROUNDS];
    let mut state = Poseidon2::hash([TAG_INIT], 1);
    let mut carried = 0;
    let mut has_carry = false;

    for round in 0..ROUNDS {
        let mut values: [Field; FIBER] = [0; FIBER];
        for t in 0..FIBER {
            values[t] = (round * 31 + t * 7 + 3) as Field;
        }
        if has_carry {
            values[0] = carried + link_offset;
        }
        round_values[round] = values;

        let (node, _) = fold_to_cap(Poseidon2::hash(values, FIBER), zero_bits, zero_siblings);
        caps[round][0] = node;

        state = absorb_root(state, root_from_cap(caps[round]));
        let (next_state, challenge) = squeeze(state, LABEL_FRI_FOLD);
        state = next_state;

        carried = fold_fiber(points[round], values, challenge);
        has_carry = true;
    }

    let mut final_coefficients: [Field; FINAL_COEFFS] = [0; FINAL_COEFFS];
    final_coefficients[0] = carried;

    // Every query uses the same opening and a zero index, which keeps the
    // cap positions trivial without weakening what is being checked.
    let mut domain_points: [[[Field; FIBER]; ROUNDS]; KAPPA] = [[[0; FIBER]; ROUNDS]; KAPPA];
    let mut coset_values: [[[Field; FIBER]; ROUNDS]; KAPPA] = [[[0; FIBER]; ROUNDS]; KAPPA];
    let siblings: [[[Field; DEPTH]; ROUNDS]; KAPPA] = [[[0; DEPTH]; ROUNDS]; KAPPA];
    let index_bits: [[[bool; INDEX_BITS]; ROUNDS]; KAPPA] = [[[false; INDEX_BITS]; ROUNDS]; KAPPA];

    for query in 0..KAPPA {
        for round in 0..ROUNDS {
            domain_points[query][round] = points[round];
            coset_values[query][round] = round_values[round];
        }
    }

    // Residuosity witnesses are chosen backwards: pick the square root
    // first, then set `o` so the claimed bit is true by construction.
    // For a residue, o = w^2. For a non-residue, o = w^2 / ALPHA, which is
    // a non-residue because dividing a residue by the non-residue ALPHA
    // flips residuosity, and w^2 == ALPHA * o then holds.
    let mut pk_bits: [bool; B] = [false; B];
    let mut t_bits: [bool; B] = [false; B];
    let mut o_values: [Field; B] = [0; B];
    let mut o_inverses: [Field; B] = [0; B];
    let mut square_roots: [Field; B] = [0; B];

    for i in 0..B {
        pk_bits[i] = i % 2 == 0;
        t_bits[i] = i % 3 == 0;
        let bit = (pk_bits[i] != t_bits[i]) as Field;

        let w = (i + 2) as Field;
        square_roots[i] = w;
        o_values[i] = (1 - bit) * (w * w) + bit * (w * w / ALPHA);
        o_inverses[i] = 1 / o_values[i];
    }

    Instance {
        caps,
        final_coefficients,
        domain_points,
        final_points: [2; KAPPA],
        index_bits,
        carried_slots: [[0; ROUNDS]; KAPPA],
        pk_bits,
        t_bits,
        coset_values,
        siblings,
        o_values,
        o_inverses,
        square_roots,
    }
}

#[test]
fn accepts_a_consistent_opening() {
    build_instance(0).run();
}

/// The layer-binding check must reject a fiber whose carried slot does not
/// match the previous fold.
#[test(should_fail)]
fn rejects_a_broken_layer_link() {
    build_instance(1).run();
}

/// A tampered Merkle commitment must not accept the opening.
#[test(should_fail)]
fn rejects_a_tampered_merkle_commitment() {
    let mut instance = build_instance(0);
    instance.caps[0][0] += 1;
    instance.run();
}

/// The final polynomial must match what the folding actually produced.
#[test(should_fail)]
fn rejects_a_tampered_final_polynomial() {
    let mut instance = build_instance(0);
    instance.final_coefficients[0] += 1;
    instance.run();
}

/// This is the test that shows Fiat-Shamir is really wired in. Slot 1 of
/// round 0's cap is never touched by the Merkle check -- every query here
/// lands on slot 0 -- so before the transcript existed this instance was
/// accepted. Now the whole cap feeds the round-0 root, so nudging it moves
/// every fold challenge and the layer link breaks.
#[test(should_fail)]
fn rejects_a_cap_entry_no_query_opens() {
    let mut instance = build_instance(0);
    instance.caps[0][1] += 1;
    instance.run();
}

/// The cap slot must come from the high index bits: pointing an opening at
/// a cap entry it does not hash to must fail. Before the geometry fix the
/// cap slot was built from the same bits that steer the path walk, so the
/// high bits did not exist and slots past the walked position were
/// unreachable.
#[test(should_fail)]
fn rejects_a_wrong_cap_slot() {
    let mut instance = build_instance(0);
    instance.index_bits[0][0][DEPTH] = true;
    instance.run();
}

/// A residuosity claim that contradicts the witness square root must fail:
/// flipping one public key bit flips the expected bit while `w` still
/// squares to the other side.
#[test(should_fail)]
fn rejects_a_wrong_residuosity_bit() {
    let mut instance = build_instance(0);
    instance.pk_bits[0] = !instance.pk_bits[0];
    instance.run();
}

/// o = 0 must be rejected. The square check alone would accept it with
/// w = 0 on either side, so this is the inverse constraint doing the work.
#[test(should_fail)]
fn rejects_a_zero_legendre_symbol() {
    let mut instance = build_instance(0);
    instance.o_values[0] = 0;
    instance.o_inverses[0] = 0;
    instance.square_roots[0] = 0;
    instance.run();
}
