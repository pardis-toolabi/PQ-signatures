//! CAPSS signature verification, in-circuit.
//!
//! # What this measures, and what it does not
//!
//! This is a **shape measurement** of `capss::piop::verify` (the Rust
//! crate's tested reference): transcript replay, Merkle openings, the
//! constraint combination at the opened points, and the sum-to-zero
//! identity. Its gate count must **not** be compared against the CAPSS
//! paper's ~20-35K R1CS figures, for the same reasons `loquat_verify`'s
//! number is not comparable to 148,825:
//!
//! 1. The paper assumes Griffin or Anemoi over BN254 as the in-circuit
//!    hash and its own parameter sets. This circuit hashes with Poseidon2
//!    over BN254, and its parameters mirror the Rust crate's `level_128`,
//!    which itself mixes paper Table 2 values with chosen ones (see
//!    `capss/src/piop.rs` Parameters for the provenance split). In
//!    particular the paper's BN254 instances use rho = 1 and far fewer
//!    challenge coefficients; the Goldilocks-derived set here needs
//!    rho = 2 and 352 of them, all squeezed in-circuit.
//! 2. The Rust crate runs Anemoi over Goldilocks with invented constants;
//!    this circuit deliberately does not interoperate with it (see
//!    circuits/README.md, "These do not interoperate" -- same reasoning).
//!
//! # What is checked
//!
//! 1. The public key is a Poseidon2 digest over (iv, y), recomputed here
//!    (the shared circuit convention).
//! 2. Fiat-Shamir replay: a running Poseidon2 transcript absorbs the
//!    message, the key, the Merkle cap, and the transmitted high
//!    coefficients of each Q_k; the challenge coefficients (gammas) and
//!    the opened evaluation points are squeezed back out in the same
//!    order as `capss::sig`'s h1..h4 chain. A prover who wants friendlier
//!    challenges has to move the cap or the coefficients, which are
//!    exactly what the rest of the circuit is pinned to.
//! 3. Merkle openings: L_PRIME leaves, each carrying the committed row
//!    and mask evaluations at one point, verified against a 16-wide cap
//!    through a depth-10 Poseidon2 path.
//! 4. The constraint combination at each opened point, using the real
//!    corrected Flystel identity from notes/capss-spec.md (the
//!    `common = a - beta*b^2 - gamma` form).
//! 5. Q_k reconstruction: the low L_PRIME coefficients are interpolated
//!    through the L_PRIME opened evaluations (minus the transmitted high
//!    part), then `sum over omega in {0..S-1} of Q_k(omega) == 0` is
//!    checked for each k. This is THE load-bearing check -- see
//!    `capss/src/piop.rs`: reconstruction spends exactly l' of the l'+1
//!    available equations, and the sum is the one kept as a test.
//!    Reconstructing l'+1 coefficients instead would leave a square
//!    system that always solves, and nothing would ever fail.
//!
//! # What is omitted, relative to `capss::piop::verify`
//!
//! - The DECS batched polynomials R_k: their gammas, transmitted high
//!   coefficients, and reconstruction. In the Rust composition that
//!   reconstruction is self-consistent by construction and contributes
//!   no independent check (documented at capss/src/piop.rs), so leaving
//!   it out removes bytes, not soundness.
//! - The salt, and the leaf-index binding inside the leaf hash. Here the
//!   index binds through the path position instead, as in loquat_verify.
//! - Distinct-index redraws: the Rust transcript redraws on collision;
//!   a circuit cannot loop on data, so a colliding draw simply makes the
//!   interpolation denominators zero and the circuit unsatisfiable.
//!
//! # Modelling choices
//!
//! - Merkle: N = 2^14 leaves as in `level_128`, opened through depth-10
//!   paths below a 16-wide cap rather than full depth-14 paths. Trimmed
//!   paths are one of the paper's own four SNARK-friendliness tweaks
//!   (section 4.4), and the same cap shape as loquat_verify keeps the
//!   two circuit rows comparable.
//! - The transcript is a rate-3 duplex sponge over the Poseidon2
//!   permutation, not loquat_verify's one-hash-per-challenge chaining:
//!   this verifier squeezes 372 field elements, and per-challenge
//!   chaining would double the transcript's cost for no extra binding.
//!   The chained absorb/squeeze structure is the same.
//! - The Flystel constants (beta, gamma, delta), the round-constant
//!   values, and the affine layer's linear map are invented placeholders,
//!   like the Rust crate's own invented Anemoi constants. The identity
//!   SHAPE is the real corrected one, and the linear map is cost-neutral:
//!   any fixed linear map is additions and constant scalings, which are
//!   nearly free in-circuit.

use poseidon::poseidon2::Poseidon2;

// ---------------------------------------------------------------------
// Parameters, mirroring capss::piop::Parameters::level_128 plus
// pacs::dimensions(). From the paper's Table 2 ("Short" trade-off):
// S = 11 rounds/columns, N_ROWS = 16, M1 = 8, M2 = 88, D = alpha = 7,
// N = 2^14 leaves. Chosen by the Rust crate, not the paper: L_PRIME = 20
// opened leaves and RHO = 2 combinations (the fewest reaching 128 bits
// over a 64-bit field). See capss/src/piop.rs for the full split.
// ---------------------------------------------------------------------

/// l': opened leaves, and the number of low Q_k coefficients rebuilt.
global L_PRIME: u32 = 20;
/// rho: independent combinations Q_k, each one sum-to-zero check.
global RHO: u32 = 2;
/// s: columns of the witness matrix; Omega = {0..S-1}.
global S: u32 = 11;
/// n: rows of the witness matrix (input state 0..7, output state 8..15).
global N_ROWS: u32 = 16;
/// m1: parallel constraints (2 per Flystel pair).
global M1: u32 = 8;
/// m2: aggregated constraints = (S-1)*STATE wiring + iv + y bindings.
global M2: u32 = 88;
/// d: constraint degree, alpha of the Flystel.
global D: u32 = 7;

global STATE: u32 = 8;
global PAIRS: u32 = 4;
global IV_SIZE: u32 = 4;
global OUT_SIZE: u32 = 4;

/// deg of a row polynomial: l' + s - 1.
global INPUT_DEG: u32 = L_PRIME + S - 1;
/// deg_q = d * (l' + s - 1) + s = 221.
global DEG_Q: u32 = D * INPUT_DEG + S;
global Q_LEN: u32 = DEG_Q + 1;
/// Transmitted coefficients of each Q_k: everything of degree >= l'.
global Q_HIGH_LEN: u32 = Q_LEN - L_PRIME;
/// Challenge coefficients: per combination, S per parallel constraint
/// (a degree-(S-1) polynomial over Omega) plus one scalar per aggregated.
global PER_K: u32 = M1 * S + M2;
global N_GAMMAS: u32 = RHO * PER_K;

/// N = 2^14 leaves; paths stop at a 16-wide cap, so 10 sibling levels.
global TREE_BITS: u32 = 14;
global DEPTH: u32 = 10;
global CAP: u32 = 16;
global N_LEAVES: u32 = 16384;
/// One opened leaf: N_ROWS row values plus RHO mask values.
global LEAF_WIDTH: u32 = N_ROWS + RHO;

// Invented Flystel constants, standing in for Anemoi's beta, gamma,
// delta. The values do not change the gate count; the identity shape
// does, and that is the real one.
global BETA: Field = 3;
global GAMMA_C: Field = 5;
global DELTA: Field = 7;

/// Transcript domain constant, in the capacity slot.
global TAG_INIT: Field = 0x63617073732d766572696679;

/// 7^{-1} mod (p - 1) for the BN254 scalar field, computed offline.
/// gcd(7, p - 1) = 1, so x -> x^7 is a bijection and x^d inverts it.
/// Used only by the test builder to run the Flystel forward.
global SEVENTH_ROOT_EXPONENT: Field =
    0x1ba70841a540edceb2770343b7b7a0353b8b60296a20d29c26ca432ff6db6db7;

// ---------------------------------------------------------------------
// Transcript: a rate-3 duplex sponge over the Poseidon2 permutation.
// ---------------------------------------------------------------------

fn permute(state: [Field; 4]) -> [Field; 4] {
    std::hash::poseidon2_permutation(state)
}

/// Adds the inputs into the rate slots three at a time, permuting after
/// each full or final chunk.
fn absorb<let N: u32>(state: [Field; 4], inputs: [Field; N]) -> [Field; 4] {
    let mut st = state;
    let mut slot = 0;
    for i in 0..N {
        st[slot] += inputs[i];
        slot += 1;
        if slot == 3 {
            st = permute(st);
            slot = 0;
        }
    }
    if slot != 0 {
        st = permute(st);
    }
    st
}

/// Reads challenges out of the rate slots, permuting between blocks and
/// once at the end so a later absorb continues from a fresh state.
fn squeeze<let N: u32>(state: [Field; 4]) -> ([Field; 4], [Field; N]) {
    let mut st = state;
    let mut out: [Field; N] = [0; N];
    let mut slot = 0;
    for i in 0..N {
        if slot == 3 {
            st = permute(st);
            slot = 0;
        }
        out[i] = st[slot];
        slot += 1;
    }
    st = permute(st);
    (st, out)
}

/// The low TREE_BITS bits of a squeezed challenge are the opened leaf
/// index: bits 0..DEPTH walk the path, bits DEPTH..TREE_BITS pick the
/// cap entry, and the DECS evaluation point is index + 2 (the Rust
/// crate's `evaluation_point`, keeping 0 and 1 out of the domain).
fn opening_position(challenge: Field) -> ([bool; TREE_BITS], Field) {
    let bits254: [bool; 254] = challenge.to_le_bits();
    let mut bits: [bool; TREE_BITS] = [false; TREE_BITS];
    let mut index: Field = 0;
    let mut weight: Field = 1;
    for i in 0..TREE_BITS {
        bits[i] = bits254[i];
        index += (bits[i] as Field) * weight;
        weight *= 2;
    }
    (bits, index)
}

// ---------------------------------------------------------------------
// Merkle openings.
// ---------------------------------------------------------------------

/// Walks a Merkle path up to the cap layer. Bit 0 is the leaf's parity;
/// even means left child. Swaps are arithmetic, not branching.
fn fold_to_cap(leaf: Field, bits: [bool; TREE_BITS], siblings: [Field; DEPTH]) -> Field {
    let mut node = leaf;
    for level in 0..DEPTH {
        let go_right = bits[level] as Field;
        let sibling = siblings[level];
        let left = (1 - go_right) * node + go_right * sibling;
        let right = go_right * node + (1 - go_right) * sibling;
        node = Poseidon2::hash([left, right], 2);
    }
    node
}

/// Picks `cap[position]` without branching: every entry is touched and
/// all but one multiplied by zero, since a circuit cannot index by a
/// runtime value.
fn select_cap(cap: [Field; CAP], position: Field) -> Field {
    let mut chosen = 0;
    for i in 0..CAP {
        let is_match = (position == i as Field) as Field;
        chosen += is_match * cap[i];
    }
    chosen
}

// ---------------------------------------------------------------------
// Polynomial toolkit. Coefficients are lowest-degree first, matching
// capss/src/decs.rs.
// ---------------------------------------------------------------------

/// Horner evaluation.
fn evaluate<let N: u32>(coefficients: [Field; N], x: Field) -> Field {
    let mut result = 0;
    for i in 0..N {
        result = result * x + coefficients[N - 1 - i];
    }
    result
}

/// Lagrange interpolation through distinct points, via the master
/// polynomial and synthetic division -- a port of decs::interpolate.
/// Each basis polynomial costs one runtime division, and those divisions
/// are part of the honest price of reconstruction (loquat_verify's
/// fold_fiber has the same shape). Repeated points make a denominator
/// zero and the circuit unsatisfiable, which stands in for the Rust
/// transcript's redraw-on-collision.
fn interpolate<let N: u32>(points: [Field; N], values: [Field; N]) -> [Field; N] {
    let mut master: [Field; N + 1] = [0; N + 1];
    master[0] = 1;
    for d in 0..N {
        let point = points[d];
        for t in 0..d + 1 {
            let index = d + 1 - t;
            master[index] = master[index - 1] - point * master[index];
        }
        master[0] = 0 - point * master[0];
    }

    let mut result: [Field; N] = [0; N];
    for j in 0..N {
        let point = points[j];
        let mut basis: [Field; N] = [0; N];
        basis[N - 1] = master[N];
        for t in 0..N - 1 {
            let index = N - 2 - t;
            basis[index] = master[index + 1] + point * basis[index + 1];
        }
        let scale = values[j] / evaluate(basis, point);
        for c in 0..N {
            result[c] += scale * basis[c];
        }
    }
    result
}

fn pow7(x: Field) -> Field {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x2 * x
}

/// x^L_PRIME, the shift that separates the reconstructed low part of
/// Q_k from the transmitted high part.
fn pow_l_prime(x: Field) -> Field {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x5 = x4 * x;
    let x10 = x5 * x5;
    x10 * x10
}

/// The Lagrange basis over Omega = {0..S-1} at a runtime point. The
/// denominators are compile-time constants, so each basis value costs
/// only the two prefix/suffix products.
fn omega_basis(point: Field) -> [Field; S] {
    let mut prefix: [Field; S] = [1; S];
    for i in 1..S {
        prefix[i] = prefix[i - 1] * (point - (i - 1) as Field);
    }
    let mut suffix: [Field; S] = [1; S];
    for t in 0..S - 1 {
        let i = S - 2 - t;
        suffix[i] = suffix[i + 1] * (point - (i + 1) as Field);
    }
    let mut basis: [Field; S] = [0; S];
    for i in 0..S {
        basis[i] = prefix[i] * suffix[i] / omega_denominator(i);
    }
    basis
}

/// prod over u != i of (i - u). All-constant, folds at compile time.
fn omega_denominator(i: u32) -> Field {
    let mut denominator: Field = 1;
    for u in 0..S {
        if u != i {
            denominator *= (i as Field) - (u as Field);
        }
    }
    denominator
}

/// Power sums over Omega: PS[i] = sum over omega in {0..S-1} of omega^i,
/// with 0^0 = 1 so PS[0] = S. All-constant, folds at compile time. The
/// sum-to-zero check `sum_omega Q_k(omega) == 0` becomes the linear
/// combination `sum_i coeff_i * PS[i] == 0`, which is the same equation
/// with the constant evaluations at Omega folded away.
fn power_sums() -> [Field; Q_LEN] {
    let mut sums: [Field; Q_LEN] = [0; Q_LEN];
    let mut powers: [Field; S] = [1; S];
    for i in 0..Q_LEN {
        let mut total: Field = 0;
        for w in 0..S {
            total += powers[w];
            powers[w] *= w as Field;
        }
        sums[i] = total;
    }
    sums
}

// ---------------------------------------------------------------------
// The constraint combination -- the in-circuit half of piop's
// Combination::value_at.
// ---------------------------------------------------------------------

/// Invented round-constant values on Omega. rc polynomial j is the
/// degree-(S-1) interpolant through rc_value(j, 0..S), mirroring the
/// Rust round_constant_polynomials; the circuit evaluates it through the
/// shared omega basis, so arbitrary values cost the same as Anemoi's.
fn rc_value(slot: u32, column: u32) -> Field {
    ((slot * 61 + column * 23 + 17) * 40787 + 97) as Field
}

/// Placeholder for the affine layer's linear map (unit lower triangular:
/// out[i] = state[i] + sum of state[j] for j < i). Cost-neutral: any
/// fixed linear map is additions and constant scalings, nearly free
/// in-circuit, and this one is trivially invertible for the test
/// builder. The Rust reference splits its affine layer the same way:
/// linear part on the state, round constants carried separately.
fn linear_layer(state: [Field; STATE]) -> [Field; STATE] {
    let mut out: [Field; STATE] = [0; STATE];
    let mut running: Field = 0;
    for i in 0..STATE {
        out[i] = state[i] + running;
        running += state[i];
    }
    out
}

/// The aggregated family folded into per-row coefficient values over
/// Omega, plus a constant row carrying the public-key terms -- the
/// scatter half of piop's aggregated_coefficients. One challenge per
/// aggregated constraint: wiring ties column col's output rows to
/// column col+1's input rows, then iv and y pin the two ends.
struct Aggregated {
    rows: [[Field; S]; N_ROWS],
    constant: [Field; S],
}

fn aggregated_scatter(
    gammas: [Field; N_GAMMAS],
    k: u32,
    iv: [Field; IV_SIZE],
    y: [Field; OUT_SIZE],
) -> Aggregated {
    let mut rows: [[Field; S]; N_ROWS] = [[0; S]; N_ROWS];
    let mut constant: [Field; S] = [0; S];
    let mut t = k * PER_K + M1 * S;

    for col in 0..S - 1 {
        for i in 0..STATE {
            let weight = gammas[t];
            t += 1;
            rows[STATE + i][col] += weight;
            rows[i][col + 1] -= weight;
        }
    }
    for i in 0..IV_SIZE {
        let weight = gammas[t];
        t += 1;
        rows[i][0] += weight;
        constant[0] -= weight * iv[i];
    }
    for i in 0..OUT_SIZE {
        let weight = gammas[t];
        t += 1;
        rows[STATE + i][S - 1] += weight;
        constant[S - 1] -= weight * y[i];
    }
    Aggregated { rows, constant }
}

/// Q_k(point) for every k, given the row and mask values at that point.
/// Both the circuit and the test builder call this -- the circuit with
/// opened leaf values, the builder with its own polynomial evaluations --
/// which is what guarantees the two sides agree, exactly as the Rust
/// prover and verifier share Combination::value_at.
fn combination_values(
    point: Field,
    rows: [Field; N_ROWS],
    masks: [Field; RHO],
    gammas: [Field; N_GAMMAS],
    aggregated: [Aggregated; RHO],
) -> [Field; RHO] {
    let basis = omega_basis(point);

    let mut input_state: [Field; STATE] = [0; STATE];
    for i in 0..STATE {
        input_state[i] = rows[i];
    }
    let linear = linear_layer(input_state);

    // The corrected Flystel round identity from notes/capss-spec.md:
    // common = a - beta*b^2 - gamma, with (a, b) post-affine. Two
    // constraint values per pair, m1 = 8 in all.
    let mut parallel_values: [Field; M1] = [0; M1];
    for pair in 0..PAIRS {
        let mut rc_a: Field = 0;
        let mut rc_b: Field = 0;
        for c in 0..S {
            rc_a += basis[c] * rc_value(pair, c);
            rc_b += basis[c] * rc_value(PAIRS + pair, c);
        }
        let a = linear[pair] + rc_a;
        let b = linear[PAIRS + pair] + rc_b;
        let u = rows[STATE + pair];
        let v = rows[STATE + PAIRS + pair];
        let common = a - BETA * b * b - GAMMA_C;
        parallel_values[2 * pair] = pow7(b - v) - common;
        parallel_values[2 * pair + 1] = u - BETA * v * v - DELTA - common;
    }

    let mut values: [Field; RHO] = [0; RHO];
    for k in 0..RHO {
        // Parallel constraints, each weighted by a degree-(S-1)
        // challenge polynomial evaluated through the shared basis. A
        // scalar weight would only force the sum over columns to vanish;
        // the polynomial weight forces every column individually.
        let mut total = masks[k];
        for j in 0..M1 {
            let mut weight: Field = 0;
            for c in 0..S {
                weight += basis[c] * gammas[k * PER_K + j * S + c];
            }
            total += weight * parallel_values[j];
        }
        // Aggregated constraints, scalar-weighted and pre-folded into
        // one coefficient value per row.
        for i in 0..N_ROWS {
            let mut coefficient: Field = 0;
            for c in 0..S {
                coefficient += basis[c] * aggregated[k].rows[i][c];
            }
            total += coefficient * rows[i];
        }
        let mut constant: Field = 0;
        for c in 0..S {
            constant += basis[c] * aggregated[k].constant[c];
        }
        values[k] = total + constant;
    }
    values
}

// ---------------------------------------------------------------------
// The verifier.
// ---------------------------------------------------------------------

fn main(
    // Public: the statement. The key is one field element, a Poseidon2
    // digest the circuit recomputes, and the message arrives pre-hashed
    // -- the conventions every circuit in this repo shares.
    public_key: pub Field,
    message_digest: pub Field,
    // Private: the signature and the key material under the digest.
    iv: [Field; IV_SIZE],
    y: [Field; OUT_SIZE],
    cap: [Field; CAP],
    q_high: [[Field; Q_HIGH_LEN]; RHO],
    leaf_rows: [[Field; N_ROWS]; L_PRIME],
    leaf_masks: [[Field; RHO]; L_PRIME],
    siblings: [[Field; DEPTH]; L_PRIME],
) {
    let mut key_material: [Field; IV_SIZE + OUT_SIZE] = [0; IV_SIZE + OUT_SIZE];
    for i in 0..IV_SIZE {
        key_material[i] = iv[i];
    }
    for i in 0..OUT_SIZE {
        key_material[IV_SIZE + i] = y[i];
    }
    assert(Poseidon2::hash(key_material, IV_SIZE + OUT_SIZE) == public_key);

    // h1: message and key, before anything the prover chooses.
    // h2: the commitment, which fixes the challenge coefficients.
    let mut state = absorb([0, 0, 0, TAG_INIT], [message_digest, public_key]);
    state = absorb(state, cap);
    let (after_gammas, gammas) = squeeze::<N_GAMMAS>(state);
    state = after_gammas;

    // h3: the PIOP message. h4: the opening indices -- squeezed only
    // after every prover message is bound, so steering the openings
    // means regrinding the whole transcript.
    for k in 0..RHO {
        state = absorb(state, q_high[k]);
    }
    let (_, opening_challenges) = squeeze::<L_PRIME>(state);

    let aggregated = [
        aggregated_scatter(gammas, 0, iv, y),
        aggregated_scatter(gammas, 1, iv, y),
    ];

    // Merkle openings and the constraint combination at each point.
    let mut points: [Field; L_PRIME] = [0; L_PRIME];
    let mut q_values: [[Field; L_PRIME]; RHO] = [[0; L_PRIME]; RHO];
    for j in 0..L_PRIME {
        let (bits, index) = opening_position(opening_challenges[j]);
        points[j] = index + 2;

        let mut leaf_input: [Field; LEAF_WIDTH] = [0; LEAF_WIDTH];
        for r in 0..N_ROWS {
            leaf_input[r] = leaf_rows[j][r];
        }
        for k in 0..RHO {
            leaf_input[N_ROWS + k] = leaf_masks[j][k];
        }
        let leaf = Poseidon2::hash(leaf_input, LEAF_WIDTH);
        let node = fold_to_cap(leaf, bits, siblings[j]);

        let mut cap_position: Field = 0;
        let mut weight: Field = 1;
        for i in 0..TREE_BITS - DEPTH {
            cap_position += (bits[DEPTH + i] as Field) * weight;
            weight *= 2;
        }
        assert(select_cap(cap, cap_position) == node);

        let values = combination_values(points[j], leaf_rows[j], leaf_masks[j], gammas, aggregated);
        for k in 0..RHO {
            q_values[k][j] = values[k];
        }
    }

    // Reconstruct each Q_k's low L_PRIME coefficients from the L_PRIME
    // opened evaluations, then spend the one remaining equation on the
    // sum-to-zero check. PS folds the constant evaluations at Omega, so
    // `sum == 0` is literally `sum over omega of Q_k(omega) == 0`.
    let ps = power_sums();
    for k in 0..RHO {
        let mut residuals: [Field; L_PRIME] = [0; L_PRIME];
        for j in 0..L_PRIME {
            residuals[j] =
                q_values[k][j] - pow_l_prime(points[j]) * evaluate(q_high[k], points[j]);
        }
        let low = interpolate(points, residuals);

        let mut sum: Field = 0;
        for i in 0..L_PRIME {
            sum += low[i] * ps[i];
        }
        for i in 0..Q_HIGH_LEN {
            sum += q_high[k][i] * ps[L_PRIME + i];
        }
        assert(sum == 0);
    }
}

// ---------------------------------------------------------------------
// Tests
//
// A circuit that can never be satisfied still compiles and still reports
// a gate count, so these are what show the constraints are solvable and
// wired together. build_instance is an unconstrained honest prover: it
// runs the Flystel forward over Omega (seventh roots are cheap natively),
// commits real degree-30 row polynomials and degree-221 masks over all
// 2^14 leaves, replays the same transcript functions the circuit uses,
// and opens whatever indices that transcript derives.
// ---------------------------------------------------------------------

global HEAP: u32 = 2 * N_LEAVES;

struct Instance {
    public_key: Field,
    message_digest: Field,
    iv: [Field; IV_SIZE],
    y: [Field; OUT_SIZE],
    cap: [Field; CAP],
    q_high: [[Field; Q_HIGH_LEN]; RHO],
    leaf_rows: [[Field; N_ROWS]; L_PRIME],
    leaf_masks: [[Field; RHO]; L_PRIME],
    siblings: [[Field; DEPTH]; L_PRIME],
}

impl Instance {
    fn run(self) {
        main(
            self.public_key,
            self.message_digest,
            self.iv,
            self.y,
            self.cap,
            self.q_high,
            self.leaf_rows,
            self.leaf_masks,
            self.siblings,
        );
    }
}

/// x^(1/7) by exponentiation with the hardcoded inverse exponent.
unconstrained fn seventh_root(x: Field) -> Field {
    let exponent_bits: [bool; 254] = SEVENTH_ROOT_EXPONENT.to_le_bits();
    let mut result: Field = 1;
    let mut base = x;
    for i in 0..254 {
        if exponent_bits[i] {
            result *= base;
        }
        base *= base;
    }
    result
}

/// Builds a consistent instance by running the prover honestly.
///
/// `row_tamper` is added to row 0's evaluation in every committed leaf
/// -- but not to the polynomial Q_k is built from. Zero gives a valid
/// instance. Anything else is a commitment that disagrees with the
/// transmitted Q_k: every hash, path and transcript step stays
/// internally consistent, and only the sum-to-zero identity can catch
/// it. That mirrors what a real forgery looks like: a cheating prover's
/// true Q_k has a non-zero sum, so the q_high they send must belong to
/// some other polynomial, and the disagreement surfaces at the opened
/// points.
unconstrained fn build_instance(row_tamper: Field) -> Instance {
    // 1. A witness matrix satisfying every constraint on Omega: run the
    //    Flystel forward column by column. val1 = (b-v)^7 - common
    //    vanishes because v = b - common^(1/7), val2 by construction of
    //    u, wiring because each output feeds the next input, and iv / y
    //    are read off the two ends -- this is keygen, in miniature.
    let mut witness: [[Field; S]; N_ROWS] = [[0; S]; N_ROWS];
    let mut input_state: [Field; STATE] = [0; STATE];
    for i in 0..STATE {
        input_state[i] = (i * 1009 + 37) as Field;
    }
    let mut iv: [Field; IV_SIZE] = [0; IV_SIZE];
    for i in 0..IV_SIZE {
        iv[i] = input_state[i];
    }

    for col in 0..S {
        for i in 0..STATE {
            witness[i][col] = input_state[i];
        }
        let linear = linear_layer(input_state);
        let mut output_state: [Field; STATE] = [0; STATE];
        for pair in 0..PAIRS {
            let a = linear[pair] + rc_value(pair, col);
            let b = linear[PAIRS + pair] + rc_value(PAIRS + pair, col);
            let common = a - BETA * b * b - GAMMA_C;
            let v = b - seventh_root(common);
            let u = common + BETA * v * v + DELTA;
            output_state[pair] = u;
            output_state[PAIRS + pair] = v;
        }
        for i in 0..STATE {
            witness[STATE + i][col] = output_state[i];
        }
        input_state = output_state;
    }
    let mut y: [Field; OUT_SIZE] = [0; OUT_SIZE];
    for i in 0..OUT_SIZE {
        y[i] = witness[STATE + i][S - 1];
    }

    let mut key_material: [Field; IV_SIZE + OUT_SIZE] = [0; IV_SIZE + OUT_SIZE];
    for i in 0..IV_SIZE {
        key_material[i] = iv[i];
    }
    for i in 0..OUT_SIZE {
        key_material[IV_SIZE + i] = y[i];
    }
    let public_key = Poseidon2::hash(key_material, IV_SIZE + OUT_SIZE);
    let message_digest = 0x6d657373616765;

    // 2. Row polynomials: witness values on Omega, arbitrary pads on
    //    {S..S+L_PRIME-1}, interpolated to degree INPUT_DEG.
    let mut interpolation_points: [Field; INPUT_DEG + 1] = [0; INPUT_DEG + 1];
    for i in 0..INPUT_DEG + 1 {
        interpolation_points[i] = i as Field;
    }
    let mut row_polys: [[Field; INPUT_DEG + 1]; N_ROWS] = [[0; INPUT_DEG + 1]; N_ROWS];
    for r in 0..N_ROWS {
        let mut values: [Field; INPUT_DEG + 1] = [0; INPUT_DEG + 1];
        for c in 0..S {
            values[c] = witness[r][c];
        }
        for c in S..INPUT_DEG + 1 {
            values[c] = ((r * 97 + c * 29 + 11) * 65537 + 5) as Field;
        }
        row_polys[r] = interpolate(interpolation_points, values);
    }

    // 3. Masks of full degree DEG_Q, uniform-looking subject to summing
    //    to zero over Omega: pick every coefficient above the constant,
    //    then let the constant absorb the sum -- piop's mask_polynomials.
    let ps = power_sums();
    let mut masks: [[Field; Q_LEN]; RHO] = [[0; Q_LEN]; RHO];
    for k in 0..RHO {
        let mut total: Field = 0;
        for c in 1..Q_LEN {
            masks[k][c] = ((k * 7919 + c * 13 + 3) * 131071 + 19) as Field;
            total += masks[k][c] * ps[c];
        }
        masks[k][0] = 0 - total / (S as Field);
    }

    // 4. Commit: every leaf hashes the row and mask evaluations at its
    //    point, then the tree folds up to the 16-wide cap. The heap
    //    layout puts leaf i at N_LEAVES + i, so the cap is nodes 16..32.
    let mut nodes: [Field; HEAP] = [0; HEAP];
    for idx in 0..N_LEAVES {
        let point = (idx + 2) as Field;
        let mut leaf_input: [Field; LEAF_WIDTH] = [0; LEAF_WIDTH];
        for r in 0..N_ROWS {
            leaf_input[r] = evaluate(row_polys[r], point);
        }
        leaf_input[0] += row_tamper;
        for k in 0..RHO {
            leaf_input[N_ROWS + k] = evaluate(masks[k], point);
        }
        nodes[N_LEAVES + idx] = Poseidon2::hash(leaf_input, LEAF_WIDTH);
    }
    for t in 0..N_LEAVES - CAP {
        let i = N_LEAVES - 1 - t;
        nodes[i] = Poseidon2::hash([nodes[2 * i], nodes[2 * i + 1]], 2);
    }
    let mut cap: [Field; CAP] = [0; CAP];
    for i in 0..CAP {
        cap[i] = nodes[CAP + i];
    }

    // 5. Replay the transcript with the same functions the circuit uses.
    let mut state = absorb([0, 0, 0, TAG_INIT], [message_digest, public_key]);
    state = absorb(state, cap);
    let (after_gammas, gammas) = squeeze::<N_GAMMAS>(state);
    state = after_gammas;

    // 6. Build each Q_k the way the Rust prover does: evaluate the whole
    //    combination at DEG_Q + 1 points and interpolate. The sum over
    //    Omega is zero by construction -- parallel constraints vanish at
    //    every omega, aggregated ones sum to zero, masks sum to zero --
    //    independent of what the gammas turn out to be.
    let aggregated = [
        aggregated_scatter(gammas, 0, iv, y),
        aggregated_scatter(gammas, 1, iv, y),
    ];
    let mut q_points: [Field; Q_LEN] = [0; Q_LEN];
    let mut q_evals: [[Field; Q_LEN]; RHO] = [[0; Q_LEN]; RHO];
    for t in 0..Q_LEN {
        let x = t as Field;
        q_points[t] = x;
        let mut rows_at: [Field; N_ROWS] = [0; N_ROWS];
        for r in 0..N_ROWS {
            rows_at[r] = evaluate(row_polys[r], x);
        }
        let mut masks_at: [Field; RHO] = [0; RHO];
        for k in 0..RHO {
            masks_at[k] = evaluate(masks[k], x);
        }
        let values = combination_values(x, rows_at, masks_at, gammas, aggregated);
        for k in 0..RHO {
            q_evals[k][t] = values[k];
        }
    }
    let mut q_high: [[Field; Q_HIGH_LEN]; RHO] = [[0; Q_HIGH_LEN]; RHO];
    for k in 0..RHO {
        let q_poly = interpolate(q_points, q_evals[k]);
        for i in 0..Q_HIGH_LEN {
            q_high[k][i] = q_poly[L_PRIME + i];
        }
    }

    // 7. Squeeze the opening indices and read the openings out of the
    //    committed tree.
    for k in 0..RHO {
        state = absorb(state, q_high[k]);
    }
    let (_, opening_challenges) = squeeze::<L_PRIME>(state);

    let mut leaf_rows: [[Field; N_ROWS]; L_PRIME] = [[0; N_ROWS]; L_PRIME];
    let mut leaf_masks: [[Field; RHO]; L_PRIME] = [[0; RHO]; L_PRIME];
    let mut siblings: [[Field; DEPTH]; L_PRIME] = [[0; DEPTH]; L_PRIME];
    for j in 0..L_PRIME {
        let (_, index) = opening_position(opening_challenges[j]);
        let point = index + 2;
        for r in 0..N_ROWS {
            leaf_rows[j][r] = evaluate(row_polys[r], point);
        }
        leaf_rows[j][0] += row_tamper;
        for k in 0..RHO {
            leaf_masks[j][k] = evaluate(masks[k], point);
        }
        let mut node_index = N_LEAVES + (index as u32);
        for level in 0..DEPTH {
            let sibling = if node_index % 2 == 0 { node_index + 1 } else { node_index - 1 };
            siblings[j][level] = nodes[sibling];
            node_index = node_index / 2;
        }
    }

    Instance {
        public_key,
        message_digest,
        iv,
        y,
        cap,
        q_high,
        leaf_rows,
        leaf_masks,
        siblings,
    }
}

#[test]
fn accepts_a_consistent_instance() {
    // Safety: unconstrained is only used to construct the witness; every
    // value it produces is then checked by the constrained circuit.
    let instance = unsafe { build_instance(0) };
    instance.run();
}

/// A commitment that disagrees with the transmitted Q_k. The Merkle
/// paths verify and the transcript replays exactly -- the committed
/// values really are committed -- so nothing but the sum-to-zero
/// identity can reject this. It is the test that shows which check does
/// the work, mirroring piop's the_sum_to_zero_check_is_what_rejects.
#[test(should_fail)]
fn rejects_an_inconsistent_committed_row() {
    // Safety: see accepts_a_consistent_instance.
    let instance = unsafe { build_instance(1) };
    instance.run();
}

/// A tampered Merkle commitment. Whichever cap entry the openings land
/// on, moving any entry either breaks a path directly or, through the
/// transcript, moves every challenge and opening index.
#[test(should_fail)]
fn rejects_a_tampered_merkle_commitment() {
    // Safety: see accepts_a_consistent_instance.
    let mut instance = unsafe { build_instance(0) };
    instance.cap[0] += 1;
    instance.run();
}

/// A tampered transmitted high coefficient. q_high is absorbed before
/// the opening indices are squeezed, so the Fiat-Shamir replay moves
/// the openings and the supplied paths no longer verify -- the binding
/// that makes grinding the reconstruction expensive.
#[test(should_fail)]
fn rejects_a_tampered_high_coefficient() {
    // Safety: see accepts_a_consistent_instance.
    let mut instance = unsafe { build_instance(0) };
    instance.q_high[0][0] += 1;
    instance.run();
}

/// A tampered mask opening: the masks are committed inside the leaves,
/// so the leaf hash no longer matches its path.
#[test(should_fail)]
fn rejects_a_tampered_mask_opening() {
    // Safety: see accepts_a_consistent_instance.
    let mut instance = unsafe { build_instance(0) };
    instance.leaf_masks[0][0] += 1;
    instance.run();
}

/// A different message: h1 seeds the whole transcript, so every
/// challenge and opening index moves.
#[test(should_fail)]
fn rejects_a_tampered_message() {
    // Safety: see accepts_a_consistent_instance.
    let mut instance = unsafe { build_instance(0) };
    instance.message_digest += 1;
    instance.run();
}
