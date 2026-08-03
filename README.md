# PQ-signatures

Three post-quantum signature schemes, implemented in Rust as small
educational libraries: **Lamport**, **WOTS**, and **XMSS**. All three build
on nothing but a hash function (SHA-256 here), which is why they're
considered safe against quantum computers — there's no known quantum
shortcut for breaking a hash function the way Shor's algorithm breaks the
elliptic-curve math behind ECDSA or the number theory behind RSA.

Each one is a bigger idea than the last:

- **Lamport** — the simplest possible hash-based signature. Sign a message
  once by revealing half of a big pile of secrets.
- **WOTS** — a smaller, more efficient version of the same idea, using hash
  chains instead of one secret per bit.
- **XMSS** — takes WOTS and adds a Merkle tree on top, turning a one-time
  signature into a many-time one, with a tiny fixed-size public key.

Read `lamport/README.md`, `wots/README.md`, and `xmss/README.md` for a
step-by-step walkthrough of the math behind each one.

## Trying it out

```
cargo test --workspace       # correctness tests for all three schemes
cargo run --release -p compare   # timing and size comparison
```

## Comparison

Measured on this machine with `cargo run --release -p compare` (message
signed each time: a ~48-byte string; timings are averaged over multiple runs
to smooth out noise):

| Scheme      | Keygen      | Sign     | Verify   | Signature | Public key | Signs how many messages? |
|-------------|-------------|----------|----------|-----------|------------|---------------------------|
| Lamport     | 24 µs       | 0.6 µs   | 49 µs    | 8.0 KB    | 16.0 KB    | 1 (must discard key after) |
| WOTS        | 2.7 µs      | 77 µs    | 84 µs    | 2.1 KB    | 2.1 KB     | 1 (must discard key after) |
| XMSS (h=4)  | 2.3 ms      | 67 µs    | 77 µs    | 2.2 KB    | 32 B       | up to 16 |
| XMSS (h=10) | 119 ms      | 54 µs    | 61 µs    | 2.4 KB    | 32 B       | up to 1024 |

*(h is the XMSS tree height; it can sign `2^h` messages before a new key
pair is needed. Bigger h means slower keygen but doesn't change sign/verify
speed much.)*

### What actually matters here

- **Signature and public key size**: WOTS is about 4x smaller than Lamport
  for both, because it packs a hash chain's worth of information into each
  32-byte value instead of spending one whole value per bit. XMSS keeps
  WOTS's small signature size and shrinks the public key down to a single
  32-byte hash, no matter how many messages the key pair can sign.

- **Speed**: Lamport signing is the fastest operation of all — it's just
  picking 256 already-computed values, no hashing needed. Its *verify* is
  slower because it has to hash all 256 of them. WOTS and XMSS spend their
  time walking hash chains, which is why sign and verify cost about the same
  for both.

- **Key generation cost**: this is where the schemes really diverge. Lamport
  and WOTS keygen is cheap because it's a one-time key, generated right
  before use. XMSS keygen is expensive because it's really generating and
  hashing together *many* WOTS key pairs up front (`2^h` of them) — that
  cost buys you the ability to sign many messages later without doing this
  again.

- **How many times you can sign**: this is the most important practical
  difference. Lamport and WOTS are strictly **one-time** — sign twice with
  the same key and the scheme becomes forgeable. XMSS trades a slower,
  one-time setup cost for the ability to sign up to `2^h` messages with one
  public key, which is why it's the one actually used in real protocols
  (it's an IETF standard, RFC 8391).

- **Statefulness**: Lamport and WOTS have no state to manage — generate,
  sign once, done. XMSS *does* have state: it must remember which leaf index
  it's already used, or it risks reusing a one-time key, which breaks
  security. This library tracks that automatically, but it's the reason XMSS
  is harder to deploy safely than the other two (e.g. it can't be trivially
  restored from a backup without also restoring the index).

### Bottom line

Lamport is the easiest to understand and reason about, but wasteful — one
signature only, and the biggest keys/signatures of the three. WOTS shrinks
everything by around 4x for the same one-time-only limitation. XMSS is the
practical one: small signatures, a tiny public key, and the ability to sign
many messages — paid for with a slower setup and the responsibility of
tracking state.

## A note on scope

These implementations are written to be read and understood, not to be
dropped into a production system. A few corners were simplified on purpose
for clarity — for example, key material is generated directly from randomness
rather than derived from a seed with a pseudorandom function (which real
implementations use to make backups easier and keys smaller to store).
