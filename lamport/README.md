# Lamport Signatures

A digital signature solves a simple everyday problem: how do you prove that a
message really came from you, and was not changed on the way, without meeting
in person? You publish something (a public key), keep something secret (a
private key), and attach a proof (a signature) to each message that anyone
can check against the public key — but that nobody could have produced
without the secret. Leslie Lamport showed in 1979 how to build such a proof
out of nothing but a one-way function — a function that is easy to compute
forward and practically impossible to run backward. An ordinary hash function
like SHA-256 fits.

Lamport signatures are the simplest post-quantum signature scheme. They only
need a hash function to be secure — no elliptic curves, no number theory. That
is exactly why they resist quantum computers: a good hash function is not
known to be breakable by Shor's algorithm the way RSA and ECDSA are.

The tradeoff is that a Lamport key pair can only be used **once**. Sign a
second message with the same key and anyone can forge new signatures.

## The idea in one sentence

For every bit of the message, you prove you know one of two secret values —
without ever revealing the secret value for the *other* bit.

## Step by step

**1. Pick two random secrets for every bit.**

A SHA-256 hash is 256 bits long, so we need 256 pairs. For each position
`i` from 0 to 255, generate two random 32-byte blocks:

```
secret_zero[i]   (used if bit i of the message hash is 0)
secret_one[i]    (used if bit i of the message hash is 1)
```

That is 512 random blocks total. This is the private key.

**2. Hash every secret to build the public key.**

```
public_zero[i] = H(secret_zero[i])
public_one[i]  = H(secret_one[i])
```

The public key is safe to share: going from a hash back to the secret that
produced it is what "hash function" means to be hard.

**3. Signing: reveal half of the secrets.**

To sign a message, first hash it: `digest = H(message)`. This gives you 256
bits. Then, for each bit position `i`:

- if `digest bit i == 0`, reveal `secret_zero[i]`
- if `digest bit i == 1`, reveal `secret_one[i]`

The signature is just this list of 256 revealed blocks. Note only one of the
two secrets per position is ever revealed — the other stays hidden forever.

**4. Verifying: hash what was revealed and compare.**

The verifier also hashes the message to get the same 256 bits. For each
position `i`, they hash the revealed block from the signature and check it
matches the public key entry for that bit:

```
H(signature[i]) == (bit i == 0 ? public_zero[i] : public_one[i])
```

If every one of the 256 checks passes, the signature is valid.

## A tiny worked example (2 bits, by hand)

Pretend message digests were only 2 bits long, and pretend our "hash
function" turns lowercase into uppercase (a real one is irreversible, of
course). Pick four random secrets, two per bit position:

```
                bit 0     bit 1
secret_zero:    "ax"      "bq"
secret_one:     "cv"      "dk"

public_zero:    "AX"      "BQ"      (each secret, hashed)
public_one:     "CV"      "DK"
```

Now sign a message whose digest is `10`:

- bit 0 is `1` → reveal `secret_one[0]` = `"cv"`
- bit 1 is `0` → reveal `secret_zero[1]` = `"bq"`

The signature is `("cv", "bq")`. The verifier hashes each revealed value and
compares: `H("cv") = "CV"` matches `public_one[0]`, and `H("bq") = "BQ"`
matches `public_zero[1]`. Valid. Note that `"ax"` and `"dk"` were never
revealed — and without them, nobody can sign `01`, `00`, or `11`.

## Why it's only good for one signature

Each secret pair `(secret_zero[i], secret_one[i])` only hides one bit's
worth of secrecy. Once you sign one message, half of all 512 secrets are now
public. If you signed a second, different message, an attacker who read both
signatures could often pick up the missing secret for a new, third message
they invent themselves, letting them forge a signature. So: **one key pair,
one signature, then throw the key away.**

In this library, `PrivateKey::sign` takes `self` by value (not by
reference), so Rust's ownership rules make it a compile error to sign twice
with the same key — the key is consumed the moment you use it.

## Cost

- Private key: 512 × 32 bytes = 16 KB
- Public key: 512 × 32 bytes = 16 KB
- Signature: 256 × 32 bytes = 8 KB
- Signing: 1 hash (the message digest) — the rest is just selecting
  secrets, so it is nearly instant
- Verifying: 257 hash operations (the message digest plus one per
  revealed value), still very fast

The signature is large compared to classical schemes like ECDSA (64 bytes),
but the operations are just hashing, which is cheap and simple to trust.

## Where this lives in the code

| Concept | Code |
| --- | --- |
| Two random secrets per bit (private key) | `PrivateKey::generate` in [`src/lib.rs`](src/lib.rs) |
| Hashing every secret (public key) | `PrivateKey::public_key` in [`src/lib.rs`](src/lib.rs) |
| Splitting the message digest into 256 bits | `message_bits` in [`src/lib.rs`](src/lib.rs) |
| Signing — reveal one secret per bit | `PrivateKey::sign` in [`src/lib.rs`](src/lib.rs) |
| Verifying — hash each revealed value, compare | `verify` in [`src/lib.rs`](src/lib.rs) |
| One key, one signature (enforced by ownership) | `sign(self, ...)` takes the key by value in [`src/lib.rs`](src/lib.rs) |

## References

- L. Lamport, ["Constructing Digital Signatures from a One Way
  Function"](https://www.microsoft.com/en-us/research/publication/constructing-digital-signatures-one-way-function/),
  SRI International technical report CSL-98, October 1979
  ([PDF](https://lamport.azurewebsites.net/pubs/dig-sig.pdf)). The origin of
  the scheme: §2 ("The Algorithm") shows how to sign by revealing a
  message-selected subset of one-way-function preimages, and why a key must
  only be used once.
- R. Merkle, ["A Certified Digital
  Signature"](https://www.ralphmerkle.com/papers/Certified1979.pdf), CRYPTO
  '89 (written 1979). §3 ("The Lamport-Diffie One Time Signature") writes
  down the exact two-secrets-per-bit form implemented in this crate.
