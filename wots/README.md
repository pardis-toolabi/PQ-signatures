# WOTS (Winternitz One-Time Signature)

Like Lamport signatures, WOTS lets you prove a message came from you using
nothing but a hash function — no number theory, nothing a quantum computer is
known to break. The problem it tackles is practicality: Lamport signatures
are honest but bulky, and Robert Winternitz's observation (published in
Merkle's 1979 paper) was that you can trade a little computation for a lot of
size by signing several bits at a time with a single hash *chain* instead of
one secret per bit.

WOTS solves Lamport's biggest problem: signature size. A Lamport signature
needs one hash value per **bit** of the message (256 of them). WOTS instead
needs one hash value per **group of bits**, which means far fewer values —
at the cost of a bit more computation per value. Like Lamport, a WOTS key
pair is still only safe to sign **one message**.

## The idea in one sentence

Instead of hiding one of two secrets per bit, hide the *start* of a hash
chain, and reveal how far along that chain you are — the further along, the
"bigger" the digit you're proving.

## Hash chains

A hash chain repeatedly hashes a value:

```
chain(x, 0) = x
chain(x, k) = H(H(H( ... H(x) ... )))     (k times)
```

Going forward (computing more hashes) is easy for anyone. Going backward
(finding what `x` was, given `chain(x, k)`) is as hard as reversing a hash —
which is the same assumption Lamport relies on.

**A tiny worked example.** Take a chain of length 3 and pretend hashing just
scrambles letters: start with a secret `x = "fox"`, and suppose

```
"fox" --H--> "tlq" --H--> "wze" --H--> "mrk"
 x           chain(x,1)   chain(x,2)   chain(x,3)  <- public key
```

The public key is the end of the chain, `"mrk"`. To sign the digit **2**,
reveal `chain(x, 2) = "wze"`. The verifier walks the remaining `3 - 2 = 1`
step: `H("wze") = "mrk"` — it lands exactly on the public key, so the digit
really was 2. Someone who only saw `"wze"` could hash forward and claim digit
3, but could never produce `"tlq"` (digit 1) — that would mean running `H`
backward. That one-way asymmetry is the entire scheme; the checksum below
exists purely to punish the "hash forward and claim a bigger digit" cheat.

## Step by step

**1. Split the message into digits, not bits.**

We use a parameter `w = 16`, so instead of bits (base 2), we work in base
16 — each "digit" is a value from 0 to 15 (one hex nibble). A 256-bit SHA-256
hash becomes 64 digits.

**2. Add a checksum.**

Chains only walk forward, so anyone holding a signature value for digit
`5` can hash it twice more and claim digit `7` — *raising* a digit is
free. Without a fix, a forger could pass off any message whose digits are
all ≥ the signed one's. To stop this, we compute a checksum that moves the
opposite way:

```
checksum = sum of (15 - digit) for all 64 message digits
```

Raising any message digit now *lowers* the checksum, so some checksum
digit must be lowered to match — and lowering a digit means walking a
hash chain *backward*, which is exactly what's hard. (The "Why raising a
digit doesn't work" section below spells this out.) The checksum needs 3
more base-16 digits to represent, so in total there are `64 + 3 = 67` digits.

**3. Generate one hash chain per digit.**

The private key is 67 random 32-byte blocks, one per digit position — the
very start of each chain. The public key is each chain walked all the way to
the end (15 hashes each):

```
public_key[i] = chain(private_key[i], 15)
```

**4. Signing: walk each chain partway.**

To sign a message, compute its 67 digits (64 from the message hash + 3
checksum digits). For each position `i`, walk that chain only as far as
digit `i` says:

```
signature[i] = chain(private_key[i], digit[i])
```

A digit of `0` means "reveal the private key itself, unchanged." A digit of
`15` means "reveal the same value as the public key."

**5. Verifying: finish the walk and compare.**

The verifier knows the digits (recomputed from the message) and the
signature. For each position, they walk the *remaining* distance to the end
of the chain and check it lands on the public key:

```
chain(signature[i], 15 - digit[i]) == public_key[i]
```

If all 67 positions match, the signature is valid.

## Why raising a digit doesn't work

Hash chains only move one direction easily: forward. Given
`signature[i] = chain(private_key[i], 5)`, anyone can hash it a couple more
times to get `chain(private_key[i], 7)` — moving a digit *up* is free. Moving
a digit *down* would mean finding what hashes *to* a value, which is exactly
what a hash function is designed to prevent.

So an attacker who wants to forge a new message just needs its digits to all
be greater than or equal to the real message's digits (with at least one
strictly greater) — they can build every one of those signature values by
hashing forward from what they already have.

This is exactly what the checksum blocks. Raising a message digit lowers
that digit's `(15 - digit)` contribution, so the checksum total goes *down*.
To keep the checksum digits consistent with a lower checksum, the attacker
would now need to *lower* one of the checksum chain values — which means
moving backward, the direction hash chains don't allow. Every forgery
attempt is stopped at the checksum.

## Cost (with w = 16)

- Private key: 67 × 32 bytes ≈ 2.1 KB
- Public key: 67 × 32 bytes ≈ 2.1 KB
- Signature: 67 × 32 bytes ≈ 2.1 KB
- Signing: up to 67 × 15 = 1,005 hash operations
- Verifying: up to another 1,005 hash operations

The signature is roughly 4x smaller than Lamport's (8 KB → 2.1 KB) and
the keys about 7.6x smaller (16 KB → 2.1 KB), at the cost of walking hash
chains instead of a single hash per position.

One simplification to be aware of: the chains here iterate raw SHA-256.
Real WOTS+ (RFC 8391) keys and addresses every hash call — a per-chain,
per-step domain separator — to prevent values being reused across chains
or key pairs. This teaching version omits that.

## Where this lives in the code

| Concept | Code |
| --- | --- |
| Walking a hash chain forward | `chain` in [`src/lib.rs`](src/lib.rs) |
| Message digits + checksum digits | `digits_of` in [`src/lib.rs`](src/lib.rs) |
| Chain starts (private key) | `PrivateKey::generate` in [`src/lib.rs`](src/lib.rs) |
| Chain ends (public key) | `PrivateKey::public_key` in [`src/lib.rs`](src/lib.rs) |
| Signing — walk each chain `digit` steps | `PrivateKey::sign` in [`src/lib.rs`](src/lib.rs) |
| Finishing the walk (used directly by XMSS) | `recover_public_key` in [`src/lib.rs`](src/lib.rs) |
| Verifying — recovered key must match | `verify` in [`src/lib.rs`](src/lib.rs) |

## References

This crate implements the *plain*, pedagogical WOTS. The chain idea and the
checksum come from Merkle's paper; the digit/checksum layout (base `w`
digits, `len_2` checksum digits) follows the standardized description in
RFC 8391; the per-step keying that this crate deliberately omits is the
contribution of WOTS+.

- R. Merkle, ["A Certified Digital
  Signature"](https://www.ralphmerkle.com/papers/Certified1979.pdf), CRYPTO
  '89 (written 1979). §5 ("The Winternitz Improvement") introduces hash-chain
  signing — publish `y = F^16(x)`, reveal `F^digit(x)` — including the
  raise-a-digit forgery and the checksum fix; §4's count-of-zeros trick is
  the checksum's ancestor.
- A. Hülsing, ["W-OTS+ — Shorter Signatures for Hash-Based Signature
  Schemes"](https://eprint.iacr.org/2017/965), AFRICACRYPT 2013 (ePrint
  2017/965). Adds per-chain, per-step keys and bitmasks to the chain
  function, giving tighter security proofs and shorter signatures.
- [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html), "XMSS: eXtended
  Merkle Signature Scheme", §3. The standardized WOTS+: §3.1.2 defines the
  chaining function, §3.1.5 the checksum and signature generation, §3.1.6
  verification by recomputing the public key (`WOTS_pkFromSig`).
