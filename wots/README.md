# WOTS (Winternitz One-Time Signature)

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

## Step by step

**1. Split the message into digits, not bits.**

We use a parameter `w = 16`, so instead of bits (base 2), we work in base
16 — each "digit" is a value from 0 to 15 (one hex nibble). A 256-bit SHA-256
hash becomes 64 digits.

**2. Add a checksum.**

If someone could quietly turn a digit like `5` into a smaller digit like
`2`, they'd only need to reveal *less* of a hash chain than the real
signer did — which would let them alter the message and still pass
verification. To stop this, we compute a checksum:

```
checksum = sum of (15 - digit) for all 64 message digits
```

If any real digit is lowered, the checksum goes up, and the attacker would
need to also raise the checksum digits — but raising a digit means walking
a hash chain *backward*, which is exactly what's hard. The checksum needs 3
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

Roughly 4x smaller than Lamport for keys and signatures, at the cost of
walking hash chains instead of a single hash per position.
