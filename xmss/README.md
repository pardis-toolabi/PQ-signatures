# XMSS (eXtended Merkle Signature Scheme)

WOTS gives us small, one-time signatures. But "one-time" is a real problem —
most real-world uses need to sign more than once with the same public key.
XMSS solves this by combining *many* WOTS key pairs under a single public
key, using a Merkle tree.

## The idea in one sentence

Generate a whole batch of WOTS key pairs ahead of time, publish only the
root of a hash tree built over their public keys, and each signature both
proves you own one of the WOTS keys *and* proves that key is really part of
that tree.

## Step by step

**1. Generate many one-time key pairs.**

Choose a height `h`. This gives `2^h` WOTS key pairs — for example, `h = 8`
gives 256 of them. Each one can sign exactly one message, same as before.

**2. Turn each WOTS public key into a "leaf".**

Hash each WOTS public key down to a single 32-byte value. These become the
leaves of a binary tree:

```
leaf[i] = H(wots_public_key[i])
```

**3. Build a Merkle tree on top of the leaves.**

Pair up neighboring leaves and hash them together, then pair up *those*
results, and so on, until only one value is left:

```
level_1[i] = H(leaf[2i] || leaf[2i+1])
level_2[i] = H(level_1[2i] || level_1[2i+1])
...
root       = the single value left at the top
```

The **root** is the entire XMSS public key — just 32 bytes, no matter how
many leaves there are underneath.

**4. Signing: use the next unused leaf, and prove where it lives.**

To sign the `i`-th message, use the `i`-th WOTS key pair to produce a normal
WOTS signature. Then attach an **authentication path**: the list of sibling
hashes needed to recompute the root starting from leaf `i`. There is exactly
one sibling per tree level, so the path has `h` entries.

```
signature = (index i, WOTS signature, authentication path)
```

**5. Verifying: rebuild the WOTS public key, then walk up to the root.**

The verifier doesn't have the WOTS public keys stored anywhere — they
recompute the one used for this signature straight from the message and
signature (this is the same trick as WOTS's `recover_public_key`). Then they
hash it down to a leaf, and use the authentication path to walk back up to a
root, combining with each sibling in the right left/right order (based on
whether the current index is even or odd):

```
node = H(recovered_wots_public_key)
for each sibling in authentication path:
    node = index even ? H(node || sibling) : H(sibling || node)
    index = index / 2
```

If the final `node` matches the public root, the signature is valid — this
proves both that the WOTS signature is genuine *and* that it belongs to leaf
`i` of the tree that the public key committed to.

## Why the index matters (statefulness)

Each leaf is still a one-time WOTS key underneath. If the same leaf index is
ever used twice, it's exactly as unsafe as reusing a Lamport or WOTS key —
an attacker with two signatures from the same leaf can forge a third. This
means an XMSS signer must **remember which index they're on** and never sign
twice with the same one. This library tracks the index automatically and
`sign()` refuses to reuse a leaf, but if you ever restore a private key from
a backup, you must make sure it remembers the correct next index, or you
risk reusing one.

## Cost (height h, 2^h signatures available)

- Public key: 32 bytes, regardless of `h`
- Signature: a 4-byte leaf index + 1 WOTS signature (≈2.1 KB) + `h`
  sibling hashes (`h × 32` bytes)
- Key generation: build `2^h` WOTS key pairs — this is the expensive part,
  and it happens once, up front
- Signing/verifying: one WOTS sign/verify, plus `h` extra hashes for the
  authentication path — barely more expensive than plain WOTS

This is the key improvement over plain WOTS: a tiny, fixed-size public key,
and the ability to sign many messages instead of just one.
