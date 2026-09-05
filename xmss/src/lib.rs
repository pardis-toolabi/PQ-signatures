//! XMSS: many one-time WOTS keys under a single Merkle-tree public key.
//!
//! References:
//! - J. Buchmann, E. Dahmen, A. Hülsing, "XMSS – A Practical Forward Secure
//!   Signature Scheme Based on Minimal Security Assumptions", PQCrypto 2011.
//!   https://eprint.iacr.org/2011/484
//! - RFC 8391 (XMSS), §4. https://www.rfc-editor.org/rfc/rfc8391.html
//! - R. Merkle, "A Certified Digital Signature", CRYPTO '89. §6 ("Tree
//!   Authentication") is the original Merkle tree and authentication path.
//!   https://www.ralphmerkle.com/papers/Certified1979.pdf
//!
//! Simplified for teaching: hashes are raw SHA-256 with one-byte leaf/node
//! domain-separation prefixes, where RFC 8391 uses keyed, bitmasked hashing
//! throughout, and the whole tree is kept in memory rather than recomputed.

use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;

fn leaf_hash(public_key: &wots::PublicKey) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(public_key.to_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

fn node_hash(left: [u8; HASH_LEN], right: [u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

// Merkle '89 §6 / RFC 8391 §4.1.6 (treeHash): hash sibling pairs upward
// until a single root remains, which becomes the entire public key.
fn build_tree(leaves: Vec<[u8; HASH_LEN]>) -> Vec<Vec<[u8; HASH_LEN]>> {
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let next = levels
            .last()
            .unwrap()
            .chunks(2)
            .map(|pair| node_hash(pair[0], pair[1]))
            .collect();
        levels.push(next);
    }
    levels
}

pub struct PrivateKey {
    wots_keys: Vec<Option<wots::PrivateKey>>,
    tree: Vec<Vec<[u8; HASH_LEN]>>,
    height: u32,
    next_index: usize,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    root: [u8; HASH_LEN],
    height: u32,
}

pub struct Signature {
    index: u32,
    wots_signature: wots::Signature,
    auth_path: Vec<[u8; HASH_LEN]>,
}

impl PrivateKey {
    /// `height` sets the tree size: 2^height one-time key pairs, so this
    /// key pair can sign up to 2^height messages in total.
    pub fn generate(height: u32) -> Self {
        let leaf_count = 1usize << height;
        let wots_privates: Vec<wots::PrivateKey> =
            (0..leaf_count).map(|_| wots::PrivateKey::generate()).collect();
        let leaves = wots_privates.iter().map(|sk| leaf_hash(&sk.public_key())).collect();
        let tree = build_tree(leaves);
        let wots_keys = wots_privates.into_iter().map(Some).collect();
        PrivateKey { wots_keys, tree, height, next_index: 0 }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey { root: self.tree[self.height as usize][0], height: self.height }
    }

    pub fn remaining_signatures(&self) -> usize {
        (1usize << self.height) - self.next_index
    }

    /// Signs with the next unused one-time key and advances the internal
    /// index. Returns `None` once every leaf has been used — the tree is
    /// exhausted and a fresh key pair is needed.
    ///
    /// RFC 8391 §4.1.9: XMSS signing is stateful — the index update is part
    /// of the private key, not an implementation convenience.
    pub fn sign(&mut self, message: &[u8]) -> Option<Signature> {
        if self.next_index >= self.wots_keys.len() {
            return None;
        }
        let index = self.next_index;
        self.next_index += 1;

        let wots_sk = self.wots_keys[index].take().expect("leaf already used");
        let wots_signature = wots_sk.sign(message);
        let auth_path = self.auth_path(index);
        Some(Signature { index: index as u32, wots_signature, auth_path })
    }

    // Merkle '89 §6's authentication path (RFC 8391 §4.1.8): the sibling at
    // each level (index ^ 1) is exactly what a verifier needs to rebuild the
    // root from one leaf.
    fn auth_path(&self, mut index: usize) -> Vec<[u8; HASH_LEN]> {
        let mut path = Vec::with_capacity(self.height as usize);
        for level in &self.tree[..self.height as usize] {
            path.push(level[index ^ 1]);
            index /= 2;
        }
        path
    }
}

// RFC 8391 §4.1.10: recover the WOTS public key from the signature, hash it
// to a leaf, then fold in the auth-path siblings; valid iff the root matches.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    if signature.auth_path.len() as u32 != public_key.height {
        return false;
    }
    // The Merkle walk below only consumes the low `height` bits of the
    // index, so without this bound any index congruent mod 2^height would
    // verify too — a malleable signature claiming a leaf it never used.
    if u64::from(signature.index) >= 1u64 << public_key.height {
        return false;
    }
    let recovered_wots_key = wots::recover_public_key(message, &signature.wots_signature);
    let mut node = leaf_hash(&recovered_wots_key);
    let mut index = signature.index as usize;
    for sibling in &signature.auth_path {
        node = if index.is_multiple_of(2) { node_hash(node, *sibling) } else { node_hash(*sibling, node) };
        index /= 2;
    }
    node == public_key.root
}

impl Signature {
    pub fn size_bytes(&self) -> usize {
        4 + self.wots_signature.size_bytes() + self.auth_path.len() * HASH_LEN
    }
}

impl PublicKey {
    pub fn size_bytes(&self) -> usize {
        HASH_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_several_messages() {
        let mut sk = PrivateKey::generate(3);
        let pk = sk.public_key();

        for i in 0..8 {
            let message = format!("message number {i}");
            let signature = sk.sign(message.as_bytes()).unwrap();
            assert!(verify(&pk, message.as_bytes(), &signature));
        }
    }

    #[test]
    fn tree_is_exhausted_after_all_leaves_used() {
        let mut sk = PrivateKey::generate(2);
        for _ in 0..4 {
            assert!(sk.sign(b"message").is_some());
        }
        assert!(sk.sign(b"one too many").is_none());
    }

    #[test]
    fn tampered_message_fails() {
        let mut sk = PrivateKey::generate(3);
        let pk = sk.public_key();
        let signature = sk.sign(b"original").unwrap();
        assert!(!verify(&pk, b"different", &signature));
    }

    #[test]
    fn wrong_leaf_index_fails() {
        let mut sk = PrivateKey::generate(3);
        let pk = sk.public_key();
        let mut signature = sk.sign(b"message").unwrap();
        signature.index += 1;
        assert!(!verify(&pk, b"message", &signature));
    }

    #[test]
    fn out_of_range_leaf_index_fails() {
        // An index congruent to the real leaf mod 2^height walks the same
        // Merkle path; only the explicit bound check rejects it.
        let mut sk = PrivateKey::generate(3);
        let pk = sk.public_key();
        let mut signature = sk.sign(b"message").unwrap();
        signature.index += 8;
        assert!(!verify(&pk, b"message", &signature));
        signature.index += 8;
        assert!(!verify(&pk, b"message", &signature));
    }
}
