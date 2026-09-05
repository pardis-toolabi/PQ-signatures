//! Merkle commitments with a "tree cap".
//!
//! Loquat opens the same tree at many positions (kappa = 32 queries), and
//! near the top those paths all overlap. The cap exploits that: stop
//! building at the layer holding `2^cap_log` nodes and hash all of them
//! together into the root. Every query then carries a shorter path, and
//! the handful of cap nodes are sent once instead of being re-derived per
//! query. Soundness is unchanged — the root still binds every leaf.
//!
//! Reference: paper §4.3 "Hash by Subset and Tree Cap" (both ideas: 2^eta
//! values per leaf, and the capped root); the cap width t = ceil(log2(kappa)
//! - 1) is from its Appendix C constraint count.

use crate::transcript::{hash_many, hash_pair, Hash};

pub struct MerkleTree {
    /// `layers[0]` is the leaves; the last layer is the cap.
    layers: Vec<Vec<Hash>>,
    cap_log: u32,
}

/// An opening for one leaf: the sibling at each layer below the cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub siblings: Vec<Hash>,
}

impl MerkleTree {
    /// `cap_log` is how many nodes the cap layer holds, as a power of two.
    /// `cap_log = 0` gives an ordinary Merkle tree with a single root.
    pub fn build(leaves: Vec<Hash>, cap_log: u32) -> MerkleTree {
        assert!(leaves.len().is_power_of_two(), "leaf count must be a power of two");
        assert!(
            (1usize << cap_log) <= leaves.len(),
            "cap layer cannot be wider than the leaf layer"
        );

        let mut layers = vec![leaves];
        while layers.last().unwrap().len() > (1usize << cap_log) {
            let next = layers
                .last()
                .unwrap()
                .chunks(2)
                .map(|pair| hash_pair(b"node", &pair[0], &pair[1]))
                .collect();
            layers.push(next);
        }
        MerkleTree { layers, cap_log }
    }

    /// The cap nodes, which the verifier needs in full to rebuild the root.
    pub fn cap(&self) -> &[Hash] {
        self.layers.last().unwrap()
    }

    pub fn root(&self) -> Hash {
        hash_many(b"cap", self.cap())
    }

    pub fn open(&self, mut index: usize) -> MerklePath {
        assert!(index < self.layers[0].len(), "leaf index out of range");
        let depth = self.layers.len() - 1;
        let mut siblings = Vec::with_capacity(depth);
        for layer in &self.layers[..depth] {
            siblings.push(layer[index ^ 1]);
            index /= 2;
        }
        MerklePath { siblings }
    }

    pub fn depth(&self) -> usize {
        self.layers.len() - 1
    }

    pub fn cap_log(&self) -> u32 {
        self.cap_log
    }
}

/// Recomputes the cap-layer node a leaf leads to, following its path.
pub fn fold_to_cap(leaf: Hash, index: usize, path: &MerklePath) -> (Hash, usize) {
    let mut node = leaf;
    let mut position = index;
    for sibling in &path.siblings {
        node = if position.is_multiple_of(2) {
            hash_pair(b"node", &node, sibling)
        } else {
            hash_pair(b"node", sibling, &node)
        };
        position /= 2;
    }
    (node, position)
}

/// Verifies an opening against a cap that the caller has already checked
/// hashes to the expected root.
pub fn verify_with_cap(cap: &[Hash], leaf: Hash, index: usize, path: &MerklePath) -> bool {
    let (node, position) = fold_to_cap(leaf, index, path);
    position < cap.len() && cap[position] == node
}

/// Verifies an opening against a root, given the full cap.
pub fn verify(root: &Hash, cap: &[Hash], leaf: Hash, index: usize, path: &MerklePath) -> bool {
    if hash_many(b"cap", cap) != *root {
        return false;
    }
    verify_with_cap(cap, leaf, index, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: u8) -> Hash {
        let mut h = [0u8; 32];
        h[0] = i;
        h
    }

    fn sample_leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| leaf(i as u8)).collect()
    }

    #[test]
    fn openings_verify_for_every_leaf() {
        for cap_log in [0u32, 1, 2, 3] {
            let leaves = sample_leaves(16);
            let tree = MerkleTree::build(leaves.clone(), cap_log);
            let root = tree.root();
            for (index, leaf) in leaves.iter().enumerate() {
                let path = tree.open(index);
                assert!(
                    verify(&root, tree.cap(), *leaf, index, &path),
                    "cap_log={cap_log} index={index}"
                );
            }
        }
    }

    #[test]
    fn cap_shortens_the_path() {
        let leaves = sample_leaves(64);
        let plain = MerkleTree::build(leaves.clone(), 0);
        let capped = MerkleTree::build(leaves, 3);
        assert_eq!(plain.depth(), 6);
        assert_eq!(capped.depth(), 3, "cap of 2^3 nodes removes 3 layers");
    }

    #[test]
    fn wrong_leaf_is_rejected() {
        let leaves = sample_leaves(16);
        let tree = MerkleTree::build(leaves, 2);
        let path = tree.open(5);
        assert!(!verify(&tree.root(), tree.cap(), leaf(99), 5, &path));
    }

    #[test]
    fn wrong_index_is_rejected() {
        let leaves = sample_leaves(16);
        let tree = MerkleTree::build(leaves.clone(), 2);
        let path = tree.open(5);
        assert!(!verify(&tree.root(), tree.cap(), leaves[5], 6, &path));
    }

    #[test]
    fn tampered_path_is_rejected() {
        let leaves = sample_leaves(16);
        let tree = MerkleTree::build(leaves.clone(), 1);
        let mut path = tree.open(5);
        path.siblings[0] = leaf(200);
        assert!(!verify(&tree.root(), tree.cap(), leaves[5], 5, &path));
    }

    #[test]
    fn tampered_cap_is_rejected() {
        let leaves = sample_leaves(16);
        let tree = MerkleTree::build(leaves.clone(), 2);
        let path = tree.open(3);
        let mut cap = tree.cap().to_vec();
        cap[0] = leaf(123);
        assert!(!verify(&tree.root(), &cap, leaves[3], 3, &path));
    }

    #[test]
    fn different_leaves_give_different_roots() {
        let a = MerkleTree::build(sample_leaves(16), 2);
        let mut other = sample_leaves(16);
        other[7] = leaf(200);
        let b = MerkleTree::build(other, 2);
        assert_ne!(a.root(), b.root());
    }
}
