//! Merkle commitments compressed with Jive, not with a sponge.
//!
//! Reference: Jive is Definition 2 in the Anemoi paper (ePrint 2022/840,
//! Section 3.2, "Merkle Compression Function: the Jive Mode"). CAPSS
//! (ePrint 2025/061) adopts it for Merkle trees in Section 2.1 and makes
//! the tree arity a trade-off knob in Section 4.1.
//!
//! This is the detail most likely to be got wrong when reading the CAPSS
//! paper quickly. Leaves are hashed with the sponge XOF in `transcript`,
//! but internal nodes are compressed with **Jive**, a Davies-Meyer
//! construction wrapped around the same permutation:
//!
//! ```text
//! P'(x) = P(x) + x                                 feed-forward
//! Jive(x) = sum over i in [0, arity) of P'_i(x)     chunk-wise sum
//! ```
//!
//! `P'` is split into `arity` chunks of `c = t / arity` elements each and
//! the chunks are added together, giving an `arity`-to-1 map
//! `F_q^t -> F_q^c`. One permutation call compresses a whole node, where a
//! sponge would need one call per rate block plus a squeeze. That is the
//! single biggest lever in the scheme: `notes/capss-spec.md` records that
//! Merkle path verification is 41-63% of all R1CS constraints, so halving
//! the permutation calls per node halves most of the circuit.
//!
//! The `arity` here is the **tree arity**, not the S-box exponent
//! `alpha = 7`. The paper uses the same letter for both.
//!
//! ## Which arities work at t = 8
//!
//! `arity` must divide `t`, so with the reference C configuration's
//! `t = 8` the choices are 2, 4 and 8 — giving node widths of 4, 2 and 1
//! field elements. **Arity 3, which the paper does use, is not available
//! at `t = 8`**; it needs `t = 3` (the BN254 Griffin instances) or `t = 6`.
//!
//! Only arity 2 is safe here. A node must be `2*lambda` bits wide for
//! collision resistance, and at 64 bits per element that means 4 elements:
//!
//! | arity | node width | node bits | collision security |
//! |-------|-----------|-----------|--------------------|
//! | 2 | 4 | 256 | 128 bits |
//! | 4 | 2 | 128 | 64 bits — too weak |
//! | 8 | 1 | 64 | 32 bits — far too weak |
//!
//! Arities 4 and 8 are implemented because the structure is identical and
//! they are useful for testing the general path, but `DEFAULT_ARITY` is 2
//! and nothing at 128-bit security should use the others over Goldilocks.
//! A real high-arity CAPSS instance widens `t` to keep the node at
//! `2*lambda` bits; it does not shrink the node.

use crate::anemoi::{permute, WIDTH};
use crate::field::Fp;

/// The only arity that gives `2*lambda`-bit nodes at `t = 8`. See the
/// module comment.
pub const DEFAULT_ARITY: usize = 2;

/// Arities this implementation accepts: the divisors of `t` above 1.
pub const SUPPORTED_ARITIES: [usize; 3] = [2, 4, 8];

/// Node width `c = t / arity`, in field elements.
pub fn node_width(arity: usize) -> usize {
    assert!(SUPPORTED_ARITIES.contains(&arity), "arity {arity} does not divide t = {WIDTH}");
    WIDTH / arity
}

/// Jive compression: `arity` child nodes in, one node out.
///
/// `Jive(x) = sum_i P'_i(x)` with `P'(x) = P(x) + x`, per Definition 2
/// of the Anemoi paper (Section 3.2).
/// The feed-forward `P(x) + x` is what makes this one-way rather than
/// merely a permutation restricted to a subspace — without it, inverting
/// the compression would only need one inverse permutation call.
pub fn compress(children: &[Fp], arity: usize) -> Vec<Fp> {
    let width = node_width(arity);
    assert_eq!(children.len(), WIDTH, "Jive consumes a full permutation state");

    let mut state = [Fp::ZERO; WIDTH];
    state.copy_from_slice(children);
    permute(&mut state);
    for (slot, input) in state.iter_mut().zip(children) {
        *slot = *slot + *input;
    }

    (0..width)
        .map(|position| {
            (0..arity).fold(Fp::ZERO, |sum, chunk| sum + state[chunk * width + position])
        })
        .collect()
}

/// A Merkle tree over nodes of `node_width(arity)` field elements.
///
/// Layers are stored flat — one `Vec<Fp>` per layer holding
/// `count * width` elements — because a `Vec<Vec<Fp>>` of four-element
/// nodes spends more time chasing pointers than hashing.
pub struct MerkleTree {
    arity: usize,
    width: usize,
    layers: Vec<Vec<Fp>>,
}

/// An opening for one leaf: at every level, the `arity - 1` sibling nodes,
/// in their positional order with the leaf's own subtree left out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub siblings: Vec<Vec<Fp>>,
}

impl MerkleTree {
    /// `leaves` must all be `node_width(arity)` elements wide, and there
    /// must be a power of `arity` of them.
    pub fn build(leaves: &[Vec<Fp>], arity: usize) -> MerkleTree {
        let width = node_width(arity);
        assert!(!leaves.is_empty(), "cannot commit to nothing");
        assert!(
            leaves.iter().all(|leaf| leaf.len() == width),
            "every leaf must be {width} field elements wide"
        );
        assert!(is_power_of(leaves.len(), arity), "leaf count must be a power of {arity}");

        let mut layers = vec![leaves.concat()];
        while layers.last().unwrap().len() > width {
            let previous = layers.last().unwrap();
            let mut next = Vec::with_capacity(previous.len() / arity);
            for group in previous.chunks(WIDTH) {
                next.extend_from_slice(&compress(group, arity));
            }
            layers.push(next);
        }
        MerkleTree { arity, width, layers }
    }

    pub fn root(&self) -> Vec<Fp> {
        self.layers.last().unwrap().clone()
    }

    pub fn leaf(&self, index: usize) -> &[Fp] {
        &self.layers[0][index * self.width..(index + 1) * self.width]
    }

    pub fn open(&self, mut index: usize) -> MerklePath {
        assert!(index < self.layers[0].len() / self.width, "leaf index out of range");
        let depth = self.layers.len() - 1;
        let mut siblings = Vec::with_capacity(depth);
        for layer in &self.layers[..depth] {
            let group = index / self.arity;
            let position = index % self.arity;
            let start = group * WIDTH;
            let mut level = Vec::with_capacity((self.arity - 1) * self.width);
            for child in 0..self.arity {
                if child != position {
                    let offset = start + child * self.width;
                    level.extend_from_slice(&layer[offset..offset + self.width]);
                }
            }
            siblings.push(level);
            index = group;
        }
        MerklePath { siblings }
    }

    pub fn depth(&self) -> usize {
        self.layers.len() - 1
    }

    pub fn arity(&self) -> usize {
        self.arity
    }

    pub fn leaf_count(&self) -> usize {
        self.layers[0].len() / self.width
    }
}

fn is_power_of(value: usize, base: usize) -> bool {
    let mut current = 1usize;
    while current < value {
        current *= base;
    }
    current == value
}

/// Recomputes the root a leaf and its path imply. `None` if the path is
/// malformed or the index does not fit the path's depth.
pub fn fold_to_root(
    leaf: &[Fp],
    mut index: usize,
    path: &MerklePath,
    arity: usize,
) -> Option<Vec<Fp>> {
    let width = node_width(arity);
    if leaf.len() != width {
        return None;
    }

    let mut node = leaf.to_vec();
    for level in &path.siblings {
        if level.len() != (arity - 1) * width {
            return None;
        }
        let position = index % arity;
        let mut group = Vec::with_capacity(WIDTH);
        let mut taken = 0;
        for child in 0..arity {
            if child == position {
                group.extend_from_slice(&node);
            } else {
                group.extend_from_slice(&level[taken * width..(taken + 1) * width]);
                taken += 1;
            }
        }
        node = compress(&group, arity);
        index /= arity;
    }

    // An index above the tree's width would otherwise fold to the root
    // from a position that does not exist.
    if index != 0 {
        return None;
    }
    Some(node)
}

pub fn verify(root: &[Fp], leaf: &[Fp], index: usize, path: &MerklePath, arity: usize) -> bool {
    match fold_to_root(leaf, index, path, arity) {
        Some(computed) => computed == root,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::xof;

    fn sample_leaves(count: usize, width: usize, seed: u64) -> Vec<Vec<Fp>> {
        (0..count)
            .map(|i| xof(b"merkle-test-leaf", &[Fp::new(seed), Fp::new(i as u64)], width))
            .collect()
    }

    #[test]
    fn jive_maps_a_full_state_down_to_one_node() {
        for arity in SUPPORTED_ARITIES {
            let width = node_width(arity);
            assert_eq!(width * arity, WIDTH);
            let input: Vec<Fp> = (0..WIDTH as u64).map(Fp::new).collect();
            assert_eq!(compress(&input, arity).len(), width);
        }
        // Arity 2 is the only one that keeps a node at 2*lambda bits.
        assert_eq!(node_width(DEFAULT_ARITY) * 64, 256);
    }

    #[test]
    fn jive_is_sensitive_to_every_input_position() {
        let base: Vec<Fp> = (0..WIDTH as u64).map(Fp::new).collect();
        let reference = compress(&base, DEFAULT_ARITY);
        for position in 0..WIDTH {
            let mut changed = base.clone();
            changed[position] = changed[position] + Fp::ONE;
            assert_ne!(compress(&changed, DEFAULT_ARITY), reference, "position {position}");
        }
    }

    #[test]
    fn jive_is_not_a_plain_chunk_sum() {
        // Without the permutation, Jive would collapse to adding the
        // chunks, and (a, b) would collide with (b, a). It must not.
        let forward: Vec<Fp> = (1..=WIDTH as u64).map(Fp::new).collect();
        let mut swapped = forward.clone();
        swapped.swap(0, 4);
        swapped.swap(1, 5);
        swapped.swap(2, 6);
        swapped.swap(3, 7);
        assert_ne!(compress(&forward, 2), compress(&swapped, 2));
    }

    #[test]
    fn openings_verify_for_every_leaf() {
        for arity in SUPPORTED_ARITIES {
            let width = node_width(arity);
            let count = arity * arity * arity;
            let leaves = sample_leaves(count, width, 1);
            let tree = MerkleTree::build(&leaves, arity);
            let root = tree.root();
            assert_eq!(tree.depth(), 3, "arity={arity}");
            for (index, leaf) in leaves.iter().enumerate() {
                let path = tree.open(index);
                assert_eq!(path.siblings.len(), 3);
                assert!(verify(&root, leaf, index, &path, arity), "arity={arity} index={index}");
            }
        }
    }

    #[test]
    fn single_leaf_tree_has_the_leaf_as_its_root() {
        let leaves = sample_leaves(1, node_width(2), 5);
        let tree = MerkleTree::build(&leaves, 2);
        assert_eq!(tree.depth(), 0);
        assert_eq!(tree.root(), leaves[0]);
        assert!(verify(&tree.root(), &leaves[0], 0, &tree.open(0), 2));
    }

    #[test]
    fn wrong_leaf_is_rejected() {
        let leaves = sample_leaves(16, node_width(2), 2);
        let tree = MerkleTree::build(&leaves, 2);
        let path = tree.open(5);
        assert!(!verify(&tree.root(), &leaves[6], 5, &path, 2));

        // A single-element change in the leaf, not just a different leaf.
        let mut tweaked = leaves[5].clone();
        tweaked[0] = tweaked[0] + Fp::ONE;
        assert!(!verify(&tree.root(), &tweaked, 5, &path, 2));
    }

    #[test]
    fn wrong_index_is_rejected() {
        let leaves = sample_leaves(16, node_width(2), 3);
        let tree = MerkleTree::build(&leaves, 2);
        let path = tree.open(5);
        assert!(!verify(&tree.root(), &leaves[5], 4, &path, 2));
        assert!(!verify(&tree.root(), &leaves[5], 13, &path, 2));
        // Out of range entirely: the fold must not wrap around.
        assert!(!verify(&tree.root(), &leaves[5], 21, &path, 2));
    }

    #[test]
    fn tampered_path_is_rejected() {
        for arity in SUPPORTED_ARITIES {
            let width = node_width(arity);
            let leaves = sample_leaves(arity * arity, width, 4);
            let tree = MerkleTree::build(&leaves, arity);
            for level in 0..tree.depth() {
                let mut path = tree.open(1);
                path.siblings[level][0] = path.siblings[level][0] + Fp::ONE;
                assert!(
                    !verify(&tree.root(), &leaves[1], 1, &path, arity),
                    "arity={arity} level={level}"
                );
            }
            // A path of the wrong length must be rejected, not panic.
            let mut short = tree.open(1);
            short.siblings.pop();
            assert!(!verify(&tree.root(), &leaves[1], 1, &short, arity));
            let mut ragged = tree.open(1);
            ragged.siblings[0].pop();
            assert!(!verify(&tree.root(), &leaves[1], 1, &ragged, arity));
        }
    }

    #[test]
    fn tampered_root_is_rejected() {
        let leaves = sample_leaves(16, node_width(2), 6);
        let tree = MerkleTree::build(&leaves, 2);
        let mut root = tree.root();
        root[2] = root[2] + Fp::ONE;
        assert!(!verify(&root, &leaves[3], 3, &tree.open(3), 2));
    }

    #[test]
    fn different_leaves_give_different_roots() {
        let leaves = sample_leaves(16, node_width(2), 7);
        let first = MerkleTree::build(&leaves, 2).root();

        let mut changed = leaves.clone();
        changed[7][1] = changed[7][1] + Fp::ONE;
        assert_ne!(MerkleTree::build(&changed, 2).root(), first);

        // Reordering the leaves must change the root too — a tree that
        // only committed to the multiset would not bind indices.
        let mut swapped = leaves.clone();
        swapped.swap(2, 9);
        assert_ne!(MerkleTree::build(&swapped, 2).root(), first);
    }

    #[test]
    fn arity_changes_the_depth_not_the_leaf_count() {
        let count = 64;
        for arity in SUPPORTED_ARITIES {
            let leaves = sample_leaves(count, node_width(arity), 8);
            let tree = MerkleTree::build(&leaves, arity);
            assert_eq!(tree.leaf_count(), count);
            // 64 = 2^6 = 4^3 = 8^2.
            let expected = match arity {
                2 => 6,
                4 => 3,
                _ => 2,
            };
            assert_eq!(tree.depth(), expected, "arity={arity}");
            assert_eq!(tree.open(0).siblings.len(), expected);
        }
    }
}
