// Use sha256
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Digest([u8; 32]);

#[derive(Debug)]
pub struct Merkle {
    root: Digest,
    layers: Vec<Vec<Digest>>,
}

#[derive(Debug)]
pub struct MerkleInclusionPath {
    value: Vec<u8>,
    path: Vec<(Digest, bool)>,
}

impl Merkle {
    pub fn commit(data: Vec<u8>) -> Merkle {
        assert!(
            data.len().is_power_of_two(),
            "Data length must be power of two"
        );

        let leaf_hashes = data
            .chunks_exact(1)
            .map(|chunk| Self::hash_leaf(chunk))
            .collect::<Vec<_>>();

        let mut layers = vec![leaf_hashes];

        while layers.last().unwrap().len() > 1 {
            let current_layer = layers.last().unwrap();
            let next_layer = current_layer
                .chunks(2)
                .map(|pair| Self::hash_node(&pair[0], &pair[1]))
                .collect();
            layers.push(next_layer);
        }

        Merkle {
            root: layers.last().unwrap()[0].clone(),
            layers,
        }
    }

    pub fn open(&self, index: usize) -> MerkleInclusionPath {
        assert!(index < self.layers[0].len(), "Index out of bounds");

        let mut path = Vec::new();
        let mut current_index = index;
        let value = self.layers[0][current_index].0.to_vec();

        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling = layer
                .get(sibling_index)
                .cloned()
                .unwrap_or_else(|| Digest::default());

            path.push((sibling, current_index % 2 == 0));
            current_index /= 2;
        }

        MerkleInclusionPath { value, path }
    }

    fn hash_leaf(data: &[u8]) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Digest(hasher.finalize().into())
    }

    fn hash_node(left: &Digest, right: &Digest) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(&left.0);
        hasher.update(&right.0);
        Digest(hasher.finalize().into())
    }
}

impl MerkleInclusionPath {
    pub fn verify(&self, root: &Digest) -> bool {
        let mut current_hash = Self::hash_leaf(&self.value);

        for (sibling_hash, is_right) in &self.path {
            current_hash = if *is_right {
                Merkle::hash_node(&current_hash, sibling_hash)
            } else {
                Merkle::hash_node(sibling_hash, &current_hash)
            };
        }

        &current_hash == root
    }
}

impl Default for Digest {
    fn default() -> Self {
        Digest([0u8; 32])
    }
}
