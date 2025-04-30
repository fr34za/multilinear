use sha2::digest::{generic_array::GenericArray, OutputSizeUser};
use sha2::{Digest, Sha256};

pub type HashDigest = GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>;

#[derive(Debug)]
pub struct Merkle<T> {
    pub root: HashDigest,
    pub layers: Vec<Vec<HashDigest>>,
    pub data: Vec<T>,
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Left,
    Right,
}

#[derive(Debug)]
pub struct MerkleInclusionPath<T> {
    pub value: T,
    pub sibling: (T, Direction), // Valor do sibling e direção (esquerda/direita)
    pub path: Vec<(HashDigest, Direction)>, // Hash do sibling e direção em cada nível
}

impl<T> Merkle<T>
where
    T: AsRef<[u8]>, // Ajustei o trait para permitir operações com slices de bytes
{
    pub fn commit(data: Vec<T>) -> Self {
        assert!(
            data.len().is_power_of_two(),
            "Data length must be a power of two"
        );

        let first_layer: Vec<HashDigest> = data.iter().map(|item| Self::hash_leaf(item)).collect();

        let mut layers: Vec<Vec<HashDigest>> = vec![first_layer];

        while layers.last().unwrap().len() > 1 {
            let current_layer = layers.last().unwrap();
            let next_layer: Vec<HashDigest> = current_layer
                .chunks(2)
                .map(|pair| Self::hash_node(&pair[0], &pair[1]))
                .collect();
            layers.push(next_layer);
        }

        Merkle {
            root: layers.last().unwrap()[0],
            layers,
            data,
        }
    }

    fn hash_leaf(item: &T) -> HashDigest {
        let mut hasher = Sha256::new();
        hasher.update(item.as_ref());
        hasher.finalize()
    }

    fn hash_node(left: &HashDigest, right: &HashDigest) -> HashDigest {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize()
    }

    pub fn open(&self, index: usize) -> Option<MerkleInclusionPath<T>>
    where
        T: Clone,
    {
        if index >= self.data.len() {
            return None;
        }

        let value = self.data[index].clone();
        let mut path = Vec::new();
        let mut current_index = index;

        for layer in &self.layers {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let direction = if current_index % 2 == 0 {
                Direction::Right
            } else {
                Direction::Left
            };

            if sibling_index < layer.len() {
                path.push((layer[sibling_index], direction));
            }

            current_index /= 2; // Move para o próximo nível
        }

        let sibling = if index % 2 == 0 {
            (self.data[index + 1].clone(), Direction::Right)
        } else {
            (self.data[index - 1].clone(), Direction::Left)
        };

        Some(MerkleInclusionPath {
            value,
            sibling,
            path,
        })
    }
}

#[test]
fn test_commit() {
    // main aparece como never used ainda
    // Adicionei os dados como `Vec<Vec<u8>>`, pois `u8` precisa ser tratado como um slice.
    let data = vec![[0], [8], [4], [1], [5], [7], [6], [1]];

    let merkle_tree = Merkle::commit(data);

    /*
        // tinha escrito assim pq a quantidade de itens deve ser uma potência de 2.

        let data = vec![0u8, 8, 4, 1, 5, 7, 6, 1];
        let merkle_tree = Merkle::commit(data);

        println!("Merkle Root: {:x?}", merkle_tree.root);

        ver se notação da IA melhorou
    */

    println!("Merkle Root: {:x?}", merkle_tree.root);

    // Testando "open" com um índice válido
    if let Some(proof) = merkle_tree.open(5) {
        println!("Inclusion Path for index 5: {:?}", proof);
    } else {
        println!("Invalid index!");
    }
}
