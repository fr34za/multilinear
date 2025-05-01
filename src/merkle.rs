use sha2::digest::{generic_array::GenericArray, OutputSizeUser};
use sha2::{Digest, Sha256};

pub type HashDigest = GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>;

#[derive(Debug)]
pub struct Merkle<T> {
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

        Merkle { layers, data }
    }

    pub fn root(&self) -> HashDigest {
        self.layers.last().unwrap()[0]
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
            let (sibling_index, direction) = if current_index % 2 == 0 {
                (current_index + 1, Direction::Right)
            } else {
                (current_index - 1, Direction::Left)
            };

            if sibling_index < layer.len() {
                path.push((layer[sibling_index], direction));
            }

            current_index /= 2; // Move para o próximo nível
        }

        Some(MerkleInclusionPath { value, path })
    }
}

pub enum MerkleInclusionPathError {
    IncompatibleHash(HashDigest, HashDigest),
}

impl std::fmt::Debug for MerkleInclusionPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MerkleInclusionPathError::IncompatibleHash(hash1, hash2) => {
                write!(f, "{:x?} != {:x?}", hash1, hash2)
            }
        }
    }
}

// impl<T> MerkleInclusionPath<T> {
//     pub fn verify(&self) -> Result<(), MerkleInclusionPathError> {
//         Ok(())
//     }
// }

impl<T> MerkleInclusionPath<T>
where
    T: AsRef<[u8]> + Clone, // o clone é necessário para o valor da leaf;
{
    /// Verifica se o caminho de inclusão é válido, comparando o hash recalculado com a raiz
    pub fn verify(&self, root: &HashDigest) -> Result<(), MerkleInclusionPathError> {
        // Recalcular o hash a partir do valor da folha.
        let mut computed_hash = {
            let mut hasher = Sha256::new();
            hasher.update(self.value.as_ref());
            hasher.finalize()
        };

        // Validar o caminho da inclusão, recalculando o hash até chegar na raiz.
        // for (sibling_hash, direction) in &self.path {
        //     computed_hash = match direction {
        //         Direction::Left => {
        //             let mut hasher = Sha256::new();
        //             hasher.update(sibling_hash);
        //             hasher.update(&computed_hash);
        //             hasher.finalize()
        //         }
        //         Direction::Right => {
        //             let mut hasher = Sha256::new();
        //             hasher.update(&computed_hash);
        //             hasher.update(sibling_hash);
        //             hasher.finalize()
        //         }
        //     };
        // }
        for (sibling_hash, direction) in &self.path {
            computed_hash = match direction {
                Direction::Left => Merkle::hash_node(sibling_hash, &computed_hash),
                Direction::Right => Merkle::hash_node(&computed_hash, sibling_hash),
            };
        }
        // let mut hasher = Sha256::new();
        // hasher.update(left);
        // hasher.update(right);
        // computed_hash = hasher.finalize();

        // Validar se o hash recalculado corresponde à raiz da árvore.
        if &computed_hash == root {
            Ok(())
        } else {
            Err(MerkleInclusionPathError::IncompatibleHash(
                *root,
                computed_hash,
            ))
        }
    }
}
#[cfg(test)]
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

        println!("Merkle Root: {:x?}", merkle_tree.root());

        ver se notação da IA melhorou
    */

    println!("Merkle Root:\n {:x?}", merkle_tree.root());

    // Testando "open" com um índice válido
    if let Some(proof) = merkle_tree.open(5) {
        println!("Inclusion Path for index 5:\n {:x?}", proof);
    } else {
        println!("Invalid index!");
    }
}
