use crate::field::Field128;
use crate::merkle_tree::{Merkle, MerkleInclusionPath};
use crate::ntt::{NttField, Polynomial};
use crate::{field::Field, merkle_tree::HashDigest};

use sha2::{Digest, Sha256};

pub struct Transcript {
    state: Sha256,
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    pub fn new() -> Self {
        Self {
            state: Sha256::new(),
        }
    }

    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.state.update(label);
        self.state.update(message);
    }

    pub fn random(&self) -> [u8; 32] {
        let cloned_state = self.state.clone();
        let result = cloned_state.finalize();
        let mut random_bytes = [0u8; 32];
        random_bytes.copy_from_slice(&result[..32]);
        random_bytes
    }
}

pub trait HashableField: Field + AsRef<[u8]> {
    fn to_bytes(&self) -> &[u8];
    fn from_digest(digest: &[u8; 32]) -> Self;
}

impl HashableField for Field128 {
    fn to_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    fn from_digest(digest: &[u8; 32]) -> Self {
        let x = u128::from_le_bytes(digest[0..16].try_into().unwrap());
        Self::from(x)
    }
}

pub struct ProverData<F> {
    pub commitments: Vec<Merkle<F>>,
    pub polynomials: Vec<Vec<F>>,
    pub last_element: Option<F>,
}

pub const LOG_BLOWUP: usize = 1;
pub const NUM_QUERIES: usize = 128;

pub fn reed_solomon<F: Field>(mut coeffs: Vec<F>, gen: F) -> Vec<F> {
    // first, multiply the size of `coeffs` by a factor of `blowup` through adding zeros
    let n = coeffs.len();
    let blowup = 1 << LOG_BLOWUP;
    assert!(blowup > 1);
    coeffs.resize(blowup * n, F::from(0));
    // use `ntt` to compute the Reed-Solomon encoding.
    let lagrange = Polynomial { coeffs }.ntt_iterative(gen);
    lagrange.evals
}

impl<F: HashableField> ProverData<F> {
    pub fn init(values: Vec<F>, gen: F, transcript: &mut Transcript) -> Self {
        // `values` must be power of two.
        assert!(
            values.len().is_power_of_two(),
            "Input size must be a power of two"
        );
        // push save a copy of `values` to `polynomials`
        let polynomials = vec![values.clone()];
        // use `reed_solomon` to compute the values for commitment.
        let rs_encoded = reed_solomon(values, gen);
        // commit to a `Merkle` tree using `to_bytes` method.
        let mut commitments = Vec::new();
        let merkle = Merkle::commit(rs_encoded);
        let root = merkle.root();
        // add to `commitments`.
        commitments.push(merkle);
        // Use the `root()` to update the transcript
        transcript.append_message(b"merkle_root", root.as_slice());
        Self {
            commitments,
            polynomials,
            last_element: None,
        }
    }

    pub fn fold_step(&mut self, gen: F, transcript: &mut Transcript) {
        let last_poly = self.polynomials.last().unwrap().clone();
        let n = last_poly.len();
        if n <= 1 {
            return;
        }

        // generate random field element called `r` from the transcript using `random` and `from_digest`
        let random_bytes = transcript.random();
        let r = F::from_digest(&random_bytes);

        let half_n = n >> 1;
        let mut next_poly = Vec::with_capacity(half_n);

        for i in 0..(half_n) {
            let even = last_poly[i * 2];
            let odd = last_poly[i * 2 + 1];

            next_poly.push(even + r * odd);
        }
        if half_n == 1 {
            // sanity check: last polynomial must be constant
            let first = next_poly[0];
            assert!(
                next_poly.iter().all(|next| first == *next),
                "not an RS code"
            );
            self.last_element = Some(first);
            transcript.append_message(b"last_element", first.as_ref());
            return;
        }
        self.polynomials.push(next_poly.clone());

        // Use `reed_solomon` to compute the values for commitment.
        let next_gen = gen * gen;
        let rs_encoded = reed_solomon(next_poly, next_gen);

        // `commit` to Merkle, etc
        let merkle = Merkle::commit(rs_encoded);
        let root = merkle.root();
        self.commitments.push(merkle);

        // Use the `root()` to update the transcript
        transcript.append_message(b"merkle_root", root.as_slice());
    }

    pub fn fold_step_opt(&mut self, gen: F, transcript: &mut Transcript) {
        // do not use polynomials. instead work solely on lagrange basis reading
        // the merkle `value` field
        let last_data = self.commitments.last().unwrap().data.clone();
        let n = last_data.len();
        let blowup = 1 << LOG_BLOWUP;
        if n <= blowup {
            return;
        }
        let random_bytes = transcript.random();
        let r = F::from_digest(&random_bytes);
        let half_n = n >> 1;
        let mut next_data = Vec::with_capacity(half_n);
        let mut gen_pow = F::from(1);
        for i in 0..half_n {
            // p(gen^i)
            let a = last_data[i];
            // p(-gen^i)
            let b = last_data[i + half_n];
            // even(x^2) = (p(x) + p(-x))/2, where x = gen^i
            let even = (a + b) / F::from(2);
            // odd(x^2) = (p(x) - p(-x))/2x, where x = gen^i
            let odd = (a - b) / (F::from(2) * gen_pow);
            // p(x) + p(-x) == 2*even(x^2)
            next_data.push(even + r * odd);
            gen_pow *= gen;
        }

        if half_n == blowup {
            // sanity check: last RS code must be constant
            let first = next_data[0];
            assert!(
                next_data.iter().all(|next| first == *next),
                "not an RS code"
            );
            self.last_element = Some(first);
            transcript.append_message(b"last_element", first.as_ref());
            return;
        }
        // `commit` to Merkle, etc
        let merkle = Merkle::commit(next_data);
        let root = merkle.root();
        self.commitments.push(merkle);

        // Use the `root()` to update the transcript
        transcript.append_message(b"merkle_root", root.as_slice());
    }

    pub fn fold(gen: F, values: Vec<F>, transcript: &mut Transcript) -> Self {
        let mut prover_data = Self::init(values, gen, transcript);
        let mut current_gen = gen;
        while prover_data.last_element.is_none() {
            prover_data.fold_step_opt(current_gen, transcript);
            current_gen *= current_gen;
        }
        prover_data
    }

    pub fn fold_roots(&self) -> Vec<HashDigest> {
        self.commitments
            .iter()
            .map(|merkle| merkle.root())
            .collect()
    }

    pub fn open_query_at(&self, index: usize) -> QueryProof<F> {
        let n = self.commitments[0].data.len();
        assert!(index < n / 2);
        let conjugate_index = index + n / 2;

        let mut paths = Vec::new();
        let mut current_index = index;
        let mut current_conjugate = conjugate_index;

        for merkle in &self.commitments {
            let path = merkle.open(current_index).expect("Index out of bounds");
            let conjugate_path = merkle
                .open(current_conjugate)
                .expect("Conjugate index out of bounds");

            paths.push((path, conjugate_path));

            current_index /= 2;
            current_conjugate /= 2;
        }

        QueryProof { index, paths }
    }
}

pub struct QueryProof<F> {
    // initial random index, from 0..N/2
    pub index: usize,
    // merkle paths for all fold layers at both the index and index + N/2
    // the index at subsequent layers are halved
    pub paths: Vec<(MerkleInclusionPath<F>, MerkleInclusionPath<F>)>,
}

pub struct FriProof<F> {
    // there are N commitments, where N is the log2 of the message size (the polynomial)
    pub commitments: Vec<HashDigest>,
    // there are `NUM_QUERIES` number of query proofs
    pub queries: Vec<QueryProof<F>>,
    // this is the last message, a single element
    pub last_elem: F,
}

impl<F: HashableField + NttField> FriProof<F> {
    pub fn prove(message: Vec<F>, transcript: &mut Transcript) -> FriProof<F> {
        // get the generator for length = blowup * message.len
        let n = message.len();
        let blowup = 1 << LOG_BLOWUP;
        let domain_size = blowup * n;
        let log_size = domain_size.trailing_zeros();
        let gen = F::pow_2_generator(log_size as u64).unwrap();

        // call `fold`
        let prover_data = ProverData::fold(gen, message, transcript);
        // define `mut n = blowup * message.len()`
        let mut n = domain_size;
        // for `0..NUM_QUERIES` generate random index between `0..n/2`
        let mut queries = Vec::with_capacity(NUM_QUERIES);
        for _ in 0..NUM_QUERIES {
            let random_bytes = transcript.random();
            let random_index = (u64::from_le_bytes(random_bytes[..8].try_into().unwrap())
                % (n / 2) as u64) as usize;
            // open query at this index and add the proof to a vector of query proofs
            let query_proof = prover_data.open_query_at(random_index);
            queries.push(query_proof);
            // use the `index` to update the transcript
            transcript.append_message(b"query_index", &random_index.to_le_bytes());
            n /= 2;
        }
        // at the end create the FriProof using the queries, last_elem and the
        FriProof {
            commitments: prover_data.fold_roots(),
            queries,
            last_elem: prover_data.last_element.unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ntt::NttField;

    use super::*;

    #[test]
    fn fold_step_test() {
        let log_n = 5;
        let values: Vec<Field128> = (0..1 << log_n)
            .map(|i| Field128::from(i as i64 * 7 + 3))
            .collect();

        let gen = Field128::pow_2_generator(log_n + 1).unwrap();

        let mut transcript1 = Transcript::new();
        let mut transcript2 = Transcript::new();

        let mut prover1 = ProverData::init(values.clone(), gen, &mut transcript1);
        let mut prover2 = ProverData::init(values.clone(), gen, &mut transcript2);

        prover1.fold_step(gen, &mut transcript1);
        prover2.fold_step_opt(gen, &mut transcript2);

        assert_eq!(
            prover1.commitments[1].root(),
            prover2.commitments[1].root(),
            "Merkle roots differ after folding"
        );

        assert_eq!(
            prover1.commitments[1].data, prover2.commitments[1].data,
            "Commitment data differs after folding"
        );
    }
}
