use crate::merkle_tree::{HashDigest, Merkle, MerkleInclusionPath, MerkleInclusionPathError};
use crate::ntt::{NttField, Polynomial};
use crate::transcript::{HashableField, Transcript};
use serde::{Deserialize, Serialize};

pub struct ProverData<F> {
    // Now using Merkle<ReedSolomonPair<F>>
    pub commitments: Vec<Merkle<ReedSolomonPair<F>>>,
    pub last_element: Option<F>,
}

pub const LOG_BLOWUP: usize = 1;
pub const NUM_QUERIES: usize = 128;

// FIX add `gen_pows: &[F]` to `reed_solomon`
pub fn reed_solomon<F: NttField>(mut coeffs: Vec<F>, gen_pows: &[F]) -> Vec<F> {
    // first, multiply the size of `coeffs` by a factor of `blowup` through adding zeros
    let n = coeffs.len();
    let blowup = 1 << LOG_BLOWUP;
    assert!(blowup > 1);
    coeffs.resize(blowup * n, F::from(0));
    // compute the generator for the domain size
    let domain_size = coeffs.len();
    let log_size = domain_size.trailing_zeros();
    let gen = F::pow_2_generator(log_size as u64).unwrap();
    // use `ntt` to compute the Reed-Solomon encoding.
    let lagrange = Polynomial { coeffs }.ntt(gen);
    lagrange.evals
}

#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReedSolomonPair<F> {
    pub value: F,
    pub minus_value: F,
}

impl<F: AsRef<[u8]>> AsRef<[u8]> for ReedSolomonPair<F> {
    fn as_ref(&self) -> &[u8] {
        let len = 2 * self.value.as_ref().len();
        let ptr: *const ReedSolomonPair<F> = self;
        unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) }
    }
}

fn commit_rs_code<F: HashableField>(code: Vec<F>) -> Merkle<ReedSolomonPair<F>> {
    let n = code.len();
    let half_n = n / 2;
    let pairs = (0..half_n)
        .map(|i| ReedSolomonPair {
            value: code[i],
            minus_value: code[i + half_n],
        })
        .collect();
    Merkle::commit(pairs)
}

impl<F: HashableField + NttField> ProverData<F> {
    pub fn init(code: &[F], transcript: &mut Transcript) -> Self {
        // `values` must be power of two.
        assert!(
            code.len().is_power_of_two(),
            "Input size must be a power of two"
        );
        // commit to a `Merkle` tree using `to_bytes` method.
        let mut commitments = Vec::new();
        let merkle = commit_rs_code(code.to_vec());
        let root = merkle.root();
        // add to `commitments`.
        commitments.push(merkle);
        // Use the `root()` to update the transcript
        transcript.append_message(b"merkle_root", root.as_slice());
        Self {
            commitments,
            last_element: None,
        }
    }

    #[allow(clippy::needless_range_loop)]
    // FIX use `gen_pows`, and add which step of the fold it is (call it `k` maybe)
    pub fn fold_step(&mut self, gen_pows: &[F], k: usize, transcript: &mut Transcript) {
        let last_data = self.commitments.last().unwrap().data.clone();
        let n = last_data.len() * 2;
        let blowup = 1 << LOG_BLOWUP;
        if n <= blowup {
            return;
        }
        let random_bytes = transcript.random();
        let r = F::from_digest(&random_bytes);
        let half_n = n >> 1;
        let mut next_data = Vec::with_capacity(half_n);
        let half = F::from(1) / F::from(2); // FIX move (F::from(1) / F::from(2)) outside the loop!

        for i in 0..half_n {
            // p(gen^i)
            let a = last_data[i].value;
            // p(-gen^i)
            let b = last_data[i].minus_value;
            // even(x^2) = (p(x) + p(-x))/2, where x = gen^i

            let even = (a + b) * half;
            // odd(x^2) = (p(x) - p(-x))/2x, where x = gen^i
            // FIX gen_pow is gen_pows[i * (1 << k)]
            // FIX the inverse of gen_pow is also a power!!
            // FIX thus it is in fact `gen_pows[len - i * (1 << k)]` where len=gen_pows.len()
            let gen_pow_index = i * (1 << k);
            println!(
                "gen_pow_index: {}, gen_pows.len(): {}",
                gen_pow_index,
                gen_pows.len()
            );
            let odd = (a - b) / (F::from(2) * gen_pows[gen_pows.len() - gen_pow_index]);

            // p(x) + p(-x) == 2*even(x^2)
            // FIX instead of multiplying both even and odd by `half` you can
            // FIX multiply the sum `even + r * odd` by half
            next_data.push((even + r * odd) * half);
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
        let merkle = commit_rs_code(next_data);
        let root = merkle.root();
        self.commitments.push(merkle);

        // Use the `root()` to update the transcript
        transcript.append_message(b"merkle_root", root.as_slice());
    }

    // FIX take `gen_pows`
    pub fn fold(gen: F, code: Vec<F>, transcript: &mut Transcript) -> Self {
        let mut prover_data = Self::init(&code, transcript);
        let mut k = 0;
        let gen_pows: Vec<F> = (0..code.len()).map(|i| gen.pow([i as u64])).collect();

        while prover_data.last_element.is_none() {
            // pass `k`, the power of the generator
            prover_data.fold_step(&gen_pows, k, transcript);
            k += 1;
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
        assert!(index < n);

        let mut paths = Vec::new();
        let mut current_index = index;
        let mut current_n = n;

        for merkle in &self.commitments {
            // Open only once, as it opens both elements
            let path = merkle.open(current_index).expect("Index out of bounds");

            // Only push the path
            paths.push(path);

            current_n /= 2;
            current_index %= current_n;
        }

        QueryProof { paths }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryProof<F> {
    // merkle paths for all fold layers
    pub paths: Vec<MerkleInclusionPath<ReedSolomonPair<F>>>,
}

impl<F: HashableField + NttField> QueryProof<F> {
    pub fn verify(
        &self,
        domain_size: usize,
        gen: F,
        commitments: &[HashDigest],
        last_element: F,
        random_elements: &[F],
        transcript: &mut Transcript,
    ) -> Result<(), FriProofError> {
        if self.paths.len() != commitments.len() {
            return Err(FriProofError::WrongNumberOfPaths);
        }

        let n = domain_size / 2;
        let random_u64 = u64::from_le_bytes(transcript.random()[..8].try_into().unwrap());
        // the index is half of the domain size because the merkle tree takes pairs of elements
        let random_index = random_u64 as usize % n;
        transcript.append_message(b"query_index", &random_index.to_le_bytes());

        let mut current_n = n;
        let mut current_index = random_index;
        let mut current_gen = gen;
        for i in 0..self.paths.len() {
            let path = &self.paths[i];
            let commitment = &commitments[i];
            if let Err(err) = path.verify(commitment, current_index) {
                return Err(FriProofError::InclusionPathError(err));
            }

            let value = path.value.value; // p(g^i)
            let minus_value = path.value.minus_value; // p(-g^i)
            let current_gen_pow = current_gen.pow([current_index as u64]); // g^i
            let even = (value + minus_value) / F::from(2);
            let odd = (value - minus_value) / (F::from(2) * current_gen_pow);

            if i == self.paths.len() - 1 {
                if last_element != even + random_elements[i] * odd {
                    return Err(FriProofError::QueryMismatch(i));
                }
                break;
            }
            let next_index = current_index % (current_n / 2);
            let next_path = &self.paths[i + 1];
            let next_value = if next_index == current_index {
                next_path.value.value
            } else {
                next_path.value.minus_value
            }; // p(g^(2i))
            if next_value != even + random_elements[i] * odd {
                return Err(FriProofError::QueryMismatch(i));
            }

            current_gen *= current_gen;
            current_n /= 2;
            current_index = next_index;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriProof<F: HashableField + NttField> {
    // there are N commitments, where N is the log2 of the message size (the polynomial)
    pub commitments: Vec<HashDigest>,
    // there are `NUM_QUERIES` number of query proofs
    pub queries: Vec<QueryProof<F>>,
    // this is the last message, a single element
    pub last_elem: F,
    // last random element, mostly for debugging purposes
    pub last_random: [u8; 32],
}

#[derive(Debug)]
pub enum FriProofError {
    QueryMismatch(usize),
    WrongNumberOfQueries,
    WrongNumberOfPaths,
    InclusionPathError(MerkleInclusionPathError),
    IncompatibleLastRandom,
}

impl<F: HashableField + NttField> FriProof<F> {
    pub fn prove(code: Vec<F>, transcript: &mut Transcript) -> FriProof<F> {
        // get the generator for length = blowup * message.len
        let domain_size = code.len();
        let log_size = domain_size.trailing_zeros();
        let gen = F::pow_2_generator(log_size as u64).unwrap();

        // call `fold`
        let prover_data = ProverData::fold(gen, code, transcript);
        // for `0..NUM_QUERIES` generate random index between `0..domain_size/2`
        let mut queries = Vec::with_capacity(NUM_QUERIES);
        for _ in 0..NUM_QUERIES {
            let random_u64 = u64::from_le_bytes(transcript.random()[..8].try_into().unwrap());
            // the index is half of the domain size because the merkle tree takes pairs of elements
            let random_index = random_u64 as usize % (domain_size / 2);
            // open query at this index and add the proof to a vector of query proofs
            let query_proof = prover_data.open_query_at(random_index);
            queries.push(query_proof);
            // use the `index` to update the transcript
            transcript.append_message(b"query_index", &random_index.to_le_bytes());
        }
        // at the end create the FriProof using the queries, last_elem and the
        FriProof {
            commitments: prover_data.fold_roots(),
            queries,
            last_elem: prover_data.last_element.unwrap(),
            last_random: transcript.random(),
        }
    }

    pub fn verify(&self) -> Result<(), FriProofError> {
        // `verify` has to simulate two stages, namely the "fold" stage and the "query" stage.  The
        // "fold" stage will basically just produce a bunch of random values to pass to the query
        // verifier The "query" stage will call the query verifier for all queries of the proof Also
        // verify that the number of queries is equal to `NUM_QUERIES`
        if self.queries.len() != NUM_QUERIES {
            return Err(FriProofError::WrongNumberOfQueries);
        }

        // Create a transcript for verification
        let mut transcript = Transcript::new();
        let mut random_elements = Vec::new();
        // Simulate the "fold" stage
        for root in self.commitments.iter() {
            transcript.append_message(b"merkle_root", root.as_slice());
            let random_bytes = transcript.random();
            let random_element = F::from_digest(&random_bytes);
            random_elements.push(random_element);
        }
        // Last fold step
        transcript.append_message(b"last_element", self.last_elem.as_ref());

        let log_domain_size = self.commitments.len() + LOG_BLOWUP;
        let domain_size = 1 << log_domain_size;
        let gen = F::pow_2_generator(log_domain_size as u64).unwrap();
        // Simulate the "query" stage
        for query in &self.queries {
            query.verify(
                domain_size,
                gen,
                &self.commitments,
                self.last_elem,
                &random_elements,
                &mut transcript,
            )?;
        }

        if self.last_random != transcript.random() {
            return Err(FriProofError::IncompatibleLastRandom);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::field::Field128;
    use bincode; // Ensure bincode is imported

    // create a test for prove and verify!

    // create a test for creating the proof for a big RS code (1 million field
    // elements, or 16mb), serializes it and prints the size of the proof to
    // serialize please use `Serde` and `Bincode`. You'll have to add derive
    // instances for Serde in the proof datatype

    // FIX
    #[test]
    fn prove_and_verify_test() {
        let log_n = 10;
        let values: Vec<Field128> = (0..1 << log_n)
            .map(|i| Field128::from(i as i64 * 7 + 3))
            .collect();

        // Calculate gen_pows
        let gen = Field128::pow_2_generator(log_n as u64).unwrap();
        let gen_pows: Vec<Field128> = (0..values.len()).map(|i| gen.pow([i as u64])).collect();

        let code = reed_solomon(values, &gen_pows);
        let mut transcript = Transcript::new();
        let proof = FriProof::prove(code, &mut transcript);
        proof.verify().unwrap();
    }

    #[test]
    fn big_rs_code_proof_test() {
        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();

        // Create a large RS code with 2 million elements
        let values: Vec<Field128> = (0..1 << 20).map(|i| Field128::from(i as i64)).collect();

        // Calculate gen_pows
        let gen = Field128::pow_2_generator(20).unwrap();
        let gen_pows: Vec<Field128> = (0..values.len()).map(|i| gen.pow([i as u64])).collect();

        let code = reed_solomon(values, &gen_pows);
        let mut transcript = Transcript::new();
        let now = Instant::now();
        let proof = FriProof::prove(code, &mut transcript);
        println!("Proof time: {:?}", now.elapsed());

        // Serialize the proof using Serde and Bincode
        let serialized_proof =
            bincode::serde::encode_to_vec(&proof, config).expect("Serialization failed");
        println!("Proof size: {} bytes", serialized_proof.len());

        // Deserialize the proof
        let _: (FriProof<Field128>, usize) =
            bincode::serde::decode_from_slice(&serialized_proof, config)
                .expect("Deserialization failed");
    }
}
