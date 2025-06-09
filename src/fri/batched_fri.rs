use crate::{
    merkle_tree::{HashDigest, Merkle, MerkleInclusionPath},
    ntt::NttField,
    transcript::{HashableField, Transcript},
};

use super::{FriProofError, FriProverData, QueryProof, ReedSolomonPair};

pub struct BatchedFriProverData<F> {
    // batched commit
    pub batch_layer: Merkle<Vec<ReedSolomonPair<F>>>,
    pub fingerprint_r: F,
    pub fri_data: FriProverData<F>,
}

pub struct BatchedQueryProof<F> {
    pub batch_layer: MerkleInclusionPath<Vec<ReedSolomonPair<F>>>,
    pub query_proof: QueryProof<F>,
}

pub struct BatchedFriProof<F> {
    pub batch_layer_commitment: HashDigest,
    pub commitments: Vec<HashDigest>,
    pub queries: Vec<BatchedQueryProof<F>>,
    pub last_elem: F,
    pub last_random: [u8; 32],
}

// USEFUL FUNCTION. USE ITERATORS `impl Iterator<Item = F>` INSTEAD OF ARRAY SLICES
fn fingerprint<F: NttField>(r: F, coeffs: &[F]) -> F {
    // Compute a fingerprint of the coefficients using Horner's method:
    // result = coeffs[0] + r*coeffs[1] + r^2*coeffs[2] + ... + r^(n-1)*coeffs[n-1]
    let mut result = F::from(0);
    for coeff in coeffs {
        result = result * r + *coeff;
    }
    result
}

impl<F: HashableField + NttField> BatchedFriProverData<F> {
    pub fn init(codes: &[Vec<F>], transcript: &mut Transcript) -> Self {
        // similar to normal fri, you verify that all codes are powers of 2 (check that they have the same size too!)
        // create one merkle tree per code and add them to the batch_layer.
        // create an empty fri data
        // absorb all merkle trees
        // create the fingerprint random number
        // absorb the fingerprint random number

        // Verify that all codes are powers of 2 and have the same size
        assert!(!codes.is_empty(), "Codes must not be empty");
        let code_size = codes[0].len();
        assert!(
            code_size.is_power_of_two(),
            "Code size must be a power of two"
        );

        for code in codes {
            assert_eq!(code.len(), code_size, "All codes must have the same size");
        }

        // Create RS pairs for each code
        let batch_data: Vec<Vec<ReedSolomonPair<F>>> = codes
            .iter()
            .map(|code| {
                let n = code.len();
                let half_n = n / 2;
                (0..half_n)
                    .map(|i| ReedSolomonPair {
                        value: code[i],
                        minus_value: code[i + half_n],
                    })
                    .collect()
            })
            .collect();

        // Create a batched Merkle tree
        let batch_layer = Merkle::batch_commit(batch_data);

        // Absorb the root of the batch layer into the transcript
        transcript.absorb(batch_layer.root().as_slice());

        // Create the fingerprint random number
        let fingerprint_r = transcript.next_challenge();

        // Absorb the fingerprint random number
        transcript.absorb(fingerprint_r.as_ref());

        // Create an empty FRI data (will be populated in fold_step)
        let fri_data = FriProverData {
            merkle_trees: Vec::new(),
            last_element: None,
        };

        Self {
            batch_layer,
            fingerprint_r,
            fri_data,
        }
    }

    pub fn batched_fold_step(&mut self, gen_pows: &[F], r: F, transcript: &mut Transcript) {
        // similar to normal fold step, but instead of last_data you will get the data of all trees from the batch layer
        // and whenever you would take last_data[i] instead you take the fingerprint of all data[j][i] for all j
        // next_data will go into the normal fri data

        let batch_data = &self.batch_layer.data;
        if batch_data.is_empty() {
            return;
        }

        let n = batch_data[0].len() * 2; // Each RS pair represents 2 elements
        let blowup = 1 << super::LOG_BLOWUP;
        if n <= blowup {
            return;
        }

        let half_n = n >> 1;
        let mut next_data = Vec::with_capacity(half_n);

        // Move half calculation outside the loop
        let half = F::from(1) / F::from(2);

        // For each position, compute fingerprint across all batches
        for i in 0..half_n {
            // Collect values and minus_values from all batches at position i
            let values: Vec<F> = batch_data.iter().map(|data| data[i].value).collect();
            let minus_values: Vec<F> = batch_data.iter().map(|data| data[i].minus_value).collect();

            // Compute fingerprints
            let a = fingerprint(self.fingerprint_r, &values);
            let b = fingerprint(self.fingerprint_r, &minus_values);

            if i == 0 {
                // The first case is special since gen_pows[0] == 1
                next_data.push(((a + b) + r * (a - b)) * half);
            } else {
                // even(x^2) = (p(x) + p(-x))/2, where x = gen^i
                let even = a + b;

                // Calculate gen_pow_index using gen_pows[len - i * (1 << k)]
                let gen_pow_index = i;
                let gen_pows_len = gen_pows.len();

                // Use gen_pows[len - i] for the inverse
                let odd = (a - b) * (gen_pows[gen_pows_len - gen_pow_index]);

                // Apply half to the sum (even + r * odd) instead of individually
                next_data.push((even + r * odd) * half);
            }
        }

        if half_n == blowup {
            // sanity check: last RS code must be constant
            let first = next_data[0];
            assert!(
                next_data.iter().all(|next| first == *next),
                "not an RS code"
            );
            self.fri_data.last_element = Some(first);
            transcript.absorb(first.as_ref());
            return;
        }

        // Create RS pairs from next_data
        let rs_pairs: Vec<ReedSolomonPair<F>> = (0..half_n / 2)
            .map(|i| ReedSolomonPair {
                value: next_data[i],
                minus_value: next_data[i + half_n / 2],
            })
            .collect();

        // Commit to Merkle tree
        let merkle = Merkle::commit(rs_pairs);
        let root = merkle.root();

        // Add to merkle_trees
        self.fri_data.merkle_trees.push(merkle);

        // Use the root to update the transcript
        transcript.absorb(root.as_slice());
    }

    pub fn fold(gen_pows: &[F], codes: &[Vec<F>], transcript: &mut Transcript) -> Self {
        // similar to normal fold, except that the first step is a batched_fold_step. all other steps are normal

        // Initialize the batched FRI prover data
        let mut prover_data = Self::init(codes, transcript);

        // Get the size of the code (all codes have the same size as verified in init)
        let code_size = codes[0].len();
        let num_steps = code_size.trailing_zeros() as usize - super::LOG_BLOWUP;

        // First step is a batched fold step
        let r = transcript.next_challenge();
        prover_data.batched_fold_step(gen_pows, r, transcript);

        // Remaining steps are normal fold steps
        for k in 1..num_steps {
            let r = transcript.next_challenge();
            if let Some(last_merkle) = prover_data.fri_data.merkle_trees.last() {
                let last_data = last_merkle.data.clone();
                let mut fri_data_clone = prover_data.fri_data.clone();
                fri_data_clone.merkle_trees.pop(); // Remove the last tree to avoid duplication

                // Create a temporary FriProverData to use fold_step
                let mut temp_fri_data = FriProverData {
                    merkle_trees: fri_data_clone.merkle_trees,
                    last_element: None,
                };

                // Manually reconstruct the code from RS pairs
                let mut code = Vec::with_capacity(last_data.len() * 2);
                for pair in &last_data {
                    code.push(pair.value);
                }
                for pair in &last_data {
                    code.push(pair.minus_value);
                }

                // Use the normal fold_step
                temp_fri_data.fold_step(gen_pows, k, r, transcript);

                // Update the original fri_data
                prover_data.fri_data = temp_fri_data;
            }
        }

        assert!(prover_data.fri_data.last_element.is_some());
        prover_data
    }

    pub fn open_query_at(&self, index: usize) -> BatchedQueryProof<F> {
        // Open a query at the given index in both the batch layer and the FRI data

        // Open the batch layer at the index
        let batch_layer = self.batch_layer.open(index).expect("Index out of bounds");

        // Open the query in the FRI data
        let query_proof = self.fri_data.open_query_at(index);

        BatchedQueryProof {
            batch_layer,
            query_proof,
        }
    }
}

impl<F: HashableField + NttField> BatchedFriProof<F> {
    pub fn prove(codes: &[Vec<F>], gen_pows: &[F], transcript: &mut Transcript) -> Self {
        // Similar to normal FRI prove, but using batched operations

        // Get the domain size (all codes have the same size as verified in fold)
        let domain_size = codes[0].len();

        // Call fold to get the batched prover data
        let prover_data = BatchedFriProverData::fold(gen_pows, codes, transcript);

        // Generate queries
        let mut queries = Vec::with_capacity(super::NUM_QUERIES);
        for _ in 0..super::NUM_QUERIES {
            let random_u64 = u64::from_le_bytes(transcript.random()[..8].try_into().unwrap());
            // The index is half of the domain size because the merkle tree takes pairs of elements
            let random_index = random_u64 as usize % (domain_size / 2);

            // Open query at this index
            let query_proof = prover_data.open_query_at(random_index);
            queries.push(query_proof);

            // Use the index to update the transcript
            transcript.absorb(&random_index.to_le_bytes());
        }

        // Create the batched FRI proof
        BatchedFriProof {
            batch_layer_commitment: prover_data.batch_layer.root(),
            commitments: prover_data.fri_data.fold_roots(),
            queries,
            last_elem: prover_data.fri_data.last_element.unwrap(),
            last_random: transcript.random(),
        }
    }
}
