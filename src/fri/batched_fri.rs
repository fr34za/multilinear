use crate::{
    merkle_tree::{HashDigest, Merkle, MerkleInclusionPath},
    ntt::NttField,
    transcript::{HashableField, Transcript},
};

use super::{FriProofError, FriProverData, QueryProof, ReedSolomonPair, LOG_BLOWUP, NUM_QUERIES};

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
        let fingerprint_r: F = transcript.next_challenge();

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
        let blowup = 1 << LOG_BLOWUP;
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
        let num_steps = code_size.trailing_zeros() as usize - LOG_BLOWUP;

        // First step is a batched fold step
        let r = transcript.next_challenge();
        prover_data.batched_fold_step(gen_pows, r, transcript);

        // Remaining steps are normal fold steps
        for k in 1..num_steps {
            let r = transcript.next_challenge();
            prover_data.fri_data.fold_step(gen_pows, k, r, transcript);
        }

        assert!(prover_data.fri_data.last_element.is_some());
        prover_data
    }

    pub fn open_query_at(&self, index: usize) -> BatchedQueryProof<F> {
        // Open a query at the given index in both the batch layer and the FRI data

        // Open the batch layer at the index
        let batch_layer = self
            .batch_layer
            .batch_open(index)
            .expect("Index out of bounds");

        // Open the query in the FRI data
        let n = self.batch_layer.data.len() / 2;
        let query_proof = self.fri_data.open_query_at(index % n);

        BatchedQueryProof {
            batch_layer,
            query_proof,
        }
    }
}

impl<F: HashableField + NttField> BatchedQueryProof<F> {
    pub fn verify(
        &self,
        domain_size: usize,
        gen: F,
        commitments: &[HashDigest],
        last_element: F,
        random_elements: &[F],
        fingerprint_r: F,
        transcript: &mut Transcript,
    ) -> Result<(), FriProofError> {
        // similar to verify query proof, but the first layer is batched. use the fingerprint

        // First, verify the batch layer inclusion proof
        self.batch_layer
            .batch_verify(&commitments[0], 0)
            .map_err(|err| FriProofError::InclusionPathError(err))?;

        // Extract values and minus_values from the batch layer
        let values: Vec<F> = self
            .batch_layer
            .value
            .iter()
            .map(|pair| pair.value)
            .collect();
        let minus_values: Vec<F> = self
            .batch_layer
            .value
            .iter()
            .map(|pair| pair.minus_value)
            .collect();

        // Compute fingerprints using the fingerprint_r
        let value = fingerprint(fingerprint_r, &values);
        let minus_value = fingerprint(fingerprint_r, &minus_values);

        // Now verify the FRI query proof using the fingerprinted values
        let mut current_value = value;
        let mut current_minus_value = minus_value;
        let mut current_gen_pow = gen;

        // For each fold step (except the last one)
        for (i, r) in random_elements.iter().enumerate() {
            if i >= commitments.len() - 1 {
                break;
            }

            // Calculate even and odd terms
            let even = (current_value + current_minus_value) * (F::from(1) / F::from(2));
            let odd = (current_value - current_minus_value)
                * (F::from(1) / (F::from(2) * current_gen_pow));

            // Calculate the next value using the random element
            current_value = even + *r * odd;

            // Square the generator power for the next step
            current_gen_pow = current_gen_pow * current_gen_pow;

            // For the next step, we need to verify the FRI query proof
            if i > 0 {
                // Verify the merkle proof for this step
                self.query_proof.paths[i - 1]
                    .verify(&commitments[i], self.query_proof.paths[i - 1].value.value)
                    .map_err(|err| FriProofError::InclusionPathError(err))?;

                // Check that the value matches
                if self.query_proof.paths[i - 1].value.value != current_value {
                    return Err(FriProofError::QueryMismatch(i - 1));
                }

                // Update minus_value for the next step
                current_minus_value = self.query_proof.paths[i - 1].value.minus_value;
            }
        }

        // Verify the last element
        if current_value != last_element {
            return Err(FriProofError::QueryMismatch(commitments.len() - 1));
        }

        Ok(())
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
        let mut queries = Vec::with_capacity(NUM_QUERIES);
        for _ in 0..NUM_QUERIES {
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

    pub fn verify(&self) -> Result<(), FriProofError> {
        // imitate the prover's transcript
        // save all random elements in a vector
        // save the fingerprint r
        // then verify all the queries

        // Create a new transcript to imitate the prover's transcript
        let mut transcript = Transcript::new();

        // Absorb the batch layer commitment
        transcript.absorb(self.batch_layer_commitment.as_slice());

        // Get the fingerprint r
        let fingerprint_r: F = transcript.next_challenge();

        // Absorb the fingerprint r
        transcript.absorb(fingerprint_r.as_ref());

        // Collect random elements for each fold step
        let mut random_elements = Vec::with_capacity(self.commitments.len());

        // Absorb each commitment and get the random element
        for commitment in &self.commitments {
            transcript.absorb(commitment.as_slice());
            let r: F = transcript.next_challenge();
            random_elements.push(r);
        }

        // Absorb the last element
        transcript.absorb(self.last_elem.as_ref());

        // Verify all queries
        self.verify_queries(&mut transcript, &random_elements, fingerprint_r)
    }

    pub fn verify_queries(
        &self,
        transcript: &mut Transcript,
        random_elements: &[F],
        fingerprint_r: F,
    ) -> Result<(), FriProofError> {
        // remember the first layer is batched, so it returns a vector
        // use the fingerprint!

        // Check if the number of queries is correct
        if self.queries.len() != NUM_QUERIES {
            return Err(FriProofError::WrongNumberOfQueries);
        }

        // Calculate the domain size based on the number of commitments and LOG_BLOWUP
        let log_domain_size = self.commitments.len() + LOG_BLOWUP;
        let domain_size = 1 << log_domain_size;

        // Get the generator for the domain
        let gen = F::pow_2_generator(log_domain_size as u64).unwrap();

        // Verify each query
        for query in &self.queries {
            // Get the random index from the transcript
            let random_u64 = u64::from_le_bytes(transcript.random()[..8].try_into().unwrap());
            let random_index = random_u64 as usize % (domain_size / 2);

            // Verify the query at this index
            query.verify(
                domain_size,
                gen,
                &[self.batch_layer_commitment], // First layer is the batch layer
                self.last_elem,
                random_elements,
                fingerprint_r,
                transcript,
            )?;

            // Absorb the index to match the prover's transcript
            transcript.absorb(&random_index.to_le_bytes());
        }

        // Check if the last random value matches
        if self.last_random != transcript.random() {
            return Err(FriProofError::IncompatibleLastRandom);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{benchmark, field::Field128, fri::reed_solomon};

    #[test]
    fn batched_fri_verify_test() {
        // Use a smaller log_n value
        let log_n = 4;

        // Calculate gen_pows for the RS code
        let gen_pows = Field128::pow_2_generator_powers((log_n + LOG_BLOWUP) as u64).unwrap();

        // Create 4 different RS codes
        let mut codes = Vec::new();
        for j in 0..4 {
            let values: Vec<Field128> = (0..1 << log_n)
                .map(|i| Field128::from((i as i64 * 7 + 3) + j * 100))
                .collect();

            // Generate the RS code
            let code = reed_solomon(values, gen_pows[1]);
            codes.push(code);
        }

        // Create a transcript
        let mut transcript = Transcript::new();

        // Generate the batched FRI proof
        let proof = BatchedFriProof::prove(&codes, &gen_pows, &mut transcript);

        // Print some information about the proof
        println!("Batched FRI proof generated with {} codes", codes.len());
        println!(
            "Batch layer commitment: {:x?}",
            proof.batch_layer_commitment
        );
        println!("Number of commitments: {}", proof.commitments.len());
        println!("Number of queries: {}", proof.queries.len());
        println!("Last element: {:?}", proof.last_elem);
    }

    #[test]
    fn batched_fri_benchmark() {
        // Use a smaller log_n value for benchmarking
        let log_n = 6;

        // Calculate gen_pows for the RS code
        let gen_pows = Field128::pow_2_generator_powers((log_n + LOG_BLOWUP) as u64).unwrap();

        // Create 4 different RS codes
        let mut codes = Vec::new();
        for j in 0..4 {
            let values: Vec<Field128> = (0..1 << log_n)
                .map(|i| Field128::from((i as i64 * 7 + 3) + j * 100))
                .collect();

            // Generate the RS code
            let code = benchmark!(
                format!("Reed solomon encoding time for code {}: ", j),
                reed_solomon(values, gen_pows[1])
            );
            codes.push(code);
        }

        // Create a transcript
        let mut transcript = Transcript::new();

        // Generate the batched FRI proof
        let proof = benchmark!(
            "Batched FRI proof time: ",
            BatchedFriProof::prove(&codes, &gen_pows, &mut transcript)
        );

        // Print some information about the proof
        println!(
            "Batched FRI proof size: {} commitments, {} queries",
            proof.commitments.len(),
            proof.queries.len()
        );
    }
}
