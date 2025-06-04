use crate::{
    constraint_system::{
        constraints::{ConstraintSet, Expr},
        sumcheck::{SumcheckPolynomial, SumcheckTables},
        system::{System, WitnessLayout},
        trace::Trace,
    },
    fri::LOG_BLOWUP,
    ntt::NttField,
    polynomials::MultilinearPolynomialEvals,
    transcript::{HashableField, Transcript},
};

use super::{FriProof, FriProverData, NUM_QUERIES};

pub struct PCSProverData<F> {
    // FRI data
    pub fri_data: FriProverData<F>,
    // Sumcheck data
    pub sumcheck_tables: SumcheckTables<F>,
    pub sumcheck_polynomials: Vec<SumcheckPolynomial<F>>,
}

impl<F: HashableField + NttField> PCSProverData<F> {
    pub fn init(
        inputs: &[F],
        poly: &MultilinearPolynomialEvals<F>,
        code: &[F],
        transcript: &mut Transcript,
    ) -> Self {
        // call `FriProverData::init`
        let fri_data = FriProverData::init(code, transcript);
        let sumcheck_tables = SumcheckTables::build_tables_for_pcs(inputs, poly);

        // sumcheck_polynomials start empty
        let sumcheck_polynomials = Vec::new();

        Self {
            fri_data,
            sumcheck_tables,
            sumcheck_polynomials,
        }
    }

    pub fn fold(
        inputs: &[F],
        output: F,
        poly: &MultilinearPolynomialEvals<F>,
        gen_pows: &[F],
        code: &[F],
        transcript: &mut Transcript,
    ) -> Self {
        let mut prover_data = Self::init(inputs, poly, code, transcript);
        let num_steps = code.len().trailing_zeros() as usize - LOG_BLOWUP;

        let mut previous_sum = output;
        // Define the composition function
        let composition = &|x: &[F]| x[0];
        let total_degree = 1;

        for k in 0..num_steps {
            // Compute the sumcheck polynomial
            // This returns a tuple (SumcheckPolynomial, F)
            let (sumcheck_poly, r) = prover_data.sumcheck_tables.compute_sumcheck_polynomial(
                composition,
                total_degree,
                &mut previous_sum,
                transcript,
            );

            // Add the sumcheck polynomial to the vector
            prover_data.sumcheck_polynomials.push(sumcheck_poly);

            // Run fold_step from fri
            prover_data.fri_data.fold_step(gen_pows, k, r, transcript);
        }

        assert!(prover_data.fri_data.last_element.is_some());
        prover_data
    }
}

pub struct PCSProof<F> {
    // FRI proof
    pub fri_proof: FriProof<F>,
    // Sumcheck proof
    pub sumcheck_polynomials: Vec<SumcheckPolynomial<F>>,
    // PCS claim
    pub inputs: Vec<F>,
    pub output: F,
}

impl<F: HashableField + NttField> PCSProof<F> {
    pub fn prove(
        inputs: Vec<F>,
        output: F,
        poly: MultilinearPolynomialEvals<F>,
        transcript: &mut Transcript,
    ) -> Self {
        // First, convert the polynomial to canonical form
        let coeffs = poly.to_coefficient();

        // Compute gen_pows for the RS code
        let log_domain_size = coeffs.coeffs.len().trailing_zeros() as u64 + LOG_BLOWUP as u64;
        let gen_pows = F::pow_2_generator_powers(log_domain_size).unwrap();
        let gen = gen_pows[1];

        // Then compute the RS code of the canonical coefficients
        let code = super::reed_solomon(coeffs.coeffs, gen);

        // Run the PCS fold, using the polynomial, code, gen_pows
        let prover_data = PCSProverData::fold(&inputs, output, &poly, &gen_pows, &code, transcript);

        // Do the queries, similar to FRI
        let domain_size = 1 << log_domain_size;
        let mut queries = Vec::with_capacity(NUM_QUERIES);
        for _ in 0..NUM_QUERIES {
            let random_u64 = u64::from_le_bytes(transcript.random()[..8].try_into().unwrap());
            let random_index = random_u64 as usize % (domain_size / 2);
            let query_proof = prover_data.fri_data.open_query_at(random_index);
            queries.push(query_proof);
            transcript.absorb(&random_index.to_le_bytes());
        }

        // Construct the PCSProof
        let fri_proof = FriProof {
            commitments: prover_data.fri_data.fold_roots(),
            queries,
            last_elem: prover_data.fri_data.last_element.unwrap(),
            last_random: transcript.random(),
        };
        PCSProof {
            fri_proof,
            sumcheck_polynomials: prover_data.sumcheck_polynomials,
            inputs,
            output,
        }
    }

    pub fn verify(&self, transcript: &mut Transcript) -> Result<(), super::FriProofError> {
        // // First, verify all sumcheck polynomials
        // let mut previous_sum = self.output;

        // for poly in &self.sumcheck_polynomials {
        //     // Convert the sumcheck polynomial to a regular polynomial
        //     let polynomial = poly.to_polynomial(previous_sum);

        //     // Get the next challenge from the transcript
        //     let r = transcript.next_challenge();

        //     // Update the previous sum for the next iteration
        //     previous_sum = polynomial.evaluate(r);
        // }

        // // Finally, verify the FRI proof
        // self.fri_proof.verify()
        todo!()
    }
}
