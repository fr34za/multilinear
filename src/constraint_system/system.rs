use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{
    constraints::ConstraintSet,
    evaluation::Mask,
    trace::{Commitment, Trace},
};
use crate::field::Field;

pub struct System<F> {
    constraints: ConstraintSet<F>,
    challenges: ChallengeSet<F>,
    constraint_mask: Box<[F]>,
    layout: WitnessLayout,
    commitment: Commitment<F>,
    trace: Option<Trace<F>>,
}

pub struct WitnessLayout {
    // Total number of columns
    pub columns: usize,
    // Total number of random challenges
    pub randoms: usize,
    // This is the number of initial columns which are used to generate random challenges.
    // These are the columns that you must fill before knowing the value of the random
    // challenges. The other columns will have access to the random values.
    pub pre_random_columns: usize,
    // Which columns will use the sum check protocol. The sum of all sum columns is
    // the main result of the trace
    pub sum_columns: Box<[usize]>,
}

pub struct ChallengeSet<F> {
    row: Box<[F]>,
    trace: Box<[F]>,
    constraint: Box<[F]>,
}

impl<F: Field> System<F> {
    pub fn verifier(
        transcript: &mut Transcript,
        constraints: ConstraintSet<F>,
        layout: WitnessLayout,
        commitment: Commitment<F>,
        log_num_rows: usize,
    ) -> Self {
        Self::new(
            transcript,
            constraints,
            layout,
            commitment,
            log_num_rows,
            None,
        )
    }

    pub fn prover(
        transcript: &mut Transcript,
        constraints: ConstraintSet<F>,
        layout: WitnessLayout,
        trace: Trace<F>,
    ) -> Self {
        let log_num_rows = trace.height().trailing_zeros() as usize;
        let commitment = Commitment::new(&trace);
        Self::new(
            transcript,
            constraints,
            layout,
            commitment,
            log_num_rows,
            Some(trace),
        )
    }

    fn new(
        transcript: &mut Transcript,
        constraints: ConstraintSet<F>,
        layout: WitnessLayout,
        commitment: Commitment<F>,
        log_num_rows: usize,
        trace: Option<Trace<F>>,
    ) -> Self {
        let num_randoms = layout.randoms;
        let log_num_constraints = constraints
            .constraints()
            .len()
            .next_power_of_two()
            .trailing_zeros() as usize;
        let challenges =
            ChallengeSet::new(transcript, num_randoms, log_num_constraints, log_num_rows);
        let constraint_challenges = &challenges.constraint;
        let n_vars = constraint_challenges.len();
        let n_constraints = constraints.constraints().len();
        let constraint_mask = (0..n_constraints)
            .map(|index| (Mask { index, n_vars }).evaluate(constraint_challenges))
            .collect();
        Self {
            constraints,
            challenges,
            constraint_mask,
            layout,
            commitment,
            trace,
        }
    }

    pub fn num_columns(&self) -> usize {
        self.layout.columns
    }

    pub fn constraints(&self) -> &ConstraintSet<F> {
        &self.constraints
    }

    pub fn constraint_mask(&self) -> &[F] {
        &self.constraint_mask
    }

    pub fn challenges(&self) -> &ChallengeSet<F> {
        &self.challenges
    }

    pub fn commitment(&self) -> &Commitment<F> {
        &self.commitment
    }

    pub fn trace(&self) -> Option<&Trace<F>> {
        self.trace.as_ref()
    }
}

impl<F: Field> ChallengeSet<F> {
    pub fn new(
        transcript: &mut Transcript,
        num_randoms: usize,
        log_num_constraints: usize,
        log_num_rows: usize,
    ) -> Self {
        let row = vec![transcript.next_challenge(); log_num_rows].into();
        let trace = vec![transcript.next_challenge(); num_randoms].into();
        let constraint = vec![transcript.next_challenge(); log_num_constraints].into();
        Self {
            row,
            trace,
            constraint,
        }
    }

    pub fn row(&self) -> &[F] {
        &self.row
    }

    pub fn trace(&self) -> &[F] {
        &self.trace
    }

    pub fn constraint(&self) -> &[F] {
        &self.constraint
    }
}

#[derive(Clone)]
pub struct Transcript {
    inner: ChaCha8Rng,
}

#[allow(clippy::new_without_default)]
impl Transcript {
    pub fn new() -> Self {
        let inner = ChaCha8Rng::seed_from_u64(1);
        Transcript { inner }
    }

    pub fn next_challenge<F: Field>(&mut self) -> F {
        F::from(self.inner.random::<i64>())
    }

    pub fn absorb(&mut self, _values: &[u8]) {}
}
