use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    constraints::ConstraintSet,
    field::Field,
    trace::{Commitment, Trace},
};

pub struct System<F> {
    constraints: ConstraintSet<F>,
    challenges: ChallengeSet<F>,
    log_num_rows: usize,
    commitment: Commitment<F>,
    trace: Option<Trace<F>>,
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
        log_num_rows: usize,
        commitment: Commitment<F>,
    ) -> Self {
        Self::new(transcript, constraints, log_num_rows, commitment, None)
    }

    pub fn prover(
        transcript: &mut Transcript,
        constraints: ConstraintSet<F>,
        trace: Trace<F>,
    ) -> Self {
        let log_num_rows = trace.height().trailing_zeros() as usize;
        let commitment = Commitment::new(&trace);
        Self::new(
            transcript,
            constraints,
            log_num_rows,
            commitment,
            Some(trace),
        )
    }

    fn new(
        transcript: &mut Transcript,
        constraints: ConstraintSet<F>,
        log_num_rows: usize,
        commitment: Commitment<F>,
        trace: Option<Trace<F>>,
    ) -> Self {
        let num_randoms = constraints.num_randoms();
        let log_num_constraints = constraints.log_num_constraints();
        let challenges =
            ChallengeSet::new(transcript, num_randoms, log_num_constraints, log_num_rows);
        Self {
            constraints,
            challenges,
            log_num_rows,
            commitment,
            trace,
        }
    }

    pub fn constraints(&self) -> &ConstraintSet<F> {
        &self.constraints
    }

    pub fn challenges(&self) -> &ChallengeSet<F> {
        &self.challenges
    }

    pub fn log_num_rows(&self) -> usize {
        self.log_num_rows
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
        F::from(self.inner.random::<u64>())
    }

    pub fn absorb(&mut self, _values: &[u8]) {}
}
