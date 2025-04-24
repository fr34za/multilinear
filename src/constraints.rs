use crate::field::Field;

#[derive(Clone, Debug)]
pub struct Expr<F>(pub fn(&[F], &[F]) -> F);

impl<F: Field> Expr<F> {
    pub fn evaluate(&self, values: &[F], randoms: &[F]) -> F {
        self.0(values, randoms)
    }
}

#[derive(Clone, Debug)]
pub struct ConstraintSet<F> {
    // Constraints are of the form `expr = 0`
    constraints: Box<[Expr<F>]>,
    degree: usize,
}

impl<F> ConstraintSet<F> {
    pub fn new(constraints: Box<[Expr<F>]>, degree: usize) -> Self {
        Self {
            constraints,
            degree,
        }
    }

    pub fn constraints(&self) -> &[Expr<F>] {
        &self.constraints
    }

    pub fn degree(&self) -> usize {
        self.degree
    }
}
