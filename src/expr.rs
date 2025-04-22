use std::ops::{Add, Mul, Sub};

#[derive(Clone)]
pub enum Expr<F> {
    Elem(F),
    Var(usize),
    Random(usize),
    Add(Box<Expr<F>>, Box<Expr<F>>),
    Sub(Box<Expr<F>>, Box<Expr<F>>),
    Mul(Box<Expr<F>>, Box<Expr<F>>),
}

impl<F> Expr<F> {
    pub fn var(index: usize) -> Expr<F> {
        Expr::Var(index)
    }
}

impl<F: From<u64>> From<u64> for Expr<F> {
    fn from(elem: u64) -> Self {
        Expr::Elem(F::from(elem))
    }
}

impl<F> Add for Expr<F> {
    type Output = Expr<F>;
    fn add(self, other: Expr<F>) -> Expr<F> {
        Expr::Add(self.into(), other.into())
    }
}

impl<F> Sub for Expr<F> {
    type Output = Expr<F>;
    fn sub(self, other: Expr<F>) -> Expr<F> {
        Expr::Sub(self.into(), other.into())
    }
}

impl<F> Mul for Expr<F> {
    type Output = Expr<F>;
    fn mul(self, other: Expr<F>) -> Expr<F> {
        Expr::Mul(self.into(), other.into())
    }
}
