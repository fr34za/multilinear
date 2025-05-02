use crate::field::Field;

#[derive (Clone, Debug, PartialEq)]
pub struct Polynomial<F> {
    pub coeffs: Vec<F>,
}

impl<F: Field> Polynomial<F> {
    pub fn evaluate(&self, x: F) -> F {
        self.coeffs
            .iter()
            .rev()
            .fold(F::from(0), |acc, &coeff| acc * x + coeff)
    }

    pub fn ntt(&self, gen: F) -> LagrangePolynomial<F> {
        assert!(self.coeffs.len().is_power_of_two());
        let evals = [].to_vec(); // FIXME
        LagrangePolynomial {
            gen,
            evals,
        }
    }
}

#[derive (Clone, Debug, PartialEq)]
pub struct LagrangePolynomial<F> {
    gen: F,
    evals: Vec<F>,
}

impl<F: Field> LagrangePolynomial<F> {
    pub fn intt(&self) -> Polynomial<F> {
        todo!()
    }
}

#[test]
fn ntt_test() {
    let coeffs = [1, 3, 4, 2, 8, 7, 6, 1].into();
    let pol = Polynomial::<i64> { coeffs };
    let gen = 3;
    let lagrange = pol.ntt(gen);
    assert_eq!(pol, lagrange.intt());
}
