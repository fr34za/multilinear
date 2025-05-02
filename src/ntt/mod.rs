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

    pub fn ntt_naive(&self, gen: F) -> LagrangePolynomial<F> {
        assert!(self.coeffs.len().is_power_of_two());
        let n = self.coeffs.len();
        let mut evals = Vec::with_capacity(n);
        let mut root = F::from(1); // Start with the first root of unity (gen^0)
    
        for _ in 0..n {
            evals.push(self.evaluate(root));
            root = root * gen; // Move to the next root of unity
        }
    
        LagrangePolynomial {
            gen,
            evals,
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
