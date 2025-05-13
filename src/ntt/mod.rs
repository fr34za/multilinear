use crate::field::Field;

#[derive(Clone, Debug, PartialEq)]
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
            root *= gen; // Move to the next root of unity
        }

        LagrangePolynomial { gen, evals }
    }

    pub fn ntt(&self, gen: F) -> LagrangePolynomial<F> {
        let n = self.coeffs.len();
        if n == 0 {
            return LagrangePolynomial { gen, evals: vec![] };
        }
        assert!(
            n.is_power_of_two(),
            "The number of coeffs must be a power of 2"
        );

        let evals = recursive_ntt(&self.coeffs, gen, 0, 1, n);
        LagrangePolynomial { gen, evals }
    }
}

fn recursive_ntt<F: Field>(coeffs: &[F], omega: F, offset: usize, jump: usize, n: usize) -> Vec<F> {
    if n == 1 {
        return vec![coeffs[offset]];
    }

    let half_n = n / 2;
    let omega_squared = omega * omega;

    let even_evals = recursive_ntt(coeffs, omega_squared, offset, jump * 2, half_n);
    let odd_evals = recursive_ntt(coeffs, omega_squared, offset + jump, jump * 2, half_n);

    let mut omega_pow = F::from(1);
    let mut out = Vec::with_capacity(n);

    for i in 0..n {
        out.push(even_evals[i % half_n] + omega_pow * odd_evals[i % half_n]);
        omega_pow *= omega;
    }
    out
}

#[derive(Clone, Debug, PartialEq)]
pub struct LagrangePolynomial<F> {
    pub gen: F,
    pub evals: Vec<F>,
}

impl<F: Field> LagrangePolynomial<F> {
    pub fn intt(&self) -> Polynomial<F> {
        let n = self.evals.len();
        assert!(n.is_power_of_two());

        let gen_inv = F::from(1) / self.gen;
        let n_inv = F::from(1) / F::from(n as i64);

        let coeffs = recursive_ntt(&self.evals, gen_inv, 0, 1, n);

        let scaled_coeffs = coeffs.into_iter().map(|coeff| coeff * n_inv).collect();

        Polynomial {
            coeffs: scaled_coeffs,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hint::black_box;

    use super::*;
    use crate::field::Field128 as F;
    use ark_ff::Field;
    const MODULUS: u128 = 340282366920938463463374557953744961537;

    fn generator(len: usize) -> F {
        let exp = (MODULUS - 1) / (len as u128);
        let exp_low = exp as u64;
        let exp_high = (exp >> 64) as u64;
        F::from(3).pow([exp_low, exp_high])
    }

    #[test]
    fn ntt_benchmark_test() {
        let log_n = 20;
        let coeffs = (0..1 << log_n).map(F::from).collect();
        let pol = Polynomial::<F> { coeffs };
        let gen = generator(pol.coeffs.len());
        let now = std::time::Instant::now();
        black_box(pol.ntt(gen));
        println!("NTT elapsed {:?}", now.elapsed());
    }

    #[test]
    fn ntt_test() {
        let log_n = 4;
        let coeffs = (0..1 << log_n).map(F::from).collect();
        let pol = Polynomial::<F> { coeffs };
        let gen = generator(pol.coeffs.len());
        let now = std::time::Instant::now();
        let ntt = pol.ntt(gen);
        println!("NTT elapsed {:?}", now.elapsed());
        let now = std::time::Instant::now();
        let ntt_naive = pol.ntt_naive(gen);
        println!("NTT naive elapsed {:?}", now.elapsed());
        assert_eq!(ntt, ntt_naive);
    }

    #[test]
    fn intt_test() {
        let log_n = 4;
        let coeffs = (0..1 << log_n).map(F::from).collect();
        let pol = Polynomial::<F> { coeffs };
        let gen = generator(pol.coeffs.len());
        let now = std::time::Instant::now();
        let ntt = pol.ntt(gen);
        println!("NTT elapsed {:?}", now.elapsed());
        let now = std::time::Instant::now();
        let intt = ntt.intt();
        println!("INTT elapsed {:?}", now.elapsed());
        assert_eq!(pol, intt);
    }
}
