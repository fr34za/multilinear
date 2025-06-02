use ark_ff::Field as ArkField;

use crate::field::{Field, Field128};

#[derive(Clone, Debug, PartialEq)]
pub struct Polynomial<F> {
    pub coeffs: Vec<F>,
}

pub trait NttField: Field {
    fn modulus() -> u128;

    fn generator() -> Self;

    fn pow_2_generator(log_size: u64) -> Option<Self>;

    // 1, gen, gen^2, gen^3, ..., gen^(2^log_size - 1)
    fn pow_2_generator_powers(log_size: u64) -> Option<Vec<Self>> {
        let gen = Self::pow_2_generator(log_size)?;
        let size = 1 << log_size;
        let mut powers = Vec::with_capacity(size);
        let mut current = Self::from(1);
        for _ in 0..size {
            powers.push(current);
            current = current * gen;
        }
        Some(powers)
    }

    fn pow<S: AsRef<[u64]>>(&self, exp: S) -> Self;
}

impl NttField for Field128 {
    fn modulus() -> u128 {
        340282366920938463463374557953744961537
    }

    fn generator() -> Self {
        Field128::from(3)
    }

    fn pow_2_generator(log_size: u64) -> Option<Self> {
        let modulus_minus_1 = Self::modulus() - 1;
        let max_log_size = modulus_minus_1.trailing_zeros();

        if log_size > max_log_size as u64 {
            return None;
        }

        let size = 1u128 << log_size;
        let exp = modulus_minus_1 / size;

        let exp_low = exp as u64;
        let exp_high = (exp >> 64) as u64;

        Some(Self::generator().pow([exp_low, exp_high]))
    }

    fn pow<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        Field128(self.0.pow(exp))
    }
}

impl<F: NttField> Polynomial<F> {
    pub fn evaluate(&self, x: F) -> F {
        self.coeffs
            .iter()
            .rev()
            .fold(F::from(0), |acc, &coeff| acc * x + coeff)
    }

    pub fn ntt(&self, gen: F) -> LagrangePolynomial<F> {
        let n = self.coeffs.len();
        assert!(
            n.is_power_of_two(),
            "The number of coeffs must be a power of 2"
        );

        let mut values = self.coeffs.clone();

        bit_reverse_permutation(&mut values);

        // unroll the first step
        for i in (0..n).step_by(2) {
            let u = values[i];
            let v = values[i + 1];
            values[i] = u + v;
            values[i + 1] = u - v;
        }
        let mut len = 4;
        while len <= n {
            let wlen = gen.pow([(n / len) as u64]);
            for i in (0..n).step_by(len) {
                let mut w = F::from(1);
                for j in 0..len / 2 {
                    let v = values[i + j + len / 2] * w;
                    w *= wlen;
                    let u = values[i + j];
                    values[i + j] = u + v;
                    values[i + j + len / 2] = u - v;
                }
            }
            len *= 2;
        }

        LagrangePolynomial { gen, evals: values }
    }
}

fn bit_reverse_permutation<F>(values: &mut [F]) {
    let n = values.len();
    let bits = n.trailing_zeros() as usize;

    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS as usize - bits);
        if i < j {
            values.swap(i, j);
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LagrangePolynomial<F> {
    pub gen: F,
    pub evals: Vec<F>,
}

impl<F: NttField> LagrangePolynomial<F> {
    pub fn intt(&self) -> Polynomial<F> {
        let n = self.evals.len();
        assert!(n.is_power_of_two());

        let mut values = self.evals.clone();

        bit_reverse_permutation(&mut values);

        let gen_inv = F::from(1) / self.gen;
        // unroll the first step
        for i in (0..n).step_by(2) {
            let u = values[i];
            let v = values[i + 1];
            values[i] = u + v;
            values[i + 1] = u - v;
        }
        let mut len = 4;
        while len <= n {
            let wlen = gen_inv.pow([(n / len) as u64]);
            for i in (0..n).step_by(len) {
                let mut w = F::from(1);
                for j in 0..len / 2 {
                    let u = values[i + j];
                    let v = values[i + j + len / 2] * w;
                    w *= wlen;
                    values[i + j] = u + v;
                    values[i + j + len / 2] = u - v;
                }
            }
            len *= 2;
        }

        let n_inv = F::from(1) / F::from(n as i64);
        values.iter_mut().for_each(|val| *val *= n_inv);
        Polynomial { coeffs: values }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Field128 as F;
    use std::hint::black_box;

    #[test]
    fn ntt_benchmark_test() {
        let log_n = 24;
        let n = 1 << log_n;
        let coeffs = (0..n).map(F::from).collect();
        let pol = Polynomial::<F> { coeffs };
        let gen = F::pow_2_generator(log_n).unwrap();
        let now = std::time::Instant::now();
        black_box(pol.ntt(gen));
        println!("NTT elapsed {:?}", now.elapsed());
    }

    #[test]
    fn intt_test() {
        let log_n = 18;
        let n = 1 << log_n;
        let coeffs = (0..n).map(|i| F::from(i as i64)).collect();
        let pol = Polynomial::<F> { coeffs };
        let gen = F::pow_2_generator(log_n as u64).unwrap();
        let now = std::time::Instant::now();
        let ntt = pol.ntt(gen);
        println!("NTT elapsed {:?}", now.elapsed());
        let now = std::time::Instant::now();
        let intt = ntt.intt();
        println!("INTT elapsed {:?}", now.elapsed());
        assert_eq!(pol, intt);
    }
}
