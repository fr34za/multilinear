use super::{constraints::ConstraintSet, system::System, trace::Trace};
use crate::field::Field;

impl<F: Field> System<F> {
    pub fn evaluate_composition(&self, outputs: &[F]) -> F {
        let randoms = self.challenges().trace();
        let constraint_mask = self.constraint_mask();
        assert_eq!(outputs.len(), self.num_columns());
        self.constraints()
            .evaluate(outputs, randoms, constraint_mask)
    }

    pub fn evaluate_delta(&self, inputs: &[F]) -> F {
        let data = self.challenges().row();
        assert_eq!(inputs.len(), data.len());
        let delta = Delta { data };
        delta.evaluate(inputs)
    }
}

impl<F: Field> ConstraintSet<F> {
    fn evaluate(&self, values: &[F], randoms: &[F], constraint_mask: &[F]) -> F {
        self.constraints()
            .iter()
            .zip(constraint_mask)
            .map(|(expr, &mask)| mask * expr.evaluate(values, randoms))
            .sum()
    }
}

impl<F: Field> Trace<F> {
    pub fn evaluate(&self, points: &[F]) -> Box<[F]> {
        let n_vars = self.height().trailing_zeros() as usize;
        assert_eq!(points.len(), n_vars);
        let mut res = vec![F::from(0); self.width()];
        self.matrix()
            .chunks(self.width())
            .enumerate()
            .for_each(|(index, row)| {
                let mask = Mask { n_vars, index };
                let coeff = mask.evaluate(points);
                row.iter().enumerate().for_each(|(j, &val)| {
                    res[j] += coeff * val;
                });
            });
        res.into()
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Mask {
    pub(crate) index: usize,
    pub(crate) n_vars: usize,
}

impl Mask {
    pub(crate) fn evaluate<F: Field>(&self, points: &[F]) -> F {
        let n_vars = self.n_vars;
        let index = self.index;
        let one = F::from(1i64);
        let select = |i| {
            // Note: the points are read from last to first, since WHIR
            // is big endian and we want to follow the same convention
            let point = points[n_vars - 1 - i];
            if (index >> i) & 1 == 1 {
                point
            } else {
                one - point
            }
        };
        (0..n_vars).map(select).product()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Delta<'a, F> {
    pub data: &'a [F],
}

impl<F: Field> Delta<'_, F> {
    pub fn evaluate(&self, points: &[F]) -> F {
        let data = &self.data;
        let one = F::from(1);
        let pass = |i| {
            let a = data[i];
            let b = points[i];
            a * b + (one - a) * (one - b)
        };
        (0..points.len()).map(pass).product()
    }
}
