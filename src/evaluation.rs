use crate::{constraints::ConstrainSet, expr::Expr, field::Field, system::System, trace::Trace};

impl<F: Field> System<F> {
    pub fn evaluate_composition(&self, outputs: &[F]) -> F {
        let randoms = self.challenges().trace();
        let constraints = self.challenges().constraint();
        assert_eq!(outputs.len(), self.constraints().total_columns());
        self.constraints().evaluate(outputs, randoms, constraints)
    }

    pub fn evaluate_delta(&self, inputs: &[F]) -> F {
        let data = self.challenges().row();
        assert_eq!(inputs.len(), data.len());
        let delta = Delta { data };
        delta.evaluate(inputs)
    }
}

impl<F: Field> ConstrainSet<F> {
    fn evaluate(&self, values: &[F], randoms: &[F], constraints: &[F]) -> F {
        let n_vars = constraints.len();
        self.constraints()
            .iter()
            .enumerate()
            .map(|(index, expr): (usize, &Expr<F>)| {
                let mask = Mask { index, n_vars };
                mask.evaluate(constraints) * expr.evaluate(values, randoms)
            })
            .sum()
    }
}

impl<F: Field> Expr<F> {
    fn evaluate(&self, values: &[F], randoms: &[F]) -> F {
        match self {
            Expr::Elem(a) => *a,
            Expr::Var(col) => values[*col],
            Expr::Random(random) => randoms[*random],
            Expr::Add(a, b) => a.evaluate(values, randoms) + b.evaluate(values, randoms),
            Expr::Sub(a, b) => a.evaluate(values, randoms) - b.evaluate(values, randoms),
            Expr::Mul(a, b) => a.evaluate(values, randoms) * b.evaluate(values, randoms),
        }
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
struct Mask {
    index: usize,
    n_vars: usize,
}

impl Mask {
    fn evaluate<F: Field>(&self, points: &[F]) -> F {
        let n_vars = self.n_vars;
        let index = self.index;
        let one = F::from(1u64);
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
struct Delta<'a, F> {
    data: &'a [F],
}

impl<F: Field> Delta<'_, F> {
    fn evaluate(&self, points: &[F]) -> F {
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
