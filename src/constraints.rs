use crate::expr::Expr;

#[derive(Clone, Debug)]
pub struct ConstraintSet<F> {
    // Constraints are of the form `expr = 0`
    constraints: Box<[Expr<F>]>,
    degree: usize,
    min_num_columns: usize,
    min_num_randoms: usize,
}

impl<F> ConstraintSet<F> {
    pub fn new(constraints: Box<[Expr<F>]>) -> Self {
        let info = constraints
            .iter()
            .fold(ExprInfo::empty(), |a, b| a.combine(expr_info(b)));
        Self {
            constraints,
            degree: info.degree,
            min_num_columns: info.min_num_columns,
            min_num_randoms: info.min_num_randoms,
        }
    }

    pub fn constraints(&self) -> &[Expr<F>] {
        &self.constraints
    }

    pub fn degree(&self) -> usize {
        self.degree
    }

    pub fn min_num_columns(&self) -> usize {
        self.min_num_columns
    }

    pub fn min_num_randoms(&self) -> usize {
        self.min_num_randoms
    }
}

#[derive(Clone, Copy)]
struct ExprInfo {
    degree: usize,
    min_num_randoms: usize,
    min_num_columns: usize,
}

impl ExprInfo {
    fn empty() -> Self {
        ExprInfo {
            degree: 0,
            min_num_randoms: 0,
            min_num_columns: 0,
        }
    }

    fn combine(self, b: Self) -> Self {
        let degree = self.degree.max(b.degree);
        let max_random_index = self.min_num_randoms.max(b.min_num_randoms);
        let max_column_index = self.min_num_columns.max(b.min_num_columns);
        ExprInfo {
            degree,
            min_num_randoms: max_random_index,
            min_num_columns: max_column_index,
        }
    }

    fn bump_degree(mut self) -> Self {
        self.degree += 1;
        self
    }
}

fn expr_info<F>(expr: &Expr<F>) -> ExprInfo {
    match expr {
        Expr::Elem(..) => ExprInfo {
            degree: 0,
            min_num_randoms: 0,
            min_num_columns: 0,
        },
        Expr::Var(col) => ExprInfo {
            degree: 1,
            min_num_randoms: 0,
            min_num_columns: *col + 1,
        },
        Expr::Random(random) => ExprInfo {
            degree: 0,
            min_num_randoms: *random + 1,
            min_num_columns: 0,
        },
        Expr::Add(a, b) => expr_info(a).combine(expr_info(b)),
        Expr::Sub(a, b) => expr_info(a).combine(expr_info(b)),
        Expr::Mul(a, b) => expr_info(a).combine(expr_info(b)).bump_degree(),
    }
}
