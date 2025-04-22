use crate::expr::Expr;

#[derive(Clone, Debug)]
pub struct ConstraintSet<F> {
    // Constraints are of the form `expr = 0`
    constraints: Box<[Expr<F>]>,
    // Logarithm of the number of constraints. This sets the size
    // of the constraint multi-index
    log_num_constraints: usize,
    // Maximum degree of the constraints
    degree: usize,
    // How many different random values the constraint set uses
    num_randoms: usize,
    // Total number of columns, i.e. different variables
    total_columns: usize,
    // This is the number of initial columns which are used to generate random challenges.
    // These are the columns that you must fill before knowing the value of the random
    // challenges. The other columns will have access to the random values.
    pre_random_columns: usize,
    // Which columns will use the sum check protocol. The sum of all sum columns is
    // the main result of the trace
    sum_columns: Box<[usize]>,
}

impl<F> ConstraintSet<F> {
    pub fn new(
        constraints: Box<[Expr<F>]>,
        total_columns: usize,
        sum_columns: Box<[usize]>,
        pre_random_columns: usize,
    ) -> Self {
        let log_num_constraints = constraints.len().next_power_of_two().trailing_zeros() as usize;
        let degree = 0;
        let num_randoms = 0;
        let max_column_index = sum_columns
            .iter()
            .copied()
            .max()
            .unwrap_or(pre_random_columns);
        let info = constraints.iter().fold(
            ExprInfo {
                degree,
                max_random_index: num_randoms,
                max_column_index,
            },
            |a, b| a.combine(expr_info(b)),
        );
        assert!(max_column_index < total_columns);
        Self {
            constraints,
            log_num_constraints,
            degree: info.degree,
            num_randoms: info.max_random_index + 1,
            total_columns,
            pre_random_columns,
            sum_columns,
        }
    }

    pub fn constraints(&self) -> &[Expr<F>] {
        &self.constraints
    }

    pub fn log_num_constraints(&self) -> usize {
        self.log_num_constraints
    }

    pub fn degree(&self) -> usize {
        self.degree
    }

    pub fn num_randoms(&self) -> usize {
        self.num_randoms
    }

    pub fn total_columns(&self) -> usize {
        self.total_columns
    }

    pub fn pre_random_columns(&self) -> usize {
        self.pre_random_columns
    }

    pub fn sum_columns(&self) -> &[usize] {
        &self.sum_columns
    }
}

#[derive(Clone, Copy)]
struct ExprInfo {
    degree: usize,
    max_random_index: usize,
    max_column_index: usize,
}

impl ExprInfo {
    fn combine(self, b: Self) -> Self {
        let degree = self.degree.max(b.degree);
        let max_random_index = self.max_random_index.max(b.max_random_index);
        let max_column_index = self.max_column_index.max(b.max_column_index);
        ExprInfo {
            degree,
            max_random_index,
            max_column_index,
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
            max_random_index: 0,
            max_column_index: 0,
        },
        Expr::Var(col) => ExprInfo {
            degree: 1,
            max_random_index: 0,
            max_column_index: *col,
        },
        Expr::Random(random) => ExprInfo {
            degree: 0,
            max_random_index: *random,
            max_column_index: 0,
        },
        Expr::Add(a, b) => expr_info(a).combine(expr_info(b)),
        Expr::Sub(a, b) => expr_info(a).combine(expr_info(b)),
        Expr::Mul(a, b) => expr_info(a).combine(expr_info(b)).bump_degree(),
    }
}
