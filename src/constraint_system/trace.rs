use std::marker::PhantomData;

pub struct Trace<F> {
    pub matrix: Box<[F]>,
    height: usize,
    width: usize,
}

impl<F> Trace<F> {
    pub fn new(matrix: Box<[F]>, width: usize) -> Trace<F> {
        assert_eq!(matrix.len() % width, 0);
        let height = matrix.len() / width;
        assert!(height.is_power_of_two());
        Trace {
            matrix,
            height,
            width,
        }
    }

    pub fn matrix(&self) -> &[F] {
        &self.matrix
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn height(&self) -> usize {
        self.height
    }
}

impl<F: Copy> Trace<F> {
    pub fn get(&self, i: usize, j: usize) -> F {
        self.matrix[i * self.width + j]
    }
}

// TODO
pub struct Commitment<F>(pub(crate) PhantomData<F>);

// TODO
impl<F> Commitment<F> {
    pub fn new(_trace: &Trace<F>) -> Commitment<F> {
        Commitment(PhantomData)
    }
}
