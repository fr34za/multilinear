use std::marker::PhantomData;

pub struct Trace<F> {
    matrix: Box<[F]>,
    height: usize,
    width: usize,
}

impl<F> Trace<F> {
    pub fn new(values: Vec<F>, width: usize) -> Trace<F> {
        assert_eq!(values.len() % width, 0);
        let height = values.len() / width;
        assert!(height.is_power_of_two());
        let matrix = values.into();
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

// TODO
pub struct Commitment<F>(PhantomData<F>);

// TODO
impl<F> Commitment<F> {
    pub fn new(_trace: &Trace<F>) -> Commitment<F> {
        Commitment(PhantomData)
    }
}
