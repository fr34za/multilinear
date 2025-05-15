use crate::field::Field;
use crate::merkle_tree::Merkle;

use sha2::{Sha256, Digest}; 

pub struct Transcript {
    state: Sha256, 
}

impl Transcript {
 
    pub fn new() -> Self {
        Self {
            state: Sha256::new(),
        }
    }

   
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.state.update(label);   
        self.state.update(message); 
    }

    
    pub fn random(&self) -> [u8; 32] {
        let cloned_state = self.state.clone(); 
        let result = cloned_state.finalize();  
        let mut random_bytes = [0u8; 32];
        random_bytes.copy_from_slice(&result[..32]); 
        random_bytes
    }
}


pub trait HashableField: AsRef<[u8]> {
    fn to_bytes(&self) -> &[u8]; 
    fn from_digest(digest: &[u8; 32]) -> Self; 
}

pub struct ProverData<F: Clone> {
    pub commitments: Vec<Merkle<F>>,
    pub polynomials: Vec<Vec<F>>,
}

pub fn reed_solomon<F: Field>(coeffs: Vec<F>, gen: F) -> Vec<F> {
    // first, duplicate the size of `coeffs` by adding zeros (blowup 2).
    let mut extended_coeffs = coeffs.clone();
    let n = extended_coeffs.len();
    extended_coeffs.resize(2 * n, F::zero());
    // use `ntt` to compute the Reed-Solomon encoding.
    F::ntt(&mut extended_coeffs, gen);
    
    extended_coeffs
}

impl<F: HashableField + Clone> ProverData<F> {
    pub fn new(values: Vec<F>, gen: F, transcript: &mut Transcript) -> Self {
        // `values` must be power of two.
        assert!(values.len().is_power_of_two(), "Input size must be a power of two");
        // push save a copy of `values` to `polynomials`
        let mut polynomials = Vec::new();
        polynomials.push(values.clone());
        // use `reed_solomon` to compute the values for commitment.
        let rs_encoded = reed_solomon(values, gen);
        // commit to a `Merkle` tree using `to_bytes` method.
        let mut commitments = Vec::new();
        let merkle = Merkle::commit(&rs_encoded.iter().map(|v| v.to_bytes()).collect::<Vec<_>>());
        // add to `commitments`.
        commitments.push(merkle);
        // Use the `root()` to update the transcript
        let root = commitments.last().unwrap().root();
        transcript.append_message(b"merkle_root", root.as_slice());
        Self {
            commitments,
            polynomials,
        }
    }

    pub fn fold_step(&mut self, transcript: &mut Transcript) {
        // generate random field element called `r` from the transcript using `random` and `from_digest`.
        let random_bytes = transcript.random();
        let r = F::from_digest(&random_bytes);
        // Then do the fold step as described by
        // https://aszepieniec.github.io/stark-anatomy/fri.html#split-and-fold
        // watch at 9:25 https://www.youtube.com/watch?v=gd1NbKUOJwA
        // do not worry about queries now!
        // in the last polynomial of the `polynomials` field
        let last_poly = self.polynomials.last().unwrap().clone();
        let n = last_poly.len();
        assert!(n.is_power_of_two(), "Polynomial size must be a power of two");

        let mut next_poly = Vec::with_capacity(n / 2);
        
        for i in 0..(n / 2) {
            let even = last_poly[i * 2];
            let odd = last_poly[i * 2 + 1];

            next_poly.push(even + r * odd);
        }

        self.polynomials.push(next_poly.clone());

        
        // Use `reed_solomon` to compute the values for commitment.
        let rs_encoded = reed_solomon(next_poly, F::gen()); //check gen() method @Gabriel
        
        // `commit` to Merkle, etc
        let merkle = Merkle::commit(&rs_encoded.iter().map(|v| v.to_bytes()).collect::<Vec<_>>());
        self.commitments.push(merkle);
        
        // Use the `root()` to update the transcript
        transcript.append_message(b"merkle_root", self.commitments.last().unwrap().root().as_slice());
    }
}

fn main() {
    let mut transcript = Transcript::new();

    transcript.append_message(b"label1", b"mensagem1");
    transcript.append_message(b"label2", b"mensagem2");

    let random_value = transcript.random();

    println!("Random digest: {:x?}", random_value); 
}
