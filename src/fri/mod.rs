use crate::field::Field;
use crate::merkle_tree::{HashDigest, Merkle};

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
        let cloned_state = self.state.clone(); // Clona o estado atual
        let result = cloned_state.finalize();  // Finaliza o estado para obter o hash
        let mut random_bytes = [0u8; 32];
        random_bytes.copy_from_slice(&result[..32]); // Copia os primeiros 32 bytes do hash
        random_bytes
    }
}


pub trait HashableField {
    fn to_bytes(&self) -> &[u8]; 
    fn from_digest(digest: &[u8; 32]) -> Self; 
}


fn main() {
    // Inicializando um novo transcript
    let mut transcript = Transcript::new();

    // Adicionando mensagens ao transcript
    transcript.append_message(b"label1", b"mensagem1");
    transcript.append_message(b"label2", b"mensagem2");

    // Gerando um valor pseudoaleatório baseado no estado atual
    let random_value = transcript.random();

    println!("Random digest: {:x?}", random_value); // Mostra o digest gerado
}