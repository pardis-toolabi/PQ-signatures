use rand::RngCore;
use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;
pub const MESSAGE_BITS: usize = HASH_LEN * 8;

fn hash(data: &[u8]) -> [u8; HASH_LEN] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

fn random_block() -> [u8; HASH_LEN] {
    let mut block = [0u8; HASH_LEN];
    rand::thread_rng().fill_bytes(&mut block);
    block
}

fn message_bits(message: &[u8]) -> [u8; MESSAGE_BITS] {
    let digest = hash(message);
    let mut bits = [0u8; MESSAGE_BITS];
    for (byte_index, byte) in digest.iter().enumerate() {
        for bit_index in 0..8 {
            bits[byte_index * 8 + bit_index] = (byte >> bit_index) & 1;
        }
    }
    bits
}

pub struct PrivateKey {
    zero: Vec<[u8; HASH_LEN]>,
    one: Vec<[u8; HASH_LEN]>,
}

pub struct PublicKey {
    zero: Vec<[u8; HASH_LEN]>,
    one: Vec<[u8; HASH_LEN]>,
}

pub struct Signature {
    values: Vec<[u8; HASH_LEN]>,
}

impl PrivateKey {
    pub fn generate() -> Self {
        let zero = (0..MESSAGE_BITS).map(|_| random_block()).collect();
        let one = (0..MESSAGE_BITS).map(|_| random_block()).collect();
        PrivateKey { zero, one }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            zero: self.zero.iter().map(|block| hash(block)).collect(),
            one: self.one.iter().map(|block| hash(block)).collect(),
        }
    }

    /// Consumes the private key: a Lamport key must never sign a second
    /// message, since two signatures together leak enough secret halves
    /// to forge a signature on a new message.
    pub fn sign(self, message: &[u8]) -> Signature {
        let bits = message_bits(message);
        let values = bits
            .iter()
            .enumerate()
            .map(|(i, &bit)| if bit == 0 { self.zero[i] } else { self.one[i] })
            .collect();
        Signature { values }
    }
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    if signature.values.len() != MESSAGE_BITS {
        return false;
    }
    let bits = message_bits(message);
    for (i, &bit) in bits.iter().enumerate() {
        let expected = if bit == 0 { public_key.zero[i] } else { public_key.one[i] };
        if hash(&signature.values[i]) != expected {
            return false;
        }
    }
    true
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.values.iter().flatten().copied().collect()
    }

    pub fn size_bytes(&self) -> usize {
        self.values.len() * HASH_LEN
    }
}

impl PublicKey {
    pub fn size_bytes(&self) -> usize {
        (self.zero.len() + self.one.len()) * HASH_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        let message = b"post quantum signatures";
        let signature = sk.sign(message);
        assert!(verify(&pk, message, &signature));
    }

    #[test]
    fn tampered_message_fails() {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        let signature = sk.sign(b"original message");
        assert!(!verify(&pk, b"different message", &signature));
    }

    #[test]
    fn tampered_signature_fails() {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        let message = b"original message";
        let mut signature = sk.sign(message);
        signature.values[0] = random_block();
        assert!(!verify(&pk, message, &signature));
    }
}
