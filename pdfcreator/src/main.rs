use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use lopdf::Document;
use base64;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;
use sha2::{Sha256, Digest};

// Define a struct to hold the payload and encryption keys
struct Payload {
    payload: Vec<u8>,
    symmetric_key: Vec<u8>,
    asymmetric_key: Vec<u8>,
}

impl Payload {
    // Generate symmetric and asymmetric keys
    fn generate_keys() -> (Vec<u8>, Vec<u8>) {
        let hasher = Sha256::new();
        let symmetric_key = hasher.finalize().to_vec();
        let hasher = Sha256::new();
        let asymmetric_key = hasher.finalize().to_vec();
        (symmetric_key, asymmetric_key)
    }

    // Encrypt the payload with the symmetric key
    fn encrypt_payload(&self, symmetric_key: &Vec<u8>) -> Vec<u8> {
        let key = Key::<Aes256Gcm>::from_slice(symmetric_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(b"unique_nonce");
        let encrypted_payload = cipher.encrypt(nonce, self.payload.as_ref()).unwrap();
        encrypted_payload
    }

    // Encrypt the payload with the asymmetric key
    fn encrypt_with_public_key(&self, _public_key: &Vec<u8>) -> Vec<u8> {
        // Not implemented
        vec![]
    }
}

fn main() {
    // Select a file
    let file_path = "path_to_your_file";
    let mut file = File::open(file_path).unwrap();
    let mut payload = Vec::new();
    file.read_to_end(&mut payload).unwrap();

    // Generate symmetric and asymmetric keys
    let (symmetric_key, asymmetric_key) = Payload::generate_keys();

    // Encrypt the payload
    let encrypted_payload = Payload {
        payload,
        symmetric_key: symmetric_key.clone(),
        asymmetric_key: asymmetric_key.clone(),
    }
    .encrypt_payload(&symmetric_key);

    // Create a PDF document
    let mut document = Document::new();

    // Save the PDF to a file
    let mut file = PathBuf::from("payload.pdf");
    document.save(file).unwrap();

    // Display the final payload details
    println!("Payload details:");
    println!("Payload file: {}", file_path);
    println!("Encrypted payload (Base64): {}", base64::encode(&encrypted_payload));
    println!("Symmetric key (Base64): {}", base64::encode(&symmetric_key));
    println!("Asymmetric key (Base64): {}", base64::encode(&asymmetric_key));
}
