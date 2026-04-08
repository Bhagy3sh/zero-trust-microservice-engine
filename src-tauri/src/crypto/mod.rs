//! Cryptographic utilities for ZeroTrust Mesh
//!
//! Implements requirements:
//! - SEC1: All cryptographic keys stored encrypted (AES-256-GCM)
//! - A1.4: Private keys in encrypted format
//! - H2.1: RSA key generation (2048, 3072, 4096 bits)
//! - H2.2: RSA + AES hybrid encryption

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use rand::RngCore;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Cryptographic errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    #[error("Invalid key size: {0}")]
    InvalidKeySize(usize),
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

/// AES-256-GCM encryption key
pub struct AesKey {
    key: [u8; 32],
}

impl AesKey {
    /// Generate a new random AES-256 key
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }
    
    /// Create from existing bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeySize(bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }
    
    /// Get key bytes (for secure storage)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
    
    /// Derive a key from a password using PBKDF2-like derivation
    pub fn from_password(password: &str, salt: &[u8]) -> Self {
        // Simple derivation using SHA-256 (in production, use proper PBKDF2)
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        Self { key }
    }
}

/// AES-256-GCM encryption/decryption
pub struct Aes256GcmCrypto {
    cipher: Aes256Gcm,
}

impl Aes256GcmCrypto {
    /// Create new instance with the given key
    pub fn new(key: &AesKey) -> Self {
        let cipher = Aes256Gcm::new_from_slice(&key.key).expect("Invalid key length");
        Self { cipher }
    }
    
    /// Encrypt data with AES-256-GCM
    /// Returns: nonce (12 bytes) || ciphertext
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt data with AES-256-GCM
    /// Input: nonce (12 bytes) || ciphertext
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < 12 {
            return Err(CryptoError::InvalidNonce);
        }
        
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
}

/// RSA key pair for asymmetric encryption
pub struct RsaKeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RsaKeyPair {
    /// Generate a new RSA key pair
    /// Supports 2048, 3072, 4096 bit keys (H2.1)
    pub fn generate(bits: usize) -> Result<Self, CryptoError> {
        match bits {
            2048 | 3072 | 4096 => {}
            _ => return Err(CryptoError::InvalidKeySize(bits)),
        }
        
        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        let public_key = RsaPublicKey::from(&private_key);
        
        Ok(Self {
            private_key,
            public_key,
        })
    }
    
    /// Get the public key
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }
    
    /// Get the private key
    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }
    
    /// Export public key as PEM
    pub fn export_public_pem(&self) -> Result<String, CryptoError> {
        self.public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))
    }
    
    /// Export private key as PEM
    pub fn export_private_pem(&self) -> Result<String, CryptoError> {
        self.private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))
    }
    
    /// Import from PEM strings
    pub fn from_pem(private_pem: &str, public_pem: &str) -> Result<Self, CryptoError> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem)
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        let public_key = RsaPublicKey::from_public_key_pem(public_pem)
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        
        Ok(Self {
            private_key,
            public_key,
        })
    }
    
    /// Encrypt data using RSA-PKCS1v15 (for small data like AES keys)
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.public_key
            .encrypt(&mut OsRng, Pkcs1v15Encrypt, data)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
    }
    
    /// Decrypt data using RSA-PKCS1v15
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.private_key
            .decrypt(Pkcs1v15Encrypt, data)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
}

/// Hybrid RSA + AES encryption (H2.2)
/// Encrypts data using AES-256-GCM with a random key, then encrypts the key with RSA
pub struct HybridCrypto {
    rsa_key: RsaKeyPair,
}

impl HybridCrypto {
    pub fn new(rsa_key: RsaKeyPair) -> Self {
        Self { rsa_key }
    }
    
    /// Encrypt data using hybrid encryption
    /// Returns: encrypted_aes_key (RSA encrypted) || encrypted_data (AES-GCM)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Generate random AES key
        let aes_key = AesKey::generate();
        let aes_crypto = Aes256GcmCrypto::new(&aes_key);
        
        // Encrypt data with AES
        let encrypted_data = aes_crypto.encrypt(plaintext)?;
        
        // Encrypt AES key with RSA
        let encrypted_key = self.rsa_key.encrypt(aes_key.as_bytes())?;
        
        // Format: key_length (4 bytes) || encrypted_key || encrypted_data
        let key_len = encrypted_key.len() as u32;
        let mut result = Vec::with_capacity(4 + encrypted_key.len() + encrypted_data.len());
        result.extend_from_slice(&key_len.to_le_bytes());
        result.extend(encrypted_key);
        result.extend(encrypted_data);
        
        Ok(result)
    }
    
    /// Decrypt hybrid-encrypted data
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < 4 {
            return Err(CryptoError::DecryptionFailed("Data too short".into()));
        }
        
        // Read key length
        let key_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        
        if data.len() < 4 + key_len {
            return Err(CryptoError::DecryptionFailed("Invalid data format".into()));
        }
        
        // Extract encrypted key and data
        let encrypted_key = &data[4..4 + key_len];
        let encrypted_data = &data[4 + key_len..];
        
        // Decrypt AES key with RSA
        let aes_key_bytes = self.rsa_key.decrypt(encrypted_key)?;
        let aes_key = AesKey::from_bytes(&aes_key_bytes)?;
        
        // Decrypt data with AES
        let aes_crypto = Aes256GcmCrypto::new(&aes_key);
        aes_crypto.decrypt(encrypted_data)
    }
}

/// Compute SHA-256 hash (E1.1: Binary hash measurement)
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute SHA-256 hash of a file
pub fn sha256_file(path: &std::path::Path) -> Result<[u8; 32]> {
    let data = std::fs::read(path).context("Failed to read file for hashing")?;
    Ok(sha256_hash(&data))
}

/// Securely compare two byte slices in constant time
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Generate a cryptographically secure random token
pub fn generate_secure_token(length: usize) -> Vec<u8> {
    let mut token = vec![0u8; length];
    OsRng.fill_bytes(&mut token);
    token
}

/// Generate a random hex string
pub fn generate_hex_token(bytes: usize) -> String {
    hex::encode(generate_secure_token(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = AesKey::generate();
        let crypto = Aes256GcmCrypto::new(&key);
        
        let plaintext = b"Hello, ZeroTrust Mesh!";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }
    
    #[test]
    fn test_rsa_key_generation() {
        let key_pair = RsaKeyPair::generate(2048).unwrap();
        assert!(key_pair.export_public_pem().is_ok());
        assert!(key_pair.export_private_pem().is_ok());
    }
    
    #[test]
    fn test_rsa_encrypt_decrypt() {
        let key_pair = RsaKeyPair::generate(2048).unwrap();
        let data = b"Secret message";
        
        let encrypted = key_pair.encrypt(data).unwrap();
        let decrypted = key_pair.decrypt(&encrypted).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
    }
    
    #[test]
    fn test_hybrid_encrypt_decrypt() {
        let rsa_key = RsaKeyPair::generate(2048).unwrap();
        let hybrid = HybridCrypto::new(rsa_key);
        
        let plaintext = b"Large amount of data that would be too big for RSA alone";
        let encrypted = hybrid.encrypt(plaintext).unwrap();
        let decrypted = hybrid.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }
    
    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32);
        
        // Verify deterministic
        let hash2 = sha256_hash(data);
        assert_eq!(hash, hash2);
    }
    
    #[test]
    fn test_constant_time_compare() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        let c = [1, 2, 3, 4, 6];
        
        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
    }
}
