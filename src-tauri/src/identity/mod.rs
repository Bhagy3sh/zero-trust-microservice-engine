//! Identity Management for ZeroTrust Mesh
//!
//! Implements Feature Group A requirements:
//! - A1: SPIFFE Identity Provider
//! - A2: Service Registration
//! - A3: Identity Propagation
//!
//! SPIFFE ID format: spiffe://<trust_domain>/<workload>

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::crypto::{sha256_hash, Aes256GcmCrypto, AesKey};
use crate::storage::Database;

/// Identity-related errors
#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
    #[error("Certificate generation failed: {0}")]
    CertGenerationFailed(String),
    #[error("Invalid SPIFFE ID format: {0}")]
    InvalidSpiffeId(String),
    #[error("JWT signing failed: {0}")]
    JwtSigningFailed(String),
    #[error("JWT verification failed: {0}")]
    JwtVerificationFailed(String),
    #[error("Certificate revoked")]
    CertificateRevoked,
    #[error("Certificate expired")]
    CertificateExpired,
    #[error("Trust domain mismatch")]
    TrustDomainMismatch,
}

/// SPIFFE ID structure (A1.6)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpiffeId {
    pub trust_domain: String,
    pub path: String,
}

impl SpiffeId {
    /// Create a new SPIFFE ID
    pub fn new(trust_domain: &str, workload: &str) -> Self {
        Self {
            trust_domain: trust_domain.to_string(),
            path: workload.to_string(),
        }
    }
    
    /// Parse SPIFFE ID from URI string
    pub fn from_uri(uri: &str) -> Result<Self, IdentityError> {
        // Format: spiffe://<trust_domain>/<path>
        if !uri.starts_with("spiffe://") {
            return Err(IdentityError::InvalidSpiffeId(
                "Must start with 'spiffe://'".into(),
            ));
        }
        
        let rest = &uri[9..]; // Remove "spiffe://"
        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        
        if parts.is_empty() || parts[0].is_empty() {
            return Err(IdentityError::InvalidSpiffeId(
                "Missing trust domain".into(),
            ));
        }
        
        Ok(Self {
            trust_domain: parts[0].to_string(),
            path: parts.get(1).map(|s| s.to_string()).unwrap_or_default(),
        })
    }
    
    /// Convert to URI string
    pub fn to_uri(&self) -> String {
        format!("spiffe://{}/{}", self.trust_domain, self.path)
    }
}

/// Service registration data (A2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    pub spiffe_id: SpiffeId,
    pub name: String,
    pub description: Option<String>,
    pub port: u16,
    pub binary_path: Option<PathBuf>,
    pub binary_hash: Option<String>,
    pub user: Option<String>,
    pub pid: Option<u32>,
    pub status: ServiceStatus,
    pub trust_score: f64,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

/// Service status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    Active,
    Inactive,
    Suspended,
    Terminated,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceStatus::Active => write!(f, "active"),
            ServiceStatus::Inactive => write!(f, "inactive"),
            ServiceStatus::Suspended => write!(f, "suspended"),
            ServiceStatus::Terminated => write!(f, "terminated"),
        }
    }
}

/// JWT-SVID claims (A1.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvidClaims {
    /// Subject (SPIFFE ID)
    pub sub: String,
    /// Expiration time
    pub exp: i64,
    /// Issued at
    pub iat: i64,
    /// Audience
    pub aud: Vec<String>,
    /// Service metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    /// Trust score at issuance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_score: Option<f64>,
}

/// Certificate with encrypted private key
#[derive(Debug, Clone)]
pub struct ServiceCertificate {
    pub id: String,
    pub service_id: String,
    pub cert_pem: String,
    pub private_key_encrypted: Vec<u8>,
    pub not_before: chrono::DateTime<Utc>,
    pub not_after: chrono::DateTime<Utc>,
    pub revoked: bool,
}

/// Identity Provider (SPIFFE-compliant)
pub struct IdentityProvider {
    trust_domain: String,
    ca_key_pair: KeyPair,
    ca_certificate: Certificate,
    encryption_key: AesKey,
    jwt_expiration_seconds: u32,
}

impl IdentityProvider {
    /// Create a new identity provider (A1)
    pub fn new(trust_domain: &str, ca_key_path: &Path, ca_cert_path: &Path) -> Result<Self> {
        // Generate or load CA key pair
        let (ca_key_pair, ca_certificate) = if ca_key_path.exists() && ca_cert_path.exists() {
            Self::load_ca(ca_key_path, ca_cert_path)?
        } else {
            Self::generate_ca(trust_domain, ca_key_path, ca_cert_path)?
        };
        
        // Generate encryption key for private key storage (A1.4)
        let encryption_key = AesKey::generate();
        
        info!("Identity provider initialized for trust domain: {}", trust_domain);
        
        Ok(Self {
            trust_domain: trust_domain.to_string(),
            ca_key_pair,
            ca_certificate,
            encryption_key,
            jwt_expiration_seconds: 900, // 15 minutes default (A1.2)
        })
    }
    
    /// Generate new CA certificate
    fn generate_ca(
        trust_domain: &str,
        key_path: &Path,
        cert_path: &Path,
    ) -> Result<(KeyPair, Certificate)> {
        info!("Generating new CA for trust domain: {}", trust_domain);
        
        let mut params = CertificateParams::default();
        
        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("ZeroTrust Mesh CA - {}", trust_domain));
        dn.push(DnType::OrganizationName, "ZeroTrust Mesh");
        params.distinguished_name = dn;
        
        // CA settings
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(2));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        
        // Valid for 10 years
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 1, 1);
        
        // Generate key pair
        let key_pair = KeyPair::generate()?;
        params.key_pair = Some(key_pair.clone());
        
        let cert = Certificate::from_params(params)?;
        
        // Save CA files
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        std::fs::write(key_path, key_pair.serialize_pem())?;
        std::fs::write(cert_path, cert.serialize_pem()?)?;
        
        info!("CA certificate generated and saved");
        Ok((key_pair, cert))
    }
    
    /// Load existing CA
    fn load_ca(key_path: &Path, cert_path: &Path) -> Result<(KeyPair, Certificate)> {
        info!("Loading existing CA from {:?}", key_path);
        
        let key_pem = std::fs::read_to_string(key_path)?;
        let key_pair = KeyPair::from_pem(&key_pem)?;
        
        // For rcgen, we need to recreate the certificate params
        // This is a simplified version - in production, parse the existing cert
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(2));
        params.key_pair = Some(key_pair.clone());
        
        let cert = Certificate::from_params(params)?;
        
        Ok((key_pair, cert))
    }
    
    /// Register a new service and issue certificate (A2, A1.1)
    pub fn register_service(
        &self,
        name: &str,
        port: u16,
        description: Option<&str>,
        binary_path: Option<&Path>,
    ) -> Result<(Service, ServiceCertificate)> {
        let service_id = Uuid::new_v4().to_string();
        let workload = format!("{}-{}", name.to_lowercase().replace(' ', "-"), &service_id[..8]);
        let spiffe_id = SpiffeId::new(&self.trust_domain, &workload);
        
        // Calculate binary hash if path provided (A2.4)
        let binary_hash = binary_path.map(|p| {
            if p.exists() {
                crate::crypto::sha256_file(p)
                    .map(|h| hex::encode(h))
                    .ok()
            } else {
                None
            }
        }).flatten();
        
        let now = Utc::now();
        let service = Service {
            id: service_id.clone(),
            spiffe_id: spiffe_id.clone(),
            name: name.to_string(),
            description: description.map(String::from),
            port,
            binary_path: binary_path.map(PathBuf::from),
            binary_hash,
            user: None,
            pid: None,
            status: ServiceStatus::Active,
            trust_score: 1.0,
            created_at: now,
            updated_at: now,
        };
        
        // Issue certificate
        let cert = self.issue_certificate(&service)?;
        
        info!("Registered service '{}' with SPIFFE ID: {}", name, spiffe_id.to_uri());
        
        Ok((service, cert))
    }
    
    /// Issue X.509 certificate for a service (A1.1)
    pub fn issue_certificate(&self, service: &Service) -> Result<ServiceCertificate> {
        let cert_id = Uuid::new_v4().to_string();
        
        let mut params = CertificateParams::default();
        
        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &service.name);
        params.distinguished_name = dn;
        
        // Set SPIFFE ID as SAN URI
        params.subject_alt_names = vec![SanType::URI(service.spiffe_id.to_uri())];
        
        // Client and server authentication
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        
        // Valid for 24 hours (short-lived for zero-trust)
        let now = Utc::now();
        let expires = now + Duration::hours(24);
        
        // Generate key pair for the service
        let key_pair = KeyPair::generate()?;
        params.key_pair = Some(key_pair.clone());
        
        // Create certificate signed by CA
        let cert = Certificate::from_params(params)?;
        let cert_pem = cert.serialize_pem_with_signer(&self.ca_certificate)?;
        
        // Encrypt private key (A1.4)
        let private_key_pem = key_pair.serialize_pem();
        let crypto = Aes256GcmCrypto::new(&self.encryption_key);
        let private_key_encrypted = crypto.encrypt(private_key_pem.as_bytes())?;
        
        let service_cert = ServiceCertificate {
            id: cert_id,
            service_id: service.id.clone(),
            cert_pem,
            private_key_encrypted,
            not_before: now,
            not_after: expires,
            revoked: false,
        };
        
        debug!("Issued certificate for service: {}", service.name);
        Ok(service_cert)
    }
    
    /// Issue JWT-SVID (A1.2)
    pub fn issue_jwt_svid(
        &self,
        service: &Service,
        audience: Vec<String>,
    ) -> Result<String, IdentityError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.jwt_expiration_seconds as i64);
        
        let claims = SvidClaims {
            sub: service.spiffe_id.to_uri(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            aud: audience,
            service_name: Some(service.name.clone()),
            trust_score: Some(service.trust_score),
        };
        
        // Use the CA key for signing (in production, use a separate signing key)
        let key_pem = self.ca_key_pair.serialize_pem();
        let encoding_key = EncodingKey::from_ec_pem(key_pem.as_bytes())
            .map_err(|e| IdentityError::JwtSigningFailed(e.to_string()))?;
        
        let header = Header::new(Algorithm::ES256);
        let token = encode(&header, &claims, &encoding_key)
            .map_err(|e| IdentityError::JwtSigningFailed(e.to_string()))?;
        
        debug!("Issued JWT-SVID for service: {}", service.name);
        Ok(token)
    }
    
    /// Verify JWT-SVID (A3.2)
    pub fn verify_jwt_svid(&self, token: &str) -> Result<SvidClaims, IdentityError> {
        let key_pem = self.ca_key_pair.serialize_pem();
        let decoding_key = DecodingKey::from_ec_pem(key_pem.as_bytes())
            .map_err(|e| IdentityError::JwtVerificationFailed(e.to_string()))?;
        
        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = true;
        
        let token_data = decode::<SvidClaims>(token, &decoding_key, &validation)
            .map_err(|e| IdentityError::JwtVerificationFailed(e.to_string()))?;
        
        // Verify trust domain (A1.5)
        let spiffe_id = SpiffeId::from_uri(&token_data.claims.sub)?;
        if spiffe_id.trust_domain != self.trust_domain {
            return Err(IdentityError::TrustDomainMismatch);
        }
        
        Ok(token_data.claims)
    }
    
    /// Renew certificate before expiration (A1.3)
    pub fn renew_certificate(
        &self,
        service: &Service,
        _old_cert: &ServiceCertificate,
    ) -> Result<ServiceCertificate> {
        // Issue a new certificate
        self.issue_certificate(service)
    }
    
    /// Check if a certificate needs renewal
    pub fn needs_renewal(cert: &ServiceCertificate, threshold_hours: i64) -> bool {
        let now = Utc::now();
        let threshold = cert.not_after - Duration::hours(threshold_hours);
        now >= threshold
    }
    
    /// Get trust domain
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }
    
    /// Set JWT expiration time
    pub fn set_jwt_expiration(&mut self, seconds: u32) {
        self.jwt_expiration_seconds = seconds;
    }
}

/// Revocation list management (A1.7)
pub struct RevocationList {
    revoked_certs: HashMap<String, chrono::DateTime<Utc>>,
    revoked_tokens: HashMap<String, chrono::DateTime<Utc>>,
}

impl RevocationList {
    pub fn new() -> Self {
        Self {
            revoked_certs: HashMap::new(),
            revoked_tokens: HashMap::new(),
        }
    }
    
    /// Revoke a certificate
    pub fn revoke_certificate(&mut self, cert_id: &str) {
        self.revoked_certs.insert(cert_id.to_string(), Utc::now());
        warn!("Certificate revoked: {}", cert_id);
    }
    
    /// Revoke a JWT token
    pub fn revoke_token(&mut self, token_hash: &str) {
        self.revoked_tokens.insert(token_hash.to_string(), Utc::now());
        warn!("JWT token revoked: {}", token_hash);
    }
    
    /// Check if certificate is revoked
    pub fn is_cert_revoked(&self, cert_id: &str) -> bool {
        self.revoked_certs.contains_key(cert_id)
    }
    
    /// Check if token is revoked
    pub fn is_token_revoked(&self, token_hash: &str) -> bool {
        self.revoked_tokens.contains_key(token_hash)
    }
}

impl Default for RevocationList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_spiffe_id_parsing() {
        let uri = "spiffe://example.com/workload/service1";
        let id = SpiffeId::from_uri(uri).unwrap();
        
        assert_eq!(id.trust_domain, "example.com");
        assert_eq!(id.path, "workload/service1");
        assert_eq!(id.to_uri(), uri);
    }
    
    #[test]
    fn test_spiffe_id_invalid() {
        assert!(SpiffeId::from_uri("http://example.com/service").is_err());
        assert!(SpiffeId::from_uri("spiffe://").is_err());
    }
    
    #[test]
    fn test_identity_provider_creation() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("ca.key");
        let cert_path = dir.path().join("ca.crt");
        
        let provider = IdentityProvider::new("test.local", &key_path, &cert_path);
        assert!(provider.is_ok());
        
        // Verify files were created
        assert!(key_path.exists());
        assert!(cert_path.exists());
    }
}
