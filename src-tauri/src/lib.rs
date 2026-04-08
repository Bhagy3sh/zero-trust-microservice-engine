//! ZeroTrust Mesh - Zero-Trust Network Micro-Segmentation Engine
//!
//! This library provides the core functionality for the ZeroTrust Mesh application,
//! including identity management, policy evaluation, WireGuard mesh networking,
//! eBPF-based packet inspection, and trust scoring.

pub mod config;
pub mod crypto;
pub mod storage;
pub mod identity;
pub mod policy;
pub mod wireguard;
pub mod ebpf;
pub mod attestation;

use anyhow::Result;
use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{info, error};

/// Global application state
pub static APP_STATE: OnceCell<Arc<AppState>> = OnceCell::new();

/// Central application state holding all subsystems
pub struct AppState {
    pub config: Arc<RwLock<config::Config>>,
    pub db: Arc<storage::Database>,
    pub identity_provider: Arc<RwLock<identity::IdentityProvider>>,
    pub policy_engine: Arc<RwLock<policy::PolicyEngine>>,
    pub trust_manager: Arc<RwLock<attestation::TrustManager>>,
}

impl AppState {
    /// Initialize the application state with all subsystems
    pub async fn new(config_path: Option<&str>) -> Result<Arc<Self>> {
        // Load configuration
        let config = config::Config::load(config_path)?;
        let config = Arc::new(RwLock::new(config));
        
        // Initialize database
        let db_path = {
            let cfg = config.read();
            cfg.storage.database_path.clone()
        };
        let db = Arc::new(storage::Database::new(&db_path)?);
        
        // Initialize identity provider
        let identity_provider = {
            let cfg = config.read();
            identity::IdentityProvider::new(
                &cfg.identity.trust_domain,
                &cfg.identity.ca_key_path,
                &cfg.identity.ca_cert_path,
            )?
        };
        let identity_provider = Arc::new(RwLock::new(identity_provider));
        
        // Initialize policy engine
        let policy_engine = policy::PolicyEngine::new(db.clone())?;
        let policy_engine = Arc::new(RwLock::new(policy_engine));
        
        // Initialize trust manager
        let trust_manager = {
            let cfg = config.read();
            attestation::TrustManager::new(
                cfg.attestation.tpm_enabled,
                cfg.attestation.clone(),
            )?
        };
        let trust_manager = Arc::new(RwLock::new(trust_manager));
        
        let state = Arc::new(Self {
            config,
            db,
            identity_provider,
            policy_engine,
            trust_manager,
        });
        
        info!("ZeroTrust Mesh initialized successfully");
        Ok(state)
    }
}

/// Initialize the global application state
pub async fn init_app(config_path: Option<&str>) -> Result<Arc<AppState>> {
    let state = AppState::new(config_path).await?;
    APP_STATE.set(state.clone()).map_err(|_| {
        anyhow::anyhow!("Application state already initialized")
    })?;
    Ok(state)
}

/// Get the global application state
pub fn get_app_state() -> Option<Arc<AppState>> {
    APP_STATE.get().cloned()
}
