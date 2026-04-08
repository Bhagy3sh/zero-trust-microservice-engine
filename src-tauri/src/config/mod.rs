//! Configuration management for ZeroTrust Mesh
//!
//! Handles loading, parsing, and validating TOML configuration files.
//! Implements requirement MNT4: Configuration file in TOML format.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use validator::Validate;

/// Default configuration file path
const DEFAULT_CONFIG_PATH: &str = "/etc/zerotrust-mesh/config.toml";

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct Config {
    #[validate]
    pub general: GeneralConfig,
    #[validate]
    pub identity: IdentityConfig,
    #[validate]
    pub policy: PolicyConfig,
    #[validate]
    pub wireguard: WireGuardConfig,
    #[validate]
    pub ebpf: EbpfConfig,
    #[validate]
    pub attestation: AttestationConfig,
    #[validate]
    pub storage: StorageConfig,
    #[validate]
    pub logging: LoggingConfig,
    #[validate]
    pub network: NetworkConfig,
}

/// General application settings
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct GeneralConfig {
    /// Application autostart on system boot
    pub autostart: bool,
    /// UI theme (light/dark)
    #[validate(custom = "validate_theme")]
    pub theme: String,
    /// Enable desktop notifications
    pub notifications_enabled: bool,
    /// Inactivity lock timeout in minutes (SEC7: 15 minutes default)
    #[validate(range(min = 1, max = 60))]
    pub inactivity_lock_minutes: u32,
}

/// Identity provider configuration (Feature Group A)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct IdentityConfig {
    /// SPIFFE trust domain (e.g., "zerotrust.local")
    #[validate(length(min = 1, max = 253))]
    pub trust_domain: String,
    /// JWT-SVID expiration in seconds (A1.2: default 15 minutes = 900 seconds)
    #[validate(range(min = 60, max = 86400))]
    pub jwt_expiration_seconds: u32,
    /// Path to CA private key
    pub ca_key_path: PathBuf,
    /// Path to CA certificate
    pub ca_cert_path: PathBuf,
    /// Path to store service certificates
    pub certs_path: PathBuf,
}

/// Policy engine configuration (Feature Group B)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PolicyConfig {
    /// Policy evaluation cache TTL in seconds (B2.3: 5 seconds)
    #[validate(range(min = 1, max = 60))]
    pub cache_ttl_seconds: u32,
    /// Maximum number of cached evaluations
    #[validate(range(min = 100, max = 1000000))]
    pub max_cache_entries: u32,
    /// Default policy action when no rules match
    #[validate(custom = "validate_policy_action")]
    pub default_action: String,
}

/// WireGuard mesh configuration (Feature Group C)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct WireGuardConfig {
    /// WireGuard listen port (default 51820)
    #[validate(range(min = 1024, max = 65535))]
    pub listen_port: u16,
    /// Virtual IP subnet for mesh (C1.5: 10.128.0.0/16)
    #[validate(length(min = 1))]
    pub virtual_subnet: String,
    /// Persistent keepalive interval in seconds (C2.4: 25 seconds)
    #[validate(range(min = 10, max = 120))]
    pub keepalive_seconds: u32,
    /// Key rotation interval in days (C1.6: 7 days)
    #[validate(range(min = 1, max = 90))]
    pub key_rotation_days: u32,
    /// MTU for WireGuard interface
    #[validate(range(min = 1280, max = 9000))]
    pub mtu: u16,
}

/// eBPF data plane configuration (Feature Group D)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct EbpfConfig {
    /// Enable eBPF packet filtering
    pub enabled: bool,
    /// Network interface to attach XDP program
    pub interface: String,
    /// SYN flood threshold per IP (D2.1: 100 SYNs/sec)
    #[validate(range(min = 10, max = 10000))]
    pub syn_flood_threshold: u32,
    /// Port scan threshold (D2.2: 50 ports in 10 seconds)
    #[validate(range(min = 10, max = 1000))]
    pub port_scan_threshold: u32,
    /// HTTP flood threshold (D2.3: 1000 req/sec)
    #[validate(range(min = 100, max = 100000))]
    pub http_flood_threshold: u32,
    /// ICMP flood threshold (D2.4: 500 pings/sec)
    #[validate(range(min = 50, max = 10000))]
    pub icmp_flood_threshold: u32,
    /// Log sampling rate for dropped packets (0.0-1.0)
    #[validate(range(min = 0.0, max = 1.0))]
    pub drop_log_sample_rate: f32,
}

/// Attestation and trust scoring configuration (Feature Group E)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AttestationConfig {
    /// Enable TPM 2.0 attestation
    pub tpm_enabled: bool,
    /// Trust score recalculation interval in seconds (E3.6: 30 seconds)
    #[validate(range(min = 10, max = 300))]
    pub recalculation_interval_seconds: u32,
    /// TPM attestation weight (E3.2: 40%)
    #[validate(range(min = 0.0, max = 1.0))]
    pub tpm_weight: f32,
    /// Process integrity weight (E3.3: 25%)
    #[validate(range(min = 0.0, max = 1.0))]
    pub process_integrity_weight: f32,
    /// Behavioral anomaly weight (E3.4: 20%)
    #[validate(range(min = 0.0, max = 1.0))]
    pub behavioral_weight: f32,
    /// Resource usage weight (E3.5: 15%)
    #[validate(range(min = 0.0, max = 1.0))]
    pub resource_weight: f32,
    /// Threshold for full access (E3.7: >0.8)
    #[validate(range(min = 0.0, max = 1.0))]
    pub full_access_threshold: f32,
    /// Threshold for limited access (E3.7: 0.5-0.8)
    #[validate(range(min = 0.0, max = 1.0))]
    pub limited_access_threshold: f32,
    /// Threshold for isolation (E3.7: 0.3-0.5)
    #[validate(range(min = 0.0, max = 1.0))]
    pub isolation_threshold: f32,
    /// Threshold for termination (E3.7: <0.3)
    #[validate(range(min = 0.0, max = 1.0))]
    pub termination_threshold: f32,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct StorageConfig {
    /// Path to SQLite database
    pub database_path: PathBuf,
    /// Log retention days (G1.6: 90 days)
    #[validate(range(min = 1, max = 365))]
    pub log_retention_days: u32,
    /// Maximum alert storage (SCL4: 1,000,000)
    #[validate(range(min = 1000, max = 10000000))]
    pub max_alerts: u32,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct LoggingConfig {
    /// Log level (MNT3: DEBUG, INFO, WARN, ERROR)
    #[validate(custom = "validate_log_level")]
    pub level: String,
    /// Log to file
    pub file_enabled: bool,
    /// Log file path
    pub file_path: PathBuf,
    /// Maximum log file size in MB
    #[validate(range(min = 1, max = 1000))]
    pub max_file_size_mb: u32,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct NetworkConfig {
    /// Dashboard API port
    #[validate(range(min = 1024, max = 65535))]
    pub api_port: u16,
    /// WebSocket port for real-time updates
    #[validate(range(min = 1024, max = 65535))]
    pub websocket_port: u16,
    /// Service discovery interval in seconds (NFR4: 5 seconds)
    #[validate(range(min = 1, max = 60))]
    pub discovery_interval_seconds: u32,
    /// DNS resolver for the mesh
    pub dns_resolver: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                autostart: false,
                theme: "dark".to_string(),
                notifications_enabled: true,
                inactivity_lock_minutes: 15,
            },
            identity: IdentityConfig {
                trust_domain: "zerotrust.local".to_string(),
                jwt_expiration_seconds: 900, // 15 minutes
                ca_key_path: PathBuf::from("/var/lib/zerotrust-mesh/ca.key"),
                ca_cert_path: PathBuf::from("/var/lib/zerotrust-mesh/ca.crt"),
                certs_path: PathBuf::from("/var/lib/zerotrust-mesh/certs"),
            },
            policy: PolicyConfig {
                cache_ttl_seconds: 5,
                max_cache_entries: 10000,
                default_action: "Deny".to_string(),
            },
            wireguard: WireGuardConfig {
                listen_port: 51820,
                virtual_subnet: "10.128.0.0/16".to_string(),
                keepalive_seconds: 25,
                key_rotation_days: 7,
                mtu: 1420,
            },
            ebpf: EbpfConfig {
                enabled: true,
                interface: "eth0".to_string(),
                syn_flood_threshold: 100,
                port_scan_threshold: 50,
                http_flood_threshold: 1000,
                icmp_flood_threshold: 500,
                drop_log_sample_rate: 0.1,
            },
            attestation: AttestationConfig {
                tpm_enabled: true,
                recalculation_interval_seconds: 30,
                tpm_weight: 0.40,
                process_integrity_weight: 0.25,
                behavioral_weight: 0.20,
                resource_weight: 0.15,
                full_access_threshold: 0.8,
                limited_access_threshold: 0.5,
                isolation_threshold: 0.3,
                termination_threshold: 0.3,
            },
            storage: StorageConfig {
                database_path: PathBuf::from("/var/lib/zerotrust-mesh/zerotrust.db"),
                log_retention_days: 90,
                max_alerts: 1000000,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_enabled: true,
                file_path: PathBuf::from("/var/log/zerotrust-mesh/app.log"),
                max_file_size_mb: 100,
            },
            network: NetworkConfig {
                api_port: 8080,
                websocket_port: 8081,
                discovery_interval_seconds: 5,
                dns_resolver: "1.1.1.1".to_string(),
            },
        }
    }
}

impl Config {
    /// Load configuration from file, falling back to defaults
    pub fn load(path: Option<&str>) -> Result<Self> {
        let config_path = path.unwrap_or(DEFAULT_CONFIG_PATH);
        
        if Path::new(config_path).exists() {
            let content = fs::read_to_string(config_path)
                .context(format!("Failed to read config file: {}", config_path))?;
            let config: Config = toml::from_str(&content)
                .context("Failed to parse configuration file")?;
            config.validate().context("Configuration validation failed")?;
            Ok(config)
        } else {
            tracing::warn!("Config file not found at {}, using defaults", config_path);
            Ok(Self::default())
        }
    }
    
    /// Save configuration to file
    pub fn save(&self, path: &str) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize configuration")?;
        
        // Ensure parent directory exists
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)
                .context("Failed to create config directory")?;
        }
        
        fs::write(path, content)
            .context(format!("Failed to write config file: {}", path))?;
        
        Ok(())
    }
}

// Custom validators
fn validate_theme(theme: &str) -> Result<(), validator::ValidationError> {
    match theme {
        "light" | "dark" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_theme")),
    }
}

fn validate_log_level(level: &str) -> Result<(), validator::ValidationError> {
    match level.to_lowercase().as_str() {
        "debug" | "info" | "warn" | "error" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_log_level")),
    }
}

fn validate_policy_action(action: &str) -> Result<(), validator::ValidationError> {
    match action {
        "Allow" | "Deny" | "RequireMFA" | "Log" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_policy_action")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.identity.trust_domain, config.identity.trust_domain);
    }
}
