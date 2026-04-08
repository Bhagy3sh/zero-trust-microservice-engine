//! Attestation and Trust Scoring for ZeroTrust Mesh
//!
//! Implements Feature Group E requirements:
//! - E1: Process Attestation
//! - E2: TPM Integration
//! - E3: Trust Score Calculation

use anyhow::Result;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::config::AttestationConfig;
use crate::crypto::sha256_file;

/// Attestation-related errors
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("Binary verification failed: expected {expected}, got {actual}")]
    BinaryMismatch { expected: String, actual: String },
    #[error("Process injection detected: {0}")]
    ProcessInjectionDetected(String),
    #[error("TPM operation failed: {0}")]
    TpmOperationFailed(String),
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
    #[error("Attestation failed: {0}")]
    AttestationFailed(String),
}

/// Trust score level based on thresholds (E3.7)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Score > 0.8: Full access
    FullAccess,
    /// Score 0.5-0.8: Limited access
    LimitedAccess,
    /// Score 0.3-0.5: Isolated
    Isolated,
    /// Score < 0.3: Terminate
    Terminated,
}

impl TrustLevel {
    pub fn from_score(score: f64, config: &AttestationConfig) -> Self {
        if score >= config.full_access_threshold as f64 {
            TrustLevel::FullAccess
        } else if score >= config.limited_access_threshold as f64 {
            TrustLevel::LimitedAccess
        } else if score >= config.termination_threshold as f64 {
            TrustLevel::Isolated
        } else {
            TrustLevel::Terminated
        }
    }
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustLevel::FullAccess => write!(f, "Full Access"),
            TrustLevel::LimitedAccess => write!(f, "Limited Access"),
            TrustLevel::Isolated => write!(f, "Isolated"),
            TrustLevel::Terminated => write!(f, "Terminated"),
        }
    }
}

/// Trust score components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScoreComponents {
    /// TPM attestation score (E3.2: 40%)
    pub tpm_score: f64,
    /// Process integrity score (E3.3: 25%)
    pub process_score: f64,
    /// Behavioral anomaly score (E3.4: 20%)
    pub behavioral_score: f64,
    /// Resource usage score (E3.5: 15%)
    pub resource_score: f64,
}

impl Default for TrustScoreComponents {
    fn default() -> Self {
        Self {
            tpm_score: 1.0,
            process_score: 1.0,
            behavioral_score: 1.0,
            resource_score: 1.0,
        }
    }
}

/// Trust score with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub service_id: String,
    pub score: f64,
    pub level: TrustLevel,
    pub components: TrustScoreComponents,
    pub reason: Option<String>,
    pub calculated_at: DateTime<Utc>,
}

/// Binary measurement for attestation (E1.1, E1.4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryMeasurement {
    pub path: PathBuf,
    pub sha256_hash: String,
    pub measured_at: DateTime<Utc>,
    pub size_bytes: u64,
}

/// Process information for monitoring (E1.2, E1.3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
    pub cmdline: Option<String>,
    pub uid: u32,
    pub start_time: DateTime<Utc>,
    pub children: Vec<u32>,
}

/// TPM PCR values (E2.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmPcrValues {
    pub pcr0: Option<String>,  // BIOS/firmware
    pub pcr1: Option<String>,  // BIOS configuration
    pub pcr2: Option<String>,  // Option ROMs
    pub pcr3: Option<String>,  // Option ROM configuration
    pub pcr4: Option<String>,  // MBR
    pub pcr5: Option<String>,  // MBR configuration
    pub pcr6: Option<String>,  // State transitions
    pub pcr7: Option<String>,  // Platform manufacturer control
}

/// TPM status (E2.1, E2.5)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmStatus {
    pub available: bool,
    pub version: Option<String>,
    pub manufacturer: Option<String>,
    pub pcr_values: Option<TpmPcrValues>,
    pub last_check: DateTime<Utc>,
}

/// Resource usage for scoring (E3.5)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub memory_percent: f64,
    pub open_files: u32,
    pub network_connections: u32,
    pub disk_io_bytes: u64,
}

/// Known good binary hashes for verification (E1.4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownGoodBinary {
    pub path: PathBuf,
    pub expected_hash: String,
    pub registered_at: DateTime<Utc>,
    pub description: Option<String>,
}

/// Service attestation state
#[derive(Debug, Clone)]
struct ServiceAttestationState {
    pub service_id: String,
    pub binary_measurement: Option<BinaryMeasurement>,
    pub known_good_hash: Option<String>,
    pub process_info: Option<ProcessInfo>,
    pub resource_usage: Option<ResourceUsage>,
    pub last_measurement: DateTime<Utc>,
    pub anomaly_count: u32,
}

/// Trust Manager (E1, E2, E3)
pub struct TrustManager {
    config: AttestationConfig,
    tpm_available: bool,
    tpm_status: Option<TpmStatus>,
    
    /// Service attestation states
    service_states: DashMap<String, ServiceAttestationState>,
    
    /// Trust scores cache
    trust_scores: DashMap<String, TrustScore>,
    
    /// Known good binaries
    known_good: DashMap<PathBuf, KnownGoodBinary>,
    
    /// Behavioral baselines for anomaly detection
    behavioral_baselines: DashMap<String, ResourceUsage>,
}

impl TrustManager {
    /// Create new trust manager
    pub fn new(tpm_enabled: bool, config: AttestationConfig) -> Result<Self> {
        let tpm_status = if tpm_enabled {
            Self::check_tpm_availability()
        } else {
            None
        };
        
        let tpm_available = tpm_status.as_ref().map(|s| s.available).unwrap_or(false);
        
        if tpm_enabled && !tpm_available {
            warn!("TPM requested but not available, using software fallback (E2.5)");
        }
        
        info!(
            "Trust manager initialized (TPM: {})",
            if tpm_available { "available" } else { "software mode" }
        );
        
        Ok(Self {
            config,
            tpm_available,
            tpm_status,
            service_states: DashMap::new(),
            trust_scores: DashMap::new(),
            known_good: DashMap::new(),
            behavioral_baselines: DashMap::new(),
        })
    }
    
    /// Check TPM 2.0 availability (E2.1)
    fn check_tpm_availability() -> Option<TpmStatus> {
        // Check if TPM device exists
        #[cfg(target_os = "linux")]
        {
            let tpm_path = Path::new("/dev/tpm0");
            let tpmrm_path = Path::new("/dev/tpmrm0");
            
            if tpm_path.exists() || tpmrm_path.exists() {
                // In production, would use tpm2-rs to communicate with TPM
                // For now, return simulated status
                return Some(TpmStatus {
                    available: true,
                    version: Some("2.0".to_string()),
                    manufacturer: Some("Simulated".to_string()),
                    pcr_values: None,
                    last_check: Utc::now(),
                });
            }
        }
        
        Some(TpmStatus {
            available: false,
            version: None,
            manufacturer: None,
            pcr_values: None,
            last_check: Utc::now(),
        })
    }
    
    /// Measure binary SHA-256 hash (E1.1)
    pub fn measure_binary(&self, path: &Path) -> Result<BinaryMeasurement> {
        if !path.exists() {
            return Err(anyhow::anyhow!("Binary not found: {:?}", path));
        }
        
        let metadata = std::fs::metadata(path)?;
        let hash_bytes = sha256_file(path)?;
        let hash = hex::encode(hash_bytes);
        
        let measurement = BinaryMeasurement {
            path: path.to_path_buf(),
            sha256_hash: hash,
            measured_at: Utc::now(),
            size_bytes: metadata.len(),
        };
        
        debug!("Measured binary {:?}: {}", path, measurement.sha256_hash);
        Ok(measurement)
    }
    
    /// Register a known good binary hash (E1.4)
    pub fn register_known_good(&self, path: &Path, hash: &str, description: Option<&str>) {
        let known_good = KnownGoodBinary {
            path: path.to_path_buf(),
            expected_hash: hash.to_string(),
            registered_at: Utc::now(),
            description: description.map(String::from),
        };
        
        self.known_good.insert(path.to_path_buf(), known_good);
        info!("Registered known good binary: {:?}", path);
    }
    
    /// Verify binary against known good hash (E1.4)
    pub fn verify_binary(&self, path: &Path) -> Result<bool, AttestationError> {
        let measurement = self.measure_binary(path)
            .map_err(|e| AttestationError::AttestationFailed(e.to_string()))?;
        
        if let Some(known) = self.known_good.get(path) {
            if measurement.sha256_hash == known.expected_hash {
                Ok(true)
            } else {
                Err(AttestationError::BinaryMismatch {
                    expected: known.expected_hash.clone(),
                    actual: measurement.sha256_hash,
                })
            }
        } else {
            // No known good hash registered
            Ok(true)
        }
    }
    
    /// Monitor process for injection (E1.2)
    /// Checks for ptrace, LD_PRELOAD, etc.
    pub fn check_process_integrity(&self, pid: u32) -> Result<bool, AttestationError> {
        #[cfg(target_os = "linux")]
        {
            // Check /proc/<pid>/status for TracerPid
            let status_path = format!("/proc/{}/status", pid);
            if let Ok(content) = std::fs::read_to_string(&status_path) {
                for line in content.lines() {
                    if line.starts_with("TracerPid:") {
                        let tracer_pid: u32 = line
                            .split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        
                        if tracer_pid != 0 {
                            return Err(AttestationError::ProcessInjectionDetected(
                                format!("Process {} is being traced by PID {}", pid, tracer_pid),
                            ));
                        }
                    }
                }
            }
            
            // Check for LD_PRELOAD in environment
            let environ_path = format!("/proc/{}/environ", pid);
            if let Ok(content) = std::fs::read_to_string(&environ_path) {
                if content.contains("LD_PRELOAD=") {
                    return Err(AttestationError::ProcessInjectionDetected(
                        format!("Process {} has LD_PRELOAD set", pid),
                    ));
                }
            }
        }
        
        Ok(true)
    }
    
    /// Get process information
    #[cfg(target_os = "linux")]
    fn get_process_info(&self, pid: u32) -> Option<ProcessInfo> {
        let status_path = format!("/proc/{}/status", pid);
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let exe_path = format!("/proc/{}/exe", pid);
        
        let status = std::fs::read_to_string(&status_path).ok()?;
        let cmdline = std::fs::read_to_string(&cmdline_path).ok();
        let exe = std::fs::read_link(&exe_path).ok();
        
        let mut ppid = 0u32;
        let mut uid = 0u32;
        let mut name = String::new();
        
        for line in status.lines() {
            if line.starts_with("PPid:") {
                ppid = line.split_whitespace().nth(1)?.parse().ok()?;
            } else if line.starts_with("Uid:") {
                uid = line.split_whitespace().nth(1)?.parse().ok()?;
            } else if line.starts_with("Name:") {
                name = line.split_whitespace().nth(1)?.to_string();
            }
        }
        
        Some(ProcessInfo {
            pid,
            ppid,
            name,
            exe_path: exe,
            cmdline: cmdline.map(|c| c.replace('\0', " ").trim().to_string()),
            uid,
            start_time: Utc::now(), // Would need to parse from /proc/<pid>/stat
            children: Vec::new(),
        })
    }
    
    #[cfg(not(target_os = "linux"))]
    fn get_process_info(&self, pid: u32) -> Option<ProcessInfo> {
        None
    }
    
    /// Calculate trust score for a service (E3.1)
    pub fn calculate_trust_score(&self, service_id: &str) -> TrustScore {
        let state = self.service_states.get(service_id);
        let components = self.calculate_score_components(state.as_deref());
        
        // Calculate weighted score (E3.2 - E3.5)
        let score = 
            components.tpm_score * self.config.tpm_weight as f64 +
            components.process_score * self.config.process_integrity_weight as f64 +
            components.behavioral_score * self.config.behavioral_weight as f64 +
            components.resource_score * self.config.resource_weight as f64;
        
        // Clamp to 0.0 - 1.0
        let score = score.max(0.0).min(1.0);
        let level = TrustLevel::from_score(score, &self.config);
        
        let reason = self.generate_score_reason(&components, score);
        
        let trust_score = TrustScore {
            service_id: service_id.to_string(),
            score,
            level,
            components,
            reason,
            calculated_at: Utc::now(),
        };
        
        // Cache the score
        self.trust_scores.insert(service_id.to_string(), trust_score.clone());
        
        debug!("Trust score for {}: {:.2} ({:?})", service_id, score, level);
        trust_score
    }
    
    /// Calculate individual score components
    fn calculate_score_components(
        &self,
        state: Option<&ServiceAttestationState>,
    ) -> TrustScoreComponents {
        let mut components = TrustScoreComponents::default();
        
        // TPM score (E3.2)
        if self.tpm_available {
            components.tpm_score = 1.0; // Would verify against TPM quote
        } else {
            // Software fallback: slightly lower confidence
            components.tpm_score = 0.9;
        }
        
        if let Some(state) = state {
            // Process integrity score (E3.3)
            if state.known_good_hash.is_some() {
                if let Some(ref measurement) = state.binary_measurement {
                    if state.known_good_hash.as_ref() == Some(&measurement.sha256_hash) {
                        components.process_score = 1.0;
                    } else {
                        components.process_score = 0.0; // Binary mismatch
                    }
                }
            }
            
            // Behavioral score (E3.4) - based on anomaly count
            components.behavioral_score = match state.anomaly_count {
                0 => 1.0,
                1..=2 => 0.8,
                3..=5 => 0.5,
                _ => 0.2,
            };
            
            // Resource score (E3.5)
            if let Some(ref usage) = state.resource_usage {
                let cpu_score = if usage.cpu_percent > 90.0 { 0.5 } else { 1.0 };
                let mem_score = if usage.memory_percent > 90.0 { 0.5 } else { 1.0 };
                components.resource_score = (cpu_score + mem_score) / 2.0;
            }
        }
        
        components
    }
    
    /// Generate human-readable reason for score
    fn generate_score_reason(&self, components: &TrustScoreComponents, _score: f64) -> Option<String> {
        let mut reasons = Vec::new();
        
        if !self.tpm_available {
            reasons.push("TPM not available (software fallback)");
        }
        
        if components.process_score < 1.0 {
            reasons.push("Process integrity issue detected");
        }
        
        if components.behavioral_score < 0.8 {
            reasons.push("Behavioral anomalies detected");
        }
        
        if components.resource_score < 0.8 {
            reasons.push("High resource usage");
        }
        
        if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("; "))
        }
    }
    
    /// Update service attestation state (E1.5 - re-measure on restart)
    pub fn update_service(&self, service_id: &str, binary_path: Option<&Path>, pid: Option<u32>) -> Result<()> {
        let mut state = self.service_states
            .entry(service_id.to_string())
            .or_insert_with(|| ServiceAttestationState {
                service_id: service_id.to_string(),
                binary_measurement: None,
                known_good_hash: None,
                process_info: None,
                resource_usage: None,
                last_measurement: Utc::now(),
                anomaly_count: 0,
            });
        
        // Re-measure binary
        if let Some(path) = binary_path {
            state.binary_measurement = self.measure_binary(path).ok();
            
            // Check against known good
            if let Some(known) = self.known_good.get(path) {
                state.known_good_hash = Some(known.expected_hash.clone());
            }
        }
        
        // Update process info
        if let Some(p) = pid {
            state.process_info = self.get_process_info(p);
        }
        
        state.last_measurement = Utc::now();
        
        Ok(())
    }
    
    /// Get trust score for a service
    pub fn get_trust_score(&self, service_id: &str) -> Option<TrustScore> {
        self.trust_scores.get(service_id).map(|s| s.clone())
    }
    
    /// Get all trust scores
    pub fn get_all_trust_scores(&self) -> Vec<TrustScore> {
        self.trust_scores.iter().map(|s| s.clone()).collect()
    }
    
    /// Get TPM status
    pub fn get_tpm_status(&self) -> Option<TpmStatus> {
        self.tpm_status.clone()
    }
    
    /// Check if TPM is available
    pub fn is_tpm_available(&self) -> bool {
        self.tpm_available
    }
    
    /// Record behavioral anomaly
    pub fn record_anomaly(&self, service_id: &str, description: &str) {
        if let Some(mut state) = self.service_states.get_mut(service_id) {
            state.anomaly_count += 1;
            warn!("Anomaly recorded for {}: {} (count: {})", 
                  service_id, description, state.anomaly_count);
        }
    }
    
    /// Update resource usage
    pub fn update_resource_usage(&self, service_id: &str, usage: ResourceUsage) {
        if let Some(mut state) = self.service_states.get_mut(service_id) {
            // Check for anomalies compared to baseline
            if let Some(baseline) = self.behavioral_baselines.get(service_id) {
                // CPU spike detection
                if usage.cpu_percent > baseline.cpu_percent * 3.0 {
                    state.anomaly_count += 1;
                }
                // Memory spike detection
                if usage.memory_percent > baseline.memory_percent * 2.0 {
                    state.anomaly_count += 1;
                }
            }
            
            state.resource_usage = Some(usage);
        }
    }
    
    /// Set behavioral baseline
    pub fn set_baseline(&self, service_id: &str, usage: ResourceUsage) {
        self.behavioral_baselines.insert(service_id.to_string(), usage);
    }
    
    /// Determine action based on trust level (E3.7)
    pub fn determine_action(&self, score: &TrustScore) -> TrustAction {
        match score.level {
            TrustLevel::FullAccess => TrustAction::Allow,
            TrustLevel::LimitedAccess => TrustAction::LimitAccess {
                read_only: true,
                rate_limited: true,
            },
            TrustLevel::Isolated => TrustAction::Isolate {
                alert_security: true,
            },
            TrustLevel::Terminated => TrustAction::Terminate,
        }
    }
}

/// Action to take based on trust level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustAction {
    /// Full access allowed
    Allow,
    /// Limited access (read-only, rate-limited)
    LimitAccess {
        read_only: bool,
        rate_limited: bool,
    },
    /// Service isolated, alert security team
    Isolate {
        alert_security: bool,
    },
    /// Terminate service
    Terminate,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn test_config() -> AttestationConfig {
        AttestationConfig {
            tpm_enabled: false,
            recalculation_interval_seconds: 30,
            tpm_weight: 0.40,
            process_integrity_weight: 0.25,
            behavioral_weight: 0.20,
            resource_weight: 0.15,
            full_access_threshold: 0.8,
            limited_access_threshold: 0.5,
            isolation_threshold: 0.3,
            termination_threshold: 0.3,
        }
    }
    
    #[test]
    fn test_trust_level_from_score() {
        let config = test_config();
        
        assert_eq!(TrustLevel::from_score(0.9, &config), TrustLevel::FullAccess);
        assert_eq!(TrustLevel::from_score(0.6, &config), TrustLevel::LimitedAccess);
        assert_eq!(TrustLevel::from_score(0.4, &config), TrustLevel::Isolated);
        assert_eq!(TrustLevel::from_score(0.2, &config), TrustLevel::Terminated);
    }
    
    #[test]
    fn test_trust_score_calculation() {
        let config = test_config();
        let manager = TrustManager::new(false, config).unwrap();
        
        let score = manager.calculate_trust_score("test-service");
        
        assert!(score.score >= 0.0 && score.score <= 1.0);
    }
    
    #[test]
    fn test_default_components() {
        let components = TrustScoreComponents::default();
        
        assert_eq!(components.tpm_score, 1.0);
        assert_eq!(components.process_score, 1.0);
        assert_eq!(components.behavioral_score, 1.0);
        assert_eq!(components.resource_score, 1.0);
    }
}
