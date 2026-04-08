//! Attestation and trust scoring Tauri commands

use serde::{Deserialize, Serialize};
use tauri::command;
use tracing::info;

use crate::get_app_state;

/// Trust score response
#[derive(Debug, Serialize)]
pub struct TrustScoreResponse {
    pub service_id: String,
    pub score: f64,
    pub level: String,
    pub tpm_score: f64,
    pub process_score: f64,
    pub behavioral_score: f64,
    pub resource_score: f64,
    pub reason: Option<String>,
    pub calculated_at: String,
}

/// TPM status response
#[derive(Debug, Serialize)]
pub struct TpmStatusResponse {
    pub available: bool,
    pub version: Option<String>,
    pub manufacturer: Option<String>,
    pub last_check: String,
}

/// Binary measurement response
#[derive(Debug, Serialize)]
pub struct BinaryMeasurementResponse {
    pub path: String,
    pub sha256_hash: String,
    pub size_bytes: u64,
    pub measured_at: String,
}

/// Get trust score for a service (E3.1)
#[command]
pub async fn get_trust_score(service_id: String) -> Result<TrustScoreResponse, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    let trust_manager = state.trust_manager.read();
    
    let score = trust_manager.calculate_trust_score(&service_id);
    
    Ok(TrustScoreResponse {
        service_id: score.service_id,
        score: score.score,
        level: format!("{}", score.level),
        tpm_score: score.components.tpm_score,
        process_score: score.components.process_score,
        behavioral_score: score.components.behavioral_score,
        resource_score: score.components.resource_score,
        reason: score.reason,
        calculated_at: score.calculated_at.to_rfc3339(),
    })
}

/// List all trust scores
#[command]
pub async fn list_trust_scores() -> Result<Vec<TrustScoreResponse>, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    let trust_manager = state.trust_manager.read();
    
    let scores = trust_manager.get_all_trust_scores();
    
    Ok(scores.into_iter().map(|score| TrustScoreResponse {
        service_id: score.service_id,
        score: score.score,
        level: format!("{}", score.level),
        tpm_score: score.components.tpm_score,
        process_score: score.components.process_score,
        behavioral_score: score.components.behavioral_score,
        resource_score: score.components.resource_score,
        reason: score.reason,
        calculated_at: score.calculated_at.to_rfc3339(),
    }).collect())
}

/// Measure binary hash (E1.1)
#[command]
pub async fn measure_binary(path: String) -> Result<BinaryMeasurementResponse, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    let trust_manager = state.trust_manager.read();
    
    let measurement = trust_manager
        .measure_binary(std::path::Path::new(&path))
        .map_err(|e| e.to_string())?;
    
    info!("Measured binary {}: {}", path, measurement.sha256_hash);
    
    Ok(BinaryMeasurementResponse {
        path: measurement.path.to_string_lossy().to_string(),
        sha256_hash: measurement.sha256_hash,
        size_bytes: measurement.size_bytes,
        measured_at: measurement.measured_at.to_rfc3339(),
    })
}

/// Get TPM status (E2.1)
#[command]
pub async fn get_tpm_status() -> Result<TpmStatusResponse, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    let trust_manager = state.trust_manager.read();
    
    if let Some(status) = trust_manager.get_tpm_status() {
        Ok(TpmStatusResponse {
            available: status.available,
            version: status.version,
            manufacturer: status.manufacturer,
            last_check: status.last_check.to_rfc3339(),
        })
    } else {
        Ok(TpmStatusResponse {
            available: false,
            version: None,
            manufacturer: None,
            last_check: chrono::Utc::now().to_rfc3339(),
        })
    }
}
