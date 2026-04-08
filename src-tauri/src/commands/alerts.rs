//! Alert management Tauri commands

use serde::{Deserialize, Serialize};
use tauri::command;
use tracing::info;

use crate::get_app_state;

/// Alert response
#[derive(Debug, Serialize)]
pub struct AlertResponse {
    pub id: i64,
    pub alert_type: String,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub source: Option<String>,
    pub acknowledged: bool,
    pub acknowledged_at: Option<String>,
    pub muted: bool,
    pub created_at: String,
}

/// Get alerts (F2.1)
#[command]
pub async fn get_alerts(
    limit: Option<u32>,
    unacknowledged_only: Option<bool>,
) -> Result<Vec<AlertResponse>, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    let limit = limit.unwrap_or(100);
    let unacknowledged_only = unacknowledged_only.unwrap_or(false);
    
    let sql = if unacknowledged_only {
        format!(
            "SELECT id, alert_type, severity, title, message, source, acknowledged, 
             acknowledged_at, muted, created_at 
             FROM alerts WHERE acknowledged = 0 ORDER BY created_at DESC LIMIT {}",
            limit
        )
    } else {
        format!(
            "SELECT id, alert_type, severity, title, message, source, acknowledged, 
             acknowledged_at, muted, created_at 
             FROM alerts ORDER BY created_at DESC LIMIT {}",
            limit
        )
    };
    
    let alerts: Vec<AlertResponse> = state.db.query_map(
        &sql,
        &[],
        |row| {
            Ok(AlertResponse {
                id: row.get(0)?,
                alert_type: row.get(1)?,
                severity: row.get(2)?,
                title: row.get(3)?,
                message: row.get(4)?,
                source: row.get(5)?,
                acknowledged: row.get(6)?,
                acknowledged_at: row.get(7)?,
                muted: row.get(8)?,
                created_at: row.get(9)?,
            })
        },
    ).map_err(|e| e.to_string())?;
    
    Ok(alerts)
}

/// Acknowledge an alert (F2.2)
#[command]
pub async fn acknowledge_alert(alert_id: i64) -> Result<(), String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    state.db.execute(
        "UPDATE alerts SET acknowledged = 1, acknowledged_at = ?1 WHERE id = ?2",
        &[&chrono::Utc::now().to_rfc3339(), &alert_id],
    ).map_err(|e| e.to_string())?;
    
    info!("Acknowledged alert: {}", alert_id);
    Ok(())
}

/// Mute alerts by type or source (F2.3)
#[command]
pub async fn mute_alert_type(alert_type: String) -> Result<(), String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    state.db.execute(
        "UPDATE alerts SET muted = 1 WHERE alert_type = ?1",
        &[&alert_type],
    ).map_err(|e| e.to_string())?;
    
    info!("Muted alert type: {}", alert_type);
    Ok(())
}
