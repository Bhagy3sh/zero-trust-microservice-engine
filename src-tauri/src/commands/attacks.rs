//! Attack detection Tauri commands

use serde::{Deserialize, Serialize};
use tauri::command;
use tracing::info;

use crate::get_app_state;

/// Attack statistics response
#[derive(Debug, Serialize)]
pub struct AttackStatsResponse {
    pub total_24h: u64,
    pub blocked_24h: u64,
    pub by_type: Vec<(String, i64)>,
    pub top_attackers: Vec<(String, i64)>,
    pub blacklist_count: u64,
}

/// Attack event response
#[derive(Debug, Serialize)]
pub struct AttackEventResponse {
    pub id: i64,
    pub attack_type: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub destination_port: Option<i32>,
    pub severity: String,
    pub packet_count: i64,
    pub blocked: bool,
    pub created_at: String,
}

/// Blacklist entry response
#[derive(Debug, Serialize)]
pub struct BlacklistEntryResponse {
    pub ip: String,
    pub reason: String,
    pub expires_at: Option<String>,
    pub created_at: String,
}

/// Get attack statistics (F1.3)
#[command]
pub async fn get_attack_stats() -> Result<AttackStatsResponse, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    // Query database for attack statistics
    let day_ago = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    
    let by_type: Vec<(String, i64)> = state.db.query_map(
        "SELECT attack_type, COUNT(*) FROM attacks 
         WHERE created_at > ?1 GROUP BY attack_type ORDER BY COUNT(*) DESC LIMIT 5",
        &[&day_ago],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap_or_default();
    
    let top_attackers: Vec<(String, i64)> = state.db.query_map(
        "SELECT source_ip, COUNT(*) FROM attacks 
         WHERE created_at > ?1 GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 5",
        &[&day_ago],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap_or_default();
    
    let total: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM attacks WHERE created_at > ?1",
        &[&day_ago],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let blocked: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM attacks WHERE created_at > ?1 AND blocked = 1",
        &[&day_ago],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let blacklist_count: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM blacklist",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    Ok(AttackStatsResponse {
        total_24h: total as u64,
        blocked_24h: blocked as u64,
        by_type,
        top_attackers,
        blacklist_count: blacklist_count as u64,
    })
}

/// Get recent attacks (F1.2)
#[command]
pub async fn get_recent_attacks(limit: Option<u32>) -> Result<Vec<AttackEventResponse>, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    let limit = limit.unwrap_or(100);
    
    let attacks: Vec<AttackEventResponse> = state.db.query_map(
        &format!(
            "SELECT id, attack_type, source_ip, destination_ip, destination_port, 
             severity, packet_count, blocked, created_at 
             FROM attacks ORDER BY created_at DESC LIMIT {}",
            limit
        ),
        &[],
        |row| {
            Ok(AttackEventResponse {
                id: row.get(0)?,
                attack_type: row.get(1)?,
                source_ip: row.get(2)?,
                destination_ip: row.get(3)?,
                destination_port: row.get(4)?,
                severity: row.get(5)?,
                packet_count: row.get(6)?,
                blocked: row.get(7)?,
                created_at: row.get(8)?,
            })
        },
    ).map_err(|e| e.to_string())?;
    
    Ok(attacks)
}

/// Blacklist an IP (D3.5)
#[command]
pub async fn blacklist_ip(
    ip: String,
    reason: String,
    duration_hours: Option<u32>,
) -> Result<(), String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    let expires_at = duration_hours.map(|h| {
        (chrono::Utc::now() + chrono::Duration::hours(h as i64)).to_rfc3339()
    });
    
    state.db.execute(
        "INSERT OR REPLACE INTO blacklist (ip, reason, auto_generated, expires_at, created_at)
         VALUES (?1, ?2, 0, ?3, ?4)",
        &[&ip, &reason, &expires_at, &chrono::Utc::now().to_rfc3339()],
    ).map_err(|e| e.to_string())?;
    
    info!("Blacklisted IP {}: {}", ip, reason);
    Ok(())
}

/// Whitelist an IP (D3.4)
#[command]
pub async fn whitelist_ip(ip: String, description: String) -> Result<(), String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    // Remove from blacklist if present
    state.db.execute("DELETE FROM blacklist WHERE ip = ?1", &[&ip]).ok();
    
    // Add to whitelist
    state.db.execute(
        "INSERT OR REPLACE INTO whitelist (ip, description, created_at)
         VALUES (?1, ?2, ?3)",
        &[&ip, &description, &chrono::Utc::now().to_rfc3339()],
    ).map_err(|e| e.to_string())?;
    
    info!("Whitelisted IP {}: {}", ip, description);
    Ok(())
}

/// Get blacklist
#[command]
pub async fn get_blacklist() -> Result<Vec<BlacklistEntryResponse>, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    let entries: Vec<BlacklistEntryResponse> = state.db.query_map(
        "SELECT ip, reason, expires_at, created_at FROM blacklist ORDER BY created_at DESC",
        &[],
        |row| {
            Ok(BlacklistEntryResponse {
                ip: row.get(0)?,
                reason: row.get(1)?,
                expires_at: row.get(2)?,
                created_at: row.get(3)?,
            })
        },
    ).map_err(|e| e.to_string())?;
    
    Ok(entries)
}
