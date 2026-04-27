//! Audit logging Tauri commands

use serde::Serialize;
use tauri::command;

use crate::get_app_state;

/// Audit log response
#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub id: i64,
    pub event_type: String,
    pub action: String,
    pub subject: Option<String>,
    pub details: Option<String>,
    pub source_ip: Option<String>,
    pub user: Option<String>,
    pub success: bool,
    pub created_at: String,
}

/// Get audit logs (G1)
#[command]
pub async fn get_audit_logs(
    event_type: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<Vec<AuditLogResponse>, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    let limit = limit.unwrap_or(100);
    let offset = offset.unwrap_or(0);
    
    // Use parameterized queries to prevent SQL injection
    let logs: Vec<AuditLogResponse> = if let Some(ref et) = event_type {
        let sql = format!(
            "SELECT id, event_type, action, subject, details, source_ip, user, success, created_at
             FROM audit_logs WHERE event_type = ?1
             ORDER BY created_at DESC LIMIT {} OFFSET {}",
            limit, offset
        );
        state.db.query_map(
            &sql,
            &[et as &dyn rusqlite::ToSql],
            |row| {
                Ok(AuditLogResponse {
                    id: row.get(0)?,
                    event_type: row.get(1)?,
                    action: row.get(2)?,
                    subject: row.get(3)?,
                    details: row.get(4)?,
                    source_ip: row.get(5)?,
                    user: row.get(6)?,
                    success: row.get(7)?,
                    created_at: row.get(8)?,
                })
            },
        ).map_err(|e| e.to_string())?
    } else {
        let sql = format!(
            "SELECT id, event_type, action, subject, details, source_ip, user, success, created_at
             FROM audit_logs ORDER BY created_at DESC LIMIT {} OFFSET {}",
            limit, offset
        );
        state.db.query_map(
            &sql,
            &[],
            |row| {
                Ok(AuditLogResponse {
                    id: row.get(0)?,
                    event_type: row.get(1)?,
                    action: row.get(2)?,
                    subject: row.get(3)?,
                    details: row.get(4)?,
                    source_ip: row.get(5)?,
                    user: row.get(6)?,
                    success: row.get(7)?,
                    created_at: row.get(8)?,
                })
            },
        ).map_err(|e| e.to_string())?
    };
    
    Ok(logs)
}

/// Export logs as JSON file (G2)
#[command]
pub async fn export_logs(
    start_date: Option<String>,
    end_date: Option<String>,
) -> Result<String, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    let logs: Vec<AuditLogResponse> = match (&start_date, &end_date) {
        (Some(start), Some(end)) => {
            let sql = "SELECT id, event_type, action, subject, details, source_ip, user, success, created_at
                       FROM audit_logs WHERE created_at >= ?1 AND created_at <= ?2 ORDER BY created_at";
            state.db.query_map(sql, &[start as &dyn rusqlite::ToSql, end], |row| {
                Ok(AuditLogResponse {
                    id: row.get(0)?,
                    event_type: row.get(1)?,
                    action: row.get(2)?,
                    subject: row.get(3)?,
                    details: row.get(4)?,
                    source_ip: row.get(5)?,
                    user: row.get(6)?,
                    success: row.get(7)?,
                    created_at: row.get(8)?,
                })
            }).map_err(|e| e.to_string())?
        }
        (Some(start), None) => {
            let sql = "SELECT id, event_type, action, subject, details, source_ip, user, success, created_at
                       FROM audit_logs WHERE created_at >= ?1 ORDER BY created_at";
            state.db.query_map(sql, &[start as &dyn rusqlite::ToSql], |row| {
                Ok(AuditLogResponse {
                    id: row.get(0)?,
                    event_type: row.get(1)?,
                    action: row.get(2)?,
                    subject: row.get(3)?,
                    details: row.get(4)?,
                    source_ip: row.get(5)?,
                    user: row.get(6)?,
                    success: row.get(7)?,
                    created_at: row.get(8)?,
                })
            }).map_err(|e| e.to_string())?
        }
        (None, Some(end)) => {
            let sql = "SELECT id, event_type, action, subject, details, source_ip, user, success, created_at
                       FROM audit_logs WHERE created_at <= ?1 ORDER BY created_at";
            state.db.query_map(sql, &[end as &dyn rusqlite::ToSql], |row| {
                Ok(AuditLogResponse {
                    id: row.get(0)?,
                    event_type: row.get(1)?,
                    action: row.get(2)?,
                    subject: row.get(3)?,
                    details: row.get(4)?,
                    source_ip: row.get(5)?,
                    user: row.get(6)?,
                    success: row.get(7)?,
                    created_at: row.get(8)?,
                })
            }).map_err(|e| e.to_string())?
        }
        (None, None) => {
            let sql = "SELECT id, event_type, action, subject, details, source_ip, user, success, created_at
                       FROM audit_logs ORDER BY created_at";
            state.db.query_map(sql, &[], |row| {
                Ok(AuditLogResponse {
                    id: row.get(0)?,
                    event_type: row.get(1)?,
                    action: row.get(2)?,
                    subject: row.get(3)?,
                    details: row.get(4)?,
                    source_ip: row.get(5)?,
                    user: row.get(6)?,
                    success: row.get(7)?,
                    created_at: row.get(8)?,
                })
            }).map_err(|e| e.to_string())?
        }
    };
    
    let json = serde_json::to_string_pretty(&logs).map_err(|e| e.to_string())?;
    
    // Write to a timestamped file in the system temp directory
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let export_path = std::env::temp_dir().join(format!("zerotrust-audit-{}.json", timestamp));
    std::fs::write(&export_path, &json).map_err(|e| format!("Failed to write export file: {}", e))?;
    
    Ok(export_path.to_string_lossy().to_string())
}
