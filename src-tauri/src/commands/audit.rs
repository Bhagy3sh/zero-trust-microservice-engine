//! Audit logging Tauri commands

use serde::{Deserialize, Serialize};
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
    
    let sql = if let Some(ref et) = event_type {
        format!(
            "SELECT id, event_type, action, subject, details, source_ip, user, success, created_at
             FROM audit_logs WHERE event_type = '{}' 
             ORDER BY created_at DESC LIMIT {} OFFSET {}",
            et, limit, offset
        )
    } else {
        format!(
            "SELECT id, event_type, action, subject, details, source_ip, user, success, created_at
             FROM audit_logs ORDER BY created_at DESC LIMIT {} OFFSET {}",
            limit, offset
        )
    };
    
    let logs: Vec<AuditLogResponse> = state.db.query_map(
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
    ).map_err(|e| e.to_string())?;
    
    Ok(logs)
}

/// Export logs as JSON (G2)
#[command]
pub async fn export_logs(
    start_date: Option<String>,
    end_date: Option<String>,
) -> Result<String, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    let sql = match (&start_date, &end_date) {
        (Some(start), Some(end)) => format!(
            "SELECT id, event_type, action, subject, details, source_ip, user, success, created_at
             FROM audit_logs WHERE created_at >= '{}' AND created_at <= '{}' ORDER BY created_at",
            start, end
        ),
        (Some(start), None) => format!(
            "SELECT id, event_type, action, subject, details, source_ip, user, success, created_at
             FROM audit_logs WHERE created_at >= '{}' ORDER BY created_at",
            start
        ),
        (None, Some(end)) => format!(
            "SELECT id, event_type, action, subject, details, source_ip, user, success, created_at
             FROM audit_logs WHERE created_at <= '{}' ORDER BY created_at",
            end
        ),
        (None, None) => {
            "SELECT id, event_type, action, subject, details, source_ip, user, success, created_at
             FROM audit_logs ORDER BY created_at".to_string()
        }
    };
    
    let logs: Vec<AuditLogResponse> = state.db.query_map(
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
    ).map_err(|e| e.to_string())?;
    
    serde_json::to_string_pretty(&logs).map_err(|e| e.to_string())
}
