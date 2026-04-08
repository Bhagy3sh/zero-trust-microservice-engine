//! Dashboard data Tauri commands

use serde::{Deserialize, Serialize};
use tauri::command;

use crate::get_app_state;

/// Dashboard data response
#[derive(Debug, Serialize)]
pub struct DashboardDataResponse {
    pub services: ServiceSummary,
    pub attacks: AttackSummary,
    pub policies: PolicySummary,
    pub alerts: AlertSummary,
    pub tunnels: TunnelSummary,
}

#[derive(Debug, Serialize)]
pub struct ServiceSummary {
    pub total: u64,
    pub active: u64,
    pub healthy: u64,
    pub warning: u64,
    pub critical: u64,
}

#[derive(Debug, Serialize)]
pub struct AttackSummary {
    pub total_24h: u64,
    pub blocked_24h: u64,
    pub by_hour: Vec<HourlyCount>,
    pub top_types: Vec<(String, i64)>,
}

#[derive(Debug, Serialize)]
pub struct HourlyCount {
    pub hour: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct PolicySummary {
    pub total: u64,
    pub enabled: u64,
    pub recent_hits: u64,
}

#[derive(Debug, Serialize)]
pub struct AlertSummary {
    pub total: u64,
    pub unacknowledged: u64,
    pub critical: u64,
    pub high: u64,
}

#[derive(Debug, Serialize)]
pub struct TunnelSummary {
    pub total: u64,
    pub active: u64,
    pub bytes_transferred: u64,
}

/// Service topology node
#[derive(Debug, Serialize)]
pub struct TopologyNode {
    pub id: String,
    pub name: String,
    pub trust_score: f64,
    pub status: String,
}

/// Service topology edge (tunnel)
#[derive(Debug, Serialize)]
pub struct TopologyEdge {
    pub source: String,
    pub target: String,
    pub status: String,
}

/// Service topology response (F3.1)
#[derive(Debug, Serialize)]
pub struct ServiceTopologyResponse {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

/// Get dashboard data
#[command]
pub async fn get_dashboard_data() -> Result<DashboardDataResponse, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    let now = chrono::Utc::now();
    let day_ago = (now - chrono::Duration::hours(24)).to_rfc3339();
    
    // Service summary
    let total_services: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM services",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let active_services: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM services WHERE status = 'active'",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let healthy_services: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM services WHERE trust_score >= 0.8",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let warning_services: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM services WHERE trust_score >= 0.5 AND trust_score < 0.8",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let critical_services: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM services WHERE trust_score < 0.5",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    // Attack summary
    let total_attacks: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM attacks WHERE created_at > ?1",
        &[&day_ago],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let blocked_attacks: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM attacks WHERE created_at > ?1 AND blocked = 1",
        &[&day_ago],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let top_types: Vec<(String, i64)> = state.db.query_map(
        "SELECT attack_type, COUNT(*) FROM attacks 
         WHERE created_at > ?1 GROUP BY attack_type ORDER BY COUNT(*) DESC LIMIT 5",
        &[&day_ago],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap_or_default();
    
    // Policy summary
    let total_policies: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM policies",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let enabled_policies: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM policies WHERE enabled = 1",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let recent_hits: i64 = state.db.query_map(
        "SELECT SUM(hit_count) FROM policies",
        &[],
        |row| row.get::<_, Option<i64>>(0).map(|v| v.unwrap_or(0)),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    // Alert summary
    let total_alerts: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM alerts",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let unacknowledged_alerts: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let critical_alerts: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'Critical' AND acknowledged = 0",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let high_alerts: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'High' AND acknowledged = 0",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    // Tunnel summary
    let total_tunnels: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM tunnels",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let active_tunnels: i64 = state.db.query_map(
        "SELECT COUNT(*) FROM tunnels WHERE status = 'active'",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    let bytes_transferred: i64 = state.db.query_map(
        "SELECT COALESCE(SUM(bytes_sent + bytes_received), 0) FROM tunnels",
        &[],
        |row| row.get(0),
    ).unwrap_or_default().first().copied().unwrap_or(0);
    
    Ok(DashboardDataResponse {
        services: ServiceSummary {
            total: total_services as u64,
            active: active_services as u64,
            healthy: healthy_services as u64,
            warning: warning_services as u64,
            critical: critical_services as u64,
        },
        attacks: AttackSummary {
            total_24h: total_attacks as u64,
            blocked_24h: blocked_attacks as u64,
            by_hour: vec![], // Would aggregate by hour
            top_types,
        },
        policies: PolicySummary {
            total: total_policies as u64,
            enabled: enabled_policies as u64,
            recent_hits: recent_hits as u64,
        },
        alerts: AlertSummary {
            total: total_alerts as u64,
            unacknowledged: unacknowledged_alerts as u64,
            critical: critical_alerts as u64,
            high: high_alerts as u64,
        },
        tunnels: TunnelSummary {
            total: total_tunnels as u64,
            active: active_tunnels as u64,
            bytes_transferred: bytes_transferred as u64,
        },
    })
}

/// Get service topology (F3.1)
#[command]
pub async fn get_service_topology() -> Result<ServiceTopologyResponse, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    // Get all services as nodes
    let nodes: Vec<TopologyNode> = state.db.query_map(
        "SELECT id, name, trust_score, status FROM services WHERE status != 'inactive'",
        &[],
        |row| {
            Ok(TopologyNode {
                id: row.get(0)?,
                name: row.get(1)?,
                trust_score: row.get(2)?,
                status: row.get(3)?,
            })
        },
    ).map_err(|e| e.to_string())?;
    
    // Get all tunnels as edges
    let edges: Vec<TopologyEdge> = state.db.query_map(
        "SELECT service_a_id, service_b_id, status FROM tunnels",
        &[],
        |row| {
            Ok(TopologyEdge {
                source: row.get(0)?,
                target: row.get(1)?,
                status: row.get(2)?,
            })
        },
    ).map_err(|e| e.to_string())?;
    
    Ok(ServiceTopologyResponse { nodes, edges })
}
