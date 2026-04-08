//! Identity management Tauri commands

use serde::{Deserialize, Serialize};
use tauri::command;
use tracing::{info, error};

use crate::{get_app_state};

/// Service registration request
#[derive(Debug, Deserialize)]
pub struct RegisterServiceRequest {
    pub name: String,
    pub port: u16,
    pub description: Option<String>,
    pub binary_path: Option<String>,
}

/// Service response
#[derive(Debug, Serialize)]
pub struct ServiceResponse {
    pub id: String,
    pub spiffe_id: String,
    pub name: String,
    pub description: Option<String>,
    pub port: u16,
    pub status: String,
    pub trust_score: f64,
}

/// Register a new service (A2.2)
#[command]
pub async fn register_service(request: RegisterServiceRequest) -> Result<ServiceResponse, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    let mut provider = state.identity_provider.write();
    
    let binary_path = request.binary_path.as_ref().map(std::path::Path::new);
    
    let (service, _cert) = provider
        .register_service(
            &request.name,
            request.port,
            request.description.as_deref(),
            binary_path,
        )
        .map_err(|e| e.to_string())?;
    
    // Store in database
    state.db.execute(
        "INSERT INTO services (id, spiffe_id, name, description, port, binary_path, status, trust_score)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        &[
            &service.id,
            &service.spiffe_id.to_uri(),
            &service.name,
            &service.description,
            &(service.port as i32),
            &request.binary_path,
            &service.status.to_string(),
            &service.trust_score,
        ],
    ).map_err(|e| e.to_string())?;
    
    // Log audit event (G1.2)
    state.db.execute(
        "INSERT INTO audit_logs (event_type, action, subject, details, success)
         VALUES ('identity', 'register_service', ?1, ?2, 1)",
        &[&service.id, &format!("Registered service: {}", service.name)],
    ).ok();
    
    info!("Registered service: {} ({})", service.name, service.id);
    
    Ok(ServiceResponse {
        id: service.id,
        spiffe_id: service.spiffe_id.to_uri(),
        name: service.name,
        description: service.description,
        port: service.port,
        status: service.status.to_string(),
        trust_score: service.trust_score,
    })
}

/// Deregister a service (A2.6)
#[command]
pub async fn deregister_service(service_id: String) -> Result<(), String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    state.db.execute(
        "UPDATE services SET status = 'inactive' WHERE id = ?1",
        &[&service_id],
    ).map_err(|e| e.to_string())?;
    
    // Log audit event
    state.db.execute(
        "INSERT INTO audit_logs (event_type, action, subject, success)
         VALUES ('identity', 'deregister_service', ?1, 1)",
        &[&service_id],
    ).ok();
    
    info!("Deregistered service: {}", service_id);
    Ok(())
}

/// List all services
#[command]
pub async fn list_services() -> Result<Vec<ServiceResponse>, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    let services: Vec<ServiceResponse> = state.db.query_map(
        "SELECT id, spiffe_id, name, description, port, status, trust_score 
         FROM services WHERE status != 'inactive' ORDER BY name",
        &[],
        |row| {
            Ok(ServiceResponse {
                id: row.get(0)?,
                spiffe_id: row.get(1)?,
                name: row.get(2)?,
                description: row.get(3)?,
                port: row.get::<_, i32>(4)? as u16,
                status: row.get(5)?,
                trust_score: row.get(6)?,
            })
        },
    ).map_err(|e| e.to_string())?;
    
    Ok(services)
}

/// Get a single service
#[command]
pub async fn get_service(service_id: String) -> Result<ServiceResponse, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    let services: Vec<ServiceResponse> = state.db.query_map(
        "SELECT id, spiffe_id, name, description, port, status, trust_score 
         FROM services WHERE id = ?1",
        &[&service_id],
        |row| {
            Ok(ServiceResponse {
                id: row.get(0)?,
                spiffe_id: row.get(1)?,
                name: row.get(2)?,
                description: row.get(3)?,
                port: row.get::<_, i32>(4)? as u16,
                status: row.get(5)?,
                trust_score: row.get(6)?,
            })
        },
    ).map_err(|e| e.to_string())?;
    
    services.into_iter().next()
        .ok_or_else(|| format!("Service not found: {}", service_id))
}

/// Issue JWT-SVID for a service (A1.2)
#[command]
pub async fn issue_jwt_svid(service_id: String, audience: Vec<String>) -> Result<String, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    // Get service from database
    let services: Vec<(String, String, f64)> = state.db.query_map(
        "SELECT spiffe_id, name, trust_score FROM services WHERE id = ?1",
        &[&service_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(|e| e.to_string())?;
    
    let (spiffe_id_str, name, trust_score) = services.into_iter().next()
        .ok_or_else(|| format!("Service not found: {}", service_id))?;
    
    let spiffe_id = zerotrust_mesh_lib::identity::SpiffeId::from_uri(&spiffe_id_str)
        .map_err(|e| e.to_string())?;
    
    let service = zerotrust_mesh_lib::identity::Service {
        id: service_id.clone(),
        spiffe_id,
        name,
        description: None,
        port: 0,
        binary_path: None,
        binary_hash: None,
        user: None,
        pid: None,
        status: zerotrust_mesh_lib::identity::ServiceStatus::Active,
        trust_score,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    
    let provider = state.identity_provider.read();
    let token = provider.issue_jwt_svid(&service, audience)
        .map_err(|e| e.to_string())?;
    
    // Log audit event (A1.8)
    state.db.execute(
        "INSERT INTO audit_logs (event_type, action, subject, success)
         VALUES ('identity', 'issue_jwt', ?1, 1)",
        &[&service_id],
    ).ok();
    
    Ok(token)
}

/// Verify JWT-SVID (A3.2)
#[command]
pub async fn verify_svid(token: String) -> Result<bool, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    let provider = state.identity_provider.read();
    
    match provider.verify_jwt_svid(&token) {
        Ok(_claims) => Ok(true),
        Err(e) => {
            error!("SVID verification failed: {}", e);
            Ok(false)
        }
    }
}
