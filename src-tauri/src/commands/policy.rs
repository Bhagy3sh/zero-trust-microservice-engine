//! Policy management Tauri commands

use serde::{Deserialize, Serialize};
use tauri::command;
use tracing::info;

use crate::get_app_state;
use zerotrust_mesh_lib::policy::{Policy, PolicyAction, PolicyCondition};

/// Policy response for frontend
#[derive(Debug, Serialize)]
pub struct PolicyResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub enabled: bool,
    pub conditions: serde_json::Value,
    pub action: String,
    pub hit_count: u64,
    pub last_match: Option<String>,
}

/// Create policy request
#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
}

/// Evaluation request
#[derive(Debug, Deserialize)]
pub struct EvaluateRequest {
    pub source_spiffe_id: Option<String>,
    pub source_ip: Option<String>,
    pub dest_spiffe_id: Option<String>,
    pub dest_port: Option<u16>,
    pub method: Option<String>,
    pub trust_score: Option<f64>,
}

/// Evaluation response
#[derive(Debug, Serialize)]
pub struct EvaluationResponse {
    pub action: String,
    pub matched_policy_id: Option<String>,
    pub matched_policy_name: Option<String>,
    pub deny_reason: Option<String>,
    pub evaluation_time_us: u64,
}

/// Create a new policy (B3.1)
#[command]
pub async fn create_policy(request: CreatePolicyRequest) -> Result<PolicyResponse, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    let action = match request.action.as_str() {
        "Allow" => PolicyAction::Allow,
        "Deny" => PolicyAction::Deny,
        "RequireMFA" => PolicyAction::RequireMFA,
        "Log" => PolicyAction::Log,
        _ => return Err(format!("Invalid action: {}", request.action)),
    };
    
    let conditions: Vec<PolicyCondition> = serde_json::from_value(request.conditions.clone())
        .map_err(|e| format!("Invalid conditions: {}", e))?;
    
    let mut policy = Policy::new(&request.name, request.priority, action);
    policy.description = request.description.clone();
    for condition in conditions {
        policy.conditions.push(condition);
    }
    
    // Validate policy (B3.5)
    policy.validate().map_err(|e| format!("Validation failed: {}", e))?;
    
    let mut engine = state.policy_engine.write();
    engine.add_policy(policy.clone()).map_err(|e| e.to_string())?;
    
    // Log audit event (G1.3)
    state.db.execute(
        "INSERT INTO audit_logs (event_type, action, subject, details, success)
         VALUES ('policy', 'create', ?1, ?2, 1)",
        &[&policy.id, &format!("Created policy: {}", policy.name)],
    ).ok();
    
    info!("Created policy: {} ({})", policy.name, policy.id);
    
    Ok(PolicyResponse {
        id: policy.id,
        name: policy.name,
        description: policy.description,
        priority: policy.priority,
        enabled: policy.enabled,
        conditions: request.conditions,
        action: request.action,
        hit_count: 0,
        last_match: None,
    })
}

/// Update an existing policy
#[command]
pub async fn update_policy(
    policy_id: String,
    request: CreatePolicyRequest,
) -> Result<PolicyResponse, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    // Delete old policy and create new one with same ID
    let mut engine = state.policy_engine.write();
    engine.remove_policy(&policy_id).map_err(|e| e.to_string())?;
    
    let action = match request.action.as_str() {
        "Allow" => PolicyAction::Allow,
        "Deny" => PolicyAction::Deny,
        "RequireMFA" => PolicyAction::RequireMFA,
        "Log" => PolicyAction::Log,
        _ => return Err(format!("Invalid action: {}", request.action)),
    };
    
    let conditions: Vec<PolicyCondition> = serde_json::from_value(request.conditions.clone())
        .map_err(|e| format!("Invalid conditions: {}", e))?;
    
    let mut policy = Policy::new(&request.name, request.priority, action);
    policy.id = policy_id.clone();
    policy.description = request.description.clone();
    for condition in conditions {
        policy.conditions.push(condition);
    }
    
    engine.add_policy(policy.clone()).map_err(|e| e.to_string())?;
    
    // Log audit event
    state.db.execute(
        "INSERT INTO audit_logs (event_type, action, subject, details, success)
         VALUES ('policy', 'update', ?1, ?2, 1)",
        &[&policy_id, &format!("Updated policy: {}", policy.name)],
    ).ok();
    
    Ok(PolicyResponse {
        id: policy.id,
        name: policy.name,
        description: policy.description,
        priority: policy.priority,
        enabled: policy.enabled,
        conditions: request.conditions,
        action: request.action,
        hit_count: 0,
        last_match: None,
    })
}

/// Delete a policy (B3.1)
#[command]
pub async fn delete_policy(policy_id: String) -> Result<(), String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    let mut engine = state.policy_engine.write();
    engine.remove_policy(&policy_id).map_err(|e| e.to_string())?;
    
    // Log audit event
    state.db.execute(
        "INSERT INTO audit_logs (event_type, action, subject, success)
         VALUES ('policy', 'delete', ?1, 1)",
        &[&policy_id],
    ).ok();
    
    info!("Deleted policy: {}", policy_id);
    Ok(())
}

/// List all policies
#[command]
pub async fn list_policies() -> Result<Vec<PolicyResponse>, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    let policies: Vec<PolicyResponse> = state.db.query_map(
        "SELECT id, name, description, priority, enabled, conditions, action, hit_count, last_match
         FROM policies ORDER BY priority ASC",
        &[],
        |row| {
            let conditions_str: String = row.get(5)?;
            let conditions: serde_json::Value = serde_json::from_str(&conditions_str)
                .unwrap_or(serde_json::Value::Array(vec![]));
            
            Ok(PolicyResponse {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                priority: row.get(3)?,
                enabled: row.get(4)?,
                conditions,
                action: row.get(6)?,
                hit_count: row.get(7)?,
                last_match: row.get(8)?,
            })
        },
    ).map_err(|e| e.to_string())?;
    
    Ok(policies)
}

/// Get a single policy
#[command]
pub async fn get_policy(policy_id: String) -> Result<PolicyResponse, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    let policies: Vec<PolicyResponse> = state.db.query_map(
        "SELECT id, name, description, priority, enabled, conditions, action, hit_count, last_match
         FROM policies WHERE id = ?1",
        &[&policy_id],
        |row| {
            let conditions_str: String = row.get(5)?;
            let conditions: serde_json::Value = serde_json::from_str(&conditions_str)
                .unwrap_or(serde_json::Value::Array(vec![]));
            
            Ok(PolicyResponse {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                priority: row.get(3)?,
                enabled: row.get(4)?,
                conditions,
                action: row.get(6)?,
                hit_count: row.get(7)?,
                last_match: row.get(8)?,
            })
        },
    ).map_err(|e| e.to_string())?;
    
    policies.into_iter().next()
        .ok_or_else(|| format!("Policy not found: {}", policy_id))
}

/// Evaluate a request against policies (B2.1)
#[command]
pub async fn evaluate_policy(request: EvaluateRequest) -> Result<EvaluationResponse, String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    let mut context = zerotrust_mesh_lib::policy::RequestContext::default();
    context.source_spiffe_id = request.source_spiffe_id;
    context.source_ip = request.source_ip.and_then(|s| s.parse().ok());
    context.dest_spiffe_id = request.dest_spiffe_id;
    context.dest_port = request.dest_port;
    context.method = request.method;
    context.trust_score = request.trust_score;
    
    let engine = state.policy_engine.read();
    let result = engine.evaluate(&context);
    
    // Update hit count if policy matched
    if let Some(ref policy_id) = result.matched_policy_id {
        engine.update_hit_count(policy_id);
    }
    
    // Log audit event (G1.1)
    state.db.execute(
        "INSERT INTO audit_logs (event_type, action, subject, details, success)
         VALUES ('policy', 'evaluate', ?1, ?2, 1)",
        &[
            &result.matched_policy_id.clone().unwrap_or_default(),
            &format!("Action: {:?}", result.action),
        ],
    ).ok();
    
    Ok(EvaluationResponse {
        action: format!("{:?}", result.action),
        matched_policy_id: result.matched_policy_id,
        matched_policy_name: result.matched_policy_name,
        deny_reason: result.deny_reason,
        evaluation_time_us: result.evaluation_time_us,
    })
}

/// Toggle policy enabled state (B3.4)
#[command]
pub async fn toggle_policy(policy_id: String, enabled: bool) -> Result<(), String> {
    let state = get_app_state().ok_or("Application not initialized")?;
    
    let mut engine = state.policy_engine.write();
    engine.toggle_policy(&policy_id, enabled).map_err(|e| e.to_string())?;
    
    info!("Toggled policy {}: enabled={}", policy_id, enabled);
    Ok(())
}

/// Test policy against sample request (B1.6)
#[command]
pub async fn test_policy(
    policy_id: String,
    request: EvaluateRequest,
) -> Result<EvaluationResponse, String> {
    // Same as evaluate but for testing specific policy
    evaluate_policy(request).await
}
