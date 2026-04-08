//! Policy Engine for ZeroTrust Mesh
//!
//! Implements Feature Group B requirements:
//! - B1: Policy Definition Language (JSON-based)
//! - B2: Policy Evaluation (<10ms per request)
//! - B3: Policy Management

use anyhow::Result;
use chrono::{DateTime, Datelike, Timelike, Utc};
use dashmap::DashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, info};
use uuid::Uuid;
use validator::Validate;

use crate::storage::Database;

/// Policy-related errors
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),
    #[error("Invalid policy condition: {0}")]
    InvalidCondition(String),
    #[error("Policy evaluation failed: {0}")]
    EvaluationFailed(String),
    #[error("Invalid policy action: {0}")]
    InvalidAction(String),
    #[error("Policy validation failed: {0}")]
    ValidationFailed(String),
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

/// Policy actions (B1.3)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum PolicyAction {
    Allow,
    Deny,
    RequireMFA,
    Log,
}

impl std::fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyAction::Allow => write!(f, "Allow"),
            PolicyAction::Deny => write!(f, "Deny"),
            PolicyAction::RequireMFA => write!(f, "RequireMFA"),
            PolicyAction::Log => write!(f, "Log"),
        }
    }
}

/// Condition operators for policy matching
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    In,
    NotIn,
    Matches,  // Regex
}

/// Policy condition (B1.2 - at least 5 conditions)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyCondition {
    /// Source identity/IP condition
    Source {
        field: SourceField,
        operator: Operator,
        value: serde_json::Value,
    },
    /// Destination service condition
    Destination {
        field: DestinationField,
        operator: Operator,
        value: serde_json::Value,
    },
    /// HTTP method condition
    Method {
        operator: Operator,
        value: serde_json::Value,
    },
    /// Time-based condition (B2.5)
    Time {
        field: TimeField,
        operator: Operator,
        value: serde_json::Value,
    },
    /// Trust/risk score condition
    RiskScore {
        operator: Operator,
        threshold: f64,
    },
    /// Rate limiting condition (B2.6)
    RateLimit {
        max_requests: u32,
        window_seconds: u32,
    },
    /// Combined AND condition
    And {
        conditions: Vec<PolicyCondition>,
    },
    /// Combined OR condition
    Or {
        conditions: Vec<PolicyCondition>,
    },
    /// Negation
    Not {
        condition: Box<PolicyCondition>,
    },
}

/// Source fields for conditions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SourceField {
    SpiffeId,
    IpAddress,
    ServiceName,
    User,
    Port,
}

/// Destination fields for conditions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DestinationField {
    SpiffeId,
    IpAddress,
    ServiceName,
    Port,
    Path,
}

/// Time fields for conditions (B2.5)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TimeField {
    HourOfDay,      // 0-23
    DayOfWeek,      // 0-6 (Sunday = 0)
    DateRange,      // ISO date range
}

/// Policy definition (B1)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct Policy {
    pub id: String,
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub description: Option<String>,
    /// Priority (lower = higher priority, first match wins - B1.4)
    #[validate(range(min = 1, max = 10000))]
    pub priority: u32,
    pub enabled: bool,
    pub conditions: Vec<PolicyCondition>,
    pub action: PolicyAction,
    /// Statistics
    pub hit_count: u64,
    pub last_match: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Policy {
    /// Create a new policy
    pub fn new(name: &str, priority: u32, action: PolicyAction) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: None,
            priority,
            enabled: true,
            conditions: Vec::new(),
            action,
            hit_count: 0,
            last_match: None,
            created_at: now,
            updated_at: now,
        }
    }
    
    /// Add a condition to the policy
    pub fn add_condition(mut self, condition: PolicyCondition) -> Self {
        self.conditions.push(condition);
        self
    }
    
    /// Set description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }
}

/// Request context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    /// Source identity
    pub source_spiffe_id: Option<String>,
    pub source_ip: Option<IpAddr>,
    pub source_service_name: Option<String>,
    pub source_user: Option<String>,
    pub source_port: Option<u16>,
    
    /// Destination
    pub dest_spiffe_id: Option<String>,
    pub dest_ip: Option<IpAddr>,
    pub dest_service_name: Option<String>,
    pub dest_port: Option<u16>,
    pub dest_path: Option<String>,
    
    /// Request metadata
    pub method: Option<String>,
    pub trust_score: Option<f64>,
    pub timestamp: DateTime<Utc>,
    
    /// Additional context
    pub headers: Option<std::collections::HashMap<String, String>>,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            source_spiffe_id: None,
            source_ip: None,
            source_service_name: None,
            source_user: None,
            source_port: None,
            dest_spiffe_id: None,
            dest_ip: None,
            dest_service_name: None,
            dest_port: None,
            dest_path: None,
            method: None,
            trust_score: None,
            timestamp: Utc::now(),
            headers: None,
        }
    }
}

/// Policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub action: PolicyAction,
    pub matched_policy_id: Option<String>,
    pub matched_policy_name: Option<String>,
    pub deny_reason: Option<String>,
    pub evaluation_time_us: u64,
    pub cached: bool,
}

/// Cached evaluation entry
#[derive(Clone)]
struct CacheEntry {
    result: EvaluationResult,
    expires_at: Instant,
}

/// Rate limit tracking
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

/// Policy Engine (B2)
pub struct PolicyEngine {
    policies: Vec<Policy>,
    db: Arc<Database>,
    cache: DashMap<String, CacheEntry>,
    cache_ttl: Duration,
    rate_limits: DashMap<String, RateLimitEntry>,
    default_action: PolicyAction,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new(db: Arc<Database>) -> Result<Self> {
        let engine = Self {
            policies: Vec::new(),
            db,
            cache: DashMap::new(),
            cache_ttl: Duration::from_secs(5), // B2.3
            rate_limits: DashMap::new(),
            default_action: PolicyAction::Deny,
        };
        
        // Load policies from database
        // engine.load_policies()?;
        
        Ok(engine)
    }
    
    /// Load policies from database
    pub fn load_policies(&mut self) -> Result<()> {
        let policies: Vec<Policy> = self.db.query_map(
            "SELECT id, name, description, priority, enabled, conditions, action, 
             hit_count, last_match, created_at, updated_at 
             FROM policies WHERE enabled = 1 ORDER BY priority ASC",
            &[],
            |row| {
                let conditions_json: String = row.get(5)?;
                let conditions: Vec<PolicyCondition> = serde_json::from_str(&conditions_json)
                    .unwrap_or_default();
                
                let action_str: String = row.get(6)?;
                let action = match action_str.as_str() {
                    "Allow" => PolicyAction::Allow,
                    "Deny" => PolicyAction::Deny,
                    "RequireMFA" => PolicyAction::RequireMFA,
                    "Log" => PolicyAction::Log,
                    _ => PolicyAction::Deny,
                };
                
                Ok(Policy {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    priority: row.get(3)?,
                    enabled: row.get(4)?,
                    conditions,
                    action,
                    hit_count: row.get(7)?,
                    last_match: row.get::<_, Option<String>>(8)?
                        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                        .map(|dt| dt.with_timezone(&Utc)),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(10)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            },
        )?;
        
        self.policies = policies;
        info!("Loaded {} policies", self.policies.len());
        Ok(())
    }
    
    /// Evaluate request against policies (B2.1 - <10ms target)
    pub fn evaluate(&self, context: &RequestContext) -> EvaluationResult {
        let start = Instant::now();
        
        // Check cache (B2.3)
        let cache_key = self.compute_cache_key(context);
        if let Some(entry) = self.cache.get(&cache_key) {
            if entry.expires_at > Instant::now() {
                let mut result = entry.result.clone();
                result.cached = true;
                result.evaluation_time_us = start.elapsed().as_micros() as u64;
                return result;
            }
        }
        
        // Evaluate policies (first match wins - B1.4)
        for policy in &self.policies {
            if !policy.enabled {
                continue;
            }
            
            if self.matches_policy(policy, context) {
                let result = EvaluationResult {
                    action: policy.action,
                    matched_policy_id: Some(policy.id.clone()),
                    matched_policy_name: Some(policy.name.clone()),
                    deny_reason: if policy.action == PolicyAction::Deny {
                        Some(format!("Denied by policy: {}", policy.name))
                    } else {
                        None
                    },
                    evaluation_time_us: start.elapsed().as_micros() as u64,
                    cached: false,
                };
                
                // Cache result
                self.cache.insert(cache_key, CacheEntry {
                    result: result.clone(),
                    expires_at: Instant::now() + self.cache_ttl,
                });
                
                // Update hit count (async, don't block)
                debug!("Policy '{}' matched request", policy.name);
                
                return result;
            }
        }
        
        // No policy matched, use default action (B2.4)
        let result = EvaluationResult {
            action: self.default_action,
            matched_policy_id: None,
            matched_policy_name: None,
            deny_reason: if self.default_action == PolicyAction::Deny {
                Some("No matching policy found, default deny".to_string())
            } else {
                None
            },
            evaluation_time_us: start.elapsed().as_micros() as u64,
            cached: false,
        };
        
        self.cache.insert(cache_key, CacheEntry {
            result: result.clone(),
            expires_at: Instant::now() + self.cache_ttl,
        });
        
        result
    }
    
    /// Check if request matches policy conditions
    fn matches_policy(&self, policy: &Policy, context: &RequestContext) -> bool {
        if policy.conditions.is_empty() {
            // Policy with no conditions matches everything
            return true;
        }
        
        // All conditions must match (implicit AND)
        policy.conditions.iter().all(|cond| self.evaluate_condition(cond, context))
    }
    
    /// Evaluate a single condition
    fn evaluate_condition(&self, condition: &PolicyCondition, context: &RequestContext) -> bool {
        match condition {
            PolicyCondition::Source { field, operator, value } => {
                self.evaluate_source_condition(field, operator, value, context)
            }
            PolicyCondition::Destination { field, operator, value } => {
                self.evaluate_destination_condition(field, operator, value, context)
            }
            PolicyCondition::Method { operator, value } => {
                self.evaluate_method_condition(operator, value, context)
            }
            PolicyCondition::Time { field, operator, value } => {
                self.evaluate_time_condition(field, operator, value, context)
            }
            PolicyCondition::RiskScore { operator, threshold } => {
                self.evaluate_risk_score_condition(operator, *threshold, context)
            }
            PolicyCondition::RateLimit { max_requests, window_seconds } => {
                self.evaluate_rate_limit(*max_requests, *window_seconds, context)
            }
            PolicyCondition::And { conditions } => {
                conditions.iter().all(|c| self.evaluate_condition(c, context))
            }
            PolicyCondition::Or { conditions } => {
                conditions.iter().any(|c| self.evaluate_condition(c, context))
            }
            PolicyCondition::Not { condition } => {
                !self.evaluate_condition(condition, context)
            }
        }
    }
    
    fn evaluate_source_condition(
        &self,
        field: &SourceField,
        operator: &Operator,
        value: &serde_json::Value,
        context: &RequestContext,
    ) -> bool {
        let field_value: Option<String> = match field {
            SourceField::SpiffeId => context.source_spiffe_id.clone(),
            SourceField::IpAddress => context.source_ip.map(|ip| ip.to_string()),
            SourceField::ServiceName => context.source_service_name.clone(),
            SourceField::User => context.source_user.clone(),
            SourceField::Port => context.source_port.map(|p| p.to_string()),
        };
        
        self.compare_string_value(field_value.as_deref(), operator, value)
    }
    
    fn evaluate_destination_condition(
        &self,
        field: &DestinationField,
        operator: &Operator,
        value: &serde_json::Value,
        context: &RequestContext,
    ) -> bool {
        let field_value: Option<String> = match field {
            DestinationField::SpiffeId => context.dest_spiffe_id.clone(),
            DestinationField::IpAddress => context.dest_ip.map(|ip| ip.to_string()),
            DestinationField::ServiceName => context.dest_service_name.clone(),
            DestinationField::Port => context.dest_port.map(|p| p.to_string()),
            DestinationField::Path => context.dest_path.clone(),
        };
        
        self.compare_string_value(field_value.as_deref(), operator, value)
    }
    
    fn evaluate_method_condition(
        &self,
        operator: &Operator,
        value: &serde_json::Value,
        context: &RequestContext,
    ) -> bool {
        self.compare_string_value(context.method.as_deref(), operator, value)
    }
    
    fn evaluate_time_condition(
        &self,
        field: &TimeField,
        operator: &Operator,
        value: &serde_json::Value,
        context: &RequestContext,
    ) -> bool {
        match field {
            TimeField::HourOfDay => {
                let hour = context.timestamp.hour() as i64;
                self.compare_numeric_value(hour, operator, value)
            }
            TimeField::DayOfWeek => {
                let day = context.timestamp.weekday().num_days_from_sunday() as i64;
                self.compare_numeric_value(day, operator, value)
            }
            TimeField::DateRange => {
                // Expect value to be an object with "start" and "end" ISO dates
                if let Some(obj) = value.as_object() {
                    let now = context.timestamp;
                    let start = obj.get("start")
                        .and_then(|v| v.as_str())
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&Utc));
                    let end = obj.get("end")
                        .and_then(|v| v.as_str())
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&Utc));
                    
                    match (start, end) {
                        (Some(s), Some(e)) => now >= s && now <= e,
                        (Some(s), None) => now >= s,
                        (None, Some(e)) => now <= e,
                        (None, None) => true,
                    }
                } else {
                    false
                }
            }
        }
    }
    
    fn evaluate_risk_score_condition(
        &self,
        operator: &Operator,
        threshold: f64,
        context: &RequestContext,
    ) -> bool {
        let score = context.trust_score.unwrap_or(1.0);
        match operator {
            Operator::GreaterThan => score > threshold,
            Operator::LessThan => score < threshold,
            Operator::GreaterThanOrEqual => score >= threshold,
            Operator::LessThanOrEqual => score <= threshold,
            Operator::Equals => (score - threshold).abs() < f64::EPSILON,
            _ => false,
        }
    }
    
    fn evaluate_rate_limit(
        &self,
        max_requests: u32,
        window_seconds: u32,
        context: &RequestContext,
    ) -> bool {
        // Create a key based on source identity
        let key = context.source_spiffe_id.as_ref()
            .or(context.source_ip.as_ref().map(|ip| ip.to_string()).as_ref())
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        
        let now = Instant::now();
        let window = Duration::from_secs(window_seconds as u64);
        
        let mut entry = self.rate_limits.entry(key).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });
        
        // Reset window if expired
        if now.duration_since(entry.window_start) > window {
            entry.count = 0;
            entry.window_start = now;
        }
        
        entry.count += 1;
        
        // Return true if under limit (allow), false if exceeded (deny)
        entry.count <= max_requests
    }
    
    fn compare_string_value(
        &self,
        field_value: Option<&str>,
        operator: &Operator,
        expected: &serde_json::Value,
    ) -> bool {
        let field_value = match field_value {
            Some(v) => v,
            None => return false,
        };
        
        match operator {
            Operator::Equals => {
                expected.as_str().map(|e| field_value == e).unwrap_or(false)
            }
            Operator::NotEquals => {
                expected.as_str().map(|e| field_value != e).unwrap_or(true)
            }
            Operator::Contains => {
                expected.as_str().map(|e| field_value.contains(e)).unwrap_or(false)
            }
            Operator::StartsWith => {
                expected.as_str().map(|e| field_value.starts_with(e)).unwrap_or(false)
            }
            Operator::EndsWith => {
                expected.as_str().map(|e| field_value.ends_with(e)).unwrap_or(false)
            }
            Operator::In => {
                expected.as_array()
                    .map(|arr| arr.iter().any(|v| v.as_str() == Some(field_value)))
                    .unwrap_or(false)
            }
            Operator::NotIn => {
                expected.as_array()
                    .map(|arr| !arr.iter().any(|v| v.as_str() == Some(field_value)))
                    .unwrap_or(true)
            }
            Operator::Matches => {
                expected.as_str().and_then(|pattern| {
                    Regex::new(pattern).ok().map(|re: Regex| re.is_match(field_value))
                }).unwrap_or(false)
            }
            _ => false,
        }
    }
    
    fn compare_numeric_value(
        &self,
        field_value: i64,
        operator: &Operator,
        expected: &serde_json::Value,
    ) -> bool {
        let expected_num = expected.as_i64().unwrap_or(0);
        
        match operator {
            Operator::Equals => field_value == expected_num,
            Operator::NotEquals => field_value != expected_num,
            Operator::GreaterThan => field_value > expected_num,
            Operator::LessThan => field_value < expected_num,
            Operator::GreaterThanOrEqual => field_value >= expected_num,
            Operator::LessThanOrEqual => field_value <= expected_num,
            Operator::In => {
                expected.as_array()
                    .map(|arr| arr.iter().any(|v| v.as_i64() == Some(field_value)))
                    .unwrap_or(false)
            }
            _ => false,
        }
    }
    
    /// Compute cache key for request context
    fn compute_cache_key(&self, context: &RequestContext) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        
        if let Some(ref spiffe) = context.source_spiffe_id {
            hasher.update(spiffe.as_bytes());
        }
        if let Some(ip) = context.source_ip {
            hasher.update(ip.to_string().as_bytes());
        }
        if let Some(ref dest) = context.dest_spiffe_id {
            hasher.update(dest.as_bytes());
        }
        if let Some(ref method) = context.method {
            hasher.update(method.as_bytes());
        }
        
        hex::encode(hasher.finalize())
    }
    
    /// Add a new policy
    pub fn add_policy(&mut self, policy: Policy) -> Result<()> {
        policy.validate().map_err(|e| PolicyError::ValidationFailed(e.to_string()))?;
        
        // Insert into database
        let conditions_json = serde_json::to_string(&policy.conditions)?;
        self.db.execute(
            "INSERT INTO policies (id, name, description, priority, enabled, conditions, action, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            &[
                &policy.id,
                &policy.name,
                &policy.description.as_deref().unwrap_or(""),
                &(policy.priority as i32),
                &policy.enabled,
                &conditions_json,
                &policy.action.to_string(),
                &policy.created_at.to_rfc3339(),
                &policy.updated_at.to_rfc3339(),
            ],
        )?;
        
        // Add to in-memory list and re-sort by priority
        self.policies.push(policy);
        self.policies.sort_by_key(|p| p.priority);
        
        // Clear cache
        self.cache.clear();
        
        Ok(())
    }
    
    /// Remove a policy
    pub fn remove_policy(&mut self, policy_id: &str) -> Result<()> {
        self.db.execute("DELETE FROM policies WHERE id = ?1", &[&policy_id])?;
        self.policies.retain(|p| p.id != policy_id);
        self.cache.clear();
        Ok(())
    }
    
    /// Toggle policy enabled state (B3.4)
    pub fn toggle_policy(&mut self, policy_id: &str, enabled: bool) -> Result<()> {
        self.db.execute(
            "UPDATE policies SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
            &[&enabled, &Utc::now().to_rfc3339(), &policy_id],
        )?;
        
        if let Some(policy) = self.policies.iter_mut().find(|p| p.id == policy_id) {
            policy.enabled = enabled;
        }
        
        self.cache.clear();
        Ok(())
    }
    
    /// Get all policies
    pub fn get_policies(&self) -> &[Policy] {
        &self.policies
    }
    
    /// Get a policy by ID
    pub fn get_policy(&self, policy_id: &str) -> Option<&Policy> {
        self.policies.iter().find(|p| p.id == policy_id)
    }
    
    /// Update policy hit count
    pub fn update_hit_count(&self, policy_id: &str) {
        let _ = self.db.execute(
            "UPDATE policies SET hit_count = hit_count + 1, last_match = ?1 WHERE id = ?2",
            &[&Utc::now().to_rfc3339(), &policy_id],
        );
    }
    
    /// Set default action
    pub fn set_default_action(&mut self, action: PolicyAction) {
        self.default_action = action;
    }
    
    /// Set cache TTL
    pub fn set_cache_ttl(&mut self, seconds: u64) {
        self.cache_ttl = Duration::from_secs(seconds);
    }
    
    /// Clear evaluation cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

/// Policy templates (B1.5)
pub mod templates {
    use super::*;
    
    /// Allow all traffic from a specific service
    pub fn allow_service(service_spiffe_id: &str) -> Policy {
        Policy::new("Allow Service", 100, PolicyAction::Allow)
            .add_condition(PolicyCondition::Source {
                field: SourceField::SpiffeId,
                operator: Operator::Equals,
                value: serde_json::Value::String(service_spiffe_id.to_string()),
            })
            .with_description("Allow all traffic from specified service")
    }
    
    /// Deny access outside business hours
    pub fn business_hours_only(start_hour: u8, end_hour: u8) -> Policy {
        Policy::new("Business Hours Only", 50, PolicyAction::Deny)
            .add_condition(PolicyCondition::Or {
                conditions: vec![
                    PolicyCondition::Time {
                        field: TimeField::HourOfDay,
                        operator: Operator::LessThan,
                        value: serde_json::Value::Number(start_hour.into()),
                    },
                    PolicyCondition::Time {
                        field: TimeField::HourOfDay,
                        operator: Operator::GreaterThanOrEqual,
                        value: serde_json::Value::Number(end_hour.into()),
                    },
                ],
            })
            .with_description("Deny access outside business hours")
    }
    
    /// Rate limit per service
    pub fn rate_limit(max_requests: u32, window_seconds: u32) -> Policy {
        Policy::new("Rate Limit", 10, PolicyAction::Deny)
            .add_condition(PolicyCondition::Not {
                condition: Box::new(PolicyCondition::RateLimit {
                    max_requests,
                    window_seconds,
                }),
            })
            .with_description("Rate limit requests per source")
    }
    
    /// Require high trust score
    pub fn high_trust_required(min_score: f64) -> Policy {
        Policy::new("High Trust Required", 20, PolicyAction::Deny)
            .add_condition(PolicyCondition::RiskScore {
                operator: Operator::LessThan,
                threshold: min_score,
            })
            .with_description("Deny requests from services with low trust scores")
    }
    
    /// Block specific IP
    pub fn block_ip(ip: &str) -> Policy {
        Policy::new("Block IP", 1, PolicyAction::Deny)
            .add_condition(PolicyCondition::Source {
                field: SourceField::IpAddress,
                operator: Operator::Equals,
                value: serde_json::Value::String(ip.to_string()),
            })
            .with_description(&format!("Block traffic from IP: {}", ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;
    
    fn create_test_context() -> RequestContext {
        RequestContext {
            source_spiffe_id: Some("spiffe://test.local/service-a".to_string()),
            source_ip: Some(IpAddr::from_str("192.168.1.100").unwrap()),
            source_service_name: Some("service-a".to_string()),
            source_user: None,
            source_port: Some(8080),
            dest_spiffe_id: Some("spiffe://test.local/service-b".to_string()),
            dest_ip: Some(IpAddr::from_str("192.168.1.101").unwrap()),
            dest_service_name: Some("service-b".to_string()),
            dest_port: Some(443),
            dest_path: Some("/api/v1/data".to_string()),
            method: Some("GET".to_string()),
            trust_score: Some(0.85),
            timestamp: Utc::now(),
            headers: None,
        }
    }
    
    #[test]
    fn test_policy_creation() {
        let policy = Policy::new("Test Policy", 100, PolicyAction::Allow)
            .add_condition(PolicyCondition::Source {
                field: SourceField::SpiffeId,
                operator: Operator::Equals,
                value: serde_json::Value::String("spiffe://test.local/service-a".to_string()),
            });
        
        assert_eq!(policy.name, "Test Policy");
        assert_eq!(policy.action, PolicyAction::Allow);
        assert_eq!(policy.conditions.len(), 1);
    }
    
    #[test]
    fn test_policy_serialization() {
        let policy = templates::allow_service("spiffe://test.local/service-a");
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: Policy = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.name, policy.name);
        assert_eq!(parsed.action, policy.action);
    }
}
