//! eBPF Data Plane for ZeroTrust Mesh
//!
//! Implements Feature Group D requirements:
//! - D1: Packet Inspection
//! - D2: Attack Detection
//! - D3: Packet Filtering
//!
//! Note: This module provides the userspace management interface.
//! Actual eBPF programs are in the ebpf/ directory and require
//! libbpf-rs/aya-rs and root privileges to load.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn};

use crate::storage::Database;

/// eBPF-related errors
#[derive(Error, Debug)]
pub enum EbpfError {
    #[error("eBPF program load failed: {0}")]
    LoadFailed(String),
    #[error("Map operation failed: {0}")]
    MapOperationFailed(String),
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),
    #[error("Insufficient privileges")]
    InsufficientPrivileges,
    #[error("Kernel version not supported")]
    KernelNotSupported,
}

/// Attack types (D2)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    /// SYN flood (D2.1: >100 SYNs/sec from single IP)
    SynFlood,
    /// Port scan (D2.2: >50 ports in 10 seconds)
    PortScan,
    /// HTTP flood (D2.3: >1000 req/sec)
    HttpFlood,
    /// ICMP flood (D2.4: >500 pings/sec)
    IcmpFlood,
    /// DNS amplification (D2.5)
    DnsAmplification,
    /// Unknown/Other
    Unknown,
}

impl std::fmt::Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackType::SynFlood => write!(f, "SYN Flood"),
            AttackType::PortScan => write!(f, "Port Scan"),
            AttackType::HttpFlood => write!(f, "HTTP Flood"),
            AttackType::IcmpFlood => write!(f, "ICMP Flood"),
            AttackType::DnsAmplification => write!(f, "DNS Amplification"),
            AttackType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Attack severity (D2.6)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AttackSeverity {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for AttackSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackSeverity::Low => write!(f, "Low"),
            AttackSeverity::Medium => write!(f, "Medium"),
            AttackSeverity::High => write!(f, "High"),
        }
    }
}

/// Protocol type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unknown,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Unknown => write!(f, "Unknown"),
        }
    }
}

/// 5-tuple for packet identification (D1.3)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8, // IP protocol number (6=TCP, 17=UDP, 1=ICMP)
}

impl FiveTuple {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }
    
    pub fn protocol_name(&self) -> Protocol {
        match self.protocol {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            _ => Protocol::Unknown,
        }
    }
}

/// Detected attack event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEvent {
    pub id: u64,
    pub attack_type: AttackType,
    pub source_ip: IpAddr,
    pub source_port: Option<u16>,
    pub destination_ip: IpAddr,
    pub destination_port: Option<u16>,
    pub protocol: Protocol,
    pub severity: AttackSeverity,
    pub packet_count: u64,
    pub details: Option<String>,
    pub blocked: bool,
    pub timestamp: DateTime<Utc>,
}

/// Packet counters per service (D1.6)
#[derive(Debug, Default)]
pub struct PacketCounters {
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub dropped: AtomicU64,
}

impl PacketCounters {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn increment_in(&self, bytes: u64) {
        self.packets_in.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }
    
    pub fn increment_out(&self, bytes: u64) {
        self.packets_out.fetch_add(1, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
    }
    
    pub fn increment_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn snapshot(&self) -> PacketCountersSnapshot {
        PacketCountersSnapshot {
            packets_in: self.packets_in.load(Ordering::Relaxed),
            packets_out: self.packets_out.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of packet counters (serializable)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketCountersSnapshot {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub dropped: u64,
}

/// Rate tracker for attack detection
struct RateTracker {
    counts: DashMap<IpAddr, Vec<DateTime<Utc>>>,
    window_duration: Duration,
}

impl RateTracker {
    fn new(window_seconds: i64) -> Self {
        Self {
            counts: DashMap::new(),
            window_duration: Duration::seconds(window_seconds),
        }
    }
    
    fn record(&self, ip: IpAddr) -> u64 {
        let now = Utc::now();
        let cutoff = now - self.window_duration;
        
        let mut entry = self.counts.entry(ip).or_insert_with(Vec::new);
        
        // Remove old entries
        entry.retain(|t| *t > cutoff);
        
        // Add new entry
        entry.push(now);
        
        entry.len() as u64
    }
    
    fn get_rate(&self, ip: &IpAddr) -> u64 {
        let now = Utc::now();
        let cutoff = now - self.window_duration;
        
        self.counts.get(ip)
            .map(|entry| entry.iter().filter(|t| **t > cutoff).count() as u64)
            .unwrap_or(0)
    }
    
    fn cleanup(&self) {
        let now = Utc::now();
        let cutoff = now - self.window_duration;
        
        self.counts.retain(|_, v| {
            v.retain(|t| *t > cutoff);
            !v.is_empty()
        });
    }
}

/// Port scan tracker
struct PortScanTracker {
    /// Maps source IP to set of (destination IP, port) pairs
    scans: DashMap<IpAddr, HashMap<(IpAddr, u16), DateTime<Utc>>>,
    window_seconds: i64,
}

impl PortScanTracker {
    fn new(window_seconds: i64) -> Self {
        Self {
            scans: DashMap::new(),
            window_seconds,
        }
    }
    
    fn record(&self, src_ip: IpAddr, dst_ip: IpAddr, port: u16) -> u64 {
        let now = Utc::now();
        let cutoff = now - Duration::seconds(self.window_seconds);
        
        let mut entry = self.scans.entry(src_ip).or_insert_with(HashMap::new);
        
        // Remove old entries
        entry.retain(|_, t| *t > cutoff);
        
        // Add new entry
        entry.insert((dst_ip, port), now);
        
        entry.len() as u64
    }
}

/// Attack Detector (D2)
pub struct AttackDetector {
    db: Arc<Database>,
    
    // Rate trackers
    syn_tracker: RateTracker,
    http_tracker: RateTracker,
    icmp_tracker: RateTracker,
    port_scan_tracker: PortScanTracker,
    
    // Thresholds
    syn_flood_threshold: u64,      // D2.1: 100 SYNs/sec
    port_scan_threshold: u64,      // D2.2: 50 ports in 10 seconds
    http_flood_threshold: u64,     // D2.3: 1000 req/sec
    icmp_flood_threshold: u64,     // D2.4: 500 pings/sec
    
    // Blacklist (D3.5)
    blacklist: DashMap<IpAddr, (String, Option<DateTime<Utc>>)>,
    
    // Whitelist (D3.4)
    whitelist: DashMap<IpAddr, String>,
    
    // Counters per service
    counters: DashMap<String, Arc<PacketCounters>>,
    
    // Event ID counter
    next_event_id: AtomicU64,
}

impl AttackDetector {
    /// Create new attack detector with thresholds from config
    pub fn new(
        db: Arc<Database>,
        syn_flood_threshold: u32,
        port_scan_threshold: u32,
        http_flood_threshold: u32,
        icmp_flood_threshold: u32,
    ) -> Self {
        Self {
            db,
            syn_tracker: RateTracker::new(1),      // 1 second window
            http_tracker: RateTracker::new(1),     // 1 second window
            icmp_tracker: RateTracker::new(1),     // 1 second window
            port_scan_tracker: PortScanTracker::new(10), // 10 second window (D2.2)
            syn_flood_threshold: syn_flood_threshold as u64,
            port_scan_threshold: port_scan_threshold as u64,
            http_flood_threshold: http_flood_threshold as u64,
            icmp_flood_threshold: icmp_flood_threshold as u64,
            blacklist: DashMap::new(),
            whitelist: DashMap::new(),
            counters: DashMap::new(),
            next_event_id: AtomicU64::new(1),
        }
    }
    
    /// Process a packet and check for attacks
    pub fn process_packet(
        &self,
        five_tuple: &FiveTuple,
        _packet_size: u64,
        tcp_flags: Option<u8>,
    ) -> Option<AttackEvent> {
        // Check whitelist first (D3.4)
        if self.whitelist.contains_key(&five_tuple.src_ip) {
            return None;
        }
        
        // Check blacklist (D3.5)
        if let Some(entry) = self.blacklist.get(&five_tuple.src_ip) {
            // Check if blacklist entry has expired
            if let Some(expires) = entry.1 {
                if Utc::now() < expires {
                    return Some(self.create_attack_event(
                        AttackType::Unknown,
                        five_tuple,
                        AttackSeverity::High,
                        1,
                        Some(format!("Blocked: {}", entry.0)),
                        true,
                    ));
                }
            } else {
                return Some(self.create_attack_event(
                    AttackType::Unknown,
                    five_tuple,
                    AttackSeverity::High,
                    1,
                    Some(format!("Blocked: {}", entry.0)),
                    true,
                ));
            }
        }
        
        // Check for different attack types
        match five_tuple.protocol {
            6 => self.check_tcp_attacks(five_tuple, tcp_flags),
            17 => self.check_udp_attacks(five_tuple),
            1 => self.check_icmp_attacks(five_tuple),
            _ => None,
        }
    }
    
    /// Check for TCP-based attacks
    fn check_tcp_attacks(
        &self,
        five_tuple: &FiveTuple,
        tcp_flags: Option<u8>,
    ) -> Option<AttackEvent> {
        // Check for SYN flood (D2.1)
        // TCP SYN flag = 0x02
        if tcp_flags.map(|f| f & 0x02 != 0).unwrap_or(false) {
            let rate = self.syn_tracker.record(five_tuple.src_ip);
            
            if rate > self.syn_flood_threshold {
                let event = self.create_attack_event(
                    AttackType::SynFlood,
                    five_tuple,
                    if rate > self.syn_flood_threshold * 10 {
                        AttackSeverity::High
                    } else if rate > self.syn_flood_threshold * 5 {
                        AttackSeverity::Medium
                    } else {
                        AttackSeverity::Low
                    },
                    rate,
                    Some(format!("{} SYNs/sec detected", rate)),
                    true,
                );
                
                self.record_attack(&event);
                self.auto_blacklist(&five_tuple.src_ip, "SYN flood detected");
                
                return Some(event);
            }
        }
        
        // Check for port scan (D2.2)
        let ports_scanned = self.port_scan_tracker.record(
            five_tuple.src_ip,
            five_tuple.dst_ip,
            five_tuple.dst_port,
        );
        
        if ports_scanned > self.port_scan_threshold {
            let event = self.create_attack_event(
                AttackType::PortScan,
                five_tuple,
                AttackSeverity::Medium,
                ports_scanned,
                Some(format!("{} ports scanned in 10 seconds", ports_scanned)),
                true,
            );
            
            self.record_attack(&event);
            self.auto_blacklist(&five_tuple.src_ip, "Port scan detected");
            
            return Some(event);
        }
        
        // Check for HTTP flood (D2.3) - ports 80, 8080, 8000
        if matches!(five_tuple.dst_port, 80 | 8080 | 8000) {
            let rate = self.http_tracker.record(five_tuple.src_ip);
            
            if rate > self.http_flood_threshold {
                let event = self.create_attack_event(
                    AttackType::HttpFlood,
                    five_tuple,
                    if rate > self.http_flood_threshold * 5 {
                        AttackSeverity::High
                    } else {
                        AttackSeverity::Medium
                    },
                    rate,
                    Some(format!("{} HTTP requests/sec detected", rate)),
                    true,
                );
                
                self.record_attack(&event);
                self.auto_blacklist(&five_tuple.src_ip, "HTTP flood detected");
                
                return Some(event);
            }
        }
        
        None
    }
    
    /// Check for UDP-based attacks
    fn check_udp_attacks(&self, five_tuple: &FiveTuple) -> Option<AttackEvent> {
        // Check for DNS amplification (D2.5) - port 53
        if five_tuple.src_port == 53 {
            // DNS amplification typically uses spoofed source IPs
            // This is a simplified check
            let event = self.create_attack_event(
                AttackType::DnsAmplification,
                five_tuple,
                AttackSeverity::Medium,
                1,
                Some("Potential DNS amplification response".to_string()),
                false, // Don't auto-block, might be legitimate
            );
            
            self.record_attack(&event);
            return Some(event);
        }
        
        None
    }
    
    /// Check for ICMP-based attacks (D2.4)
    fn check_icmp_attacks(&self, five_tuple: &FiveTuple) -> Option<AttackEvent> {
        let rate = self.icmp_tracker.record(five_tuple.src_ip);
        
        if rate > self.icmp_flood_threshold {
            let event = self.create_attack_event(
                AttackType::IcmpFlood,
                five_tuple,
                if rate > self.icmp_flood_threshold * 5 {
                    AttackSeverity::High
                } else {
                    AttackSeverity::Medium
                },
                rate,
                Some(format!("{} ICMP packets/sec detected", rate)),
                true,
            );
            
            self.record_attack(&event);
            self.auto_blacklist(&five_tuple.src_ip, "ICMP flood detected");
            
            return Some(event);
        }
        
        None
    }
    
    /// Create an attack event
    fn create_attack_event(
        &self,
        attack_type: AttackType,
        five_tuple: &FiveTuple,
        severity: AttackSeverity,
        packet_count: u64,
        details: Option<String>,
        blocked: bool,
    ) -> AttackEvent {
        AttackEvent {
            id: self.next_event_id.fetch_add(1, Ordering::SeqCst),
            attack_type,
            source_ip: five_tuple.src_ip,
            source_port: if five_tuple.src_port > 0 { Some(five_tuple.src_port) } else { None },
            destination_ip: five_tuple.dst_ip,
            destination_port: if five_tuple.dst_port > 0 { Some(five_tuple.dst_port) } else { None },
            protocol: five_tuple.protocol_name(),
            severity,
            packet_count,
            details,
            blocked,
            timestamp: Utc::now(),
        }
    }
    
    /// Record attack in database
    fn record_attack(&self, event: &AttackEvent) {
        let _ = self.db.execute(
            "INSERT INTO attacks (attack_type, source_ip, source_port, destination_ip, 
             destination_port, protocol, severity, packet_count, details, blocked, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            &[
                &event.attack_type.to_string(),
                &event.source_ip.to_string(),
                &event.source_port.map(|p| p as i32),
                &event.destination_ip.to_string(),
                &event.destination_port.map(|p| p as i32),
                &event.protocol.to_string(),
                &event.severity.to_string(),
                &(event.packet_count as i64),
                &event.details,
                &event.blocked,
                &event.timestamp.to_rfc3339(),
            ],
        );
        
        warn!(
            "Attack detected: {} from {} (severity: {})",
            event.attack_type, event.source_ip, event.severity
        );
    }
    
    /// Automatically blacklist an IP (D3.5)
    fn auto_blacklist(&self, ip: &IpAddr, reason: &str) {
        // Auto-blacklist for 1 hour
        let expires = Utc::now() + Duration::hours(1);
        self.blacklist.insert(*ip, (reason.to_string(), Some(expires)));
        
        let _ = self.db.execute(
            "INSERT OR REPLACE INTO blacklist (ip, reason, auto_generated, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                &ip.to_string(),
                &reason,
                &true,
                &expires.to_rfc3339(),
                &Utc::now().to_rfc3339(),
            ],
        );
        
        info!("Auto-blacklisted IP {} for: {}", ip, reason);
    }
    
    /// Manually blacklist an IP
    pub fn blacklist_ip(&self, ip: IpAddr, reason: &str, duration_hours: Option<u32>) {
        let expires = duration_hours.map(|h| Utc::now() + Duration::hours(h as i64));
        self.blacklist.insert(ip, (reason.to_string(), expires));
        
        let _ = self.db.execute(
            "INSERT OR REPLACE INTO blacklist (ip, reason, auto_generated, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                &ip.to_string(),
                &reason,
                &false,
                &expires.map(|e| e.to_rfc3339()),
                &Utc::now().to_rfc3339(),
            ],
        );
    }
    
    /// Remove IP from blacklist
    pub fn unblacklist_ip(&self, ip: &IpAddr) {
        self.blacklist.remove(ip);
        let _ = self.db.execute("DELETE FROM blacklist WHERE ip = ?1", &[&ip.to_string()]);
    }
    
    /// Add IP to whitelist (D3.4)
    pub fn whitelist_ip(&self, ip: IpAddr, description: &str) {
        self.whitelist.insert(ip, description.to_string());
        
        let _ = self.db.execute(
            "INSERT OR REPLACE INTO whitelist (ip, description, created_at)
             VALUES (?1, ?2, ?3)",
            &[&ip.to_string(), &description, &Utc::now().to_rfc3339()],
        );
    }
    
    /// Remove IP from whitelist
    pub fn unwhitelist_ip(&self, ip: &IpAddr) {
        self.whitelist.remove(ip);
        let _ = self.db.execute("DELETE FROM whitelist WHERE ip = ?1", &[&ip.to_string()]);
    }
    
    /// Check if IP is blacklisted
    pub fn is_blacklisted(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.blacklist.get(ip) {
            if let Some(expires) = entry.1 {
                return Utc::now() < expires;
            }
            return true;
        }
        false
    }
    
    /// Check if IP is whitelisted
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.whitelist.contains_key(ip)
    }
    
    /// Get blacklist
    pub fn get_blacklist(&self) -> Vec<(IpAddr, String, Option<DateTime<Utc>>)> {
        self.blacklist
            .iter()
            .map(|entry| (*entry.key(), entry.value().0.clone(), entry.value().1))
            .collect()
    }
    
    /// Get whitelist
    pub fn get_whitelist(&self) -> Vec<(IpAddr, String)> {
        self.whitelist
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect()
    }
    
    /// Get packet counters for a service
    pub fn get_counters(&self, service_id: &str) -> PacketCountersSnapshot {
        self.counters
            .get(service_id)
            .map(|c| c.snapshot())
            .unwrap_or_default()
    }
    
    /// Get or create counters for a service
    pub fn get_or_create_counters(&self, service_id: &str) -> Arc<PacketCounters> {
        self.counters
            .entry(service_id.to_string())
            .or_insert_with(|| Arc::new(PacketCounters::new()))
            .clone()
    }
    
    /// Get attack statistics
    pub fn get_attack_stats(&self) -> Result<AttackStats> {
        let now = Utc::now();
        let day_ago = (now - Duration::hours(24)).to_rfc3339();
        
        // Get counts by attack type
        let by_type: Vec<(String, i64)> = self.db.query_map(
            "SELECT attack_type, COUNT(*) FROM attacks 
             WHERE created_at > ?1 GROUP BY attack_type ORDER BY COUNT(*) DESC",
            &[&day_ago],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        
        // Get top attacking IPs
        let top_ips: Vec<(String, i64)> = self.db.query_map(
            "SELECT source_ip, COUNT(*) FROM attacks 
             WHERE created_at > ?1 GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 5",
            &[&day_ago],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        
        // Get total count
        let total: i64 = self.db.query_map(
            "SELECT COUNT(*) FROM attacks WHERE created_at > ?1",
            &[&day_ago],
            |row| row.get(0),
        )?.first().copied().unwrap_or(0);
        
        // Get blocked count
        let blocked: i64 = self.db.query_map(
            "SELECT COUNT(*) FROM attacks WHERE created_at > ?1 AND blocked = 1",
            &[&day_ago],
            |row| row.get(0),
        )?.first().copied().unwrap_or(0);
        
        Ok(AttackStats {
            total_24h: total as u64,
            blocked_24h: blocked as u64,
            by_type: by_type.into_iter().collect(),
            top_attackers: top_ips,
            blacklist_count: self.blacklist.len() as u64,
        })
    }
    
    /// Cleanup old data
    pub fn cleanup(&self) {
        self.syn_tracker.cleanup();
        self.http_tracker.cleanup();
        self.icmp_tracker.cleanup();
        
        // Remove expired blacklist entries
        let now = Utc::now();
        self.blacklist.retain(|_, v| {
            v.1.map(|e| now < e).unwrap_or(true)
        });
    }
}

/// Attack statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStats {
    pub total_24h: u64,
    pub blocked_24h: u64,
    pub by_type: HashMap<String, i64>,
    pub top_attackers: Vec<(String, i64)>,
    pub blacklist_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    
    fn create_test_five_tuple(src_ip: &str, dst_port: u16, protocol: u8) -> FiveTuple {
        FiveTuple {
            src_ip: IpAddr::from_str(src_ip).unwrap(),
            dst_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 12345,
            dst_port,
            protocol,
        }
    }
    
    #[test]
    fn test_five_tuple() {
        let tuple = create_test_five_tuple("10.0.0.1", 80, 6);
        assert_eq!(tuple.protocol_name(), Protocol::Tcp);
    }
    
    #[test]
    fn test_rate_tracker() {
        let tracker = RateTracker::new(1);
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        
        // Record multiple events
        for _ in 0..10 {
            tracker.record(ip);
        }
        
        assert_eq!(tracker.get_rate(&ip), 10);
    }
    
    #[test]
    fn test_port_scan_tracker() {
        let tracker = PortScanTracker::new(10);
        let src_ip = IpAddr::from_str("10.0.0.1").unwrap();
        let dst_ip = IpAddr::from_str("192.168.1.1").unwrap();
        
        // Scan multiple ports
        for port in 1..=60 {
            tracker.record(src_ip, dst_ip, port);
        }
        
        // Should have detected 60 ports scanned
        let last = tracker.record(src_ip, dst_ip, 61);
        assert_eq!(last, 61);
    }
}
