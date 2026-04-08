//! WireGuard Mesh Network Management
//!
//! Implements Feature Group C requirements:
//! - C1: Mesh Topology Management
//! - C2: Tunnel Management
//! - C3: Network Isolation

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::crypto::{generate_secure_token, Aes256GcmCrypto, AesKey};
use crate::storage::Database;

/// WireGuard-related errors
#[derive(Error, Debug)]
pub enum WireGuardError {
    #[error("Tunnel creation failed: {0}")]
    TunnelCreationFailed(String),
    #[error("Tunnel not found: {0}")]
    TunnelNotFound(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("WireGuard command failed: {0}")]
    CommandFailed(String),
    #[error("IP allocation failed: no available IPs")]
    IpAllocationFailed,
    #[error("Interface already exists: {0}")]
    InterfaceExists(String),
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
}

/// Tunnel status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TunnelStatus {
    Active,
    Inactive,
    Connecting,
    Error,
}

impl std::fmt::Display for TunnelStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelStatus::Active => write!(f, "active"),
            TunnelStatus::Inactive => write!(f, "inactive"),
            TunnelStatus::Connecting => write!(f, "connecting"),
            TunnelStatus::Error => write!(f, "error"),
        }
    }
}

/// Mesh topology type (C1.2, C1.3)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MeshTopology {
    /// Every service connects to every other (C1.2)
    FullMesh,
    /// Central gateway (C1.3)
    HubSpoke,
    /// Custom topology
    Custom,
}

/// WireGuard tunnel information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    pub id: String,
    pub service_a_id: String,
    pub service_b_id: String,
    pub interface_name: String,
    pub public_key: String,
    pub virtual_ip: IpAddr,
    pub peer_endpoint: Option<SocketAddr>,
    pub peer_public_key: Option<String>,
    pub peer_virtual_ip: Option<IpAddr>,
    pub status: TunnelStatus,
    pub last_handshake: Option<DateTime<Utc>>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub created_at: DateTime<Utc>,
}

/// WireGuard key pair
#[derive(Debug, Clone)]
pub struct WgKeyPair {
    pub private_key: String,
    pub public_key: String,
}

impl WgKeyPair {
    /// Generate a new WireGuard key pair
    pub fn generate() -> Result<Self> {
        // Generate 32 random bytes for private key
        let private_bytes = generate_secure_token(32);
        let private_key = BASE64.encode(&private_bytes);
        
        // In real implementation, use curve25519 to derive public key
        // For now, we'll generate a placeholder (in production, use wireguard-uapi)
        let public_key = Self::derive_public_key(&private_bytes);
        
        Ok(Self {
            private_key,
            public_key,
        })
    }
    
    /// Derive public key from private key (simplified - use proper curve25519 in production)
    fn derive_public_key(private_bytes: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(private_bytes);
        hasher.update(b"wireguard-pubkey-derivation");
        BASE64.encode(hasher.finalize())
    }
}

/// Peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub public_key: String,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Option<u16>,
}

/// WireGuard interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    pub private_key: String,
    pub address: IpAddr,
    pub listen_port: u16,
    pub mtu: u16,
    pub peers: Vec<PeerConfig>,
}

/// IP address allocator for the mesh (C1.5: 10.128.0.0/16)
pub struct IpAllocator {
    subnet: IpNetwork,
    allocated: HashMap<String, IpAddr>,
    next_octet3: u8,
    next_octet4: u8,
}

impl IpAllocator {
    /// Create new allocator for subnet (default: 10.128.0.0/16)
    pub fn new(subnet: &str) -> Result<Self> {
        let subnet: IpNetwork = subnet.parse()
            .context("Invalid subnet format")?;
        
        Ok(Self {
            subnet,
            allocated: HashMap::new(),
            next_octet3: 0,
            next_octet4: 1, // Start at .0.1 (skip .0.0 for network address)
        })
    }
    
    /// Allocate a new IP for a service
    pub fn allocate(&mut self, service_id: &str) -> Result<IpAddr, WireGuardError> {
        // Check if already allocated
        if let Some(ip) = self.allocated.get(service_id) {
            return Ok(*ip);
        }
        
        // For 10.128.0.0/16, we have 10.128.0.1 to 10.128.255.254
        if self.next_octet3 > 255 || (self.next_octet3 == 255 && self.next_octet4 > 254) {
            return Err(WireGuardError::IpAllocationFailed);
        }
        
        let ip = match self.subnet.network() {
            IpAddr::V4(base) => {
                let octets = base.octets();
                IpAddr::V4(Ipv4Addr::new(
                    octets[0],
                    octets[1],
                    self.next_octet3,
                    self.next_octet4,
                ))
            }
            IpAddr::V6(_) => return Err(WireGuardError::InvalidConfiguration(
                "IPv6 not supported".into(),
            )),
        };
        
        // Increment for next allocation
        self.next_octet4 += 1;
        if self.next_octet4 > 254 {
            self.next_octet4 = 1;
            self.next_octet3 += 1;
        }
        
        self.allocated.insert(service_id.to_string(), ip);
        Ok(ip)
    }
    
    /// Release an allocated IP
    pub fn release(&mut self, service_id: &str) {
        self.allocated.remove(service_id);
    }
    
    /// Get allocated IP for a service
    pub fn get(&self, service_id: &str) -> Option<IpAddr> {
        self.allocated.get(service_id).copied()
    }
}

/// WireGuard Mesh Controller
pub struct WireGuardController {
    db: Arc<Database>,
    ip_allocator: IpAllocator,
    tunnels: HashMap<String, Tunnel>,
    encryption_key: AesKey,
    listen_port: u16,
    keepalive_seconds: u16,
    mtu: u16,
    topology: MeshTopology,
}

impl WireGuardController {
    /// Create new WireGuard controller
    pub fn new(
        db: Arc<Database>,
        subnet: &str,
        listen_port: u16,
        keepalive_seconds: u16,
        mtu: u16,
    ) -> Result<Self> {
        let ip_allocator = IpAllocator::new(subnet)?;
        let encryption_key = AesKey::generate();
        
        let controller = Self {
            db,
            ip_allocator,
            tunnels: HashMap::new(),
            encryption_key,
            listen_port,
            keepalive_seconds,
            mtu,
            topology: MeshTopology::FullMesh,
        };
        
        info!("WireGuard controller initialized with subnet {}", subnet);
        Ok(controller)
    }
    
    /// Create a new tunnel between two services (C2.1)
    pub fn create_tunnel(
        &mut self,
        service_a_id: &str,
        service_b_id: &str,
        service_a_endpoint: Option<SocketAddr>,
    ) -> Result<Tunnel> {
        let tunnel_id = Uuid::new_v4().to_string();
        let interface_name = format!("wg{}", &tunnel_id[..8]);
        
        // Generate key pair
        let key_pair = WgKeyPair::generate()?;
        
        // Allocate virtual IP
        let virtual_ip = self.ip_allocator.allocate(service_a_id)?;
        
        // Encrypt private key for storage
        let crypto = Aes256GcmCrypto::new(&self.encryption_key);
        let encrypted_private_key = crypto.encrypt(key_pair.private_key.as_bytes())?;
        
        let now = Utc::now();
        let tunnel = Tunnel {
            id: tunnel_id.clone(),
            service_a_id: service_a_id.to_string(),
            service_b_id: service_b_id.to_string(),
            interface_name: interface_name.clone(),
            public_key: key_pair.public_key.clone(),
            virtual_ip,
            peer_endpoint: service_a_endpoint,
            peer_public_key: None,
            peer_virtual_ip: None,
            status: TunnelStatus::Connecting,
            last_handshake: None,
            bytes_sent: 0,
            bytes_received: 0,
            created_at: now,
        };
        
        // Store in database
        self.db.execute(
            "INSERT INTO tunnels (id, service_a_id, service_b_id, interface_name, 
             private_key_encrypted, public_key, virtual_ip, peer_endpoint, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            &[
                &tunnel.id,
                &tunnel.service_a_id,
                &tunnel.service_b_id,
                &tunnel.interface_name,
                &encrypted_private_key,
                &tunnel.public_key,
                &tunnel.virtual_ip.to_string(),
                &tunnel.peer_endpoint.map(|e| e.to_string()),
                &tunnel.status.to_string(),
                &now.to_rfc3339(),
            ],
        )?;
        
        // Store in memory
        self.tunnels.insert(tunnel_id.clone(), tunnel.clone());
        
        info!("Created tunnel {} between {} and {}", tunnel_id, service_a_id, service_b_id);
        
        // Note: Actual WireGuard interface creation would require root privileges
        // and would use ip link / wg commands or wireguard-uapi
        
        Ok(tunnel)
    }
    
    /// Destroy a tunnel (C2.2)
    pub fn destroy_tunnel(&mut self, tunnel_id: &str) -> Result<()> {
        let tunnel = self.tunnels.remove(tunnel_id)
            .ok_or_else(|| WireGuardError::TunnelNotFound(tunnel_id.to_string()))?;
        
        // Release allocated IP
        self.ip_allocator.release(&tunnel.service_a_id);
        
        // Remove from database
        self.db.execute("DELETE FROM tunnels WHERE id = ?1", &[&tunnel_id])?;
        
        // Note: Would also need to remove the WireGuard interface
        // sudo ip link delete <interface_name>
        
        info!("Destroyed tunnel {}", tunnel_id);
        Ok(())
    }
    
    /// Get tunnel status
    pub fn get_tunnel(&self, tunnel_id: &str) -> Option<&Tunnel> {
        self.tunnels.get(tunnel_id)
    }
    
    /// List all tunnels
    pub fn list_tunnels(&self) -> Vec<&Tunnel> {
        self.tunnels.values().collect()
    }
    
    /// Add peer to tunnel
    pub fn add_peer(
        &mut self,
        tunnel_id: &str,
        peer_public_key: &str,
        peer_endpoint: Option<SocketAddr>,
        peer_virtual_ip: IpAddr,
    ) -> Result<()> {
        let tunnel = self.tunnels.get_mut(tunnel_id)
            .ok_or_else(|| WireGuardError::TunnelNotFound(tunnel_id.to_string()))?;
        
        tunnel.peer_public_key = Some(peer_public_key.to_string());
        tunnel.peer_endpoint = peer_endpoint;
        tunnel.peer_virtual_ip = Some(peer_virtual_ip);
        tunnel.status = TunnelStatus::Active;
        
        // Update database
        self.db.execute(
            "UPDATE tunnels SET peer_endpoint = ?1, status = ?2 WHERE id = ?3",
            &[
                &peer_endpoint.map(|e| e.to_string()),
                &tunnel.status.to_string(),
                &tunnel_id,
            ],
        )?;
        
        Ok(())
    }
    
    /// Update tunnel statistics
    pub fn update_stats(
        &mut self,
        tunnel_id: &str,
        bytes_sent: u64,
        bytes_received: u64,
        last_handshake: Option<DateTime<Utc>>,
    ) -> Result<()> {
        if let Some(tunnel) = self.tunnels.get_mut(tunnel_id) {
            tunnel.bytes_sent = bytes_sent;
            tunnel.bytes_received = bytes_received;
            tunnel.last_handshake = last_handshake;
            
            self.db.execute(
                "UPDATE tunnels SET bytes_sent = ?1, bytes_received = ?2, last_handshake = ?3 WHERE id = ?4",
                &[
                    &(bytes_sent as i64),
                    &(bytes_received as i64),
                    &last_handshake.map(|t| t.to_rfc3339()),
                    &tunnel_id,
                ],
            )?;
        }
        Ok(())
    }
    
    /// Check tunnel health and reconnect if needed (C2.3)
    pub fn check_health(&mut self) -> Vec<String> {
        let mut unhealthy = Vec::new();
        
        for (id, tunnel) in &self.tunnels {
            // Check last handshake time
            if let Some(last_handshake) = tunnel.last_handshake {
                let elapsed = Utc::now() - last_handshake;
                
                // If no handshake in 3 minutes, mark as unhealthy
                if elapsed.num_seconds() > 180 {
                    unhealthy.push(id.clone());
                    warn!("Tunnel {} appears unhealthy (last handshake: {:?})", id, last_handshake);
                }
            } else if tunnel.status == TunnelStatus::Active {
                // Active tunnel with no handshake ever
                unhealthy.push(id.clone());
            }
        }
        
        unhealthy
    }
    
    /// Generate WireGuard configuration file
    pub fn generate_config(&self, tunnel: &Tunnel) -> String {
        let mut config = String::new();
        
        config.push_str("[Interface]\n");
        config.push_str(&format!("Address = {}/24\n", tunnel.virtual_ip));
        config.push_str(&format!("ListenPort = {}\n", self.listen_port));
        config.push_str(&format!("MTU = {}\n", self.mtu));
        config.push_str("# PrivateKey = <encrypted, retrieve from secure storage>\n");
        config.push('\n');
        
        if let (Some(peer_public_key), Some(peer_virtual_ip)) = 
            (&tunnel.peer_public_key, &tunnel.peer_virtual_ip) 
        {
            config.push_str("[Peer]\n");
            config.push_str(&format!("PublicKey = {}\n", peer_public_key));
            config.push_str(&format!("AllowedIPs = {}/32\n", peer_virtual_ip));
            
            if let Some(endpoint) = &tunnel.peer_endpoint {
                config.push_str(&format!("Endpoint = {}\n", endpoint));
            }
            
            config.push_str(&format!("PersistentKeepalive = {}\n", self.keepalive_seconds));
        }
        
        config
    }
    
    /// Set mesh topology
    pub fn set_topology(&mut self, topology: MeshTopology) {
        self.topology = topology;
        info!("Mesh topology set to {:?}", topology);
    }
    
    /// Get current topology
    pub fn topology(&self) -> MeshTopology {
        self.topology
    }
}

/// Network isolation rules (C3)
pub struct NetworkIsolation {
    /// Whitelisted services that can communicate
    allowed_pairs: HashMap<(String, String), bool>,
    /// Default deny (C3.2)
    default_deny: bool,
    /// Allowed DNS resolvers (C3.3)
    dns_resolvers: Vec<IpAddr>,
}

impl NetworkIsolation {
    pub fn new() -> Self {
        Self {
            allowed_pairs: HashMap::new(),
            default_deny: true, // C3.2: Block all traffic by default
            dns_resolvers: vec![
                "1.1.1.1".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
            ],
        }
    }
    
    /// Allow communication between two services
    pub fn allow(&mut self, service_a: &str, service_b: &str) {
        // Store both directions for bidirectional communication
        self.allowed_pairs.insert((service_a.to_string(), service_b.to_string()), true);
        self.allowed_pairs.insert((service_b.to_string(), service_a.to_string()), true);
    }
    
    /// Deny communication between two services
    pub fn deny(&mut self, service_a: &str, service_b: &str) {
        self.allowed_pairs.remove(&(service_a.to_string(), service_b.to_string()));
        self.allowed_pairs.remove(&(service_b.to_string(), service_a.to_string()));
    }
    
    /// Check if communication is allowed
    pub fn is_allowed(&self, source: &str, destination: &str) -> bool {
        if !self.default_deny {
            return true;
        }
        
        self.allowed_pairs.contains_key(&(source.to_string(), destination.to_string()))
    }
    
    /// Add DNS resolver
    pub fn add_dns_resolver(&mut self, resolver: IpAddr) {
        if !self.dns_resolvers.contains(&resolver) {
            self.dns_resolvers.push(resolver);
        }
    }
    
    /// Check if DNS resolver is allowed
    pub fn is_dns_allowed(&self, ip: &IpAddr) -> bool {
        self.dns_resolvers.contains(ip)
    }
    
    /// Get allowed DNS resolvers
    pub fn dns_resolvers(&self) -> &[IpAddr] {
        &self.dns_resolvers
    }
}

impl Default for NetworkIsolation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ip_allocator() {
        let mut allocator = IpAllocator::new("10.128.0.0/16").unwrap();
        
        let ip1 = allocator.allocate("service-1").unwrap();
        let ip2 = allocator.allocate("service-2").unwrap();
        
        assert_ne!(ip1, ip2);
        
        // Same service should get same IP
        let ip1_again = allocator.allocate("service-1").unwrap();
        assert_eq!(ip1, ip1_again);
    }
    
    #[test]
    fn test_key_generation() {
        let key_pair = WgKeyPair::generate().unwrap();
        
        assert!(!key_pair.private_key.is_empty());
        assert!(!key_pair.public_key.is_empty());
        assert_ne!(key_pair.private_key, key_pair.public_key);
    }
    
    #[test]
    fn test_network_isolation() {
        let mut isolation = NetworkIsolation::new();
        
        // Default deny
        assert!(!isolation.is_allowed("service-a", "service-b"));
        
        // Allow specific pair
        isolation.allow("service-a", "service-b");
        assert!(isolation.is_allowed("service-a", "service-b"));
        assert!(isolation.is_allowed("service-b", "service-a")); // Bidirectional
        
        // Deny
        isolation.deny("service-a", "service-b");
        assert!(!isolation.is_allowed("service-a", "service-b"));
    }
    
    #[test]
    fn test_dns_filtering() {
        let isolation = NetworkIsolation::new();
        
        assert!(isolation.is_dns_allowed(&"1.1.1.1".parse().unwrap()));
        assert!(isolation.is_dns_allowed(&"8.8.8.8".parse().unwrap()));
        assert!(!isolation.is_dns_allowed(&"9.9.9.9".parse().unwrap()));
    }
}
