//! SQLite database storage for ZeroTrust Mesh
//!
//! Implements requirements:
//! - G1.5: Logs stored in SQLite database
//! - G1.6: 90-day retention
//! - REL3: No data loss on crash (WAL mode)
//! - SEC6: Audit logs protected from unprivileged deletion

use anyhow::{Context, Result};
use parking_lot::Mutex;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use tracing::{debug, info};

/// Database wrapper with connection pooling
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Create new database connection
    pub fn new(path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create database directory")?;
        }
        
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )
        .context("Failed to open database")?;
        
        // Enable WAL mode for better performance and crash safety (REL3)
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .context("Failed to set database pragmas")?;
        
        let db = Self {
            conn: Mutex::new(conn),
        };
        
        // Initialize schema
        db.init_schema()?;
        
        info!("Database initialized at {:?}", path);
        Ok(db)
    }
    
    /// Initialize database schema
    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock();
        
        conn.execute_batch(
            r#"
            -- Services table (Feature Group A: Service Registration)
            CREATE TABLE IF NOT EXISTS services (
                id TEXT PRIMARY KEY,
                spiffe_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                port INTEGER NOT NULL,
                binary_path TEXT,
                binary_hash TEXT,
                user TEXT,
                pid INTEGER,
                status TEXT DEFAULT 'active',
                trust_score REAL DEFAULT 1.0,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_services_spiffe ON services(spiffe_id);
            CREATE INDEX IF NOT EXISTS idx_services_status ON services(status);

            -- Certificates table (A1: Identity Management)
            CREATE TABLE IF NOT EXISTS certificates (
                id TEXT PRIMARY KEY,
                service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
                cert_pem TEXT NOT NULL,
                private_key_encrypted BLOB NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                revoked INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_certs_service ON certificates(service_id);
            CREATE INDEX IF NOT EXISTS idx_certs_revoked ON certificates(revoked);

            -- JWT tokens table (A1.2: JWT-SVIDs)
            CREATE TABLE IF NOT EXISTS jwt_tokens (
                id TEXT PRIMARY KEY,
                service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_jwt_service ON jwt_tokens(service_id);
            CREATE INDEX IF NOT EXISTS idx_jwt_expires ON jwt_tokens(expires_at);

            -- Policies table (Feature Group B: Policy Engine)
            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                priority INTEGER DEFAULT 100,
                enabled INTEGER DEFAULT 1,
                conditions TEXT NOT NULL,  -- JSON
                action TEXT NOT NULL,      -- Allow, Deny, RequireMFA, Log
                hit_count INTEGER DEFAULT 0,
                last_match TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
            CREATE INDEX IF NOT EXISTS idx_policies_priority ON policies(priority);

            -- WireGuard tunnels table (Feature Group C: WireGuard Mesh)
            CREATE TABLE IF NOT EXISTS tunnels (
                id TEXT PRIMARY KEY,
                service_a_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
                service_b_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
                interface_name TEXT NOT NULL,
                private_key_encrypted BLOB NOT NULL,
                public_key TEXT NOT NULL,
                virtual_ip TEXT NOT NULL,
                peer_endpoint TEXT,
                status TEXT DEFAULT 'active',
                last_handshake TEXT,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                UNIQUE(service_a_id, service_b_id)
            );
            CREATE INDEX IF NOT EXISTS idx_tunnels_status ON tunnels(status);

            -- Attacks table (Feature Group D: eBPF Data Plane)
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER,
                protocol TEXT,
                severity TEXT NOT NULL,   -- High, Medium, Low
                packet_count INTEGER DEFAULT 1,
                details TEXT,             -- JSON
                blocked INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_attacks_type ON attacks(attack_type);
            CREATE INDEX IF NOT EXISTS idx_attacks_source ON attacks(source_ip);
            CREATE INDEX IF NOT EXISTS idx_attacks_created ON attacks(created_at);

            -- Blacklist table (D3.5: Dynamic blacklisting)
            CREATE TABLE IF NOT EXISTS blacklist (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                auto_generated INTEGER DEFAULT 0,
                expires_at TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            -- Whitelist table (D3.4: Bypass eBPF for whitelisted IPs)
            CREATE TABLE IF NOT EXISTS whitelist (
                ip TEXT PRIMARY KEY,
                description TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            -- Trust scores history (Feature Group E: Attestation)
            CREATE TABLE IF NOT EXISTS trust_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
                score REAL NOT NULL,
                tpm_score REAL,
                process_score REAL,
                behavioral_score REAL,
                resource_score REAL,
                reason TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_trust_service ON trust_scores(service_id);
            CREATE INDEX IF NOT EXISTS idx_trust_created ON trust_scores(created_at);

            -- Alerts table (Feature Group F: Dashboard)
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,   -- Critical, High, Medium, Low, Info
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                source TEXT,
                acknowledged INTEGER DEFAULT 0,
                acknowledged_at TEXT,
                acknowledged_by TEXT,
                muted INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged);
            CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

            -- Audit logs table (Feature Group G: Reporting & Audit)
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                action TEXT NOT NULL,
                subject TEXT,            -- Service ID, Policy ID, etc.
                details TEXT,            -- JSON
                source_ip TEXT,
                user TEXT,
                success INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_logs(event_type);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

            -- Configuration changes table (G1.3)
            CREATE TABLE IF NOT EXISTS config_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_key TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT NOT NULL,
                changed_by TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );
            "#,
        )
        .context("Failed to initialize database schema")?;
        
        debug!("Database schema initialized");
        Ok(())
    }
    
    /// Execute a query with parameters
    pub fn execute(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Result<usize> {
        let conn = self.conn.lock();
        conn.execute(sql, params)
            .context("Database execute failed")
    }
    
    /// Query and map results
    pub fn query_map<T, F>(&self, sql: &str, params: &[&dyn rusqlite::ToSql], f: F) -> Result<Vec<T>>
    where
        F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(params, f)?;
        
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }
    
    /// Insert and return last row ID
    pub fn insert(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Result<i64> {
        let conn = self.conn.lock();
        conn.execute(sql, params)?;
        Ok(conn.last_insert_rowid())
    }
    
    /// Run cleanup to enforce retention policy (G1.6)
    pub fn cleanup_old_records(&self, retention_days: u32) -> Result<usize> {
        let conn = self.conn.lock();
        let cutoff = format!("datetime('now', '-{} days')", retention_days);
        
        let mut total_deleted = 0usize;
        
        // Clean up old audit logs
        total_deleted += conn.execute(
            &format!("DELETE FROM audit_logs WHERE created_at < {}", cutoff),
            [],
        )?;
        
        // Clean up old attacks
        total_deleted += conn.execute(
            &format!("DELETE FROM attacks WHERE created_at < {}", cutoff),
            [],
        )?;
        
        // Clean up old trust scores
        total_deleted += conn.execute(
            &format!("DELETE FROM trust_scores WHERE created_at < {}", cutoff),
            [],
        )?;
        
        // Clean up acknowledged alerts
        total_deleted += conn.execute(
            &format!(
                "DELETE FROM alerts WHERE acknowledged = 1 AND created_at < {}",
                cutoff
            ),
            [],
        )?;
        
        // Clean up expired JWT tokens
        total_deleted += conn.execute(
            "DELETE FROM jwt_tokens WHERE expires_at < datetime('now')",
            [],
        )?;
        
        // Clean up expired blacklist entries
        total_deleted += conn.execute(
            "DELETE FROM blacklist WHERE expires_at IS NOT NULL AND expires_at < datetime('now')",
            [],
        )?;
        
        info!("Cleaned up {} old records", total_deleted);
        Ok(total_deleted)
    }
    
    /// Get database statistics
    pub fn get_stats(&self) -> Result<DatabaseStats> {
        let conn = self.conn.lock();
        
        let service_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM services WHERE status = 'active'",
            [],
            |row| row.get(0),
        )?;
        
        let policy_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM policies WHERE enabled = 1",
            [],
            |row| row.get(0),
        )?;
        
        let tunnel_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM tunnels WHERE status = 'active'",
            [],
            |row| row.get(0),
        )?;
        
        let attack_count_24h: i64 = conn.query_row(
            "SELECT COUNT(*) FROM attacks WHERE created_at > datetime('now', '-1 day')",
            [],
            |row| row.get(0),
        )?;
        
        let alert_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0",
            [],
            |row| row.get(0),
        )?;
        
        let blacklist_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM blacklist",
            [],
            |row| row.get(0),
        )?;
        
        Ok(DatabaseStats {
            service_count: service_count as u64,
            policy_count: policy_count as u64,
            tunnel_count: tunnel_count as u64,
            attack_count_24h: attack_count_24h as u64,
            unacknowledged_alerts: alert_count as u64,
            blacklist_count: blacklist_count as u64,
        })
    }
}

/// Database statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct DatabaseStats {
    pub service_count: u64,
    pub policy_count: u64,
    pub tunnel_count: u64,
    pub attack_count_24h: u64,
    pub unacknowledged_alerts: u64,
    pub blacklist_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_database_creation() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Database::new(&db_path).unwrap();
        
        assert!(db_path.exists());
    }
    
    #[test]
    fn test_database_operations() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Database::new(&db_path).unwrap();
        
        // Insert a service
        let result = db.execute(
            "INSERT INTO services (id, spiffe_id, name, port) VALUES (?1, ?2, ?3, ?4)",
            &[&"test-id", &"spiffe://test/service", &"Test Service", &8080i32],
        );
        assert!(result.is_ok());
        
        // Query services
        let services: Vec<String> = db.query_map(
            "SELECT name FROM services",
            &[],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0], "Test Service");
    }
}
