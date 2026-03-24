// ============================================================================
// File: config.rs
// Description: Shield security engine configuration for all defense layers
// Author: Andrew Jewell Sr. - AutomataNexus
// Updated: March 24, 2026
//
// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
use std::collections::HashSet;
use crate::email_guard::EmailGuardConfig;

/// Complete configuration for the Shield security engine.
#[derive(Debug, Clone)]
pub struct ShieldConfig {
    /// Threat score threshold above which requests are blocked (0.0–1.0).
    pub block_threshold: f64,
    /// Threat score threshold for logging warnings (0.0–1.0).
    pub warn_threshold: f64,
    /// SQL firewall configuration.
    pub sql: SqlFirewallConfig,
    /// SSRF guard configuration.
    pub ssrf: SsrfConfig,
    /// Rate limiting configuration.
    pub rate: RateConfig,
    /// Data quarantine configuration.
    pub quarantine: QuarantineConfig,
    /// Maximum audit chain events to keep in memory before pruning.
    pub audit_max_events: usize,
    /// Email guard configuration.
    pub email: EmailGuardConfig,
}

#[derive(Debug, Clone)]
pub struct SqlFirewallConfig {
    /// Allow SQL comments (-- and /* */) in queries. Default: false.
    pub allow_comments: bool,
    /// Maximum query length in bytes. Default: 10_000.
    pub max_query_length: usize,
    /// Maximum nesting depth for subqueries. Default: 3.
    pub max_subquery_depth: u32,
    /// Additional function names to block (beyond built-in dangerous list).
    pub blocked_functions: Vec<String>,
    /// Additional schema names to block (beyond built-in system schemas).
    pub blocked_schemas: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SsrfConfig {
    /// Block requests to private/internal IP ranges. Default: true.
    pub block_private_ips: bool,
    /// Block requests to loopback addresses. Default: true.
    pub block_loopback: bool,
    /// Block requests to link-local addresses (169.254.x.x). Default: true.
    pub block_link_local: bool,
    /// Block requests to cloud metadata endpoints (169.254.169.254). Default: true.
    pub block_metadata_endpoints: bool,
    /// Allowed URL schemes. Default: ["http", "https"].
    pub allowed_schemes: Vec<String>,
    /// Explicit IP/host allowlist (bypasses all checks).
    pub allowlist: HashSet<String>,
    /// Explicit IP/host blocklist (checked before allowlist).
    pub blocklist: HashSet<String>,
    /// Blocked ports (e.g., 22 SSH, 6379 Redis). Default: common internal service ports.
    pub blocked_ports: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct RateConfig {
    /// Maximum requests per second per IP. Default: 50.
    pub requests_per_second: f64,
    /// Burst allowance (token bucket capacity). Default: 100.
    pub burst_capacity: f64,
    /// Number of violations before escalating to warn. Default: 3.
    pub warn_after: u32,
    /// Number of violations before throttling. Default: 8.
    pub throttle_after: u32,
    /// Number of violations before blocking. Default: 15.
    pub block_after: u32,
    /// Number of violations before temporary ban. Default: 30.
    pub ban_after: u32,
    /// Ban duration in seconds. Default: 300 (5 minutes).
    pub ban_duration_secs: u64,
    /// Violation decay period in seconds. Default: 60.
    pub violation_decay_secs: u64,
}

#[derive(Debug, Clone)]
pub struct QuarantineConfig {
    /// Maximum rows allowed in imported data. Default: 5_000_000.
    pub max_rows: usize,
    /// Maximum total size in bytes. Default: 500 MB.
    pub max_size_bytes: usize,
    /// Maximum columns allowed. Default: 500.
    pub max_columns: usize,
    /// Check for formula injection (=, +, -, @). Default: true.
    pub check_formula_injection: bool,
    /// Check for embedded scripts. Default: true.
    pub check_embedded_scripts: bool,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            block_threshold: 0.7,
            warn_threshold: 0.4,
            sql: SqlFirewallConfig::default(),
            ssrf: SsrfConfig::default(),
            rate: RateConfig::default(),
            quarantine: QuarantineConfig::default(),
            audit_max_events: 100_000,
            email: EmailGuardConfig::default(),
        }
    }
}

impl Default for SqlFirewallConfig {
    fn default() -> Self {
        Self {
            allow_comments: false,
            max_query_length: 10_000,
            max_subquery_depth: 3,
            blocked_functions: Vec::new(),
            blocked_schemas: Vec::new(),
        }
    }
}

impl Default for SsrfConfig {
    fn default() -> Self {
        Self {
            block_private_ips: true,
            block_loopback: true,
            block_link_local: true,
            block_metadata_endpoints: true,
            allowed_schemes: vec!["http".into(), "https".into()],
            allowlist: HashSet::new(),
            blocklist: HashSet::new(),
            blocked_ports: vec![
                22, 23, 25, 53, 111, 135, 139, 445, 514, 873,
                2049, 3306, 5432, 6379, 6380, 9200, 9300,
                11211, 27017, 27018, 50070,
            ],
        }
    }
}

impl Default for RateConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 50.0,
            burst_capacity: 100.0,
            warn_after: 3,
            throttle_after: 8,
            block_after: 15,
            ban_after: 30,
            ban_duration_secs: 300,
            violation_decay_secs: 60,
        }
    }
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            max_rows: 5_000_000,
            max_size_bytes: 500 * 1024 * 1024,
            max_columns: 500,
            check_formula_injection: true,
            check_embedded_scripts: true,
        }
    }
}
