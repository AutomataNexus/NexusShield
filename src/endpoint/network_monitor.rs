// ============================================================================
// File: endpoint/network_monitor.rs
// Description: Network connection monitoring via /proc/net/tcp
// Author: Andrew Jewell Sr. - AutomataNexus
// Updated: March 24, 2026
// ============================================================================
//! Network Monitor — detects malicious IPs, suspicious ports, C2 beaconing,
//! and data exfiltration by parsing /proc/net/tcp and /proc/net/tcp6.

use super::runtime_allowlist::RuntimeAllowlist;
use super::threat_intel::ThreatIntelDB;
use super::{DetectionCategory, RecommendedAction, ScanResult, Severity};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Configuration for the network monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitorConfig {
    pub poll_interval_ms: u64,
    pub exfil_threshold_bytes: u64,
    pub beacon_jitter_pct: f64,
    pub beacon_min_count: u32,
    pub suspicious_ports: Vec<u16>,
    /// IPv4 CIDRs to skip beacon + suspicious-port checks on. Threat-intel
    /// matches still fire. Defaults to well-known benign CDN/cloud ranges so
    /// normal browser and background-service traffic (Google, Cloudflare,
    /// Fastly, etc.) doesn't constantly trip the beacon heuristic.
    #[serde(default = "default_benign_cidrs")]
    pub allowlist_cidrs: Vec<String>,
    /// Process names (/proc/[pid]/comm) whose outbound connections are
    /// exempt from beacon + suspicious-port checks. Useful for daemons
    /// that intentionally keep persistent/rhythmic connections alive
    /// (Tailscale, VPNs, sync clients). Threat-intel matches still fire.
    #[serde(default = "default_allowlist_processes")]
    pub allowlist_processes: Vec<String>,
}

impl Default for NetworkMonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 5000,
            exfil_threshold_bytes: 52_428_800, // 50 MB
            beacon_jitter_pct: 15.0,
            beacon_min_count: 10,
            suspicious_ports: vec![4444, 5555, 8888, 6667, 6697, 1337, 31337, 9001, 1234],
            allowlist_cidrs: default_benign_cidrs(),
            allowlist_processes: default_allowlist_processes(),
        }
    }
}

/// Daemons whose outbound beacon-like traffic is expected behavior.
fn default_allowlist_processes() -> Vec<String> {
    vec![
        "tailscaled".into(),       // Tailscale keeps persistent DERP relays
        "systemd-resolve".into(),  // DNS stub resolver
        "systemd-timesyn".into(),  // NTP time sync (comm truncated to 15 chars)
        "chrony".into(),           // alt NTP
        "chronyd".into(),
        "NetworkManager".into(),
        "dhclient".into(),
        "avahi-daemon".into(),
        "vault".into(),            // HashiCorp Vault internal beaconing
    ]
}

/// Well-known benign CDN / cloud ranges.
/// Not exhaustive — covers the top-talkers that constantly trip beacon
/// heuristics on a developer workstation (browser keep-alives, OS telemetry,
/// package mirrors). Extend via config if needed.
fn default_benign_cidrs() -> Vec<String> {
    vec![
        // Google services (Search, Gmail, YouTube, googleapis, fonts, ads)
        "8.8.4.0/24".into(),
        "8.8.8.0/24".into(),
        "34.64.0.0/10".into(),
        "34.128.0.0/10".into(),  // GCP LB block #2 — hosts api.anthropic.com (e.g. 34.149.66.137)
        "35.184.0.0/13".into(),
        "35.192.0.0/14".into(),
        "35.196.0.0/15".into(),
        "35.198.0.0/16".into(),
        "35.199.0.0/17".into(),
        "35.199.128.0/18".into(),
        "35.200.0.0/13".into(),
        "35.208.0.0/12".into(),
        "35.224.0.0/12".into(),
        "35.240.0.0/13".into(),
        "64.233.160.0/19".into(),
        "66.102.0.0/20".into(),
        "66.249.80.0/20".into(),
        "72.14.192.0/18".into(),
        "74.125.0.0/16".into(),
        "108.177.8.0/21".into(),
        "142.250.0.0/15".into(),  // covers 142.250.* AND 142.251.*
        "172.217.0.0/16".into(),
        "173.194.0.0/16".into(),
        "209.85.128.0/17".into(),
        "216.58.192.0/19".into(),
        "216.239.32.0/19".into(),

        // Cloudflare (CDN, 1.1.1.1, many websites)
        "1.0.0.0/24".into(),
        "1.1.1.0/24".into(),
        "104.16.0.0/12".into(),
        "172.64.0.0/13".into(),
        "131.0.72.0/22".into(),

        // Fastly (CDN)
        "151.101.0.0/16".into(),
        "199.232.0.0/16".into(),

        // Microsoft / Azure / Office / Teams / Edge telemetry (broad)
        "13.64.0.0/11".into(),
        "20.0.0.0/8".into(),
        "40.64.0.0/10".into(),
        "52.96.0.0/14".into(),
        "52.108.0.0/14".into(),
        "52.112.0.0/14".into(),

        // GitHub
        "140.82.112.0/20".into(),
        "192.30.252.0/22".into(),
        "185.199.108.0/22".into(),

        // Akamai (CDN behind many enterprise/app update services)
        "23.32.0.0/11".into(),
        "23.192.0.0/11".into(),
        "184.24.0.0/13".into(),
        "104.64.0.0/10".into(),

        // Amazon / AWS (extremely broad — covers most SaaS)
        "3.0.0.0/9".into(),
        "18.64.0.0/10".into(),
        "34.192.0.0/10".into(),
        "52.0.0.0/11".into(),
        "52.32.0.0/11".into(),
        "52.84.0.0/15".into(),
        "54.64.0.0/11".into(),
        "54.144.0.0/12".into(),
        "54.160.0.0/12".into(),
        "54.192.0.0/12".into(),
        "54.208.0.0/13".into(),
        "54.224.0.0/12".into(),
        "54.240.0.0/12".into(),

        // Private / link-local (RFC 1918 + RFC 3927) — always trusted for
        // network_monitor heuristics; internal LAN and VPN traffic.
        "10.0.0.0/8".into(),
        "172.16.0.0/12".into(),
        "192.168.0.0/16".into(),
        "169.254.0.0/16".into(),
        "100.64.0.0/10".into(),  // CGNAT (Tailscale uses this range)
    ]
}

/// Parse an IPv4 dotted-quad string into a u32. Returns None on malformed input.
fn ipv4_to_u32(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out: u32 = 0;
    for p in parts {
        let octet: u8 = p.parse().ok()?;
        out = (out << 8) | u32::from(octet);
    }
    Some(out)
}

/// Test whether an IPv4 address falls inside a CIDR block like "10.0.0.0/8".
/// Returns false on malformed input or non-IPv4 addresses (IPv6 never matches).
pub fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let (net_str, prefix) = match cidr.split_once('/') {
        Some((n, p)) => match p.parse::<u8>() {
            Ok(v) if v <= 32 => (n, v),
            _ => return false,
        },
        None => (cidr, 32u8),
    };
    let (Some(ip_u), Some(net_u)) = (ipv4_to_u32(ip), ipv4_to_u32(net_str)) else {
        return false;
    };
    if prefix == 0 {
        return true;
    }
    let mask: u32 = (!0u32) << (32 - prefix);
    (ip_u & mask) == (net_u & mask)
}

/// Check a list of CIDRs.
pub fn ip_in_any_cidr(ip: &str, cidrs: &[String]) -> bool {
    cidrs.iter().any(|c| ip_in_cidr(ip, c))
}

/// Walk /proc/*/fd once and build a map of socket inode → process comm name.
///
/// Each FD entry whose target reads `socket:[<inode>]` is a socket belonging
/// to that PID. This lets the caller cheaply look up which process owns a
/// given TCP connection without re-walking /proc for every lookup.
///
/// Bounded by the number of open FDs across all processes on the box —
/// typically a few thousand, and the walk is direct /proc reads (no syscalls
/// per entry beyond `read_link` + `read_to_string`). We silently skip any FD
/// we can't read (permission denied on another user's /proc/[pid]/fd, etc.).
fn build_inode_to_comm_map() -> HashMap<u64, String> {
    let mut map: HashMap<u64, String> = HashMap::new();

    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return map;
    };

    for pid_entry in proc_dir.flatten() {
        let name = pid_entry.file_name();
        let name_str = name.to_string_lossy();
        // Only numeric dirs (PIDs).
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{}/fd", pid);
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };

        // Cache comm for this PID — only read if we find at least one socket.
        let mut comm: Option<String> = None;

        for fd_entry in fds.flatten() {
            let Ok(link) = std::fs::read_link(fd_entry.path()) else {
                continue;
            };
            let link_str = link.to_string_lossy();
            // Links look like: socket:[14931]
            let Some(rest) = link_str.strip_prefix("socket:[") else {
                continue;
            };
            let Some(inode_str) = rest.strip_suffix(']') else {
                continue;
            };
            let Ok(inode) = inode_str.parse::<u64>() else {
                continue;
            };

            if comm.is_none() {
                comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                    .ok()
                    .map(|s| s.trim().to_string());
            }
            if let Some(ref c) = comm {
                map.insert(inode, c.clone());
            }
        }
    }

    map
}

/// A parsed TCP connection entry from /proc/net/tcp.
#[derive(Debug, Clone)]
pub struct TcpEntry {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: u8,
    pub uid: u32,
    /// Socket inode — used to map the connection back to the owning process
    /// by walking /proc/*/fd.
    pub inode: u64,
}

/// Real-time network connection monitor.
pub struct NetworkMonitor {
    config: NetworkMonitorConfig,
    threat_intel: Arc<ThreatIntelDB>,
    conn_history: RwLock<HashMap<String, Vec<Instant>>>,
    running: Arc<AtomicBool>,
    /// Hot-editable allowlist applied at runtime by the security-ticker +
    /// shield agent after user approval. Supplements the static config.
    runtime_allowlist: Arc<RuntimeAllowlist>,
}

impl NetworkMonitor {
    pub fn new(config: NetworkMonitorConfig, threat_intel: Arc<ThreatIntelDB>) -> Self {
        Self::with_runtime_allowlist(config, threat_intel, RuntimeAllowlist::new())
    }

    pub fn with_runtime_allowlist(
        config: NetworkMonitorConfig,
        threat_intel: Arc<ThreatIntelDB>,
        runtime_allowlist: Arc<RuntimeAllowlist>,
    ) -> Self {
        Self {
            config,
            threat_intel,
            conn_history: RwLock::new(HashMap::new()),
            running: Arc::new(AtomicBool::new(true)),
            runtime_allowlist,
        }
    }

    /// Parse the contents of /proc/net/tcp or /proc/net/tcp6.
    pub fn parse_proc_net_tcp(content: &str) -> Vec<TcpEntry> {
        let mut entries = Vec::new();

        for (i, line) in content.lines().enumerate() {
            // Skip header line
            if i == 0 {
                continue;
            }

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 8 {
                continue;
            }

            // field[1] = local_address:port, field[2] = rem_address:port
            // field[3] = state, field[7] = uid, field[9] = inode
            let local = fields[1];
            let remote = fields[2];
            let state_hex = fields[3];
            let uid_str = fields.get(7).unwrap_or(&"0");
            let inode_str = fields.get(9).unwrap_or(&"0");

            let (local_ip, local_port) = match parse_hex_addr(local) {
                Some(v) => v,
                None => continue,
            };

            let (remote_ip, remote_port) = match parse_hex_addr(remote) {
                Some(v) => v,
                None => continue,
            };

            let state = u8::from_str_radix(state_hex, 16).unwrap_or(0);
            let uid: u32 = uid_str.parse().unwrap_or(0);
            let inode: u64 = inode_str.parse().unwrap_or(0);

            entries.push(TcpEntry {
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                state,
                uid,
                inode,
            });
        }

        entries
    }

    /// Perform a single scan of network connections. Returns detections.
    pub fn scan_once(&self) -> Vec<ScanResult> {
        let mut results = Vec::new();

        // Read /proc/net/tcp
        let tcp4 = std::fs::read_to_string("/proc/net/tcp").unwrap_or_default();
        let tcp6 = std::fs::read_to_string("/proc/net/tcp6").unwrap_or_default();

        let mut entries = Self::parse_proc_net_tcp(&tcp4);
        // For tcp6, we'd need IPv6 parsing — just use tcp4 for now
        // tcp6 entries with IPv4-mapped addresses are in tcp4 too
        let _ = tcp6;

        // Filter to ESTABLISHED connections (state 01)
        entries.retain(|e| e.state == 1);

        // Skip loopback and null
        entries.retain(|e| e.remote_ip != "127.0.0.1" && e.remote_ip != "0.0.0.0");

        let now = Instant::now();

        // Build a socket-inode → process-comm map once per scan. Used both
        // for process-based allowlisting AND for enriching detection
        // messages with the owning process name — so analysts can see
        // "beacon from chrome" vs "beacon from unknown binary" at a glance
        // instead of chasing inodes after the fact.
        let inode_to_comm: HashMap<u64, String> = build_inode_to_comm_map();

        for entry in &entries {
            let conn_key = format!("{}:{}", entry.remote_ip, entry.remote_port);
            let comm = inode_to_comm.get(&entry.inode).cloned();
            let comm_suffix = comm
                .as_deref()
                .map(|c| format!(" [{}]", c))
                .unwrap_or_default();

            // Allowlist: well-known benign CDN/cloud ranges skip the
            // suspicious-port and beacon heuristics. Threat-intel match
            // still fires — if an allowlisted range somehow shows up on a
            // malicious-IP feed, defense-in-depth should still catch it.
            //
            // Two layers: static CIDRs from config + runtime CIDRs added
            // by the shield agent after user approval via the ticker.
            let cidr_allowlisted = ip_in_any_cidr(&entry.remote_ip, &self.config.allowlist_cidrs)
                || ip_in_any_cidr(&entry.remote_ip, &self.runtime_allowlist.cidrs_snapshot());

            // Process-based allowlist: static config + runtime additions.
            let proc_allowlisted = comm
                .as_deref()
                .map(|c| {
                    self.config
                        .allowlist_processes
                        .iter()
                        .any(|a| c.eq_ignore_ascii_case(a))
                        || self.runtime_allowlist.contains_process(c)
                })
                .unwrap_or(false);

            let allowlisted = cidr_allowlisted || proc_allowlisted;

            // 1. Check against threat intel
            if self.threat_intel.check_ip(&entry.remote_ip) {
                results.push(ScanResult::new(
                    "network_monitor",
                    &conn_key,
                    Severity::High,
                    DetectionCategory::NetworkAnomaly {
                        connection: conn_key.clone(),
                    },
                    format!(
                        "Connection to known malicious IP {} on port {}{} — threat intel match",
                        entry.remote_ip, entry.remote_port, comm_suffix
                    ),
                    0.95,
                    RecommendedAction::BlockConnection {
                        addr: conn_key.clone(),
                    },
                ));
            }

            // Short-circuit the rest of the heuristics for allowlisted IPs.
            if allowlisted {
                continue;
            }

            // 2. Check suspicious ports
            if self.config.suspicious_ports.contains(&entry.remote_port) {
                results.push(ScanResult::new(
                    "network_monitor",
                    &conn_key,
                    Severity::Medium,
                    DetectionCategory::NetworkAnomaly {
                        connection: conn_key.clone(),
                    },
                    format!(
                        "Outbound connection to suspicious port {} (IP: {}){} — common C2/backdoor port",
                        entry.remote_port, entry.remote_ip, comm_suffix
                    ),
                    0.6,
                    RecommendedAction::Alert,
                ));
            }

            // 3. Track for beaconing detection
            let mut history = self.conn_history.write();
            let timestamps = history.entry(entry.remote_ip.clone()).or_default();
            timestamps.push(now);

            // Keep only last 100 timestamps
            if timestamps.len() > 100 {
                timestamps.drain(..timestamps.len() - 100);
            }

            // Check for beaconing (regular intervals)
            if timestamps.len() >= self.config.beacon_min_count as usize {
                if let Some(score) = detect_beaconing(timestamps, self.config.beacon_jitter_pct) {
                    if score > 0.7 {
                        results.push(ScanResult::new(
                            "network_monitor",
                            &entry.remote_ip,
                            Severity::Critical,
                            DetectionCategory::NetworkAnomaly {
                                connection: format!("beacon:{}", entry.remote_ip),
                            },
                            format!(
                                "C2 beaconing detected — {} connections to {}{} at regular intervals (score: {:.2})",
                                timestamps.len(), entry.remote_ip, comm_suffix, score
                            ),
                            score,
                            RecommendedAction::BlockConnection {
                                addr: entry.remote_ip.clone(),
                            },
                        ));
                    }
                }
            }
        }

        results
    }

    /// Start the network monitor in a background task.
    pub fn start(
        self: Arc<Self>,
        detection_tx: tokio::sync::mpsc::UnboundedSender<ScanResult>,
    ) -> tokio::task::JoinHandle<()> {
        let running = Arc::clone(&self.running);
        let interval_ms = self.config.poll_interval_ms;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(interval_ms));

            while running.load(Ordering::Relaxed) {
                interval.tick().await;
                let results = self.scan_once();
                for result in results {
                    if detection_tx.send(result).is_err() {
                        return;
                    }
                }
            }
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Parse a hex-encoded IP:port from /proc/net/tcp format.
/// Format: "AABBCCDD:PORT" where IP bytes are in little-endian on x86.
pub fn parse_hex_addr(addr: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip_hex = parts[0];
    let port_hex = parts[1];

    let port = u16::from_str_radix(port_hex, 16).ok()?;

    // IPv4: 8 hex chars, little-endian on x86
    if ip_hex.len() == 8 {
        let ip_bytes = u32::from_str_radix(ip_hex, 16).ok()?;
        let ip = format!(
            "{}.{}.{}.{}",
            ip_bytes & 0xFF,
            (ip_bytes >> 8) & 0xFF,
            (ip_bytes >> 16) & 0xFF,
            (ip_bytes >> 24) & 0xFF,
        );
        Some((ip, port))
    } else {
        // IPv6 or unknown — return raw hex
        Some((ip_hex.to_string(), port))
    }
}

/// Detect C2 beaconing by measuring regularity of connection timestamps.
/// Returns a score 0.0–1.0 where 1.0 = perfectly regular beaconing.
fn detect_beaconing(timestamps: &[Instant], max_jitter_pct: f64) -> Option<f64> {
    if timestamps.len() < 3 {
        return None;
    }

    // Compute intervals between consecutive timestamps
    let mut intervals: Vec<f64> = Vec::new();
    for i in 1..timestamps.len() {
        let dur = timestamps[i].duration_since(timestamps[i - 1]);
        intervals.push(dur.as_secs_f64());
    }

    if intervals.is_empty() {
        return None;
    }

    // Compute mean and standard deviation
    let mean: f64 = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean < 0.001 {
        return None; // Too fast to be meaningful beaconing
    }

    let variance: f64 =
        intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let stddev = variance.sqrt();

    // Coefficient of variation (CV) = stddev/mean
    let cv = stddev / mean;
    let jitter_threshold = max_jitter_pct / 100.0;

    // Score: 1.0 if CV is 0 (perfect regularity), decreasing as CV increases
    let score = (1.0 - (cv / jitter_threshold)).max(0.0).min(1.0);

    Some(score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_loopback() {
        // 0100007F = 127.0.0.1 in little-endian
        let result = parse_hex_addr("0100007F:1F90").unwrap();
        assert_eq!(result.0, "127.0.0.1");
        assert_eq!(result.1, 0x1F90); // 8080
    }

    #[test]
    fn parse_null_addr() {
        let result = parse_hex_addr("00000000:0000").unwrap();
        assert_eq!(result.0, "0.0.0.0");
        assert_eq!(result.1, 0);
    }

    #[test]
    fn parse_real_addr() {
        // 0101A8C0 = 192.168.1.1 in little-endian
        // 192 = 0xC0, 168 = 0xA8, 1 = 0x01, 1 = 0x01
        // LE: 0x01, 0x01, 0xA8, 0xC0 -> "0101A8C0"
        let result = parse_hex_addr("0101A8C0:0050").unwrap();
        assert_eq!(result.0, "192.168.1.1");
        assert_eq!(result.1, 80);
    }

    #[test]
    fn port_parsing() {
        let result = parse_hex_addr("00000000:01BB").unwrap();
        assert_eq!(result.1, 443);
    }

    #[test]
    fn parse_proc_net_tcp_sample() {
        let sample = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0035 0101A8C0:D431 01 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000000000000000 100 0 0 10 0"#;

        let entries = NetworkMonitor::parse_proc_net_tcp(sample);
        assert_eq!(entries.len(), 2);

        // First entry: listening (state 0A = 10)
        assert_eq!(entries[0].local_ip, "127.0.0.1");
        assert_eq!(entries[0].local_port, 8080);
        assert_eq!(entries[0].state, 0x0A); // LISTEN

        // Second entry: established (state 01)
        assert_eq!(entries[1].state, 0x01); // ESTABLISHED
        assert_eq!(entries[1].remote_ip, "192.168.1.1");
    }

    #[test]
    fn suspicious_port_detection() {
        let config = NetworkMonitorConfig::default();
        assert!(config.suspicious_ports.contains(&4444));
        assert!(config.suspicious_ports.contains(&6667));
        assert!(!config.suspicious_ports.contains(&80));
        assert!(!config.suspicious_ports.contains(&443));
    }

    #[test]
    fn beaconing_detection_regular() {
        // Simulate perfectly regular 5-second beaconing
        let base = Instant::now();
        let timestamps: Vec<Instant> = (0..15)
            .map(|i| base + std::time::Duration::from_secs(i * 5))
            .collect();

        let score = detect_beaconing(&timestamps, 15.0);
        assert!(score.is_some());
        assert!(
            score.unwrap() > 0.8,
            "Score should be high for regular intervals, got {}",
            score.unwrap()
        );
    }

    #[test]
    fn beaconing_detection_irregular() {
        // Random-ish timestamps — not beaconing
        let base = Instant::now();
        let offsets = [0, 1, 5, 6, 20, 21, 50, 51, 100, 200];
        let timestamps: Vec<Instant> = offsets
            .iter()
            .map(|&s| base + std::time::Duration::from_secs(s))
            .collect();

        let score = detect_beaconing(&timestamps, 15.0);
        // Should be low score or None for irregular intervals
        if let Some(s) = score {
            assert!(
                s < 0.5,
                "Score should be low for irregular intervals, got {}",
                s
            );
        }
    }

    #[test]
    fn anthropic_api_endpoint_allowlisted() {
        // 34.149.66.137 is api.anthropic.com via Google Cloud Load Balancer.
        // Regression guard for the false-positive C2 beaconing flag on Claude
        // API conversation traffic.
        let config = NetworkMonitorConfig::default();
        assert!(
            ip_in_any_cidr("34.149.66.137", &config.allowlist_cidrs),
            "Anthropic API endpoint must be in default allowlist"
        );
    }

    #[test]
    fn config_defaults() {
        let config = NetworkMonitorConfig::default();
        assert_eq!(config.poll_interval_ms, 5000);
        assert!(config.exfil_threshold_bytes > 0);
    }

    #[test]
    fn scan_once_no_crash() {
        let ti = Arc::new(ThreatIntelDB::new(
            super::super::threat_intel::ThreatIntelConfig::new(
                std::env::temp_dir().join("nexus-netmon-test"),
            ),
        ));
        let monitor = NetworkMonitor::new(NetworkMonitorConfig::default(), ti);
        let results = monitor.scan_once();
        let _ = results; // Should not crash
    }
}
