//! security-ticker — always-on-top desktop widget for real-time NexusShield
//! security operations on your laptop.
//!
//! Polls a locally running `nexus-shield` instance and shows:
//!   1. Backend health LED (is the shield running?)
//!   2. Endpoint protection status (files scanned, threats, quarantine size)
//!   3. Per-module LEDs for gateway + endpoint scanners
//!   4. Rolling stats (5-min + 1-hour): blocked, rate-limited, SQL, SSRF
//!   5. Scrolling log of recent detections and audit events
//!   6. Input bar for on-demand path scans via POST /endpoint/scan
//!
//! Environment:
//!   NEXUS_SHIELD_URL   — default http://127.0.0.1:8080
//!   NEXUS_SHIELD_TOKEN — optional Bearer token (matches `api_token` in config)
//!
//! Launch: security-ticker &

use eframe::egui;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// =============================================================================
// Config
// =============================================================================

const TICKER_WIDTH: f32 = 520.0;
const TICKER_HEIGHT: f32 = 440.0;
const MAX_LOG_LINES: usize = 200;
const HEALTH_POLL_SECS: u64 = 5;
const STATS_POLL_SECS: u64 = 10;
const DETECTIONS_POLL_SECS: u64 = 5;
const AUDIT_POLL_SECS: u64 = 8;

/// Gateway modules shown as LEDs (from /status `modules.gateway`).
const GATEWAY_MODULES: &[&str] = &[
    "sql_firewall",
    "ssrf_guard",
    "rate_governor",
    "fingerprint",
    "quarantine",
    "email_guard",
    "credential_vault",
    "audit_chain",
    "sanitizer",
    "threat_score",
    "siem_export",
    "journal",
    "sse_events",
];

/// Endpoint scanners shown as LEDs (from /status `modules.endpoint`).
const ENDPOINT_MODULES: &[&str] = &[
    "signatures",
    "heuristics",
    "yara_engine",
    "watcher",
    "process_monitor",
    "network_monitor",
    "memory_scanner",
    "rootkit_detector",
    "dns_filter",
    "usb_monitor",
    "fim",
    "container_scanner",
    "supply_chain",
    "allowlist",
    "threat_intel",
    "file_quarantine",
];

// =============================================================================
// Entry
// =============================================================================

fn main() -> eframe::Result {
    // Frameless + transparent — we paint our own rounded background and
    // custom titlebar. Matches the nexus-ticker / tech-ticker chrome so
    // all three widgets read as a single set.
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([TICKER_WIDTH, TICKER_HEIGHT])
            .with_min_inner_size([420.0, 300.0])
            .with_always_on_top()
            .with_decorations(false)
            .with_transparent(true)
            .with_resizable(true)
            .with_title("nexus-shield"),
        ..Default::default()
    };

    eframe::run_native(
        "security-ticker",
        options,
        Box::new(|cc| Ok(Box::new(TickerApp::new(cc)))),
    )
}

// =============================================================================
// State
// =============================================================================

#[derive(Clone, PartialEq)]
enum Status {
    Idle,
    Watching(String),
    Alert(String),
    Offline(String),
}

impl Status {
    fn label(&self) -> &str {
        match self {
            Self::Idle => "IDLE",
            Self::Watching(_) => "WATCHING",
            Self::Alert(_) => "ALERT",
            Self::Offline(_) => "OFFLINE",
        }
    }
    fn detail(&self) -> String {
        match self {
            Self::Idle => "all clear".to_string(),
            Self::Watching(s) | Self::Alert(s) | Self::Offline(s) => s.clone(),
        }
    }
}

#[derive(Clone)]
struct LogEntry {
    timestamp: String,
    message: String,
    severity: Sev,
}

#[derive(Clone, Copy, PartialEq)]
enum Sev {
    Info,
    Warn,
    Crit,
}

#[derive(Clone, Default)]
struct Stats {
    blocked_5m: u64,
    rate_limited_5m: u64,
    sql_5m: u64,
    ssrf_5m: u64,
    blocked_1h: u64,
    rate_limited_1h: u64,
    sql_1h: u64,
    ssrf_1h: u64,
    total_audit_events: u64,
}

#[derive(Clone, Default)]
struct EndpointStats {
    files_scanned: u64,
    threats_detected: u64,
    quarantined: u64,
    active_monitors: u64,
    scanners_active: u64,
    last_scan_time: Option<String>,
}

struct SharedState {
    status: Status,
    log: Vec<LogEntry>,
    backend_online: bool,
    base_url: String,
    have_token: bool,
    stats: Stats,
    endpoint: EndpointStats,
    /// Module name → last known "alive" state. `true` means the module
    /// was reported by /status on the most recent successful poll.
    modules_alive: HashMap<String, bool>,
    /// ID of the most recent detection we've logged, to avoid re-printing.
    last_detection_id: Option<String>,
    /// ID of the most recent audit event we've logged.
    last_audit_id: Option<String>,
    /// Rolling count of detections seen since start.
    detection_count: u64,
}

impl SharedState {
    fn push_log(&mut self, msg: &str, severity: Sev) {
        self.log.push(LogEntry {
            timestamp: now(),
            message: msg.to_string(),
            severity,
        });
        let excess = self.log.len().saturating_sub(MAX_LOG_LINES);
        if excess > 0 {
            self.log.drain(0..excess);
        }
    }
}

/// Identifies which stat chip the user clicked. Drives the drill-down
/// modal filter and the task string handed to the shield agent.
#[derive(Clone, Copy, PartialEq, Debug)]
enum StatKind {
    Blocked5m,
    Sql5m,
    Ssrf5m,
    Rate5m,
    Blocked1h,
    Sql1h,
    Ssrf1h,
    Rate1h,
    FilesScanned,
    Threats,
    Quarantine,
    AuditEvents,
}

impl StatKind {
    fn label(self) -> &'static str {
        match self {
            Self::Blocked5m => "blocked 5m",
            Self::Sql5m => "sql 5m",
            Self::Ssrf5m => "ssrf 5m",
            Self::Rate5m => "rate 5m",
            Self::Blocked1h => "blocked 1h",
            Self::Sql1h => "sql 1h",
            Self::Ssrf1h => "ssrf 1h",
            Self::Rate1h => "rate 1h",
            Self::FilesScanned => "files scanned",
            Self::Threats => "threats",
            Self::Quarantine => "quarantine",
            Self::AuditEvents => "audit events",
        }
    }

    /// Time window token matching the agent's WINDOW header.
    fn window(self) -> &'static str {
        match self {
            Self::Blocked5m | Self::Sql5m | Self::Ssrf5m | Self::Rate5m => "last_5_min",
            Self::Blocked1h | Self::Sql1h | Self::Ssrf1h | Self::Rate1h => "last_hour",
            _ => "all_time",
        }
    }
}

/// A single action the shield agent has proposed. Rendered as a row in
/// the drill-down modal with Accept / Reject buttons.
#[derive(Clone, Debug)]
struct ShieldAction {
    kind: String,           // "allowlist_cidr" | "allowlist_process" | "kill_process" | ...
    reason: String,
    params: serde_json::Value,
    state: ActionState,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum ActionState {
    Pending,
    Accepting,
    Accepted,
    Rejected,
    Failed,
}

/// State of a shield-agent investigation kicked off from a drill-down.
#[derive(Clone, Debug, Default)]
struct AgentRun {
    stat: Option<StatKind>,
    status: AgentStatus,
    /// Free-text investigation notes the agent wrote before the JSON block.
    notes: String,
    summary: String,
    classification: String,
    actions: Vec<ShieldAction>,
    /// Error text shown when status = Failed.
    error: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Debug, Default)]
enum AgentStatus {
    #[default]
    Idle,
    Running,
    Done,
    Failed,
}

struct TickerApp {
    state: Arc<Mutex<SharedState>>,
    input: String,
    runtime: tokio::runtime::Runtime,
    theme: Theme,
    /// When true, render a side panel listing recent detections in full.
    /// Toggled by clicking the `det:N` indicator in the header.
    show_detections: bool,
    /// When Some, render the stat drill-down modal for that stat kind.
    open_stat_drill: Option<StatKind>,
    /// Active / last shield-agent investigation. Shared so the spawned
    /// tokio task can update it while the UI is painting.
    agent_run: Arc<Mutex<AgentRun>>,
}

impl TickerApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let base_url = std::env::var("NEXUS_SHIELD_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let token = std::env::var("NEXUS_SHIELD_TOKEN").ok();
        let have_token = token.is_some();

        let state = Arc::new(Mutex::new(SharedState {
            status: Status::Watching("starting up...".to_string()),
            log: vec![LogEntry {
                timestamp: now(),
                message: format!("security-ticker started → {base_url}"),
                severity: Sev::Info,
            }],
            backend_online: false,
            base_url: base_url.clone(),
            have_token,
            stats: Stats::default(),
            endpoint: EndpointStats::default(),
            modules_alive: HashMap::new(),
            last_detection_id: None,
            last_audit_id: None,
            detection_count: 0,
        }));

        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("reqwest client");

        // --- Health + /status poll (every 5s) ---
        {
            let s = state.clone();
            let c = client.clone();
            let url = base_url.clone();
            let tok = token.clone();
            runtime.spawn(async move {
                loop {
                    poll_health_and_status(s.clone(), &c, &url, tok.as_deref()).await;
                    tokio::time::sleep(std::time::Duration::from_secs(HEALTH_POLL_SECS)).await;
                }
            });
        }

        // --- Stats poll (every 10s) ---
        {
            let s = state.clone();
            let c = client.clone();
            let url = base_url.clone();
            let tok = token.clone();
            runtime.spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                loop {
                    poll_stats(s.clone(), &c, &url, tok.as_deref()).await;
                    tokio::time::sleep(std::time::Duration::from_secs(STATS_POLL_SECS)).await;
                }
            });
        }

        // --- Endpoint detections poll (every 5s) ---
        {
            let s = state.clone();
            let c = client.clone();
            let url = base_url.clone();
            let tok = token.clone();
            runtime.spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                loop {
                    poll_endpoint(s.clone(), &c, &url, tok.as_deref()).await;
                    tokio::time::sleep(std::time::Duration::from_secs(DETECTIONS_POLL_SECS)).await;
                }
            });
        }

        // --- Audit events poll (every 8s) ---
        {
            let s = state.clone();
            let c = client.clone();
            let url = base_url.clone();
            let tok = token.clone();
            runtime.spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                loop {
                    poll_audit(s.clone(), &c, &url, tok.as_deref()).await;
                    tokio::time::sleep(std::time::Duration::from_secs(AUDIT_POLL_SECS)).await;
                }
            });
        }

        Self {
            state,
            input: String::new(),
            runtime,
            show_detections: false,
            theme: load_theme(),
            open_stat_drill: None,
            agent_run: Arc::new(Mutex::new(AgentRun::default())),
        }
    }

    fn push_log(&self, msg: &str, sev: Sev) {
        if let Ok(mut s) = self.state.lock() {
            s.push_log(msg, sev);
        }
    }

    fn submit_command(&mut self) {
        let cmd = self.input.trim().to_string();
        if cmd.is_empty() {
            return;
        }
        self.input.clear();

        // Input is treated as a filesystem path to scan.
        self.push_log(&format!("> scan {cmd}"), Sev::Info);

        let state = self.state.clone();
        let (base_url, token_opt) = match state.lock() {
            Ok(s) => (
                s.base_url.clone(),
                std::env::var("NEXUS_SHIELD_TOKEN").ok(),
            ),
            Err(_) => return,
        };

        self.runtime.spawn(async move {
            let client = reqwest::Client::new();
            let mut req = client
                .post(format!("{base_url}/endpoint/scan"))
                .body(cmd.clone());
            if let Some(t) = &token_opt {
                req = req.bearer_auth(t);
            }

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body);
                    if let Ok(mut s) = state.lock() {
                        if !status.is_success() {
                            s.push_log(&format!("  scan HTTP {status}: {body}"), Sev::Crit);
                            return;
                        }
                        if let Ok(v) = parsed {
                            let clean = v.get("clean").and_then(|x| x.as_bool()).unwrap_or(false);
                            let found = v
                                .get("threats_found")
                                .and_then(|x| x.as_u64())
                                .unwrap_or(0);
                            if clean {
                                s.push_log(&format!("  {cmd}: clean"), Sev::Info);
                            } else {
                                s.push_log(
                                    &format!("  {cmd}: {found} threat(s) found"),
                                    Sev::Crit,
                                );
                                if let Some(dets) = v.get("detections").and_then(|d| d.as_array())
                                {
                                    for d in dets.iter().take(5) {
                                        let scanner = d
                                            .get("scanner")
                                            .and_then(|x| x.as_str())
                                            .unwrap_or("?");
                                        let sev = d
                                            .get("severity")
                                            .and_then(|x| x.as_str())
                                            .unwrap_or("?");
                                        let desc = d
                                            .get("description")
                                            .and_then(|x| x.as_str())
                                            .unwrap_or("");
                                        s.push_log(
                                            &format!("    [{scanner}] {sev}: {desc}"),
                                            Sev::Warn,
                                        );
                                    }
                                }
                            }
                        } else {
                            s.push_log(&format!("  scan response: {body}"), Sev::Info);
                        }
                    }
                }
                Err(e) => {
                    if let Ok(mut s) = state.lock() {
                        s.push_log(&format!("  scan failed: {e}"), Sev::Crit);
                    }
                }
            }
        });
    }

    /// Spawn the shield agent as a nexus-agent subprocess to investigate
    /// the events currently filtered for the given stat. Output is
    /// parsed into AgentRun and rendered in the drill-down modal.
    fn spawn_shield_agent(
        &self,
        kind: StatKind,
        events: &[(String, String, Sev)],
    ) {
        // Mark running immediately so the UI flips state.
        if let Ok(mut r) = self.agent_run.lock() {
            *r = AgentRun {
                stat: Some(kind),
                status: AgentStatus::Running,
                notes: String::new(),
                summary: String::new(),
                classification: String::new(),
                actions: Vec::new(),
                error: None,
            };
        }

        // Build the task payload. The shield agent's system prompt
        // specifies the "STAT: ... WINDOW: ... EVENTS: ..." format.
        let mut task = format!("STAT: {}\nWINDOW: {}\nEVENTS:\n", kind.label(), kind.window());
        for (ts, msg, sev) in events.iter().take(30) {
            let tag = match sev {
                Sev::Crit => "CRIT",
                Sev::Warn => "WARN",
                Sev::Info => "INFO",
            };
            task.push_str(&format!("{{\"ts\":\"{ts}\",\"severity\":\"{tag}\",\"message\":{}}}\n",
                serde_json::Value::String(msg.clone())));
        }
        if events.is_empty() {
            task.push_str("(no events matched in current buffer — investigate stat meaning + propose baseline if useful)\n");
        }

        let agent_run = self.agent_run.clone();
        self.push_log(
            &format!("> shield-agent: investigating '{}'", kind.label()),
            Sev::Info,
        );

        self.runtime.spawn(async move {
            // Match nexus-ticker's convention — absolute release-build path.
            // nexus-agent isn't on PATH in the ticker's launch environment.
            const NEXUS_AGENT_BIN: &str =
                "/opt/AxonML/nexus-agent/target/release/nexus-agent";
            let output = tokio::process::Command::new(NEXUS_AGENT_BIN)
                .arg("shield")
                .arg(&task)
                .output()
                .await;

            let parsed: (AgentStatus, String, String, Vec<ShieldAction>, Option<String>, String) =
                match output {
                    Ok(out) if out.status.success() => {
                        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                        match parse_agent_output(&stdout) {
                            Ok((summary, classification, actions, notes)) => {
                                (AgentStatus::Done, summary, classification, actions, None, notes)
                            }
                            Err(e) => (
                                AgentStatus::Failed,
                                String::new(),
                                String::new(),
                                Vec::new(),
                                Some(format!("could not parse agent output: {e}")),
                                stdout,
                            ),
                        }
                    }
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        (
                            AgentStatus::Failed,
                            String::new(),
                            String::new(),
                            Vec::new(),
                            Some(format!("nexus-agent exit {}: {}", out.status, stderr)),
                            String::new(),
                        )
                    }
                    Err(e) => (
                        AgentStatus::Failed,
                        String::new(),
                        String::new(),
                        Vec::new(),
                        Some(format!("could not launch nexus-agent: {e}")),
                        String::new(),
                    ),
                };

            if let Ok(mut r) = agent_run.lock() {
                r.status = parsed.0;
                r.summary = parsed.1;
                r.classification = parsed.2;
                r.actions = parsed.3;
                r.error = parsed.4;
                r.notes = parsed.5;
            }
        });
    }

    /// User clicked Accept on a proposed action. Dispatches to the
    /// appropriate shield endpoint (allowlist_cidr, allowlist_process)
    /// or surfaces a "manual" note for action kinds the backend doesn't
    /// yet implement.
    fn accept_action(&self, idx: usize) {
        let (kind, params, reason, base_url, token_opt) = {
            let r = match self.agent_run.lock() {
                Ok(v) => v,
                Err(_) => return,
            };
            let Some(a) = r.actions.get(idx) else { return };
            let (url, tok) = match self.state.lock() {
                Ok(s) => (s.base_url.clone(), std::env::var("NEXUS_SHIELD_TOKEN").ok()),
                Err(_) => return,
            };
            (a.kind.clone(), a.params.clone(), a.reason.clone(), url, tok)
        };

        // Mark accepting
        if let Ok(mut r) = self.agent_run.lock() {
            if let Some(a) = r.actions.get_mut(idx) {
                a.state = ActionState::Accepting;
            }
        }

        let agent_run = self.agent_run.clone();
        self.push_log(
            &format!("> accept action [{kind}]: {reason}"),
            Sev::Info,
        );

        self.runtime.spawn(async move {
            let client = reqwest::Client::new();
            let result: Result<(u16, String), String> = match kind.as_str() {
                "allowlist_cidr" => {
                    let cidr = params
                        .get("cidr")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let body =
                        serde_json::json!({"cidr": cidr, "reason": reason}).to_string();
                    let mut req = client
                        .post(format!("{base_url}/endpoint/allowlist/cidr"))
                        .header("content-type", "application/json")
                        .body(body);
                    if let Some(t) = &token_opt {
                        req = req.bearer_auth(t);
                    }
                    match req.send().await {
                        Ok(resp) => {
                            let s = resp.status().as_u16();
                            let t = resp.text().await.unwrap_or_default();
                            Ok((s, t))
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
                "allowlist_process" => {
                    let comm = params
                        .get("comm")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let body =
                        serde_json::json!({"comm": comm, "reason": reason}).to_string();
                    let mut req = client
                        .post(format!("{base_url}/endpoint/allowlist/process"))
                        .header("content-type", "application/json")
                        .body(body);
                    if let Some(t) = &token_opt {
                        req = req.bearer_auth(t);
                    }
                    match req.send().await {
                        Ok(resp) => {
                            let s = resp.status().as_u16();
                            let t = resp.text().await.unwrap_or_default();
                            Ok((s, t))
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
                "no_action" => Ok((200, String::from("{\"ok\":true,\"kind\":\"no_action\"}"))),
                _ => Err(format!(
                    "action kind '{kind}' not yet implemented on the shield backend — apply manually"
                )),
            };

            if let Ok(mut r) = agent_run.lock() {
                if let Some(a) = r.actions.get_mut(idx) {
                    match result {
                        Ok((code, _body)) if (200..300).contains(&code) => {
                            a.state = ActionState::Accepted;
                        }
                        Ok((code, body)) => {
                            a.state = ActionState::Failed;
                            a.reason = format!("{} [HTTP {code}: {body}]", a.reason);
                        }
                        Err(e) => {
                            a.state = ActionState::Failed;
                            a.reason = format!("{} [err: {e}]", a.reason);
                        }
                    }
                }
            }
        });
    }

    fn reject_action(&self, idx: usize) {
        if let Ok(mut r) = self.agent_run.lock() {
            if let Some(a) = r.actions.get_mut(idx) {
                a.state = ActionState::Rejected;
            }
        }
    }
}

/// Parse the shield agent's final message. The prompt requires a
/// fenced ```json { ... } ``` block at the end. Returns
/// (summary, classification, actions, notes_before_json).
fn parse_agent_output(
    stdout: &str,
) -> Result<(String, String, Vec<ShieldAction>, String), String> {
    // Find the last ```json fence.
    let lower = stdout.to_ascii_lowercase();
    let open = lower
        .rfind("```json")
        .ok_or_else(|| "no ```json fence in agent output".to_string())?;
    let after = &stdout[open + 7..];
    let close = after
        .find("```")
        .ok_or_else(|| "unterminated ```json fence".to_string())?;
    let json_str = after[..close].trim();
    let notes = stdout[..open].trim().to_string();

    let v: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("bad json: {e}"))?;

    let summary = v
        .get("summary")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let classification = v
        .get("classification")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    let mut actions: Vec<ShieldAction> = Vec::new();
    if let Some(arr) = v.get("proposed_actions").and_then(|x| x.as_array()) {
        for a in arr {
            let kind = a
                .get("kind")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if kind.is_empty() {
                continue;
            }
            actions.push(ShieldAction {
                kind,
                reason: a
                    .get("reason")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                params: a.get("params").cloned().unwrap_or(serde_json::json!({})),
                state: ActionState::Pending,
            });
        }
    }

    Ok((summary, classification, actions, notes))
}

// =============================================================================
// Background pollers
// =============================================================================

fn bearer(req: reqwest::RequestBuilder, token: Option<&str>) -> reqwest::RequestBuilder {
    if let Some(t) = token {
        req.bearer_auth(t)
    } else {
        req
    }
}

async fn poll_health_and_status(
    state: Arc<Mutex<SharedState>>,
    client: &reqwest::Client,
    base: &str,
    token: Option<&str>,
) {
    // /health is public — no token.
    let health = client
        .get(format!("{base}/health"))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    if !health {
        if let Ok(mut s) = state.lock() {
            let was_online = s.backend_online;
            s.backend_online = false;
            if was_online {
                s.push_log("shield backend offline", Sev::Crit);
            }
            s.status = Status::Offline("shield unreachable".to_string());
        }
        return;
    }

    // /status requires auth if a token is configured server-side.
    let resp = bearer(client.get(format!("{base}/status")), token)
        .send()
        .await;

    if let Ok(mut s) = state.lock() {
        let became_online = !s.backend_online;
        s.backend_online = true;
        if became_online {
            s.push_log("shield backend online", Sev::Info);
        }
    }

    if let Ok(r) = resp {
        if r.status().is_success() {
            if let Ok(v) = r.json::<serde_json::Value>().await {
                if let Ok(mut s) = state.lock() {
                    if let Some(mods) = v.get("modules") {
                        let mut alive: HashMap<String, bool> = HashMap::new();
                        for field in ["gateway", "endpoint"] {
                            if let Some(arr) = mods.get(field).and_then(|x| x.as_array()) {
                                for m in arr {
                                    if let Some(name) = m.as_str() {
                                        alive.insert(name.to_string(), true);
                                    }
                                }
                            }
                        }
                        s.modules_alive = alive;
                    }
                    let chain_valid = v
                        .get("audit_chain")
                        .and_then(|a| a.get("chain_valid"))
                        .and_then(|x| x.as_bool())
                        .unwrap_or(true);
                    if !chain_valid {
                        s.push_log("audit chain integrity FAIL", Sev::Crit);
                        s.status = Status::Alert("audit chain broken".to_string());
                    }
                }
            }
        } else if r.status() == reqwest::StatusCode::UNAUTHORIZED {
            if let Ok(mut s) = state.lock() {
                s.status = Status::Alert("auth: set NEXUS_SHIELD_TOKEN".to_string());
            }
        }
    }
}

async fn poll_stats(
    state: Arc<Mutex<SharedState>>,
    client: &reqwest::Client,
    base: &str,
    token: Option<&str>,
) {
    let resp = bearer(client.get(format!("{base}/stats")), token).send().await;
    let Ok(r) = resp else { return };
    if !r.status().is_success() {
        return;
    }
    let Ok(v) = r.json::<serde_json::Value>().await else {
        return;
    };

    let (stats, crit) = {
        let mut stats = Stats::default();
        let g = |v: &serde_json::Value, a: &str, b: &str| -> u64 {
            v.get(a)
                .and_then(|x| x.get(b))
                .and_then(|x| x.as_u64())
                .unwrap_or(0)
        };
        stats.blocked_5m = g(&v, "last_5min", "blocked");
        stats.rate_limited_5m = g(&v, "last_5min", "rate_limited");
        stats.sql_5m = g(&v, "last_5min", "sql_injection");
        stats.ssrf_5m = g(&v, "last_5min", "ssrf");
        stats.blocked_1h = g(&v, "last_hour", "blocked");
        stats.rate_limited_1h = g(&v, "last_hour", "rate_limited");
        stats.sql_1h = g(&v, "last_hour", "sql_injection");
        stats.ssrf_1h = g(&v, "last_hour", "ssrf");
        stats.total_audit_events = v
            .get("total_audit_events")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let critical = stats.sql_5m + stats.ssrf_5m;
        (stats, critical)
    };

    if let Ok(mut s) = state.lock() {
        s.stats = stats;
        if crit > 0 {
            s.status = Status::Alert(format!("{crit} critical hit(s) in 5m"));
        } else if s.stats.blocked_5m > 0 {
            s.status = Status::Watching(format!("{} block(s) in 5m", s.stats.blocked_5m));
        } else if matches!(s.status, Status::Alert(_) | Status::Watching(_))
            && s.backend_online
        {
            s.status = Status::Idle;
        }
    }
}

async fn poll_endpoint(
    state: Arc<Mutex<SharedState>>,
    client: &reqwest::Client,
    base: &str,
    token: Option<&str>,
) {
    // /endpoint/status — may return 404 if endpoint mode isn't enabled.
    let st_resp = bearer(client.get(format!("{base}/endpoint/status")), token)
        .send()
        .await;
    if let Ok(r) = st_resp {
        if r.status().is_success() {
            if let Ok(v) = r.json::<serde_json::Value>().await {
                if let Ok(mut s) = state.lock() {
                    let g = |key: &str| v.get(key).and_then(|x| x.as_u64()).unwrap_or(0);
                    s.endpoint.files_scanned = g("total_files_scanned");
                    s.endpoint.threats_detected = g("total_threats_detected");
                    s.endpoint.quarantined = g("quarantined_files");
                    s.endpoint.active_monitors = g("active_monitors");
                    s.endpoint.scanners_active = g("scanners_active");
                    s.endpoint.last_scan_time = v
                        .get("last_scan_time")
                        .and_then(|x| x.as_str())
                        .map(|x| x.to_string());
                }
            }
        }
    }

    // /endpoint/detections — surface new ones in the log.
    let det_resp = bearer(client.get(format!("{base}/endpoint/detections")), token)
        .send()
        .await;
    let Ok(r) = det_resp else { return };
    if !r.status().is_success() {
        return;
    }
    let Ok(v) = r.json::<serde_json::Value>().await else {
        return;
    };
    let Some(arr) = v.get("detections").and_then(|x| x.as_array()) else {
        return;
    };

    // Detections come newest-first. Walk backwards and log any that are
    // newer than last_detection_id.
    let last_seen = state
        .lock()
        .ok()
        .and_then(|s| s.last_detection_id.clone());
    let mut to_log: Vec<(String, String, String, String, String)> = Vec::new();
    for d in arr.iter() {
        let id = d.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if let Some(ref seen) = last_seen {
            if id == *seen {
                break;
            }
        }
        let scanner = d
            .get("scanner")
            .and_then(|x| x.as_str())
            .unwrap_or("?")
            .to_string();
        let sev = d
            .get("severity")
            .and_then(|x| x.as_str())
            .unwrap_or("?")
            .to_string();
        let desc = d
            .get("description")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let target = d
            .get("target")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        to_log.push((id, scanner, sev, desc, target));
        if last_seen.is_none() {
            // First poll ever — only show the top N newest so we don't flood.
            if to_log.len() >= 5 {
                break;
            }
        }
    }

    if to_log.is_empty() {
        return;
    }

    if let Ok(mut s) = state.lock() {
        // Log oldest-first so the order reads naturally.
        for (id, scanner, sev, desc, target) in to_log.iter().rev() {
            let severity = match sev.as_str() {
                "Critical" | "critical" => Sev::Crit,
                "High" | "high" | "Medium" | "medium" => Sev::Warn,
                _ => Sev::Info,
            };
            let short = if target.len() > 60 {
                format!("…{}", &target[target.len() - 58..])
            } else {
                target.clone()
            };
            s.push_log(
                &format!("[{scanner}] {sev}: {desc}  {short}"),
                severity,
            );
            s.detection_count += 1;
            s.last_detection_id = Some(id.clone());
        }
        let critical = to_log
            .iter()
            .any(|(_, _, sev, _, _)| sev.eq_ignore_ascii_case("critical"));
        if critical {
            s.status = Status::Alert("endpoint detection: CRITICAL".to_string());
        }
    }
}

async fn poll_audit(
    state: Arc<Mutex<SharedState>>,
    client: &reqwest::Client,
    base: &str,
    token: Option<&str>,
) {
    let resp = bearer(client.get(format!("{base}/audit")), token).send().await;
    let Ok(r) = resp else { return };
    if !r.status().is_success() {
        return;
    }
    let Ok(v) = r.json::<serde_json::Value>().await else {
        return;
    };
    let Some(arr) = v.get("recent_events").and_then(|x| x.as_array()) else {
        return;
    };

    let last_seen = state.lock().ok().and_then(|s| s.last_audit_id.clone());
    let mut to_log: Vec<(String, String, String, f64)> = Vec::new();
    for e in arr.iter() {
        let id = e.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if let Some(ref seen) = last_seen {
            if id == *seen {
                break;
            }
        }
        let event_type = e
            .get("event_type")
            .and_then(|x| x.as_str())
            .unwrap_or("?")
            .to_string();
        // Filter noise + dedupe against /endpoint/detections.
        // Events already surfaced via the endpoint detections stream are skipped
        // here to avoid each incident showing up twice in the log.
        match event_type.as_str() {
            // Pure noise — never log.
            "RequestAllowed" | "HealthCheck" | "ChainVerified" => continue,
            // These are also surfaced via /endpoint/detections with richer
            // scanner+description context, so skip them in the audit view.
            "SuspiciousProcess" | "SuspiciousNetwork" | "MalwareDetected"
            | "MemoryAnomaly" | "RootkitIndicator" | "FileQuarantined"
            | "FileRestored" | "SignatureDbUpdated" | "EndpointScanStarted"
            | "EndpointScanCompleted" => continue,
            _ => {}
        }
        let source = e
            .get("source_ip")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let score = e
            .get("threat_score")
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0);
        to_log.push((id, event_type, source, score));
        if last_seen.is_none() && to_log.len() >= 3 {
            break;
        }
    }

    if to_log.is_empty() {
        return;
    }

    if let Ok(mut s) = state.lock() {
        for (id, ev, src, score) in to_log.iter().rev() {
            let sev = if *score >= 0.7 {
                Sev::Crit
            } else if *score >= 0.4 {
                Sev::Warn
            } else {
                Sev::Info
            };
            let src_label = if src.is_empty() {
                String::new()
            } else {
                format!(" from {src}")
            };
            s.push_log(
                &format!("{ev}{src_label} (score {:.2})", score),
                sev,
            );
            s.last_audit_id = Some(id.clone());
        }
    }
}

// =============================================================================
// UI
// =============================================================================

impl eframe::App for TickerApp {
    /// Clear to full transparency so only the rounded pill is visible —
    /// matches the nexus-ticker / tech-ticker treatment.
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        [0.0, 0.0, 0.0, 0.0]
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Repaint for LED pulse animation.
        ctx.request_repaint_after(std::time::Duration::from_millis(60));

        // Active palette (derived from user's theme choice).
        let p = Palette::for_theme(self.theme);
        let mut visuals = if p.is_dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        visuals.panel_fill = egui::Color32::TRANSPARENT;
        visuals.window_fill = egui::Color32::TRANSPARENT;
        visuals.override_text_color = Some(p.cream);
        ctx.set_visuals(visuals);

        let snap = self.state.lock().unwrap().clone_snapshot();
        let is_active = snap.status_label != "IDLE";

        // Outer rounded pill — same dimensions as the other tickers for
        // visual consistency.
        let outer_frame = egui::Frame::none()
            .fill(p.bg_dark)
            .rounding(egui::Rounding::same(10.0))
            .stroke(egui::Stroke::new(
                1.0,
                if p.is_dark {
                    egui::Color32::from_rgba_unmultiplied(255, 255, 255, 18)
                } else {
                    egui::Color32::from_rgba_unmultiplied(
                        p.text_dim.r(), p.text_dim.g(), p.text_dim.b(), 90,
                    )
                },
            ))
            .shadow(egui::epaint::Shadow {
                offset: egui::vec2(0.0, 2.0),
                blur: 8.0,
                spread: 0.0,
                color: egui::Color32::from_rgba_unmultiplied(0, 0, 0, if p.is_dark { 120 } else { 32 }),
            })
            .inner_margin(egui::Margin::symmetric(10.0, 8.0));

        egui::CentralPanel::default()
            .frame(egui::Frame::none().inner_margin(egui::Margin::same(6.0)))
            .show(ctx, |ui| { outer_frame.show(ui, |ui| {
            // ── Custom titlebar: drag region + close/min buttons ──────────
            let title_resp = ui.horizontal(|ui| {
                let main_color = status_led_color(&p, &snap.status_label);
                draw_led(ui, main_color, 5.0, is_active);
                ui.label(
                    egui::RichText::new("NEXUS-SHIELD")
                        .strong()
                        .size(11.0)
                        .color(p.cream),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(egui::Button::new(
                        egui::RichText::new("✕").size(12.0).color(p.text_dim),
                    ).frame(false).min_size(egui::vec2(20.0, 20.0)))
                        .on_hover_text("close").clicked()
                    {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        std::process::exit(0);
                    }
                    if ui.add(egui::Button::new(
                        egui::RichText::new("—").size(12.0).color(p.text_dim),
                    ).frame(false).min_size(egui::vec2(20.0, 20.0)))
                        .on_hover_text("minimize").clicked()
                    {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                        let _ = std::process::Command::new("sh")
                            .arg("-c")
                            .arg("xdotool search --name '^nexus-shield$' windowminimize 2>/dev/null")
                            .spawn();
                    }
                });
            }).response;
            let drag_sense = ui.interact(
                title_resp.rect,
                egui::Id::new("shield-drag"),
                egui::Sense::click_and_drag(),
            );
            if drag_sense.drag_started_by(egui::PointerButton::Primary) {
                ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }
            ui.separator();

            // ---- Status line (was the old header) ----
            ui.horizontal(|ui| {
                let main_color = status_led_color(&p, &snap.status_label);
                draw_led(ui, main_color, 6.0, is_active);
                ui.label(
                    egui::RichText::new(&snap.status_label)
                        .strong()
                        .size(11.0)
                        .color(p.cream),
                );
                ui.label(
                    egui::RichText::new(&snap.status_detail)
                        .size(9.0)
                        .color(p.text_dim),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Theme toggle — matches nexus-agent ticker: ☀ in dark mode
                    // (click to go light), ☾ in light mode (click to go dark).
                    // Amber so the sun reads as "yellow" against the dark pill.
                    let is_dark = self.theme == Theme::Dark;
                    let glyph = if is_dark { "☀" } else { "☾" };
                    let tip = if is_dark {
                        "Switch to light theme"
                    } else {
                        "Switch to dark theme"
                    };
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new(glyph)
                                    .size(11.0)
                                    .color(p.amber)
                                    .strong(),
                            )
                            .frame(false)
                            .min_size(egui::vec2(16.0, 16.0)),
                        )
                        .on_hover_text(tip)
                        .clicked()
                    {
                        self.theme = self.theme.toggled();
                        save_theme(self.theme);
                    }
                    ui.add_space(4.0);

                    // Shield backend LED
                    let back_c = if snap.backend_online { p.teal } else { p.terracotta };
                    let back_tip = if snap.backend_online {
                        format!("shield backend ONLINE — {}", snap.base_url)
                    } else {
                        format!("shield backend OFFLINE — cannot reach {}", snap.base_url)
                    };
                    draw_led(ui, back_c, 4.0, !snap.backend_online).on_hover_text(&back_tip);
                    ui.label(
                        egui::RichText::new("shield")
                            .size(8.0)
                            .color(p.text_dim),
                    ).on_hover_text(&back_tip);

                    // Auth indicator
                    let auth_c = if snap.have_token { p.teal } else { p.amber };
                    let auth_tip = if snap.have_token {
                        "Bearer token configured — shield API calls are authenticated"
                    } else {
                        "AMBER: no NEXUS_SHIELD_TOKEN set — shield API is publicly readable. \
                         Mint a token, write to vault key secret/nexus-shield, restart launcher."
                    };
                    draw_led(ui, auth_c, 3.5, false).on_hover_text(auth_tip);
                    ui.label(
                        egui::RichText::new(if snap.have_token { "auth" } else { "no-auth" })
                            .size(8.0)
                            .color(p.text_dim),
                    ).on_hover_text(auth_tip);

                    // Detections counter — clickable to open the detail window.
                    let det_c = if snap.detection_count == 0 { p.teal } else { p.amber };
                    let det_tip = if snap.detection_count == 0 {
                        "no detections since launch — click anyway to open detail panel".to_string()
                    } else {
                        format!(
                            "{} detection(s) since launch — click to view full descriptions",
                            snap.detection_count
                        )
                    };
                    if draw_led(ui, det_c, 4.0, snap.detection_count > 0)
                        .on_hover_text(&det_tip)
                        .clicked()
                    {
                        self.show_detections = !self.show_detections;
                    }
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new(format!("det:{}", snap.detection_count))
                                    .size(8.0)
                                    .color(p.text_dim),
                            )
                            .frame(false),
                        )
                        .on_hover_text(&det_tip)
                        .clicked()
                    {
                        self.show_detections = !self.show_detections;
                    }
                });
            });

            ui.add_space(2.0);

            // ---- Gateway module LEDs ----
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new("gw ")
                        .size(8.0)
                        .color(p.text_dim)
                        .monospace(),
                ).on_hover_text("Gateway-side modules — request inspection + outbound policy");
                for m in GATEWAY_MODULES {
                    let alive = snap.modules_alive.get(*m).copied().unwrap_or(false)
                        && snap.backend_online;
                    let color = if alive { p.teal } else { p.slate };
                    let state_word = if alive { "ALIVE" } else { "not loaded" };
                    let tip = format!("{m} [{state_word}]\n{}", module_long(m));
                    draw_led(ui, color, 2.8, false).on_hover_text(&tip);
                    ui.label(
                        egui::RichText::new(module_short(m))
                            .size(7.5)
                            .color(p.text_dim),
                    ).on_hover_text(&tip);
                    ui.add_space(2.0);
                }
            });

            // ---- Endpoint module LEDs ----
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new("ep ")
                        .size(8.0)
                        .color(p.text_dim)
                        .monospace(),
                ).on_hover_text("Endpoint-side modules — local OS/process/file scanners");
                for m in ENDPOINT_MODULES {
                    let alive = snap.modules_alive.get(*m).copied().unwrap_or(false)
                        && snap.backend_online;
                    let color = if alive { p.teal } else { p.slate };
                    let state_word = if alive { "ALIVE" } else { "not loaded" };
                    let tip = format!("{m} [{state_word}]\n{}", module_long(m));
                    draw_led(ui, color, 2.8, false).on_hover_text(&tip);
                    ui.label(
                        egui::RichText::new(module_short(m))
                            .size(7.5)
                            .color(p.text_dim),
                    ).on_hover_text(&tip);
                    ui.add_space(2.0);
                }
            });

            ui.add_space(2.0);
            ui.separator();

            // ---- Stats row (5m / 1h) — every chip is clickable and
            //     opens a drill-down modal with agent option.
            let mut clicked_stat: Option<StatKind> = None;
            ui.horizontal(|ui| {
                if stat_chip(ui, &p, "blocked 5m", snap.stats.blocked_5m, p.terracotta).clicked() {
                    clicked_stat = Some(StatKind::Blocked5m);
                }
                if stat_chip(ui, &p, "sql 5m", snap.stats.sql_5m, p.terracotta).clicked() {
                    clicked_stat = Some(StatKind::Sql5m);
                }
                if stat_chip(ui, &p, "ssrf 5m", snap.stats.ssrf_5m, p.terracotta).clicked() {
                    clicked_stat = Some(StatKind::Ssrf5m);
                }
                if stat_chip(ui, &p, "rate 5m", snap.stats.rate_limited_5m, p.amber).clicked() {
                    clicked_stat = Some(StatKind::Rate5m);
                }
            });
            ui.horizontal(|ui| {
                if stat_chip(ui, &p, "blocked 1h", snap.stats.blocked_1h, p.cream).clicked() {
                    clicked_stat = Some(StatKind::Blocked1h);
                }
                if stat_chip(ui, &p, "sql 1h", snap.stats.sql_1h, p.cream).clicked() {
                    clicked_stat = Some(StatKind::Sql1h);
                }
                if stat_chip(ui, &p, "ssrf 1h", snap.stats.ssrf_1h, p.cream).clicked() {
                    clicked_stat = Some(StatKind::Ssrf1h);
                }
                if stat_chip(ui, &p, "rate 1h", snap.stats.rate_limited_1h, p.cream).clicked() {
                    clicked_stat = Some(StatKind::Rate1h);
                }
            });
            ui.horizontal(|ui| {
                if stat_chip(ui, &p, "files scanned", snap.endpoint.files_scanned, p.cream).clicked() {
                    clicked_stat = Some(StatKind::FilesScanned);
                }
                if stat_chip(ui, &p, "threats", snap.endpoint.threats_detected, p.amber).clicked() {
                    clicked_stat = Some(StatKind::Threats);
                }
                if stat_chip(ui, &p, "quarantine", snap.endpoint.quarantined, p.amber).clicked() {
                    clicked_stat = Some(StatKind::Quarantine);
                }
                if stat_chip(ui, &p, "audit events", snap.stats.total_audit_events, p.cream).clicked() {
                    clicked_stat = Some(StatKind::AuditEvents);
                }
            });
            if let Some(k) = clicked_stat {
                self.open_stat_drill = Some(k);
                // Reset any prior agent run — fresh drill-down, fresh context.
                if let Ok(mut r) = self.agent_run.lock() {
                    *r = AgentRun::default();
                    r.stat = Some(k);
                }
            }

            ui.separator();

            // ---- Log controls ----
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("log ({} lines)", snap.log_entries.len()))
                        .size(8.0)
                        .color(p.text_dim),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button(egui::RichText::new("copy all").size(9.0).color(p.teal))
                        .on_hover_text("Copy entire log to clipboard")
                        .clicked()
                    {
                        let buf: String = snap
                            .log_entries
                            .iter()
                            .map(|(ts, msg, _)| format!("{ts}  {msg}"))
                            .collect::<Vec<_>>()
                            .join("\n");
                        ui.ctx().copy_text(buf);
                    }
                    if ui
                        .button(egui::RichText::new("clear").size(9.0).color(p.amber))
                        .on_hover_text("Clear the log buffer")
                        .clicked()
                    {
                        if let Ok(mut s) = self.state.lock() {
                            s.log.clear();
                        }
                    }
                });
            });

            // ---- Scrolling log (text is selectable; Ctrl+A/Ctrl+C work) ----
            let available = ui.available_height() - 34.0;
            egui::ScrollArea::vertical()
                .max_height(available)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for (ts, msg, sev) in &snap.log_entries {
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(ts).size(8.0).color(p.slate),
                                )
                                .selectable(true),
                            );
                            let color = match sev {
                                Sev::Info => p.cream,
                                Sev::Warn => p.amber,
                                Sev::Crit => p.terracotta,
                            };
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(msg).size(9.0).color(color),
                                )
                                .selectable(true)
                                .wrap(),
                            );
                        });
                    }
                });

            // ---- Input bar ----
            ui.separator();
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("scan")
                        .size(9.0)
                        .color(p.teal)
                        .strong(),
                );
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.input)
                        .desired_width(ui.available_width() - 10.0)
                        .hint_text("path to scan (file or directory)...")
                        .font(egui::TextStyle::Small),
                );
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.submit_command();
                    r.request_focus();
                }
            });
            }); // closes outer_frame.show
        });

        // ---- Detection detail floating window (toggled by det:N click) ----
        if self.show_detections {
            let mut still_open = true;
            egui::Window::new("Detections — full detail")
                .open(&mut still_open)
                .default_size([520.0, 360.0])
                .resizable(true)
                .collapsible(false)
                .frame(
                    egui::Frame::none()
                        .fill(p.bg_dark)
                        .rounding(egui::Rounding::same(8.0))
                        .stroke(egui::Stroke::new(1.0, p.teal))
                        .inner_margin(egui::Margin::same(10.0)),
                )
                .show(ctx, |ui| {
                    ui.label(
                        egui::RichText::new(format!(
                            "{} detection(s) seen since launch — newest first",
                            snap.detection_count
                        ))
                        .size(10.0)
                        .color(p.cream),
                    );
                    ui.label(
                        egui::RichText::new(
                            "Each line is one event from /endpoint/detections or /audit. \
                             Severity colors: red=Crit, amber=Warn, neutral=Info.",
                        )
                        .size(8.0)
                        .color(p.text_dim),
                    );
                    ui.separator();

                    let detections: Vec<_> = snap
                        .log_entries
                        .iter()
                        .rev()
                        .filter(|(_, _, sev)| *sev != Sev::Info)
                        .take(80)
                        .collect();
                    if detections.is_empty() {
                        ui.label(
                            egui::RichText::new("(no Warn/Crit entries in current log buffer)")
                                .size(9.0)
                                .color(p.text_dim),
                        );
                    } else {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for (ts, msg, sev) in detections {
                                let color = match sev {
                                    Sev::Crit => p.terracotta,
                                    Sev::Warn => p.amber,
                                    Sev::Info => p.cream,
                                };
                                let sev_tag = match sev {
                                    Sev::Crit => "CRIT",
                                    Sev::Warn => "WARN",
                                    Sev::Info => "INFO",
                                };
                                ui.horizontal_wrapped(|ui| {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(ts).size(8.0).color(p.slate),
                                        )
                                        .selectable(true),
                                    );
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(sev_tag)
                                                .size(8.0)
                                                .color(color)
                                                .strong(),
                                        )
                                        .selectable(true),
                                    );
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(msg).size(9.0).color(color),
                                        )
                                        .selectable(true)
                                        .wrap(),
                                    );
                                });
                                ui.add_space(2.0);
                            }
                        });
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui
                            .button(egui::RichText::new("copy").size(9.0).color(p.teal))
                            .clicked()
                        {
                            let buf: String = snap
                                .log_entries
                                .iter()
                                .rev()
                                .filter(|(_, _, sev)| *sev != Sev::Info)
                                .map(|(ts, msg, sev)| {
                                    let tag = match sev {
                                        Sev::Crit => "CRIT",
                                        Sev::Warn => "WARN",
                                        Sev::Info => "INFO",
                                    };
                                    format!("{ts}  {tag}  {msg}")
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            ui.ctx().copy_text(buf);
                        }
                    });
                });
            if !still_open {
                self.show_detections = false;
            }
        }

        // ---- Stat drill-down + shield agent window ----
        if let Some(kind) = self.open_stat_drill {
            let mut still_open = true;
            let agent_snapshot = self
                .agent_run
                .lock()
                .map(|r| r.clone())
                .unwrap_or_default();

            egui::Window::new(format!("{} — investigate", kind.label()))
                .open(&mut still_open)
                .default_size([560.0, 440.0])
                .resizable(true)
                .collapsible(false)
                .frame(
                    egui::Frame::none()
                        .fill(p.bg_dark)
                        .rounding(egui::Rounding::same(8.0))
                        .stroke(egui::Stroke::new(1.0, p.teal))
                        .inner_margin(egui::Margin::same(10.0)),
                )
                .show(ctx, |ui| {
                    // Subheader — stat meaning + window
                    ui.label(
                        egui::RichText::new(stat_chip_tooltip(kind.label()))
                            .size(9.0)
                            .color(p.cream),
                    );
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!("window: {}", kind.window()))
                                .size(8.0)
                                .color(p.text_dim),
                        );
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if ui
                                    .button(
                                        egui::RichText::new("clear")
                                            .size(9.0)
                                            .color(p.amber),
                                    )
                                    .on_hover_text(
                                        "Reset the agent investigation panel (events stay — \
                                         they mirror the log buffer).",
                                    )
                                    .clicked()
                                {
                                    if let Ok(mut r) = self.agent_run.lock() {
                                        *r = AgentRun {
                                            stat: Some(kind),
                                            ..Default::default()
                                        };
                                    }
                                }
                                if ui
                                    .button(
                                        egui::RichText::new("copy all")
                                            .size(9.0)
                                            .color(p.teal),
                                    )
                                    .on_hover_text(
                                        "Copy events + agent summary + notes + proposed \
                                         actions as plain text to the clipboard.",
                                    )
                                    .clicked()
                                {
                                    let evs = filter_events_for_stat(&snap.log_entries, kind, 200);
                                    let buf = build_drill_copy_buffer(
                                        kind,
                                        &evs,
                                        &agent_snapshot,
                                    );
                                    ui.ctx().copy_text(buf);
                                }
                            },
                        );
                    });
                    ui.separator();

                    // ---- Events panel (filtered from the log buffer) ----
                    let events: Vec<(String, String, Sev)> =
                        filter_events_for_stat(&snap.log_entries, kind, 40);
                    ui.label(
                        egui::RichText::new(format!(
                            "{} recent event(s) matching this stat",
                            events.len()
                        ))
                        .size(9.0)
                        .color(p.text_dim),
                    );
                    egui::ScrollArea::vertical()
                        .max_height(140.0)
                        .show(ui, |ui| {
                            if events.is_empty() {
                                ui.label(
                                    egui::RichText::new(
                                        "(no matching events in current log buffer)",
                                    )
                                    .size(9.0)
                                    .color(p.text_dim),
                                );
                            } else {
                                for (ts, msg, sev) in &events {
                                    let color = match sev {
                                        Sev::Crit => p.terracotta,
                                        Sev::Warn => p.amber,
                                        Sev::Info => p.cream,
                                    };
                                    ui.horizontal_wrapped(|ui| {
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(ts)
                                                    .size(8.0)
                                                    .color(p.slate),
                                            )
                                            .selectable(true),
                                        );
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(msg)
                                                    .size(9.0)
                                                    .color(color),
                                            )
                                            .selectable(true)
                                            .wrap(),
                                        );
                                    });
                                    ui.add_space(2.0);
                                }
                            }
                        });

                    ui.separator();

                    // ---- Agent status + run button ----
                    ui.horizontal(|ui| {
                        let (status_txt, status_color) = match agent_snapshot.status {
                            AgentStatus::Idle => ("agent: idle", p.text_dim),
                            AgentStatus::Running => ("agent: investigating...", p.teal),
                            AgentStatus::Done => ("agent: done", p.teal),
                            AgentStatus::Failed => ("agent: failed", p.terracotta),
                        };
                        ui.label(
                            egui::RichText::new(status_txt)
                                .size(9.0)
                                .color(status_color),
                        );
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                let running = agent_snapshot.status == AgentStatus::Running;
                                let btn_label = if agent_snapshot.status == AgentStatus::Done
                                    || agent_snapshot.status == AgentStatus::Failed
                                {
                                    "re-run shield agent"
                                } else {
                                    "run shield agent"
                                };
                                let btn = egui::Button::new(
                                    egui::RichText::new(btn_label)
                                        .size(9.0)
                                        .color(if running { p.text_dim } else { p.teal }),
                                );
                                if ui.add_enabled(!running, btn).clicked() {
                                    self.spawn_shield_agent(kind, &events);
                                }
                            },
                        );
                    });

                    // ---- Agent notes ----
                    if !agent_snapshot.summary.is_empty()
                        || !agent_snapshot.notes.is_empty()
                        || agent_snapshot.error.is_some()
                    {
                        ui.separator();
                        if !agent_snapshot.summary.is_empty() {
                            ui.label(
                                egui::RichText::new(&agent_snapshot.summary)
                                    .size(10.0)
                                    .color(p.cream)
                                    .strong(),
                            );
                        }
                        if !agent_snapshot.classification.is_empty() {
                            ui.label(
                                egui::RichText::new(format!(
                                    "classification: {}",
                                    agent_snapshot.classification
                                ))
                                .size(8.0)
                                .color(p.text_dim),
                            );
                        }
                        if let Some(err) = &agent_snapshot.error {
                            ui.label(
                                egui::RichText::new(err)
                                    .size(9.0)
                                    .color(p.terracotta),
                            );
                        }
                        if !agent_snapshot.notes.is_empty() {
                            egui::ScrollArea::vertical()
                                .id_salt("agent-notes")
                                .max_height(100.0)
                                .show(ui, |ui| {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(&agent_snapshot.notes)
                                                .size(8.5)
                                                .color(p.text_dim),
                                        )
                                        .selectable(true)
                                        .wrap(),
                                    );
                                });
                        }
                    }

                    // ---- Proposed actions ----
                    if !agent_snapshot.actions.is_empty() {
                        ui.separator();
                        ui.label(
                            egui::RichText::new(format!(
                                "proposed actions ({})",
                                agent_snapshot.actions.len()
                            ))
                            .size(9.0)
                            .color(p.amber),
                        );
                        for (idx, action) in agent_snapshot.actions.iter().enumerate() {
                            ui.add_space(3.0);
                            let (tag, tag_color) = match action.state {
                                ActionState::Pending => ("pending", p.amber),
                                ActionState::Accepting => ("applying", p.teal),
                                ActionState::Accepted => ("applied", p.teal),
                                ActionState::Rejected => ("rejected", p.slate),
                                ActionState::Failed => ("failed", p.terracotta),
                            };
                            ui.horizontal_wrapped(|ui| {
                                ui.label(
                                    egui::RichText::new(format!("[{}]", action.kind))
                                        .size(9.0)
                                        .color(p.cream)
                                        .strong(),
                                );
                                ui.label(
                                    egui::RichText::new(format!("({tag})"))
                                        .size(8.0)
                                        .color(tag_color),
                                );
                                let params_str = action.params.to_string();
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&params_str)
                                            .size(8.5)
                                            .color(p.text_dim),
                                    )
                                    .selectable(true)
                                    .wrap(),
                                );
                            });
                            ui.horizontal_wrapped(|ui| {
                                ui.add_space(6.0);
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&action.reason)
                                            .size(8.5)
                                            .color(p.cream),
                                    )
                                    .selectable(true)
                                    .wrap(),
                                );
                            });

                            // Action buttons (Pending only)
                            if action.state == ActionState::Pending {
                                ui.horizontal(|ui| {
                                    if ui
                                        .button(
                                            egui::RichText::new("accept")
                                                .size(9.0)
                                                .color(p.teal)
                                                .strong(),
                                        )
                                        .clicked()
                                    {
                                        self.accept_action(idx);
                                    }
                                    if ui
                                        .button(
                                            egui::RichText::new("reject")
                                                .size(9.0)
                                                .color(p.slate),
                                        )
                                        .clicked()
                                    {
                                        self.reject_action(idx);
                                    }
                                });
                            }
                        }
                    }
                });
            if !still_open {
                self.open_stat_drill = None;
            }
        }
    }
}

/// Build the plain-text buffer copied to the clipboard when the user
/// clicks "copy all" in the stat drill-down modal. Includes the events,
/// the shield agent's summary + notes + classification, and every
/// proposed action with its current accept/reject state.
fn build_drill_copy_buffer(
    kind: StatKind,
    events: &[(String, String, Sev)],
    agent: &AgentRun,
) -> String {
    let mut s = String::new();
    s.push_str(&format!("# NexusShield stat drill-down: {}\n", kind.label()));
    s.push_str(&format!("window: {}\n\n", kind.window()));

    s.push_str(&format!("## events ({})\n", events.len()));
    if events.is_empty() {
        s.push_str("(no matching events in current log buffer)\n");
    } else {
        for (ts, msg, sev) in events {
            let tag = match sev {
                Sev::Crit => "CRIT",
                Sev::Warn => "WARN",
                Sev::Info => "INFO",
            };
            s.push_str(&format!("{ts}  {tag}  {msg}\n"));
        }
    }
    s.push('\n');

    s.push_str("## shield agent\n");
    let status = match agent.status {
        AgentStatus::Idle => "idle",
        AgentStatus::Running => "running",
        AgentStatus::Done => "done",
        AgentStatus::Failed => "failed",
    };
    s.push_str(&format!("status: {status}\n"));
    if !agent.classification.is_empty() {
        s.push_str(&format!("classification: {}\n", agent.classification));
    }
    if !agent.summary.is_empty() {
        s.push_str(&format!("summary: {}\n", agent.summary));
    }
    if let Some(err) = &agent.error {
        s.push_str(&format!("error: {err}\n"));
    }
    if !agent.notes.is_empty() {
        s.push_str("\n--- agent notes ---\n");
        s.push_str(&agent.notes);
        if !agent.notes.ends_with('\n') {
            s.push('\n');
        }
    }
    s.push('\n');

    if !agent.actions.is_empty() {
        s.push_str(&format!("## proposed actions ({})\n", agent.actions.len()));
        for (i, a) in agent.actions.iter().enumerate() {
            let state = match a.state {
                ActionState::Pending => "pending",
                ActionState::Accepting => "applying",
                ActionState::Accepted => "accepted",
                ActionState::Rejected => "rejected",
                ActionState::Failed => "failed",
            };
            s.push_str(&format!(
                "{}. [{}] ({state}) params={} reason: {}\n",
                i + 1,
                a.kind,
                a.params,
                a.reason,
            ));
        }
    }

    s
}

/// Filter the ticker's log buffer down to entries that plausibly match
/// the selected stat. Keyword-based — the ticker doesn't keep
/// per-category counters, so we match on the message text that the
/// poller wrote when it wired an event into the log.
fn filter_events_for_stat(
    entries: &[(String, String, Sev)],
    kind: StatKind,
    limit: usize,
) -> Vec<(String, String, Sev)> {
    let needles: &[&str] = match kind {
        StatKind::Blocked5m | StatKind::Blocked1h => &["block", "sanitizer", "Blocked"],
        StatKind::Sql5m | StatKind::Sql1h => &["SQL", "sql_injection", "SQLi"],
        StatKind::Ssrf5m | StatKind::Ssrf1h => &["SSRF", "ssrf"],
        StatKind::Rate5m | StatKind::Rate1h => &["rate_limit", "RateLimited", "rate-limit"],
        StatKind::FilesScanned => &["scan", "Scanned"],
        StatKind::Threats => &[
            "beaconing",
            "malicious",
            "Suspicious",
            "threat",
            "Malware",
        ],
        StatKind::Quarantine => &["quarantine", "Quarantined"],
        StatKind::AuditEvents => &[""], // match everything
    };

    entries
        .iter()
        .rev()
        .filter(|(_, msg, sev)| {
            // Drop Info-only noise from the drill-down unless this is
            // the audit-events stat which is intentionally comprehensive.
            if *sev == Sev::Info && !matches!(kind, StatKind::AuditEvents | StatKind::FilesScanned) {
                return false;
            }
            if needles.iter().all(|n| n.is_empty()) {
                return true;
            }
            needles.iter().any(|n| !n.is_empty() && msg.contains(n))
        })
        .take(limit)
        .cloned()
        .collect()
}

/// Render a single clickable stat chip. Returns the combined click
/// Response so the caller can react to clicks (opens the drill-down
/// modal for that stat kind).
fn stat_chip(
    ui: &mut egui::Ui,
    pal: &Palette,
    label: &str,
    value: u64,
    color: egui::Color32,
) -> egui::Response {
    let c = if value > 0 { color } else { pal.text_dim };
    let tip = stat_chip_tooltip(label);

    // Group the label + value so the whole thing is one clickable region
    // with a single hover/click surface. InteractKind::Click makes the
    // response report `clicked()` when the pointer is released inside.
    let resp = ui
        .scope(|ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 3.0;
                ui.label(
                    egui::RichText::new(label.to_string())
                        .size(8.0)
                        .color(pal.text_dim),
                );
                ui.label(
                    egui::RichText::new(format!("{value}"))
                        .size(9.0)
                        .color(c)
                        .strong(),
                );
            });
        })
        .response
        .interact(egui::Sense::click())
        .on_hover_text(format!("{tip}\n\nClick to drill down + run shield agent."));

    // Subtle hover hint — cursor becomes a pointing hand.
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }

    ui.add_space(6.0);
    resp
}

fn stat_chip_tooltip(label: &str) -> &'static str {
    match label {
        "blocked 5m" => "Requests blocked by the gateway in the last 5 minutes (SQLi/SSRF/sanitizer matches).",
        "sql 5m" => "SQL injection attempts blocked in the last 5 minutes.",
        "ssrf 5m" => "Server-side request forgery attempts blocked in the last 5 minutes.",
        "rate 5m" => "Requests rate-limited (token bucket exhausted) in the last 5 minutes.",
        "blocked 1h" => "Requests blocked by the gateway in the last hour.",
        "sql 1h" => "SQL injection attempts blocked in the last hour.",
        "ssrf 1h" => "SSRF attempts blocked in the last hour.",
        "rate 1h" => "Requests rate-limited in the last hour.",
        "files scanned" => "Total files scanned by the endpoint scanners since shield start.",
        "threats" => "Total endpoint threats detected since shield start (any severity).",
        "quarantine" => "Files currently held in quarantine awaiting review.",
        "audit events" => "Total audit-chain events recorded since shield start.",
        _ => "stat",
    }
}

/// Shorten a module name for the compact LED row.
fn module_short(name: &str) -> &str {
    match name {
        "sql_firewall" => "sql",
        "ssrf_guard" => "ssrf",
        "rate_governor" => "rate",
        "fingerprint" => "fp",
        "quarantine" => "qtn",
        "email_guard" => "mail",
        "credential_vault" => "vault",
        "audit_chain" => "audit",
        "sanitizer" => "san",
        "threat_score" => "score",
        "siem_export" => "siem",
        "journal" => "jrn",
        "sse_events" => "sse",
        "signatures" => "sig",
        "heuristics" => "heur",
        "yara_engine" => "yara",
        "watcher" => "watch",
        "process_monitor" => "proc",
        "network_monitor" => "net",
        "memory_scanner" => "mem",
        "rootkit_detector" => "rkit",
        "dns_filter" => "dns",
        "usb_monitor" => "usb",
        "fim" => "fim",
        "container_scanner" => "ctr",
        "supply_chain" => "sup",
        "allowlist" => "allow",
        "threat_intel" => "intel",
        "file_quarantine" => "fqtn",
        _ => name,
    }
}

// =============================================================================
// Palette + LED rendering
// =============================================================================

#[derive(Clone, Copy, PartialEq, Debug)]
enum Theme {
    Dark,
    Light,
}

impl Theme {
    fn toggled(self) -> Self {
        match self {
            Self::Dark => Self::Light,
            Self::Light => Self::Dark,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
        }
    }
    fn from_str(s: &str) -> Self {
        if s.trim().eq_ignore_ascii_case("light") {
            Self::Light
        } else {
            Self::Dark
        }
    }
}

#[derive(Clone, Copy)]
struct Palette {
    /// Primary text color (high-contrast on bg).
    cream: egui::Color32,
    /// Success / ok / online signals.
    teal: egui::Color32,
    /// Alerts / critical.
    terracotta: egui::Color32,
    /// Warnings / pending.
    amber: egui::Color32,
    /// Muted / offline / unknown.
    slate: egui::Color32,
    /// Panel + window background.
    bg_dark: egui::Color32,
    /// Secondary/dim text.
    text_dim: egui::Color32,
    /// Base theme visuals (dark vs light egui base).
    is_dark: bool,
}

impl Palette {
    /// NexusStratum dark theme (original).
    fn dark() -> Self {
        Self {
            cream: egui::Color32::from_rgb(245, 240, 235),
            teal: egui::Color32::from_rgb(20, 184, 166),
            terracotta: egui::Color32::from_rgb(205, 92, 68),
            amber: egui::Color32::from_rgb(245, 180, 60),
            slate: egui::Color32::from_rgb(150, 145, 138),
            bg_dark: egui::Color32::from_rgb(45, 42, 38),
            text_dim: egui::Color32::from_rgb(155, 145, 138),
            is_dark: true,
        }
    }
    /// Claude-browser-inspired light theme: warm cream paper bg, warm
    /// near-black text, Claude's terracotta accent. Signal colors stay
    /// semantic (success=green, alert=red, warn=amber) but tuned darker
    /// for legibility on the cream bg.
    fn light() -> Self {
        Self {
            // High-contrast text — warm near-black (Claude body text).
            cream: egui::Color32::from_rgb(31, 30, 29),
            // Success / online — muted forest green (reads as "good" on cream).
            teal: egui::Color32::from_rgb(46, 125, 90),
            // Critical — Claude's signature terracotta, saturated for alert punch.
            terracotta: egui::Color32::from_rgb(184, 64, 42),
            // Warning — deep amber that doesn't fade on cream.
            amber: egui::Color32::from_rgb(184, 132, 42),
            // Muted / offline / unknown.
            slate: egui::Color32::from_rgb(158, 154, 146),
            // Paper background — Claude's soft cream #F5F4EF.
            bg_dark: egui::Color32::from_rgb(245, 244, 239),
            // Secondary/dim text — warm gray.
            text_dim: egui::Color32::from_rgb(107, 104, 98),
            is_dark: false,
        }
    }
    fn for_theme(t: Theme) -> Self {
        match t {
            Theme::Dark => Self::dark(),
            Theme::Light => Self::light(),
        }
    }
}

/// Where the theme preference is persisted between launches.
fn theme_pref_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home).join(".nexus-shield/ticker-theme")
}

fn load_theme() -> Theme {
    std::fs::read_to_string(theme_pref_path())
        .map(|s| Theme::from_str(&s))
        .unwrap_or(Theme::Dark)
}

fn save_theme(t: Theme) {
    let path = theme_pref_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, t.as_str());
}

fn draw_led(
    ui: &mut egui::Ui,
    color: egui::Color32,
    radius: f32,
    pulse: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(radius * 2.5, radius * 2.5),
        egui::Sense::click(),
    );
    let center = rect.center();

    let alpha = if pulse {
        let t = ui.input(|i| i.time) as f32;
        let wave = (t * 2.0).sin() * 0.2 + 0.8;
        (wave * 255.0) as u8
    } else {
        255
    };

    let c = egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), alpha);
    let glow =
        egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), alpha / 4);
    ui.painter().circle_filled(center, radius * 1.6, glow);
    ui.painter().circle_filled(center, radius, c);
    let highlight = egui::Color32::from_rgba_unmultiplied(255, 255, 255, alpha / 3);
    ui.painter().circle_filled(
        center + egui::vec2(-radius * 0.2, -radius * 0.2),
        radius * 0.35,
        highlight,
    );

    response
}

/// Human-readable name for a gateway/endpoint module — used as hover text on
/// the compact LED row so the user can find out what `proc`, `fp`, `fim` etc.
/// actually mean without leaving the ticker.
fn module_long(name: &str) -> &'static str {
    match name {
        // Gateway
        "sql_firewall" => "SQL injection firewall — inspects request bodies for SQLi patterns",
        "ssrf_guard" => "SSRF guard — blocks outbound requests to internal/cloud-metadata IPs",
        "rate_governor" => "Rate governor — per-IP / per-route token-bucket throttle",
        "fingerprint" => "Client fingerprinting — TLS + HTTP fingerprints for bot detection",
        "quarantine" => "Request quarantine — holds suspicious requests for inspection",
        "email_guard" => "Email guard — outbound mail policy + DLP",
        "credential_vault" => "Credential vault — gateway-side secret broker",
        "audit_chain" => "Audit chain — append-only hash-chained event log",
        "sanitizer" => "Input sanitizer — strips XSS / dangerous payloads",
        "threat_score" => "Threat scorer — composite per-request risk score",
        "siem_export" => "SIEM exporter — forwards events to external SIEMs",
        "journal" => "Persistent journal — durable event store",
        "sse_events" => "SSE event stream — live event feed for clients",
        // Endpoint
        "signatures" => "Signature scanner — known-malware hash + YARA rule matching",
        "heuristics" => "Heuristics engine — behavioral file scoring",
        "yara_engine" => "YARA engine — custom rule matching against files",
        "watcher" => "Filesystem watcher — inotify on critical paths",
        "process_monitor" => "Process monitor — reverse shells, miners, sustained-CPU jobs (THIS is what flagged xmrig)",
        "network_monitor" => "Network monitor — /proc/net/tcp scan for C2 beaconing + threat IPs",
        "memory_scanner" => "Memory scanner — RWX page + injected-shellcode detection",
        "rootkit_detector" => "Rootkit detector — hidden PID + hooked syscall checks",
        "dns_filter" => "DNS filter — DGA + sinkhole + DoH-bypass detection",
        "usb_monitor" => "USB monitor — auto-classify + scan removable media on insert",
        "fim" => "File integrity monitor — hash-watch for /etc, /usr/bin, etc.",
        "container_scanner" => "Container scanner — image layer CVE + secret scan",
        "supply_chain" => "Supply-chain scanner — package manifest provenance check",
        "allowlist" => "Developer allowlist — auto-detected toolchains exempt from scans",
        "threat_intel" => "Threat intel DB — local cache of malicious IP/hash feeds",
        "file_quarantine" => "File quarantine — moves detected threats to a sealed dir",
        _ => "module",
    }
}

fn status_led_color(pal: &Palette, status: &str) -> egui::Color32 {
    match status {
        "IDLE" | "WATCHING" => pal.teal,
        "ALERT" => pal.terracotta,
        "OFFLINE" => pal.slate,
        _ => pal.slate,
    }
}

// =============================================================================
// Helpers / snapshot
// =============================================================================

fn now() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

struct Snapshot {
    status_label: String,
    status_detail: String,
    backend_online: bool,
    have_token: bool,
    base_url: String,
    detection_count: u64,
    stats: Stats,
    endpoint: EndpointStats,
    modules_alive: HashMap<String, bool>,
    log_entries: Vec<(String, String, Sev)>,
}

impl SharedState {
    fn clone_snapshot(&self) -> Snapshot {
        Snapshot {
            status_label: self.status.label().to_string(),
            status_detail: self.status.detail(),
            backend_online: self.backend_online,
            have_token: self.have_token,
            base_url: self.base_url.clone(),
            detection_count: self.detection_count,
            stats: self.stats.clone(),
            endpoint: self.endpoint.clone(),
            modules_alive: self.modules_alive.clone(),
            log_entries: self
                .log
                .iter()
                .map(|e| (e.timestamp.clone(), e.message.clone(), e.severity))
                .collect(),
        }
    }
}
