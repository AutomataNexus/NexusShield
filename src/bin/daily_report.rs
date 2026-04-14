// ============================================================================
// File: bin/daily_report.rs
// Description: Generates a NexusShield daily security report by querying a
//              running shield instance and renders the Ferrum-Mail-styled
//              HTML summary.
// Author: Andrew Jewell Sr. - AutomataNexus
// ============================================================================
//!
//! Usage:
//!   daily-report                          # fetches from $NEXUS_SHIELD_URL, writes to /tmp
//!   daily-report --out /path/to/out.html  # write to specific path
//!   daily-report --sample                 # skip shield, render from a canned sample
//!   daily-report --hours 24               # window to aggregate (default 24)
//!
//! Required env (unless --sample):
//!   NEXUS_SHIELD_URL   default http://127.0.0.1:8080
//!   NEXUS_SHIELD_TOKEN required if shield has api_token configured
//!
//! This binary does NOT send email. It writes HTML to disk so you can
//! preview in a browser and iterate on the design. The send step is a
//! separate cron job that runs this + pipes output to an SMTP sender.

use std::collections::HashSet;
use std::process::ExitCode;

use clap::Parser;
use nexus_shield::daily_report::{DailyReport, TopDetection, render_html, render_text, subject};

#[derive(Parser, Debug)]
#[command(name = "daily-report", about = "Generate a NexusShield daily security report")]
struct Args {
    /// Path to write the rendered HTML to.
    #[arg(long, default_value = "/tmp/shield-daily-report.html")]
    out: String,

    /// Aggregation window in hours.
    #[arg(long, default_value = "24")]
    hours: u32,

    /// Render a canned sample report (no shield query).
    #[arg(long, default_value = "false")]
    sample: bool,

    /// Source label shown in the footer (hostname, Tailscale IP, domain).
    #[arg(long)]
    source: Option<String>,

    /// Print subject line + JSON summary to stdout (useful for piping to
    /// an SMTP sender).
    #[arg(long, default_value = "false")]
    print_meta: bool,

    /// Send the rendered HTML as the email body via the Ferrum Mail API.
    /// Requires FERRUM_API_URL, FERRUM_USER, FERRUM_PASS env vars (or
    /// credentials at secret/ferrum-mail in Vault).
    #[arg(long, default_value = "false")]
    send: bool,

    /// Recipient email address(es). Repeatable. Required with --send.
    #[arg(long = "to")]
    to: Vec<String>,

    /// Override the subject line. Defaults to auto-generated from report.
    #[arg(long)]
    subject: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let report = if args.sample {
        build_sample(args.hours, args.source.clone())
    } else {
        match build_from_shield(args.hours, args.source.clone()).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("daily-report: failed to build from shield: {e}");
                return ExitCode::from(1);
            }
        }
    };

    let html = render_html(&report);
    if let Err(e) = std::fs::write(&args.out, &html) {
        eprintln!("daily-report: failed to write {}: {}", args.out, e);
        return ExitCode::from(2);
    }

    eprintln!("daily-report: wrote {} ({} bytes)", args.out, html.len());
    let subj = args.subject.clone().unwrap_or_else(|| subject(&report));
    eprintln!("  subject: {}", subj);

    if args.send {
        if args.to.is_empty() {
            eprintln!("daily-report: --send requires at least one --to <email>");
            return ExitCode::from(3);
        }
        let text = render_text(&report);
        match send_via_ferrum(&subj, &html, &text, &args.to).await {
            Ok(()) => {
                eprintln!("daily-report: sent to {}", args.to.join(", "));
            }
            Err(e) => {
                eprintln!("daily-report: send failed: {e}");
                return ExitCode::from(4);
            }
        }
    }

    if args.print_meta {
        // Print a small JSON blob with subject + path so callers can pipe.
        let meta = serde_json::json!({
            "subject": subject(&report),
            "html_path": args.out,
            "date": report.date,
            "critical": report.endpoint_critical,
            "gateway_total": report.gateway_total(),
            "endpoint_total": report.endpoint_total(),
        });
        println!("{}", meta);
    }

    ExitCode::SUCCESS
}

async fn build_from_shield(hours: u32, source: Option<String>) -> Result<DailyReport, String> {
    let base = std::env::var("NEXUS_SHIELD_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let token = std::env::var("NEXUS_SHIELD_TOKEN").ok();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("client build: {e}"))?;

    let bearer =
        |r: reqwest::RequestBuilder| if let Some(t) = &token { r.bearer_auth(t) } else { r };

    // ── /status — for audit chain integrity + totals ──────────────────
    let status: serde_json::Value = bearer(client.get(format!("{base}/status")))
        .send()
        .await
        .map_err(|e| format!("/status: {e}"))?
        .error_for_status()
        .map_err(|e| format!("/status: {e}"))?
        .json()
        .await
        .map_err(|e| format!("/status json: {e}"))?;

    let audit_chain_valid = status
        .get("audit_chain")
        .and_then(|a| a.get("chain_valid"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let uptime_secs = status
        .get("uptime_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // ── /audit — recent audit events, filtered to last N hours ────────
    let audit_resp: serde_json::Value = bearer(client.get(format!("{base}/audit")))
        .send()
        .await
        .map_err(|e| format!("/audit: {e}"))?
        .error_for_status()
        .map_err(|e| format!("/audit: {e}"))?
        .json()
        .await
        .map_err(|e| format!("/audit json: {e}"))?;

    let cutoff = chrono::Utc::now() - chrono::Duration::hours(hours as i64);
    let empty = Vec::new();
    let events = audit_resp
        .get("recent_events")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);

    let mut requests_inspected: u64 = 0;
    let mut blocked = 0u64;
    let mut sql_injection = 0u64;
    let mut ssrf = 0u64;
    let mut path_traversal = 0u64;
    let mut rate_limited = 0u64;
    let mut auth_failures = 0u64;
    let mut bans_issued = 0u64;
    let mut source_ips: HashSet<String> = HashSet::new();

    for e in events {
        let ts = e
            .get("timestamp")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
        if let Some(ts) = ts {
            if ts.with_timezone(&chrono::Utc) < cutoff {
                continue;
            }
        }
        let et = e
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let ip = e
            .get("source_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !ip.is_empty() {
            source_ips.insert(ip.to_string());
        }
        match et {
            "RequestAllowed" | "RequestBlocked" => requests_inspected += 1,
            _ => {}
        }
        match et {
            "RequestBlocked" => blocked += 1,
            "SqlInjectionAttempt" => sql_injection += 1,
            "SsrfAttempt" => ssrf += 1,
            "PathTraversalAttempt" => path_traversal += 1,
            "RateLimitHit" => rate_limited += 1,
            "AuthFailure" => auth_failures += 1,
            "BanIssued" => bans_issued += 1,
            _ => {}
        }
    }

    // ── /endpoint/status + /endpoint/detections ───────────────────────
    let mut files_scanned_total: u64 = 0;
    let mut quarantined_total: u64 = 0;
    if let Ok(resp) = bearer(client.get(format!("{base}/endpoint/status"))).send().await {
        if resp.status().is_success() {
            if let Ok(v) = resp.json::<serde_json::Value>().await {
                files_scanned_total = v
                    .get("total_files_scanned")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                quarantined_total = v
                    .get("quarantined_files")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
            }
        }
    }

    let ep_dets: serde_json::Value = bearer(client.get(format!("{base}/endpoint/detections")))
        .send()
        .await
        .map_err(|e| format!("/endpoint/detections: {e}"))?
        .error_for_status()
        .map_err(|e| format!("/endpoint/detections: {e}"))?
        .json()
        .await
        .map_err(|e| format!("/endpoint/detections json: {e}"))?;

    let empty = Vec::new();
    let detections = ep_dets
        .get("detections")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);

    let mut endpoint_critical = 0u64;
    let mut endpoint_high = 0u64;
    let mut endpoint_medium = 0u64;
    let mut endpoint_low = 0u64;
    let mut top_detections: Vec<TopDetection> = Vec::new();

    for d in detections {
        let ts = d
            .get("timestamp")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
        if let Some(ts) = ts {
            if ts.with_timezone(&chrono::Utc) < cutoff {
                continue;
            }
        }
        let sev = d
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        match sev.to_lowercase().as_str() {
            "critical" => endpoint_critical += 1,
            "high" => endpoint_high += 1,
            "medium" => endpoint_medium += 1,
            "low" => endpoint_low += 1,
            _ => {}
        }

        // Collect notable detections (critical + high) for the top list.
        let sev_rank = match sev.to_lowercase().as_str() {
            "critical" => 3,
            "high" => 2,
            "medium" => 1,
            _ => 0,
        };
        if sev_rank >= 2 && top_detections.len() < 10 {
            let ts_str = d
                .get("timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let pretty_ts = chrono::DateTime::parse_from_rfc3339(&ts_str)
                .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or(ts_str);
            top_detections.push(TopDetection {
                scanner: d.get("scanner").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
                severity: sev,
                description: d.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                target: d.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                timestamp: pretty_ts,
            });
        }
    }

    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let source_label = source.unwrap_or_else(|| {
        // Strip scheme + port for a clean footer label.
        base.replace("https://", "")
            .replace("http://", "")
            .split('/')
            .next()
            .unwrap_or(&base)
            .to_string()
    });

    Ok(DailyReport {
        date,
        source: source_label,
        covered_hours: hours,
        requests_inspected,
        blocked,
        sql_injection,
        ssrf,
        path_traversal,
        rate_limited,
        auth_failures,
        bans_issued,
        unique_source_ips: source_ips.len() as u64,
        endpoint_critical,
        endpoint_high,
        endpoint_medium,
        endpoint_low,
        files_scanned_total,
        quarantined_total,
        audit_chain_valid,
        uptime_secs,
        top_detections,
    })
}

/// POST to Ferrum Mail's login endpoint, then its send endpoint, using the
/// rendered HTML as the email body (not an attachment).
///
/// Looks up credentials in this order:
///   1. env vars: FERRUM_API_URL, FERRUM_USER, FERRUM_PASS
///   2. vault: secret/ferrum-mail (fields: api_url, username, password)
async fn send_via_ferrum(
    subject_line: &str,
    html_body: &str,
    text_body: &str,
    to: &[String],
) -> Result<(), String> {
    let (api_url, username, password) = resolve_ferrum_creds().await?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("client build: {e}"))?;

    // ── Step 1: login → JWT ───────────────────────────────────────────
    let login_url = format!("{}/mailbox/api/v1/auth/login", api_url.trim_end_matches('/'));
    let login_resp = client
        .post(&login_url)
        .json(&serde_json::json!({
            "username": username,
            "password": password,
        }))
        .send()
        .await
        .map_err(|e| format!("login request: {e}"))?;

    let login_status = login_resp.status();
    let login_text = login_resp.text().await.unwrap_or_default();
    if !login_status.is_success() {
        return Err(format!(
            "login returned HTTP {login_status}: {login_text}"
        ));
    }

    let login_json: serde_json::Value = serde_json::from_str(&login_text)
        .map_err(|e| format!("login response not JSON: {e} body={login_text}"))?;
    let token = login_json
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("no `token` field in login response: {login_text}"))?
        .to_string();

    // ── Step 2: send the email ────────────────────────────────────────
    let send_url = format!("{}/mailbox/api/v1/send", api_url.trim_end_matches('/'));
    let payload = serde_json::json!({
        "to": to,
        "subject": subject_line,
        "html": html_body,
        "text": text_body,
    });

    let send_resp = client
        .post(&send_url)
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("send request: {e}"))?;

    let send_status = send_resp.status();
    let send_text = send_resp.text().await.unwrap_or_default();
    if !send_status.is_success() {
        return Err(format!(
            "send returned HTTP {send_status}: {send_text}"
        ));
    }

    Ok(())
}

async fn resolve_ferrum_creds() -> Result<(String, String, String), String> {
    // Explicit env vars win outright — useful for local testing.
    if let (Ok(u), Ok(user), Ok(pw)) = (
        std::env::var("FERRUM_API_URL"),
        std::env::var("FERRUM_USER"),
        std::env::var("FERRUM_PASS"),
    ) {
        return Ok((u, user, pw));
    }

    // NexusVault fallback (primary production path on DO).
    // Bootstrap secret: NEXUSVAULT_ADDR + NEXUSVAULT_API_KEY only. Everything
    // else lives in vault: ferrum-mail-api-url, ferrum-mail-api-user,
    // ferrum-mail-api-password.
    if let (Ok(addr), Ok(key)) = (
        std::env::var("NEXUSVAULT_ADDR"),
        std::env::var("NEXUSVAULT_API_KEY"),
    ) {
        let api_url = nexusvault_get(&addr, &key, "ferrum-mail-api-url").await?;
        let username = nexusvault_get(&addr, &key, "ferrum-mail-api-user").await?;
        let password = nexusvault_get(&addr, &key, "ferrum-mail-api-password").await?;
        return Ok((api_url, username, password));
    }

    // HashiCorp Vault CLI fallback — used on the dev laptop.
    let run = |arg: &str| -> Result<String, String> {
        let out = std::process::Command::new("vault")
            .args(["kv", "get", "-field", arg, "secret/ferrum-mail"])
            .output()
            .map_err(|e| format!("vault CLI: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "vault kv get secret/ferrum-mail -field={arg} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };

    let api_url = run("api_url")?;
    let username = run("username")?;
    let password = run("password")?;

    if api_url.is_empty() || username.is_empty() || password.is_empty() {
        return Err(
            "missing Ferrum creds — set NEXUSVAULT_ADDR+NEXUSVAULT_API_KEY (prod), FERRUM_* env vars (dev), or populate HashiCorp secret/ferrum-mail".into(),
        );
    }
    Ok((api_url, username, password))
}

/// Fetch a single secret from NexusVault via its HTTP API.
///
/// Endpoint: `GET <addr>/v1/secrets/<name>` with `Authorization: Bearer <key>`.
/// Response shape: `{"name":"...", "value":"..."}` — we return the value.
async fn nexusvault_get(addr: &str, key: &str, name: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("nexusvault client: {e}"))?;

    let url = format!("{}/v1/secrets/{}", addr.trim_end_matches('/'), name);
    let resp = client
        .get(&url)
        .bearer_auth(key)
        .send()
        .await
        .map_err(|e| format!("nexusvault GET {name}: {e}"))?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("nexusvault GET {name} returned HTTP {status}: {text}"));
    }

    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("nexusvault response not JSON: {e} body={text}"))?;

    // NexusVault returns the secret under either `value` or `data.value`
    // depending on version — accept both.
    v.get("value")
        .or_else(|| v.get("data").and_then(|d| d.get("value")))
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("nexusvault {name} response missing `value`: {text}"))
}

fn build_sample(hours: u32, source: Option<String>) -> DailyReport {
    DailyReport {
        date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        source: source.unwrap_or_else(|| "automatanexus.com".into()),
        covered_hours: hours,
        requests_inspected: 14_523,
        blocked: 42,
        sql_injection: 3,
        ssrf: 1,
        path_traversal: 0,
        rate_limited: 187,
        auth_failures: 12,
        bans_issued: 2,
        unique_source_ips: 2_841,
        endpoint_critical: 1,
        endpoint_high: 7,
        endpoint_medium: 15,
        endpoint_low: 64,
        files_scanned_total: 48_291,
        quarantined_total: 0,
        audit_chain_valid: true,
        uptime_secs: 14 * 86400 + 3 * 3600,
        top_detections: vec![
            TopDetection {
                scanner: "sql_firewall".into(),
                severity: "Critical".into(),
                description:
                    "UNION-based SQL injection attempt against /api/search q= parameter".into(),
                target: "203.0.113.42".into(),
                timestamp: "2026-04-12 14:22:18".into(),
            },
            TopDetection {
                scanner: "network_monitor".into(),
                severity: "High".into(),
                description:
                    "Port-scan burst — 412 connection attempts in 30s across 30 ports".into(),
                target: "198.51.100.7".into(),
                timestamp: "2026-04-12 09:41:02".into(),
            },
            TopDetection {
                scanner: "rate_governor".into(),
                severity: "High".into(),
                description: "Sustained 150 rps from single IP over 5 minutes — ban issued".into(),
                target: "192.0.2.88".into(),
                timestamp: "2026-04-12 06:12:55".into(),
            },
        ],
    }
}
