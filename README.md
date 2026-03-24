<p align="center">
  <img src="assets/NexusShield_logo.png" alt="NexusShield Logo" width="280" />
</p>

<h1 align="center">NexusShield</h1>

<p align="center">
  <strong>Real-time database security shield. Detect, block, and neutralize threats automatically.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License: Apache-2.0" /></a>
  <img src="https://img.shields.io/badge/Rust-1.75%2B-orange.svg" alt="Rust 1.75+" />
  <img src="https://img.shields.io/badge/version-0.2.2-green.svg" alt="v0.2.2" />
  <img src="https://img.shields.io/badge/tests-69-brightgreen.svg" alt="69 tests" />
  <img src="https://img.shields.io/badge/LOC-2554-informational.svg" alt="2554 LOC" />
  <img src="https://img.shields.io/badge/SQL%20injection%20patterns-38-red.svg" alt="38 SQL injection patterns" />
</p>

---

## Overview

NexusShield is a comprehensive, real-time database security engine written in Rust. It operates as an inline middleware layer between your application and your database, inspecting every incoming request and SQL query before it reaches the data layer. When a threat is detected, NexusShield scores it, classifies it, and takes action --- blocking, rate-limiting, or allowing the request --- all within microseconds.

### What It Does

NexusShield combines six independent detection modules into a single scoring pipeline:

1. **SQL Injection Detection** --- 38 compiled regex patterns covering UNION injection, stacked queries, time-based blind attacks, encoding evasion, metadata extraction, and more.
2. **IP Reputation Tracking** --- Per-IP scoring from -100 (worst) to +100 (best), updated on every request. Tracks total requests, failed authentications, blocked requests, and threat events.
3. **Request Fingerprinting** --- Classifies user-agents into Browser, ApiClient, Bot, Scanner, or Unknown. Detects 19 known scanner tools (sqlmap, nikto, Burp Suite, etc.) and applies heuristic suspicion scoring.
4. **Anomaly Detection** --- Learns per-user/per-IP query rate baselines using exponential moving averages. After a configurable learning period, flags deviations that exceed the threshold.
5. **Auto-Blocking** --- Automatically bans IPs that exceed the threat score threshold. Supports configurable ban durations, escalation multipliers, and manual overrides.
6. **Live Threat Feed** --- Rolling in-memory event buffer with aggregated statistics, per-IP event counts, top offender tracking, and per-level/per-type breakdowns.

### How It Works as Middleware

NexusShield is designed to sit in your HTTP middleware chain. The typical integration looks like this:

```rust
// In your Axum/Actix/Warp middleware:
let verdict = shield.analyze_request(&request_context);
match verdict {
    ShieldVerdict::Allow => { /* proceed to handler */ }
    ShieldVerdict::Block { reason, threat_level } => {
        return Err(forbidden(reason));
    }
    ShieldVerdict::RateLimit { delay_ms } => {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

// Later, in the query handler:
let verdict = shield.analyze_query(&sql, &request_context);
```

### Why NexusShield Is Different

- **Single-pass scoring**: All detection modules run in a single pass. No secondary lookups, no async waits.
- **Zero allocations on the hot path**: Pattern matching uses pre-compiled regexes. Reputation lookups use `parking_lot::RwLock` for minimal contention.
- **Composable verdicts**: The `ShieldVerdict` enum (Allow / Block / RateLimit) integrates cleanly with any web framework.
- **Security presets**: Choose Strict, Moderate, or Permissive and get tuned thresholds out of the box. Override with custom rules for specific paths.
- **No external dependencies at runtime**: No network calls, no database lookups, no file I/O. Everything runs in-process.

---

## Architecture

```
                    Incoming HTTP Request
                           |
                           v
                  +------------------+
                  |   Allowlist      |  <-- Bypass all checks for trusted IPs
                  +------------------+
                           |
                    (not allowlisted)
                           |
                           v
                  +------------------+
                  |   Ban Check      |  <-- Is this IP currently banned?
                  +------------------+
                           |
                    (not banned)
                           |
                           v
                  +------------------+
                  |  Auto-Blocker    |  <-- Active block entries (timed bans)
                  +------------------+
                           |
                    (not blocked)
                           |
              +------------+------------+
              |                         |
              v                         v
    +------------------+      +------------------+
    |  Fingerprinting  |      |  IP Reputation   |
    |  (User-Agent     |      |  (Score -100     |
    |   classification)|      |   to +100)       |
    +------------------+      +------------------+
              |                         |
              +------------+------------+
                           |
                    combined_score
                           |
                           v
                  +------------------+
                  |  Policy Engine   |  <-- Custom rules + preset thresholds
                  +------------------+
                           |
              +------------+------------+------------+
              |            |            |             |
              v            v            v             v
           ALLOW     RATE-LIMIT      BLOCK          BAN
                                       |             |
                                       v             v
                                +------------------+
                                |  Threat Feed     |  <-- Record event
                                +------------------+


                    SQL Query Analysis
                           |
                           v
                  +------------------+
                  | SQL Injection    |  <-- 38 regex patterns, score 0-100
                  | Detector         |
                  +------------------+
                           |
                           v
                  +------------------+
                  | Anomaly          |  <-- Baseline deviation analysis
                  | Detector         |
                  +------------------+
                           |
                    combined_score
                           |
                           v
                  +------------------+
                  |  Policy Engine   |  <-- Same policy as request analysis
                  +------------------+
                           |
              +------------+------------+
              |            |            |
              v            v            v
           ALLOW     RATE-LIMIT      BLOCK
```

---

## Threat Detection Capabilities

### SQL Injection Detection

The `SqlInjectionDetector` holds 38 pre-compiled regex patterns organized into categories. Each pattern has a name, a score (0-100), and a description. When a query matches multiple patterns, scores are summed and capped at 100.

#### UNION / Subquery Injection

| # | Pattern | Score | Description |
|---|---------|-------|-------------|
| 1 | `union_select` | 90 | `UNION [ALL] SELECT` injection |

#### Tautology / Always-True Conditions

| # | Pattern | Score | Description |
|---|---------|-------|-------------|
| 2 | `or_always_true` | 85 | `OR 1=1` or `OR '1'='1'` always-true condition |
| 19 | `boolean_and` | 70 | `AND 1=1` boolean-based blind injection |
| 36 | `tautology_string` | 85 | String tautology `OR 'a'='a'` |

#### Stacked Queries (Piggyback Injection)

| # | Pattern | Score | Description |
|---|---------|-------|-------------|
| 3 | `stacked_drop` | 95 | `; DROP ...` stacked query |
| 4 | `stacked_delete` | 95 | `; DELETE ...` stacked query |
| 5 | `stacked_insert` | 90 | `; INSERT ...` stacked query |
| 6 | `stacked_update` | 90 | `; UPDATE ...` stacked query |
| 20 | `string_termination` | 90 | Quote + semicolon followed by DDL/DML command |
| 33 | `alter_table` | 90 | `; ALTER TABLE` stacked DDL |
| 34 | `create_stacked` | 90 | `; CREATE TABLE/DATABASE/USER` |

#### Comment Injection

| # | Pattern | Score | Description |
|---|---------|-------|-------------|
| 7 | `comment_dash` | 60 | Trailing `--` single-line comment |
| 8 | `comment_block` | 60 | `/* ... */` block comment |
| 9 | `comment_hash` | 60 | Trailing `#` hash comment (MySQL) |
| 10 | `nested_comment` | 65 | Nested `/* ... /* ...` comments |

#### Time-Based Blind Injection

| # | Pattern | Score | Description |
|---|---------|-------|-------------|
| 11 | `sleep_fn` | 80 | `SLEEP()` timing attack (MySQL) |
| 12 | `benchmark_fn` | 80 | `BENCHMARK()` timing attack (MySQL) |
| 13 | `waitfor_delay` | 80 | `WAITFOR DELAY` timing attack (MSSQL) |
| 24 | `pg_sleep` | 80 | `pg_sleep()` timing attack (PostgreSQL) |

#### File System Access

| # | Pattern | Score | Description |
|---|---------|-------|-------------|
| 14 | `load_file` | 90 | `LOAD_FILE()` read server files |
| 15 | `into_outfile` | 90 | `INTO OUTFILE/DUMPFILE` write server files |

#### String Obfuscation / Encoding Evasion

| # | Pattern | Score | Description |
|---|---------|-------|-------------|
| 16 | `char_obfuscation` | 70 | `CHAR(97,100,109)` obfuscation |
| 17 | `concat_obfuscation` | 70 | `CONCAT()` string building |
| 18 | `hex_encoding` | 75 | `0x61646D696E` hex-encoded values |
| 30 | `double_encode` | 75 | `%2527` double URL-encoded quotes |
| 31 | `unicode_encode` | 75 | `\u0027` / `%u0027` Unicode-encoded quotes |

#### Stored Procedure / Command Execution

| # | Pattern | Score | Description |
|---|---------|-------|-------------|
| 21 | `exec_proc` | 90 | `EXEC xp_` / `EXECUTE sp_` stored procedures |
| 22 | `xp_cmdshell` | 95 | `xp_cmdshell` OS command execution |
| 35 | `shutdown_cmd` | 95 | `SHUTDOWN` command |

#### Metadata / Schema Extraction

| # | Pattern | Score | Description |
|---|---------|-------|-------------|
| 23 | `information_schema` | 75 | `INFORMATION_SCHEMA` metadata access |

#### Clause Injection

| # | Pattern | Score | Description |
|---|---------|-------|-------------|
| 25 | `having_injection` | 70 | `HAVING 1=1` clause injection |
| 26 | `order_by_enum` | 60 | `ORDER BY 99` column enumeration |
| 27 | `group_by_having` | 50 | `GROUP BY ... HAVING` combined injection |

#### XML / Function Injection

| # | Pattern | Score | Description |
|---|---------|-------|-------------|
| 28 | `xml_extract` | 85 | `EXTRACTVALUE()` / `UPDATEXML()` XML injection |
| 29 | `convert_cast` | 40 | `CONVERT/CAST ... AS ...` type coercion |
| 37 | `if_blind` | 70 | `IF(condition, true, false)` blind injection |

#### Other

| # | Pattern | Score | Description |
|---|---------|-------|-------------|
| 32 | `into_var` | 70 | `INTO @variable` assignment |
| 38 | `like_wildcard` | 30 | `LIKE '%'` wildcard abuse |

### IP Reputation

Every IP address that interacts with NexusShield gets a reputation record with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `score` | `i32` | -100 (worst) to +100 (best), starts at 0 |
| `total_requests` | `u64` | Total requests from this IP |
| `failed_auths` | `u64` | Failed authentication attempts |
| `blocked_requests` | `u64` | Requests blocked by shield |
| `threat_events` | `u64` | Threat events generated |
| `first_seen` | `i64` | Unix timestamp of first request |
| `last_seen` | `i64` | Unix timestamp of last request |
| `banned_until` | `Option<u64>` | Epoch seconds ban expiry, or None |
| `ban_reason` | `Option<String>` | Reason for current ban |

**Scoring Mechanics:**

- Each normal request: `+1` to score (capped at +100)
- Each failed authentication: `-10` to score
- Each blocked request: `-20` to score
- Each threat event: `-(threat_score / 10)` to score
- Score clamped to range `[-100, +100]`

**Reputation-based scoring in request analysis:**

- Score below `-50`: adds `+30` to combined threat score
- Score below `-20`: adds `+15` to combined threat score

### Request Fingerprinting

The `RequestFingerprinter` classifies every incoming request into one of five user-agent classes:

| Class | Description | Base Suspicion Score |
|-------|-------------|---------------------|
| `Browser` | Standard web browsers (Chrome, Firefox, Safari, Edge, Opera) | 0 |
| `ApiClient` | HTTP clients (curl, wget, Postman, Insomnia, axios, python-requests, etc.) | 0 |
| `Bot` | Search engine crawlers (Googlebot, Bingbot, etc.) | 20 |
| `Scanner` | Known security scanners and attack tools | 90 |
| `Unknown` | Unrecognized or missing user-agent | 40 |

**Detected Scanners (19 signatures):**

- `sqlmap` --- SQL injection automation tool
- `nikto` --- Web server vulnerability scanner
- `nmap` --- Network discovery and security auditing
- `masscan` --- Internet-scale port scanner
- `gobuster` --- Directory/file brute-forcer
- `dirbuster` --- Web application directory brute-forcer
- `wfuzz` --- Web application fuzzer
- `hydra` --- Network login brute-forcer
- `burpsuite` / `burp suite` --- Web vulnerability scanner and proxy
- `owasp zap` / `zaproxy` --- OWASP Zed Attack Proxy
- `w3af` --- Web application attack and audit framework
- `arachni` --- Web application security scanner
- `skipfish` --- Active web application security reconnaissance
- `havij` --- Automated SQL injection tool
- `acunetix` --- Web vulnerability scanner
- `nessus` --- Vulnerability assessment scanner
- `openvas` --- Open vulnerability assessment system

**Detected Bots (15 signatures):**

- `googlebot`, `bingbot`, `baiduspider`, `yandexbot`, `duckduckbot`
- `slurp`, `ia_archiver`, `facebot`, `twitterbot`, `linkedinbot`
- `semrushbot`, `ahrefsbot`, `mj12bot`, `dotbot`, `petalbot`

**Detected API Clients (10 signatures):**

- `curl`, `wget`, `httpie`, `postman`, `insomnia`
- `axios`, `python-requests`, `go-http-client`, `java/`, `okhttp`

**Heuristic Scoring Adjustments:**

| Condition | Score Added |
|-----------|-----------|
| Unrecognized user-agent | +15 |
| User-agent shorter than 10 chars | +10 |
| Missing/empty user-agent | +40 (returned immediately as Unknown) |
| 4+ values in `X-Forwarded-For` | +15 |
| Browser UA missing `Accept` header | +10 |

### Anomaly Detection

The `QueryAnomalyDetector` builds per-identifier (IP or authenticated user) baselines using an exponential moving average of query rate:

```
alpha = 0.1
avg_rate = avg_rate * (1 - alpha) + current_rate * alpha
```

**Learning Period:**
- Configurable via `anomaly_learning_period_secs` (default: 3600s for Moderate)
- Also requires at least 100 samples before flagging anomalies
- During learning, all queries are allowed and the baseline is built silently

**Deviation Scoring:**
- If `current_rate / baseline_rate > deviation_threshold`, the query is flagged
- Score formula: `min((deviation / threshold) * 30, 80)`
- Anomaly events with score >= 30 are recorded in the threat feed

### Auto-Blocking

The `AutoBlocker` manages timed IP bans with allowlist support:

- **Automatic blocking**: When a threat score exceeds `auto_block_threshold`, the IP is blocked for `default_ban_duration_secs`
- **Brute force escalation**: After 10 failed authentication attempts from a single IP, the IP is automatically banned
- **Allowlist bypass**: IPs on the allowlist are never blocked, regardless of threat score
- **Expiry management**: `cleanup_expired()` removes expired blocks; call periodically or on a timer
- **Manual control**: Block/unblock IPs programmatically with custom reasons and durations

---

## Security Presets

Three presets provide tuned defaults for different security postures:

| Setting | Strict | Moderate | Permissive |
|---------|--------|----------|------------|
| `enabled` | `true` | `true` | `true` |
| `sql_injection_enabled` | `true` | `true` | `true` |
| `anomaly_detection_enabled` | `true` | `true` | `true` |
| `ip_reputation_enabled` | `true` | `true` | `true` |
| `fingerprinting_enabled` | `true` | `true` | `true` |
| `auto_blocking_enabled` | `true` | `true` | `false` |
| `auto_block_threshold` | 60 | 80 | 95 |
| `default_ban_duration_secs` | 7200 (2h) | 3600 (1h) | 300 (5m) |
| `max_ban_duration_secs` | 172800 (48h) | 86400 (24h) | 3600 (1h) |
| `escalation_multiplier` | 3.0 | 2.0 | 1.5 |
| `max_events_in_memory` | 20000 | 10000 | 5000 |
| `anomaly_learning_period_secs` | 1800 (30m) | 3600 (1h) | 7200 (2h) |
| `anomaly_deviation_threshold` | 2.0x | 3.0x | 5.0x |
| `cleanup_interval_secs` | 120 (2m) | 300 (5m) | 600 (10m) |
| **Policy: block threshold** | 60 | 80 | 95 |
| **Policy: rate-limit threshold** | 30 | 50 | 70 |

---

## Quick Start

Add NexusShield to your `Cargo.toml`:

```toml
[dependencies]
nexus-shield = { path = "../NexusShield" }
```

Create and use the shield:

```rust
use nexus_shield::{ShieldEngine, ShieldConfig, SecurityPreset, RequestContext, ShieldVerdict};
use std::collections::HashMap;

fn main() {
    // Initialize with a preset
    let config = ShieldConfig::from_preset(SecurityPreset::Moderate);
    let shield = ShieldEngine::new(config);

    // Build a request context from your HTTP request
    let ctx = RequestContext {
        source_ip: "203.0.113.42".to_string(),
        path: "/api/v1/query".to_string(),
        method: "POST".to_string(),
        user_agent: Some("Mozilla/5.0 Chrome/120".to_string()),
        auth_user: Some("alice".to_string()),
        body_size: 256,
        headers: HashMap::new(),
    };

    // Step 1: Analyze the request (checks IP, fingerprint, reputation)
    match shield.analyze_request(&ctx) {
        ShieldVerdict::Allow => { /* proceed */ }
        ShieldVerdict::Block { reason, .. } => {
            eprintln!("Request blocked: {}", reason);
            return;
        }
        ShieldVerdict::RateLimit { delay_ms } => {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
    }

    // Step 2: Analyze the SQL query
    let sql = "SELECT * FROM users WHERE id = $1";
    match shield.analyze_query(sql, &ctx) {
        ShieldVerdict::Allow => {
            println!("Query allowed, execute it.");
        }
        ShieldVerdict::Block { reason, .. } => {
            eprintln!("Query blocked: {}", reason);
        }
        ShieldVerdict::RateLimit { delay_ms } => {
            eprintln!("Rate limited for {}ms", delay_ms);
        }
    }

    // Check the shield status
    let status = shield.get_status();
    println!(
        "Shield: enabled={}, preset={:?}, requests={}, threats={}",
        status.enabled, status.preset,
        status.total_requests_analyzed, status.total_threats_detected
    );
}
```

---

## Full API Reference

### `ShieldEngine`

The main facade that coordinates all detection modules.

#### Constructor

```rust
pub fn new(config: ShieldConfig) -> Self
```

Creates a new shield engine with the given configuration. Initializes all detection modules, the threat feed, and the policy engine.

#### Request Analysis

```rust
pub fn analyze_request(&self, ctx: &RequestContext) -> ShieldVerdict
```

Analyzes an incoming HTTP request before it reaches any handler. Runs the following checks in order:

1. Shield enabled check (returns `Allow` if disabled)
2. Allowlist bypass
3. Ban check (IP reputation)
4. Auto-blocker check (active block entries)
5. Request fingerprinting (user-agent classification + suspicion scoring)
6. IP reputation scoring
7. Policy evaluation (custom rules, then preset thresholds)

Returns `ShieldVerdict::Allow`, `ShieldVerdict::Block`, or `ShieldVerdict::RateLimit`.

```rust
pub fn analyze_query(&self, query: &str, ctx: &RequestContext) -> ShieldVerdict
```

Analyzes a SQL query string for injection patterns and anomalous behavior. Runs:

1. SQL injection pattern matching (38 patterns)
2. Anomaly detection (rate deviation from baseline)
3. Policy evaluation

Returns the same `ShieldVerdict` enum.

#### Authentication Tracking

```rust
pub fn record_failed_auth(&self, ip: &str, username: &str)
```

Records a failed authentication attempt from the given IP. Decreases reputation by 10 points per failure. After 10 failures from the same IP (when auto-blocking is enabled), the IP is automatically banned for `default_ban_duration_secs`.

```rust
pub fn record_success(&self, ctx: &RequestContext)
```

Records a successful request, slightly improving the IP's reputation score (+1).

#### Dashboard / Monitoring Methods

```rust
pub fn get_stats(&self) -> ThreatStats
```

Returns aggregated statistics including: total events, events by threat level, events by type, blocked IPs count, active bans, top 10 offending IPs, and timestamp of last critical event.

```rust
pub fn get_recent_events(&self, limit: usize) -> Vec<ThreatEvent>
```

Returns the most recent threat events (newest first), up to `limit` entries.

```rust
pub fn get_blocked_ips(&self) -> Vec<BlockEntry>
```

Returns all currently active (non-expired) block entries.

```rust
pub fn get_ip_reputation(&self, ip: &str) -> Option<IpReputation>
```

Returns the full reputation record for a specific IP, or `None` if never seen.

```rust
pub fn get_status(&self) -> ShieldStatus
```

Returns a summary of the shield engine's current state: enabled flag, active preset, uptime in seconds, total requests analyzed, total threats detected, active bans count, and blocked IPs count.

#### IP Management

```rust
pub fn unblock_ip(&self, ip: &str) -> bool
```

Removes an IP from both the auto-blocker and the ban list. Returns `true` if the IP was found in either.

```rust
pub fn add_to_allowlist(&self, ip: &str)
```

Adds an IP to the allowlist. Allowlisted IPs bypass all security checks.

```rust
pub fn remove_from_allowlist(&self, ip: &str)
```

Removes an IP from the allowlist.

```rust
pub fn get_allowlist(&self) -> Vec<String>
```

Returns all IPs currently on the allowlist.

```rust
pub fn manual_block(&self, ip: &str, reason: &str, duration_secs: u64)
```

Manually blocks an IP for the specified duration with a custom reason. The block is recorded at `ThreatLevel::High`.

#### Policy Management

```rust
pub fn update_policy(&self, policy: SecurityPolicy)
```

Replaces the active security policy. Takes effect immediately for all subsequent requests.

```rust
pub fn get_policy(&self) -> SecurityPolicy
```

Returns a clone of the currently active security policy.

#### Maintenance

```rust
pub fn cleanup_expired(&self)
```

Removes expired block entries and bans. Should be called periodically (e.g., on a timer matching `cleanup_interval_secs`).

---

## REST API Endpoints

When integrated with the Aegis-DB server, NexusShield exposes the following REST endpoints:

| # | Method | Endpoint | Description |
|---|--------|----------|-------------|
| 1 | `GET` | `/api/v1/shield/status` | Get shield engine status |
| 2 | `GET` | `/api/v1/shield/stats` | Get aggregated threat statistics |
| 3 | `GET` | `/api/v1/shield/events` | Get recent threat events |
| 4 | `GET` | `/api/v1/shield/events/:id` | Get a specific threat event by ID |
| 5 | `GET` | `/api/v1/shield/blocked` | List all blocked IPs |
| 6 | `POST` | `/api/v1/shield/block` | Manually block an IP |
| 7 | `DELETE` | `/api/v1/shield/block/:ip` | Unblock an IP |
| 8 | `GET` | `/api/v1/shield/allowlist` | List allowlisted IPs |
| 9 | `POST` | `/api/v1/shield/allowlist` | Add IP to allowlist |
| 10 | `DELETE` | `/api/v1/shield/allowlist/:ip` | Remove IP from allowlist |
| 11 | `GET` | `/api/v1/shield/reputation/:ip` | Get IP reputation details |
| 12 | `GET` | `/api/v1/shield/policy` | Get current security policy |
| 13 | `PUT` | `/api/v1/shield/policy` | Update security policy |

### Endpoint Examples

**Get shield status:**

```bash
curl http://localhost:9090/api/v1/shield/status
```

```json
{
  "enabled": true,
  "preset": "Moderate",
  "uptime_secs": 86400,
  "total_requests_analyzed": 152847,
  "total_threats_detected": 23,
  "active_bans": 2,
  "blocked_ips": 3
}
```

**Get threat statistics:**

```bash
curl http://localhost:9090/api/v1/shield/stats
```

```json
{
  "total_events": 47,
  "events_by_level": { "critical": 2, "high": 8, "medium": 15, "low": 12, "info": 10 },
  "events_by_type": { "SqlInjection": 18, "BruteForce": 12, "SuspiciousFingerprint": 9, "QueryAnomaly": 8 },
  "blocked_ips_count": 3,
  "active_bans": 2,
  "top_offending_ips": [["203.0.113.42", 12], ["198.51.100.7", 8]],
  "last_critical_event": 1711324800
}
```

**Get recent threat events:**

```bash
curl "http://localhost:9090/api/v1/shield/events?limit=5"
```

**Manually block an IP:**

```bash
curl -X POST http://localhost:9090/api/v1/shield/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "203.0.113.42", "reason": "manual block", "duration_secs": 7200}'
```

**Unblock an IP:**

```bash
curl -X DELETE http://localhost:9090/api/v1/shield/block/203.0.113.42
```

**Get IP reputation:**

```bash
curl http://localhost:9090/api/v1/shield/reputation/203.0.113.42
```

```json
{
  "ip": "203.0.113.42",
  "score": -47,
  "total_requests": 312,
  "failed_auths": 8,
  "blocked_requests": 5,
  "threat_events": 12,
  "first_seen": 1711238400,
  "last_seen": 1711324800,
  "banned_until": 1711332000,
  "ban_reason": "brute force detected"
}
```

**Add to allowlist:**

```bash
curl -X POST http://localhost:9090/api/v1/shield/allowlist \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.1"}'
```

**Get current policy:**

```bash
curl http://localhost:9090/api/v1/shield/policy
```

**Update policy:**

```bash
curl -X PUT http://localhost:9090/api/v1/shield/policy \
  -H "Content-Type: application/json" \
  -d '{
    "preset": "Strict",
    "sql_injection_enabled": true,
    "anomaly_detection_enabled": true,
    "ip_reputation_enabled": true,
    "fingerprinting_enabled": true,
    "auto_blocking_enabled": true,
    "custom_rules": [{
      "name": "admin_lockdown",
      "path_pattern": "/api/v1/admin",
      "max_score": 30,
      "action": "Blocked"
    }]
  }'
```

---

## Configuration Reference

### `ShieldConfig` Fields

| Field | Type | Default (Moderate) | Description |
|-------|------|--------------------|-------------|
| `enabled` | `bool` | `true` | Master switch for the shield |
| `preset` | `SecurityPreset` | `Moderate` | Active preset (Strict / Moderate / Permissive) |
| `sql_injection_enabled` | `bool` | `true` | Enable SQL injection pattern matching |
| `anomaly_detection_enabled` | `bool` | `true` | Enable query anomaly detection |
| `ip_reputation_enabled` | `bool` | `true` | Enable IP reputation tracking |
| `fingerprinting_enabled` | `bool` | `true` | Enable request fingerprinting |
| `auto_blocking_enabled` | `bool` | `true` | Enable automatic IP blocking |
| `auto_block_threshold` | `u32` | `80` | Threat score at which to auto-block |
| `default_ban_duration_secs` | `u64` | `3600` | Default ban duration in seconds |
| `max_ban_duration_secs` | `u64` | `86400` | Maximum ban duration in seconds |
| `escalation_multiplier` | `f64` | `2.0` | Ban duration multiplier for repeat offenders |
| `max_events_in_memory` | `usize` | `10000` | Maximum threat events in the rolling buffer |
| `anomaly_learning_period_secs` | `u64` | `3600` | Baseline learning period before anomaly detection activates |
| `anomaly_deviation_threshold` | `f64` | `3.0` | Query rate deviation multiplier to trigger anomaly |
| `cleanup_interval_secs` | `u64` | `300` | Interval for cleaning up expired bans/blocks |

### `RequestContext` Fields

| Field | Type | Description |
|-------|------|-------------|
| `source_ip` | `String` | Client IP address |
| `path` | `String` | HTTP request path |
| `method` | `String` | HTTP method (GET, POST, etc.) |
| `user_agent` | `Option<String>` | User-Agent header value |
| `auth_user` | `Option<String>` | Authenticated username, if any |
| `body_size` | `usize` | Request body size in bytes |
| `headers` | `HashMap<String, String>` | All request headers |

---

## Threat Event JSON Schema

Every threat event recorded in the feed has the following structure:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1711324800,
  "threat_type": "SqlInjection",
  "level": "High",
  "score": 85,
  "source_ip": "203.0.113.42",
  "description": "SQL injection patterns: union_select, or_always_true",
  "request_path": "/api/v1/query",
  "user_agent": "curl/7.81.0",
  "details": {},
  "action_taken": "Blocked"
}
```

**`threat_type` values:** `SqlInjection`, `QueryAnomaly`, `BruteForce`, `RateLimitAbuse`, `SuspiciousFingerprint`, `ReputationBlock`, `UnauthorizedAccess`, `PortScan`

**`level` values:** `Critical` (score >= 90), `High` (70-89), `Medium` (40-69), `Low` (20-39), `Info` (0-19)

**`action_taken` values:** `Allowed`, `RateLimited`, `Blocked`, `Banned`

---

## Module Reference

| Module | File | Description |
|--------|------|-------------|
| `lib` | `src/lib.rs` | ShieldEngine facade, RequestContext, ShieldVerdict, ShieldStatus |
| `sql_injection` | `src/sql_injection.rs` | 38-pattern SQL injection detector |
| `ip_reputation` | `src/ip_reputation.rs` | Per-IP reputation tracker with ban management |
| `fingerprint` | `src/fingerprint.rs` | User-agent classification and scanner detection |
| `anomaly` | `src/anomaly.rs` | Per-identifier query rate baseline and deviation detection |
| `blocker` | `src/blocker.rs` | Auto-blocker with timed bans and allowlist |
| `threat` | `src/threat.rs` | ThreatEvent, ThreatLevel, ThreatType, ThreatAction types |
| `config` | `src/config.rs` | ShieldConfig, SecurityPreset with 3 presets |
| `policy` | `src/policy.rs` | SecurityPolicy with custom rules and threshold evaluation |
| `feed` | `src/feed.rs` | Rolling threat event feed with aggregated statistics |
| `error` | `src/error.rs` | ShieldError types (Blocked, PolicyViolation, ConfigError) |

---

## Performance Characteristics

- **Pattern matching**: All 38 SQL injection regexes are compiled once at initialization. Matching is O(n * p) where n = query length and p = number of patterns.
- **Reputation lookups**: `parking_lot::RwLock<HashMap>` provides minimal contention. Read-heavy workloads benefit from the reader-writer lock.
- **Threat feed**: Ring buffer (VecDeque) with configurable max size (default 10,000 events). O(1) insertion, O(1) eviction.
- **Fingerprinting**: Pure string matching against known signatures. No allocations for classification; single allocation for the result.
- **Memory footprint**: Dominated by the threat event buffer. At 10,000 events with average 500 bytes per event, approximately 5MB.
- **No async**: All operations are synchronous. Locks are held for microseconds. Safe to call from async contexts without blocking the executor.

---

## Building from Source

### Prerequisites

- Rust 1.75 or later
- Cargo

### Build

```bash
cd /opt/NexusShield
cargo build --release
```

### Run Tests

```bash
cargo test
```

All 69 tests cover: SQL injection pattern matching (10 tests), IP reputation scoring and bans (7 tests), request fingerprinting (7 tests), anomaly detection baselines (4 tests), auto-blocker operations (6 tests), threat event types (4 tests), configuration presets (4 tests), security policy evaluation (4 tests), threat feed operations (5 tests), error types (4 tests), and full engine integration (14 tests).

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

```
Copyright 2024-2026 NexusShield Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
