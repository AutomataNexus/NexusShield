<p align="center">
  <img src="assets/NexusShield_logo.png" alt="NexusShield Logo" width="350" />
</p>

<h1 align="center">NexusShield</h1>

<p align="center">
  <strong>Adaptive zero-trust security gateway for developer environments. Pure Rust.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/Rust-1.75%2B-orange.svg" alt="Rust 1.75+" />
  <img src="https://img.shields.io/badge/version-0.2.2-green.svg" alt="v0.2.2" />
  <img src="https://img.shields.io/badge/LOC-5182-informational.svg" alt="5182 LOC" />
  <img src="https://img.shields.io/badge/modules-13-blueviolet.svg" alt="13 modules" />
</p>

---

## Overview

NexusShield is a reverse-proxy security gateway that protects developer services running on laptops, desktops, and servers. It sits between incoming traffic and your upstream application, inspecting every request through a layered defense pipeline before forwarding clean traffic. When a threat is detected, NexusShield scores it, classifies it, and takes action -- blocking, rate-limiting, or warning -- all before the request ever reaches your service.

Unlike regex-based web application firewalls, NexusShield performs **AST-level SQL analysis** using the `sqlparser` crate, parsing queries into a full abstract syntax tree and walking the tree to detect injection patterns semantically. This eliminates false positives from string-matching heuristics and catches attacks that regex cannot see, such as tautology conditions buried inside nested subqueries, CHAR() encoding bypass, and hex-encoded payloads combined with SQL keywords.

NexusShield also uses **multi-signal threat scoring** to evaluate requests holistically. Four independent signals -- request fingerprinting (30%), rate pressure (25%), behavioral anomaly (30%), and recent violation history (15%) -- are combined into a single 0.0-1.0 threat score. The score determines whether a request is allowed, warned, or blocked. Adaptive rate limiting with 5-level escalation (None, Warn, Throttle, Block, Ban) automatically increases restrictions on repeat offenders and relaxes them over time through violation decay. Every security event is recorded in a tamper-evident SHA-256 hash-chained audit log where any modification or deletion breaks the chain and is immediately detectable.

---

## Architecture

```
                          Client Request
                               |
                               v
                      +------------------+
                      |   NexusShield    |
                      |   (port 8080)    |
                      +------------------+
                               |
              +----------------+----------------+
              |                |                |
              v                v                v
     +--------------+  +--------------+  +--------------+
     | Rate Governor|  | Fingerprint  |  | SQL Firewall |
     | (token       |  | (header      |  | (AST-level   |
     |  bucket +    |  |  analysis +  |  |  sqlparser   |
     |  escalation) |  |  bot detect) |  |  analysis)   |
     +--------------+  +--------------+  +--------------+
              |                |                |
              v                v                v
     +--------------+  +--------------+  +--------------+
     | SSRF Guard   |  | Email Guard  |  | Data         |
     | (IP/DNS/port |  | (CRLF, rate, |  | Quarantine   |
     |  validation) |  |  injection)  |  | (CSV/JSON)   |
     +--------------+  +--------------+  +--------------+
              |                |                |
              +----------------+----------------+
                               |
                               v
                      +------------------+
                      | Threat Score     |
                      | Engine           |
                      | (multi-signal    |
                      |  0.0 - 1.0)      |
                      +------------------+
                               |
                     +---------+---------+
                     |         |         |
                     v         v         v
                  ALLOW      WARN      BLOCK
                     |                   |
                     v                   v
              +--------------+   +--------------+
              | Audit Chain  |   | Audit Chain  |
              | (record)     |   | (record)     |
              +--------------+   +--------------+
                     |
                     v
              +--------------+
              | Upstream     |
              | Service      |
              | (port 3000)  |
              +--------------+
```

### Request Flow (Middleware Pipeline)

```
Client --> NexusShield Gateway
              |
              +--> [1] Rate Governor    -- token bucket per IP, escalation check
              +--> [2] Fingerprinter    -- header analysis, bot/tool detection
              +--> [3] Behavioral Score -- request rate, error rate, burst detection
              +--> [4] Violation Check  -- recent audit chain events
              +--> [5] Threat Score     -- weighted combination of all signals
              |         |
              |    score < 0.4 --> ALLOW --> forward to upstream
              |    score 0.4-0.7 --> WARN --> log + forward to upstream
              |    score >= 0.7 --> BLOCK --> 403 Forbidden
              |
              +--> [6] Response Tracking -- record errors for behavioral analysis
```

---

## Features

### 1. SQL Firewall (AST-Level Analysis)

**File:** `src/sql_firewall.rs`

The SQL firewall parses every query into an Abstract Syntax Tree using the `sqlparser` crate's `GenericDialect` parser. It then walks the AST recursively, inspecting every node for injection patterns. This is fundamentally different from regex-based detection because it understands SQL structure.

**Detection categories:**

| Category | Violation Type | Risk Score | Description |
|----------|---------------|------------|-------------|
| UNION injection | `UnionInjection` | +0.6 | Detects `UNION SELECT` operations in `SetOperation` AST nodes |
| Stacked queries | `StackedQueries` | +0.8 | Multiple statements separated by semicolons |
| Dangerous functions | `DangerousFunction` | +0.8 | 30+ built-in dangerous functions detected in `Function` AST nodes |
| System table access | `SystemTableAccess` | +0.7 | Queries against `information_schema`, `pg_catalog`, `sqlite_master`, etc. |
| Tautology detection | `Tautology` | +0.5 | `1=1`, `'a'='a'`, `OR TRUE` detected via `BinaryOp` equality comparison |
| INTO OUTFILE | `IntoOutfile` | +1.0 | `SELECT INTO` / `INTO OUTFILE` / `INTO DUMPFILE` |
| Comment injection | `CommentInjection` | +0.3 | `/* */` block comments and `--` line comments (outside string literals) |
| Hex-encoded payloads | `HexEncodedPayload` | +0.4 | `0x` hex values combined with SQL keywords |
| CHAR() bypass | `CharEncoding` | +0.3 | `CHAR()`, `CHR()`, `CONCAT()` combined with SQL keywords |
| Non-SELECT statements | `NonSelectStatement` | +1.0 | INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE, GRANT, REVOKE |
| Excessive nesting | `ExcessiveNesting` | +0.4 | Subquery depth exceeds configurable limit (default: 3) |
| Query too long | `QueryTooLong` | +0.5 | Exceeds `max_query_length` (default: 10,000 bytes) |
| Unparseable SQL | `Unparseable` | 1.0 | Query fails to parse (highly suspicious) |

**Built-in dangerous functions list (30+):**

- **MySQL file ops:** `load_file`, `into_outfile`, `into_dumpfile`
- **PostgreSQL file ops:** `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_stat_file`, `lo_import`, `lo_export`, `pg_file_write`
- **PostgreSQL command exec:** `pg_execute_server_program`
- **SQL Server command exec:** `xp_cmdshell`, `sp_oacreate`, `sp_oamethod`
- **MySQL UDF:** `sys_exec`, `sys_eval`
- **Time-based blind:** `sleep`, `benchmark`, `waitfor`, `pg_sleep`
- **XML injection:** `extractvalue`, `updatexml`
- **SQLite:** `load_extension`

**System schemas/catalogs blocked:**

`information_schema`, `pg_catalog`, `pg_temp`, `pg_toast`, `sys`, `mysql`, `performance_schema`, `sqlite_master`, `sqlite_schema`, `sqlite_temp_master`, `master`, `tempdb`, `msdb`, `model`

**AST walk covers:**
- `SELECT` projection expressions (function calls in select list)
- `FROM` clauses (table names, derived tables, nested joins)
- `WHERE` clauses (tautology detection + dangerous functions)
- `HAVING` clauses
- `CASE` / `BETWEEN` / `EXISTS` / `IN (subquery)` expressions
- `CAST` expressions
- `BinaryOp` / `UnaryOp` / `Nested` expression recursion
- Subqueries at any depth

**Configuration (`SqlFirewallConfig`):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow_comments` | `bool` | `false` | Allow SQL comments in queries |
| `max_query_length` | `usize` | `10,000` | Maximum query length in bytes |
| `max_subquery_depth` | `u32` | `3` | Maximum nesting depth for subqueries |
| `blocked_functions` | `Vec<String>` | `[]` | Additional function names to block |
| `blocked_schemas` | `Vec<String>` | `[]` | Additional schema names to block |

---

### 2. SSRF Guard

**File:** `src/ssrf_guard.rs`

Validates URLs and IP addresses to prevent Server-Side Request Forgery attacks. Blocks access to internal networks, cloud metadata endpoints, and dangerous ports.

**IP ranges blocked:**

| Range | Description |
|-------|-------------|
| `127.0.0.0/8` | Loopback addresses |
| `10.0.0.0/8` | Private network (Class A) |
| `172.16.0.0/12` | Private network (Class B) |
| `192.168.0.0/16` | Private network (Class C) |
| `169.254.0.0/16` | Link-local (including cloud metadata at `169.254.169.254`) |
| `0.0.0.0` | Unspecified address |
| `255.255.255.255` | Broadcast address |
| `::1` | IPv6 loopback |
| `::` | IPv6 unspecified |
| `fe80::/10` | IPv6 link-local |
| `::ffff:x.x.x.x` | IPv4-mapped IPv6 (checks the embedded IPv4) |

**Hostname blocking:**

- `localhost`, `localhost.localdomain`, `*.localhost`
- Cloud metadata: `metadata.google.internal`, `metadata.google`, `instance-data`
- Internal TLDs: `.internal`, `.local`, `.corp`, `.home`, `.lan`

**Scheme validation:**

Only `http` and `https` are allowed by default. Blocks `file://`, `ftp://`, `gopher://`, etc.

**Blocked ports (common internal services):**

`22` (SSH), `23` (Telnet), `25` (SMTP), `53` (DNS), `111` (RPC), `135` (MSRPC), `139` (NetBIOS), `445` (SMB), `514` (Syslog), `873` (Rsync), `2049` (NFS), `3306` (MySQL), `5432` (PostgreSQL), `6379`/`6380` (Redis), `9200`/`9300` (Elasticsearch), `11211` (Memcached), `27017`/`27018` (MongoDB), `50070` (HDFS)

**Allowlist/Blocklist:**

- Explicit `allowlist` bypasses all checks for trusted hosts/IPs
- Explicit `blocklist` is checked before allowlist

**Configuration (`SsrfConfig`):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `block_private_ips` | `bool` | `true` | Block RFC 1918 private ranges |
| `block_loopback` | `bool` | `true` | Block 127.0.0.0/8 and ::1 |
| `block_link_local` | `bool` | `true` | Block 169.254.0.0/16 |
| `block_metadata_endpoints` | `bool` | `true` | Block cloud metadata endpoints |
| `allowed_schemes` | `Vec<String>` | `["http", "https"]` | Allowed URL schemes |
| `allowlist` | `HashSet<String>` | `{}` | Hosts/IPs that bypass all checks |
| `blocklist` | `HashSet<String>` | `{}` | Hosts/IPs always blocked |
| `blocked_ports` | `Vec<u16>` | (22 ports) | Blocked port numbers |

---

### 3. Email Guard

**File:** `src/email_guard.rs`

Protects email-sending endpoints from header injection, bombing attacks, HTML/template injection, and address abuse.

**Detection capabilities:**

| Attack Vector | Detection Method |
|--------------|-----------------|
| CRLF header injection | Scans for `\r` and `\n` in addresses, subjects, names |
| Email bombing | Per-recipient rate limiting (default: 5 emails per recipient per 5 minutes) |
| HTML/script injection | Detects 23+ patterns in template content (see below) |
| Encoded payloads | Base64-encoded attack strings, Unicode BiDi overrides, zero-width characters |
| Disposable domains | Blocks 10 known disposable email services + localhost/internal domains |
| IP address domains | Blocks `[127.0.0.1]` style email addresses |
| Content length limits | Per-field max lengths (subject: 200, body: 10,000, name: 100) |
| Null byte injection | Blocks null bytes in addresses and headers |
| Excessive recipients | Configurable max recipients per email (default: 10) |

**HTML injection patterns blocked in template content:**

`<script`, `</script`, `javascript:`, `vbscript:`, `data:text/html`, `onerror=`, `onload=`, `onclick=`, `onmouseover=`, `onfocus=`, `onblur=`, `eval(`, `expression(`, `url(data:`, `<iframe`, `<object`, `<embed`, `<form`, `<input`, `<meta`, `<link`, `<base`, `<svg`, `<!--`, `srcdoc=`

**Encoded attack detection:**

- Base64-encoded `<script>`, `javascript:`, `<svg`, `>alert(`
- Unicode right-to-left override (`U+202E`), right-to-left mark (`U+200F`), left-to-right mark (`U+200E`)
- Zero-width characters: `U+200B` (zero-width space), `U+FEFF` (BOM), `U+200C` (zero-width non-joiner), `U+200D` (zero-width joiner)

**Blocked email domains:**

`localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]`, `internal`, `local`, `corp`, `mailinator.com`, `guerrillamail.com`, `tempmail.com`, `throwaway.email`, `yopmail.com`, `sharklasers.com`, `guerrillamailblock.com`, `grr.la`, `dispostable.com`, `trashmail.com`

**HTML escaping:**

The `html_escape()` function escapes `&`, `<`, `>`, `"`, `'`, `/` and strips null bytes for safe template interpolation.

**Configuration (`EmailGuardConfig`):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_per_recipient` | `u32` | `5` | Max emails per recipient per window |
| `rate_window_secs` | `u64` | `300` | Rate limiting window (5 minutes) |
| `max_recipients` | `u32` | `10` | Max recipients per single email |
| `max_subject_len` | `usize` | `200` | Maximum subject length |
| `max_body_len` | `usize` | `10,000` | Maximum body/message field length |
| `max_name_len` | `usize` | `100` | Maximum name field length |
| `blocked_domains` | `Vec<String>` | (17 domains) | Blocked email domains |

---

### 4. Behavioral Fingerprinting

**File:** `src/fingerprint.rs`

Extracts features from HTTP request headers to build a behavioral fingerprint. Automated attack tools have distinctive patterns: missing standard headers, unusual header ordering, rapid request cadence, and known tool user-agent strings.

**Per-request signals extracted:**

| Signal | Description |
|--------|-------------|
| `has_user_agent` | Whether `User-Agent` header is present |
| `has_accept` | Whether `Accept` header is present |
| `has_accept_language` | Whether `Accept-Language` header is present |
| `has_accept_encoding` | Whether `Accept-Encoding` header is present |
| `has_referer` | Whether `Referer` header is present |
| `header_count` | Total number of headers |
| `header_order_hash` | SHA-256 hash of header names in order (first 16 hex chars) |
| `user_agent` | User-Agent string (truncated to 200 chars) |

**Anomaly score calculation:**

| Condition | Score Added |
|-----------|-----------|
| Missing `User-Agent` header | +0.3 |
| Missing `Accept` header | +0.1 |
| Missing `Accept-Language` header | +0.1 |
| Missing `Accept-Encoding` header | +0.05 |
| Fewer than 3 headers | +0.25 |
| More than 30 headers (proxy chain / header stuffing) | +0.15 |
| Known attack tool user-agent | +0.4 |
| Empty user-agent string | +0.2 |

**Known attack tools detected (14 signatures):**

`sqlmap`, `nikto`, `nmap`, `masscan`, `zgrab`, `gobuster`, `dirbuster`, `wfuzz`, `ffuf`, `nuclei`, `httpx`, `python-requests`, `go-http-client`, `java/`

**Behavioral tracking (per-IP over time):**

| Condition | Score Added |
|-----------|-----------|
| Request rate > 20 RPS | +0.3 |
| Request rate > 100 RPS | +0.3 (additional) |
| Error rate > 50% (after 5+ requests) | +0.3 |
| 50+ requests in < 5 seconds (burst) | +0.4 |
| 20+ distinct endpoints in < 30 seconds (scanning) | +0.2 |
| 5+ distinct source types (enumeration) | +0.2 |

**Fingerprint hash:** SHA-256 of `ua + header_count + header_order_hash + accept + lang` (first 32 hex chars). Stable across identical request profiles.

---

### 5. Adaptive Rate Limiting

**File:** `src/rate_governor.rs`

Per-IP token bucket rate limiter with automatic escalation. Well-behaved clients get full capacity; repeat violators get progressively restricted up to temporary bans.

**Token bucket algorithm:**

- Each IP gets a bucket with `burst_capacity` tokens (default: 100)
- Tokens refill at `requests_per_second` rate (default: 50/s)
- Each request consumes 1 token
- When the bucket is empty, the request is denied and a violation is recorded

**5-level escalation:**

| Level | Violations Required | Behavior |
|-------|-------------------|----------|
| **None** | 0 | Normal operation |
| **Warn** | 3+ | Allowed but logged |
| **Throttle** | 8+ | Only allowed if bucket > 50% full |
| **Block** | 15+ | All requests denied |
| **Ban** | 30+ | All requests denied for `ban_duration_secs` (default: 300s) |

**Violation decay:** Every `violation_decay_secs` (default: 60s) without a new violation, one violation is removed. This allows clients to recover from temporary spikes.

**Manual controls:**

- `ban_ip(ip)` -- Manually ban an IP for the configured ban duration
- `unban_ip(ip)` -- Remove ban and reset violations to 0
- `peek_escalation(ip)` -- Check escalation level without consuming a token

**Ban expiry:** Bans automatically expire after `ban_duration_secs`. The ban flag is cleared on the next request check after expiry.

**Stale pruning:** Background task prunes IP state for clients not seen in 600 seconds (runs every 60 seconds).

**Configuration (`RateConfig`):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `requests_per_second` | `f64` | `50.0` | Token refill rate per IP |
| `burst_capacity` | `f64` | `100.0` | Maximum tokens (burst allowance) |
| `warn_after` | `u32` | `3` | Violations before warn escalation |
| `throttle_after` | `u32` | `8` | Violations before throttle escalation |
| `block_after` | `u32` | `15` | Violations before block escalation |
| `ban_after` | `u32` | `30` | Violations before ban escalation |
| `ban_duration_secs` | `u64` | `300` | Ban duration (5 minutes) |
| `violation_decay_secs` | `u64` | `60` | Seconds between violation decay |

---

### 6. Data Quarantine

**File:** `src/quarantine.rs`

Validates imported data (CSV and JSON) for malicious payloads before they enter the system.

**CSV validation checks:**

| Check | Description |
|-------|-------------|
| Formula injection | Cells starting with `=`, `@`, `\t`, `\r` are blocked. `+` and `-` are only blocked if not followed by a valid number. |
| Embedded scripts | `<script`, `javascript:`, `onerror=`, `onload=`, `onclick=`, `vbscript:`, `data:text/html` |
| Null bytes | Any `\0` character in content |
| Size limit | Total byte size (default: 500 MB) |
| Row limit | Maximum rows (default: 5,000,000) |
| Column limit | Maximum columns from header (default: 500) |
| Repetitive patterns | Content with < 5 unique characters in first 1000 bytes and > 10KB total (padding attack) |

**JSON validation:** Size check + null byte detection + embedded script detection.

**Performance:** Only scans the first 10,000 rows of CSV data (attackers typically inject early in the payload).

**Configuration (`QuarantineConfig`):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_rows` | `usize` | `5,000,000` | Maximum rows allowed |
| `max_size_bytes` | `usize` | `524,288,000` | Maximum total size (500 MB) |
| `max_columns` | `usize` | `500` | Maximum columns allowed |
| `check_formula_injection` | `bool` | `true` | Enable formula injection checks |
| `check_embedded_scripts` | `bool` | `true` | Enable embedded script checks |

---

### 7. Credential Vault

**File:** `src/credential_vault.rs`

Encrypts sensitive configuration fields with AES-256-GCM before storage. Uses per-user key derivation so each user's credentials are isolated.

**Key hierarchy:**

```
NEXUS_VAULT_KEY (env var, 32+ chars)
  |
  +-- SHA-256(master_key + ":user:" + user_id) --> per-user 256-bit key
        |
        +-- AES-256-GCM(key, random_12_byte_nonce, plaintext) --> ciphertext
```

**Encrypted value format:** `vault:v1:<base64(nonce + ciphertext)>`

**Sensitive fields automatically detected:**

`api_key`, `token`, `connection_string`, `password`, `secret`, `api_secret`, `access_key`, `secret_key`

**Operations:**

| Function | Description |
|----------|-------------|
| `encrypt_source_config(config, user_id)` | Encrypts all sensitive fields in a JSON object |
| `decrypt_source_config(config, user_id)` | Decrypts all sensitive fields |
| `redact_source_config(config)` | Masks secrets for API display (first 4 + last 2 chars visible) |
| `is_encrypted(value)` | Checks if a value has the `vault:v1:` prefix |

**Graceful degradation:** If `NEXUS_VAULT_KEY` is not set, credentials are stored unencrypted (for development environments). A warning is logged.

**Safety guarantees:**
- Already-encrypted fields are not re-encrypted (idempotent)
- Empty fields are not encrypted
- Non-sensitive fields (like `database`, `collection`) pass through unchanged
- Wrong user key fails decryption (per-user isolation)

---

### 8. Tamper-Evident Audit Chain

**File:** `src/audit_chain.rs`

SHA-256 hash-chained append-only security event log. Each event includes the hash of the previous event, forming a chain. If any event is modified, inserted, or deleted, the chain breaks.

**Hash computation:**

```
hash = SHA-256(id | timestamp | event_type | source_ip | details | threat_score | previous_hash)
```

The first event in the chain links to the genesis hash `"genesis"`.

**Security event types:**

| Event Type | Description |
|------------|-------------|
| `RequestAllowed` | Request passed all checks |
| `RequestBlocked` | Request blocked by threat score |
| `RateLimitHit` | Request denied by rate governor |
| `SqlInjectionAttempt` | SQL firewall detected injection |
| `SsrfAttempt` | SSRF guard blocked a URL/IP |
| `PathTraversalAttempt` | Path traversal detected |
| `MaliciousPayload` | Malicious content detected |
| `DataQuarantined` | Imported data failed quarantine |
| `AuthFailure` | Authentication failure |
| `BanIssued` | IP ban applied |
| `BanLifted` | IP ban removed |
| `ChainVerified` | Chain integrity verified |

**Chain verification:** `verify_chain()` recomputes every hash from event data and verifies the chain links. Returns the index of the first broken link if tampering is detected.

**Pruning:** When the chain exceeds `audit_max_events` (default: 100,000), oldest events are drained from the head.

**Query methods:**

| Method | Description |
|--------|-------------|
| `record(type, ip, details, score)` | Append a new event |
| `verify_chain()` | Full integrity verification |
| `recent(count)` | Get N most recent events (newest first) |
| `count_since(type, timestamp)` | Count events of a type since a time |
| `export_json()` | Export entire chain as JSON |
| `len()` / `is_empty()` | Chain size |

---

### 9. Input Sanitizer

**File:** `src/sanitizer.rs`

Validates connection strings, file paths, and sanitizes error messages to prevent information leakage.

**Connection string validation:**

| Check | Blocked Content |
|-------|----------------|
| Shell metacharacters | `` ` ``, `$`, `|`, `&`, `;`, `\n`, `\r`, `\0` |
| Command substitution | `$(...)`, `${...}` |
| Dangerous URL parameters | `sslrootcert=/etc`, `sslcert=/proc`, `init_command=`, `options=-c`, `application_name=';` |
| URL format | Must be parseable as a valid URL |

**File path validation:**

| Check | Description |
|-------|-------------|
| Path traversal | Blocks `..` in any path |
| Null bytes | Blocks `\0` |
| Sensitive directories | `/etc/`, `/proc/`, `/sys/`, `/dev/`, `/root/`, `/boot/`, `/var/run/`, `/var/log/`, `/tmp/.`, `/home/`, `C:\Windows\`, `C:\Users\` |
| Sensitive filenames | `passwd`, `shadow`, `id_rsa`, `id_ed25519`, `authorized_keys`, `.ssh`, `.env`, `.git`, `credentials`, `secret`, `.bash_history`, `.pgpass`, `.my.cnf`, `wp-config.php` |
| Relative paths | Must be absolute (starts with `/` or drive letter) |

**Error message sanitization:**

| Redaction | Description |
|-----------|-------------|
| Internal paths | Unix paths with 2+ `/` separators replaced with `[path redacted]` |
| Internal IPs | `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x` replaced with `[internal-ip]` |
| Stack traces | Lines starting with `at `, `thread '...panicked at`, `stack backtrace:` removed |
| Length limit | Truncated to 500 characters |

**Header sanitization:** `sanitize_header_value()` strips `\r`, `\n`, and `\0` to prevent header injection.

---

### 10. Multi-Signal Threat Scoring

**File:** `src/threat_score.rs`

Combines four independent signals into a single 0.0-1.0 threat score using weighted averaging.

**Signal weights:**

| Signal | Weight | Source |
|--------|--------|--------|
| Fingerprint anomaly | 30% | `fingerprint.rs` -- header analysis + bot detection |
| Rate pressure | 25% | `rate_governor.rs` -- escalation level mapped to 0.0-1.0 |
| Behavioral anomaly | 30% | `fingerprint.rs` -- request rate, error rate, burst detection |
| Recent violations | 15% | `audit_chain.rs` -- any blocked requests in last 5 minutes |

**Rate pressure mapping:**

| Escalation Level | Score |
|-----------------|-------|
| None | 0.0 |
| Warn | 0.3 |
| Throttle | 0.6 |
| Block | 0.9 |
| Ban | 1.0 |

**Score formula:**

```
score = min(1.0,
    fingerprint_anomaly * 0.30
  + rate_pressure * 0.25
  + behavioral_anomaly * 0.30
  + (recent_violations ? 1.0 : 0.0) * 0.15
)
```

**Action thresholds:**

| Score Range | Action | HTTP Response |
|-------------|--------|---------------|
| 0.0 - 0.39 | **Allow** | Request forwarded to upstream |
| 0.4 - 0.69 | **Warn** | Request forwarded, warning logged to audit chain |
| 0.7 - 1.0 | **Block** | 403 Forbidden, event recorded in audit chain |

---

## Quick Start

### Run as a Reverse Proxy

Protect a local service running on port 3000:

```bash
nexus-shield --port 8080 --upstream http://localhost:3000
```

All traffic to port 8080 is inspected by the full NexusShield pipeline before being forwarded to port 3000.

### Run in Standalone Mode

Run NexusShield without an upstream target (for testing or as an inspection-only gateway):

```bash
nexus-shield --port 8080 --standalone
```

In standalone mode, all requests pass through the security pipeline and receive "NexusShield: request inspected and allowed" on the fallback handler.

### Integrate as Axum Middleware

Use NexusShield as a middleware layer in your own Axum application:

```rust
use std::sync::Arc;
use axum::{Router, Extension, middleware};
use nexus_shield::{Shield, ShieldConfig, shield_middleware};

let config = ShieldConfig::default();
let shield = Arc::new(Shield::new(config));

let app = Router::new()
    .route("/api/query", post(query_handler))
    .layer(middleware::from_fn(shield_middleware))
    .layer(Extension(shield.clone()));
```

### Validate SQL Directly

```rust
let shield = Shield::new(ShieldConfig::default());

// Safe query -- passes
shield.validate_sql("SELECT * FROM sensors WHERE id = 1").unwrap();

// Injection attempt -- blocked
let err = shield.validate_sql("SELECT * FROM users UNION SELECT password FROM admin");
assert!(err.is_err());
```

### Validate URLs for SSRF

```rust
// Public URL -- passes
shield.validate_url("https://api.example.com/data").unwrap();

// Cloud metadata -- blocked
let err = shield.validate_url("http://169.254.169.254/latest/meta-data/");
assert!(err.is_err());
```

---

## CLI Reference

```
nexus-shield [OPTIONS]

Options:
  -p, --port <PORT>                  Port to listen on [default: 8080]
  -u, --upstream <URL>               Upstream target to proxy to (e.g., http://localhost:3000)
  -c, --config <PATH>                Config file path [default: /etc/nexus-shield/config.toml]
      --block-threshold <FLOAT>      Score threshold for blocking (0.0-1.0) [default: 0.7]
      --warn-threshold <FLOAT>       Score threshold for warnings (0.0-1.0) [default: 0.4]
      --rps <FLOAT>                  Requests per second per IP [default: 50]
      --standalone                   Run without upstream (inspection-only mode) [default: false]
  -h, --help                         Print help
```

**Examples:**

```bash
# Protect a Node.js app
nexus-shield --port 8080 --upstream http://localhost:3000

# Strict mode
nexus-shield --port 8080 --upstream http://localhost:3000 \
    --block-threshold 0.5 --warn-threshold 0.2 --rps 20

# Permissive mode for development
nexus-shield --port 8080 --upstream http://localhost:3000 \
    --block-threshold 0.9 --warn-threshold 0.6 --rps 200

# Standalone inspection mode
nexus-shield --port 8080 --standalone
```

---

## API Endpoints

NexusShield exposes 4 status endpoints alongside the proxy. These are available in both proxy and standalone modes.

### `GET /health`

Health check endpoint.

```bash
curl http://localhost:8080/health
```

```
NexusShield OK
```

### `GET /status`

Returns gateway configuration, active modules, and audit chain integrity.

```bash
curl http://localhost:8080/status
```

```json
{
  "service": "NexusShield",
  "version": "0.1.0",
  "status": "active",
  "config": {
    "block_threshold": 0.7,
    "warn_threshold": 0.4,
    "rate_rps": 50.0,
    "rate_burst": 100.0
  },
  "audit_chain": {
    "total_events": 1247,
    "chain_valid": true
  },
  "modules": [
    "sql_firewall",
    "ssrf_guard",
    "rate_governor",
    "fingerprint",
    "quarantine",
    "email_guard",
    "credential_vault",
    "audit_chain",
    "sanitizer",
    "threat_score"
  ]
}
```

### `GET /audit`

Returns the 50 most recent security events (newest first) with chain integrity status.

```bash
curl http://localhost:8080/audit
```

```json
{
  "recent_events": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "timestamp": "2026-03-24T10:30:00Z",
      "event_type": "RequestBlocked",
      "source_ip": "203.0.113.42",
      "details": "score=0.823, fingerprint=0.700, rate=0.900, behavioral=0.600",
      "threat_score": 0.823
    }
  ],
  "total": 1247,
  "chain_valid": true
}
```

### `GET /stats`

Returns threat statistics for the last 5 minutes and last hour.

```bash
curl http://localhost:8080/stats
```

```json
{
  "last_5min": {
    "blocked": 3,
    "rate_limited": 12,
    "sql_injection": 1,
    "ssrf": 0
  },
  "last_hour": {
    "blocked": 18,
    "rate_limited": 47,
    "sql_injection": 5,
    "ssrf": 2
  },
  "total_audit_events": 1247
}
```

---

## Configuration Reference

### `ShieldConfig` (Top-Level)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `block_threshold` | `f64` | `0.7` | Threat score at which requests are blocked |
| `warn_threshold` | `f64` | `0.4` | Threat score at which warnings are logged |
| `sql` | `SqlFirewallConfig` | (see below) | SQL firewall settings |
| `ssrf` | `SsrfConfig` | (see below) | SSRF guard settings |
| `rate` | `RateConfig` | (see below) | Rate limiting settings |
| `quarantine` | `QuarantineConfig` | (see below) | Data quarantine settings |
| `email` | `EmailGuardConfig` | (see below) | Email guard settings |
| `audit_max_events` | `usize` | `100,000` | Maximum events in the audit chain before pruning |

### `SqlFirewallConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow_comments` | `bool` | `false` | Allow SQL comments (`--` and `/* */`) |
| `max_query_length` | `usize` | `10,000` | Maximum query length in bytes |
| `max_subquery_depth` | `u32` | `3` | Maximum subquery nesting depth |
| `blocked_functions` | `Vec<String>` | `[]` | Additional dangerous function names |
| `blocked_schemas` | `Vec<String>` | `[]` | Additional system schema names |

### `SsrfConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `block_private_ips` | `bool` | `true` | Block RFC 1918 private IP ranges |
| `block_loopback` | `bool` | `true` | Block loopback addresses |
| `block_link_local` | `bool` | `true` | Block link-local addresses (169.254.x.x) |
| `block_metadata_endpoints` | `bool` | `true` | Block cloud metadata endpoints |
| `allowed_schemes` | `Vec<String>` | `["http", "https"]` | Allowed URL schemes |
| `allowlist` | `HashSet<String>` | `{}` | Hosts/IPs bypassing all checks |
| `blocklist` | `HashSet<String>` | `{}` | Hosts/IPs always blocked |
| `blocked_ports` | `Vec<u16>` | 22 ports | Dangerous port numbers |

### `RateConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `requests_per_second` | `f64` | `50.0` | Token refill rate per IP |
| `burst_capacity` | `f64` | `100.0` | Maximum tokens (burst allowance) |
| `warn_after` | `u32` | `3` | Violations to trigger warn |
| `throttle_after` | `u32` | `8` | Violations to trigger throttle |
| `block_after` | `u32` | `15` | Violations to trigger block |
| `ban_after` | `u32` | `30` | Violations to trigger ban |
| `ban_duration_secs` | `u64` | `300` | Ban duration in seconds |
| `violation_decay_secs` | `u64` | `60` | Seconds between violation decay |

### `QuarantineConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_rows` | `usize` | `5,000,000` | Maximum CSV rows |
| `max_size_bytes` | `usize` | `524,288,000` | Maximum data size (500 MB) |
| `max_columns` | `usize` | `500` | Maximum CSV columns |
| `check_formula_injection` | `bool` | `true` | Check for `=`, `@`, `+`, `-` prefixes |
| `check_embedded_scripts` | `bool` | `true` | Check for `<script>`, `javascript:`, etc. |

### `EmailGuardConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_per_recipient` | `u32` | `5` | Max emails per recipient per window |
| `rate_window_secs` | `u64` | `300` | Rate limiting window (5 minutes) |
| `max_recipients` | `u32` | `10` | Max recipients per email |
| `max_subject_len` | `usize` | `200` | Max subject length |
| `max_body_len` | `usize` | `10,000` | Max body length |
| `max_name_len` | `usize` | `100` | Max name field length |
| `blocked_domains` | `Vec<String>` | 17 domains | Blocked email domains |

---

## Security Presets

NexusShield uses two primary thresholds that control its response posture:

| Preset | `warn_threshold` | `block_threshold` | Use Case |
|--------|-----------------|-------------------|----------|
| **Strict** | 0.2 | 0.5 | Production-facing endpoints |
| **Default** | 0.4 | 0.7 | Developer services, internal tools |
| **Permissive** | 0.6 | 0.9 | Development / testing |

Set thresholds via CLI flags:

```bash
# Strict
nexus-shield --warn-threshold 0.2 --block-threshold 0.5 --upstream http://localhost:3000

# Permissive
nexus-shield --warn-threshold 0.6 --block-threshold 0.9 --upstream http://localhost:3000
```

---

## Module Reference

| # | Module | File | Lines | Description |
|---|--------|------|-------|-------------|
| 1 | `lib` | `src/lib.rs` | 712 | Core `Shield` struct, Axum middleware, error types, convenience methods |
| 2 | `sql_firewall` | `src/sql_firewall.rs` | 609 | AST-level SQL injection detection via `sqlparser` |
| 3 | `ssrf_guard` | `src/ssrf_guard.rs` | 282 | SSRF prevention with IP/DNS/port/scheme validation |
| 4 | `email_guard` | `src/email_guard.rs` | 635 | Email endpoint protection: CRLF, bombing, injection |
| 5 | `fingerprint` | `src/fingerprint.rs` | 543 | HTTP request fingerprinting and behavioral analysis |
| 6 | `rate_governor` | `src/rate_governor.rs` | 466 | Adaptive per-IP rate limiting with 5-level escalation |
| 7 | `quarantine` | `src/quarantine.rs` | 249 | CSV/JSON data validation for malicious payloads |
| 8 | `credential_vault` | `src/credential_vault.rs` | 424 | AES-256-GCM credential encryption with per-user keys |
| 9 | `audit_chain` | `src/audit_chain.rs` | 323 | SHA-256 hash-chained tamper-evident event log |
| 10 | `sanitizer` | `src/sanitizer.rs` | 293 | Connection string, path, and error message sanitization |
| 11 | `threat_score` | `src/threat_score.rs` | 180 | Multi-signal weighted threat scoring engine |
| 12 | `config` | `src/config.rs` | 174 | Configuration structs with defaults for all modules |
| 13 | `main` | `src/bin/main.rs` | 298 | Binary entry point, CLI args, Axum server, reverse proxy |
| | **Total** | | **5,188** | |

---

## Deployment Models

### Developer Laptop

Protect local services (Node.js, Python, Go dev servers) from attacks when exposed on a network:

```bash
# Protect a local API server
nexus-shield --port 8080 --upstream http://localhost:3000
```

All requests to `localhost:8080` are inspected before reaching your dev server on port 3000.

### CI/CD Pipeline

Add NexusShield as a validation step to inspect payloads before they reach staging/production:

```yaml
# GitHub Actions example
- name: Security scan
  run: |
    cargo install nexus-shield
    nexus-shield --standalone --port 8080 &
    # Run integration tests against the shielded endpoint
    curl -X POST http://localhost:8080/api/query \
      -d '{"sql": "SELECT * FROM users WHERE id = 1"}'
```

### Production Gateway

Run NexusShield as a reverse proxy in front of your production services:

```bash
nexus-shield \
    --port 443 \
    --upstream http://internal-service:3000 \
    --block-threshold 0.5 \
    --warn-threshold 0.2 \
    --rps 100
```

### PM2 Deployment

```javascript
module.exports = {
  apps: [{
    name: 'nexus-shield',
    script: '/opt/NexusShield/target/release/nexus-shield',
    args: '--port 8080 --upstream http://localhost:3000',
    env: { RUST_LOG: 'info,nexus_shield=debug' },
    autorestart: true,
    max_restarts: 10,
    restart_delay: 2000
  }]
};
```

---

## Performance

- **AST parsing:** SQL queries are parsed with `sqlparser`'s zero-copy parser. The `GenericDialect` is instantiated per-call (stateless, no allocation overhead).
- **Lock-free where possible:** `parking_lot::RwLock` for concurrent read access to behavioral data and audit chain. Write locks are held for microseconds.
- **Per-IP state pruning:** Background task runs every 60 seconds, removing state for IPs not seen in the last 600 seconds. Prevents unbounded memory growth.
- **Atomic operations:** Token bucket refill uses floating-point elapsed-time calculation, avoiding atomic contention.
- **Async throughout:** Built on Tokio with `axum` for the HTTP layer. The reverse proxy uses `hyper-util` for efficient HTTP/1.1 forwarding.
- **Memory footprint:** Dominated by the audit chain buffer. At 100,000 events with ~200 bytes per event, approximately 20 MB. Rate governor and fingerprint state scale with unique IP count.
- **Request overhead:** The full middleware pipeline (rate check + fingerprint + behavioral + threat score) completes in microseconds for clean traffic. SQL parsing adds low-millisecond overhead per query.

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

The binary is produced at `target/release/nexus-shield`.

### Run Tests

```bash
cargo test
```

### Run with Logging

```bash
RUST_LOG=info,nexus_shield=debug cargo run -- --port 8080 --standalone
```

---

## Error Responses

NexusShield returns deliberately vague error messages to avoid leaking security internals to attackers:

| Error | HTTP Status | Client Message |
|-------|-------------|----------------|
| SQL injection detected | 403 Forbidden | "Request blocked by security policy" |
| SSRF blocked | 403 Forbidden | "Request blocked by security policy" |
| Threat score exceeded | 403 Forbidden | "Request blocked by security policy" |
| Path traversal blocked | 403 Forbidden | "Request blocked by security policy" |
| Rate limit exceeded | 429 Too Many Requests | "Rate limit exceeded" |
| Malicious input | 400 Bad Request | "Invalid input detected" |
| Invalid connection string | 400 Bad Request | "Invalid connection configuration" |
| Data quarantine failed | 400 Bad Request | "Data validation failed" |
| Email validation failed | 400 Bad Request | "Email validation failed" |
| Email rate limit exceeded | 429 Too Many Requests | "Email rate limit exceeded" |

Detailed reasons are logged server-side and recorded in the audit chain, but never exposed to clients.

---

## Background Tasks

NexusShield runs a background maintenance task every 60 seconds:

1. **Rate governor pruning** -- Removes per-IP token buckets not accessed in 600 seconds
2. **Fingerprint pruning** -- Removes behavioral tracking data for stale IPs
3. **Email rate limiter pruning** -- Removes expired per-recipient send records

---

## Client IP Extraction

NexusShield extracts the client IP from HTTP headers in the following priority:

1. `X-Forwarded-For` -- First IP in the comma-separated list
2. `X-Real-IP` -- Single IP value
3. Falls back to `"unknown"` if neither header is present

Both headers are trimmed of whitespace.

---

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for the full text.

```
Copyright 2024-2026 AutomataNexus - Andrew Jewell Sr.
```
