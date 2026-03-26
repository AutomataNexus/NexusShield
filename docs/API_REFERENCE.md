# NexusShield API Reference

Complete reference for all HTTP endpoints exposed by the NexusShield security gateway. Gateway endpoints are always available. Endpoint protection endpoints require the `--endpoint` flag.

Base URL: `http://localhost:8080` (default port)

---

## Endpoint Summary

### Gateway Endpoints (always available)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/dashboard` | Live HTML monitoring dashboard |
| `GET` | `/logo.png` | NexusShield logo (PNG) |
| `GET` | `/status` | Gateway configuration, modules, audit chain integrity |
| `GET` | `/audit` | Recent security events with chain verification |
| `GET` | `/stats` | Threat statistics for last 5 minutes and last hour |

### Endpoint Protection Endpoints (requires `--endpoint`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/endpoint/status` | Endpoint engine stats (scanners, monitors, threats) |
| `GET` | `/endpoint/detections` | Recent detections (last 100) |
| `GET` | `/endpoint/quarantine` | Quarantined files list |
| `POST` | `/endpoint/scan` | On-demand file or directory scan |

All paths pass through the security middleware pipeline before being handled.

---

## 1. Health Check

Returns a plain-text health status. Use for load balancer health probes.

**Endpoint:** `GET /health`

```bash
curl http://localhost:8080/health
```

**Response:** `200 OK` — `NexusShield OK`

---

## 2. Dashboard

Serves the live HTML monitoring dashboard with auto-refreshing stats, modules, threat breakdown, and audit log.

**Endpoint:** `GET /dashboard`

```bash
# Open in browser
open http://localhost:8080/dashboard
```

**Response:** `200 OK` — `text/html`

---

## 3. Logo

Serves the NexusShield logo. Used by the dashboard.

**Endpoint:** `GET /logo.png`

**Response:** `200 OK` — `image/png` (cached for 24 hours)

---

## 4. Gateway Status

Returns gateway configuration, active security modules, and audit chain integrity.

**Endpoint:** `GET /status`

```bash
curl -s http://localhost:8080/status | jq .
```

**Response:**

```json
{
  "service": "NexusShield",
  "version": "0.3.0",
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

| Field | Type | Description |
|-------|------|-------------|
| `service` | `string` | Always `"NexusShield"` |
| `version` | `string` | NexusShield version |
| `status` | `string` | Always `"active"` when running |
| `config.block_threshold` | `f64` | Threat score at which requests are blocked (0.0-1.0) |
| `config.warn_threshold` | `f64` | Threat score at which warnings are logged |
| `config.rate_rps` | `f64` | Requests per second per IP |
| `config.rate_burst` | `f64` | Token bucket burst capacity |
| `audit_chain.total_events` | `usize` | Total events in the chain |
| `audit_chain.chain_valid` | `bool` | Whether SHA-256 hash chain verifies |
| `modules` | `array<string>` | Active security modules |

---

## 5. Audit Events

Returns the 50 most recent security events from the hash-chained audit log.

**Endpoint:** `GET /audit`

```bash
curl -s http://localhost:8080/audit | jq .
```

**Response:**

```json
{
  "recent_events": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "timestamp": "2026-03-24T10:30:00.123456Z",
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

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | UUID v4 identifier |
| `timestamp` | `string` | RFC 3339 UTC timestamp |
| `event_type` | `string` | Event type (see below) |
| `source_ip` | `string` | Client IP address |
| `details` | `string` | Internal diagnostic info |
| `threat_score` | `f64` | Threat score (0.0-1.0) |

**Event types:** `RequestAllowed`, `RequestBlocked`, `RateLimitHit`, `SqlInjectionAttempt`, `SsrfAttempt`, `PathTraversalAttempt`, `MaliciousPayload`, `DataQuarantined`, `AuthFailure`, `BanIssued`, `BanLifted`, `ChainVerified`, `MalwareDetected`, `SuspiciousProcess`, `SuspiciousNetwork`, `MemoryAnomaly`, `RootkitIndicator`, `FileQuarantined`, `FileRestored`, `SignatureDbUpdated`, `EndpointScanStarted`, `EndpointScanCompleted`

**Examples:**

```bash
# Get blocked requests only
curl -s http://localhost:8080/audit | \
  jq '[.recent_events[] | select(.event_type == "RequestBlocked")]'

# Get events from a specific IP
curl -s http://localhost:8080/audit | \
  jq '[.recent_events[] | select(.source_ip == "203.0.113.42")]'

# Check chain integrity
curl -s http://localhost:8080/audit | jq '.chain_valid'
```

---

## 6. Threat Statistics

Aggregated threat counts for two time windows.

**Endpoint:** `GET /stats`

```bash
curl -s http://localhost:8080/stats | jq .
```

**Response:**

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

| Field | Type | Description |
|-------|------|-------------|
| `blocked` | `usize` | Requests blocked by threat score |
| `rate_limited` | `usize` | Requests denied by rate governor |
| `sql_injection` | `usize` | SQL injection attempts detected |
| `ssrf` | `usize` | SSRF attempts blocked |
| `total_audit_events` | `usize` | Total events in audit chain |

---

## 7. Endpoint Status

Returns endpoint protection engine statistics.

**Endpoint:** `GET /endpoint/status`
**Requires:** `--endpoint` flag

```bash
curl -s http://localhost:8080/endpoint/status | jq .
```

**Response:**

```json
{
  "endpoint_protection": "active",
  "total_files_scanned": 1523,
  "total_threats_detected": 3,
  "active_monitors": [
    "file_watcher",
    "process_monitor",
    "network_monitor",
    "usb_monitor"
  ],
  "scanners_active": [
    "signature_engine",
    "heuristic_engine",
    "yara_engine"
  ],
  "quarantined_files": 2,
  "last_scan_time": "2026-03-25T10:15:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `endpoint_protection` | `string` | Always `"active"` when running |
| `total_files_scanned` | `u64` | Cumulative files scanned since startup |
| `total_threats_detected` | `u64` | Cumulative threats detected |
| `active_monitors` | `array<string>` | Running background monitors |
| `scanners_active` | `array<string>` | Active scan engines |
| `quarantined_files` | `usize` | Files currently in quarantine vault |
| `last_scan_time` | `string|null` | RFC 3339 timestamp of most recent detection |

---

## 8. Recent Detections

Returns the 100 most recent endpoint detections.

**Endpoint:** `GET /endpoint/detections`
**Requires:** `--endpoint` flag

```bash
curl -s http://localhost:8080/endpoint/detections | jq .
```

**Response:**

```json
{
  "detections": [
    {
      "id": "a1b2c3d4-uuid",
      "timestamp": "2026-03-25T10:14:32Z",
      "scanner": "signature_engine",
      "target": "/tmp/eicar.com",
      "severity": "high",
      "description": "EICAR-Test-File: EICAR standard antivirus test file",
      "confidence": 1.0,
      "action": "quarantine(/tmp/eicar.com)",
      "artifact_hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    }
  ],
  "total": 1
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | UUID v4 detection identifier |
| `timestamp` | `string` | RFC 3339 UTC timestamp |
| `scanner` | `string` | Which engine detected it (`signature_engine`, `heuristic_engine`, `yara_engine`, `process_monitor`, `network_monitor`, `dns_filter`, `usb_monitor`, `fim`, `memory_scanner`, `rootkit_detector`) |
| `target` | `string` | What was scanned (file path, PID, connection, domain) |
| `severity` | `string` | `info`, `low`, `medium`, `high`, or `critical` |
| `description` | `string` | Human-readable detection description |
| `confidence` | `f64` | Confidence score (0.0-1.0) |
| `action` | `string` | Recommended action taken |
| `artifact_hash` | `string|null` | SHA-256 of scanned file (if applicable) |

---

## 9. Quarantine Vault

Lists all files currently held in the encrypted quarantine vault.

**Endpoint:** `GET /endpoint/quarantine`
**Requires:** `--endpoint` flag

```bash
curl -s http://localhost:8080/endpoint/quarantine | jq .
```

**Response:**

```json
{
  "quarantined_files": [
    {
      "id": "q-uuid-here",
      "original_path": "/tmp/eicar.com",
      "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "detection_reason": "EICAR-Test-File: EICAR standard antivirus test file",
      "scanner": "signature_engine",
      "severity": "high",
      "quarantined_at": "2026-03-25T10:14:32Z",
      "file_size": 68
    }
  ],
  "total": 1,
  "vault_size_bytes": 1024
}
```

| Field | Type | Description |
|-------|------|-------------|
| `original_path` | `string` | Where the file was before quarantine |
| `sha256` | `string` | SHA-256 hash of original file |
| `detection_reason` | `string` | Why it was quarantined |
| `scanner` | `string` | Which engine flagged it |
| `severity` | `string` | Detection severity |
| `quarantined_at` | `string` | RFC 3339 timestamp |
| `file_size` | `u64` | Original file size in bytes |
| `vault_size_bytes` | `u64` | Total quarantine vault disk usage |

---

## 10. On-Demand Scan

Scan a file or directory on-demand via the API.

**Endpoint:** `POST /endpoint/scan`
**Requires:** `--endpoint` flag
**Body:** Plain text file or directory path

```bash
# Scan a file
curl -X POST http://localhost:8080/endpoint/scan -d "/tmp/suspicious.bin"

# Scan a directory
curl -X POST http://localhost:8080/endpoint/scan -d "/tmp/downloads/"
```

**Response (clean):**

```json
{
  "path": "/tmp/clean-file.txt",
  "clean": true,
  "threats_found": 0,
  "detections": []
}
```

**Response (threat detected):**

```json
{
  "path": "/tmp/suspicious.bin",
  "clean": false,
  "threats_found": 2,
  "detections": [
    {
      "scanner": "signature_engine",
      "target": "/tmp/suspicious.bin",
      "severity": "high",
      "description": "EICAR-Test-File: EICAR standard antivirus test file",
      "confidence": 1.0,
      "artifact_hash": "275a021..."
    },
    {
      "scanner": "yara_engine",
      "target": "/tmp/suspicious.bin",
      "severity": "high",
      "description": "YARA rule 'EICAR_test_file' matched (1 strings: $eicar)",
      "confidence": 0.95,
      "artifact_hash": null
    }
  ]
}
```

**Error (path not found):**

```json
{
  "error": "Path does not exist",
  "path": "/nonexistent/file"
}
```

---

## Error Responses

All endpoints pass through the security middleware. Requests triggering policies receive errors:

| Status | Body | When |
|--------|------|------|
| `429 Too Many Requests` | `Rate limit exceeded` | Rate governor threshold exceeded. Includes `Retry-After` header. |
| `403 Forbidden` | `Request blocked by security policy` | Threat score exceeds block threshold (default: 0.7) |
| `502 Bad Gateway` | `Upstream unavailable` | Proxy mode only: upstream service unreachable |
| `400 Bad Request` | `Invalid upstream URI` | Proxy mode only: constructed URI invalid |

---

## Notes

- Gateway endpoints (`/health`, `/dashboard`, `/status`, `/audit`, `/stats`) are always available in both standalone and proxy modes.
- Endpoint protection endpoints (`/endpoint/*`) require the `--endpoint` CLI flag.
- The `/audit` endpoint returns a fixed maximum of 50 events. Not configurable via query parameters.
- Statistics are computed on-the-fly from the audit chain. No pre-aggregated counters.
- `chain_valid` triggers a full SHA-256 chain verification on every call. For large chains, poll infrequently.
- All timestamps use RFC 3339 format with UTC timezone.
- The `POST /endpoint/scan` endpoint scans synchronously and may take time on large directories.
