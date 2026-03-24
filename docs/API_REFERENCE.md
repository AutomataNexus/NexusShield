# NexusShield API Reference

Complete reference for the 4 HTTP endpoints exposed by the NexusShield security gateway. These endpoints are available in both reverse proxy mode and standalone mode.

Base URL: `http://localhost:8080` (default port)

---

## Endpoint Summary

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/status` | Gateway configuration, modules, audit chain integrity |
| `GET` | `/audit` | Recent security events with chain verification |
| `GET` | `/stats` | Threat statistics for last 5 minutes and last hour |

All other paths are either proxied to the upstream (in proxy mode) or return "NexusShield: request inspected and allowed" (in standalone mode). All paths pass through the full security middleware pipeline before being handled.

---

## 1. Health Check

Returns a plain-text health status. Use this for load balancer health probes and uptime monitoring.

**Endpoint:** `GET /health`

**Authentication:** None required

### Request

```bash
curl http://localhost:8080/health
```

### Response

**Status:** `200 OK`
**Content-Type:** `text/plain`

```
NexusShield OK
```

### Notes

- This endpoint always returns `200 OK` as long as the NexusShield process is running.
- The response is a fixed string; no JSON parsing is needed.
- This endpoint passes through the security middleware, so requests from banned IPs will receive `429 Too Many Requests` instead.

---

## 2. Gateway Status

Returns the full gateway configuration, list of active security modules, and audit chain integrity status.

**Endpoint:** `GET /status`

**Authentication:** None required (status is not sensitive)

### Request

```bash
curl -s http://localhost:8080/status | jq .
```

### Response

**Status:** `200 OK`
**Content-Type:** `application/json`

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

### Response Schema

| Field | Type | Description |
|-------|------|-------------|
| `service` | `string` | Always `"NexusShield"` |
| `version` | `string` | NexusShield version |
| `status` | `string` | Always `"active"` when the gateway is running |
| `config` | `object` | Active configuration parameters (see below) |
| `audit_chain` | `object` | Audit chain status (see below) |
| `modules` | `array<string>` | List of active security modules |

**`config` fields:**

| Field | Type | Description |
|-------|------|-------------|
| `block_threshold` | `f64` | Threat score at which requests are blocked (0.0-1.0) |
| `warn_threshold` | `f64` | Threat score at which warnings are logged (0.0-1.0) |
| `rate_rps` | `f64` | Configured requests per second per IP |
| `rate_burst` | `f64` | Token bucket burst capacity |

**`audit_chain` fields:**

| Field | Type | Description |
|-------|------|-------------|
| `total_events` | `usize` | Total events currently stored in the chain |
| `chain_valid` | `bool` | Whether the full SHA-256 hash chain verifies without tampering |

### Examples

**Check if chain integrity is intact:**

```bash
curl -s http://localhost:8080/status | jq '.audit_chain.chain_valid'
# true
```

**Get current thresholds:**

```bash
curl -s http://localhost:8080/status | jq '.config'
# {
#   "block_threshold": 0.7,
#   "warn_threshold": 0.4,
#   "rate_rps": 50.0,
#   "rate_burst": 100.0
# }
```

**List active modules:**

```bash
curl -s http://localhost:8080/status | jq '.modules[]'
# "sql_firewall"
# "ssrf_guard"
# "rate_governor"
# ...
```

---

## 3. Audit Events

Returns the 50 most recent security events from the hash-chained audit log (newest first), along with the total event count and chain integrity status.

**Endpoint:** `GET /audit`

**Authentication:** None required

### Request

```bash
curl -s http://localhost:8080/audit | jq .
```

### Response

**Status:** `200 OK`
**Content-Type:** `application/json`

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
    },
    {
      "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "timestamp": "2026-03-24T10:29:55.456789Z",
      "event_type": "RateLimitHit",
      "source_ip": "198.51.100.7",
      "details": "escalation=Block, violations=16",
      "threat_score": 0.8
    },
    {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "timestamp": "2026-03-24T10:29:50.789012Z",
      "event_type": "SqlInjectionAttempt",
      "source_ip": "192.0.2.15",
      "details": "UnionInjection, DangerousFunction(\"sleep\")",
      "threat_score": 0.95
    },
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "timestamp": "2026-03-24T10:28:00.000000Z",
      "event_type": "RequestAllowed",
      "source_ip": "203.0.113.10",
      "details": "WARN: score=0.450",
      "threat_score": 0.45
    }
  ],
  "total": 1247,
  "chain_valid": true
}
```

### Response Schema

| Field | Type | Description |
|-------|------|-------------|
| `recent_events` | `array<object>` | Up to 50 most recent events, newest first |
| `total` | `usize` | Total events in the audit chain |
| `chain_valid` | `bool` | Whether the full hash chain verifies |

**Event object fields:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | UUID v4 unique identifier |
| `timestamp` | `string` | RFC 3339 timestamp (e.g., `"2026-03-24T10:30:00.123456Z"`) |
| `event_type` | `string` | Security event type (see below) |
| `source_ip` | `string` | Client IP address that triggered the event |
| `details` | `string` | Human-readable description (internal diagnostic info) |
| `threat_score` | `f64` | Threat score at the time of the event (0.0-1.0) |

**Possible `event_type` values:**

| Event Type | Description |
|------------|-------------|
| `RequestAllowed` | Request passed all checks (logged when threat score triggers a warning) |
| `RequestBlocked` | Request blocked due to high threat score |
| `RateLimitHit` | Request denied by the rate governor |
| `SqlInjectionAttempt` | SQL firewall detected an injection attempt |
| `SsrfAttempt` | SSRF guard blocked a URL or IP |
| `PathTraversalAttempt` | Path traversal detected in file path validation |
| `MaliciousPayload` | Malicious content detected (email injection, etc.) |
| `DataQuarantined` | Imported data failed quarantine validation |
| `AuthFailure` | Authentication failure recorded |
| `BanIssued` | IP ban applied |
| `BanLifted` | IP ban removed |
| `ChainVerified` | Chain integrity verification was performed |

### Examples

**Get the 5 most recent blocked requests:**

```bash
curl -s http://localhost:8080/audit | \
  jq '[.recent_events[] | select(.event_type == "RequestBlocked")] | .[0:5]'
```

**Check if the audit chain has been tampered with:**

```bash
curl -s http://localhost:8080/audit | jq '.chain_valid'
# true
```

**Get all SQL injection attempts:**

```bash
curl -s http://localhost:8080/audit | \
  jq '[.recent_events[] | select(.event_type == "SqlInjectionAttempt")]'
```

**Get events from a specific IP:**

```bash
curl -s http://localhost:8080/audit | \
  jq '[.recent_events[] | select(.source_ip == "203.0.113.42")]'
```

---

## 4. Threat Statistics

Returns aggregated threat counts for two time windows: the last 5 minutes and the last hour. Useful for dashboards and alerting.

**Endpoint:** `GET /stats`

**Authentication:** None required

### Request

```bash
curl -s http://localhost:8080/stats | jq .
```

### Response

**Status:** `200 OK`
**Content-Type:** `application/json`

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

### Response Schema

| Field | Type | Description |
|-------|------|-------------|
| `last_5min` | `object` | Event counts from the last 5 minutes |
| `last_hour` | `object` | Event counts from the last hour |
| `total_audit_events` | `usize` | Total events in the audit chain |

**Time window fields (same for both `last_5min` and `last_hour`):**

| Field | Type | Description |
|-------|------|-------------|
| `blocked` | `usize` | Requests blocked by threat score (`RequestBlocked` events) |
| `rate_limited` | `usize` | Requests denied by rate governor (`RateLimitHit` events) |
| `sql_injection` | `usize` | SQL injection attempts detected (`SqlInjectionAttempt` events) |
| `ssrf` | `usize` | SSRF attempts blocked (`SsrfAttempt` events) |

### Examples

**Check if there are active attacks (last 5 minutes):**

```bash
curl -s http://localhost:8080/stats | jq '.last_5min'
# {
#   "blocked": 3,
#   "rate_limited": 12,
#   "sql_injection": 1,
#   "ssrf": 0
# }
```

**Get total blocked in the last hour:**

```bash
curl -s http://localhost:8080/stats | jq '.last_hour.blocked'
# 18
```

**Simple alerting script:**

```bash
#!/bin/bash
BLOCKED=$(curl -s http://localhost:8080/stats | jq '.last_5min.blocked')
if [ "$BLOCKED" -gt 10 ]; then
  echo "ALERT: $BLOCKED requests blocked in last 5 minutes"
fi
```

**Continuous monitoring (every 10 seconds):**

```bash
watch -n 10 'curl -s http://localhost:8080/stats | jq .'
```

---

## Error Responses

All endpoints pass through the NexusShield security middleware. Requests that trigger security policies will receive error responses instead of the expected endpoint data.

### Rate Limited (429)

```
HTTP/1.1 429 Too Many Requests
Retry-After: 60

Rate limit exceeded
```

The `Retry-After` header is included when the client IP is banned, indicating how many seconds until the ban expires.

### Blocked (403)

```
HTTP/1.1 403 Forbidden

Request blocked by security policy
```

Returned when the client's threat score exceeds the block threshold (default: 0.7).

### Upstream Unavailable (502)

Only in proxy mode when the upstream service is unreachable:

```
HTTP/1.1 502 Bad Gateway

Upstream unavailable
```

### Invalid Upstream URI (400)

Only in proxy mode when the constructed upstream URI is invalid:

```
HTTP/1.1 400 Bad Request

Invalid upstream URI
```

---

## Notes

- All 4 endpoints (`/health`, `/status`, `/audit`, `/stats`) are registered as explicit routes and are handled directly by NexusShield, never forwarded to the upstream.
- The audit endpoint returns a fixed maximum of 50 events. This is not configurable via query parameters.
- Statistics are computed on-the-fly from the audit chain by scanning events with timestamps after the window boundary. There is no pre-aggregated counter.
- The `chain_valid` field triggers a full chain verification on every call to `/status` and `/audit`. For chains with 100,000 events, this involves recomputing 100,000 SHA-256 hashes. In production with very large chains, consider polling this less frequently.
- All timestamps in the `/audit` response use RFC 3339 format with UTC timezone.
- The `/stats` time windows use the server's UTC clock. Ensure NTP synchronization for accurate window boundaries.
