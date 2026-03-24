# NexusShield REST API Reference

Complete reference for all 13 REST API endpoints exposed by NexusShield when integrated with the Aegis-DB server. All endpoints are prefixed with `/api/v1/shield/`.

Base URL: `http://localhost:9090`

---

## Table of Contents

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

---

## 1. Get Shield Status

Returns a summary of the shield engine's current operational state.

**Endpoint:** `GET /api/v1/shield/status`

**Authentication:** Required (admin)

**Parameters:** None

**curl Example:**

```bash
curl -s http://localhost:9090/api/v1/shield/status \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**

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

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `bool` | Whether the shield is actively processing requests |
| `preset` | `string` | Active security preset: `"Strict"`, `"Moderate"`, or `"Permissive"` |
| `uptime_secs` | `u64` | Seconds since the shield engine was initialized |
| `total_requests_analyzed` | `u64` | Total number of requests processed by `analyze_request()` |
| `total_threats_detected` | `u64` | Total number of threats that resulted in Block or RateLimit |
| `active_bans` | `usize` | Number of IPs currently banned in the reputation tracker |
| `blocked_ips` | `usize` | Number of IPs currently in the auto-blocker's block list |

---

## 2. Get Threat Statistics

Returns aggregated threat statistics including event breakdowns by level and type, top offending IPs, and current block/ban counts.

**Endpoint:** `GET /api/v1/shield/stats`

**Authentication:** Required (admin)

**Parameters:** None

**curl Example:**

```bash
curl -s http://localhost:9090/api/v1/shield/stats \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**

```json
{
  "total_events": 47,
  "events_by_level": {
    "critical": 2,
    "high": 8,
    "medium": 15,
    "low": 12,
    "info": 10
  },
  "events_by_type": {
    "SqlInjection": 18,
    "BruteForce": 12,
    "SuspiciousFingerprint": 9,
    "QueryAnomaly": 8
  },
  "blocked_ips_count": 3,
  "active_bans": 2,
  "top_offending_ips": [
    ["203.0.113.42", 12],
    ["198.51.100.7", 8],
    ["192.0.2.15", 5]
  ],
  "last_critical_event": 1711324800
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `total_events` | `u64` | Total threat events ever recorded |
| `events_by_level` | `map<string, u64>` | Event count grouped by threat level |
| `events_by_type` | `map<string, u64>` | Event count grouped by threat type |
| `blocked_ips_count` | `u64` | IPs currently in auto-blocker |
| `active_bans` | `u64` | IPs currently banned in reputation tracker |
| `top_offending_ips` | `array<[string, u32]>` | Top 10 IPs by event count |
| `last_critical_event` | `i64 | null` | Unix timestamp of last critical event, or null |

---

## 3. Get Recent Threat Events

Returns the most recent threat events from the rolling in-memory buffer, newest first.

**Endpoint:** `GET /api/v1/shield/events`

**Authentication:** Required (admin)

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | `usize` | `50` | Maximum number of events to return |

**curl Example:**

```bash
curl -s "http://localhost:9090/api/v1/shield/events?limit=10" \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**

```json
[
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
  },
  {
    "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "timestamp": 1711324700,
    "threat_type": "BruteForce",
    "level": "Medium",
    "score": 50,
    "source_ip": "198.51.100.7",
    "description": "failed auth for user 'admin'",
    "request_path": "/api/v1/auth/login",
    "user_agent": "python-requests/2.31.0",
    "details": { "username": "admin" },
    "action_taken": "Allowed"
  }
]
```

**Event Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | UUID v4 identifier |
| `timestamp` | `i64` | Unix epoch timestamp |
| `threat_type` | `string` | One of: `SqlInjection`, `QueryAnomaly`, `BruteForce`, `RateLimitAbuse`, `SuspiciousFingerprint`, `ReputationBlock`, `UnauthorizedAccess`, `PortScan` |
| `level` | `string` | One of: `Critical`, `High`, `Medium`, `Low`, `Info` |
| `score` | `u32` | Threat score (0-100) |
| `source_ip` | `string` | Source IP address |
| `description` | `string` | Human-readable description |
| `request_path` | `string` | HTTP path that triggered the event |
| `user_agent` | `string | null` | User-Agent header, if present |
| `details` | `object` | Additional JSON details (varies by threat type) |
| `action_taken` | `string` | One of: `Allowed`, `RateLimited`, `Blocked`, `Banned` |

---

## 4. Get Threat Event by ID

Retrieves a single threat event by its UUID.

**Endpoint:** `GET /api/v1/shield/events/:id`

**Authentication:** Required (admin)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | `string` | UUID of the threat event |

**curl Example:**

```bash
curl -s http://localhost:9090/api/v1/shield/events/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**

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

**Response (404 Not Found):**

```json
{
  "error": "Event not found"
}
```

---

## 5. List Blocked IPs

Returns all currently active (non-expired) IP blocks from the auto-blocker.

**Endpoint:** `GET /api/v1/shield/blocked`

**Authentication:** Required (admin)

**Parameters:** None

**curl Example:**

```bash
curl -s http://localhost:9090/api/v1/shield/blocked \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**

```json
[
  {
    "ip": "203.0.113.42",
    "reason": "SQL injection score 95",
    "blocked_at": 1711324800,
    "expires_at": 1711328400,
    "threat_level": "Critical"
  },
  {
    "ip": "198.51.100.7",
    "reason": "brute force detected",
    "blocked_at": 1711320000,
    "expires_at": 1711327200,
    "threat_level": "High"
  }
]
```

**Block Entry Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ip` | `string` | Blocked IP address |
| `reason` | `string` | Human-readable reason for the block |
| `blocked_at` | `u64` | Unix epoch when the block was created |
| `expires_at` | `u64 | null` | Unix epoch when the block expires, or null for permanent |
| `threat_level` | `string` | One of: `Critical`, `High`, `Medium`, `Low`, `Info` |

---

## 6. Manually Block an IP

Adds a manual IP block with a custom reason and duration.

**Endpoint:** `POST /api/v1/shield/block`

**Authentication:** Required (admin)

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ip` | `string` | Yes | IP address to block |
| `reason` | `string` | Yes | Reason for the block |
| `duration_secs` | `u64` | Yes | Block duration in seconds |

**curl Example:**

```bash
curl -s -X POST http://localhost:9090/api/v1/shield/block \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "203.0.113.42",
    "reason": "suspicious activity reported by SOC",
    "duration_secs": 86400
  }'
```

**Response (200 OK):**

```json
{
  "status": "blocked",
  "ip": "203.0.113.42",
  "expires_at": 1711411200
}
```

---

## 7. Unblock an IP

Removes an IP from both the auto-blocker block list and the reputation ban list.

**Endpoint:** `DELETE /api/v1/shield/block/:ip`

**Authentication:** Required (admin)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ip` | `string` | IP address to unblock |

**curl Example:**

```bash
curl -s -X DELETE http://localhost:9090/api/v1/shield/block/203.0.113.42 \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**

```json
{
  "status": "unblocked",
  "ip": "203.0.113.42"
}
```

**Response (404 Not Found):**

```json
{
  "error": "IP not found in block list"
}
```

---

## 8. List Allowlisted IPs

Returns all IPs currently on the allowlist. Allowlisted IPs bypass all security checks.

**Endpoint:** `GET /api/v1/shield/allowlist`

**Authentication:** Required (admin)

**Parameters:** None

**curl Example:**

```bash
curl -s http://localhost:9090/api/v1/shield/allowlist \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**

```json
[
  "10.0.0.1",
  "10.0.0.2",
  "127.0.0.1"
]
```

---

## 9. Add IP to Allowlist

Adds an IP address to the allowlist. Allowlisted IPs bypass all security checks, including IP bans and auto-blocking.

**Endpoint:** `POST /api/v1/shield/allowlist`

**Authentication:** Required (admin)

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ip` | `string` | Yes | IP address to allowlist |

**curl Example:**

```bash
curl -s -X POST http://localhost:9090/api/v1/shield/allowlist \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.5"}'
```

**Response (200 OK):**

```json
{
  "status": "added",
  "ip": "10.0.0.5"
}
```

---

## 10. Remove IP from Allowlist

Removes an IP from the allowlist. The IP will be subject to normal security checks on subsequent requests.

**Endpoint:** `DELETE /api/v1/shield/allowlist/:ip`

**Authentication:** Required (admin)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ip` | `string` | IP address to remove |

**curl Example:**

```bash
curl -s -X DELETE http://localhost:9090/api/v1/shield/allowlist/10.0.0.5 \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**

```json
{
  "status": "removed",
  "ip": "10.0.0.5"
}
```

---

## 11. Get IP Reputation

Returns the full reputation record for a specific IP address, including score, request counts, ban status, and timestamps.

**Endpoint:** `GET /api/v1/shield/reputation/:ip`

**Authentication:** Required (admin)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ip` | `string` | IP address to look up |

**curl Example:**

```bash
curl -s http://localhost:9090/api/v1/shield/reputation/203.0.113.42 \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**

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

**Response (404 Not Found):**

```json
{
  "error": "IP not found"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ip` | `string` | The IP address |
| `score` | `i32` | Reputation score from -100 (worst) to +100 (best) |
| `total_requests` | `u64` | Total requests from this IP |
| `failed_auths` | `u64` | Number of failed authentication attempts |
| `blocked_requests` | `u64` | Number of requests blocked by shield |
| `threat_events` | `u64` | Number of threat events generated |
| `first_seen` | `i64` | Unix timestamp of first request |
| `last_seen` | `i64` | Unix timestamp of most recent request |
| `banned_until` | `u64 | null` | Unix timestamp when ban expires, or null if not banned |
| `ban_reason` | `string | null` | Reason for current ban, or null |

---

## 12. Get Security Policy

Returns the currently active security policy, including preset, enabled modules, and custom rules.

**Endpoint:** `GET /api/v1/shield/policy`

**Authentication:** Required (admin)

**Parameters:** None

**curl Example:**

```bash
curl -s http://localhost:9090/api/v1/shield/policy \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**

```json
{
  "preset": "Moderate",
  "sql_injection_enabled": true,
  "anomaly_detection_enabled": true,
  "ip_reputation_enabled": true,
  "fingerprinting_enabled": true,
  "auto_blocking_enabled": true,
  "custom_rules": []
}
```

---

## 13. Update Security Policy

Replaces the active security policy. Takes effect immediately for all subsequent requests and queries.

**Endpoint:** `PUT /api/v1/shield/policy`

**Authentication:** Required (admin)

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `preset` | `string` | Yes | `"Strict"`, `"Moderate"`, or `"Permissive"` |
| `sql_injection_enabled` | `bool` | Yes | Enable SQL injection detection |
| `anomaly_detection_enabled` | `bool` | Yes | Enable anomaly detection |
| `ip_reputation_enabled` | `bool` | Yes | Enable IP reputation tracking |
| `fingerprinting_enabled` | `bool` | Yes | Enable request fingerprinting |
| `auto_blocking_enabled` | `bool` | Yes | Enable automatic IP blocking |
| `custom_rules` | `array` | No | Array of custom rule objects |

**Custom Rule Object:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` | Yes | Rule name for identification |
| `path_pattern` | `string | null` | No | Path prefix to match (null = all paths) |
| `max_score` | `u32` | Yes | Score threshold that triggers this rule |
| `action` | `string` | Yes | `"Allowed"`, `"RateLimited"`, `"Blocked"`, or `"Banned"` |

**curl Example (switch to Strict with custom rule):**

```bash
curl -s -X PUT http://localhost:9090/api/v1/shield/policy \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "preset": "Strict",
    "sql_injection_enabled": true,
    "anomaly_detection_enabled": true,
    "ip_reputation_enabled": true,
    "fingerprinting_enabled": true,
    "auto_blocking_enabled": true,
    "custom_rules": [
      {
        "name": "admin_lockdown",
        "path_pattern": "/api/v1/admin",
        "max_score": 30,
        "action": "Blocked"
      },
      {
        "name": "public_lenient",
        "path_pattern": "/api/v1/health",
        "max_score": 95,
        "action": "Allowed"
      }
    ]
  }'
```

**Response (200 OK):**

```json
{
  "status": "updated",
  "preset": "Strict",
  "custom_rules_count": 2
}
```

**curl Example (switch to Permissive, disable auto-blocking):**

```bash
curl -s -X PUT http://localhost:9090/api/v1/shield/policy \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "preset": "Permissive",
    "sql_injection_enabled": true,
    "anomaly_detection_enabled": false,
    "ip_reputation_enabled": true,
    "fingerprinting_enabled": false,
    "auto_blocking_enabled": false,
    "custom_rules": []
  }'
```

**Response (200 OK):**

```json
{
  "status": "updated",
  "preset": "Permissive",
  "custom_rules_count": 0
}
```

---

## Error Responses

All endpoints return standard error responses for common failure cases.

**401 Unauthorized:**

```json
{
  "error": "Authentication required"
}
```

**403 Forbidden:**

```json
{
  "error": "Admin access required"
}
```

**400 Bad Request:**

```json
{
  "error": "Invalid request body",
  "details": "missing field `ip` at line 1 column 2"
}
```

**404 Not Found:**

```json
{
  "error": "Resource not found"
}
```

**500 Internal Server Error:**

```json
{
  "error": "Internal server error"
}
```

---

## Rate Limiting

The shield API endpoints are subject to the server's global rate limiting:

- **API endpoints:** 1000 requests per minute per IP
- **Authentication endpoints:** 30 requests per minute per IP

Shield endpoints are administrative in nature and should only be accessed by authorized operators. Excessive polling of the events or stats endpoints should be avoided in favor of reasonable intervals (e.g., every 5-10 seconds for dashboards).
