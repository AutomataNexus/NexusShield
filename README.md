<p align="center">
  <img src="assets/NexusShield_logo.png" alt="NexusShield Logo" width="350" />
</p>

<h1 align="center">NexusShield</h1>

<p align="center">
  <strong>Adaptive zero-trust security gateway + real-time endpoint protection. Pure Rust. Developer-aware.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSL--1.1-blue.svg" alt="License: BSL-1.1" /></a>
  <img src="https://img.shields.io/badge/Rust-1.85%2B_(2024_edition)-orange.svg" alt="Rust 1.85+" />
  <img src="https://img.shields.io/badge/version-0.4.2-green.svg" alt="v0.4.2" />
  <img src="https://img.shields.io/badge/modules-39-blueviolet.svg" alt="39 modules" />
  <img src="https://img.shields.io/badge/tests-407-brightgreen.svg" alt="407 tests" />
</p>

---

## What Is NexusShield?

NexusShield is two products in one binary:

1. **Security Gateway** -- a reverse proxy that inspects every HTTP request through a layered defense pipeline (SQL firewall, SSRF guard, rate limiting, behavioral fingerprinting, threat scoring) before forwarding clean traffic to your upstream service.

2. **Endpoint Protection Engine** -- real-time file, process, network, and memory monitoring with multi-engine malware detection that replaces McAfee, Kaspersky, and ClamAV with a memory-safe, developer-aware alternative.

Both systems feed into the same tamper-evident SHA-256 hash-chained audit log, unified threat scoring, and REST API.

---

## Why NexusShield Is Better Than McAfee / Kaspersky / ClamAV

| Aspect | McAfee / Kaspersky / ClamAV | NexusShield |
|--------|---------------------------|-------------|
| **Language safety** | Written in C/C++ -- the scanner itself is an attack surface (CVE-2016-1714, CVE-2019-3648) | Pure Rust -- memory-safe. The scanner cannot be exploited via buffer overflows. |
| **Resource usage** | 200-500 MB RAM, constant CPU from scheduled scans, kernel-level hooks | Event-driven via inotify (near-zero idle CPU), <50 MB RAM, user-space only |
| **Developer awareness** | Flags `gcc`, Docker, `node`, Rust build artifacts, Go binaries as threats. Constant false positives. | Auto-detects 10+ dev toolchains (Rust, Node, Python, Go, Docker, Java, C/C++). Zero false positives on dev machines. |
| **Detection speed** | Scheduled scans (hourly/daily), on-access kernel hooks | inotify-based instant detection on file create/write. No kernel module required. |
| **Integration** | Standalone product, no API, no programmable interface | REST API, SSE real-time feed, full audit chain, programmatic quarantine management |
| **Transparency** | Proprietary signature databases, opaque heuristics | Open NDJSON signatures, YARA-compatible rules, configurable thresholds, full audit trail |
| **Overhead model** | Antimalware Service Executable consuming 10-30% CPU during scans | User-space only. inotify is zero overhead. /proc reads are microseconds per tick. |

---

## Architecture

### Security Gateway (13 modules)

```
                      Client Request
                           |
                           v
                  +------------------+
                  |   NexusShield    |
                  |   (port 8080)    |
                  +------------------+
                           |
        +------------------+------------------+
        |                  |                  |
   SQL Firewall     SSRF Guard      Rate Governor
   (AST-level)     (IP/DNS)     (5-level adaptive)
        |                  |                  |
        +------ Threat Score Engine ----------+
                    (0.0-1.0)
                       |
              +--------+--------+
              |                 |
         ALLOW/WARN          BLOCK
              |                 |
        Upstream App      Error Response
```

| Module | Description |
|--------|-------------|
| `sql_firewall` | AST-level SQL injection detection (30+ patterns, not regex) |
| `ssrf_guard` | SSRF prevention with cloud metadata, private IP, and DNS rebinding blocking |
| `rate_governor` | Adaptive rate limiting with 5-level escalation (None, Warn, Throttle, Block, Ban) |
| `fingerprint` | Behavioral bot fingerprinting via header analysis |
| `email_guard` | Email header injection and email bombing prevention |
| `quarantine` | Data quarantine for CSV/JSON imports |
| `sanitizer` | Connection string and path traversal prevention |
| `credential_vault` | AES-256-GCM encrypted credential storage |
| `audit_chain` | SHA-256 hash-chained tamper-evident event log |
| `threat_score` | Multi-signal threat scoring (fingerprint 30%, rate 25%, behavioral 30%, history 15%) |
| `config` | Centralized configuration with TOML support |

### Endpoint Protection Engine (18 modules)

```
  File Events (inotify)     /proc Polling     /proc/net/tcp     DNS Queries
        |                       |                   |                |
        v                       v                   v                v
  +----------+          +-----------+        +-----------+    +-----------+
  | Watcher  |          | Process   |        | Network   |    |   DNS     |
  |          |          | Monitor   |        | Monitor   |    |  Filter   |
  +----------+          +-----------+        +-----------+    +-----------+
        |                    |                    |                |
        v                    v                    v                v
  +----------------------------------------------------------------+
  |               EndpointEngine Orchestrator                       |
  |                                                                 |
  |  Scanners:                                                      |
  |  [SignatureEngine] [HeuristicEngine] [YaraEngine]               |
  +----------------------------------------------------------------+
        |              |              |              |
        v              v              v              v
  +-----------+  +-----------+  +-----------+  +-----------+
  | Quarantine|  | Audit     |  | Broadcast |  | Threat    |
  | Vault     |  | Chain     |  | Channel   |  | Intel DB  |
  +-----------+  +-----------+  +-----------+  +-----------+
```

| Module | Description | Key Features |
|--------|-------------|--------------|
| `endpoint::mod` | Core types + EndpointEngine orchestrator | Scanner trait, ScanResult, Severity, broadcast channel, history ring buffer |
| `endpoint::watcher` | Real-time filesystem monitoring | inotify via `notify` crate, configurable watch paths, debouncing, exclude patterns |
| `endpoint::signatures` | SHA-256 malware signature engine | NDJSON database, 12 built-in signatures (EICAR + test malware), streaming hash computation |
| `endpoint::heuristics` | Behavioral/static analysis | Shannon entropy, ELF header analysis, file type mismatch, script obfuscation, embedded executable detection |
| `endpoint::yara_engine` | YARA-compatible pattern matching | 5 built-in rules (EICAR, PowerShell, reverse shell, web shell, crypto miner), case-insensitive matching |
| `endpoint::process_monitor` | Process behavior monitoring | 19 reverse shell patterns, 17 miner patterns, deleted exe detection, /proc/[pid]/stat parsing |
| `endpoint::network_monitor` | Network connection analysis | /proc/net/tcp parsing, malicious IP detection, suspicious port alerts, C2 beaconing detection |
| `endpoint::memory_scanner` | Shellcode and injection detection | /proc/[pid]/maps RWX region detection, 7 shellcode patterns with mask-based matching, Cobalt Strike beacon detection |
| `endpoint::rootkit_detector` | System integrity verification | System binary hash baseline, 20 known rootkit module names, LD_PRELOAD detection, hidden process detection |
| `endpoint::file_quarantine` | Encrypted quarantine vault | SHA-256 chain of custody, permission stripping, restore capability, auto-expiry, atomic index persistence |
| `endpoint::threat_intel` | IOC database | 20 malicious IPs, 20 malicious domains, 10 IOC hashes, file-based persistence, community feed support |
| `endpoint::dns_filter` | DNS filtering proxy | UDP DNS proxy on 127.0.0.1:5353, blocks malicious domains via threat intel + custom blocklist, sinkhole responses, upstream forwarding, query logging |
| `endpoint::usb_monitor` | USB/removable media monitoring | /sys/block polling, new device detection, auto-scan mounted volumes, autorun.inf detection, hidden executable detection, suspicious script detection |
| `endpoint::fim` | File integrity monitoring | SHA-256 baselines of /etc, /usr/bin, /sbin; detects modifications, new files, deletions, permission/ownership changes; persistent baselines; path-aware severity |
| `endpoint::container_scanner` | Docker image scanning | Image inspect, root user detection, hardcoded secrets, dangerous base images, suspicious packages (nmap/netcat/sqlmap), pipe-to-shell, privileged mode, deep layer scanning with all engines |
| `endpoint::supply_chain` | Dependency scanning | Cargo.lock, package-lock.json, requirements.txt, go.sum parsing; known-malicious packages; typosquat detection (Levenshtein); suspicious versions; dependency confusion; custom registry detection |
| `endpoint::allowlist` | Developer-aware allowlist | Auto-detects Rust, Node, Python, Go, Docker, Java, C/C++, IDEs, Git. Component + extension + substring matching. |

---

## Quick Start

### Build

```bash
# Clone
git clone https://github.com/AutomataNexus/NexusShield.git
cd NexusShield

# Build
cargo build --release

# Run tests (275 tests)
cargo test
```

### Run as Security Gateway

```bash
# Standalone mode (shield + status dashboard)
./target/release/nexus-shield --standalone --port 8080

# Reverse proxy mode (protect an upstream service)
./target/release/nexus-shield --upstream http://localhost:3000 --port 8080

# With endpoint protection enabled
./target/release/nexus-shield --standalone --endpoint --port 8080
```

### Scan Files (One-Shot)

```bash
# Scan a single file
./target/release/nexus-shield --scan-file /tmp/suspicious.exe
# Output: CLEAN or THREATS FOUND with details

# Scan a directory recursively
./target/release/nexus-shield --scan /tmp/downloads/
# Output: list of all detections with severity, scanner, and description
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | Port to listen on |
| `--upstream` | None | Upstream target URL for proxy mode |
| `--standalone` | `false` | Run without upstream (shield + status) |
| `--endpoint` | `false` | Enable real-time endpoint protection |
| `--scan <DIR>` | None | One-shot directory scan, then exit |
| `--scan-file <FILE>` | None | One-shot file scan, then exit |
| `--block-threshold` | `0.7` | Threat score above which requests are blocked |
| `--warn-threshold` | `0.4` | Threat score above which requests are warned |
| `--rps` | `50` | Max requests per second per IP |
| `--config` | `/etc/nexus-shield/config.toml` | Config file path |

---

## API Endpoints

### Gateway Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/dashboard` | HTML dashboard widget |
| `GET` | `/status` | Shield status JSON |
| `GET` | `/audit` | Recent audit events (last 50) |
| `GET` | `/stats` | Request statistics (5min / 1hr) |
| `GET` | `/events` | SSE real-time event stream |
| `GET` | `/report` | HTML compliance report |
| `GET` | `/metrics` | Prometheus metrics |

### Endpoint Protection Endpoints (when `--endpoint` is enabled)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/endpoint/status` | Endpoint engine stats (scanned files, threats, active monitors) |
| `GET` | `/endpoint/detections` | Recent detections (last 100) |
| `GET` | `/endpoint/quarantine` | Quarantined files list |
| `POST` | `/endpoint/scan` | On-demand scan (body = file or directory path) |

### Example: On-Demand Scan via API

```bash
# Scan a file
curl -X POST http://localhost:8080/endpoint/scan -d "/tmp/suspicious.bin"

# Response:
{
  "path": "/tmp/suspicious.bin",
  "clean": false,
  "threats_found": 2,
  "detections": [
    {
      "scanner": "signature_engine",
      "severity": "high",
      "description": "EICAR-Test-File: EICAR standard antivirus test file",
      "confidence": 1.0
    },
    {
      "scanner": "yara_engine",
      "severity": "high",
      "description": "YARA rule 'EICAR_test_file' matched (1 strings: $eicar)"
    }
  ]
}
```

---

## Detection Engines

### 1. Signature Engine

SHA-256 exact-match detection. Files are hashed in streaming 8KB chunks and compared against an NDJSON signature database.

**Built-in signatures:**
- EICAR standard test file
- EICAR with trailing whitespace
- Trojan.GenericKD, Backdoor.Linux.Mirai, Ransomware.WannaCry
- Rootkit.Linux.Diamorphine, Rootkit.Linux.Reptile
- Miner.Linux.XMRig, Exploit.Linux.DirtyPipe
- Webshell.PHP.C99, Trojan.Linux.Tsunami

**Custom signatures:**
```json
{"hash":"sha256hex...","name":"MyMalware","family":"Trojan","severity":"High","description":"Custom detection"}
```
Add to `~/.nexus-shield/signatures.ndjson` (one JSON per line).

### 2. Heuristic Engine

Five independent analysis passes on every file:

| Check | What It Detects | Severity |
|-------|----------------|----------|
| **Shannon entropy** | Packed/encrypted executables (entropy > 7.2/8.0) | Medium |
| **ELF header analysis** | Stripped binaries (no sections), WX segments, suspicious entry points | Low-High |
| **File type mismatch** | .pdf with MZ header, .jpg with ELF magic, disguised executables | High |
| **Script obfuscation** | Base64 blocks >200 chars, hex payloads, eval+decode, string reversal | Medium |
| **Embedded executables** | MZ/ELF/shebang hidden inside documents past offset 1024 | High |

### 3. YARA Engine

Pure-Rust pattern matching engine (no libyara dependency) with 5 built-in rules:

| Rule | Detects | Severity |
|------|---------|----------|
| `EICAR_test_file` | Standard AV test file | High |
| `Suspicious_PowerShell` | -EncodedCommand, FromBase64String, -ExecutionPolicy Bypass | High |
| `Linux_Reverse_Shell` | bash -i /dev/tcp, nc -e, ncat, python socket, perl socket, socat | Critical |
| `Web_Shell_Indicators` | eval($_POST), system($_), passthru(), shell_exec() | Critical |
| `Crypto_Miner` | stratum+tcp://, xmrig, cryptonight, coinhive | High |

Custom rules: add `.yar` files to a rules directory and pass via config.

### 4. Process Monitor

Polls `/proc` every 2 seconds for:

- **19 reverse shell patterns**: bash -i /dev/tcp, nc -e, ncat, python/perl/ruby/PHP/socat socket, pty.spawn, openssl s_client
- **17 crypto miner patterns**: stratum+tcp/ssl, xmrig, minerd, cpuminer, cryptonight, ethminer, nbminer, phoenixminer, lolminer, nicehash
- **Deleted binary detection**: `/proc/[pid]/exe` containing "(deleted)" (common post-injection)

### 5. Network Monitor

Parses `/proc/net/tcp` every 5 seconds for:

- **Malicious IP detection**: Checks remote IPs against threat intelligence database
- **Suspicious port detection**: Flags connections to known C2/backdoor ports (4444, 5555, 6667, 6697, 1337, 31337)
- **C2 beaconing detection**: Statistical analysis of connection intervals — regular beaconing with <15% jitter triggers Critical alert

### 6. Memory Scanner

Reads `/proc/[pid]/maps` to find RWX (read-write-execute) regions and scans for:

- x86_64 syscall preamble, x86 int 0x80 shellcode
- 16-byte NOP sleds
- Reverse TCP socket setup
- Meterpreter/Metasploit/Cobalt Strike markers

### 7. DNS Filter

Lightweight UDP DNS proxy that intercepts and inspects every DNS query:

- **Malicious domain blocking**: Checks all queries against threat intel database + custom blocklist
- **Sinkhole responses**: Blocked domains resolve to `0.0.0.0` (prevents connection)
- **Upstream forwarding**: Clean queries forwarded to configurable upstream (default: 8.8.8.8)
- **Subdomain matching**: Blocking `evil.com` also blocks `sub.evil.com`
- **Whitelist override**: Critical domains can be whitelisted to never block
- **Runtime management**: Add/remove blocked domains via API without restart
- **Query logging**: Optional logging of all DNS queries for forensics
- **Stats tracking**: Total queries, blocked count, top blocked domains

```bash
# Enable DNS filter
./target/release/nexus-shield --standalone --endpoint --dns-filter --port 8080

# Point your system DNS to the filter
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
# Or use port 5353 directly for per-app filtering
```

### 8. USB/Removable Media Monitor

Polls `/sys/block` and `/proc/mounts` every 3 seconds for:

- **Device insertion detection**: Alerts when new block devices appear (USB drives, SD cards)
- **Removable device identification**: Reads `/sys/block/<dev>/removable`, vendor, model, size
- **Auto-scan mounted volumes**: When a new filesystem is mounted, scans root for threats
- **Autorun detection**: Finds `autorun.inf`, `autorun.sh`, `.autorun`, `autoexec.bat`, `desktop.ini` and other autoplay files
- **Hidden executable detection**: Dotfiles with execute permission on removable media
- **Suspicious script detection**: `.bat`, `.cmd`, `.ps1`, `.vbs`, `.wsf`, `.hta`, `.scr` files at volume root
- **Filesystem type alerting**: Flags mounts with `ntfs`, `vfat`, `exfat`, `hfsplus`, `udf` (common removable media types)

Enabled by default. Zero false positives — only alerts on genuinely new devices/mounts, not existing ones at startup.

### 9. File Integrity Monitor (FIM)

Baselines critical system files with SHA-256 hashes and detects unauthorized changes. Replaces OSSEC and Tripwire.

**Monitored by default:**
- `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`, `/etc/ssh/sshd_config`, `/etc/ld.so.preload`, `/etc/crontab`
- All files in `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/etc`

**Detection types:**

| Change | Severity | Description |
|--------|----------|-------------|
| Content modified (hash changed) | Critical/High/Medium | Based on path: `/etc/passwd` = Critical, `/usr/bin/*` = High, `/etc/*` = Medium |
| File created | Medium | New file appears in monitored directory |
| File deleted | High | Baselined file disappears |
| Permissions changed | Medium | Unix mode bits changed (e.g., 644 -> 777) |
| Ownership changed | High | UID or GID changed |

**Features:**
- Persistent baselines (survives restarts)
- Configurable polling interval (default: 60s)
- Exclude patterns for dynamic files
- `update_baseline()` to accept legitimate changes

### 10. Container Image Scanner

Inspects Docker images before they run, using `docker inspect` and `docker history`:

| Check | Severity | Description |
|-------|----------|-------------|
| Running as root | Medium | No USER directive or USER root/0 |
| Hardcoded secrets | High | `password=`, `api_key=`, `aws_secret`, etc. in ENV vars (values redacted in alerts) |
| Dangerous base image | High | kalilinux, parrotsec, known offensive images |
| Suspicious packages | Medium | nmap, netcat, socat, hydra, sqlmap, metasploit, etc. installed via apt/yum/apk |
| Pipe-to-shell | High | `curl ... \| bash` or `wget ... \| sh` patterns in Dockerfile |
| Privileged mode | High | `--privileged` or `CAP_SYS_ADMIN` in image layers |
| Suspicious ports | Medium | 4444, 5555, 6667, 1337, 31337 exposed |
| World-writable perms | Medium | `chmod 777` in build history |
| Security disabled | High | SELinux/AppArmor/seccomp disabled in layers |

**Deep scan mode**: Exports the image filesystem and runs all scan engines (signatures, heuristics, YARA) on extracted binaries in `/usr/bin`, `/usr/sbin`, `/tmp`, `/root`.

```bash
# Scan via API
curl -X POST http://localhost:8080/endpoint/scan -d "docker://myapp:latest"

# Scan via CLI
./target/release/nexus-shield --scan-file docker://nginx:latest
```

### 11. Supply Chain Scanner

Parses dependency lock files and detects supply chain attacks:

**Supported lock files:** `Cargo.lock`, `package-lock.json`, `yarn.lock`, `requirements.txt`, `Pipfile.lock`, `go.sum`

| Check | Severity | Description |
|-------|----------|-------------|
| Known-malicious package | Critical | Exact match against database of known-malicious packages (event-stream, flatmap-stream, rustdecimal, etc.) |
| Typosquat detection | High | Levenshtein distance <= 2 from popular packages (e.g., "serda" vs "serde", "expres" vs "express") |
| Suspicious version | Low | `0.0.x` versions on established-sounding packages |
| Custom registry | Medium | Packages resolved from non-standard registries (dependency confusion) |

**Popular package databases** (for typosquat detection):
- **Rust**: 26 top crates (serde, tokio, reqwest, clap, axum, etc.)
- **npm**: 24 top packages (express, react, lodash, axios, etc.)
- **PyPI**: 18 top packages (requests, numpy, pandas, flask, etc.)

```bash
# Scan your project's dependencies
./target/release/nexus-shield --scan-file Cargo.lock
./target/release/nexus-shield --scan-file package-lock.json
./target/release/nexus-shield --scan-file requirements.txt
./target/release/nexus-shield --scan-file go.sum
```

### 12. Rootkit Detector

- **System binary integrity**: SHA-256 baseline of `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` with modification detection
- **Kernel module check**: 20 known rootkit module names (diamorphine, reptile, bdvl, suterusu, etc.)
- **LD_PRELOAD detection**: Checks `/etc/ld.so.preload` and process environ for library injection
- **Hidden process detection**: Cross-references /proc readdir with status accessibility

---

## Developer Allowlist

The allowlist auto-detects installed dev environments and **never flags them as threats**:

| Environment | Detection | Skipped Paths | Skipped Processes |
|-------------|-----------|---------------|-------------------|
| **Rust** | `~/.cargo/bin`, `~/.rustup` | `target/debug/**`, `target/release/**`, `.rustup/**` | rustc, cargo, rust-analyzer, clippy-driver |
| **Node.js** | `~/.nvm`, `/usr/bin/node` | `node_modules/**`, `.npm/**`, `.nvm/**` | node, npm, npx, yarn, pnpm, bun, deno |
| **Python** | `/usr/bin/python3`, `~/.conda` | `__pycache__/**`, `.venv/**`, `venv/**` | python, python3, pip, conda, jupyter |
| **Go** | `~/go`, `GOPATH` | `go/pkg/**`, `go/bin/**` | go, gopls, dlv |
| **Docker** | `/usr/bin/docker` | `/var/lib/docker/**` | docker, dockerd, containerd, runc |
| **Java** | `/usr/bin/javac`, `JAVA_HOME` | `.gradle/**`, `.m2/repository/**` | java, javac, gradle, mvn, kotlin |
| **IDEs** | Always allowed | -- | code, nvim, vim, emacs, idea, clion, pycharm, zed, helix |
| **Compilers** | Always allowed | -- | gcc, g++, clang, make, cmake, gdb, lldb, strace, valgrind |
| **Git** | Always allowed | `.git/objects/**`, `.git/pack/**` | git, git-lfs, gh |

Custom overrides via `AllowlistConfig`:
```rust
AllowlistConfig {
    auto_detect: true,
    custom_allow_paths: vec!["my-build-dir".to_string()],
    custom_allow_processes: vec!["my-custom-tool".to_string()],
}
```

---

## Threat Intelligence

Built-in IOC database with:
- **20 malicious IPs** (RFC 5737 test ranges for safe testing)
- **20 malicious domains** (example.com subdomains for safe testing)
- **10+ IOC hashes** (EICAR + test signatures)

Custom indicators:
```bash
# Add to ~/.nexus-shield/threat-intel/ips.txt (one per line)
192.168.1.100
10.0.0.50

# Add to ~/.nexus-shield/threat-intel/domains.txt
evil-c2-server.com
phishing-domain.net

# Add to ~/.nexus-shield/threat-intel/hashes.txt
sha256hashofmalware...
```

---

## Quarantine Vault

Detected threats are moved to an encrypted quarantine vault:

- **Location**: `~/.nexus-shield/quarantine/`
- **Permissions**: Quarantined files stripped to `0o000` (no access)
- **Chain of custody**: SHA-256 hash, original path, permissions, timestamp, detection reason
- **Retention**: Auto-cleanup after 30 days (configurable)
- **Max size**: 1 GB (configurable)
- **Restore**: Files can be restored to original path with original permissions

---

## Configuration

### TOML Config File

```toml
# /etc/nexus-shield/config.toml

[endpoint]
enable_watcher = true
enable_process_monitor = true
enable_network_monitor = true
enable_memory_scanner = false        # requires elevated privileges
enable_rootkit_detector = false      # requires root
enable_dns_filter = false            # opt-in: intercepts DNS queries
enable_usb_monitor = true            # monitors for USB device insertions
enable_fim = false                   # file integrity monitoring (baselines /etc, /usr/bin)

[endpoint.watcher]
watch_paths = ["/home", "/tmp"]
exclude_patterns = ["node_modules", "target", ".git", "__pycache__"]
max_file_size = 104857600            # 100 MB
debounce_ms = 300

[endpoint.process_monitor]
poll_interval_ms = 2000
crypto_cpu_threshold = 90.0
crypto_duration_secs = 60

[endpoint.network_monitor]
poll_interval_ms = 5000
suspicious_ports = [4444, 5555, 8888, 6667, 6697, 1337, 31337]

[endpoint.fim]
poll_interval_ms = 60000             # 1 minute
watch_dirs = ["/etc", "/usr/bin", "/usr/sbin"]
watch_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
alert_on_new_files = true
alert_on_deleted_files = true
alert_on_permission_changes = true

[endpoint.usb_monitor]
poll_interval_ms = 3000
auto_scan_new_volumes = true
alert_on_insertion = true
max_scan_file_size = 104857600       # 100 MB

[endpoint.dns_filter]
listen_addr = "127.0.0.1:5353"
upstream_dns = "8.8.8.8:53"
upstream_timeout_ms = 3000
log_all_queries = false
custom_blocklist = ["evil-domain.com", "phishing-site.net"]
whitelist = ["localhost"]

[endpoint.allowlist]
auto_detect = true
custom_allow_processes = ["my-tool"]

[siem]
enabled = false
min_threat_score = 0.0               # 0.0 = all events, 0.7 = high+ only
batch_size = 1                       # 1 = real-time, >1 = batched
flush_interval_ms = 5000
source_name = "nexus-shield"

# Syslog (UDP)
[[siem.destinations]]
type = "syslog_udp"
host = "siem.company.com"
port = 514

# Elasticsearch
[[siem.destinations]]
type = "elasticsearch"
url = "https://es.company.com:9200"
index = "nexus-shield-events"
api_key = "your-api-key"

# Splunk HEC
[[siem.destinations]]
type = "splunk_hec"
url = "https://splunk.company.com:8088/services/collector"
token = "your-hec-token"
index = "security"

# Generic webhook (Slack, PagerDuty, custom)
[[siem.destinations]]
type = "webhook"
url = "https://hooks.slack.com/services/xxx/yyy/zzz"
```

---

## SIEM Integration

NexusShield forwards audit chain events to external SIEM platforms in real-time. Every event includes the SHA-256 chain hash for tamper-evidence verification.

### Supported Destinations

| Destination | Protocol | Format |
|-------------|----------|--------|
| **Syslog** | UDP or TCP | RFC 5424 with structured data |
| **Elasticsearch** | HTTP | Bulk index API (NDJSON) |
| **Splunk HEC** | HTTP | Splunk HTTP Event Collector JSON |
| **Webhook** | HTTP POST | Generic JSON payload |

### Event Format

Every exported event includes:

```json
{
  "timestamp": "2026-03-25T12:00:00Z",
  "source": "nexus-shield",
  "event_type": "SqlInjectionAttempt",
  "severity": "high",
  "severity_id": 9,
  "source_ip": "192.168.1.100",
  "threat_score": 0.85,
  "description": "UNION SELECT attack detected",
  "event_id": "uuid-here",
  "chain_hash": "sha256-hash"
}
```

### Syslog Output (RFC 5424)

```
<82>1 2026-03-25T12:00:00Z hostname nexus-shield - - [nexus-shield@49681 eventType="SqlInjectionAttempt" severity="high" threatScore="0.850" sourceIp="192.168.1.100"] UNION SELECT attack detected
```

### Features

- **Multi-destination**: Forward to multiple SIEMs simultaneously
- **Filtering**: Set minimum threat score to reduce noise (e.g., 0.7 = high+ only)
- **Batching**: Real-time (batch_size=1) or batched for high-throughput environments
- **CEF compatible**: Severity IDs map to Common Event Format (0-10)
- **Chain integrity**: Every event carries its SHA-256 chain hash for verification

---

## Real-Time Event Stream (SSE)

The `/events` endpoint streams security events in real-time using Server-Sent Events:

```bash
# Stream events in terminal
curl -N http://localhost:8080/events

# Browser JavaScript
const es = new EventSource('/events');
es.addEventListener('security', (e) => {
  const event = JSON.parse(e.data);
  console.log(`[${event.event_type}] ${event.source_ip}: ${event.details}`);
});
```

**Event format:**
```json
event: security
id: uuid-here
data: {"type":"audit_event","event_type":"RequestBlocked","source_ip":"1.2.3.4","threat_score":0.85,...}
```

- 15-second keepalive heartbeat
- No polling — events pushed as they occur
- Compatible with EventSource API in all browsers

---

## Systemd Journal Integration

Security events are written to the systemd journal with structured fields:

```bash
# View NexusShield events
journalctl -u nexus-shield -f

# Filter by priority (warnings and above)
journalctl -u nexus-shield -p warning

# JSON output for parsing
journalctl -u nexus-shield -o json | jq '.MESSAGE'
```

Each event includes structured fields: `EVENT_TYPE`, `SOURCE_IP`, `THREAT_SCORE`, `EVENT_ID`, `CHAIN_HASH` — accessible via `journalctl -o json`.

---

## Compliance Reports

Generate HTML security posture reports for auditors at `/report`:

```bash
# View in browser
open http://localhost:8080/report

# Save to file
curl -s http://localhost:8080/report > compliance-report.html
```

**Report includes:**
- Executive summary (threat counts, chain integrity)
- Severity breakdown with color-coded bars
- Active module inventory
- Configuration audit
- Top threat source IPs
- Full event log table (optional)
- Print-friendly CSS

---

## API Authentication

When `api_token` is set in config, all sensitive endpoints require Bearer token auth:

```bash
# Protected endpoints return 401 without token
curl http://localhost:8080/status
# 401 Unauthorized

# Pass the token
curl -H "Authorization: Bearer my-secret-token" http://localhost:8080/status
# 200 OK

# Public endpoints never require auth
curl http://localhost:8080/health       # always 200
curl http://localhost:8080/dashboard    # always 200
```

Configure in `config.toml`:
```toml
api_token = "your-secret-token-here"
```

---

## TLS / HTTPS

NexusShield supports TLS via rustls (no OpenSSL dependency):

```toml
tls_cert = "/etc/nexus-shield/cert.pem"
tls_key = "/etc/nexus-shield/key.pem"
```

When both are set, the server starts in HTTPS mode. Generate a self-signed cert for development:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=nexus-shield'
```

---

## Webhook Alerts

Fire HTTP POST to Slack, Discord, or any URL on security detections:

```toml
[[webhook_urls]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
min_severity = "high"
webhook_type = "slack"

[[webhook_urls]]
url = "https://discord.com/api/webhooks/xxx/yyy"
min_severity = "critical"
webhook_type = "discord"

[[webhook_urls]]
url = "https://your-pagerduty-or-custom-endpoint.com/alert"
webhook_type = "generic"
```

Slack messages include emoji severity indicators. Discord uses rich embeds with color coding. Generic sends structured JSON.

---

## Ferrum-Mail Integration

Send formatted HTML security alert emails via the Ferrum-Mail platform:

```toml
[ferrum_mail]
api_url = "http://localhost:3030"
api_key = "fm-key-123"
from_address = "shield@company.com"
alert_recipients = ["admin@company.com", "security@company.com"]
min_severity = "high"
```

Emails include color-coded severity headers, event details table, chain hash for verification, and AutomataNexus branding.

---

## Automatic Signature Updates

Pull malware signatures from a remote NDJSON feed on a timer:

```toml
[signature_update]
feed_url = "https://signatures.nexusshield.dev/v1/latest.ndjson"
interval_secs = 3600
auth_header = "Bearer your-feed-token"
```

Updates are validated (JSON per line) and written atomically (temp + rename). Invalid feeds are rejected without corrupting the local database.

---

## Prometheus Metrics

Expose counters at `/metrics` in Prometheus text exposition format:

```bash
curl http://localhost:8080/metrics
```

Available metrics:
- `nexus_shield_audit_events_total` — total audit chain events
- `nexus_shield_requests_blocked_total` — blocked requests (last hour)
- `nexus_shield_requests_blocked_5min` — blocked requests (last 5 min)
- `nexus_shield_rate_limited_total` — rate limited (last hour)
- `nexus_shield_sql_injection_total` — SQL injection attempts (last hour)
- `nexus_shield_ssrf_total` — SSRF attempts (last hour)
- `nexus_shield_malware_detected_total` — malware detections (last hour)
- `nexus_shield_chain_valid` — audit chain integrity (1=valid, 0=tampered)
- `nexus_shield_uptime_seconds` — uptime

---

## Crate Structure

```
nexus-shield/                        10,635 lines of Rust
  src/
    lib.rs                           Shield orchestrator + middleware
    auth.rs                          API authentication middleware (Bearer token)
    siem_export.rs                   SIEM integration (Syslog, ES, Splunk, webhook)
    sse_events.rs                    Server-Sent Events real-time streaming
    journal.rs                       Systemd journal integration
    compliance_report.rs             HTML/JSON compliance report generator
    webhook.rs                       Webhook alerts (Slack, Discord, generic)
    ferrum_integration.rs            Ferrum-Mail email alert integration
    signature_updater.rs             Automatic signature database updates
    metrics.rs                       Prometheus /metrics endpoint
    config.rs                        ShieldConfig with defaults
    sql_firewall.rs                  AST-level SQL injection detection
    ssrf_guard.rs                    SSRF/IP/DNS validation
    rate_governor.rs                 5-level adaptive rate limiting
    fingerprint.rs                   Behavioral bot fingerprinting
    email_guard.rs                   Email header injection prevention
    quarantine.rs                    Data import quarantine
    sanitizer.rs                     Input sanitization
    credential_vault.rs              AES-256-GCM credential storage
    audit_chain.rs                   Hash-chained tamper-evident log
    threat_score.rs                  Multi-signal threat scoring
    endpoint/
      mod.rs                         EndpointEngine, Scanner trait, core types
      container_scanner.rs             Docker image security scanning
      supply_chain.rs                 Dependency lock file scanning (typosquat, malicious, confusion)
      dns_filter.rs                  DNS filtering proxy with threat intel integration
      fim.rs                         File integrity monitoring (OSSEC/Tripwire replacement)
      usb_monitor.rs                 USB/removable media monitoring and auto-scan
      allowlist.rs                   Developer-aware toolchain detection
      signatures.rs                  SHA-256 signature matching
      heuristics.rs                  Entropy, ELF, mismatch, obfuscation
      yara_engine.rs                 YARA-compatible pattern matching
      watcher.rs                     Real-time filesystem monitoring
      process_monitor.rs             Reverse shell + miner detection
      network_monitor.rs             /proc/net/tcp connection analysis
      memory_scanner.rs              Shellcode + RWX region detection
      rootkit_detector.rs            System integrity verification
      file_quarantine.rs             Encrypted quarantine vault
      threat_intel.rs                IOC database (IPs, domains, hashes)
    bin/
      main.rs                        CLI + HTTP server + endpoint API
  widget/
    index.html                       Dashboard widget
  assets/
    NexusShield_logo.png             Logo
```

---

## Testing

275 tests covering all 24 modules:

```bash
cargo test                           # Run all tests
cargo test endpoint                  # Run endpoint tests only
cargo test signatures                # Run signature engine tests
cargo test heuristics                # Run heuristic engine tests
cargo test yara                      # Run YARA engine tests
cargo test process_monitor           # Run process monitor tests
cargo test network_monitor           # Run network monitor tests
cargo test memory_scanner            # Run memory scanner tests
cargo test rootkit                   # Run rootkit detector tests
cargo test quarantine                # Run quarantine vault tests
cargo test allowlist                 # Run developer allowlist tests
cargo test threat_intel              # Run threat intelligence tests
```

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `sqlparser` | SQL AST parsing for injection detection |
| `sha2` + `hex` | SHA-256 hashing for signatures + audit chain |
| `aes-gcm` | AES-256-GCM credential encryption |
| `parking_lot` | Fast, poison-free synchronization |
| `axum` + `hyper` | HTTP server + reverse proxy |
| `tokio` | Async runtime |
| `notify` | inotify filesystem monitoring |
| `procfs` | /proc process information |
| `nix` | Unix signal handling + getuid |
| `regex` | Pattern detection in scripts |
| `async-trait` | Async Scanner trait |
| `chrono` + `uuid` | Timestamps + unique IDs |
| `serde` + `serde_json` | Serialization |
| `clap` | CLI argument parsing |
| `tracing` | Structured logging |

---

## License

Business Source License 1.1 (BSL-1.1). Converts to Apache License 2.0 on March 24, 2030.

**Licensor**: Andrew Jewell Sr. - AutomataNexus

See [LICENSE](LICENSE) for full terms.

---

## Author

**Andrew Jewell Sr.** -- AutomataNexus

NexusShield is part of the Nexus platform (Aegis-DB, NexusVault, NexusShield).
