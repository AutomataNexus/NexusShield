<p align="center">
  <img src="assets/NexusShield_logo.png" alt="NexusShield Logo" width="350" />
</p>

<h1 align="center">NexusShield</h1>

<p align="center">
  <strong>Adaptive zero-trust security gateway + real-time endpoint protection. Pure Rust. Developer-aware.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSL--1.1-blue.svg" alt="License: BSL-1.1" /></a>
  <img src="https://img.shields.io/badge/Rust-1.75%2B-orange.svg" alt="Rust 1.75+" />
  <img src="https://img.shields.io/badge/version-0.3.0-green.svg" alt="v0.3.0" />
  <img src="https://img.shields.io/badge/LOC-10,635-informational.svg" alt="10,635 LOC" />
  <img src="https://img.shields.io/badge/modules-24-blueviolet.svg" alt="24 modules" />
  <img src="https://img.shields.io/badge/tests-275-brightgreen.svg" alt="275 tests" />
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

### Endpoint Protection Engine (12 modules, 5,055 lines)

```
  File Events (inotify)     /proc Polling     /proc/net/tcp
        |                       |                   |
        v                       v                   v
  +----------+          +-----------+        +-----------+
  | Watcher  |          | Process   |        | Network   |
  |          |          | Monitor   |        | Monitor   |
  +----------+          +-----------+        +-----------+
        |                    |                    |
        v                    v                    v
  +---------------------------------------------------+
  |            EndpointEngine Orchestrator             |
  |                                                    |
  |  Scanners:                                         |
  |  [SignatureEngine] [HeuristicEngine] [YaraEngine]  |
  +---------------------------------------------------+
        |              |              |
        v              v              v
  +-----------+  +-----------+  +-----------+
  | Quarantine|  | Audit     |  | Broadcast |
  | Vault     |  | Chain     |  | Channel   |
  +-----------+  +-----------+  +-----------+
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

### 7. Rootkit Detector

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

[endpoint.allowlist]
auto_detect = true
custom_allow_processes = ["my-tool"]
```

---

## Crate Structure

```
nexus-shield/                        10,635 lines of Rust
  src/
    lib.rs                           Shield orchestrator + middleware
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
