# NexusShield — Work State

Adaptive zero-trust security gateway + real-time endpoint protection (Pure Rust).

In-flight work tracker for this project. Read at the start of any session in `/opt/NexusShield/`.

**Last updated:** 2026-04-12 ~23:20 (daily-report binary shipped + live on DO)

---

## Top of mind — next session actions

1. **DO shield has no `api_token`** — `nexus-shield` on DO (`100.67.227.31:0.0.0.0:8080`) is publicly readable. Mint a token, store at NexusVault key `nexus-shield-api-token`, edit `/etc/nexus-shield/config.toml` on DO to add `api_token = <fetched>`, `systemctl restart nexus-shield`. Then add `NEXUS_SHIELD_TOKEN` lookup to `/etc/nexus-shield/daily-report.env` so the timer keeps working.

2. **Nginx `mirror` rollout on DO** — 20 sites (`andrew`, `automatanexus`, `ferrummail`, `oracle`, etc. — full list in `/etc/nginx/sites-enabled/`) currently go nginx → upstream direct. Shield is NOT in the request path. Add `mirror /__shield_inspect` to each site so every request is duplicated to `127.0.0.1:8080` for log-only inspection. Start with one non-critical site (`prometheus` or `stratum-ui`), verify shield `/audit` logs traffic, then roll out. Flip `mirror` → `auth_request` after a week of tuning thresholds.

3. **Point security-ticker at DO shield** — currently polls `http://127.0.0.1:8080` (local laptop shield, not production). After item 1 above, change `NEXUS_SHIELD_URL` to `http://100.67.227.31:8080` (Tailscale) in `launch-ticker.sh` + store DO token at HashiCorp vault key `secret/nexus-shield-do` for the laptop to fetch.

---

## In-flight workstreams

### W01 — security-ticker desktop widget
**Status:** Shipping, running on Andrew's laptop via WSLg.
**Location:** `src/ui/security_ticker.rs` → built as `security-ticker` binary (requires `ticker` feature).
**Launcher chain:**
- `C:\Users\Autom\Desktop\SecurityTicker.vbs` + `...\Startup\SecurityTicker.vbs` (autorun)
- VBS calls `wsl.exe -d Ubuntu -e /opt/NexusShield/launch-ticker.sh`
- `launch-ticker.sh` pulls Bearer token from HashiCorp Vault (`secret/nexus-shield`) using root-token from `/opt/Prometheus/vault/.vault-keys`, exports `NEXUS_SHIELD_TOKEN`, execs the binary.
**What it polls:** backend health, endpoint stats, per-module LEDs, rolling 5-min/1-hour stats (blocked/rate/sql/ssrf), scrolling detection log, on-demand scan input.
**Env:** `NEXUS_SHIELD_URL` (default `http://127.0.0.1:8080`), `NEXUS_SHIELD_TOKEN` (Bearer).
**Theme toggle:** light (Claude coral/cream) / dark (NexusStratum) persisted to `~/.nexus-shield/ticker-theme`.

### W02 — daily security report (email pipeline)
**Status:** LIVE on DO — first real email sent 2026-04-12 ~23:16 UTC (100 CRITICAL, 100 total events).
**Binary:** `src/bin/daily_report.rs` → `daily-report` binary (requires `report` feature). Built from `reqwest` + `clap` + `chrono` + `serde_json`.
**Template:** `src/daily_report.rs` — HTML renderer matching the Ferrum Mail forwarding-test aesthetic (cream header, teal pill badge, orange `#D96E4C` accents, 3 severity cards terracotta/teal/tan, NexusShield footer). Also renders plain-text fallback.
**Data source:** queries shield `/status`, `/audit`, `/endpoint/status`, `/endpoint/detections`. Filters events to last 24h via RFC3339 timestamp comparison.
**Credential resolution order** (in the binary): env vars → NexusVault (`NEXUSVAULT_ADDR` + `NEXUSVAULT_API_KEY` bootstrap, then fetch `ferrum-mail-api-{url,user,password}`) → HashiCorp `vault kv get secret/ferrum-mail`.
**Send path:** Ferrum Mail JWT — `POST /mailbox/api/v1/auth/login` → `POST /mailbox/api/v1/send` with HTML as body (not attachment).
**Deployment on DO (100.67.227.31):**
- `/usr/local/bin/daily-report` (root:root 755)
- `/etc/nexus-shield/daily-report.env` (root:root 600) — ONLY bootstrap creds: `NEXUSVAULT_ADDR`, `NEXUSVAULT_API_KEY`, `NEXUS_SHIELD_URL`
- `/etc/systemd/system/nexus-shield-daily-report.{service,timer}` — `oneshot` triggered by `OnCalendar=*-*-* 07:00:00 UTC` with `Persistent=true`
- Logs: `/var/log/nexus-shield/daily-report-latest.html`
**Recipients:** `automatanexus@ferrum-mail.com`, `devops@automatanexus.com`.
**NexusVault keys used (DO, accessed via `Bearer` auth NOT `X-API-Key`):** `ferrum-mail-api-url`, `ferrum-mail-api-user`, `ferrum-mail-api-password`.

### W03 — nginx gateway integration (NOT STARTED)
**Status:** Blocked on W02 verification (one week log-only observation) and on deciding whether to keep each site's existing upstream or route everything through shield. Target: `mirror` pattern first (log-only), `auth_request` later (enforce).
**Action list:** see "Top of mind" #2 above.

---

## Recently completed

- **2026-04-13 process_monitor false-positive class fixed** — split miner detection at `process_monitor.rs:42` into `MINER_MARKERS` (URL/algo strings, substring anywhere) + `MINER_BINARIES` (`xmrig`, `minerd`, etc., matched only against `comm` and `argv[0]` basename). Eliminates the entire "bash/grep/cargo-test references string `xmrig`" false-positive class without weakening real-miner detection. Regression test `miner_name_as_data_not_miner`. Both shields rebuilt + restarted (laptop + DO 100.67.227.31). See LESSONS L32.
- **2026-04-13 network_monitor — Anthropic API false-positive fixed** — added `34.128.0.0/10` to `default_benign_cidrs()` at `network_monitor.rs:97`. Was previously only allowlisting `34.64.0.0/10` (first GCP LB block); Anthropic API endpoints (e.g. `34.149.66.137`) live in the second block (`34.128.0.0/10`) and kept tripping beacon detection during Claude Code sessions. Regression test `anthropic_api_endpoint_allowlisted`. Both shields rebuilt + restarted. See LESSONS L33.
- **2026-04-13 security-ticker UI: clickable detail panel + hover tooltips on every LED** — `det:N` chip is now a clickable button that opens a "Detections — full detail" floating window listing every Warn/Crit log line with timestamp/severity/full message and a copy button. Every gateway/endpoint module LED has hover-text via new `module_long(name)` lookup ("process_monitor [ALIVE] — reverse shells, miners, sustained-CPU jobs..."). `auth`/`shield`/stat-chip LEDs all have hover descriptions. Theme toggle changed from text "light"/"dark" to amber `☀`/`☾` glyphs (matches nexus-agent ticker). Restarted via `launch-ticker.sh` (the persistent path is the Windows Startup VBS — survives reboot).
- **2026-04-12 daily-report shipped end-to-end** — binary built, NexusVault creds stored, systemd timer enabled, first live email delivered to `automatanexus@ferrum-mail.com` + `devops@automatanexus.com`. Next daily fire: 2026-04-13 07:00 UTC.
- **2026-04-12 security-ticker heuristic tuning** — killed the false-positive floods:
  - `network_monitor`: CIDR allowlist (Google/CF/Fastly/AWS/Azure/Akamai/GitHub + RFC1918 + CGNAT) **plus** per-socket-inode → /proc/*/comm process allowlist (tailscaled, systemd-resolve, chrony, vault, NetworkManager). Tailscale DERP relays stopped flooding.
  - `process_monitor`: `is_dev_rebuild_path()` exempts `/target/{release,debug}/` + `/opt/<project>/` paths from both the `(deleted)` binary check AND the sustained-high-CPU check. ML training jobs (`zephyr-train-predictor`) no longer flag.
  - `process_monitor` sustained-CPU check now fires **once per incident** not every scan (was re-firing every 2s for 60+ seconds). Re-arms when CPU drops back below threshold.
- **2026-04-12 ticker dedupe** — `poll_audit` now skips event types that are already surfaced via `/endpoint/detections` (`SuspiciousNetwork`, `SuspiciousProcess`, `MalwareDetected`, etc.). Each incident appears once in the log.
- **2026-04-12 ticker polish** — `copy all` + `clear` buttons on log area, individual lines selectable (click-drag + Ctrl+C work), light/dark theme toggle with Claude-browser colors persisted across restarts.
- **2026-04-12 laptop shield secured** — HashiCorp Vault root token regenerated via `operator generate-root` dance (LESSONS L09), fresh 43-char `api_token` stored at `secret/nexus-shield`, written to `/etc/nexus-shield/config.toml` (mode 640 root), service restarted. `curl /status` now 401 without token, 200 with.

---

## How to maintain this file

1. When a workstream starts, add it with status / owner / blockers / files / notes
2. When it changes state, update the entry
3. When it completes, move it to "Recently completed"
4. The "Top of mind" section gets rewritten each session end
5. Don't duplicate detail — link to per-file README.md, summary.md, or memory files
