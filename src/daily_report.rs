// ============================================================================
// File: daily_report.rs
// Description: Daily security report HTML renderer — visual match for the
//              Ferrum Mail "forwarding test" email (cream header, teal badge,
//              orange accents, 3 severity cards, NexusShield footer).
// Author: Andrew Jewell Sr. - AutomataNexus
// ============================================================================
//! Builds a self-contained HTML email summarizing the last 24 hours of
//! shield activity. Pure string rendering — no HTTP. The caller fetches
//! data (from `/audit` + `/endpoint/detections`), aggregates into a
//! `DailyReport`, calls `render_html`, and hands the result off to an
//! email transport (Ferrum Mail SMTP or similar).
//!
//! Visual design mirrors the Ferrum Mail transactional email aesthetic:
//!   - Cream/peach header card with logo + title
//!   - Teal status pill
//!   - Bold headline + orange-accented summary paragraph
//!   - Cream "24-hour overview" card with stat rows
//!   - Three colored severity cards (critical / high / medium+low)
//!   - Optional top-detections table
//!   - Footer: "🔒 Secured by NexusShield"

use serde::{Deserialize, Serialize};

/// Aggregated 24-hour activity summary rendered into the email.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyReport {
    /// Human date this report covers, e.g. "2026-04-12".
    pub date: String,
    /// Which shield instance this report was generated from (e.g. hostname
    /// or Tailscale IP). Shown in the footer for disambiguation.
    pub source: String,
    /// Window this report covers, in hours. Typically 24.
    pub covered_hours: u32,

    // --- Gateway-side activity (audit chain) ---
    pub requests_inspected: u64,
    pub blocked: u64,
    pub sql_injection: u64,
    pub ssrf: u64,
    pub path_traversal: u64,
    pub rate_limited: u64,
    pub auth_failures: u64,
    pub bans_issued: u64,
    pub unique_source_ips: u64,

    // --- Endpoint-side activity (scanner detections) ---
    pub endpoint_critical: u64,
    pub endpoint_high: u64,
    pub endpoint_medium: u64,
    pub endpoint_low: u64,
    pub files_scanned_total: u64,
    pub quarantined_total: u64,

    /// Audit-chain integrity. Surfaced prominently if false.
    pub audit_chain_valid: bool,
    /// Shield uptime in seconds at report time.
    pub uptime_secs: u64,

    /// Top N noteworthy detections from the endpoint scanners, already
    /// de-duplicated + sorted (most critical / most recent first).
    pub top_detections: Vec<TopDetection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopDetection {
    pub scanner: String,
    pub severity: String,
    pub description: String,
    pub target: String,
    pub timestamp: String,
}

impl DailyReport {
    /// Total endpoint detections across all severities.
    pub fn endpoint_total(&self) -> u64 {
        self.endpoint_critical + self.endpoint_high + self.endpoint_medium + self.endpoint_low
    }

    /// Sum of "interesting" (non-allowed, non-health) audit events.
    pub fn gateway_total(&self) -> u64 {
        self.blocked
            + self.sql_injection
            + self.ssrf
            + self.path_traversal
            + self.rate_limited
            + self.auth_failures
    }
}

/// Subject line for the daily email.
pub fn subject(report: &DailyReport) -> String {
    let critical = report.endpoint_critical;
    let total = report.endpoint_total() + report.gateway_total();
    if critical > 0 {
        format!(
            "[NexusShield] {} — {} CRITICAL, {} total events",
            report.date, critical, total
        )
    } else if total > 0 {
        format!("[NexusShield] {} — {} events (no critical)", report.date, total)
    } else {
        format!("[NexusShield] {} — all quiet", report.date)
    }
}

/// Render the report as a self-contained HTML email body.
pub fn render_html(report: &DailyReport) -> String {
    let date = html_escape(&report.date);
    let source = html_escape(&report.source);
    let hours = report.covered_hours;

    let total_events = report.endpoint_total() + report.gateway_total();
    let summary_line = if total_events == 0 {
        format!(
            "In the last {h}h the shield inspected <b style=\"color:#D96E4C\">{r}</b> requests and found nothing noteworthy — all clear.",
            h = hours,
            r = fmt_num(report.requests_inspected),
        )
    } else {
        format!(
            "In the last {h}h the shield inspected <b style=\"color:#D96E4C\">{r}</b> requests, logged <b style=\"color:#D96E4C\">{g}</b> gateway events, and recorded <b style=\"color:#D96E4C\">{e}</b> endpoint detections.",
            h = hours,
            r = fmt_num(report.requests_inspected),
            g = fmt_num(report.gateway_total()),
            e = fmt_num(report.endpoint_total()),
        )
    };

    let top_block = render_top_detections(&report.top_detections);
    let integrity_banner = if report.audit_chain_valid {
        String::new()
    } else {
        format!(
            r#"<div style="margin:0 0 20px;padding:14px 18px;background:{RED_BG};border:1px solid {RED_BORDER};border-radius:8px;color:{RED_DARK};font-size:13px;">
    <strong>⚠ Audit chain integrity check FAILED.</strong> The hash chain of audit events could not be verified end-to-end. Investigate immediately.
  </div>"#,
            RED_BG = "#FCE8E3",
            RED_BORDER = "#E8B8A8",
            RED_DARK = "#8B2E1C",
        )
    };

    format!(
        r##"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NexusShield — Daily Report {date}</title>
</head>
<body style="margin:0;padding:24px 12px;background:{PAGE_BG};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:{TEXT};">
<div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 2px 14px rgba(0,0,0,0.04);">

  <!-- ── HEADER: cream/peach bg, logo + title ─────────────────────────── -->
  <div style="background:{HEADER_BG};padding:40px 32px;text-align:center;">
    <img src="{LOGO_URL}" alt="NexusShield" width="88" height="88"
         style="display:block;margin:0 auto 14px;border:0;outline:none;max-width:88px;">
    <div style="font-size:13px;color:{MUTED};letter-spacing:1px;text-transform:uppercase;margin-bottom:6px;">
      NexusShield
    </div>
    <h1 style="margin:0;font-size:30px;font-weight:700;color:{ORANGE};letter-spacing:-0.3px;">
      Daily Security Report
    </h1>
    <p style="margin:8px 0 0;font-size:14px;color:{MUTED};">
      Automated {hours}-hour security summary
    </p>
  </div>

  <!-- ── BODY ─────────────────────────────────────────────────────────── -->
  <div style="padding:36px 32px;">

    <!-- Status pill -->
    <div style="display:inline-block;padding:6px 14px;background:{TEAL_BG};color:{TEAL_DARK};font-size:11px;font-weight:600;letter-spacing:0.8px;text-transform:uppercase;border-radius:20px;margin-bottom:20px;">
      ✓ Daily Report
    </div>

    <!-- Main heading -->
    <h2 style="margin:0 0 14px;font-size:22px;font-weight:700;color:{TEXT};line-height:1.3;">
      Security summary for {date}
    </h2>

    <!-- Summary paragraph with orange-accented values -->
    <p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:{BODY_TEXT};">
      {summary_line}
    </p>

    {integrity_banner}

    <!-- ── 24-HOUR OVERVIEW card (cream bg, orange heading) ───────────── -->
    <div style="background:{CARD_CREAM};border-radius:10px;padding:22px 24px;margin-bottom:22px;">
      <div style="color:{ORANGE};font-size:12px;font-weight:700;letter-spacing:1px;margin-bottom:14px;">
        24-HOUR OVERVIEW
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:13px;color:{BODY_TEXT};">
        {row_requests}
        {row_blocked}
        {row_sql}
        {row_ssrf}
        {row_traversal}
        {row_rate}
        {row_auth}
        {row_bans}
        {row_unique_ips}
        {row_files}
        {row_quarantine}
        {row_uptime}
      </table>
    </div>

    <!-- ── 3 SEVERITY CARDS ───────────────────────────────────────────── -->
    <table role="presentation" style="width:100%;border-collapse:separate;border-spacing:10px 0;margin-bottom:22px;">
      <tr>
        <td style="width:33.33%;background:{CARD_CRIT_BG};border-radius:10px;padding:16px;vertical-align:top;">
          <div style="color:{CARD_CRIT_FG};font-size:10px;font-weight:700;letter-spacing:1px;margin-bottom:8px;">
            CRITICAL
          </div>
          <div style="font-size:26px;font-weight:700;color:{CARD_CRIT_FG};line-height:1;margin-bottom:6px;">
            {critical}
          </div>
          <div style="font-size:11px;color:{BODY_TEXT};line-height:1.4;">
            Immediate attention required — active threats or chain breaks.
          </div>
        </td>
        <td style="width:33.33%;background:{CARD_HIGH_BG};border-radius:10px;padding:16px;vertical-align:top;">
          <div style="color:{CARD_HIGH_FG};font-size:10px;font-weight:700;letter-spacing:1px;margin-bottom:8px;">
            HIGH
          </div>
          <div style="font-size:26px;font-weight:700;color:{CARD_HIGH_FG};line-height:1;margin-bottom:6px;">
            {high}
          </div>
          <div style="font-size:11px;color:{BODY_TEXT};line-height:1.4;">
            Review recommended — suspicious behavior or sustained anomalies.
          </div>
        </td>
        <td style="width:33.33%;background:{CARD_MED_BG};border-radius:10px;padding:16px;vertical-align:top;">
          <div style="color:{CARD_MED_FG};font-size:10px;font-weight:700;letter-spacing:1px;margin-bottom:8px;">
            MEDIUM · LOW
          </div>
          <div style="font-size:26px;font-weight:700;color:{CARD_MED_FG};line-height:1;margin-bottom:6px;">
            {med_low}
          </div>
          <div style="font-size:11px;color:{BODY_TEXT};line-height:1.4;">
            Standard monitoring — informational detections.
          </div>
        </td>
      </tr>
    </table>

    {top_block}

  </div>

  <!-- ── FOOTER ───────────────────────────────────────────────────────── -->
  <div style="padding:22px 32px 28px;text-align:center;border-top:1px solid {FOOTER_BORDER};">
    <div style="font-size:12px;color:{MUTED};margin-bottom:6px;">
      🔒 Secured by <strong style="color:{TEXT};">NexusShield</strong>
    </div>
    <div style="font-size:11px;color:{MUTED};margin-bottom:4px;">
      Delivered via Ferrum Mail direct MX · Encrypted at rest · DKIM signed
    </div>
    <div style="font-size:11px;color:{MUTED};">
      © 2026 AutomataNexus LLC · Report generated from <span style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;">{source}</span>
    </div>
  </div>

</div>
</body>
</html>"##,
        // ── Palette tokens ──────────────────────────────────────────────
        PAGE_BG = "#F5F4EF",
        HEADER_BG = "#FBF1EC",
        CARD_CREAM = "#FAF2ED",
        FOOTER_BORDER = "#EFEAE2",
        TEXT = "#1F1E1D",
        BODY_TEXT = "#3D3A35",
        MUTED = "#8A857C",
        ORANGE = "#D96E4C",
        TEAL_BG = "#D5E7E0",
        TEAL_DARK = "#2C7A5F",
        CARD_CRIT_BG = "#F4DBD1",
        CARD_CRIT_FG = "#B0452C",
        CARD_HIGH_BG = "#D5E7E0",
        CARD_HIGH_FG = "#2C7A5F",
        CARD_MED_BG = "#F1E8DD",
        CARD_MED_FG = "#8B6F47",
        // ── Dynamic fields ──────────────────────────────────────────────
        LOGO_URL = "https://raw.githubusercontent.com/AutomataNexus/NexusShield/main/assets/NexusShield_logo.png",
        date = date,
        hours = hours,
        source = source,
        summary_line = summary_line,
        integrity_banner = integrity_banner,
        critical = fmt_num(report.endpoint_critical),
        high = fmt_num(report.endpoint_high),
        med_low = fmt_num(report.endpoint_medium + report.endpoint_low),
        top_block = top_block,
        row_requests = stat_row("Requests inspected", &fmt_num(report.requests_inspected), false),
        row_blocked = stat_row("Requests blocked", &fmt_num(report.blocked), report.blocked > 0),
        row_sql = stat_row("SQL injection attempts", &fmt_num(report.sql_injection), report.sql_injection > 0),
        row_ssrf = stat_row("SSRF attempts", &fmt_num(report.ssrf), report.ssrf > 0),
        row_traversal = stat_row("Path traversal attempts", &fmt_num(report.path_traversal), report.path_traversal > 0),
        row_rate = stat_row("Rate-limit hits", &fmt_num(report.rate_limited), false),
        row_auth = stat_row("Auth failures", &fmt_num(report.auth_failures), report.auth_failures > 0),
        row_bans = stat_row("Bans issued", &fmt_num(report.bans_issued), report.bans_issued > 0),
        row_unique_ips = stat_row("Unique source IPs", &fmt_num(report.unique_source_ips), false),
        row_files = stat_row("Files scanned", &fmt_num(report.files_scanned_total), false),
        row_quarantine = stat_row("Files quarantined", &fmt_num(report.quarantined_total), report.quarantined_total > 0),
        row_uptime = stat_row("Shield uptime", &fmt_uptime(report.uptime_secs), false),
    )
}

fn stat_row(label: &str, value: &str, emphasize: bool) -> String {
    let value_color = if emphasize { "#D96E4C" } else { "#1F1E1D" };
    let value_weight = if emphasize { "700" } else { "600" };
    format!(
        r#"<tr>
          <td style="padding:7px 0;color:#6B6862;border-bottom:1px solid #EFEAE2;">{label}</td>
          <td style="padding:7px 0;text-align:right;color:{value_color};font-weight:{value_weight};border-bottom:1px solid #EFEAE2;font-variant-numeric:tabular-nums;">{value}</td>
        </tr>"#,
        label = html_escape(label),
        value = html_escape(value),
        value_color = value_color,
        value_weight = value_weight,
    )
}

fn render_top_detections(items: &[TopDetection]) -> String {
    if items.is_empty() {
        return String::new();
    }

    let rows: String = items
        .iter()
        .take(10)
        .map(|d| {
            let sev_bg = match d.severity.to_lowercase().as_str() {
                "critical" => "#F4DBD1",
                "high" => "#F7E4D2",
                "medium" => "#F1E8DD",
                _ => "#F0EEE8",
            };
            let sev_fg = match d.severity.to_lowercase().as_str() {
                "critical" => "#B0452C",
                "high" => "#A8622A",
                "medium" => "#8B6F47",
                _ => "#6B6862",
            };
            format!(
                r#"<tr>
                      <td style="padding:8px 10px;border-bottom:1px solid #EFEAE2;font-size:11px;white-space:nowrap;color:#8A857C;font-variant-numeric:tabular-nums;">{ts}</td>
                      <td style="padding:8px 10px;border-bottom:1px solid #EFEAE2;"><span style="display:inline-block;padding:2px 8px;background:{sev_bg};color:{sev_fg};font-size:10px;font-weight:700;letter-spacing:0.5px;border-radius:4px;text-transform:uppercase;">{sev}</span></td>
                      <td style="padding:8px 10px;border-bottom:1px solid #EFEAE2;font-size:12px;color:#3D3A35;">
                        <div><strong>[{scanner}]</strong> {desc}</div>
                        <div style="font-size:11px;color:#8A857C;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin-top:2px;">{target}</div>
                      </td>
                   </tr>"#,
                ts = html_escape(&d.timestamp),
                sev = html_escape(&d.severity),
                sev_bg = sev_bg,
                sev_fg = sev_fg,
                scanner = html_escape(&d.scanner),
                desc = html_escape(&truncate(&d.description, 140)),
                target = html_escape(&truncate(&d.target, 80)),
            )
        })
        .collect();

    format!(
        r#"<div style="background:#FAFAF7;border-radius:10px;padding:22px 6px;margin-bottom:10px;">
      <div style="color:#D96E4C;font-size:12px;font-weight:700;letter-spacing:1px;margin:0 16px 12px;">
        TOP DETECTIONS
      </div>
      <table style="width:100%;border-collapse:collapse;">
        {rows}
      </table>
    </div>"#,
        rows = rows,
    )
}

/// Render a plain-text fallback version of the report (used as the `text`
/// alternative in the email for clients that can't render HTML).
pub fn render_text(r: &DailyReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "NexusShield — Daily Security Report\n{}\n{}\n\n",
        "=".repeat(42),
        r.date
    ));
    out.push_str(&format!("Source: {}\n", r.source));
    out.push_str(&format!("Window: last {}h\n", r.covered_hours));
    out.push_str(&format!("Uptime: {}\n\n", fmt_uptime(r.uptime_secs)));

    if !r.audit_chain_valid {
        out.push_str("⚠ AUDIT CHAIN INTEGRITY FAILED — investigate immediately.\n\n");
    }

    out.push_str("24-HOUR OVERVIEW\n");
    out.push_str(&format!("  Requests inspected:      {}\n", fmt_num(r.requests_inspected)));
    out.push_str(&format!("  Requests blocked:        {}\n", fmt_num(r.blocked)));
    out.push_str(&format!("  SQL injection attempts:  {}\n", fmt_num(r.sql_injection)));
    out.push_str(&format!("  SSRF attempts:           {}\n", fmt_num(r.ssrf)));
    out.push_str(&format!("  Path traversal attempts: {}\n", fmt_num(r.path_traversal)));
    out.push_str(&format!("  Rate-limit hits:         {}\n", fmt_num(r.rate_limited)));
    out.push_str(&format!("  Auth failures:           {}\n", fmt_num(r.auth_failures)));
    out.push_str(&format!("  Bans issued:             {}\n", fmt_num(r.bans_issued)));
    out.push_str(&format!("  Unique source IPs:       {}\n", fmt_num(r.unique_source_ips)));
    out.push_str(&format!("  Files scanned:           {}\n", fmt_num(r.files_scanned_total)));
    out.push_str(&format!("  Files quarantined:       {}\n\n", fmt_num(r.quarantined_total)));

    out.push_str("ENDPOINT DETECTIONS\n");
    out.push_str(&format!("  Critical:   {}\n", fmt_num(r.endpoint_critical)));
    out.push_str(&format!("  High:       {}\n", fmt_num(r.endpoint_high)));
    out.push_str(&format!("  Medium:     {}\n", fmt_num(r.endpoint_medium)));
    out.push_str(&format!("  Low:        {}\n\n", fmt_num(r.endpoint_low)));

    if !r.top_detections.is_empty() {
        out.push_str("TOP DETECTIONS\n");
        for d in r.top_detections.iter().take(10) {
            out.push_str(&format!(
                "  [{}] {} — {} ({}) @ {}\n",
                d.severity.to_uppercase(),
                d.scanner,
                truncate(&d.description, 120),
                d.target,
                d.timestamp
            ));
        }
        out.push('\n');
    }

    out.push_str("— Secured by NexusShield · AutomataNexus LLC\n");
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let len = bytes.len();
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

fn fmt_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(critical: u64) -> DailyReport {
        DailyReport {
            date: "2026-04-12".into(),
            source: "automatanexus.com".into(),
            covered_hours: 24,
            requests_inspected: 14_523,
            blocked: 42,
            sql_injection: 3,
            ssrf: 1,
            path_traversal: 0,
            rate_limited: 187,
            auth_failures: 12,
            bans_issued: 2,
            unique_source_ips: 2_841,
            endpoint_critical: critical,
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
                    description: "UNION-based SQL injection attempted in /api/search q= parameter".into(),
                    target: "203.0.113.42".into(),
                    timestamp: "2026-04-12 14:22:18".into(),
                },
                TopDetection {
                    scanner: "network_monitor".into(),
                    severity: "High".into(),
                    description: "Scan burst — 412 connection attempts in 30s across 30 ports".into(),
                    target: "198.51.100.7".into(),
                    timestamp: "2026-04-12 09:41:02".into(),
                },
            ],
        }
    }

    #[test]
    fn renders_without_panic() {
        let html = render_html(&sample(0));
        assert!(html.contains("NexusShield"));
        assert!(html.contains("Daily Security Report"));
        assert!(html.contains("2026-04-12"));
    }

    #[test]
    fn subject_line_reflects_severity() {
        assert!(subject(&sample(3)).contains("CRITICAL"));
        let quiet = DailyReport {
            requests_inspected: 10,
            blocked: 0,
            ..sample(0)
        };
        let quiet = DailyReport {
            endpoint_high: 0,
            endpoint_medium: 0,
            endpoint_low: 0,
            sql_injection: 0,
            ssrf: 0,
            path_traversal: 0,
            rate_limited: 0,
            auth_failures: 0,
            bans_issued: 0,
            ..quiet
        };
        assert!(subject(&quiet).contains("all quiet"));
    }

    #[test]
    fn integrity_banner_shows_when_chain_invalid() {
        let mut r = sample(0);
        r.audit_chain_valid = false;
        let html = render_html(&r);
        assert!(html.contains("Audit chain integrity check FAILED"));
    }

    #[test]
    fn fmt_num_has_thousands_separators() {
        assert_eq!(fmt_num(0), "0");
        assert_eq!(fmt_num(999), "999");
        assert_eq!(fmt_num(1_000), "1,000");
        assert_eq!(fmt_num(14_523), "14,523");
        assert_eq!(fmt_num(1_234_567), "1,234,567");
    }

    #[test]
    fn xss_escaped_in_detection_description() {
        let mut r = sample(1);
        r.top_detections[0].description = "<script>alert('x')</script>".into();
        let html = render_html(&r);
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
