// ============================================================================
// File: webhook.rs
// Description: Webhook alerts — fire HTTP POST to Slack, Discord, or generic
//              endpoints on security detections
// Author: Andrew Jewell Sr. - AutomataNexus
// Updated: March 26, 2026
// ============================================================================
//! Webhook — sends real-time alerts to Slack, Discord, PagerDuty, or any
//! HTTP endpoint when security events exceed a severity threshold.

use crate::audit_chain::AuditEvent;
use crate::config::WebhookConfig;

/// Send an alert to all configured webhooks that match the severity threshold.
pub async fn fire_webhooks(event: &AuditEvent, webhooks: &[WebhookConfig]) {
    for webhook in webhooks {
        if !meets_severity(event.threat_score, &webhook.min_severity) {
            continue;
        }

        let payload = match webhook.webhook_type.as_str() {
            "slack" => format_slack(event),
            "discord" => format_discord(event),
            _ => format_generic(event),
        };

        let _ = send_webhook(&webhook.url, &payload, &webhook.headers).await;
    }
}

fn meets_severity(score: f64, min: &str) -> bool {
    let threshold = match min {
        "critical" => 0.9,
        "high" => 0.7,
        "medium" => 0.5,
        "low" => 0.3,
        _ => 0.0, // "info" or anything else = all events
    };
    score >= threshold
}

fn format_slack(event: &AuditEvent) -> String {
    let severity = score_label(event.threat_score);
    let emoji = match severity {
        "CRITICAL" => ":rotating_light:",
        "HIGH" => ":warning:",
        "MEDIUM" => ":large_orange_diamond:",
        _ => ":information_source:",
    };
    serde_json::json!({
        "text": format!(
            "{} *NexusShield Alert — {}*\n*Type:* `{:?}`\n*Source:* `{}`\n*Score:* `{:.3}`\n*Details:* {}",
            emoji, severity, event.event_type, event.source_ip, event.threat_score, event.details
        )
    }).to_string()
}

fn format_discord(event: &AuditEvent) -> String {
    let severity = score_label(event.threat_score);
    let color = match severity {
        "CRITICAL" => 0xFF0000,
        "HIGH" => 0xFF6600,
        "MEDIUM" => 0xFFCC00,
        _ => 0x00CC00,
    };
    serde_json::json!({
        "embeds": [{
            "title": format!("NexusShield — {}", severity),
            "color": color,
            "fields": [
                {"name": "Event Type", "value": format!("{:?}", event.event_type), "inline": true},
                {"name": "Source IP", "value": &event.source_ip, "inline": true},
                {"name": "Threat Score", "value": format!("{:.3}", event.threat_score), "inline": true},
                {"name": "Details", "value": &event.details, "inline": false},
            ],
            "timestamp": event.timestamp.to_rfc3339(),
        }]
    }).to_string()
}

fn format_generic(event: &AuditEvent) -> String {
    serde_json::json!({
        "source": "nexus-shield",
        "severity": score_label(event.threat_score),
        "event_type": format!("{:?}", event.event_type),
        "source_ip": event.source_ip,
        "threat_score": event.threat_score,
        "details": event.details,
        "timestamp": event.timestamp.to_rfc3339(),
        "event_id": event.id,
    })
    .to_string()
}

fn score_label(score: f64) -> &'static str {
    match score {
        s if s >= 0.9 => "CRITICAL",
        s if s >= 0.7 => "HIGH",
        s if s >= 0.5 => "MEDIUM",
        s if s >= 0.3 => "LOW",
        _ => "INFO",
    }
}

async fn send_webhook(
    url: &str,
    body: &str,
    extra_headers: &[(String, String)],
) -> Result<(), String> {
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http::<axum::body::Body>();

    let uri: hyper::Uri = url.parse().map_err(|e| format!("bad webhook URL: {}", e))?;

    let mut builder = hyper::Request::builder()
        .method("POST")
        .uri(uri)
        .header("Content-Type", "application/json");

    for (k, v) in extra_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    let req = builder
        .body(axum::body::Body::from(body.to_string()))
        .map_err(|e| format!("request build error: {}", e))?;

    match client.request(req).await {
        Ok(resp) => {
            if resp.status().is_success() {
                Ok(())
            } else {
                Err(format!("webhook returned {}", resp.status()))
            }
        }
        Err(e) => Err(format!("webhook request failed: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_threshold_matching() {
        assert!(meets_severity(0.95, "critical"));
        assert!(!meets_severity(0.8, "critical"));
        assert!(meets_severity(0.7, "high"));
        assert!(!meets_severity(0.5, "high"));
        assert!(meets_severity(0.5, "medium"));
        assert!(meets_severity(0.0, "info"));
    }

    #[test]
    fn slack_format() {
        let event = test_event(0.9);
        let payload = format_slack(&event);
        assert!(payload.contains("NexusShield Alert"));
        assert!(payload.contains("CRITICAL"));
        assert!(payload.contains("rotating_light"));
    }

    #[test]
    fn discord_format() {
        let event = test_event(0.75);
        let payload = format_discord(&event);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(
            parsed["embeds"][0]["title"]
                .as_str()
                .unwrap()
                .contains("HIGH")
        );
    }

    #[test]
    fn generic_format() {
        let event = test_event(0.5);
        let payload = format_generic(&event);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["source"], "nexus-shield");
        assert_eq!(parsed["severity"], "MEDIUM");
    }

    #[test]
    fn score_labels() {
        assert_eq!(score_label(1.0), "CRITICAL");
        assert_eq!(score_label(0.9), "CRITICAL");
        assert_eq!(score_label(0.7), "HIGH");
        assert_eq!(score_label(0.5), "MEDIUM");
        assert_eq!(score_label(0.3), "LOW");
        assert_eq!(score_label(0.1), "INFO");
    }

    fn test_event(score: f64) -> AuditEvent {
        AuditEvent {
            id: "test".to_string(),
            timestamp: chrono::Utc::now(),
            event_type: crate::audit_chain::SecurityEventType::RequestBlocked,
            source_ip: "10.0.0.1".to_string(),
            details: "test detection".to_string(),
            threat_score: score,
            previous_hash: "0".to_string(),
            hash: "abc".to_string(),
        }
    }
}
