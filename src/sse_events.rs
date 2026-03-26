// ============================================================================
// File: sse_events.rs
// Description: Server-Sent Events (SSE) endpoint for real-time security event
//              streaming to dashboards and monitoring tools
// Author: Andrew Jewell Sr. - AutomataNexus
// Updated: March 26, 2026
// ============================================================================
//! SSE Events — streams audit chain events and endpoint detections in real-time
//! via the `/events` HTTP endpoint using Server-Sent Events (text/event-stream).
//!
//! Clients receive a continuous stream of JSON events as they occur, eliminating
//! the need for polling. Compatible with EventSource API in browsers and any
//! HTTP client that supports SSE.

use crate::audit_chain::AuditChain;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::Stream;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

/// Create an SSE stream from the audit chain that polls for new events.
/// Returns an Axum-compatible SSE response.
pub fn audit_event_stream(
    audit: Arc<AuditChain>,
    poll_interval_ms: u64,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        let mut last_count = audit.len();

        loop {
            tokio::time::sleep(Duration::from_millis(poll_interval_ms)).await;

            let current_count = audit.len();
            if current_count > last_count {
                // Get new events since last check
                let new_count = current_count - last_count;
                let recent = audit.recent(new_count);

                for event in recent.iter().rev() {
                    let json = serde_json::json!({
                        "type": "audit_event",
                        "id": event.id,
                        "timestamp": event.timestamp.to_rfc3339(),
                        "event_type": format!("{:?}", event.event_type),
                        "source_ip": event.source_ip,
                        "details": event.details,
                        "threat_score": event.threat_score,
                        "chain_hash": event.hash,
                    });

                    let data = serde_json::to_string(&json).unwrap_or_default();
                    yield Ok::<_, Infallible>(
                        Event::default()
                            .event("security")
                            .data(data)
                            .id(event.id.clone())
                    );
                }

                last_count = current_count;
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("heartbeat"),
    )
}

/// Create an SSE stream from an endpoint detection broadcast channel.
pub fn detection_event_stream(
    mut rx: tokio::sync::broadcast::Receiver<crate::endpoint::ScanResult>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(result) => {
                    let json = serde_json::json!({
                        "type": "detection",
                        "id": result.id,
                        "timestamp": result.timestamp.to_rfc3339(),
                        "scanner": result.scanner,
                        "target": result.target,
                        "severity": result.severity.to_string(),
                        "description": result.description,
                        "confidence": result.confidence,
                        "action": result.action.to_string(),
                        "artifact_hash": result.artifact_hash,
                    });

                    let data = serde_json::to_string(&json).unwrap_or_default();
                    yield Ok::<_, Infallible>(
                        Event::default()
                            .event("detection")
                            .data(data)
                            .id(result.id.clone())
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    let json = serde_json::json!({
                        "type": "system",
                        "message": format!("Skipped {} events (client too slow)", n),
                    });
                    let data = serde_json::to_string(&json).unwrap_or_default();
                    yield Ok::<_, Infallible>(
                        Event::default().event("system").data(data)
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("heartbeat"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_chain_stream_creation() {
        let audit = Arc::new(AuditChain::new());
        // Should not panic
        let _sse = audit_event_stream(audit, 500);
    }

    #[test]
    fn detection_stream_creation() {
        let (tx, rx) = tokio::sync::broadcast::channel::<crate::endpoint::ScanResult>(16);
        let _sse = detection_event_stream(rx);
        drop(tx);
    }
}
