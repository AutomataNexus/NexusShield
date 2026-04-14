// ============================================================================
// File: signature_updater.rs
// Description: Automatic signature database updates from a remote NDJSON feed
// Author: Andrew Jewell Sr. - AutomataNexus
// Updated: March 26, 2026
// ============================================================================
//! Signature Updater — periodically fetches malware signatures from a remote
//! NDJSON feed and updates the local signature database.
//!
//! Configure via config.toml:
//! ```toml
//! [signature_update]
//! feed_url = "https://signatures.nexusshield.dev/v1/latest.ndjson"
//! interval_secs = 3600
//! ```

use crate::config::SignatureUpdateConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Start the signature update background task.
///
/// `signatures_path` is wrapped in `Arc` so the caller can retain a reference
/// to the path being updated (e.g., to display the active signatures file in a
/// status page) without duplicating the allocation.
///
/// Returns a shutdown sender to stop the task.
pub fn start_updater(
    config: SignatureUpdateConfig,
    signatures_path: Arc<std::path::PathBuf>,
) -> (tokio::task::JoinHandle<()>, watch::Sender<bool>) {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(async move {
        let interval = Duration::from_secs(config.interval_secs);
        tracing::info!(
            url = %config.feed_url,
            interval_secs = config.interval_secs,
            "Signature auto-updater started"
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {},
                _ = shutdown_rx.changed() => {
                    tracing::info!("Signature updater shutting down");
                    return;
                }
            }

            match fetch_signatures(&config).await {
                Ok(content) => {
                    if content.trim().is_empty() {
                        tracing::debug!("Signature feed returned empty content, skipping");
                        continue;
                    }

                    let line_count = content.lines().count();

                    // Validate NDJSON format
                    let mut valid = true;
                    for (i, line) in content.lines().enumerate() {
                        if line.trim().is_empty() {
                            continue;
                        }
                        if serde_json::from_str::<serde_json::Value>(line).is_err() {
                            tracing::warn!(
                                line = i + 1,
                                "Invalid JSON in signature feed, aborting update"
                            );
                            valid = false;
                            break;
                        }
                    }

                    if valid {
                        // Atomic write: write to temp, then rename
                        // Deref Arc<PathBuf> → PathBuf → Path for path operations
                        let tmp_path = (**signatures_path).with_extension("ndjson.tmp");
                        if let Err(e) = std::fs::write(&tmp_path, &content) {
                            tracing::error!(error = %e, "Failed to write temp signature file");
                            continue;
                        }
                        if let Err(e) = std::fs::rename(&tmp_path, &**signatures_path) {
                            tracing::error!(error = %e, "Failed to rename signature file");
                            continue;
                        }

                        tracing::info!(
                            signatures = line_count,
                            "Signature database updated from remote feed"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to fetch signature update");
                }
            }
        }
    });

    (handle, shutdown_tx)
}

/// Fetch signatures from the remote URL.
async fn fetch_signatures(config: &SignatureUpdateConfig) -> Result<String, String> {
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http::<axum::body::Body>();

    let uri: hyper::Uri = config
        .feed_url
        .parse()
        .map_err(|e| format!("invalid feed URL: {}", e))?;

    let mut builder = hyper::Request::builder().method("GET").uri(uri);

    if let Some(ref auth) = config.auth_header {
        builder = builder.header("Authorization", auth.as_str());
    }

    let req = builder
        .body(axum::body::Body::empty())
        .map_err(|e| format!("request build error: {}", e))?;

    let resp = client
        .request(req)
        .await
        .map_err(|e| format!("fetch failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("feed returned status {}", resp.status()));
    }

    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .map_err(|e| format!("body read error: {}", e))?
        .to_bytes();

    String::from_utf8(body.to_vec()).map_err(|e| format!("invalid UTF-8: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ndjson_good() {
        let content =
            "{\"name\":\"test\",\"hash\":\"abc\"}\n{\"name\":\"test2\",\"hash\":\"def\"}\n";
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
        }
    }

    #[test]
    fn validate_ndjson_bad() {
        let content = "not json at all\n";
        for line in content.lines() {
            assert!(serde_json::from_str::<serde_json::Value>(line).is_err());
        }
    }

    #[test]
    fn config_defaults() {
        let config = SignatureUpdateConfig {
            feed_url: "https://example.com/sigs.ndjson".to_string(),
            interval_secs: 3600,
            auth_header: None,
        };
        assert_eq!(config.interval_secs, 3600);
        assert!(config.auth_header.is_none());
    }
}
