// ============================================================================
// NexusShield — Local Security Gateway
// Runs as a reverse proxy with full threat defense stack
// Author: Andrew Jewell Sr. - AutomataNexus
// ============================================================================

use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    Extension,
    extract::Request,
    middleware,
    response::{IntoResponse, Response},
    http::StatusCode,
    routing::get,
};
use clap::Parser;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use http_body_util::BodyExt;
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, fmt};

use nexus_shield::{
    Shield, ShieldConfig, shield_middleware,
    audit_chain::SecurityEventType,
};

#[derive(Parser, Debug)]
#[command(name = "nexus-shield", about = "NexusShield Local Security Gateway")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Upstream target to proxy to (e.g., http://localhost:3000)
    #[arg(short, long)]
    upstream: Option<String>,

    /// Config file path
    #[arg(short, long, default_value = "/etc/nexus-shield/config.toml")]
    config: String,

    /// Block threshold (0.0-1.0)
    #[arg(long, default_value = "0.7")]
    block_threshold: f64,

    /// Warn threshold (0.0-1.0)
    #[arg(long, default_value = "0.4")]
    warn_threshold: f64,

    /// Requests per second per IP
    #[arg(long, default_value = "50")]
    rps: f64,

    /// Enable standalone mode (no upstream, just shield + status)
    #[arg(long, default_value = "false")]
    standalone: bool,
}

#[tokio::main]
async fn main() {
    // Initialize logging
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,nexus_shield=debug")),
        )
        .with_target(true)
        .with_thread_ids(false)
        .init();

    let args = Args::parse();

    tracing::info!(
        r#"
    ╔══════════════════════════════════════════════╗
    ║            NexusShield v0.1.0                ║
    ║     Adaptive Zero-Trust Security Gateway     ║
    ║          AutomataNexus Engineering            ║
    ╚══════════════════════════════════════════════╝
    "#
    );

    // Build shield config
    let mut config = ShieldConfig::default();
    config.block_threshold = args.block_threshold;
    config.warn_threshold = args.warn_threshold;
    config.rate.requests_per_second = args.rps;

    let shield = Arc::new(Shield::new(config));

    // Clone for background tasks
    let shield_bg = shield.clone();

    // Background: prune stale data every 60 seconds
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            shield_bg.rate_governor.prune_stale(Duration::from_secs(600));
            shield_bg.fingerprinter.prune_stale(600);
            shield_bg.email_limiter.prune();
            tracing::debug!("Pruned stale security state");
        }
    });

    // Clone for audit export
    let shield_status = shield.clone();
    let shield_audit = shield.clone();
    let shield_stats = shield.clone();

    let app = if args.standalone || args.upstream.is_none() {
        // Standalone mode: shield + status endpoints
        tracing::info!("Running in standalone mode (no upstream proxy)");
        Router::new()
            .route("/health", get(|| async { "NexusShield OK" }))
            .route("/status", get(move || async move {
                status_handler(shield_status.clone()).await
            }))
            .route("/audit", get(move || async move {
                audit_handler(shield_audit.clone()).await
            }))
            .route("/stats", get(move || async move {
                stats_handler(shield_stats.clone()).await
            }))
            .fallback(|| async {
                (StatusCode::OK, "NexusShield: request inspected and allowed")
            })
            .layer(middleware::from_fn(shield_middleware))
            .layer(Extension(shield.clone()))
    } else {
        // Proxy mode: shield + reverse proxy to upstream
        let upstream = args.upstream.clone().unwrap();
        tracing::info!(upstream = %upstream, "Running in reverse proxy mode");

        let client = Client::builder(TokioExecutor::new()).build_http();
        let upstream = Arc::new(upstream);

        let proxy_upstream = upstream.clone();
        let proxy_client = Arc::new(client);

        Router::new()
            .route("/health", get(|| async { "NexusShield OK" }))
            .route("/status", get(move || async move {
                status_handler(shield_status.clone()).await
            }))
            .route("/audit", get(move || async move {
                audit_handler(shield_audit.clone()).await
            }))
            .route("/stats", get(move || async move {
                stats_handler(shield_stats.clone()).await
            }))
            .fallback(move |req: Request| {
                let upstream = proxy_upstream.clone();
                let client = proxy_client.clone();
                async move {
                    proxy_handler(req, &upstream, &client).await
                }
            })
            .layer(middleware::from_fn(shield_middleware))
            .layer(Extension(shield.clone()))
    };

    let addr = format!("0.0.0.0:{}", args.port);
    tracing::info!(listen = %addr, "NexusShield gateway starting");

    let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
    tracing::info!(
        "NexusShield active — protecting on port {}",
        args.port
    );

    axum::serve(listener, app)
        .await
        .expect("Server failed");
}

async fn proxy_handler(
    mut req: Request,
    upstream: &str,
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, axum::body::Body>,
) -> Response {
    let path = req.uri().path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let upstream_uri = format!("{}{}", upstream, path);

    match upstream_uri.parse::<hyper::Uri>() {
        Ok(uri) => {
            *req.uri_mut() = uri;
            match client.request(req).await {
                Ok(resp) => {
                    let (parts, body) = resp.into_parts();
                    let bytes = body.collect().await
                        .map(|b| b.to_bytes())
                        .unwrap_or_default();
                    Response::from_parts(parts, axum::body::Body::from(bytes))
                }
                Err(e) => {
                    tracing::error!(error = %e, "Upstream request failed");
                    (StatusCode::BAD_GATEWAY, "Upstream unavailable").into_response()
                }
            }
        }
        Err(_) => {
            (StatusCode::BAD_REQUEST, "Invalid upstream URI").into_response()
        }
    }
}

async fn status_handler(shield: Arc<Shield>) -> impl IntoResponse {
    let chain_verification = shield.audit.verify_chain();
    let audit_count = shield.audit.len();

    let status = serde_json::json!({
        "service": "NexusShield",
        "version": "0.1.0",
        "status": "active",
        "config": {
            "block_threshold": shield.config.block_threshold,
            "warn_threshold": shield.config.warn_threshold,
            "rate_rps": shield.config.rate.requests_per_second,
            "rate_burst": shield.config.rate.burst_capacity,
        },
        "audit_chain": {
            "total_events": audit_count,
            "chain_valid": chain_verification.valid,
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
            "threat_score",
        ]
    });

    (StatusCode::OK, axum::Json(status))
}

async fn audit_handler(shield: Arc<Shield>) -> impl IntoResponse {
    let recent = shield.audit.recent(50);
    let events: Vec<serde_json::Value> = recent.iter().map(|e| {
        serde_json::json!({
            "id": e.id,
            "timestamp": e.timestamp.to_rfc3339(),
            "event_type": format!("{:?}", e.event_type),
            "source_ip": e.source_ip,
            "details": e.details,
            "threat_score": e.threat_score,
        })
    }).collect();

    (StatusCode::OK, axum::Json(serde_json::json!({
        "recent_events": events,
        "total": shield.audit.len(),
        "chain_valid": shield.audit.verify_chain().valid,
    })))
}

async fn stats_handler(shield: Arc<Shield>) -> impl IntoResponse {
    let now = chrono::Utc::now();
    let last_hour = now - chrono::Duration::hours(1);
    let last_5min = now - chrono::Duration::minutes(5);

    let stats = serde_json::json!({
        "last_5min": {
            "blocked": shield.audit.count_since(&SecurityEventType::RequestBlocked, last_5min),
            "rate_limited": shield.audit.count_since(&SecurityEventType::RateLimitHit, last_5min),
            "sql_injection": shield.audit.count_since(&SecurityEventType::SqlInjectionAttempt, last_5min),
            "ssrf": shield.audit.count_since(&SecurityEventType::SsrfAttempt, last_5min),
        },
        "last_hour": {
            "blocked": shield.audit.count_since(&SecurityEventType::RequestBlocked, last_hour),
            "rate_limited": shield.audit.count_since(&SecurityEventType::RateLimitHit, last_hour),
            "sql_injection": shield.audit.count_since(&SecurityEventType::SqlInjectionAttempt, last_hour),
            "ssrf": shield.audit.count_since(&SecurityEventType::SsrfAttempt, last_hour),
        },
        "total_audit_events": shield.audit.len(),
    });

    (StatusCode::OK, axum::Json(stats))
}
