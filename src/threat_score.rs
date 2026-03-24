// ============================================================================
// File: threat_score.rs
// Description: Multi-signal threat scoring engine combining all Shield defense signals
// Author: Andrew Jewell Sr. - AutomataNexus
// Updated: March 24, 2026
//
// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
//! Threat Scoring Engine — Adaptive multi-signal threat assessment.
//!
//! Combines signals from the SQL firewall, SSRF guard, rate governor,
//! request fingerprinter, and behavioral history into a single threat
//! score (0.0–1.0). The score determines whether a request is allowed,
//! warned, or blocked.

use crate::fingerprint::RequestFingerprint;
use crate::rate_governor::RateCheckResult;

/// Weighted signals contributing to the overall threat score.
#[derive(Debug, Clone)]
pub struct ThreatSignals {
    /// Anomaly score from request fingerprinting (0.0–1.0).
    pub fingerprint_anomaly: f64,
    /// Rate limiting escalation severity (0.0–1.0).
    pub rate_pressure: f64,
    /// Behavioral anomaly from request history (0.0–1.0).
    pub behavioral_anomaly: f64,
    /// Whether this IP has recent security violations.
    pub recent_violations: bool,
}

/// Final threat assessment for a request.
#[derive(Debug, Clone)]
pub struct ThreatAssessment {
    /// Overall threat score (0.0 = safe, 1.0 = definitely malicious).
    pub score: f64,
    /// Individual signal contributions.
    pub signals: ThreatSignals,
    /// Recommended action based on the score.
    pub action: ThreatAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatAction {
    /// Allow the request to proceed normally.
    Allow,
    /// Allow but log a warning for review.
    Warn,
    /// Block the request with 403 Forbidden.
    Block,
}

/// Signal weights for the scoring algorithm.
const WEIGHT_FINGERPRINT: f64 = 0.30;
const WEIGHT_RATE: f64 = 0.25;
const WEIGHT_BEHAVIORAL: f64 = 0.30;
const WEIGHT_VIOLATIONS: f64 = 0.15;

/// Compute a threat assessment from available signals.
pub fn assess(
    fingerprint: &RequestFingerprint,
    rate_result: &RateCheckResult,
    behavioral_score: f64,
    has_recent_violations: bool,
    warn_threshold: f64,
    block_threshold: f64,
) -> ThreatAssessment {
    let rate_pressure = escalation_to_score(rate_result);

    let signals = ThreatSignals {
        fingerprint_anomaly: fingerprint.anomaly_score,
        rate_pressure,
        behavioral_anomaly: behavioral_score,
        recent_violations: has_recent_violations,
    };

    let violation_score = if has_recent_violations { 1.0 } else { 0.0 };

    let score = (signals.fingerprint_anomaly * WEIGHT_FINGERPRINT
        + signals.rate_pressure * WEIGHT_RATE
        + signals.behavioral_anomaly * WEIGHT_BEHAVIORAL
        + violation_score * WEIGHT_VIOLATIONS)
        .min(1.0);

    let action = if score >= block_threshold {
        ThreatAction::Block
    } else if score >= warn_threshold {
        ThreatAction::Warn
    } else {
        ThreatAction::Allow
    };

    ThreatAssessment {
        score,
        signals,
        action,
    }
}

fn escalation_to_score(rate_result: &RateCheckResult) -> f64 {
    use crate::rate_governor::EscalationLevel;
    match rate_result.escalation {
        EscalationLevel::None => 0.0,
        EscalationLevel::Warn => 0.3,
        EscalationLevel::Throttle => 0.6,
        EscalationLevel::Block => 0.9,
        EscalationLevel::Ban => 1.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::{FingerprintSignals, RequestFingerprint};
    use crate::rate_governor::{EscalationLevel, RateCheckResult};

    fn clean_fingerprint() -> RequestFingerprint {
        RequestFingerprint {
            hash: "abc".into(),
            signals: FingerprintSignals {
                has_user_agent: true,
                has_accept: true,
                has_accept_language: true,
                has_accept_encoding: true,
                has_referer: false,
                header_count: 5,
                header_order_hash: "def".into(),
                user_agent: "Mozilla/5.0".into(),
            },
            anomaly_score: 0.0,
        }
    }

    fn clean_rate() -> RateCheckResult {
        RateCheckResult {
            allowed: true,
            escalation: EscalationLevel::None,
            remaining: 100.0,
            retry_after: None,
            violations: 0,
        }
    }

    #[test]
    fn clean_request_allowed() {
        let result = assess(&clean_fingerprint(), &clean_rate(), 0.0, false, 0.4, 0.7);
        assert_eq!(result.action, ThreatAction::Allow);
        assert!(result.score < 0.1);
    }

    #[test]
    fn suspicious_fingerprint_warns() {
        let mut fp = clean_fingerprint();
        fp.anomaly_score = 0.9;
        // anomaly 0.9 * 0.30 + behavioral 0.8 * 0.30 = 0.27 + 0.24 = 0.51 > 0.4
        let result = assess(&fp, &clean_rate(), 0.8, false, 0.4, 0.7);
        assert!(
            matches!(result.action, ThreatAction::Warn | ThreatAction::Block),
            "High anomaly should trigger warn or block: {:?}",
            result
        );
    }

    #[test]
    fn multiple_bad_signals_block() {
        let mut fp = clean_fingerprint();
        fp.anomaly_score = 0.8;
        let rate = RateCheckResult {
            allowed: false,
            escalation: EscalationLevel::Block,
            remaining: 0.0,
            retry_after: None,
            violations: 20,
        };
        let result = assess(&fp, &rate, 0.7, true, 0.4, 0.7);
        assert_eq!(result.action, ThreatAction::Block);
    }
}
