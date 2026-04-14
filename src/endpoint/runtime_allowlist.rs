// ============================================================================
// File: endpoint/runtime_allowlist.rs
// Description: In-memory allowlist additions applied at runtime by the
//              security-ticker + shield agent after user approval. Not
//              persisted to config.toml — lost on shield restart. To make
//              a fix permanent, edit config.toml directly.
// Author: Andrew Jewell Sr. - AutomataNexus
// ============================================================================
//! Runtime allowlist — supplements the static on-disk allowlist with
//! entries the shield agent proposed and the user accepted via the
//! security-ticker drill-down modal.
//!
//! Checked alongside the static [`NetworkMonitorConfig::allowlist_cidrs`]
//! and [`NetworkMonitorConfig::allowlist_processes`] during every scan.
//! Adding an entry here is a hot operation — no restart required.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// Shared runtime allowlist state. Cloned (Arc) into NetworkMonitor so the
/// scan loop and the HTTP handlers can read/write the same lists.
#[derive(Debug, Default)]
pub struct RuntimeAllowlist {
    /// Additional IPv4 CIDRs to treat as benign, beyond the static config.
    cidrs: RwLock<Vec<String>>,
    /// Additional process comms to treat as benign, beyond the static
    /// config (case-insensitive match).
    processes: RwLock<Vec<String>>,
}

impl RuntimeAllowlist {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn add_cidr(&self, cidr: impl Into<String>) {
        let c = cidr.into();
        let mut list = self.cidrs.write();
        if !list.iter().any(|existing| existing == &c) {
            list.push(c);
        }
    }

    pub fn add_process(&self, comm: impl Into<String>) {
        let c = comm.into();
        let mut list = self.processes.write();
        if !list.iter().any(|existing| existing.eq_ignore_ascii_case(&c)) {
            list.push(c);
        }
    }

    pub fn cidrs_snapshot(&self) -> Vec<String> {
        self.cidrs.read().clone()
    }

    pub fn processes_snapshot(&self) -> Vec<String> {
        self.processes.read().clone()
    }

    pub fn contains_process(&self, comm: &str) -> bool {
        self.processes
            .read()
            .iter()
            .any(|c| c.eq_ignore_ascii_case(comm))
    }
}

/// Snapshot of the runtime allowlist, used for JSON responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeAllowlistSnapshot {
    pub cidrs: Vec<String>,
    pub processes: Vec<String>,
}

impl From<&RuntimeAllowlist> for RuntimeAllowlistSnapshot {
    fn from(a: &RuntimeAllowlist) -> Self {
        Self {
            cidrs: a.cidrs_snapshot(),
            processes: a.processes_snapshot(),
        }
    }
}

/// Which list to append to when persisting to config.toml.
#[derive(Debug, Clone, Copy)]
pub enum PersistKind {
    Cidr,
    Process,
}

/// Append a value to `runtime_allowlist_cidrs` or
/// `runtime_allowlist_processes` in the on-disk config.toml while
/// preserving every comment and the formatting of every other key.
///
/// Creates the array if it doesn't exist yet. No-op (returns Ok) if
/// the value is already present. Uses `toml_edit` so existing top-of-file
/// comments ("# NexusShield gateway config") survive the write.
///
/// Best-effort: if the path can't be written (e.g. permission denied
/// when shield runs as a less privileged user), the caller should log
/// the error but NOT fail the HTTP request — the in-memory state is
/// still updated and will protect until the next restart.
pub fn persist_allowlist_entry(
    config_path: &Path,
    kind: PersistKind,
    value: &str,
) -> Result<(), String> {
    let key = match kind {
        PersistKind::Cidr => "runtime_allowlist_cidrs",
        PersistKind::Process => "runtime_allowlist_processes",
    };

    let contents = std::fs::read_to_string(config_path)
        .map_err(|e| format!("read {}: {e}", config_path.display()))?;

    let mut doc: toml_edit::DocumentMut = contents
        .parse()
        .map_err(|e| format!("parse {}: {e}", config_path.display()))?;

    // Ensure the key exists as an array. If missing, insert a new array.
    if doc.get(key).is_none() {
        let mut arr = toml_edit::Array::new();
        arr.push(value);
        doc[key] = toml_edit::value(arr);
    } else {
        let item = doc
            .get_mut(key)
            .ok_or_else(|| format!("{key}: vanished between checks"))?;
        let arr = item
            .as_array_mut()
            .ok_or_else(|| format!("{key}: exists but is not an array"))?;
        // Dedupe: skip write if value is already in the array.
        let already = arr
            .iter()
            .any(|v| v.as_str().map(|s| s == value).unwrap_or(false));
        if already {
            return Ok(());
        }
        arr.push(value);
    }

    // Write back via a temp file in the same dir to avoid torn writes —
    // config.toml is mode 640 and read by the service at startup.
    let tmp = config_path.with_extension("toml.tmp");
    std::fs::write(&tmp, doc.to_string())
        .map_err(|e| format!("write tmp {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, config_path)
        .map_err(|e| format!("rename {}: {e}", tmp.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_cidr_dedupes() {
        let a = RuntimeAllowlist::default();
        a.add_cidr("45.33.0.0/16");
        a.add_cidr("45.33.0.0/16");
        assert_eq!(a.cidrs_snapshot().len(), 1);
    }

    #[test]
    fn add_process_dedupes_case_insensitive() {
        let a = RuntimeAllowlist::default();
        a.add_process("Ollama");
        a.add_process("ollama");
        assert_eq!(a.processes_snapshot().len(), 1);
    }

    #[test]
    fn contains_process_case_insensitive() {
        let a = RuntimeAllowlist::default();
        a.add_process("ollama");
        assert!(a.contains_process("OLLAMA"));
        assert!(!a.contains_process("chrome"));
    }

    #[test]
    fn persist_preserves_comments_and_appends() {
        let dir = tempdir();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "# NexusShield gateway config\n# line two\n\napi_token = \"abc\"\n",
        )
        .unwrap();

        persist_allowlist_entry(&path, PersistKind::Cidr, "45.33.0.0/16").unwrap();
        persist_allowlist_entry(&path, PersistKind::Cidr, "50.116.0.0/16").unwrap();
        // Dedup path
        persist_allowlist_entry(&path, PersistKind::Cidr, "45.33.0.0/16").unwrap();
        persist_allowlist_entry(&path, PersistKind::Process, "ollama").unwrap();

        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.contains("# NexusShield gateway config"), "top comment survived");
        assert!(out.contains("# line two"), "second comment survived");
        assert!(out.contains("api_token = \"abc\""), "api_token preserved");
        assert!(out.contains("45.33.0.0/16"));
        assert!(out.contains("50.116.0.0/16"));
        assert!(out.contains("ollama"));
        // Only one copy of the duplicated CIDR
        assert_eq!(out.matches("45.33.0.0/16").count(), 1);

        // Round-trip: serde should parse the same back into ShieldConfig's shape
        #[derive(serde::Deserialize)]
        struct Partial {
            #[serde(default)]
            runtime_allowlist_cidrs: Vec<String>,
            #[serde(default)]
            runtime_allowlist_processes: Vec<String>,
        }
        let p: Partial = toml::from_str(&out).unwrap();
        assert_eq!(p.runtime_allowlist_cidrs.len(), 2);
        assert_eq!(p.runtime_allowlist_processes, vec!["ollama".to_string()]);

        let _ = std::fs::remove_file(&path);
    }

    fn tempdir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nexus-shield-runtime-allowlist-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
