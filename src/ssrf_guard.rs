// ============================================================================
// File: ssrf_guard.rs
// Description: SSRF prevention with URL validation, IP blocking, and DNS rebinding defense
// Author: Andrew Jewell Sr. - AutomataNexus
// Updated: March 24, 2026
//
// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
//! SSRF Guard — Server-Side Request Forgery prevention.
//!
//! Validates URLs and IP addresses to prevent internal network probing,
//! cloud metadata endpoint access, and DNS rebinding attacks.

use crate::config::SsrfConfig;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

/// Validate a URL for SSRF safety. Returns Ok(()) if the URL is safe to request,
/// or Err(reason) if it should be blocked.
pub fn validate_url(raw_url: &str, config: &SsrfConfig) -> Result<(), String> {
    let parsed = Url::parse(raw_url).map_err(|e| format!("Invalid URL: {e}"))?;

    // Check scheme
    let scheme = parsed.scheme().to_lowercase();
    if !config.allowed_schemes.contains(&scheme) {
        return Err(format!(
            "URL scheme '{}' is not allowed. Allowed: {:?}",
            scheme, config.allowed_schemes
        ));
    }

    // Extract host
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    // Check explicit blocklist first
    if config.blocklist.contains(host) {
        return Err(format!("Host '{}' is in the blocklist", host));
    }

    // Check explicit allowlist (bypasses remaining checks)
    if config.allowlist.contains(host) {
        return Ok(());
    }

    // Check port
    if let Some(port) = parsed.port() {
        if config.blocked_ports.contains(&port) {
            return Err(format!(
                "Port {} is blocked (common internal service port)",
                port
            ));
        }
    }

    // Parse the host as an IP address and validate
    if let Ok(ip) = host.parse::<IpAddr>() {
        validate_ip(&ip, config)?;
    } else {
        // Host is a hostname — check for suspicious patterns
        validate_hostname(host, config)?;
    }

    Ok(())
}

/// Validate a raw IP address string (for connection_string IPs, controller_ip fields).
pub fn validate_ip_str(ip_str: &str, config: &SsrfConfig) -> Result<(), String> {
    // Check allowlist
    if config.allowlist.contains(ip_str) {
        return Ok(());
    }

    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| format!("Invalid IP address: {}", ip_str))?;
    validate_ip(&ip, config)
}

fn validate_ip(ip: &IpAddr, config: &SsrfConfig) -> Result<(), String> {
    match ip {
        IpAddr::V4(v4) => validate_ipv4(v4, config),
        IpAddr::V6(v6) => validate_ipv6(v6, config),
    }
}

fn validate_ipv4(ip: &Ipv4Addr, config: &SsrfConfig) -> Result<(), String> {
    let octets = ip.octets();

    // Loopback (127.0.0.0/8)
    if config.block_loopback && octets[0] == 127 {
        return Err(format!("Loopback address {} is blocked", ip));
    }

    // Private ranges
    if config.block_private_ips {
        // 10.0.0.0/8
        if octets[0] == 10 {
            return Err(format!("Private IP {} (10.0.0.0/8) is blocked", ip));
        }
        // 172.16.0.0/12
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return Err(format!("Private IP {} (172.16.0.0/12) is blocked", ip));
        }
        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return Err(format!("Private IP {} (192.168.0.0/16) is blocked", ip));
        }
    }

    // Link-local (169.254.0.0/16)
    if config.block_link_local && octets[0] == 169 && octets[1] == 254 {
        // Cloud metadata endpoint is the most critical to block
        if config.block_metadata_endpoints && octets[2] == 169 && octets[3] == 254 {
            return Err(format!(
                "Cloud metadata endpoint {} is blocked (CVE-class SSRF target)",
                ip
            ));
        }
        return Err(format!("Link-local address {} is blocked", ip));
    }

    // Broadcast
    if octets == [255, 255, 255, 255] {
        return Err("Broadcast address is blocked".to_string());
    }

    // 0.0.0.0
    if octets == [0, 0, 0, 0] {
        return Err("Unspecified address 0.0.0.0 is blocked".to_string());
    }

    Ok(())
}

fn validate_ipv6(ip: &Ipv6Addr, config: &SsrfConfig) -> Result<(), String> {
    // Loopback (::1)
    if config.block_loopback && ip.is_loopback() {
        return Err(format!("IPv6 loopback {} is blocked", ip));
    }

    // Unspecified (::)
    if ip.segments() == [0; 8] {
        return Err("IPv6 unspecified address :: is blocked".to_string());
    }

    // Link-local (fe80::/10)
    if config.block_link_local {
        let first_segment = ip.segments()[0];
        if first_segment & 0xffc0 == 0xfe80 {
            return Err(format!("IPv6 link-local address {} is blocked", ip));
        }
    }

    // IPv4-mapped IPv6 (::ffff:x.x.x.x) — check the embedded IPv4
    if let Some(v4) = ip.to_ipv4_mapped() {
        validate_ipv4(&v4, config)?;
    }

    Ok(())
}

fn validate_hostname(hostname: &str, config: &SsrfConfig) -> Result<(), String> {
    let lower = hostname.to_lowercase();

    // Block localhost variants
    if config.block_loopback
        && (lower == "localhost"
            || lower == "localhost.localdomain"
            || lower.ends_with(".localhost"))
    {
        return Err(format!("Hostname '{}' resolves to loopback", hostname));
    }

    // Block common cloud metadata hostnames
    if config.block_metadata_endpoints {
        let metadata_hosts = [
            "metadata.google.internal",
            "metadata.google",
            "169.254.169.254",
            "metadata",
        ];
        if metadata_hosts.iter().any(|h| lower == *h || lower.ends_with(h)) {
            return Err(format!(
                "Cloud metadata hostname '{}' is blocked",
                hostname
            ));
        }
    }

    // Block AWS metadata alternative
    if config.block_metadata_endpoints && lower == "instance-data" {
        return Err("AWS instance metadata hostname is blocked".to_string());
    }

    // Block internal TLDs
    let internal_tlds = [".internal", ".local", ".corp", ".home", ".lan"];
    if internal_tlds.iter().any(|tld| lower.ends_with(tld)) {
        return Err(format!(
            "Hostname '{}' uses an internal TLD which is blocked",
            hostname
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> SsrfConfig {
        SsrfConfig::default()
    }

    #[test]
    fn allows_public_url() {
        assert!(validate_url("http://influxdb.example.com:8086/api/v3/query_sql", &default_config()).is_ok());
    }

    #[test]
    fn allows_public_ip() {
        assert!(validate_url("http://203.0.113.50:8086/query", &default_config()).is_ok());
    }

    #[test]
    fn blocks_localhost() {
        assert!(validate_url("http://localhost:8086/query", &default_config()).is_err());
        assert!(validate_url("http://127.0.0.1:8086/query", &default_config()).is_err());
    }

    #[test]
    fn blocks_private_ips() {
        assert!(validate_url("http://10.0.0.1:8086/query", &default_config()).is_err());
        assert!(validate_url("http://172.16.0.1:8086/query", &default_config()).is_err());
        assert!(validate_url("http://192.168.1.1:8086/query", &default_config()).is_err());
    }

    #[test]
    fn blocks_cloud_metadata() {
        assert!(validate_url("http://169.254.169.254/latest/meta-data/", &default_config()).is_err());
        assert!(validate_url("http://metadata.google.internal/computeMetadata/v1/", &default_config()).is_err());
    }

    #[test]
    fn blocks_file_scheme() {
        assert!(validate_url("file:///etc/passwd", &default_config()).is_err());
    }

    #[test]
    fn blocks_internal_ports() {
        assert!(validate_url("http://203.0.113.50:22/exploit", &default_config()).is_err());
        assert!(validate_url("http://203.0.113.50:6379/CONFIG", &default_config()).is_err());
    }

    #[test]
    fn blocks_ipv6_loopback() {
        assert!(validate_ip_str("::1", &default_config()).is_err());
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1 should be blocked as loopback
        assert!(validate_ip_str("::ffff:127.0.0.1", &default_config()).is_err());
    }

    #[test]
    fn respects_allowlist() {
        let mut config = default_config();
        config.allowlist.insert("10.0.0.5".into());
        assert!(validate_url("http://10.0.0.5:9090/api", &config).is_ok());
    }

    #[test]
    fn blocks_internal_tlds() {
        assert!(validate_url("http://database.internal:5432/query", &default_config()).is_err());
        assert!(validate_url("http://redis.local:6379/", &default_config()).is_err());
    }
}
