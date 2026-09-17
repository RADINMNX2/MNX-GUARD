//! DNS over HTTPS (RFC 8484).
//!
//! The endpoint is an **IP literal** by default, so resolving it never needs
//! DNS itself: there is no bootstrap step and no chance of recursion. Payloads
//! are the raw `application/dns-message` wire format, posted over HTTPS.
//!
//! Failure is never fatal: every error path returns `None` so the caller falls
//! back to the in-tunnel plaintext resolver in `socks::dns_exchange`. A wrong
//! endpoint can therefore cost latency but cannot break name resolution.

use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

use crate::socks::{build_dns_query, dns_response_matches, parse_dns_a, QTYPE_A};

/// Cloudflare's DoH resolver, addressed directly by IP. `1.1.1.1` is also a
/// valid HTTPS name, so the certificate carries an IP SAN and verification
/// stays on.
const DEFAULT_URL: &str = "https://1.1.1.1/dns-query";

static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();

/// DoH is on unless `AETHER_DOH` is one of the explicit off spellings.
pub fn enabled() -> bool {
    match std::env::var("AETHER_DOH") {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "false" | "no"
        ),
        Err(_) => true,
    }
}

fn endpoint() -> String {
    std::env::var("AETHER_DOH_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_URL.to_string())
}

/// Escape hatch for an endpoint whose certificate is not publicly trusted.
/// Off by default; only `AETHER_DOH_INSECURE` turns it on.
fn insecure() -> bool {
    matches!(
        std::env::var("AETHER_DOH_INSECURE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn client() -> Option<&'static reqwest::Client> {
    CLIENT
        .get_or_init(|| {
            let builder = reqwest::Client::builder()
                .timeout(Duration::from_secs(4))
                .user_agent("mnx-guard-doh/1");
            let builder = if insecure() {
                builder.danger_accept_invalid_certs(true)
            } else {
                builder
            };
            match builder.build() {
                Ok(client) => Some(client),
                Err(error) => {
                    log::debug!("doh: client build failed: {error}");
                    None
                }
            }
        })
        .as_ref()
}

/// Resolve an A record over DNS-over-HTTPS.
///
/// Returns `None` when DoH is disabled or the exchange fails for any reason,
/// so the caller can fall back to plaintext DNS immediately.
pub async fn resolve(name: &str) -> Option<IpAddr> {
    if !enabled() {
        return None;
    }
    let client = client()?;
    let (query, id) = build_dns_query(name, QTYPE_A);

    let response = match client
        .post(endpoint())
        .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .body(query)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            log::debug!("doh: {name} request failed: {error}");
            return None;
        }
    };
    if !response.status().is_success() {
        log::debug!("doh: {name} HTTP {}", response.status());
        return None;
    }

    let body = match response.bytes().await {
        Ok(body) => body,
        Err(error) => {
            log::debug!("doh: {name} body read failed: {error}");
            return None;
        }
    };
    if !dns_response_matches(&body, id, name, QTYPE_A) {
        log::debug!("doh: {name} reply did not match the query");
        return None;
    }
    match parse_dns_a(&body) {
        Some(ip) => {
            log::debug!("doh: {name} -> {ip}");
            Some(ip)
        }
        None => {
            log::debug!("doh: {name} returned no A record");
            None
        }
    }
}
