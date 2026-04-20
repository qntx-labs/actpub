//! URL admission policy enforced before any IO.
//!
//! The federation runtime processes URLs that arrive from arbitrary
//! third parties. Without a guardrail an attacker who controls a
//! federated peer could direct our HTTP client at internal-network
//! addresses (SSRF), at `file://` schemes, or at hostile origins on
//! a deny-list. [`UrlPolicy`] is the central place those concerns are
//! enforced — a single check at the point where a `&Url` enters the
//! runtime, before the URL is handed to the cache, the fetcher, the
//! deliverer or the JSON parser.
//!
//! The default policy is intentionally strict:
//! - HTTPS only;
//! - no IP-literal hosts;
//! - no `localhost` / `*.local` hosts;
//! - no DNS names that resolve to a private / loopback / bogon IP;
//! - no hostnames ending in a bare dot (`example.com.` is a
//!   separate origin under RFC 3986 normalisation and would cause
//!   cache / same-origin confusion);
//! - no allow-list (so no extra restriction);
//! - empty deny-list.
//!
//! Production deployments will typically extend the allow / deny lists
//! to match their threat model.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::net::lookup_host;
use url::{Host, Url};

use crate::error::Error;

/// Admission policy a URL must pass before the federation runtime
/// will perform any IO on it.
///
/// Construct with [`UrlPolicy::default`] for the recommended baseline
/// and override individual fields as needed. Most fields are pure data
/// so a `..Default::default()` partial update is the idiomatic shape.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Each boolean toggles a distinct and orthogonal SSRF guard (scheme, IP literal, loopback name, DNS-resolved IP); collapsing them into bitflags would hide the per-rule intent from both operators and readers of the Debug output"
)]
pub struct UrlPolicy {
    /// Whether HTTPS is required. `true` by default; set to `false`
    /// only for in-process integration tests where the wiremock or
    /// httptest fixture cannot serve TLS.
    pub require_https: bool,

    /// Whether IP-literal hosts (`192.0.2.1`, `[::1]`, …) are
    /// forbidden. `true` by default, which blocks the most common
    /// SSRF target shape (private-range IP literals encoded into
    /// federated URLs).
    pub forbid_ip_literals: bool,

    /// Whether `localhost` and `.local`-suffix hostnames are
    /// forbidden. `true` by default, blocking another SSRF vector.
    pub forbid_loopback_hosts: bool,

    /// If non-empty, the host of every accepted URL MUST exactly
    /// equal one of these strings. `[]` (empty) by default, meaning
    /// no allow-list restriction.
    pub allow_hosts: Vec<String>,

    /// The host of any URL whose host appears here is rejected,
    /// regardless of [`allow_hosts`](Self::allow_hosts). `[]` by
    /// default.
    pub deny_hosts: Vec<String>,

    /// Whether the policy resolves DNS hostnames and refuses URLs
    /// whose A/AAAA records fall into a private, loopback,
    /// link-local, multicast, documentation, unspecified or
    /// broadcast range.
    ///
    /// This is the only defence against DNS-rebinding SSRF: an
    /// attacker controlling `pwn.example` cannot set its A record
    /// to `127.0.0.1` and have our fetcher connect to the local
    /// loopback. `true` by default; must be disabled in tests that
    /// fetch from `wiremock` / `httptest` listeners bound to
    /// `127.0.0.1`.
    pub forbid_private_resolved_ip: bool,
}

impl Default for UrlPolicy {
    fn default() -> Self {
        Self {
            require_https: true,
            forbid_ip_literals: true,
            forbid_loopback_hosts: true,
            allow_hosts: Vec::new(),
            deny_hosts: Vec::new(),
            forbid_private_resolved_ip: true,
        }
    }
}

impl UrlPolicy {
    /// Returns a permissive policy suitable for in-process tests:
    /// allows `http`, IP literals and loopback hosts. Production
    /// code MUST NOT use this profile.
    ///
    /// Gated behind the `test-util` Cargo feature (and unconditionally
    /// available inside `cfg(test)`) so that downstream crates cannot
    /// accidentally call it from production code paths. Integration
    /// tests that need a permissive profile should depend on this
    /// crate with `features = ["test-util"]`.
    #[must_use]
    #[cfg(any(test, feature = "test-util"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
    pub const fn permissive_for_tests() -> Self {
        Self {
            require_https: false,
            forbid_ip_literals: false,
            forbid_loopback_hosts: false,
            allow_hosts: Vec::new(),
            deny_hosts: Vec::new(),
            // `wiremock` and friends bind on 127.0.0.1; a strict
            // DNS-resolved-IP guard would break every integration
            // test that talks to them.
            forbid_private_resolved_ip: false,
        }
    }

    /// Validates `url` against this policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PolicyViolation`] with a human-readable
    /// `reason` when the URL fails any of the configured checks. The
    /// checks fire in the order listed on this struct so that the
    /// most fundamental violations (e.g. wrong scheme) are reported
    /// first.
    pub fn check(&self, url: &Url) -> Result<(), Error> {
        if self.require_https && url.scheme() != "https" {
            return Err(violation(
                url,
                format!("scheme `{}` is not allowed; expected `https`", url.scheme()),
            ));
        }
        if !matches!(url.scheme(), "https" | "http") {
            return Err(violation(
                url,
                format!("scheme `{}` is not an HTTP scheme", url.scheme()),
            ));
        }

        let host = url
            .host()
            .ok_or_else(|| violation(url, "URL has no host component".to_owned()))?;

        if self.forbid_ip_literals && matches!(host, Host::Ipv4(_) | Host::Ipv6(_)) {
            return Err(violation(
                url,
                "IP-literal hosts are forbidden (SSRF guard)".to_owned(),
            ));
        }

        if let Host::Domain(name) = &host {
            let lower = name.to_ascii_lowercase();
            if lower.ends_with('.') {
                return Err(violation(
                    url,
                    format!(
                        "host `{name}` ends in a trailing dot; normalise to `{}` before use",
                        lower.trim_end_matches('.'),
                    ),
                ));
            }
            if self.forbid_loopback_hosts && is_loopback_domain_name(&lower) {
                return Err(violation(
                    url,
                    format!("loopback host `{name}` is forbidden (SSRF guard)"),
                ));
            }
        }

        let host_str = host.to_string();
        if self.deny_hosts.iter().any(|h| h == &host_str) {
            return Err(violation(
                url,
                format!("host `{host_str}` is on the deny-list"),
            ));
        }
        if !self.allow_hosts.is_empty() && !self.allow_hosts.iter().any(|h| h == &host_str) {
            return Err(violation(
                url,
                format!("host `{host_str}` is not on the allow-list"),
            ));
        }
        Ok(())
    }

    /// Validates `url` against both the synchronous rules in
    /// [`check`](Self::check) and, when
    /// [`forbid_private_resolved_ip`](Self::forbid_private_resolved_ip)
    /// is set, an async DNS resolution of the hostname.
    ///
    /// Every runtime component that is about to open a TCP / TLS
    /// socket (fetcher, deliverer, webfinger / nodeinfo clients)
    /// SHOULD call this rather than [`check`](Self::check) so that
    /// DNS-rebinding SSRF is intercepted before the connection is
    /// attempted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PolicyViolation`] for any synchronous rule
    /// failure (as [`check`](Self::check)), or when the host
    /// resolves to at least one forbidden IP. DNS resolution
    /// failures also surface as [`Error::PolicyViolation`] (a peer
    /// whose name does not resolve is, for federation purposes,
    /// indistinguishable from a peer that refused to serve our
    /// request).
    pub async fn check_full(&self, url: &Url) -> Result<(), Error> {
        self.check(url)?;
        if self.forbid_private_resolved_ip {
            self.check_resolved_ip(url).await?;
        }
        Ok(())
    }

    /// Resolves `url`'s host and rejects it when any resulting IP
    /// address is private, loopback, link-local, multicast,
    /// documentation, unspecified, broadcast, or an IPv4-mapped
    /// IPv6 variant of any of the above.
    ///
    /// IP-literal hosts are classified directly without DNS. Raw
    /// IPs that appear here should already have been blocked by
    /// [`check`](Self::check) when [`forbid_ip_literals`](Self::forbid_ip_literals)
    /// is set; this method runs the bogon-IP check unconditionally
    /// as a defence-in-depth second opinion.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PolicyViolation`] when the host cannot be
    /// resolved, or when any resolved IP is forbidden. The error's
    /// `reason` field names the offending IP for operator triage.
    pub async fn check_resolved_ip(&self, url: &Url) -> Result<(), Error> {
        let host = url
            .host()
            .ok_or_else(|| violation(url, "URL has no host component".to_owned()))?;

        let ips: Vec<IpAddr> = match host {
            Host::Ipv4(v) => vec![IpAddr::V4(v)],
            Host::Ipv6(v) => vec![IpAddr::V6(v)],
            Host::Domain(name) => {
                // Port choice is arbitrary for resolution-only use; we
                // use 443 since every ActivityPub URL that reaches the
                // runtime SHOULD be HTTPS.
                lookup_host((name.to_owned(), 443))
                    .await
                    .map_err(|e| violation(url, format!("DNS resolution of `{name}` failed: {e}")))?
                    .map(|addr| addr.ip().to_canonical())
                    .collect()
            }
        };

        if ips.is_empty() {
            return Err(violation(
                url,
                "DNS resolver returned no addresses".to_owned(),
            ));
        }
        for ip in ips {
            if is_forbidden_ip(ip) {
                return Err(violation(
                    url,
                    format!("host resolves to forbidden IP `{ip}` (SSRF guard)"),
                ));
            }
        }
        Ok(())
    }
}

/// Whether `lower` (already ASCII-lowercased) is a loopback-style
/// hostname that federation MUST reject: bare `localhost` or
/// anything ending in the mDNS link-local suffix `.local`.
#[allow(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "`.local` is the mDNS link-local suffix, not a file extension; clippy's suggestion to detour through `std::path::Path::extension` would obscure intent and miss bare `localhost` cases"
)]
fn is_loopback_domain_name(lower: &str) -> bool {
    lower == "localhost" || lower.ends_with(".local")
}

/// Whether `ip` is an address that must not appear in any
/// federation-bound URL: private, loopback, link-local, multicast,
/// documentation, unspecified, or broadcast.
///
/// IPv6 addresses are also classified by projecting IPv4-mapped
/// variants back to IPv4 so that `::ffff:127.0.0.1` is treated
/// identically to `127.0.0.1`.
fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_forbidden(v4),
        IpAddr::V6(v6) => v6_is_forbidden(v6),
    }
}

const fn v4_is_forbidden(v4: Ipv4Addr) -> bool {
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_broadcast()
}

fn v6_is_forbidden(v6: Ipv6Addr) -> bool {
    v6.is_loopback()
        || v6.is_multicast()
        || v6.is_unique_local()
        || v6.is_unicast_link_local()
        || v6.is_unspecified()
        || v6_is_documentation(v6)
        || v6.to_ipv4_mapped().is_some_and(v4_is_forbidden)
}

/// Matches the IPv6 documentation prefixes `2001:db8::/32`
/// (RFC 3849) and `3fff::/20` (RFC 9637). `Ipv6Addr::is_documentation`
/// is still nightly-only as of Rust 1.82, so we classify by hand.
const fn v6_is_documentation(v6: Ipv6Addr) -> bool {
    matches!(
        v6.segments(),
        [0x2001, 0x0db8, ..] | [0x3fff, 0..=0x0fff, ..]
    )
}

fn violation(url: &Url, reason: String) -> Error {
    Error::PolicyViolation {
        url: url.clone(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn url(s: &str) -> Url {
        s.parse().unwrap()
    }

    #[test]
    fn default_policy_accepts_plain_https_with_dns_host() {
        UrlPolicy::default()
            .check(&url("https://example.com/users/alice"))
            .expect("vanilla HTTPS URL must pass");
    }

    #[test]
    fn default_policy_rejects_http_scheme() {
        let err = UrlPolicy::default()
            .check(&url("http://example.com/"))
            .expect_err("HTTP must fail strict policy");
        assert!(matches!(err, Error::PolicyViolation { .. }));
    }

    #[test]
    fn default_policy_rejects_non_http_scheme() {
        let err = UrlPolicy::default()
            .check(&url("file:///etc/passwd"))
            .expect_err("file:// scheme must always fail");
        assert!(matches!(err, Error::PolicyViolation { .. }));
    }

    #[test]
    fn default_policy_rejects_ipv4_literal_host() {
        let err = UrlPolicy::default()
            .check(&url("https://192.0.2.1/"))
            .expect_err("IPv4 literal must fail SSRF guard");
        let Error::PolicyViolation { reason, .. } = &err else {
            panic!("wrong variant: {err:?}");
        };
        assert!(reason.contains("IP-literal"));
    }

    #[test]
    fn default_policy_rejects_ipv6_literal_host() {
        let err = UrlPolicy::default()
            .check(&url("https://[::1]/"))
            .expect_err("IPv6 literal must fail SSRF guard");
        assert!(matches!(err, Error::PolicyViolation { .. }));
    }

    #[test]
    fn default_policy_rejects_localhost() {
        let err = UrlPolicy::default()
            .check(&url("https://localhost/"))
            .expect_err("localhost must fail SSRF guard");
        let Error::PolicyViolation { reason, .. } = &err else {
            panic!("wrong variant: {err:?}");
        };
        assert!(reason.contains("loopback"));
    }

    #[test]
    fn default_policy_rejects_dot_local() {
        let err = UrlPolicy::default()
            .check(&url("https://printer.local/"))
            .expect_err("`.local` mDNS hosts must fail SSRF guard");
        assert!(matches!(err, Error::PolicyViolation { .. }));
    }

    #[test]
    fn deny_list_blocks_listed_host() {
        let p = UrlPolicy {
            deny_hosts: vec!["bad.example".to_owned()],
            ..UrlPolicy::default()
        };
        let err = p
            .check(&url("https://bad.example/"))
            .expect_err("denied host");
        let Error::PolicyViolation { reason, .. } = &err else {
            panic!("wrong variant: {err:?}");
        };
        assert!(reason.contains("deny-list"));
    }

    #[test]
    fn allow_list_blocks_unlisted_host() {
        let p = UrlPolicy {
            allow_hosts: vec!["good.example".to_owned()],
            ..UrlPolicy::default()
        };
        let err = p
            .check(&url("https://other.example/"))
            .expect_err("non-allow-listed host");
        let Error::PolicyViolation { reason, .. } = &err else {
            panic!("wrong variant: {err:?}");
        };
        assert!(reason.contains("allow-list"));
    }

    #[test]
    fn allow_list_admits_listed_host() {
        let p = UrlPolicy {
            allow_hosts: vec!["good.example".to_owned()],
            ..UrlPolicy::default()
        };
        p.check(&url("https://good.example/u/1"))
            .expect("listed host must be admitted");
    }

    #[test]
    fn permissive_for_tests_admits_loopback_http_url() {
        UrlPolicy::permissive_for_tests()
            .check(&url("http://127.0.0.1:8080/inbox"))
            .expect("test profile must admit loopback HTTP");
    }

    #[test]
    fn default_policy_rejects_host_ending_in_trailing_dot() {
        let err = UrlPolicy::default()
            .check(&url("https://example.com./"))
            .expect_err("trailing-dot host must fail");
        let Error::PolicyViolation { reason, .. } = &err else {
            panic!("wrong variant: {err:?}");
        };
        assert!(
            reason.contains("trailing dot"),
            "reason should explain the trailing-dot rule: {reason}",
        );
    }

    #[tokio::test]
    async fn check_resolved_ip_rejects_loopback_literal() {
        // Synchronously admits the URL (we opt out of the IP-literal
        // rule for this case) and relies on the resolved-IP check to
        // catch it.
        let p = UrlPolicy {
            forbid_ip_literals: false,
            forbid_loopback_hosts: false,
            require_https: false,
            ..UrlPolicy::default()
        };
        let err = p
            .check_resolved_ip(&url("http://127.0.0.1:8080/"))
            .await
            .expect_err("loopback literal must fail resolved-IP check");
        let Error::PolicyViolation { reason, .. } = &err else {
            panic!("wrong variant: {err:?}");
        };
        assert!(
            reason.contains("127.0.0.1"),
            "reason must name the offending IP: {reason}",
        );
    }

    #[tokio::test]
    async fn check_resolved_ip_rejects_private_ipv4_literal() {
        let p = UrlPolicy {
            forbid_ip_literals: false,
            forbid_loopback_hosts: false,
            require_https: false,
            ..UrlPolicy::default()
        };
        let err = p
            .check_resolved_ip(&url("http://10.0.0.1/"))
            .await
            .expect_err("RFC1918 literal must fail resolved-IP check");
        assert!(matches!(err, Error::PolicyViolation { .. }));
    }

    #[tokio::test]
    async fn check_resolved_ip_rejects_ipv4_mapped_loopback_in_ipv6() {
        let p = UrlPolicy {
            forbid_ip_literals: false,
            forbid_loopback_hosts: false,
            require_https: false,
            ..UrlPolicy::default()
        };
        // `::ffff:127.0.0.1` — IPv4-mapped loopback must be classified
        // as loopback too; otherwise a dual-stack peer can escape the
        // check.
        let err = p
            .check_resolved_ip(&url("http://[::ffff:127.0.0.1]/"))
            .await
            .expect_err("IPv4-mapped loopback must fail");
        assert!(matches!(err, Error::PolicyViolation { .. }));
    }

    #[tokio::test]
    async fn check_full_skips_dns_when_policy_opts_out() {
        // `forbid_private_resolved_ip = false` must skip DNS
        // entirely, otherwise integration tests against `localhost`-
        // bound mocks would stall on a resolver round-trip.
        let p = UrlPolicy::permissive_for_tests();
        p.check_full(&url("http://127.0.0.1:8080/"))
            .await
            .expect("permissive profile must admit loopback without touching DNS");
    }

    #[test]
    fn deny_list_takes_precedence_over_allow_list() {
        let p = UrlPolicy {
            allow_hosts: vec!["host.example".to_owned()],
            deny_hosts: vec!["host.example".to_owned()],
            ..UrlPolicy::default()
        };
        let err = p
            .check(&url("https://host.example/"))
            .expect_err("deny-list must win even when host is allow-listed");
        let Error::PolicyViolation { reason, .. } = &err else {
            panic!("wrong variant: {err:?}");
        };
        assert_eq!(
            reason.contains("deny-list"),
            true,
            "the deny-list rule fires before the allow-list rule",
        );
    }
}
