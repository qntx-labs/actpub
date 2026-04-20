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
//! - no allow-list (so no extra restriction);
//! - empty deny-list.
//!
//! Production deployments will typically extend the allow / deny lists
//! to match their threat model.

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
}

impl Default for UrlPolicy {
    fn default() -> Self {
        Self {
            require_https: true,
            forbid_ip_literals: true,
            forbid_loopback_hosts: true,
            allow_hosts: Vec::new(),
            deny_hosts: Vec::new(),
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

        if self.forbid_loopback_hosts
            && let Host::Domain(name) = &host
        {
            let lower = name.to_ascii_lowercase();
            #[allow(
                clippy::case_sensitive_file_extension_comparisons,
                reason = "`.local` is the mDNS link-local suffix, not a file extension; clippy's suggestion to detour through `std::path::Path::extension` would obscure intent and miss bare `localhost` cases"
            )]
            if lower == "localhost" || lower.ends_with(".local") {
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
