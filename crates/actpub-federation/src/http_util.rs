//! Tiny helpers shared by the outbound HTTP paths
//! ([`crate::deliver`], [`crate::fetcher`]).

use url::Url;

/// Formats the `host` header value that must go into the HTTP
/// signature base **and** onto the wire.
///
/// Why not just `url.host_str()`? Because `Url::host_str` returns
/// only the host, never the port. A signer that binds
/// `host: example.com` into the signature base produces a signature
/// that does NOT match what `reqwest` actually sends when the URL
/// carries a non-default port — `reqwest` (per RFC 7230 §5.4) will
/// emit `Host: example.com:8443`, and any peer rebuilding the
/// signature base from the wire will recompute
/// `"host: example.com:8443"` and fail verification.
///
/// The format mirrors RFC 7230 `Host = uri-host [ ":" port ]`:
///
/// - `https://example.com/inbox`  → `example.com`
/// - `https://example.com:8443/inbox` → `example.com:8443`
///
/// Default scheme ports (80 for http, 443 for https) are **kept
/// implicit** — `Url::port()` returns `None` for those — so a plain
/// `https://example.com/inbox` still hashes as `host: example.com`,
/// matching every Mastodon-compatible deployment in the wild.
///
/// Hostless URLs (e.g. `file:` or malformed inputs that somehow
/// slipped past policy admission) render as the empty string so the
/// caller produces a deterministic — and easily rejected — signature
/// base rather than panicking.
pub(crate) fn host_for_signing(url: &Url) -> String {
    match (url.host_str(), url.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_owned(),
        (None, _) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn default_port_is_omitted_for_https() {
        let url: Url = "https://example.com/inbox".parse().unwrap();
        assert_eq!(host_for_signing(&url), "example.com");
    }

    #[test]
    fn default_port_is_omitted_for_http() {
        let url: Url = "http://example.com/inbox".parse().unwrap();
        assert_eq!(host_for_signing(&url), "example.com");
    }

    #[test]
    fn non_default_port_is_appended_after_colon() {
        // P0-4 regression: Url::host_str() by itself produces
        // `example.com`, but reqwest actually sends
        // `Host: example.com:8443`. Signing only `host: example.com`
        // would then produce a signature that fails verification at
        // the peer (base rebuilt with port). The signer MUST use
        // exactly what reqwest puts on the wire.
        let url: Url = "https://example.com:8443/inbox".parse().unwrap();
        assert_eq!(host_for_signing(&url), "example.com:8443");
    }

    #[test]
    fn non_default_http_port_is_appended() {
        let url: Url = "http://example.com:8080/inbox".parse().unwrap();
        assert_eq!(host_for_signing(&url), "example.com:8080");
    }

    #[test]
    fn ipv6_literal_host_is_preserved_verbatim() {
        // The `url` crate already emits `[…]` brackets around IPv6
        // literals; we must not strip them.
        let url: Url = "https://[::1]:8443/inbox".parse().unwrap();
        assert_eq!(host_for_signing(&url), "[::1]:8443");
    }

    #[test]
    fn hostless_url_renders_as_empty_string() {
        // `file:` URLs have no host; the helper MUST not panic.
        let url: Url = "file:///etc/hosts".parse().unwrap();
        assert_eq!(host_for_signing(&url), "");
    }
}
