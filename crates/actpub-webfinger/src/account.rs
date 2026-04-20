//! Parsing and formatting of `acct:` URIs (RFC 7565).

use std::fmt;
use std::str::FromStr;

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::Error;

/// Characters that must be percent-encoded inside the `resource=` query
/// parameter value. This follows RFC 3986 `query` component rules but keeps
/// the `:` and `@` intact since they appear in every `acct:user@host` URI
/// and Fediverse servers universally expect them unencoded.
const RESOURCE_QUERY: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'&')
    .add(b'=')
    .add(b'+')
    .add(b'%');

/// A Fediverse account identifier of the form `acct:user@host`.
///
/// See [RFC 7565](https://www.rfc-editor.org/rfc/rfc7565) for the canonical
/// definition of the `acct:` URI scheme.
///
/// # Examples
///
/// ```
/// # use actpub_webfinger::Account;
/// let a = Account::parse("acct:alice@example.com").unwrap();
/// assert_eq!(a.user(), "alice");
/// assert_eq!(a.host(), "example.com");
/// assert_eq!(a.to_string(), "acct:alice@example.com");
///
/// // Leading `@` is tolerated:
/// assert_eq!(Account::parse("@alice@example.com").unwrap(), a);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Account {
    user: String,
    host: String,
}

impl Account {
    /// Constructs an [`Account`] from its components.
    ///
    /// Both must be non-empty. The host is normalised using IDNA 2008
    /// (Unicode → ASCII Punycode, lowercased) per
    /// [RFC 7565 §7][rfc7565-7], so internationalised domain names are
    /// accepted and stored in their canonical Punycode form.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidAcct`] if `user` or `host` is empty, or if
    /// `host` contains characters that IDNA cannot map to a valid DNS
    /// label.
    ///
    /// [rfc7565-7]: https://www.rfc-editor.org/rfc/rfc7565#section-7
    pub fn new(user: impl Into<String>, host: impl Into<String>) -> Result<Self, Error> {
        let user = user.into();
        let host_raw = host.into();
        if user.is_empty() || host_raw.is_empty() {
            return Err(Error::InvalidAcct("empty user or host".into()));
        }
        let host_ascii = idna::domain_to_ascii(&host_raw)
            .map_err(|e| Error::InvalidAcct(format!("invalid IDN host `{host_raw}`: {e}")))?;
        if host_ascii.is_empty() {
            return Err(Error::InvalidAcct(format!(
                "host `{host_raw}` maps to an empty IDNA label"
            )));
        }
        Ok(Self {
            user,
            host: host_ascii,
        })
    }

    /// Parses a string into an [`Account`].
    ///
    /// Accepts the following forms:
    ///
    /// - `acct:user@host`
    /// - `@user@host`
    /// - `user@host`
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidAcct`] if the string does not match any of
    /// the supported forms or if any component is empty.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let body = input
            .strip_prefix("acct:")
            .or_else(|| input.strip_prefix('@'))
            .unwrap_or(input);

        let (user, host) = body
            .split_once('@')
            .ok_or_else(|| Error::InvalidAcct(format!("missing `@`: {input}")))?;

        if user.is_empty() || host.is_empty() {
            return Err(Error::InvalidAcct(format!("empty user or host: {input}")));
        }
        if user.contains('@') || host.contains('@') {
            return Err(Error::InvalidAcct(format!(
                "unexpected additional `@`: {input}"
            )));
        }

        Self::new(user, host)
    }

    /// Returns the local-part (username).
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// Returns the host component (always lowercase).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the resource URI in canonical `acct:` form.
    #[must_use]
    pub fn to_resource(&self) -> String {
        format!("acct:{}@{}", self.user, self.host)
    }

    /// Builds the `https://{host}/.well-known/webfinger?resource=…` URL for
    /// this account.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidUrl`] if the host is not a valid authority.
    pub fn webfinger_url(&self) -> Result<Url, Error> {
        self.webfinger_url_with_scheme("https")
    }

    /// Builds the `{scheme}://{host}/.well-known/webfinger?resource=…` URL
    /// for this account, allowing the caller to override the scheme.
    ///
    /// Production code should always use [`Self::webfinger_url`] to ensure
    /// `https`. The override exists to support test fixtures, local
    /// development, and Tor hidden-service endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidUrl`] if the resulting URL is malformed.
    pub fn webfinger_url_with_scheme(&self, scheme: &str) -> Result<Url, Error> {
        let resource = self.to_resource();
        let encoded = percent_encode(&resource);
        let raw = format!(
            "{scheme}://{host}{path}?resource={encoded}",
            host = self.host,
            path = crate::WELL_KNOWN_PATH,
        );
        Ok(Url::parse(&raw)?)
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "acct:{}@{}", self.user, self.host)
    }
}

impl FromStr for Account {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for Account {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Account> for String {
    fn from(a: Account) -> Self {
        a.to_string()
    }
}

/// Percent-encodes the `resource=` query-string value.
///
/// Uses the RFC 3986 `query` component set but leaves `:` and `@` intact,
/// since these appear in every `acct:user@host` URI and Fediverse servers
/// universally accept (and in practice require) them unencoded.
fn percent_encode(input: &str) -> String {
    utf8_percent_encode(input, RESOURCE_QUERY).to_string()
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn parses_acct_prefix() {
        let a = Account::parse("acct:alice@example.com").unwrap();
        assert_eq!(a.user(), "alice");
        assert_eq!(a.host(), "example.com");
    }

    #[test]
    fn parses_at_prefix() {
        let a = Account::parse("@alice@example.com").unwrap();
        assert_eq!(a.host(), "example.com");
    }

    #[test]
    fn parses_bare_form() {
        let a = Account::parse("alice@example.com").unwrap();
        assert_eq!(a.to_resource(), "acct:alice@example.com");
    }

    #[test]
    fn normalises_host_to_lowercase() {
        let a = Account::parse("acct:Alice@EXAMPLE.COM").unwrap();
        assert_eq!(a.host(), "example.com");
        // But preserves user case per RFC 7565 §7.
        assert_eq!(a.user(), "Alice");
    }

    #[test]
    fn idna_normalises_unicode_host_to_punycode() {
        // Unicode domain label should be converted to ASCII Punycode.
        let a = Account::parse("acct:alice@例え.jp").unwrap();
        assert_eq!(a.host(), "xn--r8jz45g.jp");
    }

    #[test]
    fn idna_rejects_invalid_unicode_labels() {
        // Contains a label that is not valid per IDNA.
        assert!(Account::new("alice", "\u{FDD0}.jp").is_err());
    }

    #[test]
    fn rejects_missing_at() {
        assert!(Account::parse("acct:alice").is_err());
    }

    #[test]
    fn rejects_empty_components() {
        assert!(Account::parse("acct:@example.com").is_err());
        assert!(Account::parse("acct:alice@").is_err());
    }

    #[test]
    fn rejects_extra_at() {
        assert!(Account::parse("acct:alice@evil@example.com").is_err());
    }

    #[test]
    fn builds_webfinger_url() {
        let a = Account::parse("acct:alice@example.com").unwrap();
        let url = a.webfinger_url().unwrap();
        assert_eq!(
            url.as_str(),
            "https://example.com/.well-known/webfinger?resource=acct:alice@example.com"
        );
    }

    #[test]
    fn roundtrips_through_serde() {
        let a = Account::parse("acct:alice@example.com").unwrap();
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, r#""acct:alice@example.com""#);
        let back: Account = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }
}
