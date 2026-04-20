//! Parsing and emitting the Cavage `Signature:` header value.
//!
//! The header is a comma-separated list of `name=value` pairs where
//! string-typed parameters (`keyId`, `algorithm`, `headers`, `signature`)
//! are double-quoted and numeric ones (`created`, `expires`) appear
//! without quotes. Parameter order is not significant.

use crate::cavage::canonical::CavageHeaderSet;
use crate::error::Error;

/// Name of the `Signature:` HTTP header.
pub const SIGNATURE_HEADER: &str = "signature";

/// Parsed `Signature:` header parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CavageHeaderParams {
    /// Reference to the public key to verify against.
    pub key_id: String,
    /// Algorithm hint; `None` means "detect from the key itself".
    pub algorithm: Option<String>,
    /// Which headers participate in the signature base string.
    pub headers: CavageHeaderSet,
    /// Base64-encoded signature bytes.
    pub signature: String,
    /// Optional `(created)` timestamp in seconds since the UNIX epoch.
    pub created: Option<i64>,
    /// Optional `(expires)` timestamp in seconds since the UNIX epoch.
    pub expires: Option<i64>,
}

impl CavageHeaderParams {
    /// Parses the raw `Signature:` header value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedSignatureHeader`] if the parameter list
    /// cannot be decoded, and [`Error::MissingSignatureParameter`] if
    /// `keyId` or `signature` is absent.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let mut key_id = None;
        let mut algorithm = None;
        let mut headers_field: Option<String> = None;
        let mut signature = None;
        let mut created = None;
        let mut expires = None;

        for pair in split_top_level_commas(raw) {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let (name, value) = split_once_trim(pair, '=').ok_or_else(|| {
                Error::MalformedSignatureHeader(format!("missing `=` in `{pair}`"))
            })?;
            let value = unquote(value);
            match name {
                "keyId" | "keyid" => key_id = Some(value.into_owned()),
                "algorithm" => algorithm = Some(value.into_owned()),
                "headers" => headers_field = Some(value.into_owned()),
                "signature" => signature = Some(value.into_owned()),
                "created" => created = Some(parse_i64_param("created", &value)?),
                "expires" => expires = Some(parse_i64_param("expires", &value)?),
                _ => {
                    // Unknown parameters are ignored per draft §2.1.
                }
            }
        }

        let key_id = key_id.ok_or(Error::MissingSignatureParameter("keyId"))?;
        let signature = signature.ok_or(Error::MissingSignatureParameter("signature"))?;

        // Per §2.1.3 default `headers` is `(created)`; if `created` is
        // absent the spec says implementations SHOULD send `date` instead.
        // Fediverse actors always set `headers` explicitly, so defaulting
        // is a pure fallback.
        let headers = headers_field.map_or_else(
            || CavageHeaderSet::new(["(created)"]),
            |v| CavageHeaderSet::new(v.split_ascii_whitespace().map(str::to_owned)),
        );

        Ok(Self {
            key_id,
            algorithm,
            headers,
            signature,
            created,
            expires,
        })
    }

    /// Serialises back into a `Signature:` header value.
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "writing to an owned `String` via `core::fmt::Write` is infallible; the `Result` only exists to satisfy the trait"
    )]
    pub fn to_header_value(&self) -> String {
        use core::fmt::Write as _;
        let mut out = String::new();
        let infallible = "writing to an owned String is infallible";
        write!(out, r#"keyId="{}""#, self.key_id).expect(infallible);
        if let Some(alg) = &self.algorithm {
            write!(out, r#",algorithm="{alg}""#).expect(infallible);
        }
        write!(out, r#",headers="{}""#, self.headers.join_spaces()).expect(infallible);
        if let Some(c) = self.created {
            write!(out, ",created={c}").expect(infallible);
        }
        if let Some(e) = self.expires {
            write!(out, ",expires={e}").expect(infallible);
        }
        write!(out, r#",signature="{}""#, self.signature).expect(infallible);
        out
    }
}

/// Splits the raw header on top-level commas, skipping commas inside
/// double-quoted regions so that `signature="a,b,c"` does not break.
fn split_top_level_commas(raw: &str) -> impl Iterator<Item = &str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    for (i, c) in raw.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(&raw[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&raw[start..]);
    parts.into_iter()
}

fn split_once_trim(s: &str, c: char) -> Option<(&str, &str)> {
    s.split_once(c).map(|(a, b)| (a.trim(), b.trim()))
}

fn parse_i64_param(name: &'static str, value: &str) -> Result<i64, Error> {
    value.parse::<i64>().map_err(|_| {
        Error::MalformedSignatureHeader(format!("`{name}` is not an integer: `{value}`"))
    })
}

fn unquote(raw: &str) -> std::borrow::Cow<'_, str> {
    if raw.len() < 2 || !raw.starts_with('"') || !raw.ends_with('"') {
        return std::borrow::Cow::Borrowed(raw);
    }
    let inner = &raw[1..raw.len() - 1];
    if !inner.contains('\\') {
        return std::borrow::Cow::Borrowed(inner);
    }
    std::borrow::Cow::Owned(unescape(inner))
}

fn unescape(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    const MASTODON_SAMPLE: &str = r#"keyId="https://mastodon.social/users/alice#main-key",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="Zm9v""#;

    #[test]
    fn parses_mastodon_style_header() {
        let params = CavageHeaderParams::parse(MASTODON_SAMPLE).expect("parse");
        assert_eq!(
            params.key_id,
            "https://mastodon.social/users/alice#main-key"
        );
        assert_eq!(params.algorithm.as_deref(), Some("rsa-sha256"));
        assert_eq!(params.headers.len(), 4);
        assert_eq!(params.signature, "Zm9v");
        assert_eq!(params.created, None);
        assert_eq!(params.expires, None);
    }

    #[test]
    fn header_roundtrips_through_serialisation() {
        let params = CavageHeaderParams::parse(MASTODON_SAMPLE).expect("parse");
        let emitted = params.to_header_value();
        let reparsed = CavageHeaderParams::parse(&emitted).expect("reparse");
        assert_eq!(reparsed, params);
    }

    #[test]
    fn missing_key_id_produces_specific_error() {
        let err =
            CavageHeaderParams::parse(r#"algorithm="rsa-sha256",headers="host",signature="Zm9v""#)
                .expect_err("missing keyId");
        assert!(matches!(err, Error::MissingSignatureParameter("keyId")));
    }

    #[test]
    fn missing_signature_produces_specific_error() {
        let err = CavageHeaderParams::parse(r#"keyId="foo",algorithm="rsa-sha256",headers="host""#)
            .expect_err("missing signature");
        assert!(matches!(err, Error::MissingSignatureParameter("signature")));
    }

    #[test]
    fn unquoted_parameters_are_tolerated() {
        // Some server implementations emit bare tokens for created/expires.
        let raw =
            r#"keyId="foo",headers="host",created=1700000000,expires=1700001000,signature="Zm9v""#;
        let params = CavageHeaderParams::parse(raw).expect("parse");
        assert_eq!(params.created, Some(1_700_000_000));
        assert_eq!(params.expires, Some(1_700_001_000));
    }

    #[test]
    fn unknown_parameters_are_silently_skipped() {
        let raw = r#"keyId="foo",headers="host",signature="Zm9v",future_thing="ignored""#;
        let params = CavageHeaderParams::parse(raw).expect("parse");
        assert_eq!(params.key_id, "foo");
    }

    #[test]
    fn commas_inside_quoted_signature_do_not_split_parameters() {
        let raw = r#"keyId="has,comma",headers="host",signature="ZmF,vo""#;
        let params = CavageHeaderParams::parse(raw).expect("parse");
        assert_eq!(params.key_id, "has,comma");
        assert_eq!(params.signature, "ZmF,vo");
    }
}
