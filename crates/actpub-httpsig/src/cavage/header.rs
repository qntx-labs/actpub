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
            let value = unquote(value)?;
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

        // Per draft §2.1.3: "If not specified, [headers] defaults to
        // the single value `(created)`. If the `created` signature
        // parameter is not provided, this parameter defaults to
        // the single value `date`."
        //
        // Fediverse actors always set `headers` explicitly, so the
        // defaulting branch is a pure fallback for spec-correctness.
        let headers = headers_field.map_or_else(
            || {
                if created.is_some() {
                    CavageHeaderSet::new(["(created)"])
                } else {
                    CavageHeaderSet::new(["date"])
                }
            },
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
    ///
    /// String-valued parameters (`keyId`, `algorithm`, `headers`,
    /// `signature`) are quoted and any `\` or `"` character inside
    /// them is backslash-escaped per the Cavage quoted-string grammar.
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "writing to an owned `String` via `core::fmt::Write` is infallible; the `Result` only exists to satisfy the trait"
    )]
    pub fn to_header_value(&self) -> String {
        use core::fmt::Write as _;
        let mut out = String::new();
        let infallible = "writing to an owned String is infallible";
        write!(out, r#"keyId="{}""#, escape_quoted(&self.key_id)).expect(infallible);
        if let Some(alg) = &self.algorithm {
            write!(out, r#",algorithm="{}""#, escape_quoted(alg)).expect(infallible);
        }
        write!(
            out,
            r#",headers="{}""#,
            escape_quoted(&self.headers.join_spaces()),
        )
        .expect(infallible);
        if let Some(c) = self.created {
            write!(out, ",created={c}").expect(infallible);
        }
        if let Some(e) = self.expires {
            write!(out, ",expires={e}").expect(infallible);
        }
        write!(out, r#",signature="{}""#, escape_quoted(&self.signature)).expect(infallible);
        out
    }
}

/// Applies the Cavage quoted-string escape rules: `\` → `\\` and
/// `"` → `\"`. All other bytes pass through unchanged.
fn escape_quoted(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Splits the raw header on top-level commas, skipping commas inside
/// double-quoted regions so that `signature="a,b,c"` does not break.
///
/// The scanner also honours the quoted-string escape sequence `\X`,
/// treating the next character as literal content. Without this a
/// payload containing `\"` would prematurely terminate the quoted
/// region and let an attacker inject additional parameter pairs.
fn split_top_level_commas(raw: &str) -> impl Iterator<Item = &str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in raw.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
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

fn unquote(raw: &str) -> Result<std::borrow::Cow<'_, str>, Error> {
    if raw.len() < 2 || !raw.starts_with('"') || !raw.ends_with('"') {
        return Ok(std::borrow::Cow::Borrowed(raw));
    }
    let inner = &raw[1..raw.len() - 1];
    if !inner.contains('\\') {
        return Ok(std::borrow::Cow::Borrowed(inner));
    }
    Ok(std::borrow::Cow::Owned(unescape(inner)?))
}

/// Unescapes a quoted-string body: `\<X>` becomes `<X>` for any
/// `<X>`. A trailing lone backslash is an encoding error and is
/// signalled by [`Error::MalformedSignatureHeader`] via the caller
/// re-wrapping; `unquote` upgrades the result to `Cow::Owned` only
/// after confirming the escape sequence is well-formed.
fn unescape(inner: &str) -> Result<String, Error> {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let next = chars.next().ok_or_else(|| {
                Error::MalformedSignatureHeader(
                    "quoted-string ends with a lone backslash".to_owned(),
                )
            })?;
            out.push(next);
        } else {
            out.push(c);
        }
    }
    Ok(out)
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

    #[test]
    fn missing_headers_parameter_with_created_defaults_to_created_pseudo() {
        // Per §2.1.3 the default `headers` value is `(created)` when
        // the `created` parameter is present.
        let raw = r#"keyId="k",created=1700000000,signature="Zm9v""#;
        let params = CavageHeaderParams::parse(raw).expect("parse");
        assert_eq!(params.headers.len(), 1);
        assert!(params.headers.iter().any(|h| h == "(created)"));
    }

    #[test]
    fn missing_headers_parameter_without_created_defaults_to_date() {
        // §2.1.3 falls back to `date` when both `headers` and
        // `created` are absent -- the Mastodon-compatible corner case.
        let raw = r#"keyId="k",signature="Zm9v""#;
        let params = CavageHeaderParams::parse(raw).expect("parse");
        assert_eq!(params.headers.len(), 1);
        assert!(params.headers.iter().any(|h| h == "date"));
    }

    #[test]
    fn escaped_double_quote_inside_quoted_string_survives_splitting() {
        // Without the escape-aware splitter this payload would split
        // early at the `"` inside `evil"`, dropping the `,attacker=`
        // trailer into a separate parameter.
        let raw = r#"keyId="legit\"evil",headers="host",signature="Zm9v""#;
        let params = CavageHeaderParams::parse(raw).expect("parse");
        assert_eq!(params.key_id, r#"legit"evil"#);
    }

    #[test]
    fn to_header_value_escapes_embedded_quote_and_backslash() {
        let raw = r#"keyId="legit\"evil\\trail",headers="host",signature="Zm9v""#;
        let params = CavageHeaderParams::parse(raw).expect("parse");
        let emitted = params.to_header_value();
        // Re-parsing must recover the same logical value.
        let reparsed = CavageHeaderParams::parse(&emitted).expect("reparse escaped");
        assert_eq!(reparsed.key_id, r#"legit"evil\trail"#);
        // And the escapes must actually be present on the wire.
        assert!(emitted.contains(r#"\""#));
        assert!(emitted.contains(r"\\"));
    }

    #[test]
    fn parameter_value_with_lone_trailing_backslash_is_rejected() {
        // A quoted value whose contents end in an unpaired backslash
        // is an encoding error: the parser has no way to know which
        // character the `\` was meant to escape.
        let raw = r#"keyId="abc\""#;
        let err = CavageHeaderParams::parse(raw).expect_err("malformed escape must fail");
        assert!(matches!(err, Error::MalformedSignatureHeader(_)));
    }
}
