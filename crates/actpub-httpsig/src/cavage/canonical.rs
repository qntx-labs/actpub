//! Building the Cavage signature base string.
//!
//! Per [Cavage draft-12 §2.3][canon] the "signing string" is formed from
//! the requested header list: each entry produces a single line of the
//! form `<name>: <value>`, except for the pseudo-headers
//! `(request-target)`, `(created)` and `(expires)`, which expand to
//! implementation-defined canonical values. Lines are joined with
//! `\n` (no trailing newline).
//!
//! [canon]: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.3

use http::Request;

use crate::error::Error;

/// The `(request-target)` pseudo-header.
pub(crate) const REQUEST_TARGET: &str = "(request-target)";

/// The `(created)` pseudo-header.
pub(crate) const CREATED: &str = "(created)";

/// The `(expires)` pseudo-header.
pub(crate) const EXPIRES: &str = "(expires)";

/// Which headers to include in the signature base string, in order.
///
/// The order is meaningful: it must exactly match the `headers="…"`
/// parameter emitted in the `Signature:` header so that verifiers can
/// reproduce the same string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CavageHeaderSet {
    names: Vec<String>,
}

impl CavageHeaderSet {
    /// Creates a header set from an iterator of lowercase header names
    /// (or pseudo-header tokens like `(request-target)`).
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            names: names.into_iter().map(Into::into).collect(),
        }
    }

    /// Iterates over the names in signing order.
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.names.iter()
    }

    /// Returns the space-separated `headers="…"` parameter value.
    #[must_use]
    pub fn join_spaces(&self) -> String {
        self.names.join(" ")
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

impl IntoIterator for CavageHeaderSet {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.names.into_iter()
    }
}

impl<'a> IntoIterator for &'a CavageHeaderSet {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.names.iter()
    }
}

impl<S: Into<String>> FromIterator<S> for CavageHeaderSet {
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        Self::new(iter)
    }
}

/// Parameters required to expand `(created)` / `(expires)`.
///
/// When the signer does not emit these pseudo-headers the values are
/// ignored. Verifiers receive them via [`CavageHeaderParams`](super::CavageHeaderParams).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Timestamps {
    pub created: Option<i64>,
    pub expires: Option<i64>,
}

/// Builds the canonical signature base string for `req` using `headers`.
///
/// # Errors
///
/// Returns [`Error::RequiredHeaderAbsent`] if any requested header is not
/// present on the request.
pub(crate) fn build_signature_base<B>(
    req: &Request<B>,
    headers: &CavageHeaderSet,
    timestamps: Timestamps,
) -> Result<String, Error> {
    if headers.is_empty() {
        return Err(Error::MalformedSignatureHeader(
            "`headers` parameter must not be empty".into(),
        ));
    }

    let mut out = String::new();
    for (i, name) in headers.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        write_line(req, name, timestamps, &mut out)?;
    }
    Ok(out)
}

#[allow(
    clippy::expect_used,
    clippy::unwrap_in_result,
    reason = "writing to an owned `String` via `core::fmt::Write` is infallible; the `Result` only exists to satisfy the trait"
)]
fn write_line<B>(
    req: &Request<B>,
    name: &str,
    ts: Timestamps,
    out: &mut String,
) -> Result<(), Error> {
    use core::fmt::Write as _;
    let infallible = "writing to an owned String is infallible";
    match name {
        REQUEST_TARGET => {
            let method = req.method().as_str().to_lowercase();
            let target = req
                .uri()
                .path_and_query()
                .map_or_else(|| req.uri().path().to_owned(), ToString::to_string);
            write!(out, "{REQUEST_TARGET}: {method} {target}").expect(infallible);
        }
        CREATED => {
            let value = ts
                .created
                .ok_or(Error::MissingSignatureParameter("created"))?;
            write!(out, "{CREATED}: {value}").expect(infallible);
        }
        EXPIRES => {
            let value = ts
                .expires
                .ok_or(Error::MissingSignatureParameter("expires"))?;
            write!(out, "{EXPIRES}: {value}").expect(infallible);
        }
        other => {
            let lowered = other.to_ascii_lowercase();
            let value = collect_header(req, &lowered)
                .ok_or_else(|| Error::RequiredHeaderAbsent(lowered.clone()))?;
            write!(out, "{lowered}: {value}").expect(infallible);
        }
    }
    Ok(())
}

/// Per Cavage §2.3 the canonical value of a repeated header is the
/// comma-separated concatenation of its values, in appearance order.
fn collect_header<B>(req: &Request<B>, lower_name: &str) -> Option<String> {
    let matches = req
        .headers()
        .iter()
        .filter(|(name, _)| name.as_str() == lower_name)
        .map(|(_, value)| value.to_str().unwrap_or("").trim());
    let mut joined = String::new();
    let mut seen = false;
    for value in matches {
        if seen {
            joined.push_str(", ");
        }
        seen = true;
        joined.push_str(value);
    }
    seen.then_some(joined)
}

#[cfg(test)]
mod tests {
    use http::{Method, Request};
    use pretty_assertions::assert_eq;

    use super::*;

    fn sample_request() -> Request<Vec<u8>> {
        Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox?a=1")
            .header("host", "example.com")
            .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
            .header("digest", "SHA-256=X48E9qOok=")
            .header("content-type", "application/activity+json")
            .body(Vec::new())
            .expect("valid request")
    }

    #[test]
    fn request_target_expands_to_lowercase_method_and_path_query() {
        let req = sample_request();
        let set = CavageHeaderSet::new([REQUEST_TARGET]);
        let base = build_signature_base(&req, &set, Timestamps::default()).unwrap();
        assert_eq!(base, "(request-target): post /inbox?a=1");
    }

    #[test]
    fn header_values_are_trimmed_and_lowercased_name() {
        let mut req = sample_request();
        req.headers_mut().insert(
            "x-custom",
            "   spaces around   ".parse().expect("valid header"),
        );
        let set = CavageHeaderSet::new(["Host", "X-Custom"]);
        let base = build_signature_base(&req, &set, Timestamps::default()).unwrap();
        assert_eq!(base, "host: example.com\nx-custom: spaces around");
    }

    #[test]
    fn missing_header_produces_required_header_absent() {
        let req = sample_request();
        let set = CavageHeaderSet::new(["authorization"]);
        let err = build_signature_base(&req, &set, Timestamps::default())
            .expect_err("missing header must error");
        match err {
            Error::RequiredHeaderAbsent(name) => assert_eq!(name, "authorization"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn full_cavage_default_base_string() {
        let req = sample_request();
        let set = CavageHeaderSet::new([REQUEST_TARGET, "host", "date", "digest"]);
        let base = build_signature_base(&req, &set, Timestamps::default()).unwrap();
        assert_eq!(
            base,
            "(request-target): post /inbox?a=1\n\
             host: example.com\n\
             date: Sun, 05 Jan 2014 21:31:40 GMT\n\
             digest: SHA-256=X48E9qOok=",
        );
    }

    #[test]
    fn created_and_expires_consume_timestamps() {
        let req = sample_request();
        let set = CavageHeaderSet::new([CREATED, EXPIRES]);
        let ts = Timestamps {
            created: Some(1_234_567_890),
            expires: Some(1_234_568_000),
        };
        let base = build_signature_base(&req, &set, ts).unwrap();
        assert_eq!(base, "(created): 1234567890\n(expires): 1234568000",);
    }

    #[test]
    fn repeated_header_values_are_concatenated_comma_space() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .header("forwarded", "for=1.1.1.1")
            .header("forwarded", "for=2.2.2.2")
            .body(Vec::<u8>::new())
            .expect("request");
        let set = CavageHeaderSet::new(["forwarded"]);
        let base = build_signature_base(&req, &set, Timestamps::default()).unwrap();
        assert_eq!(base, "forwarded: for=1.1.1.1, for=2.2.2.2");
    }
}
