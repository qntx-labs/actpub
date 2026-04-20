//! Derived components and header references for RFC 9421 signatures.
//!
//! The signature base is a sequence of lines, each of the form
//! `"<component-identifier>": <canonicalised-value>`. Identifiers starting
//! with `@` are "derived components" computed from the request itself;
//! all others name HTTP headers. This module implements the subset
//! actually used by real-world `ActivityPub` deployments:
//!
//! | Identifier        | Value                                    |
//! | ----------------- | ---------------------------------------- |
//! | `@method`         | HTTP method, upper-case                  |
//! | `@target-uri`     | full request target URL                  |
//! | `@authority`      | `Host` header / authority, lowercase     |
//! | `@scheme`         | scheme, lowercase (`http` / `https`)     |
//! | `@path`           | URI path                                 |
//! | `@query`          | URI query string including the `?`, `?` when absent |
//! | `@request-target` | `<path-and-query>` (method excluded per §2.2.5)      |
//! | `<header-name>`   | comma-joined values, OWS-trimmed         |
//!
//! `@query-param`, `@status` and the `;req`, `;bs`, `;sf`, `;tr`, `;name`
//! parameters are intentionally out of scope for the initial release;
//! they can be added when a real interoperator demands them.

use http::Request;

use crate::error::Error;
use crate::http_shared::collect_canonical_header_value;

/// A single component in an RFC 9421 signature base.
///
/// The [`Component::lexical`] representation is the quoted string that
/// appears in the signature base and in the `Signature-Input:` header
/// inner list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Component {
    /// HTTP method (upper-case).
    Method,
    /// Full request target URI.
    TargetUri,
    /// Authority (`host` equivalent).
    Authority,
    /// Request scheme (`http` / `https`).
    Scheme,
    /// URI path component.
    Path,
    /// URI query component including the leading `?`. When the
    /// request URI has no query, the canonical value is the
    /// single character `?` per [RFC 9421 §2.2.7][q].
    ///
    /// [q]: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.7
    Query,
    /// `@request-target` derived component: path and query of the
    /// request target, **without the method**, per
    /// [RFC 9421 §2.2.5][rt]. This is semantically distinct from
    /// Cavage's `(request-target)` pseudo-header which does include
    /// the method; the Cavage signer / verifier handles that shape
    /// in [`crate::cavage`] independently.
    ///
    /// [rt]: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.5
    RequestTarget,
    /// An ordinary lower-cased HTTP header name.
    Header(String),
}

impl Component {
    /// Returns the quoted lexical form that appears in a `Signature-Input:`
    /// inner list and in the signature base.
    #[must_use]
    pub fn lexical(&self) -> String {
        format!(r#""{}""#, self.identifier())
    }

    /// Returns the raw identifier without quotes.
    #[must_use]
    pub fn identifier(&self) -> &str {
        match self {
            Self::Method => "@method",
            Self::TargetUri => "@target-uri",
            Self::Authority => "@authority",
            Self::Scheme => "@scheme",
            Self::Path => "@path",
            Self::Query => "@query",
            Self::RequestTarget => "@request-target",
            Self::Header(name) => name,
        }
    }

    /// Parses an identifier back into a [`Component`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedAlgorithm`] for any `@`-prefixed
    /// identifier that is not one of the seven supported derived
    /// components (`@method`, `@target-uri`, `@authority`, `@scheme`,
    /// `@path`, `@query`, `@request-target`). Header names are accepted
    /// verbatim and lower-cased.
    pub fn parse(identifier: &str) -> Result<Self, Error> {
        if !identifier.starts_with('@') {
            return Ok(Self::Header(identifier.to_ascii_lowercase()));
        }
        Ok(match identifier {
            "@method" => Self::Method,
            "@target-uri" => Self::TargetUri,
            "@authority" => Self::Authority,
            "@scheme" => Self::Scheme,
            "@path" => Self::Path,
            "@query" => Self::Query,
            "@request-target" => Self::RequestTarget,
            other => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "derived component `{other}` is not supported"
                )));
            }
        })
    }
}

/// Canonicalises a component's value against `req`.
///
/// # Errors
///
/// Returns [`Error::RequiredHeaderAbsent`] when a header reference
/// cannot be resolved on the request.
pub(crate) fn canonical_value<B>(component: &Component, req: &Request<B>) -> Result<String, Error> {
    match component {
        Component::Method => Ok(req.method().as_str().to_uppercase()),
        Component::TargetUri => Ok(target_uri(req)),
        Component::Authority => Ok(authority(req)),
        Component::Scheme => Ok(scheme(req)),
        Component::Path => Ok(req.uri().path().to_owned()),
        Component::Query => Ok(query_with_leading_q(req)),
        Component::RequestTarget => Ok(request_target(req)),
        Component::Header(name) => header_value(req, name),
    }
}

fn target_uri<B>(req: &Request<B>) -> String {
    let scheme = scheme(req);
    let authority = authority(req);
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or_else(|| req.uri().path().to_owned(), ToString::to_string);
    format!("{scheme}://{authority}{path_and_query}")
}

fn authority<B>(req: &Request<B>) -> String {
    // Prefer the URI authority when present (i.e. absolute-form request);
    // otherwise fall back to the `Host` header per RFC 9421 §2.2.4.
    if let Some(auth) = req.uri().authority() {
        return auth.as_str().to_ascii_lowercase();
    }
    req.headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default()
}

fn scheme<B>(req: &Request<B>) -> String {
    req.uri()
        .scheme_str()
        .map_or_else(|| "https".to_owned(), str::to_ascii_lowercase)
}

fn query_with_leading_q<B>(req: &Request<B>) -> String {
    // RFC 9421 §2.2.7: "If the query string is absent from the request
    // URI, the value is the leading `?` character alone."
    req.uri()
        .query()
        .map_or_else(|| "?".to_owned(), |q| format!("?{q}"))
}

fn request_target<B>(req: &Request<B>) -> String {
    // RFC 9421 §2.2.5: "The request method is not included in the
    // request target." The canonical value is just the path-and-query.
    req.uri()
        .path_and_query()
        .map_or_else(|| req.uri().path().to_owned(), ToString::to_string)
}

fn header_value<B>(req: &Request<B>, lower_name: &str) -> Result<String, Error> {
    collect_canonical_header_value(req, lower_name)
        .ok_or_else(|| Error::RequiredHeaderAbsent(lower_name.to_owned()))
}

/// Builds the RFC 9421 signature base for `req` using the given
/// ordered list of components, ending with the `"@signature-params"`
/// line that binds the parameter tuple to the signature.
///
/// # Errors
///
/// Returns [`Error::RequiredHeaderAbsent`] when a referenced header is
/// not present on `req`.
#[allow(
    clippy::expect_used,
    clippy::unwrap_in_result,
    reason = "writing to an owned String via core::fmt::Write is infallible; the Result on write! only exists to satisfy the trait"
)]
pub(crate) fn build_signature_base<B>(
    req: &Request<B>,
    components: &[Component],
    signature_params_inner_list: &str,
) -> Result<String, Error> {
    use core::fmt::Write as _;
    let mut out = String::new();
    let infallible = "writing to an owned String is infallible";
    for component in components {
        let line = canonical_value(component, req)?;
        writeln!(out, "{}: {line}", component.lexical()).expect(infallible);
    }
    write!(out, r#""@signature-params": {signature_params_inner_list}"#).expect(infallible);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use http::{Method, Request};
    use pretty_assertions::assert_eq;

    use super::*;

    fn sample() -> Request<Vec<u8>> {
        Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox?a=1")
            .header("host", "example.com")
            .header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
            .body(Vec::new())
            .expect("valid")
    }

    #[test]
    fn method_is_uppercase() {
        assert_eq!(
            canonical_value(&Component::Method, &sample()).unwrap(),
            "POST"
        );
    }

    #[test]
    fn target_uri_includes_scheme_authority_path_and_query() {
        assert_eq!(
            canonical_value(&Component::TargetUri, &sample()).unwrap(),
            "https://example.com/inbox?a=1",
        );
    }

    #[test]
    fn authority_is_lowercase() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("https://EXAMPLE.COM/inbox")
            .body(Vec::<u8>::new())
            .expect("valid");
        assert_eq!(
            canonical_value(&Component::Authority, &req).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn path_and_query_are_separate() {
        let req = sample();
        assert_eq!(canonical_value(&Component::Path, &req).unwrap(), "/inbox");
        assert_eq!(canonical_value(&Component::Query, &req).unwrap(), "?a=1");
    }

    #[test]
    fn empty_query_canonicalises_to_single_question_mark() {
        // RFC 9421 §2.2.7 explicitly specifies this edge case.
        let req = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox")
            .body(Vec::<u8>::new())
            .expect("valid");
        assert_eq!(canonical_value(&Component::Query, &req).unwrap(), "?");
    }

    #[test]
    fn request_target_excludes_method_per_rfc9421() {
        // Cavage's `(request-target)` includes the method, but RFC 9421's
        // `@request-target` MUST NOT (§2.2.5).
        let req = sample();
        assert_eq!(
            canonical_value(&Component::RequestTarget, &req).unwrap(),
            "/inbox?a=1",
        );
    }

    #[test]
    fn request_target_is_just_path_when_query_absent() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/inbox")
            .body(Vec::<u8>::new())
            .expect("valid");
        assert_eq!(
            canonical_value(&Component::RequestTarget, &req).unwrap(),
            "/inbox",
        );
    }

    #[test]
    fn missing_header_reports_required_header_absent() {
        let req = sample();
        let err = canonical_value(&Component::Header("authorization".into()), &req)
            .expect_err("missing header must error");
        assert!(matches!(err, Error::RequiredHeaderAbsent(name) if name == "authorization"));
    }

    #[test]
    fn parse_roundtrips_known_identifiers() {
        for ident in [
            "@method",
            "@target-uri",
            "@authority",
            "@scheme",
            "@path",
            "@query",
            "@request-target",
            "date",
        ] {
            let c = Component::parse(ident).expect("known identifier");
            assert_eq!(c.identifier(), ident);
        }
    }

    #[test]
    fn parse_rejects_unknown_derived_component() {
        let err = Component::parse("@future").expect_err("unknown derived");
        assert!(matches!(err, Error::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn full_signature_base_matches_expected_shape() {
        let req = sample();
        let components = [
            Component::Method,
            Component::TargetUri,
            Component::Header("host".into()),
            Component::Header("date".into()),
        ];
        let base = build_signature_base(
            &req,
            &components,
            r#"("@method" "@target-uri" "host" "date");created=1704464900;keyid="kid""#,
        )
        .unwrap();
        assert_eq!(
            base,
            concat!(
                "\"@method\": POST\n",
                "\"@target-uri\": https://example.com/inbox?a=1\n",
                "\"host\": example.com\n",
                "\"date\": Sun, 05 Jan 2014 21:31:40 GMT\n",
                "\"@signature-params\": (\"@method\" \"@target-uri\" \"host\" \"date\");created=1704464900;keyid=\"kid\"",
            ),
        );
    }
}
