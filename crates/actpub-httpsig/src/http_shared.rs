//! Helpers shared by the Cavage draft-12 and RFC 9421 canonicalisation
//! routines.
//!
//! Both flavours of HTTP message signature need the same primitive when
//! reading a header value into the signature base: collect every
//! occurrence of `name`, OWS-trim each one, and join them with `, `
//! into a single string. Cavage [§2.3] and RFC 9421 [§2.1] phrase the
//! rule in slightly different prose but the byte-level result is
//! identical.
//!
//! Centralising the implementation here removes the duplicated code
//! that previously lived in `cavage::canonical::collect_header` and
//! `rfc9421::components::header_value`, making future fixes (e.g.
//! handling obsolete `obs-fold`) a single-site change.
//!
//! [§2.3]: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.3
//! [§2.1]: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1

use http::Request;

/// Collects every occurrence of the header named `lower_name` (which
/// MUST already be lower-cased), OWS-trims each value and joins them
/// with `, ` per the HTTP-Signatures canonicalisation rule.
///
/// Returns `None` when the header is absent — callers map that into
/// the spec-appropriate error (`RequiredHeaderAbsent` for both the
/// Cavage and RFC 9421 paths).
pub(crate) fn collect_canonical_header_value<B>(
    req: &Request<B>,
    lower_name: &str,
) -> Option<String> {
    let mut joined = String::new();
    let mut seen = false;
    for (_, value) in req
        .headers()
        .iter()
        .filter(|(name, _)| name.as_str() == lower_name)
    {
        let trimmed = value.to_str().unwrap_or("").trim();
        if seen {
            joined.push_str(", ");
        }
        seen = true;
        joined.push_str(trimmed);
    }
    seen.then_some(joined)
}

#[cfg(test)]
mod tests {
    use http::{Method, Request};
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn returns_none_for_absent_header() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .body(Vec::<u8>::new())
            .expect("request");
        assert!(collect_canonical_header_value(&req, "x-missing").is_none());
    }

    #[test]
    fn trims_ows_around_single_value() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .header("x-foo", "   bar   ")
            .body(Vec::<u8>::new())
            .expect("request");
        assert_eq!(
            collect_canonical_header_value(&req, "x-foo"),
            Some("bar".to_owned())
        );
    }

    #[test]
    fn joins_repeated_header_values_with_comma_space() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .header("forwarded", "for=1.1.1.1")
            .header("forwarded", "for=2.2.2.2")
            .body(Vec::<u8>::new())
            .expect("request");
        assert_eq!(
            collect_canonical_header_value(&req, "forwarded"),
            Some("for=1.1.1.1, for=2.2.2.2".to_owned())
        );
    }

    #[test]
    fn matches_only_lower_case_header_names() {
        // The `http` crate stores header names lower-cased internally,
        // so passing the lower-cased name is sufficient; this test
        // documents that contract.
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .header("Content-Type", "application/activity+json")
            .body(Vec::<u8>::new())
            .expect("request");
        assert_eq!(
            collect_canonical_header_value(&req, "content-type"),
            Some("application/activity+json".to_owned())
        );
    }
}
