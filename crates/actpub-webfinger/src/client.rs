//! Asynchronous `WebFinger` client built on [`reqwest`].
//!
//! # Security considerations
//!
//! The Fediverse `WebFinger` responder is untrusted by definition,
//! so this client enforces three hardening guard-rails on every
//! response:
//!
//! - **Body size cap.** Responses are streamed and rejected with
//!   [`Error::ResponseTooLarge`] once the accumulated bytes exceed
//!   [`DEFAULT_MAX_BODY_BYTES`]. A well-behaved `WebFinger` JRD is
//!   a few hundred bytes; the 64 KiB default leaves ample room for
//!   exotic extensions while foreclosing out-of-memory `DoS`.
//! - **Redirect policy.** When the caller obtains their
//!   [`reqwest::Client`] from [`recommended_client`], the client is
//!   pre-configured with a strict policy: at most two redirects
//!   and only to the same origin. This matches Mastodon's
//!   defaults and neutralises cross-origin redirect attacks on
//!   the `WebFinger` endpoint.
//! - **Subject verification.** [`resolve`] requires the returned
//!   JRD subject (or one of its aliases) to equal the requested
//!   resource; a misconfigured or malicious responder cannot swap
//!   identities under the caller's feet.

use reqwest::redirect::Policy;
use reqwest::{Client, ClientBuilder, header};
use tracing::debug;
use url::Url;

use crate::{Account, Error, Jrd};

/// Default hard cap on the response body we will read from a
/// `WebFinger` endpoint.
///
/// `WebFinger` JRDs in the wild are rarely larger than 2 KiB; 64 KiB
/// is a deliberately generous ceiling that still bounds memory use
/// against a hostile responder.
pub const DEFAULT_MAX_BODY_BYTES: u64 = 64 * 1024;

/// Builds a [`reqwest::Client`] pre-configured for safe `WebFinger`
/// resolution.
///
/// The returned client uses a strict redirect policy — at most two
/// redirects, all to the same origin — which matches Mastodon's
/// defaults and neutralises cross-origin redirect attacks on the
/// endpoint. Callers that need custom behaviour (e.g. a shared
/// connection pool) can reuse the returned client or construct
/// their own and pass it to [`resolve`] / [`fetch_at`] directly.
///
/// # Errors
///
/// Returns [`Error::Http`] if the underlying TLS stack cannot be
/// initialised.
pub fn recommended_client() -> Result<Client, Error> {
    Ok(ClientBuilder::new()
        .redirect(Policy::custom(|attempt| {
            const MAX_REDIRECTS: usize = 2;
            if attempt.previous().len() >= MAX_REDIRECTS {
                return attempt.error("too many redirects");
            }
            let origin = attempt.previous().first().unwrap_or_else(|| attempt.url());
            if origin.host_str() == attempt.url().host_str()
                && origin.scheme() == attempt.url().scheme()
            {
                attempt.follow()
            } else {
                attempt.error("cross-origin redirect forbidden for WebFinger")
            }
        }))
        .build()?)
}

/// Resolves a Fediverse [`Account`] to its [`Jrd`] via `WebFinger`.
///
/// This performs an HTTPS `GET` against the account's
/// `/.well-known/webfinger` endpoint with the correct `Accept`
/// header, verifies the returned `subject` matches the requested
/// resource (to defend against misconfigured servers returning
/// data for a different account), and then returns the parsed JRD.
///
/// Internally delegates to [`fetch_at`] with the canonical `acct:`
/// resource and [`DEFAULT_MAX_BODY_BYTES`] size cap. Pass in a
/// client obtained from [`recommended_client`] to also benefit
/// from the same-origin redirect policy.
///
/// # Errors
///
/// Returns [`Error::Http`] for network failures,
/// [`Error::BadStatus`] for non-2xx responses,
/// [`Error::ResponseTooLarge`] if the server sends more than
/// [`DEFAULT_MAX_BODY_BYTES`], [`Error::SubjectMismatch`] if the
/// returned JRD's subject does not match the request, and
/// [`Error::Json`] if the body is not valid JSON.
pub async fn resolve(account: &Account, client: &Client) -> Result<Jrd, Error> {
    let url = account.webfinger_url()?;
    let expected = account.to_resource();
    fetch_at(&url, Some(&expected), client).await
}

/// Fetches and parses a [`Jrd`] from a specific URL, optionally verifying
/// the returned subject.
///
/// This is the low-level building block behind [`resolve`]. Most callers
/// should prefer [`resolve`], which automatically constructs the
/// well-known URL from an [`Account`]. This variant is exposed for
/// callers that need:
///
/// - a non-`https` scheme (e.g. local development, Tor hidden services),
/// - a custom URL shape (e.g. a proxy endpoint), or
/// - to skip the subject check (by passing `expected_subject = None`).
///
/// When `expected_subject` is `Some`, the returned JRD's `subject` MUST
/// equal it, or one of the JRD's `aliases` MUST equal it; otherwise
/// [`Error::SubjectMismatch`] is returned. Per RFC 7033 §4.4 the server
/// MAY normalise the subject (e.g. lower-casing host) so the alias check
/// is the safety net that accepts the widely-deployed Mastodon pattern of
/// returning `acct:User@host` aliases next to the canonical subject.
///
/// # Errors
///
/// Returns [`Error::Http`] for network failures, [`Error::BadStatus`] for
/// non-2xx responses, [`Error::MissingSubject`] if the JRD omits the
/// subject field, [`Error::SubjectMismatch`] as described above, and
/// [`Error::Json`] if the body is not valid JSON.
pub async fn fetch_at(
    url: &Url,
    expected_subject: Option<&str>,
    client: &Client,
) -> Result<Jrd, Error> {
    fetch_at_with_limit(url, expected_subject, client, DEFAULT_MAX_BODY_BYTES).await
}

/// [`fetch_at`] variant that accepts an explicit body size cap.
///
/// Useful when the caller has a stricter deployment budget than
/// [`DEFAULT_MAX_BODY_BYTES`] (or, rarely, a looser one). Set
/// `max_body_bytes` to `0` to disable the cap — **not** recommended
/// outside trusted-network contexts.
///
/// # Errors
///
/// Same as [`fetch_at`].
pub async fn fetch_at_with_limit(
    url: &Url,
    expected_subject: Option<&str>,
    client: &Client,
    max_body_bytes: u64,
) -> Result<Jrd, Error> {
    debug!(%url, max_body_bytes, "fetching WebFinger JRD");

    let response = client
        .get(url.clone())
        .header(
            header::ACCEPT,
            format!("{jrd}, application/json", jrd = crate::MEDIA_TYPE),
        )
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        return Err(Error::BadStatus(status.as_u16()));
    }

    // Stream the body under an explicit cap. RFC 7033 specifies
    // `application/jrd+json` but Fediverse servers very often serve
    // `application/json`; we do not reject either Content-Type, but
    // we do reject a body that grows past `max_body_bytes`.
    let body = read_capped(response, max_body_bytes).await?;
    let jrd: Jrd = serde_json::from_slice(&body)?;

    if jrd.subject.is_empty() {
        return Err(Error::MissingSubject);
    }

    if let Some(expected) = expected_subject
        && jrd.subject != expected
        && !jrd.aliases.iter().any(|a| a == expected)
    {
        return Err(Error::SubjectMismatch {
            requested: expected.to_owned(),
            returned: jrd.subject,
        });
    }

    Ok(jrd)
}

/// Reads `response`'s body into a [`Vec<u8>`], aborting with
/// [`Error::ResponseTooLarge`] as soon as the accumulated length
/// would exceed `max_body_bytes`. A `max_body_bytes` of `0`
/// disables the cap (useful for trusted-network tests).
async fn read_capped(
    mut response: reqwest::Response,
    max_body_bytes: u64,
) -> Result<Vec<u8>, Error> {
    let mut acc: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if max_body_bytes > 0 && (acc.len() as u64 + chunk.len() as u64) > max_body_bytes {
            return Err(Error::ResponseTooLarge(max_body_bytes));
        }
        acc.extend_from_slice(&chunk);
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::rels;

    /// Builds a concrete JRD-endpoint URL pointing at the mock server.
    fn mock_url(server: &MockServer, resource: &str) -> Url {
        format!(
            "{base}/.well-known/webfinger?resource={resource}",
            base = server.uri(),
        )
        .parse()
        .expect("mock URL must parse")
    }

    #[tokio::test]
    async fn fetch_at_returns_parsed_jrd_when_subject_matches() {
        let server = MockServer::start().await;
        let subject = "acct:alice@example.com";

        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "subject": subject,
                "links": [{
                    "rel": "self",
                    "type": "application/activity+json",
                    "href": "https://example.com/users/alice"
                }]
            })))
            .mount(&server)
            .await;

        let jrd = fetch_at(&mock_url(&server, subject), Some(subject), &Client::new())
            .await
            .expect("fetch should succeed");

        assert_eq!(jrd.subject, subject);
        assert_eq!(
            jrd.activitypub_actor()
                .expect("actor link must be present")
                .rel,
            rels::ACTIVITYPUB_ACTOR,
        );
    }

    #[tokio::test]
    async fn fetch_at_accepts_expected_subject_in_aliases() {
        // Mastodon-style: canonical subject uses host-normalised form,
        // while the original queried form appears in `aliases`.
        let server = MockServer::start().await;
        let canonical = "acct:Alice@example.com";
        let queried = "acct:alice@EXAMPLE.COM";

        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "subject": canonical,
                "aliases": [queried],
            })))
            .mount(&server)
            .await;

        let jrd = fetch_at(&mock_url(&server, queried), Some(queried), &Client::new())
            .await
            .expect("alias match should satisfy the subject check");

        assert_eq!(jrd.subject, canonical);
    }

    #[tokio::test]
    async fn fetch_at_rejects_mismatched_subject() {
        // Defence against a misconfigured or malicious server returning
        // data for a different account than the one requested.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "subject": "acct:attacker@evil.example",
            })))
            .mount(&server)
            .await;

        let err = fetch_at(
            &mock_url(&server, "acct:alice@example.com"),
            Some("acct:alice@example.com"),
            &Client::new(),
        )
        .await
        .expect_err("mismatched subject must produce an error");

        assert!(
            matches!(err, Error::SubjectMismatch { .. }),
            "expected SubjectMismatch, got {err:?}",
        );
    }

    #[tokio::test]
    async fn fetch_at_rejects_empty_subject() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "subject": "",
            })))
            .mount(&server)
            .await;

        let err = fetch_at(
            &mock_url(&server, "acct:alice@example.com"),
            None,
            &Client::new(),
        )
        .await
        .expect_err("empty subject must produce an error");

        assert!(
            matches!(err, Error::MissingSubject),
            "expected MissingSubject, got {err:?}",
        );
    }

    #[tokio::test]
    async fn fetch_at_reports_bad_status_on_404() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let err = fetch_at(
            &mock_url(&server, "acct:alice@example.com"),
            None,
            &Client::new(),
        )
        .await
        .expect_err("404 response must propagate as BadStatus");

        assert!(
            matches!(err, Error::BadStatus(404)),
            "expected BadStatus(404), got {err:?}",
        );
    }

    #[tokio::test]
    async fn fetch_at_skips_subject_check_when_expected_is_none() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "subject": "acct:anyone@any.example",
            })))
            .mount(&server)
            .await;

        // `None` means "trust the server"; useful for low-level clients.
        let jrd = fetch_at(
            &mock_url(&server, "acct:anyone@any.example"),
            None,
            &Client::new(),
        )
        .await
        .expect("None-expected must skip subject verification");

        assert_eq!(jrd.subject, "acct:anyone@any.example");
    }

    #[test]
    fn resolve_future_is_send() {
        // `resolve` and `fetch_at` are held across `.await` points in many
        // multi-threaded runtimes. The returned future must therefore be
        // `Send`; this compile-time check would fail if a future
        // accidentally captured a non-`Send` value.
        fn assert_send<F: Send>(_: F) {}
        let client = Client::new();
        let account = Account::parse("acct:a@b.example").expect("valid acct");
        assert_send(resolve(&account, &client));
        let url: Url = "https://example.com/.well-known/webfinger"
            .parse()
            .expect("valid URL");
        assert_send(fetch_at(&url, None, &client));
    }

    #[tokio::test]
    async fn fetch_at_rejects_body_exceeding_size_cap() {
        // Defence against OOM-by-JSON: a hostile responder could
        // stream gigabytes under `application/json`. We stop reading
        // the moment the accumulated bytes exceed `max_body_bytes`.
        let server = MockServer::start().await;
        let big = "x".repeat(65_536);
        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                format!(r#"{{"subject":"acct:a@b.example","padding":"{big}"}}"#).into_bytes(),
                "application/jrd+json",
            ))
            .mount(&server)
            .await;

        let err = fetch_at_with_limit(
            &mock_url(&server, "acct:a@b.example"),
            None,
            &Client::new(),
            1024, // 1 KiB cap
        )
        .await
        .expect_err("oversize body must be rejected");

        assert!(
            matches!(err, Error::ResponseTooLarge(1024)),
            "expected ResponseTooLarge(1024), got {err:?}",
        );
    }

    #[tokio::test]
    async fn fetch_at_accepts_body_under_the_default_cap() {
        // Realistic JRD well under 64 KiB passes the default cap
        // without trouble.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "subject": "acct:a@b.example",
                "links": [{"rel": "self", "type": "application/activity+json", "href": "https://b.example/u/a"}],
            })))
            .mount(&server)
            .await;

        let jrd = fetch_at(
            &mock_url(&server, "acct:a@b.example"),
            Some("acct:a@b.example"),
            &Client::new(),
        )
        .await
        .expect("well-sized response must succeed");
        assert_eq!(jrd.subject, "acct:a@b.example");
    }

    #[test]
    fn recommended_client_builds_without_panicking() {
        let _ = recommended_client().expect("TLS stack must initialise");
    }
}
