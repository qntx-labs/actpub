//! Asynchronous `WebFinger` client built on [`reqwest`].

use reqwest::{Client, header};
use tracing::debug;
use url::Url;

use crate::{Account, Error, Jrd};

/// Resolves a Fediverse [`Account`] to its [`Jrd`] via `WebFinger`.
///
/// This performs an HTTPS `GET` against the account's `/.well-known/webfinger`
/// endpoint with the correct `Accept` header, verifies the returned
/// `subject` matches the requested resource (to defend against
/// misconfigured servers returning data for a different account), and then
/// returns the parsed JRD.
///
/// This is a convenience wrapper over [`fetch_at`] that delegates URL
/// construction to [`Account::webfinger_url`] and uses the account's
/// canonical `acct:` resource as the expected subject.
///
/// # Errors
///
/// Returns [`Error::Http`] for network failures, [`Error::BadStatus`] for
/// non-2xx responses, [`Error::SubjectMismatch`] if the returned JRD's
/// subject does not match the request, and [`Error::Json`] if the body is
/// not valid JSON.
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
    debug!(%url, "fetching WebFinger JRD");

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

    // The response body is parsed as JSON regardless of Content-Type.
    // RFC 7033 specifies `application/jrd+json` but Fediverse servers in
    // the wild very often serve `application/json`; both are accepted.
    let jrd: Jrd = response.json().await?;

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
}
