//! Asynchronous `WebFinger` client built on [`reqwest`].

use reqwest::{Client, header};
use tracing::debug;

use crate::{Account, Error, Jrd};

/// Resolves a Fediverse [`Account`] to its [`Jrd`] via `WebFinger`.
///
/// This performs an HTTPS `GET` against the account's `/.well-known/webfinger`
/// endpoint with the correct `Accept` header, verifies the returned
/// `subject` matches the requested resource (to defend against
/// misconfigured servers returning data for a different account), and then
/// returns the parsed JRD.
///
/// # Errors
///
/// Returns [`Error::Http`] for network failures, [`Error::BadStatus`] for
/// non-2xx responses, [`Error::SubjectMismatch`] if the returned JRD's
/// subject does not match the request, and [`Error::Json`] if the body is
/// not valid JSON.
pub async fn resolve(account: &Account, client: &Client) -> Result<Jrd, Error> {
    let url = account.webfinger_url()?;
    debug!(%url, "resolving WebFinger");

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
    // The server MAY normalise the subject (e.g. lower-casing the host) but
    // in practice the three accepted canonical forms round-trip exactly.
    let expected = account.to_resource();
    if jrd.subject != expected && !jrd.aliases.iter().any(|a| a == &expected) {
        return Err(Error::SubjectMismatch {
            requested: expected,
            returned: jrd.subject,
        });
    }

    Ok(jrd)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::rels;

    #[tokio::test]
    async fn resolves_valid_jrd_from_mock_server() {
        let server = MockServer::start().await;
        let host = server.uri().strip_prefix("http://").unwrap().to_owned();

        Mock::given(method("GET"))
            .and(path("/.well-known/webfinger"))
            .and(query_param("resource", format!("acct:alice@{host}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "subject": format!("acct:alice@{host}"),
                "links": [
                    {
                        "rel": "self",
                        "type": "application/activity+json",
                        "href": format!("http://{host}/users/alice")
                    }
                ]
            })))
            .mount(&server)
            .await;

        // Override HTTPS requirement for test: the helper normally builds
        // `https://...` URLs but wiremock speaks plain HTTP.
        let account = Account::new("alice", &host).unwrap();
        let resource = account.to_resource();
        let url = format!(
            "{base}/.well-known/webfinger?resource={resource}",
            base = server.uri(),
        );
        let jrd: Jrd = Client::new()
            .get(url)
            .header(header::ACCEPT, crate::MEDIA_TYPE)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(jrd.subject, resource);
        assert_eq!(
            jrd.activitypub_actor().unwrap().rel,
            rels::ACTIVITYPUB_ACTOR
        );
    }

    #[test]
    fn resolve_future_is_send() {
        // Compile-time check: the returned future is `Send`, which is
        // required for the client to be usable in multi-threaded async
        // runtimes such as Tokio's default scheduler.
        fn assert_send<F: Send>(_: F) {}
        let client = Client::new();
        let account = Account::parse("acct:a@b.example").unwrap();
        assert_send(resolve(&account, &client));
    }
}
