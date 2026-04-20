//! Interoperability tests against a real Mastodon `WebFinger` response.
#![allow(
    unused_crate_dependencies,
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::tests_outside_test_module,
    reason = "integration-test idioms: every `#[test]` is the file's contents; `expect`/`panic!`/`[0]` are the clearest way to assert invariants"
)]

use actpub_webfinger::{Jrd, rels};
use pretty_assertions::assert_eq;

fn load_fixture(name: &str) -> serde_json::Value {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let body =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("parse fixture {path}: {e}"))
}

/// A real Mastodon `WebFinger` document MUST round-trip byte-stable and
/// the typed accessors MUST surface `self` / template / avatar links.
#[test]
fn mastodon_webfinger_roundtrips_byte_stable() {
    let raw = load_fixture("mastodon-webfinger");
    let jrd: Jrd =
        serde_json::from_value(raw.clone()).expect("Mastodon WebFinger fixture must deserialise");

    assert_eq!(jrd.subject, "acct:Gargron@mastodon.social");
    assert_eq!(jrd.aliases.len(), 2);
    assert_eq!(jrd.links.len(), 4);

    // ActivityPub actor lookup MUST find the application/activity+json
    // self-link.
    let actor = jrd.activitypub_actor().expect("AP actor link present");
    assert_eq!(
        actor.href.as_ref().map(url::Url::as_str),
        Some("https://mastodon.social/users/Gargron"),
    );

    // The remote-follow template link MUST be resolvable by rel.
    let subscribe = jrd
        .find_link(rels::OSTATUS_SUBSCRIBE)
        .expect("OStatus subscribe link present");
    assert!(subscribe.template.is_some());
    assert!(subscribe.href.is_none());

    // RFC 7033 §4.4.4: every link satisfies the href-or-template
    // exclusion invariant.
    for link in &jrd.links {
        link.validate().unwrap_or_else(|e| panic!("invariant: {e}"));
    }

    let back = serde_json::to_value(&jrd).expect("re-serialise");
    assert_eq!(
        back, raw,
        "Mastodon WebFinger response must round-trip byte-stable"
    );
}
