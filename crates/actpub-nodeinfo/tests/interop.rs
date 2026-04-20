//! Interoperability tests against real Mastodon `NodeInfo` responses.
#![allow(
    unused_crate_dependencies,
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::tests_outside_test_module,
    reason = "integration-test idioms: every `#[test]` is the file's contents; `expect`/`panic!`/`[0]` are the clearest way to assert invariants"
)]

use actpub_nodeinfo::{Discovery, NodeInfo, Protocol, Version};
use pretty_assertions::assert_eq;

fn load_fixture(name: &str) -> serde_json::Value {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let body =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("parse fixture {path}: {e}"))
}

/// A real Mastodon `/.well-known/nodeinfo` discovery document MUST
/// round-trip and the typed accessors MUST find the 2.0 / 2.1 links.
#[test]
fn mastodon_discovery_roundtrips_byte_stable() {
    let raw = load_fixture("mastodon-discovery");
    let disc: Discovery =
        serde_json::from_value(raw.clone()).expect("Mastodon discovery fixture must deserialise");

    assert_eq!(disc.links.len(), 2);
    let v20 = disc.find_link(Version::V2_0).expect("2.0 link present");
    assert_eq!(v20.href.as_str(), "https://mastodon.social/nodeinfo/2.0");
    let v21 = disc.find_link(Version::V2_1).expect("2.1 link present");
    assert_eq!(v21.href.as_str(), "https://mastodon.social/nodeinfo/2.1");

    // The preferred-link helper picks 2.1 over 2.0 when both are present.
    let preferred = disc.preferred_link().expect("at least one known link");
    assert_eq!(preferred.version(), Some(Version::V2_1));

    let back = serde_json::to_value(&disc).expect("re-serialise");
    assert_eq!(back, raw, "Mastodon discovery must round-trip byte-stable");
}

/// A real Mastodon `NodeInfo` 2.0 response MUST round-trip and surface
/// every field through typed accessors.
#[test]
fn mastodon_nodeinfo_2_0_roundtrips_byte_stable() {
    let raw = load_fixture("mastodon-nodeinfo-2.0");
    let info: NodeInfo = serde_json::from_value(raw.clone())
        .expect("Mastodon NodeInfo 2.0 fixture must deserialise");

    assert_eq!(info.version, Version::V2_0);
    assert_eq!(info.software.name, "mastodon");
    assert_eq!(info.software.version, "4.5.0");
    assert!(info.protocols.contains(&Protocol::ActivityPub));
    assert_eq!(info.usage.users.total, Some(1_000_000));
    assert_eq!(info.usage.local_posts, Some(5_000_000));
    assert!(!info.open_registrations);
    assert!(
        info.metadata.get("nodeName").is_some(),
        "nodeName surfaced through metadata Value"
    );

    let back = serde_json::to_value(&info).expect("re-serialise");
    assert_eq!(
        back, raw,
        "Mastodon NodeInfo 2.0 must round-trip byte-stable"
    );
}
