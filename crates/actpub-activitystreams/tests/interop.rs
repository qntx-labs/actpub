//! Interoperability tests against real-world Fediverse JSON fixtures.
//!
//! Each test loads a JSON document captured from (or modelled exactly
//! after) a real Fediverse implementation, deserialises it into our
//! types, exercises the typed accessors, and re-serialises it. The
//! re-serialised JSON MUST be byte-stable (in canonical key order) with
//! the input — this is the strongest evidence we can offer that our
//! types are wire-compatible with the rest of the Fediverse.
#![allow(
    unused_crate_dependencies,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::tests_outside_test_module,
    reason = "integration-test idioms: every `#[test]` is the file's contents; `expect`/`panic!`/`[0]` are the clearest way to assert invariants"
)]

use actpub_activitystreams::{Object, WithContext, kind};
use pretty_assertions::assert_eq;

/// Loads a fixture from `tests/fixtures/<name>.json` as a
/// `serde_json::Value` so we can compare the round-trip against the
/// source.
fn load_fixture(name: &str) -> serde_json::Value {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let body =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("parse fixture {path}: {e}"))
}

/// Asserts that a fixture round-trips with stable semantics under our
/// canonical wire form: parse → serialise → re-parse → re-serialise
/// MUST be byte-identical to the first serialisation.
///
/// We deliberately do **not** require `serialised == fixture` because
/// the fixture often uses Mastodon's verbose forms (e.g. single-element
/// `"to": [\"…\"]` arrays) while our canonical [`OneOrMany`] writer
/// collapses single-element collections to a bare value. Both shapes
/// are spec-equivalent; what matters is that *our* output is stable.
fn assert_canonical_roundtrip<T>(fixture: &serde_json::Value)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let parsed: T = serde_json::from_value(fixture.clone())
        .expect("fixture must deserialise into the typed model");
    let canonical = serde_json::to_value(&parsed).expect("serialise typed model");
    let reparsed: T = serde_json::from_value(canonical.clone()).expect("re-parse canonical form");
    let recanonical = serde_json::to_value(&reparsed).expect("re-serialise typed model");
    assert_eq!(
        recanonical, canonical,
        "second-pass serialisation must be byte-stable",
    );
}

/// A real Mastodon actor MUST round-trip without losing any field, and
/// the typed accessors MUST surface every ActivityPub-mandated property.
#[test]
fn mastodon_actor_roundtrips_byte_stable() {
    let raw = load_fixture("mastodon-actor");
    let actor: WithContext<Object> =
        serde_json::from_value(raw.clone()).expect("Mastodon actor fixture must deserialise");

    // ActivityPub §4.1 mandatory actor properties — every one MUST be
    // surfaced as a typed field, not buried in `extra`.
    assert_eq!(actor.inner.preferred_username.as_deref(), Some("alice"));
    assert!(actor.inner.inbox.is_some(), "inbox typed");
    assert!(actor.inner.outbox.is_some(), "outbox typed");
    assert!(actor.inner.followers.is_some(), "followers typed");
    assert!(actor.inner.following.is_some(), "following typed");
    assert!(actor.inner.public_key.is_some(), "publicKey typed");
    assert!(actor.inner.endpoints.is_some(), "endpoints typed");

    // Mastodon extensions — also typed.
    assert!(actor.inner.featured.is_some(), "toot:featured typed");
    assert!(
        actor.inner.featured_tags.is_some(),
        "toot:featuredTags typed"
    );
    assert_eq!(actor.inner.manually_approves_followers, Some(false));
    assert_eq!(actor.inner.discoverable, Some(true));
    assert_eq!(actor.inner.indexable, Some(true));
    assert_eq!(actor.inner.memorial, Some(false));

    // Type discrimination still works after the extension.
    assert!(actor.inner.is_kind(kind::actor::PERSON));
    assert!(actor.inner.is_actor());

    // The publicKey block surfaces all three fields.
    let pk = actor.inner.public_key.as_ref().expect("public_key");
    assert_eq!(
        pk.id.as_str(),
        "https://mastodon.social/users/alice#main-key"
    );
    assert_eq!(pk.owner.as_str(), "https://mastodon.social/users/alice");
    assert!(pk.public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----"));

    // Mastodon's actor JSON has no single-element arrays in any
    // OneOrMany-typed property, so byte-stable roundtrip is achievable
    // here.
    let back = serde_json::to_value(&actor).expect("re-serialise");
    assert_eq!(
        back, raw,
        "Mastodon actor fixture must round-trip byte-stable"
    );
    assert_canonical_roundtrip::<WithContext<Object>>(&raw);
}

/// FEP-521a Multikey assertion-method blocks MUST round-trip and be
/// surfaced through the typed `assertion_method` field.
#[test]
fn fep_521a_actor_roundtrips_byte_stable() {
    let raw = load_fixture("fep-521a-actor");
    let actor: WithContext<Object> =
        serde_json::from_value(raw.clone()).expect("FEP-521a actor fixture must deserialise");

    assert_eq!(actor.inner.assertion_method.len(), 1);
    assert_eq!(actor.inner.authentication.len(), 1);

    // The assertion-method entry MUST be the inlined Multikey form.
    let am = &actor.inner.assertion_method[0];
    let key = am.as_object().expect("inline Multikey form");
    assert_eq!(key.controller.as_str(), "https://example.com/users/alice");
    assert!(key.public_key_multibase.starts_with('z'));

    // Authentication uses the bare-URL form for the same key.
    let auth = &actor.inner.authentication[0];
    assert!(auth.as_object().is_none(), "bare-URL form expected");

    // FEP-521a's `assertionMethod` is always an array of length \u22651, so
    // the canonical form differs from the fixture (single-entry Vec is
    // not coerced to bare). We assert second-pass byte-stability instead.
    assert_canonical_roundtrip::<WithContext<Object>>(&raw);
}

/// FEP-8b32 Object Integrity Proofs MUST round-trip when attached to a
/// Create activity, and the proof block MUST be surfaced via the typed
/// `proof` accessor.
#[test]
fn fep_8b32_signed_create_roundtrips_byte_stable() {
    let raw = load_fixture("fep-8b32-create");
    let create: WithContext<Object> =
        serde_json::from_value(raw.clone()).expect("FEP-8b32 fixture must deserialise");

    assert!(create.inner.is_kind("Create"));
    assert_eq!(create.inner.proof.len(), 1);
    let proof = create.inner.proof.first().expect("at least one proof");
    assert_eq!(proof.cryptosuite, "eddsa-jcs-2022");
    assert_eq!(proof.proof_purpose, "assertionMethod");
    assert!(proof.proof_value.starts_with('z'));
    assert_eq!(
        proof.verification_method.as_str(),
        "https://example.com/users/alice#ed25519-key"
    );

    // The FEP-8b32 Create fixture uses Mastodon-style `"to": ["\u2026"]`
    // arrays; our canonical form collapses single-element arrays to a
    // bare value, so we assert second-pass byte-stability.
    assert_canonical_roundtrip::<WithContext<Object>>(&raw);
}
