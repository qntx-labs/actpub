//! Core protocol traits.
//!
//! These three traits are the data-layer contract between user-defined
//! database types and the federation runtime in `actpub-federation`. By
//! parameterising the runtime over [`Object`] / [`Actor`] / [`Activity`]
//! implementations rather than concrete types, the SDK avoids forcing a
//! single ORM, async runtime, or storage layout on its users.
//!
//! # Layered design
//!
//! - The traits in this module describe **shape** only and are
//!   synchronous: an `Object` knows its `id`, its `type`, and how to
//!   render itself to JSON. Anything that involves IO (database
//!   lookups, remote fetches, queue publishing) is the concern of
//!   higher layers.
//! - The `actpub-federation` crate adds an async `Repository` trait
//!   that maps URL → `Object` via the user's storage backend, and a
//!   `Fetcher` trait that maps URL → wire-format JSON via HTTP.
//!
//! # Implementing for a database row
//!
//! ```ignore
//! struct DbNote { id: Url, content: String, attributed_to: Url }
//!
//! impl actpub_core::Object for DbNote {
//!     type Wire = serde_json::Value;
//!
//!     fn id(&self) -> &Url { &self.id }
//!     fn kind(&self) -> &str { "Note" }
//!
//!     fn to_wire(&self) -> Self::Wire {
//!         serde_json::json!({
//!             "id": self.id,
//!             "type": "Note",
//!             "content": self.content,
//!             "attributedTo": self.attributed_to,
//!         })
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use url::Url;

/// Any value addressable by an `ActivityPub` `id` URL that can be
/// serialised to a JSON wire form.
///
/// Implementors are typically database row types or in-memory caches.
/// The wire form is intentionally a separate associated type so that
/// the same domain object can be rendered into different shapes
/// depending on the consumer (e.g. a richer internal form for local
/// API responses vs. a stricter Mastodon-compatible form for the
/// federation outbox).
pub trait Object {
    /// JSON wire representation rendered by [`to_wire`](Self::to_wire).
    ///
    /// `Wire` MUST round-trip through `serde_json` losslessly so that
    /// federated peers can re-parse the document our server emits.
    type Wire: Serialize + for<'de> Deserialize<'de>;

    /// The globally unique `ActivityPub` `id` that names this object on
    /// the wire.
    ///
    /// The same `id` MUST identify the same object across federation
    /// boundaries — re-issuing a different `id` for the same logical
    /// resource breaks remote followers, caches and dedup tables.
    fn id(&self) -> &Url;

    /// The Activity Streams 2.0 `type` discriminator (e.g. `"Note"`,
    /// `"Person"`, `"Create"`).
    ///
    /// Returning a single string covers the >99% case where an object
    /// has exactly one type. Multi-typed objects (rare, used by
    /// extensions) can either return their primary type here or wrap a
    /// custom enum.
    fn kind(&self) -> &str;

    /// Renders this object to its on-the-wire JSON form.
    ///
    /// MUST produce a representation containing at least the `id` and
    /// `type` members so that receivers can deduplicate and dispatch
    /// per `ActivityPub` §6 / §7.
    fn to_wire(&self) -> Self::Wire;
}

/// An [`Object`] that owns federation mailboxes and verification keys.
///
/// Every actor in the Fediverse — `Person`, `Service`, `Group`,
/// `Application`, `Organization` — implements this trait. The
/// federation runtime uses it to route inbound activities (via
/// [`inbox`](Self::inbox)), batch outbound deliveries (via
/// [`shared_inbox`](Self::shared_inbox)) and verify HTTP-Sig + Data
/// Integrity proofs (via
/// [`verification_methods`](Self::verification_methods)).
pub trait Actor: Object {
    /// URL of the actor's personal inbox where remote servers POST
    /// activities addressed to this actor.
    fn inbox(&self) -> &Url;

    /// Optional URL of the server-wide shared inbox; remote senders
    /// SHOULD prefer this when delivering to many actors hosted on
    /// the same server, to amortise the per-delivery cost (one POST
    /// instead of N).
    fn shared_inbox(&self) -> Option<&Url> {
        None
    }

    /// FEP-521a [`Multikey`] verification methods this actor publishes,
    /// in priority order. The first entry is preferred for new
    /// signatures; the rest exist so that older signatures (e.g.
    /// during a key rotation) can still be verified.
    ///
    /// Returning an empty slice is legal — it indicates this actor
    /// only signs via the legacy Cavage `publicKey` block. Callers
    /// MUST then fall back to the [`Object::Wire`] representation to
    /// extract the legacy key.
    ///
    /// [`Multikey`]: actpub_activitystreams::Multikey
    fn verification_methods(&self) -> &[actpub_activitystreams::Multikey] {
        &[]
    }
}

/// An [`Object`] that performs a verb on behalf of an [`Actor`].
///
/// Activities (`Create`, `Update`, `Delete`, `Follow`, `Accept`,
/// `Like`, `Announce`, …) are the unit of federation: every inbox POST
/// carries one. Implementations MUST surface the responsible actor so
/// the inbox pipeline can resolve the appropriate verification key.
pub trait Activity: Object {
    /// URL of the actor performing this activity. The inbox pipeline
    /// will fetch this actor (or look it up locally) to verify both
    /// the HTTP-Sig and any FEP-8b32 Data Integrity proof.
    fn actor(&self) -> &Url;

    /// URL of the activity's primary `object` member, when one is
    /// directly addressable.
    ///
    /// For activities that embed an inline object (e.g. `Create` with
    /// a fresh `Note`), implementors typically return the inlined
    /// object's `id`. For activities that operate on a remote object
    /// by reference (e.g. `Follow`, `Like`), they return the remote
    /// URL directly.
    ///
    /// Returns `None` for the rare activities that have no addressable
    /// object (e.g. `Travel` with only a structured location).
    fn object_id(&self) -> Option<&Url> {
        None
    }
}

#[cfg(test)]
#[allow(
    clippy::unnecessary_literal_bound,
    reason = "the test impls return literal `&'static str` from a trait method whose signature returns `&str`; clippy's suggestion would be to widen the trait method itself, which is exactly the wrong direction—implementors that derive their type tag from instance state need the borrowed-from-self lifetime"
)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A minimal Object impl over a borrowed JSON value: confirms the
    /// trait surface compiles and the contract is honored.
    struct NoteRow {
        id: Url,
        content: String,
    }

    impl Object for NoteRow {
        type Wire = serde_json::Value;
        fn id(&self) -> &Url {
            &self.id
        }
        fn kind(&self) -> &str {
            "Note"
        }
        fn to_wire(&self) -> Self::Wire {
            json!({
                "id": self.id,
                "type": "Note",
                "content": self.content,
            })
        }
    }

    #[test]
    fn object_impl_round_trips_through_wire_form() {
        let note = NoteRow {
            id: "https://example.com/n/1".parse().unwrap(),
            content: "hi".to_owned(),
        };
        let wire = note.to_wire();
        assert_eq!(wire["id"], json!("https://example.com/n/1"));
        assert_eq!(wire["type"], json!("Note"));
        assert_eq!(wire["content"], json!("hi"));
        assert_eq!(note.kind(), "Note");
    }

    /// A minimal Actor impl with only the mandatory `inbox` (no shared
    /// inbox, no verification methods) confirms the default-method
    /// fallbacks compile.
    struct AlicePerson {
        id: Url,
        inbox: Url,
    }

    impl Object for AlicePerson {
        type Wire = serde_json::Value;
        fn id(&self) -> &Url {
            &self.id
        }
        fn kind(&self) -> &str {
            "Person"
        }
        fn to_wire(&self) -> Self::Wire {
            json!({ "id": self.id, "type": "Person", "inbox": self.inbox })
        }
    }

    impl Actor for AlicePerson {
        fn inbox(&self) -> &Url {
            &self.inbox
        }
    }

    #[test]
    fn actor_default_methods_yield_none_and_empty() {
        let alice = AlicePerson {
            id: "https://example.com/users/alice".parse().unwrap(),
            inbox: "https://example.com/users/alice/inbox".parse().unwrap(),
        };
        assert_eq!(alice.shared_inbox(), None);
        assert!(alice.verification_methods().is_empty());
    }

    /// A minimal Activity impl confirms the trait composition compiles.
    struct CreateActivity {
        id: Url,
        actor: Url,
        object: Url,
    }

    impl Object for CreateActivity {
        type Wire = serde_json::Value;
        fn id(&self) -> &Url {
            &self.id
        }
        fn kind(&self) -> &str {
            "Create"
        }
        fn to_wire(&self) -> Self::Wire {
            json!({ "id": self.id, "type": "Create", "actor": self.actor, "object": self.object })
        }
    }

    impl Activity for CreateActivity {
        fn actor(&self) -> &Url {
            &self.actor
        }
        fn object_id(&self) -> Option<&Url> {
            Some(&self.object)
        }
    }

    #[test]
    fn activity_carries_actor_and_object_id() {
        let act = CreateActivity {
            id: "https://example.com/a/1".parse().unwrap(),
            actor: "https://example.com/users/alice".parse().unwrap(),
            object: "https://example.com/n/1".parse().unwrap(),
        };
        assert_eq!(act.actor().as_str(), "https://example.com/users/alice");
        assert_eq!(
            act.object_id().map(Url::as_str),
            Some("https://example.com/n/1"),
        );
    }
}
