//! Well-known `WebFinger` link relation types used in the Fediverse.
//!
//! See the [IANA Link Relations registry][iana] and RFC 6415 for the full
//! list of standardised relations; this module hosts the subset that every
//! `ActivityPub` implementation needs.
//!
//! [iana]: https://www.iana.org/assignments/link-relations/link-relations.xhtml

/// The `self` relation. In combination with
/// [`crate::MEDIA_TYPE_ACTIVITYPUB`][type] it points to the `ActivityPub`
/// actor JSON document.
///
/// [type]: ACTIVITYPUB_ACTOR
pub const SELF: &str = "self";

/// The media type emitted by Fediverse servers for `ActivityPub` actor links.
pub const MEDIA_TYPE_ACTIVITYPUB: &str = "application/activity+json";

/// The full-form `ActivityPub` actor media type (equivalent to
/// [`MEDIA_TYPE_ACTIVITYPUB`] but with a JSON-LD profile).
pub const MEDIA_TYPE_ACTIVITYPUB_LD: &str =
    r#"application/ld+json; profile="https://www.w3.org/ns/activitystreams""#;

/// Link to an HTML profile page for a Fediverse actor.
///
/// Defined by [webfinger.net][rel].
///
/// [rel]: https://webfinger.net/rel/profile-page/
pub const PROFILE_PAGE: &str = "http://webfinger.net/rel/profile-page";

/// Link to an Atom feed of the actor's public activity.
pub const UPDATES_FROM: &str = "http://schemas.google.com/g/2010#updates-from";

/// `OStatus` subscribe template used by Mastodon's remote-follow button.
pub const OSTATUS_SUBSCRIBE: &str = "http://ostatus.org/schema/1.0/subscribe";

/// The `application/activity+json` shorthand alias — equivalent to
/// [`SELF`] combined with [`MEDIA_TYPE_ACTIVITYPUB`] in idiomatic usage.
///
/// This string is **not** an actual link relation; it is exposed here as a
/// helper for callers who want to search a link list for the
/// ActivityPub-actor link by both `rel` and `type`.
pub const ACTIVITYPUB_ACTOR: &str = SELF;

/// Link to an actor's avatar image (Mastodon convention).
pub const AVATAR: &str = "http://webfinger.net/rel/avatar";
