//! String type constants for every name defined in the Activity Streams 2.0
//! vocabulary and the `ActivityPub` extension types.
//!
//! These constants are used to populate and match the `type` property on
//! Activity Streams [`Object`](crate::Object) and [`Link`](crate::Link)
//! values. Matching against a constant avoids typo-prone string literals
//! throughout downstream code.

/// Core Activity Streams 2.0 types, from the
/// [Core specification](https://www.w3.org/TR/activitystreams-core/).
pub mod core {
    /// Base type for all AS 2.0 objects.
    pub const OBJECT: &str = "Object";
    /// Base type for link references.
    pub const LINK: &str = "Link";
    /// Base type for all activities.
    pub const ACTIVITY: &str = "Activity";
    /// Activity subtype without an `object` property.
    pub const INTRANSITIVE_ACTIVITY: &str = "IntransitiveActivity";
    /// Unordered collection of items.
    pub const COLLECTION: &str = "Collection";
    /// Ordered collection of items.
    pub const ORDERED_COLLECTION: &str = "OrderedCollection";
    /// A paged view of a [`COLLECTION`].
    pub const COLLECTION_PAGE: &str = "CollectionPage";
    /// A paged view of an [`ORDERED_COLLECTION`].
    pub const ORDERED_COLLECTION_PAGE: &str = "OrderedCollectionPage";
}

/// Actor types — `ActivityPub` actors, from the
/// [ActivityPub](https://www.w3.org/TR/activitypub/#actors) specification.
pub mod actor {
    /// A software application.
    pub const APPLICATION: &str = "Application";
    /// A formal or informal collective of actors.
    pub const GROUP: &str = "Group";
    /// An organization.
    pub const ORGANIZATION: &str = "Organization";
    /// An individual person.
    pub const PERSON: &str = "Person";
    /// A service provided by some entity.
    pub const SERVICE: &str = "Service";
}

/// Activity vocabulary — the 28 standard activity verbs from
/// [Activity Vocabulary](https://www.w3.org/TR/activitystreams-vocabulary/#activity-types).
pub mod activity {
    /// Accept the `object` activity.
    pub const ACCEPT: &str = "Accept";
    /// Add `object` to `target`.
    pub const ADD: &str = "Add";
    /// Share / boost the `object`.
    pub const ANNOUNCE: &str = "Announce";
    /// Arrive at `location`.
    pub const ARRIVE: &str = "Arrive";
    /// Block the `object` actor.
    pub const BLOCK: &str = "Block";
    /// Create a new `object`.
    pub const CREATE: &str = "Create";
    /// Delete the `object`.
    pub const DELETE: &str = "Delete";
    /// Dislike the `object`.
    pub const DISLIKE: &str = "Dislike";
    /// Flag the `object` for moderation.
    pub const FLAG: &str = "Flag";
    /// Follow the `object` actor.
    pub const FOLLOW: &str = "Follow";
    /// Ignore the `object`.
    pub const IGNORE: &str = "Ignore";
    /// Invite the `object` to a `target`.
    pub const INVITE: &str = "Invite";
    /// Join the `object`.
    pub const JOIN: &str = "Join";
    /// Leave the `object`.
    pub const LEAVE: &str = "Leave";
    /// Like the `object`.
    pub const LIKE: &str = "Like";
    /// Listen to the `object`.
    pub const LISTEN: &str = "Listen";
    /// Move `object` from `origin` to `target`.
    pub const MOVE: &str = "Move";
    /// Offer `object` to `target`.
    pub const OFFER: &str = "Offer";
    /// A poll or multiple-choice question.
    pub const QUESTION: &str = "Question";
    /// Reject the `object` activity.
    pub const REJECT: &str = "Reject";
    /// Mark the `object` as read.
    pub const READ: &str = "Read";
    /// Remove `object` from `target`.
    pub const REMOVE: &str = "Remove";
    /// Tentatively accept `object`.
    pub const TENTATIVE_ACCEPT: &str = "TentativeAccept";
    /// Tentatively reject `object`.
    pub const TENTATIVE_REJECT: &str = "TentativeReject";
    /// Travel to `target`.
    pub const TRAVEL: &str = "Travel";
    /// Undo a prior activity.
    pub const UNDO: &str = "Undo";
    /// Update the `object`.
    pub const UPDATE: &str = "Update";
    /// Observe the `object`.
    pub const VIEW: &str = "View";
}

/// Concrete object subtypes — the 12 standard extended object types from
/// [Activity Vocabulary](https://www.w3.org/TR/activitystreams-vocabulary/#object-types).
pub mod object {
    /// Article content (blog post, news piece).
    pub const ARTICLE: &str = "Article";
    /// Audio media.
    pub const AUDIO: &str = "Audio";
    /// Generic document.
    pub const DOCUMENT: &str = "Document";
    /// An event.
    pub const EVENT: &str = "Event";
    /// Image media.
    pub const IMAGE: &str = "Image";
    /// A short note — the de-facto microblog post type.
    pub const NOTE: &str = "Note";
    /// A web page.
    pub const PAGE: &str = "Page";
    /// A physical or virtual location.
    pub const PLACE: &str = "Place";
    /// A user profile.
    pub const PROFILE: &str = "Profile";
    /// A relationship between two objects.
    pub const RELATIONSHIP: &str = "Relationship";
    /// A placeholder for a deleted object.
    pub const TOMBSTONE: &str = "Tombstone";
    /// Video media.
    pub const VIDEO: &str = "Video";
}

/// Link subtypes from
/// [Activity Vocabulary](https://www.w3.org/TR/activitystreams-vocabulary/#link-types)
/// and community extensions (FEP / SWICG).
pub mod link {
    /// A reference to a specific actor in a message (`@username`).
    pub const MENTION: &str = "Mention";
    /// A tagging reference used for categorisation (`#tag`). Defined in
    /// [ActivityPub Miscellaneous Terms](https://swicg.github.io/miscellany/).
    pub const HASHTAG: &str = "Hashtag";
    /// Custom inline emoji reference used by Mastodon and compatibles.
    pub const EMOJI: &str = "Emoji";
}
