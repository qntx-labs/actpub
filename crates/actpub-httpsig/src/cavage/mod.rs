//! [Cavage draft-12][cavage] HTTP Message Signatures.
//!
//! The de-facto Fediverse signature standard, covering Mastodon, Pleroma,
//! Lemmy, Misskey, `PeerTube` and every `rsa-sha256`-based actor key ever
//! deployed. The IETF finalised a successor as RFC 9421 (see
//! [`crate::rfc9421`] once implemented), but deployment is still rare, so
//! signers emit Cavage for compatibility and verifiers accept both.
//!
//! [cavage]: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12

mod canonical;
mod header;
mod sign;
mod verify;

pub use self::canonical::CavageHeaderSet;
pub use self::header::{CavageHeaderParams, SIGNATURE_HEADER};
pub use self::sign::{CavageSigner, DEFAULT_HEADER_SET};
pub use self::verify::{CavageVerified, cavage_verify};
