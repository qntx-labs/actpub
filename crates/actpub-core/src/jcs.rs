//! [RFC 8785] JSON Canonicalisation Scheme (JCS) helpers.
//!
//! The Fediverse's modern signing stack — FEP-8b32 Data Integrity
//! proofs and the W3C VC-DI `EdDSA` Cryptosuites — relies on JCS to
//! produce a deterministic byte representation of a JSON document
//! before hashing. This module is a thin, error-aware wrapper around
//! the [`serde_jcs`] crate so that the rest of `actpub-core` does not
//! repeat the same `map_err` boilerplate at every call site.
//!
//! [RFC 8785]: https://www.rfc-editor.org/rfc/rfc8785

use crate::error::Error;

/// Canonicalises `value` using JCS and returns the resulting byte
/// sequence.
///
/// # Errors
///
/// Returns [`Error::Canonicalisation`] if `value` cannot be expressed
/// in the canonical form. In practice this only happens for non-finite
/// floating-point numbers (`NaN`, `±Infinity`), which the underlying
/// [`serde_json`] representation can never produce, so a failure here
/// signals a programmer error rather than malformed input.
pub fn canonicalize(value: &serde_json::Value) -> Result<Vec<u8>, Error> {
    serde_jcs::to_vec(value).map_err(|e| Error::Canonicalisation(e.to_string()))
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    /// JCS sorts keys lexicographically, so the canonical form is
    /// invariant under member-order permutations of the input.
    #[test]
    fn key_order_is_canonical() {
        let a = json!({ "b": 2, "a": 1 });
        let b = json!({ "a": 1, "b": 2 });
        assert_eq!(canonicalize(&a).unwrap(), canonicalize(&b).unwrap());
    }

    /// JCS strips insignificant whitespace; two semantically equal
    /// inputs MUST produce identical bytes.
    #[test]
    fn semantically_equal_inputs_produce_equal_bytes() {
        let a = json!({ "x": [1, 2, 3], "y": "hello" });
        let b = json!({ "y": "hello", "x": [1, 2, 3] });
        assert_eq!(canonicalize(&a).unwrap(), canonicalize(&b).unwrap());
    }

    /// Sanity check for a small RFC 8785-style example: the canonical
    /// output is a tightly-packed UTF-8 byte sequence with no spaces.
    #[test]
    fn canonical_form_has_no_insignificant_whitespace() {
        let v = json!({ "type": "Note", "content": "hi" });
        let bytes = canonicalize(&v).unwrap();
        let s = std::str::from_utf8(&bytes).expect("UTF-8");
        assert_eq!(s, r#"{"content":"hi","type":"Note"}"#);
    }
}
