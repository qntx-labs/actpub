//! Parsing and emitting the RFC 9421 `Signature:` header.
//!
//! The header is a Structured Field dictionary whose values are byte
//! sequences carrying the raw signature bytes:
//!
//! ```text
//! Signature: sig1=:<base64-signature>:, sig2=:<base64>:
//! ```
//!
//! Each label corresponds one-to-one with a label in the paired
//! `Signature-Input:` header. Callers must look up both when verifying.

use sfv::{BareItem, Dictionary, Item, ListEntry, Parser, SerializeValue};

use crate::error::Error;

/// Name of the `Signature:` HTTP header, matching the Cavage spelling so
/// that `crate::verify` can dispatch between the two flavours on a single
/// header lookup.
pub const SIGNATURE_HEADER: &str = "signature";

/// Parses the raw `Signature:` header into an ordered list of
/// `(label, signature-bytes)` pairs.
///
/// # Errors
///
/// Returns [`Error::InvalidHeader`] on sf-dictionary parse failure and
/// [`Error::MalformedSignatureHeader`] if any entry is not a byte-seq
/// item.
pub fn parse_signature_dict(raw: &str) -> Result<Vec<(String, Vec<u8>)>, Error> {
    let dict = Parser::parse_dictionary(raw.as_bytes()).map_err(|e| Error::InvalidHeader {
        name: SIGNATURE_HEADER,
        reason: e.to_owned(),
    })?;

    let mut out = Vec::with_capacity(dict.len());
    for (label, entry) in dict {
        let item = match entry {
            ListEntry::Item(item) => item,
            ListEntry::InnerList(_) => {
                return Err(Error::MalformedSignatureHeader(format!(
                    "entry `{label}` must be a byte-sequence item, not an inner list"
                )));
            }
        };
        let BareItem::ByteSeq(bytes) = item.bare_item else {
            return Err(Error::MalformedSignatureHeader(format!(
                "entry `{label}` must be a byte sequence"
            )));
        };
        out.push((label, bytes));
    }

    Ok(out)
}

/// Serialises a list of `(label, bytes)` pairs into a
/// `Signature:`-compatible value.
///
/// # Panics
///
/// Panics only if `sfv` fails to serialise an all-ByteSeq dictionary,
/// which is unreachable for the inputs we construct.
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "serialising an all-ByteSeq dictionary cannot fail"
)]
pub fn serialise_signature_dict(entries: &[(String, Vec<u8>)]) -> String {
    let mut dict = Dictionary::new();
    for (label, bytes) in entries {
        dict.insert(
            label.clone(),
            ListEntry::Item(Item::new(BareItem::ByteSeq(bytes.clone()))),
        );
    }
    dict.serialize_value()
        .expect("ByteSeq dictionary is always serialisable")
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn roundtrip_single_entry() {
        let sig_bytes = vec![0x01, 0x02, 0x03, 0x04];
        let wire = serialise_signature_dict(&[("sig1".into(), sig_bytes.clone())]);
        assert_eq!(wire, "sig1=:AQIDBA==:");
        let parsed = parse_signature_dict(&wire).expect("parse");
        assert_eq!(parsed, vec![("sig1".into(), sig_bytes)]);
    }

    #[test]
    fn roundtrip_multiple_entries_preserves_order() {
        let entries = vec![
            ("sig1".to_owned(), vec![0u8; 32]),
            ("sig2".to_owned(), vec![0xFFu8; 16]),
        ];
        let wire = serialise_signature_dict(&entries);
        let parsed = parse_signature_dict(&wire).expect("parse");
        assert_eq!(parsed, entries);
    }

    #[test]
    fn inner_list_entry_is_rejected() {
        let err = parse_signature_dict("sig1=(\"@method\")").expect_err("inner list");
        assert!(matches!(err, Error::MalformedSignatureHeader(_)));
    }

    #[test]
    fn non_byte_sequence_is_rejected() {
        let err = parse_signature_dict("sig1=123").expect_err("integer");
        assert!(matches!(err, Error::MalformedSignatureHeader(_)));
    }
}
