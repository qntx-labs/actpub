//! Parsing and emitting the `Signature-Input:` header.
//!
//! Per RFC 9421 §4.1, this header is a Structured Field dictionary of
//! inner lists with parameters:
//!
//! ```text
//! Signature-Input: sig1=("@method" "@target-uri" "host");keyid="kid";created=1700000000
//! ```
//!
//! Each entry is identified by a caller-chosen label (`sig1` by
//! convention); a single request may carry multiple labels so that
//! middle boxes can attach their own signatures.

use sfv::{BareItem, ListEntry, Parser};

use crate::error::Error;
use crate::rfc9421::components::Component;

/// Name of the `Signature-Input:` HTTP header.
pub const SIGNATURE_INPUT_HEADER: &str = "signature-input";

/// Canonical parameter names defined by RFC 9421 §2.3.
mod param {
    pub const KEYID: &str = "keyid";
    pub const ALG: &str = "alg";
    pub const CREATED: &str = "created";
    pub const EXPIRES: &str = "expires";
    pub const NONCE: &str = "nonce";
    pub const TAG: &str = "tag";
}

/// One entry of the `Signature-Input:` dictionary: the ordered component
/// list plus parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SignatureInput {
    /// Components covered by the signature, in signing order.
    pub components: Vec<Component>,
    /// `keyid=` parameter (mandatory for `ActivityPub` use).
    pub keyid: Option<String>,
    /// `alg=` parameter hint; `None` means "detect from the resolved key".
    pub algorithm: Option<String>,
    /// `created=` parameter in seconds since the UNIX epoch.
    pub created: Option<i64>,
    /// `expires=` parameter in seconds since the UNIX epoch.
    pub expires: Option<i64>,
    /// `nonce=` parameter as emitted by the signer, opaque to us.
    pub nonce: Option<String>,
    /// `tag=` parameter as emitted by the signer, opaque to us.
    pub tag: Option<String>,
}

impl SignatureInput {
    /// Serialises this entry as the inner-list-with-parameters portion
    /// that appears after `label=`. The full header value is built by
    /// [`serialise_signature_input_dict`].
    ///
    /// # Panics
    ///
    /// Panics only if `sfv` fails to serialise a well-formed inner list;
    /// this is unreachable for the inputs we construct.
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "serialising a well-formed InnerList cannot fail"
    )]
    pub fn serialise_inner_list(&self) -> String {
        use core::fmt::Write as _;
        let mut out = String::new();
        out.push('(');
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(&c.lexical());
        }
        out.push(')');
        let infallible = "writing to an owned String is infallible";
        if let Some(keyid) = &self.keyid {
            write!(out, r#";keyid="{keyid}""#).expect(infallible);
        }
        if let Some(alg) = &self.algorithm {
            write!(out, r#";alg="{alg}""#).expect(infallible);
        }
        if let Some(c) = self.created {
            write!(out, ";created={c}").expect(infallible);
        }
        if let Some(e) = self.expires {
            write!(out, ";expires={e}").expect(infallible);
        }
        if let Some(n) = &self.nonce {
            write!(out, r#";nonce="{n}""#).expect(infallible);
        }
        if let Some(t) = &self.tag {
            write!(out, r#";tag="{t}""#).expect(infallible);
        }
        out
    }
}

/// Parses the raw `Signature-Input:` header into a sequence of
/// (label, [`SignatureInput`]) pairs, preserving insertion order.
///
/// # Errors
///
/// Returns [`Error::InvalidHeader`] if the header is not a valid sf-dict,
/// and [`Error::MalformedSignatureHeader`] if any entry's components or
/// parameters are malformed.
pub fn parse_signature_input_dict(raw: &str) -> Result<Vec<(String, SignatureInput)>, Error> {
    let dict = Parser::parse_dictionary(raw.as_bytes()).map_err(|e| Error::InvalidHeader {
        name: SIGNATURE_INPUT_HEADER,
        reason: e.to_owned(),
    })?;

    let mut out = Vec::with_capacity(dict.len());
    for (label, entry) in dict {
        let inner_list = match entry {
            ListEntry::InnerList(il) => il,
            ListEntry::Item(_) => {
                return Err(Error::MalformedSignatureHeader(format!(
                    "entry `{label}` must be an inner list of components"
                )));
            }
        };

        let components: Vec<Component> = inner_list
            .items
            .iter()
            .map(|item| {
                let BareItem::String(s) = &item.bare_item else {
                    return Err(Error::MalformedSignatureHeader(format!(
                        "entry `{label}` contains a non-string component"
                    )));
                };
                Component::parse(s)
            })
            .collect::<Result<_, _>>()?;

        let mut input = SignatureInput {
            components,
            keyid: None,
            algorithm: None,
            created: None,
            expires: None,
            nonce: None,
            tag: None,
        };

        for (pname, pvalue) in &inner_list.params {
            match pname.as_str() {
                param::KEYID => input.keyid = string_param(pvalue, &label, param::KEYID)?,
                param::ALG => input.algorithm = string_param(pvalue, &label, param::ALG)?,
                param::CREATED => input.created = integer_param(pvalue, &label, param::CREATED)?,
                param::EXPIRES => input.expires = integer_param(pvalue, &label, param::EXPIRES)?,
                param::NONCE => input.nonce = string_param(pvalue, &label, param::NONCE)?,
                param::TAG => input.tag = string_param(pvalue, &label, param::TAG)?,
                _ => {
                    // Unknown parameters are tolerated per §2.3.
                }
            }
        }

        out.push((label, input));
    }

    Ok(out)
}

fn string_param(value: &BareItem, label: &str, param: &str) -> Result<Option<String>, Error> {
    match value {
        BareItem::String(s) => Ok(Some(s.clone())),
        _ => Err(Error::MalformedSignatureHeader(format!(
            "entry `{label}` has non-string `{param}` parameter"
        ))),
    }
}

fn integer_param(value: &BareItem, label: &str, param: &str) -> Result<Option<i64>, Error> {
    match value {
        BareItem::Integer(n) => Ok(Some(*n)),
        _ => Err(Error::MalformedSignatureHeader(format!(
            "entry `{label}` has non-integer `{param}` parameter"
        ))),
    }
}

/// Serialises a `(label, SignatureInput)` sequence into a single header
/// value suitable for inserting into an `http::Request`.
///
/// # Panics
///
/// Panics only if `sfv` fails to serialise a well-formed dictionary; this
/// is unreachable for the inputs we construct.
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "serialising a well-formed sf-dictionary cannot fail"
)]
pub fn serialise_signature_input_dict(entries: &[(String, SignatureInput)]) -> String {
    let mut out = String::new();
    for (i, (label, input)) in entries.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(label);
        out.push('=');
        out.push_str(&input.serialise_inner_list());
    }
    out
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn serialise_matches_rfc9421_example() {
        let input = SignatureInput {
            components: vec![
                Component::Method,
                Component::TargetUri,
                Component::Header("host".into()),
                Component::Header("date".into()),
            ],
            keyid: Some("test-key-rsa".into()),
            algorithm: None,
            created: Some(1_618_884_473),
            expires: None,
            nonce: None,
            tag: None,
        };
        let dict = serialise_signature_input_dict(&[("sig1".into(), input)]);
        assert_eq!(
            dict,
            r#"sig1=("@method" "@target-uri" "host" "date");keyid="test-key-rsa";created=1618884473"#,
        );
    }

    #[test]
    fn parse_roundtrips_through_serialise() {
        let input = SignatureInput {
            components: vec![Component::Method, Component::Authority],
            keyid: Some("kid".into()),
            algorithm: Some("ed25519".into()),
            created: Some(1_700_000_000),
            expires: Some(1_700_000_600),
            nonce: Some("abc".into()),
            tag: Some("mastodon".into()),
        };
        let wire = serialise_signature_input_dict(&[("sig".into(), input.clone())]);
        let parsed = parse_signature_input_dict(&wire).expect("parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, "sig");
        assert_eq!(parsed[0].1, input);
    }

    #[test]
    fn entry_of_wrong_shape_is_rejected() {
        // `sig1` is a bare token here, not an inner list.
        let wire = "sig1=123";
        let err = parse_signature_input_dict(wire).expect_err("wrong shape");
        assert!(matches!(err, Error::MalformedSignatureHeader(_)));
    }

    #[test]
    fn unknown_parameters_are_tolerated() {
        let wire = r#"sig1=("@method");keyid="kid";future_param=42"#;
        let parsed = parse_signature_input_dict(wire).expect("parse");
        assert_eq!(parsed[0].1.keyid.as_deref(), Some("kid"));
    }

    #[test]
    fn non_string_component_is_rejected() {
        // Components must be quoted strings, not tokens or integers.
        let wire = "sig1=(foo)";
        let err = parse_signature_input_dict(wire).expect_err("non-string component");
        assert!(matches!(err, Error::MalformedSignatureHeader(_)));
    }
}
