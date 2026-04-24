//! `canon-signer` core library.
//!
//! The binary ([`crate::main`]) is a thin NDJSON-over-stdio wrapper around
//! this library.  Exposing the event-hashing and COSE-envelope builders
//! as a library makes integration tests independent reconstructions of
//! the expected wire bytes (rather than assertions against the binary's
//! own output — which would be self-referential).
//!
//! Public surface (stable within this branch, NOT an EPHEMERAL
//! public-API commitment):
//! - [`event::encode_payload`] / [`event::event_hash`] — canonical CBOR
//!   + SHA-256 digest of a Canon fact.
//! - [`cose::build_cose_sign1`] — envelope builder.
//! - [`io::SignRequest`] / [`io::SignResponse`] / [`io::ErrorResponse`] —
//!   wire types shared between the binary and its integration tests.
//! - [`key::SignerIdentity`] / [`key::Source`] — key-loading façade.
//!
//! # Domain separation
//!
//! The COSE `external_aad` is fixed at [`COSE_EXTERNAL_AAD`].  Do not
//! reuse this constant in EPHEMERAL envelopes, and do not change it
//! post-shipping: every signature ever produced by this binary commits
//! to these exact bytes, so a rename breaks verification of historical
//! facts.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::doc_markdown)]

pub mod cose;
pub mod event;
pub mod io;
pub mod key;

/// Fixed external AAD bound into every Canon COSE_Sign1 signature.
///
/// Domain-separation tag preventing cross-protocol signature confusion
/// if the same Ed25519 key is ever reused for an EPHEMERAL envelope
/// (which uses different AADs such as `b"tariff"` or
/// `b"ephemeral/anomaly-library/v1"`).  Never change these bytes.
pub const COSE_EXTERNAL_AAD: &[u8] = b"canon/fact/v1";

/// Key-ID prefix emitted into the COSE protected header.  Combined with
/// the first 16 hex chars of the raw Ed25519 public key, yielding a
/// UTF-8 kid of the form `canon/<16-hex-chars>`.
pub const CANON_KID_PREFIX: &str = "canon/";
