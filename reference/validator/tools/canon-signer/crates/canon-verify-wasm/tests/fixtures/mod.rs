//! Deterministic golden fixture produced by `examples/dump_golden.rs`.
//!
//! Regenerate with:
//!
//! ```text
//! cargo run -p canon-verify-wasm --example dump_golden
//! ```
//!
//! and paste the output into the constants below.  The values are
//! byte-identical to what the `canon-signer` binary emits for the same
//! deterministic seed (`[1; 32]`) + the same request body — they are a
//! cryptographic commitment, not a matter of taste.  Do not edit by hand.

#![allow(dead_code)]

/// Hex-encoded COSE_Sign1 envelope signed with seed [1; 32] over the
/// demo fact `f_demo_0001 / customer:acme / Q1 revenue ...`.
pub const GOLDEN_ENVELOPE_HEX: &str = "84581ba20127045663616e6f6e2f38613838653364643734303966313935a0587187406b665f64656d6f5f303030316d637573746f6d65723a61636d65781a513120726576656e75652077617320455552203132372c30303070676d61696c3a6d73675f616263313233781d4f75722051312063616d6520696e206174203132376b204555522e2e2e1b0000018f10d5d4005840f1da68f2c73f1f53ead697488daa1fb18cbedf9f003c7cb3a68c4df80893f3cb96559c5abd192a89d4fb05245f7190da6bd4036e3c7c41bb1d778d085a2d1c0d";

/// Matching `ed25519:<base64(32)>` wire-format pubkey.
pub const GOLDEN_PUBKEY_WIRE: &str = "ed25519:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";

/// Expected UTF-8 kid in the protected header.
pub const GOLDEN_KID: &str = "canon/8a88e3dd7409f195";

/// SHA-256 over the canonical CBOR payload, lowercase hex.
pub const GOLDEN_EVENT_HASH: &str =
    "b0f3753095b506b390f066dbeb0d7c14c0c7dbbdb1a4e20654708d64fe6452f2";

/// A valid-but-unrelated Ed25519 pubkey, for wrong-key failure tests.
/// Derived from seed [11; 32].
pub const WRONG_PUBKEY_WIRE: &str = "ed25519:Zr5+Myx6RTMyvZ0Kf32wVfXF7xoGraZtmLOftoEMRzo=";
