//! Prints the deterministic golden envelope + pubkey used by both the
//! `roundtrip_native.rs` integration test and the wasm-bindgen smoke
//! tests.  Run with:
//!
//! ```text
//! cargo run -p canon-verify-wasm --example dump_golden
//! ```
//!
//! Output is meant for piping into documentation, fixture files, or
//! the hackathon "copy-paste this into the demo" card.
//!
//! This example links against `canon-signer` + `ed25519-dalek`, which
//! are only available as dev-dependencies on non-wasm32 targets (see
//! the crate `Cargo.toml`).  Compiling on wasm32 therefore collapses
//! the body into an empty `main()` — the file still needs to exist
//! for `cargo build` to traverse the examples directory cleanly.

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use canon_signer::cose::{build_cose_sign1, derive_kid};
    use canon_signer::event::{encode_payload, event_hash};
    use canon_signer::io::SignRequest;
    use ed25519_dalek::SigningKey;

    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let vk = sk.verifying_key().to_bytes();
    let kid = derive_kid(&vk);
    let pubkey_wire = format!("ed25519:{}", B64.encode(vk));

    let req = SignRequest {
        op: "sign".to_string(),
        fact_id: "f_demo_0001".to_string(),
        entity: "customer:acme".to_string(),
        claim: "Q1 revenue was EUR 127,000".to_string(),
        source_ref: "gmail:msg_abc123".to_string(),
        source_excerpt: Some("Our Q1 came in at 127k EUR...".to_string()),
        parent_hash: String::new(),
        created_at_ms: 1_713_974_400_000,
    };
    let payload = encode_payload(&req).unwrap();
    let hash = event_hash(&payload);
    let envelope = build_cose_sign1(&payload, &sk, &kid).unwrap();

    println!("// kid          = {kid}");
    println!("// pubkey_wire  = {pubkey_wire}");
    println!("// event_hash   = {hash}");
    println!("// envelope_hex = {} bytes / {} hex chars", envelope.len(), envelope.len() * 2);
    println!("pub const GOLDEN_ENVELOPE_HEX: &str = \"{}\";", hex::encode(&envelope));
    println!("pub const GOLDEN_PUBKEY_WIRE: &str = \"{pubkey_wire}\";");
    println!("pub const GOLDEN_KID: &str = \"{kid}\";");
    println!("pub const GOLDEN_EVENT_HASH: &str = \"{hash}\";");

    let wrong_sk = SigningKey::from_bytes(&[11u8; 32]);
    let wrong_vk = wrong_sk.verifying_key().to_bytes();
    let wrong_wire = format!("ed25519:{}", B64.encode(wrong_vk));
    println!("pub const WRONG_PUBKEY_WIRE: &str = \"{wrong_wire}\";");
}

#[cfg(target_arch = "wasm32")]
fn main() {}
