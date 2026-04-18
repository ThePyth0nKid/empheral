//! EPHEMERAL conformance-vector signer (Phase C.1).
//!
//! Deterministic: a given (seed, kid, payload, aad) quadruple always
//! produces byte-identical COSE_Sign1 output. That matters because the
//! committed vectors must round-trip through git diff cleanly, and any
//! later regeneration must produce the same hex so CI stays reproducible.
//!
//! ## Subcommands
//!
//! ### `sign`
//! The general-purpose single-blob signer. Reads a 32-byte Ed25519 seed,
//! hex-encodes it into a SigningKey, builds a COSE_Sign1 envelope over
//! the supplied payload with the given external AAD, and emits the
//! resulting hex to stdout together with the public key (so downstream
//! conformance JSON can pin both the blob and the anchor).
//!
//! ### `gen-phase-c1`
//! One-shot generator for the five Phase C.1 signed conformance
//! vectors (ds-069, ds-070, trej-069, trej-070, trej-071). Writes each
//! vector as a ready-to-paste JSON snippet grouped by the target file.
//! Seeds are hard-coded and deliberately fixed so the generated output
//! is stable across machines.

// Internal helper CLI — normative COSE / RFC identifiers in docs, many
// ready-made JSON Value shapes, and deliberately long literal epoch
// seconds dominate the file. Stylistic clippy warnings here add churn
// without catching real bugs.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_arguments,
    clippy::needless_pass_by_value,
    clippy::unreadable_literal
)]

use std::io::Write;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

#[derive(Parser, Debug)]
#[command(author, version, about = "EPHEMERAL COSE_Sign1 vector signer")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Build a single COSE_Sign1 blob from a seed + payload.
    Sign(SignArgs),
    /// Regenerate the five Phase C.1 signed conformance vectors.
    GenPhaseC1,
}

#[derive(clap::Args, Debug)]
struct SignArgs {
    /// 32-byte Ed25519 seed as hex (64 hex chars).
    #[arg(long)]
    seed: String,
    /// COSE key identifier for the protected header.
    #[arg(long)]
    kid: String,
    /// Payload as hex (byte-exact CBOR or any opaque blob).
    #[arg(long)]
    payload_hex: String,
    /// External AAD bytes, UTF-8 string.
    #[arg(long, default_value = "tariff")]
    aad: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Sign(a) => run_sign(&a),
        Cmd::GenPhaseC1 => run_gen_phase_c1(),
    }
}

fn run_sign(args: &SignArgs) -> Result<()> {
    let (cose_hex, pk_hex) = sign_blob(
        &args.seed,
        &args.kid,
        &hex::decode(&args.payload_hex).context("payload-hex is not valid hex")?,
        args.aad.as_bytes(),
    )?;
    let out = json!({
        "cose_sign1_bytes": cose_hex,
        "pk_hex": pk_hex,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// Core signing primitive. Deterministic in `(seed, kid, payload, aad)`.
fn sign_blob(
    seed_hex: &str,
    kid: &str,
    payload: &[u8],
    aad: &[u8],
) -> Result<(String, String)> {
    let seed_bytes = hex::decode(seed_hex).context("seed is not valid hex")?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("seed must be 32 bytes, got {}", v.len()))?;
    let sk = SigningKey::from_bytes(&seed);
    let pk_hex = hex::encode(sk.verifying_key().as_bytes());

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(kid.as_bytes().to_vec())
        .build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .create_signature(aad, |tbs| sk.sign(tbs).to_bytes().to_vec())
        .build();

    let cose_bytes = sign1
        .to_vec()
        .map_err(|e| anyhow!("serialize CoseSign1: {e}"))?;
    Ok((hex::encode(cose_bytes), pk_hex))
}

// ---- Phase C.1 fixture generation -------------------------------------
//
// Each fixture below bakes in a specific threat model:
// - `ds-069`, `ds-070`: live Ed25519 two-link chain (happy path +
//   mandate-tamper).
// - `trej-069`: payload tampered after signing → detect via verify.
// - `trej-070`: AAD swap → domain separation prevents cross-suite replay.
// - `trej-071`: impostor signer sharing a kid with the authorized
//   signer → trust-anchor lookup beats kid-based spoofing.
const SEED_ROOT: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const SEED_OPS: &str = "22222222222222222222222222222222222222222222222222222222222222aa";
const SEED_MANDATE: &str = "33333333333333333333333333333333333333333333333333333333333333aa";
const SEED_TARIFF: &str = "44444444444444444444444444444444444444444444444444444444444444aa";
const SEED_ATTACKER: &str = "55555555555555555555555555555555555555555555555555555555555555aa";

const KID_ROOT: &str = "K_cust_root_pk_TEST";
const KID_OPS: &str = "K_cust_ops_pk_TEST";
const KID_MANDATE: &str = "K_mandate_signer_pk_TEST";
const KID_TARIFF: &str = "K_tariff_signer_pk_TEST";

fn run_gen_phase_c1() -> Result<()> {
    let mut stdout = std::io::stdout().lock();

    // ----- tariff-reject vectors (trej-070 / 071 / 072) ------------------
    let tariff_payload = b"tariff-body-v1";

    // trej-070: sign a payload, then flip a byte inside it.
    let (mut cose_hex, tariff_pk) =
        sign_blob(SEED_TARIFF, KID_TARIFF, tariff_payload, b"tariff")?;
    cose_hex = tamper_payload_byte(&cose_hex)?;
    let trej069 = build_tariff_reject_vector(
        "trej-069",
        "sig-live-payload-mutated",
        "Phase C.1 live-crypto vector: a valid COSE_Sign1 over the tariff body with a single payload byte flipped after signing. Live Ed25519 verify MUST fail with signature-invalid.",
        "design-final.md §2.2 / RFC 9052 §4.4: any post-signing mutation of the signed payload breaks the MAC. Live verify is expected to detect what the mock path only asserts.",
        &cose_hex,
        &tariff_pk,
    );

    // trej-071: sign with the wrong AAD so verify (using b"tariff") fails.
    let (cose_hex, _) =
        sign_blob(SEED_TARIFF, KID_TARIFF, tariff_payload, b"delegation-link")?;
    let trej070 = build_tariff_reject_vector(
        "trej-070",
        "sig-live-aad-mismatch",
        "Phase C.1 live-crypto vector: COSE_Sign1 signed with AAD=\"delegation-link\", verified under the tariff domain AAD=\"tariff\". Domain separation MUST cause signature-invalid.",
        "design-final.md §2.2 + RFC 9052 §4.4: external AAD is part of Sig_structure_1. Reusing a delegation-link blob as a tariff blob is exactly the cross-suite replay the AAD is meant to block.",
        &cose_hex,
        &tariff_pk,
    );

    // trej-072: sign with an impostor key but keep the authorized kid.
    let (cose_hex, _) = sign_blob(SEED_ATTACKER, KID_TARIFF, tariff_payload, b"tariff")?;
    let trej071 = build_tariff_reject_vector(
        "trej-071",
        "sig-live-impostor-key",
        "Phase C.1 live-crypto vector: payload signed by an attacker-controlled Ed25519 key whose COSE header carries the authorized kid. The trust anchor resolves kid→pk using anchor-pinned bytes, so verify MUST fail.",
        "design-final.md §7.1: trust-anchor resolution is keyed on pubkey bytes, not on the attacker-supplied kid. Live verify catches the mismatch where the mock path would have needed a mock bool to flag it.",
        &cose_hex,
        &tariff_pk,
    );

    // ----- delegation-scope vectors (ds-067 / 068) -----------------------
    // Both vectors use the canonical 2-link chain (root → ops → mandate-signer)
    // because role_hierarchy_check mandates the first link's child_role ==
    // Ops and the terminal link's child_role is mandate-signer. A single-link
    // chain would violate the hierarchy and reject on ds-017.
    let link_payload = b"delegation-link-body-v1";
    let mandate_payload = b"mandate-body-v1";

    let (link0_cose, root_pk) =
        sign_blob(SEED_ROOT, KID_ROOT, link_payload, b"delegation-link")?;
    let (link1_cose, ops_pk) =
        sign_blob(SEED_OPS, KID_OPS, link_payload, b"delegation-link")?;
    let (mandate_cose_ok, mandate_pk) =
        sign_blob(SEED_MANDATE, KID_MANDATE, mandate_payload, b"mandate")?;

    let ds069 = build_delegation_accept_vector_two_link(
        "ds-069",
        "live-sig-happy-two-link",
        "Phase C.1 live-crypto vector: a two-link delegation chain (root → ops → mandate-signer) with every link and the mandate signed for real with Ed25519 COSE_Sign1. All three signatures MUST verify live against the per-vector trust anchors for the vector to accept.",
        "design-final.md §7.3 scope-match + §7.3.1 depth cap: the canonical minimum happy-path chain. Exercises scope-match at both hops AND the mandate's own signature end-to-end under live crypto, which is the path mocks could only approximate.",
        &link0_cose,
        &link1_cose,
        &mandate_cose_ok,
        &root_pk,
        &ops_pk,
        &mandate_pk,
    );

    // ds-068: same chain, but the mandate payload is flipped after signing
    // so live verify MUST catch the tamper on the mandate envelope. Links
    // remain valid so the failure is attributable exclusively to the
    // mandate's MAC.
    let mandate_cose_tampered = tamper_payload_byte(&mandate_cose_ok)?;
    let ds070 = build_delegation_reject_vector_two_link(
        "ds-070",
        "live-sig-mandate-tampered",
        "Phase C.1 live-crypto vector: two-link chain with valid signatures, but the mandate's payload has been flipped in one byte after signing. Live verify on the mandate envelope MUST fail with signature-invalid even though the chain links themselves are intact.",
        "design-final.md §2.2 + §7.3: the mandate MAC is independent from the chain MACs. A tamper on mandate bytes must fail at the mandate-signature step and never leak through via a successful chain walk.",
        &link0_cose,
        &link1_cose,
        &mandate_cose_tampered,
        &root_pk,
        &ops_pk,
        &mandate_pk,
    );

    // ----- emit -----------------------------------------------------------
    writeln!(
        stdout,
        "// ======================================================================\n\
         // Phase C.1 signed vectors — APPEND to conformance/tariff-reject.json\n\
         // (inside the `vectors` array) and conformance/delegation-scope.json\n\
         // respectively. Regenerate with `vector-signer gen-phase-c1`.\n\
         // ======================================================================"
    )?;
    writeln!(stdout, "\n// -- tariff-reject.json inserts --")?;
    writeln!(stdout, "{},", serde_json::to_string_pretty(&trej069)?)?;
    writeln!(stdout, "{},", serde_json::to_string_pretty(&trej070)?)?;
    writeln!(stdout, "{}", serde_json::to_string_pretty(&trej071)?)?;

    writeln!(stdout, "\n// -- delegation-scope.json inserts --")?;
    writeln!(stdout, "{},", serde_json::to_string_pretty(&ds069)?)?;
    writeln!(stdout, "{}", serde_json::to_string_pretty(&ds070)?)?;

    Ok(())
}

/// Parse the CoseSign1 from hex, flip byte 0 of the payload, re-encode.
/// We cannot simply flip an arbitrary position in the hex string because
/// that would scramble the header; the parse-mutate-re-encode dance keeps
/// only the inner `payload` field mutated.
fn tamper_payload_byte(cose_hex: &str) -> Result<String> {
    let bytes = hex::decode(cose_hex)?;
    let mut sign1 = coset::CoseSign1::from_slice(&bytes)
        .map_err(|e| anyhow!("parse CoseSign1: {e}"))?;
    let payload = sign1
        .payload
        .as_mut()
        .ok_or_else(|| anyhow!("CoseSign1 has no payload"))?;
    payload[0] ^= 0x01;
    let mutated = sign1
        .to_vec()
        .map_err(|e| anyhow!("reserialize CoseSign1: {e}"))?;
    Ok(hex::encode(mutated))
}

// ---- Vector JSON builders -----------------------------------------------

fn build_tariff_reject_vector(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    cose_hex: &str,
    signer_pk_hex: &str,
) -> Value {
    json!({
        "id": id,
        "category": category,
        "description": description,
        "input": {
            "tariff_cbor_hex": "<placeholder: live-crypto vector drives verification via cose_sign1_bytes>",
            "signature_verification_context": {
                "signer_key_id": KID_TARIFF,
                "trust_anchors": [KID_ROOT],
                "signature_valid_under_original_bytes": true,
                "signature_valid_under_current_bytes": true
            },
            "current_time": "2026-05-01T00:00:00Z",
            "previously_seen_version": 1,
            "cose_sign1_bytes": cose_hex,
            "trust_anchor_keys": [
                { "kid": KID_TARIFF, "alg": "ed25519", "pk_hex": signer_pk_hex }
            ]
        },
        "expected": { "outcome": "reject", "reject_code": "signature-invalid" },
        "rationale": rationale,
        "redteam_refs": ["PHASE-C1-LIVE"],
        "severity_if_failed": "critical"
    })
}

fn build_delegation_accept_vector_two_link(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    link0_cose_hex: &str,
    link1_cose_hex: &str,
    mandate_cose_hex: &str,
    root_pk_hex: &str,
    ops_pk_hex: &str,
    mandate_pk_hex: &str,
) -> Value {
    build_delegation_two_link_vector(
        id,
        category,
        description,
        rationale,
        link0_cose_hex,
        link1_cose_hex,
        mandate_cose_hex,
        root_pk_hex,
        ops_pk_hex,
        mandate_pk_hex,
        json!({ "outcome": "accept" }),
    )
}

fn build_delegation_reject_vector_two_link(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    link0_cose_hex: &str,
    link1_cose_hex: &str,
    mandate_cose_hex: &str,
    root_pk_hex: &str,
    ops_pk_hex: &str,
    mandate_pk_hex: &str,
) -> Value {
    build_delegation_two_link_vector(
        id,
        category,
        description,
        rationale,
        link0_cose_hex,
        link1_cose_hex,
        mandate_cose_hex,
        root_pk_hex,
        ops_pk_hex,
        mandate_pk_hex,
        json!({ "outcome": "reject", "reject_code": "signature-invalid" }),
    )
}

fn build_delegation_two_link_vector(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    link0_cose_hex: &str,
    link1_cose_hex: &str,
    mandate_cose_hex: &str,
    root_pk_hex: &str,
    ops_pk_hex: &str,
    mandate_pk_hex: &str,
    expected: Value,
) -> Value {
    json!({
        "id": id,
        "category": category,
        "description": description,
        "input": {
            "delegation_chain": [
                {
                    "parent_key": KID_ROOT,
                    "child_key": KID_OPS,
                    "child_role": "ops",
                    "scope": {
                        "integrations": ["stripe"],
                        "max_tier_signable": 4,
                        "max_budget": { "actions": 10000, "tokens": 1000000 },
                        "max_exp_seconds": 86400,
                        "allowed_verbs": ["charge"],
                        "allowed_resource_kinds": ["payment"]
                    },
                    "valid_from": 1_714_608_000,
                    "valid_until": 1_767_139_200,
                    "signed_by": KID_ROOT,
                    "signature_valid": true,
                    "cose_sign1_bytes": link0_cose_hex
                },
                {
                    "parent_key": KID_OPS,
                    "child_key": KID_MANDATE,
                    "child_role": "mandate_signer",
                    "scope": {
                        "integrations": ["stripe"],
                        "max_tier_signable": 3,
                        "max_budget": { "actions": 1000, "tokens": 100000 },
                        "max_exp_seconds": 86400,
                        "allowed_verbs": ["charge"],
                        "allowed_resource_kinds": ["payment"]
                    },
                    "valid_from": 1_714_608_000,
                    "valid_until": 1_767_139_200,
                    "signed_by": KID_OPS,
                    "signature_valid": true,
                    "cose_sign1_bytes": link1_cose_hex
                }
            ],
            "mandate": {
                "mandate_id": "m-phase-c1-068",
                "integration_ref": "stripe",
                "cap": [{ "verb": "charge", "resource_kind": "payment", "tier": 2 }],
                "budget": { "actions": 5 },
                "issued_at": 1_714_608_100,
                "exp": 1_714_694_400,
                "min_tariff_version": 1,
                "signer_key_hint": KID_MANDATE,
                "signed_by": KID_MANDATE,
                "signature_valid": true,
                "cose_sign1_bytes": mandate_cose_hex
            },
            "context": {
                "current_tariff_version": 2,
                "current_time": 1_714_608_500,
                "revocation_list": []
            },
            "trust_anchor_keys": [
                { "kid": KID_ROOT, "alg": "ed25519", "pk_hex": root_pk_hex },
                { "kid": KID_OPS, "alg": "ed25519", "pk_hex": ops_pk_hex },
                { "kid": KID_MANDATE, "alg": "ed25519", "pk_hex": mandate_pk_hex }
            ]
        },
        "expected": expected,
        "rationale": rationale,
        "redteam_refs": ["PHASE-C1-LIVE"],
        "severity_if_failed": "high"
    })
}
