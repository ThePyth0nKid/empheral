//! EPHEMERAL conformance-vector signer (Phase C.1 + C.2).
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
//!
//! ### `gen-phase-c2`
//! Generator for the eight Phase C.2 Nitro-attestation live-crypto vectors
//! (pcrrej-090..pcrrej-097). Appends them atomically to the target
//! conformance JSON file. Each vector exercises a single failure mode using
//! real ES384 COSE signatures produced by `ephemeral-attestation-test-support`.
//!
//! ### `gen-phase-c2-5`
//! Generator for the eight Phase C.2.5 Rekor transparency-log live-crypto
//! vectors (pcrrej-110..pcrrej-117). Delegates to `phase_c2_5::build_all()`
//! — every seed, timestamp, and tree-layout choice is pinned so regeneration
//! is byte-deterministic.
//!
//! ### `gen-phase-c3-c`
//! Generator for the eight Phase C.3-C classifier-signature verification
//! vectors (trej-120..trej-127). Delegates to `phase_c3_c::build_all()`.
//! Covers the five `TariffRejectCode::ClassifierSignature*` / `Classifier*`
//! reject codes plus two ABI-policy accept cases (default + override).
//! Signing inputs flow through `ephemeral_classifier::test_fixtures`, the
//! single source of truth also consumed by ephemeral-core's step-9.5 tests.
//!
//! ### `gen-fuzz-c3-c`
//! Phase C.3-C Session 2 Task #10 patch for `fuzz-baseline.json`.
//! Replaces the mock-era `fuzz-190` (`classifier_would_return: u32`) with
//! a real ABI-v1 classifier-WASM dispatch vector, and inserts a new
//! `fuzz-200` exercising the `classifier-execution-failed` reject surface
//! via the `fuel_exhausted` fixture.  Delegates vector shape to
//! `phase_c3_c_fuzz::build_all()`; mutates the target file in-place
//! rather than appending to an envelope.
//!
//! ### `gen-phase-c4-library`
//! Generator for the seventeen Phase C.4 anomaly-library-envelope
//! verification vectors (alrej-100..alrej-116). Delegates to
//! `phase_c4_library::build_all()`. Covers eleven of the twelve
//! `AnomalyLibError` top-level variants plus the four
//! `FiringCompanionFailure` sub-variants and two accept paths
//! (first-observation + strict-advance) that pin the replay ledger
//! dial.  Signing inputs flow through `ephemeral_anomaly::test_fixtures`,
//! the single source of truth also consumed by ephemeral-core's
//! `anomaly-library-reject` suite executor.

// NOTE: This binary unconditionally activates `test-fixtures` on
// `ephemeral-attestation`, so `insert_trusted_der_for_test` is reachable at
// runtime inside the vector-signer executable. Do NOT publish or ship the
// `vector-signer` binary from a workspace release build. Production
// artifacts go through `cargo build -p ephemeral-cli --release` (or similar
// per-package builds), neither of which depends on `ephemeral-attestation`
// today — `ephemeral-core` has no direct dep on `ephemeral-attestation`, so
// workspace-wide feature unification cannot leak `test-fixtures` into it.
// The remaining concern is shipping THIS binary, not polluting others.

// Internal helper CLI — normative COSE / RFC identifiers in docs, many
// ready-made JSON Value shapes, and deliberately long literal epoch
// seconds dominate the file. Stylistic clippy warnings here add churn
// without catching real bugs.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_arguments,
    clippy::needless_pass_by_value,
    clippy::unreadable_literal,
    // Phase identifiers like `C2_5`, `C3_C`, `C4_Library` reflect the
    // normative plan's section nomenclature (Phase C.2.5, C.3-C, C.4
    // etc.).  The `_N` / `_C` suffixes read as section subdivisions
    // for reviewers comparing CLI subcommands against plan sections;
    // renaming to `C25`, `C3C` would silently erase that mapping.
    non_camel_case_types
)]

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

mod merkle;
mod phase_c2_5;
mod phase_c3_c;
mod phase_c3_c_fuzz;
mod phase_c4_library;

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
    /// Regenerate + append the eight Phase C.2 Nitro-attestation vectors.
    GenPhaseC2(GenPhaseC2Args),
    /// Regenerate + append the eight Phase C.2.5 live-Rekor vectors.
    GenPhaseC2_5(GenPhaseC2_5Args),
    /// Regenerate + append the eight Phase C.3-C classifier-signature vectors.
    GenPhaseC3_C(GenPhaseC3_CArgs),
    /// Patch fuzz-baseline.json with the two Phase C.3-C live-classifier
    /// fuzz vectors (fuzz-190 replace, fuzz-200 insert).
    GenFuzzC3_C(GenFuzzC3_CArgs),
    /// Regenerate + append the seventeen Phase C.4 anomaly-library vectors.
    GenPhaseC4Library(GenPhaseC4LibraryArgs),
}

#[derive(clap::Args, Debug)]
struct GenPhaseC2Args {
    /// Target JSON.  Created with a fresh Phase-C.2 envelope if missing;
    /// otherwise appended to (duplicate IDs are rejected).
    ///
    /// The default points at a dedicated file so the mock-era
    /// `pcr-attestation-reject.json` stays schema-compatible until T15 wires
    /// the live-dispatch path.
    #[arg(long, default_value = r"..\..\..\conformance\pcr-attestation-reject-c2-live.json")]
    target: PathBuf,
    /// Dry-run: print the 8 JSON values to stdout; do not touch the file.
    #[arg(long)]
    dry_run: bool,
}

#[derive(clap::Args, Debug)]
struct GenPhaseC2_5Args {
    /// Target JSON.  Created with a fresh Phase-C.2.5 envelope if missing;
    /// otherwise appended to (duplicate IDs are rejected).
    ///
    /// The live-Rekor vectors live in a dedicated file — the T15 live-dispatch
    /// router must load `pcr-attestation-reject-c2-5-rekor.json` alongside
    /// `pcr-attestation-reject.json` and `pcr-attestation-reject-c2-live.json`
    /// when selecting for the `pcr-attestation-reject` suite.
    #[arg(long, default_value = r"..\..\..\conformance\pcr-attestation-reject-c2-5-rekor.json")]
    target: PathBuf,
    /// Dry-run: print the 8 JSON values to stdout; do not touch the file.
    #[arg(long)]
    dry_run: bool,
}

#[derive(clap::Args, Debug)]
struct GenPhaseC3_CArgs {
    /// Target JSON.  Created with a fresh Phase-C.3-C envelope if missing;
    /// otherwise appended to (duplicate IDs are rejected).
    ///
    /// The classifier-signature vectors belong to the `tariff-reject` suite
    /// (TariffRejectCode carries the five new classifier-* variants), so the
    /// file joins the existing `tariff-reject.json` family.  The `-c3-c-
    /// classifier` filename disambiguates: any T15-style router keyed on
    /// `vector_suite` must load both `tariff-reject.json` (mock-era) and
    /// `tariff-reject-c3-c-classifier.json` (this file) when selecting for
    /// the `tariff-reject` suite.
    ///
    /// Path is relative to the canonical invocation cwd (workspace root,
    /// i.e. `cargo run -p vector-signer -- gen-phase-c3-c`). From there,
    /// `../../conformance/` resolves to the repo-root `conformance/` dir.
    /// The earlier C.2 / C.2.5 defaults carry a latent off-by-one (three
    /// `..` instead of two) — fixed here for C.3-C; CI and regeneration
    /// currently pass explicit `--target`, so neither is exercised today.
    #[arg(long, default_value = r"..\..\conformance\tariff-reject-c3-c-classifier.json")]
    target: PathBuf,
    /// Dry-run: print the 8 JSON values to stdout; do not touch the file.
    #[arg(long)]
    dry_run: bool,
}

#[derive(clap::Args, Debug)]
struct GenPhaseC4LibraryArgs {
    /// Target JSON.  Created with a fresh Phase-C.4 anomaly-library envelope
    /// if missing; otherwise appended to (duplicate IDs are rejected).
    ///
    /// Unlike the tariff-reject C.3-C file which joined an existing suite,
    /// `anomaly-library-reject` is a brand-new suite key introduced in
    /// Session 4 (`VectorSuite::AnomalyLibraryReject`).  The filename and
    /// the `vector_suite` field match exactly — `stem_suite_hint` in
    /// `ephemeral-core::runner` falls back on the stem only when the body
    /// fails to parse, so a mismatched filename would silently misroute
    /// orphan load-errors.
    ///
    /// Path is relative to the canonical invocation cwd (workspace root,
    /// i.e. `cargo run -p vector-signer -- gen-phase-c4-library`). From
    /// there, `../../conformance/` resolves to the repo-root `conformance/`
    /// dir.
    #[arg(long, default_value = r"..\..\conformance\anomaly-library-reject.json")]
    target: PathBuf,
    /// Dry-run: print the 17 JSON values to stdout, pretty-printed and
    /// separated by newlines (matching the C.2 / C.2.5 / C.3-C pattern, NOT
    /// the single-array C.3-C-fuzz pattern).  The committed
    /// `tests/determinism_c4_library.rs` tripwire pins the SHA-256 of this
    /// dry-run output against regeneration drift.
    #[arg(long)]
    dry_run: bool,
}

#[derive(clap::Args, Debug)]
struct GenFuzzC3_CArgs {
    /// Target JSON.  The fuzz-baseline file must already exist — this
    /// subcommand patches two entries (fuzz-190 replace, fuzz-200
    /// insert-if-missing), it does not create a fresh envelope.
    ///
    /// Path is relative to the canonical invocation cwd (workspace root,
    /// i.e. `cargo run -p vector-signer -- gen-fuzz-c3-c`). From there,
    /// `../../conformance/` resolves to the repo-root `conformance/` dir.
    #[arg(long, default_value = r"..\..\conformance\fuzz-baseline.json")]
    target: PathBuf,
    /// Dry-run: print the two JSON values (fuzz-190 + fuzz-200) as a
    /// JSON array to stdout; do not touch the file.  The committed
    /// `tests/determinism_fuzz.rs` pins the SHA-256 of this dry-run
    /// output as a non-determinism tripwire.
    #[arg(long)]
    dry_run: bool,
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
        Cmd::GenPhaseC2(a) => run_gen_phase_c2(&a),
        Cmd::GenPhaseC2_5(a) => run_gen_phase_c2_5(&a),
        Cmd::GenPhaseC3_C(a) => run_gen_phase_c3_c(&a),
        Cmd::GenFuzzC3_C(a) => run_gen_fuzz_c3_c(&a),
        Cmd::GenPhaseC4Library(a) => run_gen_phase_c4_library(&a),
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

    // ----- tariff-reject vectors (trej-069 / 070 / 071) ------------------
    let tariff_payload = b"tariff-body-v1";

    // trej-069: sign a payload, then flip a byte inside it.
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
        true, // sig was valid over unmutated payload at signing time
    );

    // trej-070: sign with the wrong AAD so verify (using b"tariff") fails.
    let (cose_hex, _) =
        sign_blob(SEED_TARIFF, KID_TARIFF, tariff_payload, b"delegation-link")?;
    let trej070 = build_tariff_reject_vector(
        "trej-070",
        "sig-live-aad-mismatch",
        "Phase C.1 live-crypto vector: COSE_Sign1 signed with AAD=\"delegation-link\", verified under the tariff domain AAD=\"tariff\". Domain separation MUST cause signature-invalid.",
        "design-final.md §2.2 + RFC 9052 §4.4: external AAD is part of Sig_structure_1. Reusing a delegation-link blob as a tariff blob is exactly the cross-suite replay the AAD is meant to block.",
        &cose_hex,
        &tariff_pk,
        false, // sig never valid under the tariff AAD
    );

    // trej-071: sign with an impostor key but keep the authorized kid.
    let (cose_hex, _) = sign_blob(SEED_ATTACKER, KID_TARIFF, tariff_payload, b"tariff")?;
    let trej071 = build_tariff_reject_vector(
        "trej-071",
        "sig-live-impostor-key",
        "Phase C.1 live-crypto vector: payload signed by an attacker-controlled Ed25519 key whose COSE header carries the authorized kid. The trust anchor resolves kid→pk using anchor-pinned bytes, so verify MUST fail.",
        "design-final.md §7.1: trust-anchor resolution is keyed on pubkey bytes, not on the attacker-supplied kid. Live verify catches the mismatch where the mock path would have needed a mock bool to flag it.",
        &cose_hex,
        &tariff_pk,
        false, // sig never valid under the authorized anchor's public key
    );

    // ----- delegation-scope vectors (ds-069 / 070) -----------------------
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

    // ds-070: same chain, but the mandate payload is flipped after signing
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
        true,  // link0 intact
        true,  // link1 intact
        false, // mandate payload flipped → sig invalid
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
///
/// `pub(crate)` because Phase C.3-C's `build_trej_120_cose_verify_tampered`
/// reuses exactly this byte-flip strategy against a classifier envelope —
/// duplicating the parse-mutate-re-encode dance would be a second source of
/// truth for "what post-signing tamper looks like at the COSE_Sign1 layer".
pub(crate) fn tamper_payload_byte(cose_hex: &str) -> Result<String> {
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
    sig_valid_under_original_bytes: bool,
) -> Value {
    // These flags are the mock-era ground-truth; live verify drives the
    // actual outcome via `cose_sign1_bytes` + `trust_anchor_keys`. We set
    // them consistent with reality so a human auditor or a mock-only reader
    // sees the same reject reason the live path produces.
    // `current_bytes` is always false for these reject vectors — the whole
    // point is that the signature does NOT verify over the envelope as it
    // stands when the suite runs. `original_bytes` differs per scenario:
    //   payload-mutated → true  (sig was valid over unmutated payload)
    //   AAD mismatch    → false (sig never valid under the tariff AAD)
    //   impostor key    → false (sig never valid under the authorized pk)
    json!({
        "id": id,
        "category": category,
        "description": description,
        "input": {
            "tariff_cbor_hex": "<placeholder: live-crypto vector drives verification via cose_sign1_bytes>",
            "signature_verification_context": {
                "signer_key_id": KID_TARIFF,
                "trust_anchors": [KID_ROOT],
                "signature_valid_under_original_bytes": sig_valid_under_original_bytes,
                "signature_valid_under_current_bytes": false
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
        // All three envelopes verify — happy path.
        true,
        true,
        true,
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
    link0_sig_valid: bool,
    link1_sig_valid: bool,
    mandate_sig_valid: bool,
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
        link0_sig_valid,
        link1_sig_valid,
        mandate_sig_valid,
    )
}

#[allow(clippy::too_many_arguments)]
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
    link0_sig_valid: bool,
    link1_sig_valid: bool,
    mandate_sig_valid: bool,
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
                    "signature_valid": link0_sig_valid,
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
                    "signature_valid": link1_sig_valid,
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
                "signature_valid": mandate_sig_valid,
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

// ============================================================================
// Phase C.2: Nitro live-crypto attestation vectors (pcrrej-090..pcrrej-097)
// ============================================================================
//
// All 8 vectors use deterministic `build_attestation_doc` fixtures.
// No thread_rng(), no SystemTime::now() — timestamps are constants.
// Seeds are fixed CaSeeds defaults unless otherwise noted.

use ephemeral_attestation_test_support::{build_attestation_doc, BuildParams, CaSeeds};

/// Unix timestamp that matches BuildParams::default().now.
const C2_CURRENT_TIME: i64 = 1_700_000_000;

/// Nonce embedded in the doc for pcrrej-091 (freshness-binding test).
const C2_VALID_NONCE: &[u8] = b"c2-nonce-1700000000";

/// Expected nonce the suite presents — deliberately NOT C2_VALID_NONCE.
const C2_ALT_NONCE: &[u8] = b"c2-nonce-other";

/// Default PCR hash in BuildParams::default() — all 0xAA bytes, 48 bytes.
const PCR_AA: [u8; 48] = [0xAAu8; 48];

/// Mismatch hash used in pcrrej-092 expected_pcrs.PCR0 — all 0xBB bytes.
const PCR_BB: [u8; 48] = [0xBBu8; 48];

fn run_gen_phase_c2(args: &GenPhaseC2Args) -> Result<()> {
    let vectors = build_phase_c2_vectors();

    if args.dry_run {
        let mut stdout = std::io::stdout().lock();
        for v in &vectors {
            writeln!(stdout, "{}", serde_json::to_string_pretty(v)?)?;
        }
        return Ok(());
    }

    append_vectors(&args.target, vectors)
}

/// Build all 8 Phase C.2 vectors. Public so tests can call it directly.
pub fn build_phase_c2_vectors() -> Vec<Value> {
    vec![
        build_pcrrej_090(),
        build_pcrrej_091(),
        build_pcrrej_092(),
        build_pcrrej_093(),
        build_pcrrej_094(),
        build_pcrrej_095(),
        build_pcrrej_096(),
        build_pcrrej_097(),
    ]
}

// ---- pcrrej-090 : tampered payload → signature-invalid ----------------------

fn build_pcrrej_090() -> Value {
    let params = BuildParams {
        tamper_payload_byte_0: true,
        ..BuildParams::default()
    };
    let (cose_bytes, _roots) = build_attestation_doc(params);
    let root_ders = default_root_ders();

    build_c2_vector(
        "pcrrej-090",
        "live-sig-payload-mutated",
        "Phase C.2 live-crypto vector: a valid Nitro attestation doc with payload[0] \
         flipped after signing. Live ES384 verify MUST fail with signature-invalid.",
        &hex::encode(&cose_bytes),
        &root_ders,
        None,
        &hex::encode(PCR_AA),
        &hex::encode(PCR_AA),
        C2_CURRENT_TIME,
        "reject",
        "pcr-attestor-signature-invalid",
        "design-final.md §9.3 + RFC 9052 §4.4: any post-signing mutation of the \
         signed payload breaks ES384. Live verify is expected to detect what the \
         mock-bool path only asserts.",
    )
}

// ---- pcrrej-091 : nonce in doc ≠ expected nonce → nonce-mismatch ------------

fn build_pcrrej_091() -> Value {
    // Doc embeds C2_VALID_NONCE; vector's expected_nonce_hex is C2_ALT_NONCE.
    let params = BuildParams {
        nonce: Some(C2_VALID_NONCE.to_vec()),
        ..BuildParams::default()
    };
    let (cose_bytes, _roots) = build_attestation_doc(params);
    let root_ders = default_root_ders();

    build_c2_vector_nonce(
        "pcrrej-091",
        "live-sig-nonce-mismatch",
        "Phase C.2 live-crypto vector: attestation doc embeds nonce \
         c2-nonce-1700000000 but the suite presents c2-nonce-other as \
         expected_nonce_hex. Nonce binding enforces freshness — mismatch MUST reject.",
        &hex::encode(&cose_bytes),
        &root_ders,
        Some(&hex::encode(C2_ALT_NONCE)),
        &hex::encode(PCR_AA),
        &hex::encode(PCR_AA),
        C2_CURRENT_TIME,
        "reject",
        "pcr-attestation-nonce-mismatch",
        "design-final.md §9.3 + RFC 9052 §4.4: nonce binding prevents replay of \
         stale attestation docs. The suite-supplied expected nonce must match the \
         doc's embedded nonce exactly.",
    )
}

// ---- pcrrej-092 : expected PCR0 = 0xBB, doc PCR0 = 0xAA → mismatch ---------

fn build_pcrrej_092() -> Value {
    // Default params: PCR-0 = 0xAA×48.  Vector expected_pcrs.PCR0 = 0xBB×48.
    let params = BuildParams::default();
    let (cose_bytes, _roots) = build_attestation_doc(params);
    let root_ders = default_root_ders();

    build_c2_vector(
        "pcrrej-092",
        "live-sig-pcr-value-mismatch",
        "Phase C.2 live-crypto vector: doc has PCR-0 = 0xAA×48 but the vector's \
         expected_pcrs.PCR0 is 0xBB×48. PCR-0 divergence flags firmware/boot \
         rehash — MUST reject with pcr-attestation-mismatch.",
        &hex::encode(&cose_bytes),
        &root_ders,
        None,
        &hex::encode(PCR_BB), // deliberately wrong expected value
        &hex::encode(PCR_AA),
        C2_CURRENT_TIME,
        "reject",
        "pcr-attestation-mismatch",
        "design-final.md §9.3: PCR-0 covers firmware and bootloader; any deviation \
         between the attested value and the Tariff-pinned expected value is a hard \
         reject. No majority-selection is permitted.",
    )
}

// ---- pcrrej-093 : leaf cert expired → cert-expired --------------------------

fn build_pcrrej_093() -> Value {
    // leaf_not_after = C2_CURRENT_TIME - 1 → expired at the attestation time.
    let params = BuildParams {
        leaf_not_after: C2_CURRENT_TIME - 1,
        ..BuildParams::default()
    };
    let (cose_bytes, _roots) = build_attestation_doc(params);
    let root_ders = default_root_ders();

    build_c2_vector(
        "pcrrej-093",
        "live-sig-cert-expired",
        "Phase C.2 live-crypto vector: leaf certificate not_after is \
         C2_CURRENT_TIME - 1 so the cert is expired at the attestation timestamp. \
         Chain walk MUST fail with pcr-attestation-cert-expired.",
        &hex::encode(&cose_bytes),
        &root_ders,
        None,
        &hex::encode(PCR_AA),
        &hex::encode(PCR_AA),
        C2_CURRENT_TIME,
        "reject",
        "pcr-attestation-cert-expired",
        "design-final.md §9.3 + RFC 5280 §6.1.3: certificate validity window is \
         checked at the attestation timestamp. An expired leaf cert breaks the \
         chain regardless of signature correctness.",
    )
}

// ---- pcrrej-094 : broken CA chain → cert-chain-invalid ----------------------

fn build_pcrrej_094() -> Value {
    let params = BuildParams {
        break_ca_chain: true,
        ..BuildParams::default()
    };
    let (cose_bytes, _roots) = build_attestation_doc(params);
    let root_ders = default_root_ders();

    build_c2_vector(
        "pcrrej-094",
        "live-sig-ca-chain-broken",
        "Phase C.2 live-crypto vector: intermediate certificate re-signed by an \
         impostor key so the chain root→intermediate→leaf walk fails. MUST reject \
         with pcr-attestation-cert-chain-invalid.",
        &hex::encode(&cose_bytes),
        &root_ders,
        None,
        &hex::encode(PCR_AA),
        &hex::encode(PCR_AA),
        C2_CURRENT_TIME,
        "reject",
        "pcr-attestation-cert-chain-invalid",
        "design-final.md §9.3 + RFC 5280 §6.1: intermediate signed by a key not \
         belonging to the trusted root — chain verification fails at the root→ \
         intermediate link.",
    )
}

// ---- pcrrej-095 : doc CA root ∉ trusted set → attestor-not-trusted ----------

fn build_pcrrej_095() -> Value {
    // Build doc_A with default seeds (root_A).
    let params_a = BuildParams::default();
    let (cose_bytes_a, _roots_a) = build_attestation_doc(params_a);

    // Build root_B DER from a different seed — NOT the default root.
    // We derive the DER directly from seeds_b rather than building a full doc,
    // because `default_root_ders()` uses the default CaSeeds (the common case
    // for all other vectors).  Here we need root_B explicitly.
    let seeds_b = CaSeeds {
        root: [0x09; 48],
        ..CaSeeds::default()
    };
    let root_ders_b = root_ders_from_seeds(&seeds_b);

    // Vector: cose = doc_A (default root), trusted_roots = root_B.
    // Verifier can't chain doc_A to root_B → untrusted root.
    build_c2_vector(
        "pcrrej-095",
        "live-sig-root-untrusted",
        "Phase C.2 live-crypto vector: attestation doc uses CA chain rooted at \
         default seed root_A, but the vector's trusted_roots_der_hex contains \
         root_B (seed 0x09×48). Fingerprint ∉ pinned set → MUST reject with \
         pcr-attestor-not-trusted.",
        &hex::encode(&cose_bytes_a),
        &root_ders_b,
        None,
        &hex::encode(PCR_AA),
        &hex::encode(PCR_AA),
        C2_CURRENT_TIME,
        "reject",
        "pcr-attestor-not-trusted",
        "design-final.md §9.3: attestor CA root fingerprint must be in the pinned \
         NitroRootSet. Substituting a different root cert — even one with valid \
         internal structure — is rejected at the trust anchor step.",
    )
}

// ---- pcrrej-096 : wrong COSE alg (-7 ES256) → unsupported-cose-alg ---------

fn build_pcrrej_096() -> Value {
    let params = BuildParams {
        use_wrong_cose_alg: true,
        ..BuildParams::default()
    };
    let (cose_bytes, _roots) = build_attestation_doc(params);
    let root_ders = default_root_ders();

    build_c2_vector(
        "pcrrej-096",
        "live-sig-wrong-cose-alg",
        "Phase C.2 live-crypto vector: COSE_Sign1 protected header carries alg=-7 \
         (ES256) instead of -35 (ES384). Nitro only accepts ES384 — MUST reject \
         with pcr-attestation-unsupported-cose-alg.",
        &hex::encode(&cose_bytes),
        &root_ders,
        None,
        &hex::encode(PCR_AA),
        &hex::encode(PCR_AA),
        C2_CURRENT_TIME,
        "reject",
        "pcr-attestation-unsupported-cose-alg",
        "design-final.md §9.3 + RFC 9052 §4.4: ES384 (alg=-35) is the only \
         algorithm accepted for AWS Nitro attestation. alg=-7 (ES256) is rejected \
         before signature verification.",
    )
}

// ---- pcrrej-097 : duplicate PCR index → bundle-malformed --------------------

fn build_pcrrej_097() -> Value {
    let params = BuildParams {
        duplicate_pcr: true,
        ..BuildParams::default()
    };
    let (cose_bytes, _roots) = build_attestation_doc(params);
    let root_ders = default_root_ders();

    build_c2_vector(
        "pcrrej-097",
        "live-sig-duplicate-pcr",
        "Phase C.2 live-crypto vector: attestation CBOR contains two entries for \
         PCR index 0 — a malformed PCR map. MUST reject with pcr-bundle-malformed \
         before reaching signature or PCR-value checks.",
        &hex::encode(&cose_bytes),
        &root_ders,
        None,
        &hex::encode(PCR_AA),
        &hex::encode(PCR_AA),
        C2_CURRENT_TIME,
        "reject",
        "pcr-bundle-malformed",
        "design-final.md §9.3: a PCR map with duplicate indices is structurally \
         invalid. Parsers MUST reject it to prevent index-collision ambiguity \
         attacks.",
    )
}

// ---- vector JSON builder ----------------------------------------------------

/// Build a C.2 vector JSON object without nonce-specific fields.
#[allow(clippy::too_many_arguments)]
fn build_c2_vector(
    id: &str,
    category: &str,
    description: &str,
    cose_sign1_hex: &str,
    trusted_roots_der_hex: &[String],
    expected_nonce_hex: Option<&str>,
    pcr0_expected_hex: &str,
    pcr1_expected_hex: &str,
    current_time: i64,
    outcome: &str,
    reject_code: &str,
    rationale: &str,
) -> Value {
    build_c2_vector_nonce(
        id,
        category,
        description,
        cose_sign1_hex,
        trusted_roots_der_hex,
        expected_nonce_hex,
        pcr0_expected_hex,
        pcr1_expected_hex,
        current_time,
        outcome,
        reject_code,
        rationale,
    )
}

/// Build a C.2 vector JSON object (the actual implementation).
#[allow(clippy::too_many_arguments)]
fn build_c2_vector_nonce(
    id: &str,
    category: &str,
    description: &str,
    cose_sign1_hex: &str,
    trusted_roots_der_hex: &[String],
    expected_nonce_hex: Option<&str>,
    pcr0_expected_hex: &str,
    pcr1_expected_hex: &str,
    current_time: i64,
    outcome: &str,
    reject_code: &str,
    rationale: &str,
) -> Value {
    let nonce_value: Value = match expected_nonce_hex {
        Some(h) => Value::String(h.to_owned()),
        None => Value::Null,
    };

    let expected_obj = if outcome == "reject" {
        json!({ "outcome": "reject", "reject_code": reject_code })
    } else {
        json!({ "outcome": "accept" })
    };

    json!({
        "id": id,
        "category": category,
        "description": description,
        "input": {
            "cose_sign1_bytes": cose_sign1_hex,
            "trusted_roots_der_hex": trusted_roots_der_hex,
            "expected_nonce_hex": nonce_value,
            "expected_pcrs": {
                "PCR0": pcr0_expected_hex,
                "PCR1": pcr1_expected_hex
            },
            "current_time": current_time
        },
        "expected": expected_obj,
        "rationale": rationale,
        "redteam_refs": ["PHASE-C2-LIVE"],
        "severity_if_failed": "critical"
    })
}

// ---- helpers ----------------------------------------------------------------

/// Build the root DER hex(es) for a CA chain derived from `seeds`.
///
/// `NitroRootSet` does not expose its internal DER bytes, so we rebuild the
/// chain from the same seeds — cheap (one P-384 keygen + cert build) and
/// deterministic. Callers must pass exactly the seeds that were used to
/// build the attestation doc; mismatched seeds produce root DERs that
/// cannot chain-verify the doc.
fn root_ders_from_seeds(seeds: &CaSeeds) -> Vec<String> {
    use ephemeral_attestation_test_support::ca;
    let now = C2_CURRENT_TIME;
    let chain = ca::build_chain(
        seeds,
        now,
        now - 3600,
        now + 86400 * 365,
        false,
        false,
    );
    vec![hex::encode(&chain.root_der)]
}

/// Shorthand for the default-seed case (used by 7 of the 8 C.2 vectors).
fn default_root_ders() -> Vec<String> {
    root_ders_from_seeds(&CaSeeds::default())
}

// ---- atomic JSON append -----------------------------------------------------

/// Build the envelope for a fresh C.2 suite file.
///
/// `vector_suite` stays at `"pcr-attestation-reject"` because the
/// conformance/schema.json enum is pinned to the six canonical suite names
/// (design-final.md §15).  The filename (`*-c2-live.json`) is the disambiguator
/// — one suite, split across a mock-era file and a live-crypto file.
///
/// # T15 constraint
///
/// Both `pcr-attestation-reject.json` (mock-era) and
/// `pcr-attestation-reject-c2-live.json` (this file) carry the same
/// `vector_suite` value.  Any T15 router that keys on `vector_suite` must
/// load BOTH filenames for the `"pcr-attestation-reject"` suite — grep for
/// "pcr-attestation-reject-c2-live" when wiring the live-dispatch path.
fn build_c2_envelope() -> Value {
    json!({
        "schema_version": "1.0.0",
        "vector_suite": "pcr-attestation-reject",
        "spec_reference": "design-final.md §9.3 (Phase C.2 live crypto)",
        "spec_version": "round8-delta-applied + phase-c2-live",
        "generated_at": "2026-04-19T00:00:00Z",
        "coverage_summary": {
            "live-sig-payload-mutated": 1,
            "live-sig-nonce-mismatch": 1,
            "live-sig-pcr-value-mismatch": 1,
            "live-sig-cert-expired": 1,
            "live-sig-ca-chain-broken": 1,
            "live-sig-root-untrusted": 1,
            "live-sig-wrong-cose-alg": 1,
            "live-sig-duplicate-pcr": 1
        },
        "vectors": []
    })
}

fn append_vectors(target: &Path, new_vecs: Vec<Value>) -> Result<()> {
    // Defense-in-depth: reject paths that don't look like a conformance file.
    // `vector-signer` is a developer tool, but `--target` accepts any path —
    // guard against a typo or CI misconfiguration clobbering an unrelated file.
    if target.extension().and_then(|s| s.to_str()) != Some("json") {
        anyhow::bail!(
            "--target must have a .json extension, got: {}",
            target.display()
        );
    }

    let mut doc: Value = if target.exists() {
        let raw = fs::read_to_string(target)
            .with_context(|| format!("read {}", target.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("parse {} as JSON", target.display()))?
    } else {
        build_c2_envelope()
    };
    let vectors = doc
        .get_mut("vectors")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("target JSON missing top-level `vectors` array"))?;

    // Idempotence: refuse to append duplicate IDs.
    let existing_ids: HashSet<String> = vectors
        .iter()
        .filter_map(|v| v.get("id").and_then(Value::as_str).map(String::from))
        .collect();
    for v in &new_vecs {
        let id = v.get("id").and_then(Value::as_str).unwrap_or("<missing>");
        if existing_ids.contains(id) {
            anyhow::bail!("vector id `{id}` already exists in target; refusing to duplicate");
        }
    }

    vectors.extend(new_vecs);

    // 2-space indent matches existing file style.
    let mut out = serde_json::to_string_pretty(&doc)?;
    out.push('\n');
    fs::write(target, out)?;
    Ok(())
}

// ============================================================================
// Phase C.2.5: Rekor live transparency-log vectors (pcrrej-110..pcrrej-117)
// ============================================================================
//
// Delegated to `phase_c2_5::build_all()` — every seed, timestamp, and
// tree-layout choice is pinned in that module so regenerations are
// byte-deterministic. The determinism tripwire in
// `tests/determinism_c2_5.rs` catches any drift.

fn run_gen_phase_c2_5(args: &GenPhaseC2_5Args) -> Result<()> {
    let vectors = phase_c2_5::build_all();

    if args.dry_run {
        let mut stdout = std::io::stdout().lock();
        for v in &vectors {
            writeln!(stdout, "{}", serde_json::to_string_pretty(v)?)?;
        }
        return Ok(());
    }

    append_vectors_with_envelope(&args.target, vectors, build_c2_5_envelope)
}

/// Build the envelope for a fresh C.2.5 suite file.
///
/// `vector_suite` stays at `"pcr-attestation-reject"` — same suite, third
/// file (mock-era `pcr-attestation-reject.json`, Phase C.2 live-Nitro
/// `pcr-attestation-reject-c2-live.json`, Phase C.2.5 live-Rekor
/// `pcr-attestation-reject-c2-5-rekor.json`). Any T15 router that keys on
/// `vector_suite` must load all three filenames.
fn build_c2_5_envelope() -> Value {
    json!({
        "schema_version": "1.0.0",
        "vector_suite": "pcr-attestation-reject",
        "spec_reference": "design-final.md §9.4.2 (Phase C.2.5 live Rekor)",
        "spec_version": "round8-delta-applied + phase-c2-5-live-rekor",
        "generated_at": "2026-04-19T00:00:00Z",
        "coverage_summary": {
            "rekor-inclusion-proof-malformed-hex": 1,
            "rekor-inclusion-proof-siblings-tampered": 1,
            "rekor-inclusion-proof-depth-wrong": 1,
            "rekor-sth-signature-malformed-length": 1,
            "rekor-sth-signature-wrong-key": 1,
            "rekor-sth-timestamp-future": 1,
            "rekor-sth-stale": 1,
            "rekor-log-id-not-trusted": 1
        },
        "vectors": []
    })
}

/// Generic append that accepts an envelope factory so a single appender can
/// back both Phase C.2 and Phase C.2.5 generators. Keeps the idempotence +
/// .json guard in one place so future phases cannot diverge.
fn append_vectors_with_envelope(
    target: &Path,
    new_vecs: Vec<Value>,
    envelope: fn() -> Value,
) -> Result<()> {
    if target.extension().and_then(|s| s.to_str()) != Some("json") {
        anyhow::bail!(
            "--target must have a .json extension, got: {}",
            target.display()
        );
    }

    let mut doc: Value = if target.exists() {
        let raw = fs::read_to_string(target)
            .with_context(|| format!("read {}", target.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("parse {} as JSON", target.display()))?
    } else {
        envelope()
    };
    let vectors = doc
        .get_mut("vectors")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("target JSON missing top-level `vectors` array"))?;

    let existing_ids: HashSet<String> = vectors
        .iter()
        .filter_map(|v| v.get("id").and_then(Value::as_str).map(String::from))
        .collect();
    for v in &new_vecs {
        let id = v.get("id").and_then(Value::as_str).unwrap_or("<missing>");
        if existing_ids.contains(id) {
            anyhow::bail!("vector id `{id}` already exists in target; refusing to duplicate");
        }
    }

    vectors.extend(new_vecs);

    let mut out = serde_json::to_string_pretty(&doc)?;
    out.push('\n');
    fs::write(target, out)?;
    Ok(())
}

// ============================================================================
// Phase C.3-C: classifier-signature verification vectors (trej-120..trej-127)
// ============================================================================
//
// Delegated to `phase_c3_c::build_all()` — the eight vectors cover all five
// TariffRejectCode::classifier-* variants plus two accept cases (default ABI
// and ABI override), exercised against a single source-of-truth fixture
// signing API in `ephemeral-classifier::test_fixtures`. That API is the same
// one ephemeral-core's step-9.5 integration tests consume, so regeneration
// here and tariff.rs's tests cannot drift.

fn run_gen_phase_c3_c(args: &GenPhaseC3_CArgs) -> Result<()> {
    let vectors = phase_c3_c::build_all();

    if args.dry_run {
        let mut stdout = std::io::stdout().lock();
        for v in &vectors {
            writeln!(stdout, "{}", serde_json::to_string_pretty(v)?)?;
        }
        return Ok(());
    }

    append_vectors_with_envelope(&args.target, vectors, build_c3_c_envelope)
}

/// Build the envelope for a fresh C.3-C suite file.
///
/// `vector_suite` is `"tariff-reject"` — this mirrors the C.2.5 precedent
/// where `pcr-attestation-reject.json` (mock), `pcr-attestation-reject-c2-
/// live.json` and `pcr-attestation-reject-c2-5-rekor.json` all share the
/// single `pcr-attestation-reject` suite value and are disambiguated only by
/// filename. The classifier-signature reject codes are
/// `TariffRejectCode::ClassifierSignature*` variants — same suite, dedicated
/// file. Any T15-style router that keys on `vector_suite` must load both
/// `tariff-reject.json` and `tariff-reject-c3-c-classifier.json` for the
/// `tariff-reject` selection.
fn build_c3_c_envelope() -> Value {
    json!({
        "schema_version": "1.0.0",
        "vector_suite": "tariff-reject",
        "spec_reference": "design-final.md §4.3 (Phase C.3-C classifier signature verification)",
        "spec_version": "round8-delta-applied + phase-c3-c-classifier-sig",
        "generated_at": "2026-04-20T00:00:00Z",
        // Keys MUST match each vector's `category` string byte-for-byte so
        // any coverage checker that joins `coverage_summary` against emitted
        // vector categories lands on a hit for every row. C.2.5 set this
        // invariant; any drift here is a silent coverage-drop.
        "coverage_summary": {
            "live-classifier-sig-cose-verify-tampered": 1,
            "live-classifier-sig-payload-sha256-wrong-length": 1,
            "live-classifier-sig-abi-version-mismatch": 1,
            "live-classifier-sig-wasm-hash-mismatch": 1,
            "live-classifier-sig-inner-kid-mismatch": 1,
            "live-classifier-sig-partial-triple-missing-anchors": 1,
            "live-classifier-sig-happy-default-abi": 1,
            "live-classifier-sig-happy-abi-override": 1
        },
        "vectors": []
    })
}

// ---- Phase C.3-C Session 2 Task #10 fuzz-baseline patch ----------------
//
// `gen-fuzz-c3-c` is distinct from the other `gen-phase-*` subcommands in
// one structural way: it modifies an *existing* vectors array rather than
// appending to a fresh envelope.  `fuzz-190` already lives in
// `conformance/fuzz-baseline.json` as a hand-authored mock-era vector
// that Session 2 migrates to live classifier dispatch; `fuzz-200` is
// brand-new and exercises the `classifier-execution-failed` reject
// surface introduced by this task.  The patch-in-place flow keeps the
// 205 → 206 vector count change visible as a single deterministic
// regeneration step rather than a hand-edit.

fn run_gen_fuzz_c3_c(args: &GenFuzzC3_CArgs) -> Result<()> {
    let patches = phase_c3_c_fuzz::build_all();

    if args.dry_run {
        // Render as a JSON array so consumers (determinism tests, manual
        // inspection, scripts) can parse the full payload with a single
        // `serde_json::from_str` call. The element order matches
        // `build_all` — fuzz-190 before fuzz-200.
        let arr: Vec<Value> = patches.iter().map(|(_, v)| v.clone()).collect();
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{}", serde_json::to_string_pretty(&Value::Array(arr))?)?;
        return Ok(());
    }

    patch_vectors_in_file(&args.target, patches)
}

/// Apply a list of `(id, vector)` patches to the `vectors` array of an
/// existing suite JSON file.
///
/// Semantics per entry:
///
/// - If a vector with the given id already exists, it is replaced
///   in-place (array position preserved — critical because fuzz-190's
///   neighbors look for it at a specific index in some ad-hoc red-team
///   scripts).
/// - If it does not, the new vector is appended at the end.
///
/// The target file must already exist — this helper does not synthesise
/// a fresh envelope, unlike [`append_vectors_with_envelope`].  The
/// output is pretty-printed JSON with a trailing newline, matching the
/// existing committed shape.
fn patch_vectors_in_file(target: &Path, patches: Vec<(String, Value)>) -> Result<()> {
    if target.extension().and_then(|s| s.to_str()) != Some("json") {
        anyhow::bail!(
            "--target must have a .json extension, got: {}",
            target.display()
        );
    }
    if !target.exists() {
        anyhow::bail!(
            "patch target must already exist (gen-fuzz-c3-c does not create a fresh envelope): {}",
            target.display()
        );
    }

    let raw = fs::read_to_string(target)
        .with_context(|| format!("read {}", target.display()))?;
    let mut doc: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse {} as JSON", target.display()))?;

    let vectors = doc
        .get_mut("vectors")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("target JSON missing top-level `vectors` array"))?;

    // Reject duplicate IDs inside the patches list itself.  Without this
    // guard, a buggy caller supplying `[("fuzz-190", a), ("fuzz-190", b)]`
    // would silently overwrite once, then re-find the updated entry and
    // overwrite again with `b`, leaving `a` lost and no error surfaced.
    let mut seen_ids: HashSet<&str> = HashSet::new();
    for (id, _) in &patches {
        if !seen_ids.insert(id.as_str()) {
            anyhow::bail!("patches list contains duplicate id `{id}`");
        }
    }

    let mut replaced = HashSet::<String>::new();
    let mut inserted = Vec::<String>::new();

    for (id, new_val) in patches {
        let pos = vectors
            .iter()
            .position(|v| v.get("id").and_then(Value::as_str) == Some(id.as_str()));
        if let Some(i) = pos {
            vectors[i] = new_val;
            replaced.insert(id);
        } else {
            vectors.push(new_val);
            inserted.push(id);
        }
    }

    let mut out = serde_json::to_string_pretty(&doc)?;
    out.push('\n');

    // Atomic write: truncate-then-write via `fs::write` leaves the target
    // zero-length or half-written on SIGKILL / power loss, corrupting the
    // only copy of `fuzz-baseline.json`.  Write to a sibling temp file
    // and rename — same-volume rename is atomic on POSIX and NTFS.
    let tmp = target.with_extension("json.tmp");
    fs::write(&tmp, &out)
        .with_context(|| format!("write tmp {}", tmp.display()))?;
    fs::rename(&tmp, target)
        .with_context(|| format!("rename {} -> {}", tmp.display(), target.display()))?;

    eprintln!(
        "patched {}: replaced={:?} inserted={:?}",
        target.display(),
        replaced,
        inserted
    );
    Ok(())
}

// ============================================================================
// Phase C.4 Session 4: anomaly-library envelope verification vectors
// (alrej-100..alrej-116)
// ============================================================================
//
// Delegated to `phase_c4_library::build_all()` — the seventeen vectors cover
// eleven of the twelve `AnomalyLibError` top-level variants (excluding
// `LedgerFailure`, which needs a custom `AnomalyLedger` impl and therefore
// cannot be expressed through a JSON vector), the four
// `FiringCompanionFailure` sub-variants, and two accept paths (first
// observation + strict advance) exercising the replay ledger.  The envelope
// is signed by `ephemeral_anomaly::test_fixtures::fixture_anomaly_signing_key`
// — the same source of fixture truth the ephemeral-core
// `anomaly-library-reject` suite executor reaches for via the
// `test_fixtures` feature, so regeneration here and live-dispatch there
// cannot drift.

fn run_gen_phase_c4_library(args: &GenPhaseC4LibraryArgs) -> Result<()> {
    let vectors = phase_c4_library::build_all();

    if args.dry_run {
        let mut stdout = std::io::stdout().lock();
        for v in &vectors {
            writeln!(stdout, "{}", serde_json::to_string_pretty(v)?)?;
        }
        return Ok(());
    }

    append_vectors_with_envelope(&args.target, vectors, build_c4_library_envelope)
}

/// Build the envelope for a fresh C.4 anomaly-library suite file.
///
/// `vector_suite` is `"anomaly-library-reject"` — a brand-new suite key
/// introduced in Session 4 (`VectorSuite::AnomalyLibraryReject`).  Unlike
/// the C.2 / C.2.5 / C.3-C generators which appended into existing suite
/// families (`pcr-attestation-reject`, `tariff-reject`), this suite has
/// exactly one file; any future anomaly-library expansion should append
/// into this same file rather than introduce a second filename.
///
/// `coverage_summary` keys MUST match each vector's `category` string
/// byte-for-byte so a downstream coverage checker that joins
/// `coverage_summary` against emitted vector categories lands on a hit
/// for every row.  The C.2.5 envelope set this invariant; any drift here
/// is a silent coverage-drop.
fn build_c4_library_envelope() -> Value {
    json!({
        "schema_version": "1.0.0",
        "vector_suite": "anomaly-library-reject",
        "spec_reference": "design-final.md §3.5 (Phase C.4 anomaly-library envelope verification)",
        "spec_version": "round8-delta-applied + phase-c4-anomaly-library",
        "generated_at": "2026-04-21T00:00:00Z",
        "coverage_summary": {
            "anomaly-library-cose-verify-tampered": 1,
            "anomaly-library-payload-not-cbor": 1,
            "anomaly-library-abi-version-mismatch": 1,
            "anomaly-library-signer-kid-mismatch": 1,
            "anomaly-library-not-yet-valid": 1,
            "anomaly-library-expired": 1,
            "anomaly-library-pattern-id-duplicate": 1,
            "anomaly-library-severity-action-inconsistent": 1,
            "anomaly-library-unknown-verb-family": 1,
            "anomaly-library-companion-none-declared": 1,
            "anomaly-library-companion-not-found": 1,
            "anomaly-library-companion-not-cumulative": 1,
            "anomaly-library-companion-window-too-short": 1,
            "anomaly-library-version-replay": 1,
            "anomaly-library-version-rollback": 1,
            "anomaly-library-accept-first-observation": 1,
            "anomaly-library-accept-strict-advance": 1
        },
        "vectors": []
    })
}
