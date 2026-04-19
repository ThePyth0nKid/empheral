//! Phase C.2.5 — eight live-Rekor transparency-log reject vectors.
//!
//! Each builder returns a JSON `Value` of the `pcr-attestation-reject` shape,
//! carrying a `transparency_log_proof` populated with real RFC 9162 §2.1.1
//! inclusion-proof hashes and a real Ed25519 Signed-Tree-Head signature.
//!
//! The validator's `classify_live_rekor` dispatch is presence-gated: when
//! all seven live fields are populated, the suite reroutes from the mock
//! boolean path to full crypto verification. Each vector isolates a single
//! failure mode so the expected reject code pins a specific validator
//! branch:
//!
//! | ID        | Failure mode               | Expected code                             |
//! |-----------|----------------------------|-------------------------------------------|
//! | pcrrej-110| malformed proof-path hex   | pcr-attestation-transparency-invalid      |
//! | pcrrej-111| sibling tampered post-sign | pcr-attestation-transparency-invalid      |
//! | pcrrej-112| proof depth vs tree_size   | pcr-attestation-transparency-invalid      |
//! | pcrrej-113| STH signature 63 bytes     | pcr-attestation-transparency-invalid      |
//! | pcrrej-114| STH signed by wrong key    | pcr-attestation-transparency-invalid      |
//! | pcrrej-115| sth_timestamp > current    | pcr-attestation-transparency-invalid      |
//! | pcrrej-116| Tariff-age-window violated | pcr-attestation-transparency-stale        |
//! | pcrrej-117| log_id ∉ trusted set       | pcr-attestation-transparency-log-unknown  |
//!
//! # Determinism
//!
//! Every value that flows into a signature or hash is a fixed constant.
//! No `SystemTime::now`, no `thread_rng`, no environment reads. The SHA-256
//! tripwire in `tests/determinism_c2_5.rs` catches any accidental source of
//! non-determinism.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ephemeral_attestation::rekor::RekorSignedTreeHead;
use serde_json::{json, Value};

use crate::merkle::{generate_proof, leaf_hash};

// ─── Deterministic seeds & timestamps (pinned by the handoff spec) ──────────

/// Main log signing key seed. Pairs with `log_pubkey_hex` for every vector
/// except pcrrej-114 (which signs with `SEED_ALT_KEY` to surface the wrong-key
/// failure mode).
const SEED_SIGNING_KEY: [u8; 32] = [0x07; 32];
/// Alternate seed used exclusively for pcrrej-114.
const SEED_ALT_KEY: [u8; 32] = [0x09; 32];

/// Log identifier in the Tariff trust list (used by 7 of 8 vectors).
const LOG_ID_TRUSTED: [u8; 32] = [0x11; 32];
/// Log identifier for pcrrej-117 — deliberately absent from the trust list.
const LOG_ID_UNTRUSTED: [u8; 32] = [0x44; 32];

/// Fixed STH timestamp used by every happy-case vector. Chosen to be a
/// round number well inside the Unix epoch so the JSON literal stays short.
const STH_TIMESTAMP: i64 = 1_700_000_000;
/// Suite-supplied `current_time` for the non-stale vectors: `STH_TIMESTAMP + 100s`.
const CURRENT_TIME_OK: i64 = 1_700_000_100;
/// Suite-supplied `current_time` for pcrrej-116: `STH_TIMESTAMP + 10_000s ≈ 2h 46m`.
/// Drives the `age > max_root_age_seconds_override` path.
const CURRENT_TIME_STALE: i64 = 1_700_010_000;

/// Tariff-side freshness window used throughout; 1 hour keeps the stale
/// vector well above the threshold while every fresh vector stays below it.
const MAX_ROOT_AGE_SECONDS: u64 = 3600;

/// Fixed eight-leaf tree shared across builders. Eight is a power of two so
/// the proof depth is exactly 3 for every index — which makes the `112`
/// depth-mismatch vector trivial to construct (claim `sth_tree_size=16` in
/// the vector while the actual depth is still 3).
const TREE_SIZE: u64 = 8;
/// Fixed index whose leaf we will "prove" in every vector. Any index in
/// `[0, TREE_SIZE)` works for a power-of-two tree; 3 keeps the proof path
/// non-trivial (all three siblings differ).
const ENTRY_INDEX: u64 = 3;

/// Build the canonical leaf dataset. Eight distinct byte strings keep
/// every internal hash unique, so a sibling tamper in pcrrej-111 always
/// diverges the reconstructed root.
fn canonical_leaves() -> Vec<Vec<u8>> {
    (0..TREE_SIZE)
        .map(|i| format!("phase-c2-5-leaf-{i}").into_bytes())
        .collect()
}

/// Sign a [`RekorSignedTreeHead`] with the supplied seed. Returns the raw
/// 64-byte Ed25519 signature.
///
/// The STH's `signature` field is ignored during canonical-byte
/// computation (Rekor's canonical format excludes the signature itself),
/// so an empty placeholder before signing is equivalent to the final
/// signed form for this call — but we still emit the final signed
/// [`RekorSignedTreeHead`] back to the caller for clarity.
fn sign_sth(seed: [u8; 32], sth: &RekorSignedTreeHead) -> Vec<u8> {
    let sk = SigningKey::from_bytes(&seed);
    let bytes = sth.canonical_bytes();
    sk.sign(&bytes).to_bytes().to_vec()
}

/// Derive the verifying key bytes (32) for a given seed.
fn pubkey_for(seed: [u8; 32]) -> [u8; 32] {
    *VerifyingKey::from(&SigningKey::from_bytes(&seed))
        .as_bytes()
}

/// Shared setup: compute root + proof for the canonical leaves + index.
struct SthSetup {
    root: [u8; 32],
    proof_path_hex: Vec<String>,
    entry_leaf_hash_hex: String,
}

fn setup_sth() -> SthSetup {
    let leaves = canonical_leaves();
    let (proof, root) = generate_proof(&leaves, ENTRY_INDEX);
    let proof_path_hex = proof.iter().map(hex::encode).collect();
    let leaf_bytes = leaf_hash(
        &leaves[usize::try_from(ENTRY_INDEX).expect("ENTRY_INDEX fits in usize")],
    );
    SthSetup {
        root,
        proof_path_hex,
        entry_leaf_hash_hex: hex::encode(leaf_bytes),
    }
}

// ─── Vector builders ────────────────────────────────────────────────────────

/// Emit all eight Phase C.2.5 reject vectors in ascending ID order.
pub fn build_all() -> Vec<Value> {
    vec![
        build_pcrrej_110(),
        build_pcrrej_111(),
        build_pcrrej_112(),
        build_pcrrej_113(),
        build_pcrrej_114(),
        build_pcrrej_115(),
        build_pcrrej_116(),
        build_pcrrej_117(),
    ]
}

/// pcrrej-110 — `proof_path_hex[0]` carries an odd-length hex string so the
/// validator's `decode_hex_fixed` rejects before ever touching crypto.
fn build_pcrrej_110() -> Value {
    let s = setup_sth();
    let sth = base_sth(&s.root, TREE_SIZE, STH_TIMESTAMP, LOG_ID_TRUSTED);
    let sig = sign_sth(SEED_SIGNING_KEY, &sth);

    // Deliberately corrupt position 0 of the proof path.
    let mut proof_path_hex = s.proof_path_hex;
    proof_path_hex[0] = "abc".to_string();

    build_vector(
        "pcrrej-110",
        "rekor-inclusion-proof-malformed-hex",
        "Phase C.2.5 live-Rekor vector: a structurally valid STH + inclusion \
         proof, but the first sibling hash in proof_path_hex is a three-char \
         hex fragment (\"abc\") — odd length, not decodable. MUST reject with \
         pcr-attestation-transparency-invalid before any hashing work.",
        "design-final.md §9.4.2: fixed-width hex fields in the live path are \
         treated as adversary-controlled. Odd-length or non-hex input is \
         rejected at decode time — no partial decode, no silent zero-padding.",
        BuildFields {
            proof_path_hex,
            sth_signature_hex: hex::encode(&sig),
            sth_timestamp: STH_TIMESTAMP,
            sth_tree_root_hex: hex::encode(s.root),
            sth_tree_size: TREE_SIZE,
            entry_index: ENTRY_INDEX,
            entry_leaf_hash_hex: s.entry_leaf_hash_hex,
            log_pubkey_hex: hex::encode(pubkey_for(SEED_SIGNING_KEY)),
            log_id_hex: hex::encode(LOG_ID_TRUSTED),
            current_time: CURRENT_TIME_OK,
            trusted_log_id_hex: hex::encode(LOG_ID_TRUSTED),
            max_root_age_seconds_override: MAX_ROOT_AGE_SECONDS,
        },
        "reject",
        "pcr-attestation-transparency-invalid",
    )
}

/// pcrrej-111 — valid proof path with one byte flipped in the first sibling.
/// The Merkle walk then reconstructs a root that cannot match the signed STH
/// `tree_root`.
fn build_pcrrej_111() -> Value {
    let s = setup_sth();
    let sth = base_sth(&s.root, TREE_SIZE, STH_TIMESTAMP, LOG_ID_TRUSTED);
    let sig = sign_sth(SEED_SIGNING_KEY, &sth);

    // Take the validly generated sibling, flip byte 0 of its hex (32-byte
    // sibling → 64-char hex; flipping the first hex nibble mutates byte 0).
    let mut proof_path_hex = s.proof_path_hex;
    let first = &proof_path_hex[0];
    let mut bytes = hex::decode(first).expect("generator output is valid hex");
    bytes[0] ^= 0x01;
    proof_path_hex[0] = hex::encode(bytes);

    build_vector(
        "pcrrej-111",
        "rekor-inclusion-proof-siblings-tampered",
        "Phase C.2.5 live-Rekor vector: a valid STH over the real Merkle root, \
         but the first sibling hash in the inclusion proof has one bit \
         flipped. Merkle walk reconstructs a different root → \
         pcr-attestation-transparency-invalid.",
        "design-final.md §9.4.2: the Merkle walk is the second half of the \
         live-Rekor pipeline. Any sibling tamper must fail the root \
         comparison constant-time equality check.",
        BuildFields {
            proof_path_hex,
            sth_signature_hex: hex::encode(&sig),
            sth_timestamp: STH_TIMESTAMP,
            sth_tree_root_hex: hex::encode(s.root),
            sth_tree_size: TREE_SIZE,
            entry_index: ENTRY_INDEX,
            entry_leaf_hash_hex: s.entry_leaf_hash_hex,
            log_pubkey_hex: hex::encode(pubkey_for(SEED_SIGNING_KEY)),
            log_id_hex: hex::encode(LOG_ID_TRUSTED),
            current_time: CURRENT_TIME_OK,
            trusted_log_id_hex: hex::encode(LOG_ID_TRUSTED),
            max_root_age_seconds_override: MAX_ROOT_AGE_SECONDS,
        },
        "reject",
        "pcr-attestation-transparency-invalid",
    )
}

/// pcrrej-112 — STH claims `tree_size = 16` (signs accordingly) but the
/// proof path still has length 3 from the real 8-leaf tree.
/// `verify_rekor_inclusion` computes `expected_depth(index, 16) = 4` and
/// rejects the length mismatch.
/// Claimed tree size used by pcrrej-112's "the STH lies about size" scenario.
/// Any power-of-two strictly greater than `TREE_SIZE` works; 16 keeps the
/// depth off-by-one (the real path is depth-3 over 8 leaves, but
/// depth-4 is what a tree of size 16 would demand).
const LIED_TREE_SIZE: u64 = 16;

fn build_pcrrej_112() -> Value {
    let s = setup_sth();
    // Sign over the lie: tree_size = 16 but the underlying tree root is
    // the 8-leaf root. Verifier accepts the signature (we computed it),
    // then trips the depth check on the proof.
    let sth = base_sth(&s.root, LIED_TREE_SIZE, STH_TIMESTAMP, LOG_ID_TRUSTED);
    let sig = sign_sth(SEED_SIGNING_KEY, &sth);

    build_vector(
        "pcrrej-112",
        "rekor-inclusion-proof-depth-wrong",
        "Phase C.2.5 live-Rekor vector: STH claims tree_size=16 (signature \
         covers that value). Proof path is length 3 — the correct depth for \
         tree_size=8. Validator computes expected_depth(3, 16)=4 and rejects \
         with pcr-attestation-transparency-invalid.",
        "design-final.md §9.4.2 + RFC 9162 §2.1.1: proof_path length is \
         strictly determined by (index, tree_size). Length mismatch is an \
         early-reject because a longer- or shorter-than-expected path cannot \
         reconstruct any valid root.",
        BuildFields {
            proof_path_hex: s.proof_path_hex,
            sth_signature_hex: hex::encode(&sig),
            sth_timestamp: STH_TIMESTAMP,
            sth_tree_root_hex: hex::encode(s.root),
            sth_tree_size: LIED_TREE_SIZE,
            entry_index: ENTRY_INDEX,
            entry_leaf_hash_hex: s.entry_leaf_hash_hex,
            log_pubkey_hex: hex::encode(pubkey_for(SEED_SIGNING_KEY)),
            log_id_hex: hex::encode(LOG_ID_TRUSTED),
            current_time: CURRENT_TIME_OK,
            trusted_log_id_hex: hex::encode(LOG_ID_TRUSTED),
            max_root_age_seconds_override: MAX_ROOT_AGE_SECONDS,
        },
        "reject",
        "pcr-attestation-transparency-invalid",
    )
}

/// pcrrej-113 — STH signature hex truncated to 63 bytes (126 chars). The
/// validator's `Signature::from_slice` requires exactly 64 bytes.
fn build_pcrrej_113() -> Value {
    let s = setup_sth();
    let sth = base_sth(&s.root, TREE_SIZE, STH_TIMESTAMP, LOG_ID_TRUSTED);
    let mut sig = sign_sth(SEED_SIGNING_KEY, &sth);
    // Truncate to 63 bytes — one byte short of the required Ed25519 length.
    sig.truncate(63);

    build_vector(
        "pcrrej-113",
        "rekor-sth-signature-malformed-length",
        "Phase C.2.5 live-Rekor vector: STH signature truncated to 63 bytes \
         (one byte short of the Ed25519 required length). Validator rejects at \
         Signature::from_slice before ever calling verify_strict.",
        "design-final.md §9.4.2 + RFC 8032 §5.1.7: Ed25519 signatures are \
         exactly 64 bytes. Any non-conforming length is a malformed \
         signature and a hard reject.",
        BuildFields {
            proof_path_hex: s.proof_path_hex,
            sth_signature_hex: hex::encode(&sig),
            sth_timestamp: STH_TIMESTAMP,
            sth_tree_root_hex: hex::encode(s.root),
            sth_tree_size: TREE_SIZE,
            entry_index: ENTRY_INDEX,
            entry_leaf_hash_hex: s.entry_leaf_hash_hex,
            log_pubkey_hex: hex::encode(pubkey_for(SEED_SIGNING_KEY)),
            log_id_hex: hex::encode(LOG_ID_TRUSTED),
            current_time: CURRENT_TIME_OK,
            trusted_log_id_hex: hex::encode(LOG_ID_TRUSTED),
            max_root_age_seconds_override: MAX_ROOT_AGE_SECONDS,
        },
        "reject",
        "pcr-attestation-transparency-invalid",
    )
}

/// pcrrej-114 — STH signed by `SEED_ALT_KEY`, but `log_pubkey_hex` pins the
/// verifying key of `SEED_SIGNING_KEY`. Signature verification fails.
fn build_pcrrej_114() -> Value {
    let s = setup_sth();
    let sth = base_sth(&s.root, TREE_SIZE, STH_TIMESTAMP, LOG_ID_TRUSTED);
    // Sign with the *wrong* seed on purpose.
    let sig = sign_sth(SEED_ALT_KEY, &sth);

    build_vector(
        "pcrrej-114",
        "rekor-sth-signature-wrong-key",
        "Phase C.2.5 live-Rekor vector: STH signed by a key the validator \
         does not register. log_pubkey_hex pins SEED_SIGNING_KEY's verifying \
         key; signature was produced by SEED_ALT_KEY. verify_strict MUST \
         reject with pcr-attestation-transparency-invalid.",
        "design-final.md §9.4.2 + RFC 8032 §5.1.7: Ed25519 signatures bind \
         to exactly one verifying key. Pinning the pubkey and presenting a \
         signature from a different secret is the canonical wrong-key \
         failure and must never succeed.",
        BuildFields {
            proof_path_hex: s.proof_path_hex,
            sth_signature_hex: hex::encode(&sig),
            sth_timestamp: STH_TIMESTAMP,
            sth_tree_root_hex: hex::encode(s.root),
            sth_tree_size: TREE_SIZE,
            entry_index: ENTRY_INDEX,
            entry_leaf_hash_hex: s.entry_leaf_hash_hex,
            // Claim the MAIN key — signature was produced by the ALT key.
            log_pubkey_hex: hex::encode(pubkey_for(SEED_SIGNING_KEY)),
            log_id_hex: hex::encode(LOG_ID_TRUSTED),
            current_time: CURRENT_TIME_OK,
            trusted_log_id_hex: hex::encode(LOG_ID_TRUSTED),
            max_root_age_seconds_override: MAX_ROOT_AGE_SECONDS,
        },
        "reject",
        "pcr-attestation-transparency-invalid",
    )
}

/// pcrrej-115 — `sth_timestamp` is one second past the suite's `current_time`.
/// The validator's "no-future STH" check fires before any signature work.
fn build_pcrrej_115() -> Value {
    let s = setup_sth();
    // STH is timestamped one second in the future relative to the suite's
    // current_time. Sign accordingly so the signature itself is well-formed.
    let future_ts = CURRENT_TIME_OK + 1;
    let sth = base_sth(&s.root, TREE_SIZE, future_ts, LOG_ID_TRUSTED);
    let sig = sign_sth(SEED_SIGNING_KEY, &sth);

    build_vector(
        "pcrrej-115",
        "rekor-sth-timestamp-future",
        "Phase C.2.5 live-Rekor vector: STH timestamp strictly greater than \
         the suite-supplied current_time. Validator classifies this as a \
         future-stamped STH (a trivially forged freshness) and rejects with \
         pcr-attestation-transparency-invalid.",
        "design-final.md §9.4.2: a verifier never treats an STH signed for \
         a future time as fresh — doing so would let an attacker \
         pre-generate valid-looking STHs and race the real log.",
        BuildFields {
            proof_path_hex: s.proof_path_hex,
            sth_signature_hex: hex::encode(&sig),
            sth_timestamp: future_ts,
            sth_tree_root_hex: hex::encode(s.root),
            sth_tree_size: TREE_SIZE,
            entry_index: ENTRY_INDEX,
            entry_leaf_hash_hex: s.entry_leaf_hash_hex,
            log_pubkey_hex: hex::encode(pubkey_for(SEED_SIGNING_KEY)),
            log_id_hex: hex::encode(LOG_ID_TRUSTED),
            current_time: CURRENT_TIME_OK,
            trusted_log_id_hex: hex::encode(LOG_ID_TRUSTED),
            max_root_age_seconds_override: MAX_ROOT_AGE_SECONDS,
        },
        "reject",
        "pcr-attestation-transparency-invalid",
    )
}

/// pcrrej-116 — STH is 10 000 s old at the suite's `current_time`, and the
/// Tariff window is 3600 s. Stale → `pcr-attestation-transparency-stale`.
fn build_pcrrej_116() -> Value {
    let s = setup_sth();
    // Signed ~2h 46m before the suite's current_time. Signature itself is
    // valid; freshness fails at the Tariff-age-window check.
    let sth = base_sth(&s.root, TREE_SIZE, STH_TIMESTAMP, LOG_ID_TRUSTED);
    let sig = sign_sth(SEED_SIGNING_KEY, &sth);

    build_vector(
        "pcrrej-116",
        "rekor-sth-stale",
        "Phase C.2.5 live-Rekor vector: STH signed at STH_TIMESTAMP is 10000 \
         seconds older than the suite-supplied CURRENT_TIME_STALE, exceeding \
         the 3600-second Tariff freshness window. MUST reject with \
         pcr-attestation-transparency-stale.",
        "design-final.md §9.4.2: the Tariff-level max root age is the \
         policy dial for how fresh an STH must be. Anything older than the \
         window is rejected irrespective of signature validity.",
        BuildFields {
            proof_path_hex: s.proof_path_hex,
            sth_signature_hex: hex::encode(&sig),
            sth_timestamp: STH_TIMESTAMP,
            sth_tree_root_hex: hex::encode(s.root),
            sth_tree_size: TREE_SIZE,
            entry_index: ENTRY_INDEX,
            entry_leaf_hash_hex: s.entry_leaf_hash_hex,
            log_pubkey_hex: hex::encode(pubkey_for(SEED_SIGNING_KEY)),
            log_id_hex: hex::encode(LOG_ID_TRUSTED),
            current_time: CURRENT_TIME_STALE,
            trusted_log_id_hex: hex::encode(LOG_ID_TRUSTED),
            max_root_age_seconds_override: MAX_ROOT_AGE_SECONDS,
        },
        "reject",
        "pcr-attestation-transparency-stale",
    )
}

/// pcrrej-117 — fully valid STH + proof, but the log_id sits outside the
/// Tariff's `trusted_transparency_logs` allow-list.
fn build_pcrrej_117() -> Value {
    let s = setup_sth();
    // Sign with the UNTRUSTED log_id so the signature is self-consistent:
    // the verifier rebuilds canonical_bytes from vector fields and must see
    // a valid Ed25519 signature over log_id = LOG_ID_UNTRUSTED. The trust
    // check fires first regardless, but keeping the signature valid means
    // future refactors that reorder checks still fail with TransparencyLogUnknown.
    let sth = base_sth(&s.root, TREE_SIZE, STH_TIMESTAMP, LOG_ID_UNTRUSTED);
    let sig = sign_sth(SEED_SIGNING_KEY, &sth);

    build_vector(
        "pcrrej-117",
        "rekor-log-id-not-trusted",
        "Phase C.2.5 live-Rekor vector: STH and Merkle proof are \
         cryptographically valid under LOG_ID_UNTRUSTED, but the Tariff's \
         trusted_transparency_logs only lists LOG_ID_TRUSTED. Trust check \
         fails first → pcr-attestation-transparency-log-unknown.",
        "design-final.md §9.4.2: Tariff's trusted-log list is the root of \
         accountability for the transparency layer. A well-signed STH from \
         a log the Tariff does not recognize is still untrusted — this \
         check runs before any crypto so an unknown-log attack cannot \
         even burn verifier CPU.",
        BuildFields {
            proof_path_hex: s.proof_path_hex,
            sth_signature_hex: hex::encode(&sig),
            sth_timestamp: STH_TIMESTAMP,
            sth_tree_root_hex: hex::encode(s.root),
            sth_tree_size: TREE_SIZE,
            entry_index: ENTRY_INDEX,
            entry_leaf_hash_hex: s.entry_leaf_hash_hex,
            log_pubkey_hex: hex::encode(pubkey_for(SEED_SIGNING_KEY)),
            log_id_hex: hex::encode(LOG_ID_UNTRUSTED),
            current_time: CURRENT_TIME_OK,
            // Tariff only trusts LOG_ID_TRUSTED — the vector's log_id is
            // LOG_ID_UNTRUSTED, so the trust set membership check fails.
            trusted_log_id_hex: hex::encode(LOG_ID_TRUSTED),
            max_root_age_seconds_override: MAX_ROOT_AGE_SECONDS,
        },
        "reject",
        "pcr-attestation-transparency-log-unknown",
    )
}

// ─── Internal helpers ───────────────────────────────────────────────────────

/// Build a fresh [`RekorSignedTreeHead`] with an empty signature. Callers
/// compute `canonical_bytes()` on it and then fill `signature` with the
/// Ed25519 output.
fn base_sth(root: &[u8; 32], tree_size: u64, timestamp: i64, log_id: [u8; 32]) -> RekorSignedTreeHead {
    RekorSignedTreeHead {
        tree_root: *root,
        tree_size,
        timestamp,
        log_id,
        signature: Vec::new(),
    }
}

struct BuildFields {
    proof_path_hex: Vec<String>,
    sth_signature_hex: String,
    sth_timestamp: i64,
    sth_tree_root_hex: String,
    sth_tree_size: u64,
    entry_index: u64,
    entry_leaf_hash_hex: String,
    log_pubkey_hex: String,
    log_id_hex: String,
    current_time: i64,
    trusted_log_id_hex: String,
    max_root_age_seconds_override: u64,
}

/// Assemble a full reject-vector JSON object around the supplied live-Rekor
/// fields. Shape matches `pcr-attestation-reject.json`'s existing vectors so
/// the `pcr-attestation-reject` suite loads this file unchanged in Block D.
#[allow(clippy::too_many_arguments)]
fn build_vector(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    f: BuildFields,
    outcome: &str,
    reject_code: &str,
) -> Value {
    // Two mock attestations with `signature_valid=true` let the pipeline
    // sail through steps 1–8; the live-Rekor dispatch fires at step 9 and
    // surfaces whichever failure mode the vector encodes.
    let attestations = json!([
        {
            "attestor_id": "A1",
            "pcrs": {"PCR0": "sha256:fw", "PCR4": "sha256:k", "PCR8": "sha256:app"},
            "iat": STH_TIMESTAMP,
            "nonce": id,
            "signature_valid": true
        },
        {
            "attestor_id": "A2",
            "pcrs": {"PCR0": "sha256:fw", "PCR4": "sha256:k", "PCR8": "sha256:app"},
            "iat": STH_TIMESTAMP + 10,
            "nonce": id,
            "signature_valid": true
        }
    ]);

    let transparency_log_proof = json!({
        "log_id": f.log_id_hex,
        "inclusion_proof_valid": true,
        "root_age_seconds": 100,
        "entry_index": f.entry_index,
        "sth_tree_size": f.sth_tree_size,
        "proof_path_hex": f.proof_path_hex,
        "sth_signature_hex": f.sth_signature_hex,
        "sth_timestamp": f.sth_timestamp,
        "sth_tree_root_hex": f.sth_tree_root_hex,
        "log_pubkey_hex": f.log_pubkey_hex,
        "entry_leaf_hash_hex": f.entry_leaf_hash_hex,
        "current_time": f.current_time,
        "log_id_hex": f.log_id_hex,
        "log_key_valid_from": f.sth_timestamp - 86400,
        "log_key_valid_until": f.sth_timestamp + 86400,
        "max_root_age_seconds_override": f.max_root_age_seconds_override,
    });

    let expected = if outcome == "reject" {
        json!({ "outcome": "reject", "reject_code": reject_code })
    } else {
        json!({ "outcome": "accept" })
    };

    json!({
        "id": id,
        "category": category,
        "description": description,
        "input": {
            "tariff_pcr_requirement": {
                "attestors": ["A1", "A2", "A3"],
                "quorum": 2,
                "expected_pcrs": {"PCR0": "sha256:fw", "PCR4": "sha256:k", "PCR8": "sha256:app"},
                "trusted_transparency_logs": [
                    {
                        "log_id": f.trusted_log_id_hex,
                        "key_alg": "ed25519"
                    }
                ],
                "transparency_log_max_root_age_seconds": f.max_root_age_seconds_override
            },
            "attestation_bundle": {
                "commit_hash": "phase-c2-5",
                "attestations": attestations,
                "transparency_log_proof": transparency_log_proof
            },
            "cose_sign1_bytes": null,
            "current_time": f.current_time,
            "router_nonce_issued": id
        },
        "expected": expected,
        "rationale": rationale,
        "redteam_refs": ["PHASE-C2-5-LIVE"],
        "severity_if_failed": "critical"
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_core::PcrRejectCode;

    // All 8 vectors carry a deterministic, schema-sane JSON shape.

    #[test]
    fn build_all_returns_eight_unique_ids() {
        let v = build_all();
        assert_eq!(v.len(), 8);
        let ids: Vec<_> = v.iter().map(|x| x["id"].as_str().unwrap()).collect();
        for id in &ids {
            assert!(id.starts_with("pcrrej-11"));
        }
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 8, "ids must be unique");
    }

    #[test]
    fn build_all_produces_expected_reject_codes() {
        // Belt-and-braces: the expected kebab strings below are taken from
        // `PcrRejectCode`'s `Display` impl. If a variant is renamed the
        // `expected` set refreshes automatically and any vector that missed
        // the rename surfaces here as a mismatch.
        let transparency_invalid =
            PcrRejectCode::PcrAttestationTransparencyInvalid.to_string();
        let transparency_stale = PcrRejectCode::PcrAttestationTransparencyStale.to_string();
        let transparency_log_unknown =
            PcrRejectCode::PcrAttestationTransparencyLogUnknown.to_string();

        let v = build_all();
        let expected: [(&str, &str); 8] = [
            ("pcrrej-110", transparency_invalid.as_str()),
            ("pcrrej-111", transparency_invalid.as_str()),
            ("pcrrej-112", transparency_invalid.as_str()),
            ("pcrrej-113", transparency_invalid.as_str()),
            ("pcrrej-114", transparency_invalid.as_str()),
            ("pcrrej-115", transparency_invalid.as_str()),
            ("pcrrej-116", transparency_stale.as_str()),
            ("pcrrej-117", transparency_log_unknown.as_str()),
        ];
        for (i, (id, code)) in expected.iter().enumerate() {
            let got_id = v[i]["id"].as_str().unwrap();
            let got_code = v[i]["expected"]["reject_code"].as_str().unwrap();
            assert_eq!(got_id, *id, "vector index {i} id mismatch");
            assert_eq!(got_code, *code, "vector {id} reject_code mismatch");
        }
    }

    #[test]
    fn determinism_two_runs_produce_identical_bytes() {
        let a = serde_json::to_string(&build_all()).unwrap();
        let b = serde_json::to_string(&build_all()).unwrap();
        assert_eq!(a, b, "build_all must be byte-deterministic");
    }

    #[test]
    fn all_live_fields_populated_for_full_dispatch() {
        // The validator's `live_rekor_presence` function only dispatches to
        // `classify_live_rekor` when all seven live fields are Some.
        // Any missing field would silently demote the vector to the mock
        // path and bury the failure mode we're testing.
        let v = build_all();
        let required = [
            "proof_path_hex",
            "sth_signature_hex",
            "sth_timestamp",
            "sth_tree_root_hex",
            "log_pubkey_hex",
            "entry_leaf_hash_hex",
            "current_time",
        ];
        for vector in &v {
            let proof = &vector["input"]["attestation_bundle"]["transparency_log_proof"];
            for field in &required {
                assert!(
                    !proof[field].is_null() && proof.get(field).is_some(),
                    "vector {} missing live field {}",
                    vector["id"],
                    field
                );
            }
        }
    }

    #[test]
    fn pcrrej_110_proof_path_first_entry_is_malformed_hex() {
        let v = &build_pcrrej_110();
        let p0 =
            &v["input"]["attestation_bundle"]["transparency_log_proof"]["proof_path_hex"][0];
        assert_eq!(p0.as_str().unwrap(), "abc");
    }

    #[test]
    fn pcrrej_113_signature_is_63_bytes() {
        let v = &build_pcrrej_113();
        let sig_hex = v["input"]["attestation_bundle"]["transparency_log_proof"]
            ["sth_signature_hex"]
            .as_str()
            .unwrap();
        let sig = hex::decode(sig_hex).expect("still valid hex, just wrong length");
        assert_eq!(sig.len(), 63, "signature must be 63 bytes");
    }

    #[test]
    fn pcrrej_112_claims_tree_size_16_with_depth_3_path() {
        let v = &build_pcrrej_112();
        let proof = &v["input"]["attestation_bundle"]["transparency_log_proof"];
        assert_eq!(proof["sth_tree_size"].as_u64().unwrap(), 16);
        assert_eq!(proof["proof_path_hex"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn pcrrej_117_log_id_mismatches_trusted_list() {
        let v = &build_pcrrej_117();
        let vector_log_id = v["input"]["attestation_bundle"]["transparency_log_proof"]
            ["log_id_hex"]
            .as_str()
            .unwrap();
        let trusted = v["input"]["tariff_pcr_requirement"]["trusted_transparency_logs"][0]
            ["log_id"]
            .as_str()
            .unwrap();
        assert_eq!(vector_log_id, hex::encode(LOG_ID_UNTRUSTED));
        assert_eq!(trusted, hex::encode(LOG_ID_TRUSTED));
        assert_ne!(vector_log_id, trusted);
    }
}
