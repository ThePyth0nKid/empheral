//! Rekor Merkle inclusion proof verification + signed-tree-head
//! verification (feature = "rekor").
//!
//! Implements RFC 9162 §2.1.1 inclusion proof algorithm for a Merkle Hash
//! Tree (MHT) using SHA-256 and an Ed25519 STH-signature verifier bound to
//! a trusted log-key registry.
//!
//! Leaf hashes: `SHA-256(0x00 || leaf_content)`
//! Inner hashes: `SHA-256(0x01 || left || right)`
//!
//! The ordering of siblings (left vs right) is determined by the bit of the
//! leaf index at the current proof depth.
//!
//! # Public surface
//!
//! ```text
//! verify_rekor_inclusion(entry, payload_hash, tree_root) -> Result<(), AttestError>
//! verify_rekor_sth(sth, keys, current_time, max_age)     -> Result<(), AttestError>
//! RekorEntry, RekorSignedTreeHead, RekorKeySet, MAX_INCLUSION_DEPTH, MAX_STH_AGE_SECONDS
//! ```
//!
//! The two verifiers are complementary and callers should chain them:
//! first verify the STH signature + freshness, then verify that the
//! inclusion proof reconstructs `sth.tree_root`.
//!
//! # Security hardening (Phase C.2.5 Block A)
//!
//! All inputs are adversary-controlled. [`verify_rekor_inclusion`] rejects:
//! - `tree_size == 0` (an empty tree has no root and would otherwise accept
//!   any leaf hash as the root).
//! - `index >= tree_size` (out-of-bounds leaf position).
//! - `proof_path.len() > MAX_INCLUSION_DEPTH` (DoS cap at depth 40).
//! - `proof_path.len()` inconsistent with the RFC 9162 expected depth for
//!   `(index, tree_size)` — catches both too-short and too-long proofs.
//!
//! Hash equality uses `subtle::ConstantTimeEq` on both the leaf-match and
//! root-match checks as defense-in-depth, matching the constant-time
//! comparison pattern established in Phase C.1/C.2.
//!
//! # Signed Tree Head (Phase C.2.5 Block B)
//!
//! [`RekorSignedTreeHead::canonical_bytes`] produces the exact byte string
//! the Ed25519 signature covers:
//!
//! ```text
//! 0x02 || det_cbor({
//!   "v": 1,
//!   "ctx": "ephemeral-rekor-sth-v1",
//!   "log_id": <32 bytes>,
//!   "tree_size": <uint>,
//!   "tree_root": <32 bytes>,
//!   "ts": <int>,
//! })
//! ```
//!
//! The leading `0x02` domain prefix separates STH payloads from Merkle
//! leaf/inner hashes (which use `0x00` / `0x01`). The `"ctx"` string is
//! the version/context binding so a signature over one protocol cannot
//! be replayed as a signature over another.
//!
//! `current_time` **must** come from the caller, never from the STH
//! itself: otherwise freshness is self-asserted by the signer and
//! trivially forgeable.

#![cfg(feature = "rekor")]

use ciborium::value::{Integer, Value};
use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{AttestError, RekorSource};

/// Re-export of `ed25519_dalek::VerifyingKey`.
///
/// Callers constructing a [`RekorKeySet`] need a `VerifyingKey`; re-exporting
/// it here keeps consumers of this crate from taking a direct dependency on
/// `ed25519-dalek` solely to spell out one type.
pub use ed25519_dalek::VerifyingKey;

// ─────────────────────────────────────────────────────────────────────────────
// Block A — Merkle inclusion proof
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum accepted Merkle inclusion proof depth.
///
/// A depth of 40 corresponds to trees with up to `2^40 ≈ 1.1 × 10^12`
/// leaves — far larger than any realistic Rekor log (current public Rekor
/// v1 is ~`2^30`). Capping here bounds [`verify_rekor_inclusion`] work
/// under adversarial input.
pub const MAX_INCLUSION_DEPTH: usize = 40;

/// A Rekor log entry with its Merkle inclusion proof.
#[derive(Clone, Debug)]
pub struct RekorEntry {
    /// SHA-256 leaf hash as stored in the Merkle tree.
    pub leaf_hash: [u8; 32],
    /// Proof path: sibling hashes from leaf level to root (exclusive).
    pub proof_path: Vec<[u8; 32]>,
    /// 0-based index of this leaf in the tree.
    pub index: u64,
    /// Total number of leaves in the tree at time of proof.
    pub tree_size: u64,
}

/// Verify a Rekor Merkle inclusion proof per RFC 9162 §2.1.1.
///
/// # Checks (in order)
///
/// 1. `tree_size > 0` — empty trees cannot prove any leaf.
/// 2. `index < tree_size` — leaf must lie within `[0, tree_size)`.
/// 3. `proof_path.len() <= MAX_INCLUSION_DEPTH` — DoS cap.
/// 4. `proof_path.len()` equals the RFC 9162 expected depth for
///    `(index, tree_size)` — catches truncated or padded proofs.
/// 5. `payload_hash == entry.leaf_hash` (constant-time).
/// 6. Reconstructed tree root equals `tree_root` (constant-time).
///
/// # Returns
///
/// `Ok(())` if the proof is valid; [`AttestError::RekorProofInvalid`]
/// otherwise.
pub fn verify_rekor_inclusion(
    entry: &RekorEntry,
    payload_hash: &[u8; 32],
    tree_root: &[u8; 32],
) -> Result<(), AttestError> {
    // ── 1. tree_size > 0 ─────────────────────────────────────────────────────
    //
    // An empty tree has no root; without this guard a crafted `tree_size == 0`
    // entry with an empty `proof_path` would succeed whenever
    // `leaf_hash == tree_root`, accepting arbitrary unproven leaves.
    if entry.tree_size == 0 {
        return Err(AttestError::RekorProofInvalid {
            source: RekorSource("tree_size is zero"),
        });
    }

    // ── 2. index in range ────────────────────────────────────────────────────
    if entry.index >= entry.tree_size {
        return Err(AttestError::RekorProofInvalid {
            source: RekorSource("index out of bounds for tree_size"),
        });
    }

    // ── 3. DoS cap on proof depth ────────────────────────────────────────────
    if entry.proof_path.len() > MAX_INCLUSION_DEPTH {
        return Err(AttestError::RekorProofInvalid {
            source: RekorSource("proof_path exceeds MAX_INCLUSION_DEPTH"),
        });
    }

    // ── 4. Expected depth for (index, tree_size) per RFC 9162 §2.1.1 ─────────
    let expected_depth = expected_proof_depth(entry.index, entry.tree_size);
    if entry.proof_path.len() != expected_depth {
        return Err(AttestError::RekorProofInvalid {
            source: RekorSource("proof_path length inconsistent with tree shape"),
        });
    }

    // ── 5. payload_hash must match leaf hash (constant-time) ─────────────────
    if !bool::from(entry.leaf_hash.as_slice().ct_eq(payload_hash.as_slice())) {
        return Err(AttestError::RekorProofInvalid {
            source: RekorSource("leaf hash does not match payload hash"),
        });
    }

    // ── 6. Walk the proof path ───────────────────────────────────────────────
    let mut current = entry.leaf_hash;
    let mut index = entry.index;

    for sibling in &entry.proof_path {
        if index & 1 == 0 {
            // current is a left child — sibling is on the right
            current = inner_hash(&current, sibling);
        } else {
            // current is a right child — sibling is on the left
            current = inner_hash(sibling, &current);
        }
        index >>= 1;
    }

    // ── 7. Compare reconstructed root (constant-time) ────────────────────────
    if !bool::from(current.as_slice().ct_eq(tree_root.as_slice())) {
        return Err(AttestError::RekorProofInvalid {
            source: RekorSource("reconstructed root does not match expected tree root"),
        });
    }

    Ok(())
}

/// RFC 9162 inner node hash: `SHA-256(0x01 || left || right)`.
fn inner_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left.as_slice());
    h.update(right.as_slice());
    h.finalize().into()
}

/// Expected Merkle inclusion proof depth for a leaf at `index` in a tree of
/// size `tree_size`, per RFC 9162 §2.1.1 `PATH(m, D[n])`.
///
/// Iterative implementation that mirrors the recursive PATH definition:
/// split `D[n]` at `k = largest power of 2 strictly less than n`; descend
/// into `D[0:k]` if `m < k`, else into `D[k:n]` with `m -= k`. Each
/// descent contributes one sibling to the proof path. When `n == 1` the
/// walk terminates with the running depth.
///
/// For `tree_size == 1` returns `0` (root equals the sole leaf).
///
/// Caller must ensure `tree_size > 0` and `index < tree_size`; both
/// invariants are guarded by [`verify_rekor_inclusion`] checks 1 and 2.
fn expected_proof_depth(index: u64, tree_size: u64) -> usize {
    debug_assert!(tree_size > 0, "expected_proof_depth: tree_size must be > 0");
    debug_assert!(
        index < tree_size,
        "expected_proof_depth: index out of range"
    );
    let mut m = index;
    let mut n = tree_size;
    let mut depth: usize = 0;
    while n > 1 {
        // Largest power of 2 strictly less than n.
        let k = 1u64 << (n - 1).ilog2();
        if m < k {
            n = k;
        } else {
            m -= k;
            n -= k;
        }
        depth = depth.saturating_add(1);
    }
    depth
}

// ─────────────────────────────────────────────────────────────────────────────
// Block B — Signed Tree Head + Key registry
// ─────────────────────────────────────────────────────────────────────────────

/// Default maximum age for a Rekor Signed Tree Head, in seconds (24 h).
///
/// Parallels [`crate::NitroRootSet`]-era freshness constants in the suite
/// layer. Callers of [`verify_rekor_sth`] supply the policy-level max-age;
/// this constant is the sensible default matching the validator spec
/// (§9.4.2 R8.P2 default end of the 1..604800 range).
pub const MAX_STH_AGE_SECONDS: u64 = 86_400;

/// Static domain prefix byte for the STH signing payload.
///
/// Distinct from the Merkle leaf (`0x00`) and inner (`0x01`) prefixes so
/// that no preimage can cross-bind between a Merkle hash and an STH
/// signature.
const STH_DOMAIN_PREFIX: u8 = 0x02;

/// Context/version string bound into the STH signing payload.
///
/// Bumping this string (or the leading byte) cleanly invalidates every
/// signature produced by prior versions, forcing a coordinated
/// signer-and-verifier upgrade rather than silent protocol drift.
const STH_CONTEXT: &str = "ephemeral-rekor-sth-v1";

/// A Rekor Signed Tree Head.
///
/// Signatures are produced over [`Self::canonical_bytes`] and verified by
/// [`verify_rekor_sth`] using an Ed25519 [`VerifyingKey`] registered in a
/// [`RekorKeySet`].
#[derive(Clone, Debug)]
pub struct RekorSignedTreeHead {
    /// 32-byte SHA-256 Merkle-tree root this STH commits to.
    pub tree_root: [u8; 32],
    /// Number of leaves in the committed tree.
    pub tree_size: u64,
    /// Signer-claimed emission time (Unix seconds). Freshness is checked
    /// by [`verify_rekor_sth`] against the caller's `current_time`.
    pub timestamp: i64,
    /// Log identifier the caller uses to pick the trusted key.
    pub log_id: [u8; 32],
    /// Ed25519 signature over [`Self::canonical_bytes`]. Length must be
    /// 64 bytes; anything else is rejected at verify time.
    pub signature: Vec<u8>,
}

impl RekorSignedTreeHead {
    /// Serialize fields into the canonical signing payload.
    ///
    /// Layout: `0x02 || det_cbor({v, ctx, log_id, tree_size, tree_root, ts})`
    /// with fields emitted in the fixed order above. ciborium's
    /// insertion-order Map encoding makes this byte-deterministic for a
    /// given struct value.
    ///
    /// This is public-info bytes; constant-time encoding is not required.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Conversions below are infallible:
        // - `i128::from(u64)` / `i128::from(i64)` widen losslessly.
        // - `Integer::try_from(i128)` succeeds for the CBOR integer range
        //   `[-2^64, 2^64 - 1]`, which strictly contains every u64 / i64.
        let v_int = Integer::try_from(1i128).expect("STATIC: 1 fits in CBOR integer");
        let tree_size_int = Integer::try_from(i128::from(self.tree_size))
            .expect("STATIC: u64 fits in CBOR integer");
        let ts_int = Integer::try_from(i128::from(self.timestamp))
            .expect("STATIC: i64 fits in CBOR integer");

        let map = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(v_int)),
            (Value::Text("ctx".into()), Value::Text(STH_CONTEXT.into())),
            (Value::Text("log_id".into()), Value::Bytes(self.log_id.to_vec())),
            (Value::Text("tree_size".into()), Value::Integer(tree_size_int)),
            (Value::Text("tree_root".into()), Value::Bytes(self.tree_root.to_vec())),
            (Value::Text("ts".into()), Value::Integer(ts_int)),
        ]);

        let mut cbor_buf: Vec<u8> = Vec::new();
        ciborium::into_writer(&map, &mut cbor_buf)
            .expect("STATIC: ciborium Vec<u8> writes are infallible");

        let mut out = Vec::with_capacity(1 + cbor_buf.len());
        out.push(STH_DOMAIN_PREFIX);
        out.extend_from_slice(&cbor_buf);
        out
    }
}

/// Registered Rekor log key with validity window.
#[derive(Clone)]
struct RekorKeyEntry {
    log_id: [u8; 32],
    /// Raw 32-byte public key. Held alongside `verifying_key` so the
    /// duplicate check does not rely on comparing `VerifyingKey` values
    /// directly (which has no `PartialEq`).
    key_bytes: [u8; 32],
    verifying_key: VerifyingKey,
    valid_from: i64,
    valid_until: i64,
}

impl core::fmt::Debug for RekorKeyEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `verifying_key` is deliberately omitted from the Debug form — its
        // raw bytes already appear under `key_bytes`, and including the
        // `VerifyingKey` itself would double-print key material via its
        // derived Debug impl. `finish_non_exhaustive` keeps clippy
        // (`missing_fields_in_debug`) happy while preserving the redacted
        // shape.
        f.debug_struct("RekorKeyEntry")
            .field("log_id", &hex::encode(self.log_id))
            .field("key_bytes", &hex::encode(self.key_bytes))
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .finish_non_exhaustive()
    }
}

/// Registry of trusted Rekor transparency-log signing keys.
///
/// Each entry binds `(log_id, ed25519 VerifyingKey, validity window)`.
/// Validity is inclusive on both ends: `valid_from <= ts <= valid_until`.
///
/// # Design
///
/// `FromIterator` is intentionally absent — collecting would bypass the
/// duplicate check, re-opening the shadow-key bypass that the check
/// exists to close. Same lesson as `NitroRootSet` (Phase C.2) and
/// `TrustAnchorSet` (Phase C.1). Callers must build via
/// [`RekorKeySet::insert_trusted_key`].
///
/// # Key rotation
///
/// [`RekorKeySet::find_for_timestamp`] returns the active key with the
/// latest `valid_from` when several entries cover the same timestamp
/// (grace-period overlap). "First-match-by-newest-valid_from" allows
/// zero-downtime rotation: the signer switches to the new key once it is
/// registered, and verifiers still accept the old key for STHs emitted
/// before the switch.
///
/// # Feature: `test-fixtures`
///
/// When compiled with `--features test-fixtures`, the method
/// [`RekorKeySet::insert_trusted_key_for_test`] bypasses the log-ID
/// allowlist so locally-generated ed25519 keys can be registered in
/// tests. The code path is completely absent from default (production)
/// builds — the compiler never emits it.
#[derive(Debug, Clone, Default)]
pub struct RekorKeySet {
    entries: Vec<RekorKeyEntry>,
}

/// Log IDs allowed into [`RekorKeySet`] via the production
/// [`RekorKeySet::insert_trusted_key`] path.
///
/// Empty until production Rekor log IDs are pinned. Until then,
/// production `insert_trusted_key` calls fail closed; test fixtures go
/// through [`RekorKeySet::insert_trusted_key_for_test`] (test-fixtures
/// feature). Extending this slice requires an explicit source-level
/// change, gating every new trusted log behind code review.
const ALLOWED_LOG_IDS: &[[u8; 32]] = &[];

impl RekorKeySet {
    /// Create an empty key set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert a trusted Rekor log key (production path).
    ///
    /// Rejects if:
    /// - `log_id` is not in [`ALLOWED_LOG_IDS`], OR
    /// - the validity window is inverted (`valid_from > valid_until`).
    ///
    /// A `(log_id, key_bytes)` duplicate is idempotent success
    /// (matching `NitroRootSet::insert_trusted_der`). Registering the
    /// same `log_id` with a *different* key is allowed and participates
    /// in rotation.
    pub fn insert_trusted_key(
        &mut self,
        log_id: [u8; 32],
        key: VerifyingKey,
        valid_from: i64,
        valid_until: i64,
    ) -> Result<(), AttestError> {
        if !ALLOWED_LOG_IDS.contains(&log_id) {
            return Err(AttestError::RekorLogUntrusted { log_id });
        }
        self.insert_checked(log_id, key, valid_from, valid_until)
    }

    /// Insert a key without log-ID pinning (test path).
    ///
    /// **ONLY compiled when the `test-fixtures` feature is active.**
    /// Production builds literally do not contain this code path,
    /// closing the shadow-key bypass at compile time.
    #[cfg(feature = "test-fixtures")]
    pub fn insert_trusted_key_for_test(
        &mut self,
        log_id: [u8; 32],
        key: VerifyingKey,
        valid_from: i64,
        valid_until: i64,
    ) -> Result<(), AttestError> {
        self.insert_checked(log_id, key, valid_from, valid_until)
    }

    fn insert_checked(
        &mut self,
        log_id: [u8; 32],
        key: VerifyingKey,
        valid_from: i64,
        valid_until: i64,
    ) -> Result<(), AttestError> {
        if valid_from > valid_until {
            return Err(AttestError::RekorProofInvalid {
                source: RekorSource("key validity window inverted"),
            });
        }
        let key_bytes = key.to_bytes();
        if self
            .entries
            .iter()
            .any(|e| e.log_id == log_id && e.key_bytes == key_bytes)
        {
            return Ok(());
        }
        self.entries.push(RekorKeyEntry {
            log_id,
            key_bytes,
            verifying_key: key,
            valid_from,
            valid_until,
        });
        Ok(())
    }

    /// Return the active trusted key for `log_id` at timestamp `ts`.
    ///
    /// If several keys cover the same `(log_id, ts)` (grace-period
    /// overlap during rotation), the entry with the latest `valid_from`
    /// wins. Returns `None` when no registered key covers `(log_id, ts)`.
    #[must_use]
    pub fn find_for_timestamp(&self, log_id: &[u8; 32], ts: i64) -> Option<&VerifyingKey> {
        self.entries
            .iter()
            .filter(|e| &e.log_id == log_id && e.valid_from <= ts && ts <= e.valid_until)
            .max_by_key(|e| e.valid_from)
            .map(|e| &e.verifying_key)
    }

    /// Number of registered keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no keys have been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Verify an Ed25519 signature over a Rekor Signed Tree Head and enforce
/// freshness + log-key trust.
///
/// # Checks
///
/// 1. `sth.timestamp <= current_time` — an STH timestamped in the future
///    cannot have been produced by the log (rejects backdated-future
///    forgery).
/// 2. `sth.log_id` resolves to an active trusted key at `sth.timestamp`
///    via [`RekorKeySet::find_for_timestamp`].
/// 3. The `sth.signature` is a well-formed 64-byte Ed25519 signature.
/// 4. Strict Ed25519 verification over [`RekorSignedTreeHead::canonical_bytes`]
///    against that key (rejects non-canonical R per `verify_strict`).
/// 5. `current_time - sth.timestamp <= max_age` — freshness.
///
/// `current_time` **must** come from the caller, never from `sth.timestamp`:
/// otherwise the signer self-asserts freshness (same invariant as
/// `verify_nitro_attestation`).
pub fn verify_rekor_sth(
    sth: &RekorSignedTreeHead,
    keys: &RekorKeySet,
    current_time: i64,
    max_age: u64,
) -> Result<(), AttestError> {
    // ── 1. STH must not be from the future ──────────────────────────────────
    //
    // Done before signature verification so a trivially-forged future STH is
    // rejected without spending the signature check.
    if sth.timestamp > current_time {
        return Err(AttestError::RekorProofInvalid {
            source: RekorSource("STH timestamp is in the future"),
        });
    }

    // ── 2. log_id must be trusted at sth.timestamp ──────────────────────────
    let Some(vk) = keys.find_for_timestamp(&sth.log_id, sth.timestamp) else {
        return Err(AttestError::RekorLogUntrusted {
            log_id: sth.log_id,
        });
    };

    // ── 3. Signature length + structure ─────────────────────────────────────
    let sig = Signature::from_slice(&sth.signature).map_err(|_| AttestError::RekorProofInvalid {
        source: RekorSource("STH signature malformed"),
    })?;

    // ── 4. Strict Ed25519 verify over canonical STH bytes ───────────────────
    let bytes = sth.canonical_bytes();
    vk.verify_strict(&bytes, &sig)
        .map_err(|_| AttestError::RekorProofInvalid {
            source: RekorSource("STH signature verification failed"),
        })?;

    // ── 5. Freshness against caller-supplied current_time ───────────────────
    //
    // `sth.timestamp <= current_time` is enforced in check 1, so the
    // difference is non-negative; `u64::try_from` then cannot fail. Defense
    // in depth: if a future refactor ever reaches this point with a negative
    // `age_secs`, fail closed (u64::MAX > any caller-supplied max_age) rather
    // than silently accepting the STH as fresh.
    let age_secs = current_time.saturating_sub(sth.timestamp);
    let age_u = u64::try_from(age_secs).unwrap_or(u64::MAX);
    if age_u > max_age {
        return Err(AttestError::RekorSthStale {
            age_seconds: age_u,
            max: max_age,
        });
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_hash_for(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x00u8]);
        h.update(data);
        h.finalize().into()
    }

    // ─── Legacy tests (preserved, behaviour unchanged) ────────────────────────

    #[test]
    fn single_leaf_tree_verifies() {
        let lh = leaf_hash_for(b"only-leaf");
        let entry = RekorEntry {
            leaf_hash: lh,
            proof_path: vec![],
            index: 0,
            tree_size: 1,
        };
        verify_rekor_inclusion(&entry, &lh, &lh).expect("single-leaf tree");
    }

    #[test]
    fn wrong_payload_hash_rejected() {
        let lh = leaf_hash_for(b"leaf");
        let mut wrong = lh;
        wrong[0] ^= 0xff;
        let entry = RekorEntry {
            leaf_hash: lh,
            proof_path: vec![],
            index: 0,
            tree_size: 1,
        };
        let err = verify_rekor_inclusion(&entry, &wrong, &lh).unwrap_err();
        assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
    }

    // ─── Block A hardening tests ──────────────────────────────────────────────

    #[test]
    fn tree_size_zero_rejected() {
        // Without the guard, leaf_hash == tree_root trivially accepts.
        let lh = leaf_hash_for(b"anything");
        let entry = RekorEntry {
            leaf_hash: lh,
            proof_path: vec![],
            index: 0,
            tree_size: 0,
        };
        let err = verify_rekor_inclusion(&entry, &lh, &lh).unwrap_err();
        assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
    }

    #[test]
    fn index_equal_tree_size_rejected() {
        let lh = leaf_hash_for(b"leaf");
        let entry = RekorEntry {
            leaf_hash: lh,
            proof_path: vec![],
            index: 1, // equal to tree_size → out of bounds
            tree_size: 1,
        };
        let err = verify_rekor_inclusion(&entry, &lh, &lh).unwrap_err();
        assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
    }

    #[test]
    fn index_greater_than_tree_size_rejected() {
        let lh = leaf_hash_for(b"leaf");
        let entry = RekorEntry {
            leaf_hash: lh,
            proof_path: vec![[0u8; 32]],
            index: 99,
            tree_size: 2,
        };
        let err = verify_rekor_inclusion(&entry, &lh, &lh).unwrap_err();
        assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
    }

    #[test]
    fn proof_path_too_deep_rejected() {
        let lh = leaf_hash_for(b"leaf");
        let entry = RekorEntry {
            leaf_hash: lh,
            proof_path: vec![[0u8; 32]; MAX_INCLUSION_DEPTH + 1],
            index: 0,
            tree_size: 1u64 << 50,
        };
        let err = verify_rekor_inclusion(&entry, &lh, &lh).unwrap_err();
        assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
    }

    #[test]
    fn proof_path_length_mismatch_too_short() {
        // tree_size=2 requires proof_path of length 1; provide 0.
        let lh = leaf_hash_for(b"leaf");
        let entry = RekorEntry {
            leaf_hash: lh,
            proof_path: vec![],
            index: 0,
            tree_size: 2,
        };
        let err = verify_rekor_inclusion(&entry, &lh, &lh).unwrap_err();
        assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
    }

    #[test]
    fn proof_path_length_mismatch_too_long() {
        // tree_size=1 requires proof_path of length 0; provide 1.
        let lh = leaf_hash_for(b"leaf");
        let entry = RekorEntry {
            leaf_hash: lh,
            proof_path: vec![[0u8; 32]],
            index: 0,
            tree_size: 1,
        };
        let err = verify_rekor_inclusion(&entry, &lh, &lh).unwrap_err();
        assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
    }

    #[test]
    fn two_leaf_tree_verifies_both_indices() {
        let lh0 = leaf_hash_for(b"leaf-0");
        let lh1 = leaf_hash_for(b"leaf-1");
        let root = inner_hash(&lh0, &lh1);

        let e0 = RekorEntry {
            leaf_hash: lh0,
            proof_path: vec![lh1],
            index: 0,
            tree_size: 2,
        };
        verify_rekor_inclusion(&e0, &lh0, &root).expect("two-leaf index 0");

        let e1 = RekorEntry {
            leaf_hash: lh1,
            proof_path: vec![lh0],
            index: 1,
            tree_size: 2,
        };
        verify_rekor_inclusion(&e1, &lh1, &root).expect("two-leaf index 1");
    }

    // ─── expected_proof_depth reference values per RFC 9162 ──────────────────

    #[test]
    fn expected_depth_known_values() {
        assert_eq!(expected_proof_depth(0, 1), 0);
        assert_eq!(expected_proof_depth(0, 2), 1);
        assert_eq!(expected_proof_depth(1, 2), 1);
        assert_eq!(expected_proof_depth(0, 3), 2);
        assert_eq!(expected_proof_depth(1, 3), 2);
        assert_eq!(expected_proof_depth(2, 3), 1);
        assert_eq!(expected_proof_depth(0, 4), 2);
        assert_eq!(expected_proof_depth(3, 4), 2);
        assert_eq!(expected_proof_depth(4, 7), 3);
        assert_eq!(expected_proof_depth(5, 7), 3);
        assert_eq!(expected_proof_depth(6, 7), 2);
        // 2^40 tree depth stays within cap.
        assert!(expected_proof_depth(0, 1u64 << 40) <= MAX_INCLUSION_DEPTH);
    }

    // ─── Block B tests: STH canonical bytes + KeySet basics ──────────────────

    fn sample_sth() -> RekorSignedTreeHead {
        RekorSignedTreeHead {
            tree_root: [0x11u8; 32],
            tree_size: 42,
            timestamp: 1_700_000_000,
            log_id: [0x22u8; 32],
            signature: Vec::new(),
        }
    }

    #[test]
    fn canonical_bytes_domain_prefix() {
        let bytes = sample_sth().canonical_bytes();
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 0x02, "STH domain prefix must be 0x02");
    }

    #[test]
    fn canonical_bytes_deterministic() {
        let a = sample_sth().canonical_bytes();
        let b = sample_sth().canonical_bytes();
        assert_eq!(a, b, "canonical_bytes must be byte-deterministic");
    }

    #[test]
    fn canonical_bytes_tree_root_change_changes_output() {
        let base = sample_sth().canonical_bytes();
        let mut sth2 = sample_sth();
        sth2.tree_root[0] ^= 0x01;
        assert_ne!(base, sth2.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_log_id_change_changes_output() {
        let base = sample_sth().canonical_bytes();
        let mut sth2 = sample_sth();
        sth2.log_id[0] ^= 0x01;
        assert_ne!(base, sth2.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_timestamp_change_changes_output() {
        let base = sample_sth().canonical_bytes();
        let mut sth2 = sample_sth();
        sth2.timestamp += 1;
        assert_ne!(base, sth2.canonical_bytes());
    }

    #[test]
    fn keyset_new_is_empty() {
        let ks = RekorKeySet::new();
        assert!(ks.is_empty());
        assert_eq!(ks.len(), 0);
    }

    #[test]
    fn keyset_production_insert_rejects_unlisted_log_id() {
        // ALLOWED_LOG_IDS is empty in code, so every log_id is untrusted
        // on the production path. This ensures the fail-closed guard is
        // wired up.
        let sk_bytes: [u8; 32] = [7u8; 32];
        let vk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes).verifying_key();
        let mut ks = RekorKeySet::new();
        let err = ks
            .insert_trusted_key([0x99u8; 32], vk, 0, 2_000_000_000)
            .unwrap_err();
        assert!(matches!(err, AttestError::RekorLogUntrusted { .. }));
        assert!(ks.is_empty());
    }

    // ─── Block B tests: STH + KeySet with test-fixtures (live signing) ───────

    #[cfg(feature = "test-fixtures")]
    mod fixtures {
        use super::*;
        use ed25519_dalek::{Signer, SigningKey};

        const LOG_ID_A: [u8; 32] = [0x22u8; 32];
        const LOG_ID_B: [u8; 32] = [0x33u8; 32];
        const SEED_A: [u8; 32] = [0x07u8; 32];
        const SEED_B: [u8; 32] = [0x09u8; 32];

        fn key_pair(seed: [u8; 32]) -> (SigningKey, VerifyingKey) {
            let sk = SigningKey::from_bytes(&seed);
            let vk = sk.verifying_key();
            (sk, vk)
        }

        fn sign(sk: &SigningKey, mut sth: RekorSignedTreeHead) -> RekorSignedTreeHead {
            let bytes = sth.canonical_bytes();
            let sig = sk.sign(&bytes);
            sth.signature = sig.to_bytes().to_vec();
            sth
        }

        fn key_set_with(log_id: [u8; 32], vk: VerifyingKey) -> RekorKeySet {
            let mut ks = RekorKeySet::new();
            ks.insert_trusted_key_for_test(log_id, vk, 0, 2_000_000_000)
                .expect("insert test key");
            ks
        }

        #[test]
        fn keyset_insert_and_lookup() {
            let (_sk, vk) = key_pair(SEED_A);
            let mut ks = RekorKeySet::new();
            ks.insert_trusted_key_for_test(LOG_ID_A, vk, 1_000, 9_000)
                .unwrap();
            assert_eq!(ks.len(), 1);
            assert!(ks.find_for_timestamp(&LOG_ID_A, 5_000).is_some());
            assert!(ks.find_for_timestamp(&LOG_ID_A, 999).is_none());
            assert!(ks.find_for_timestamp(&LOG_ID_A, 9_001).is_none());
            assert!(ks.find_for_timestamp(&LOG_ID_B, 5_000).is_none());
        }

        #[test]
        fn keyset_inclusive_bounds() {
            let (_sk, vk) = key_pair(SEED_A);
            let mut ks = RekorKeySet::new();
            ks.insert_trusted_key_for_test(LOG_ID_A, vk, 1_000, 9_000)
                .unwrap();
            assert!(ks.find_for_timestamp(&LOG_ID_A, 1_000).is_some());
            assert!(ks.find_for_timestamp(&LOG_ID_A, 9_000).is_some());
        }

        #[test]
        fn keyset_inverted_window_rejected() {
            let (_sk, vk) = key_pair(SEED_A);
            let mut ks = RekorKeySet::new();
            let err = ks
                .insert_trusted_key_for_test(LOG_ID_A, vk, 5_000, 1_000)
                .unwrap_err();
            assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
        }

        #[test]
        fn keyset_duplicate_insert_is_idempotent() {
            let (_sk, vk) = key_pair(SEED_A);
            let mut ks = RekorKeySet::new();
            ks.insert_trusted_key_for_test(LOG_ID_A, vk, 1_000, 9_000)
                .unwrap();
            ks.insert_trusted_key_for_test(LOG_ID_A, vk, 1_000, 9_000)
                .unwrap();
            assert_eq!(ks.len(), 1);
        }

        #[test]
        fn keyset_grace_period_picks_newest_valid_from() {
            let (_sk_old, vk_old) = key_pair(SEED_A);
            let (_sk_new, vk_new) = key_pair(SEED_B);
            let mut ks = RekorKeySet::new();
            ks.insert_trusted_key_for_test(LOG_ID_A, vk_old, 0, 10_000)
                .unwrap();
            // new key starts mid-window (grace overlap).
            ks.insert_trusted_key_for_test(LOG_ID_A, vk_new, 5_000, 20_000)
                .unwrap();
            assert_eq!(
                ks.find_for_timestamp(&LOG_ID_A, 4_999).unwrap().to_bytes(),
                vk_old.to_bytes()
            );
            // Inside overlap: newest valid_from wins.
            assert_eq!(
                ks.find_for_timestamp(&LOG_ID_A, 7_500).unwrap().to_bytes(),
                vk_new.to_bytes()
            );
            assert_eq!(
                ks.find_for_timestamp(&LOG_ID_A, 15_000).unwrap().to_bytes(),
                vk_new.to_bytes()
            );
        }

        #[test]
        fn sth_verifies_with_matching_key() {
            let (sk, vk) = key_pair(SEED_A);
            let ks = key_set_with(LOG_ID_A, vk);
            let sth = sign(&sk, sample_sth());
            verify_rekor_sth(&sth, &ks, sth.timestamp + 60, MAX_STH_AGE_SECONDS)
                .expect("valid STH");
        }

        #[test]
        fn sth_signature_tampering_rejected() {
            let (sk, vk) = key_pair(SEED_A);
            let ks = key_set_with(LOG_ID_A, vk);
            let mut sth = sign(&sk, sample_sth());
            // Mutate tree_root AFTER signing → signature no longer covers payload.
            sth.tree_root[0] ^= 0xff;
            let err = verify_rekor_sth(&sth, &ks, sth.timestamp + 60, MAX_STH_AGE_SECONDS)
                .unwrap_err();
            assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
        }

        #[test]
        fn sth_wrong_key_rejected() {
            // Register key B, but sign with key A. Signature verification fails.
            let (sk_signer, _vk_signer) = key_pair(SEED_A);
            let (_sk_other, vk_other) = key_pair(SEED_B);
            let ks = key_set_with(LOG_ID_A, vk_other);
            let sth = sign(&sk_signer, sample_sth());
            let err = verify_rekor_sth(&sth, &ks, sth.timestamp + 60, MAX_STH_AGE_SECONDS)
                .unwrap_err();
            assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
        }

        #[test]
        fn sth_log_untrusted_rejected() {
            let (sk, _vk) = key_pair(SEED_A);
            // Empty key set → log_id matches nothing.
            let ks = RekorKeySet::new();
            let sth = sign(&sk, sample_sth());
            let err = verify_rekor_sth(&sth, &ks, sth.timestamp + 60, MAX_STH_AGE_SECONDS)
                .unwrap_err();
            assert!(matches!(err, AttestError::RekorLogUntrusted { .. }));
        }

        #[test]
        fn sth_stale_rejected() {
            let (sk, vk) = key_pair(SEED_A);
            let ks = key_set_with(LOG_ID_A, vk);
            let sth = sign(&sk, sample_sth());
            let err = verify_rekor_sth(
                &sth,
                &ks,
                sth.timestamp
                    + i64::try_from(MAX_STH_AGE_SECONDS).expect("max_age fits i64")
                    + 1,
                MAX_STH_AGE_SECONDS,
            )
            .unwrap_err();
            assert!(matches!(err, AttestError::RekorSthStale { .. }));
        }

        #[test]
        fn sth_future_timestamp_rejected() {
            let (sk, vk) = key_pair(SEED_A);
            let ks = key_set_with(LOG_ID_A, vk);
            let sth = sign(&sk, sample_sth());
            // current_time strictly before sth.timestamp.
            let err =
                verify_rekor_sth(&sth, &ks, sth.timestamp - 1, MAX_STH_AGE_SECONDS).unwrap_err();
            assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
        }

        #[test]
        fn sth_malformed_signature_rejected() {
            let (sk, vk) = key_pair(SEED_A);
            let ks = key_set_with(LOG_ID_A, vk);
            let mut sth = sign(&sk, sample_sth());
            // Truncated signature — 63 bytes instead of 64.
            sth.signature.truncate(63);
            let err = verify_rekor_sth(&sth, &ks, sth.timestamp + 60, MAX_STH_AGE_SECONDS)
                .unwrap_err();
            assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
        }

        #[test]
        fn sth_freshness_boundary_inclusive() {
            let (sk, vk) = key_pair(SEED_A);
            let ks = key_set_with(LOG_ID_A, vk);
            let sth = sign(&sk, sample_sth());
            // Exactly max_age old — must still pass (boundary inclusive).
            verify_rekor_sth(
                &sth,
                &ks,
                sth.timestamp + i64::try_from(MAX_STH_AGE_SECONDS).expect("fits"),
                MAX_STH_AGE_SECONDS,
            )
            .expect("boundary should be inclusive");
        }
    }
}
