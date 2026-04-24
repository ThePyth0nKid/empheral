# canon-signer — CLI Sidecar for Canon (Big Berlin Hack 2026-04-25/26)

**Status:** WIP on branch `feat/canon-signer`, started 2026-04-24.
**Context:** Extracted from EPHEMERAL for Canon/BBH 2026-04-25/26. EPHEMERAL's Phase-C roadmap (Rekor STH, key-rotation, Phase D) continues post-BBH on `main` untouched.

## Purpose

Canon is a Node.js application that signs "facts" (business claims extracted from emails/documents) into a tamper-evident hash chain. `canon-signer` is a long-running Rust sidecar binary that re-exposes EPHEMERAL's COSE_Sign1 + Ed25519 primitives via a stdin/stdout NDJSON protocol.

**Why a Rust sidecar instead of a pure-JS signer:**
- Standards-compliant COSE_Sign1 (RFC 9052) with strict-mode Ed25519.
- Stable keys across process restarts (process spawned once per Canon server boot).
- Small attack surface: single binary, no network, no filesystem writes except optional keyfile.
- Sub-ms sign latency (Ed25519 sign ~20µs, SHA-256 ~1µs, CBOR encode ~50µs).

## Non-Goals

No Nitro, PCR, KMS, Rekor, tariff, classifier, delegation, WASM, HTTP, gRPC, tokio, structured logging, clap. See original prompt §"Ausdrückliche Nicht-Ziele".

## Architecture

```
┌──────────────────┐   stdin  ┌─────────────────┐
│ Canon (Node.js)  │─────────>│ canon-signer    │
│                  │  NDJSON  │ (long-running)  │
│                  │<─────────│                 │
└──────────────────┘  stdout  └─────────────────┘
                                      │
                              reuses: ephemeral-crypto
                                      coset
                                      ed25519-dalek
                                      ciborium
                                      sha2
```

One line in = one line out. `writeln!` + `flush` after each response.

## Wire Protocol

### Request
```json
{
  "op": "sign",
  "fact_id": "f_01HQ...",
  "entity": "customer:acme",
  "claim": "Q1 revenue was €127,000",
  "source_ref": "gmail:msg_abc123",
  "source_excerpt": "Our Q1 came in at 127k EUR...",
  "parent_hash": "a3f2...",
  "created_at_ms": 1713974400000
}
```

`parent_hash`: hex string. Empty string `""` = genesis. `source_excerpt`: string or null.

### Response
```json
{
  "fact_id": "f_01HQ...",
  "event_hash": "b4e1...",
  "cose_sign1_hex": "d28443a10126a10...",
  "signer_pubkey": "ed25519:MC0wBQYDK2VwAyEA...",
  "signed_at_ms": 1713974400001
}
```

### Error
```json
{ "error": "parse_error", "detail": "invalid JSON: expected field `fact_id` at line 1 column 42" }
```

Error slugs: `parse_error`, `internal_error`. The process stays alive on errors; only fatal-exits when the key cannot be loaded at startup.

## Event-Hash Derivation (canonical, deterministic)

`event_hash` is `hex_lowercase(SHA256(payload_bytes))` where `payload_bytes` is canonical CBOR of an **array of 7 fields** in fixed order:

```cbor
[
  parent_hash_bytes,   ; bstr — hex-decoded bytes of parent_hash; len=0 for genesis
  fact_id,             ; tstr
  entity,              ; tstr
  claim,               ; tstr
  source_ref,          ; tstr
  source_excerpt,      ; tstr OR CBOR null (0xf6) if request field was null
  created_at_ms        ; uint (always ≥ 0)
]
```

Array encoding is positional and has no key-ordering ambiguity. This is CBOR-deterministic by construction (no float, no indefinite-length items, no map key reordering).

**Parent-hash as `bstr` not `tstr`:** binary comparison is cheaper and byte-length is fixed (32 bytes or 0). Genesis is a zero-length byte-string, distinct from any non-genesis value.

## COSE_Sign1 Envelope

- **`alg`** in protected header: `-8` (EdDSA, `ephemeral_crypto::COSE_ALG_EDDSA`).
- **`kid`** in protected header: UTF-8 string `canon/<hex-first-16-of-pubkey>` (16 hex chars). String-kid chosen so the round-trip test can use `ephemeral-crypto::verify_cose_sign1`, which requires UTF-8 kid via `extract_kid`.
- **`payload`**: the canonical CBOR array bytes from §"Event-Hash Derivation" (NOT the hash — the payload is the event itself, self-contained).
- **`external_aad`**: `b"canon/fact/v1"` — fixed domain-separation tag. Prevents cross-protocol signature confusion if the same Ed25519 key is later reused for EPHEMERAL envelopes (which use different AADs like `b"tariff"`, `b"ephemeral/anomaly-library/v1"`).
- **`signature`**: Ed25519 over `Sig_structure_1` per RFC 9052 §4.4. Built by `coset::CoseSign1Builder` with `create_signature(aad, |tbs| signing_key.sign(tbs).to_bytes().to_vec())`.

`cose_sign1_hex` = lowercase hex of the full CBOR-tagged (or untagged) COSE_Sign1 blob. Use untagged (matches EPHEMERAL's `ephemeral-crypto::verify_cose_sign1` which consumes `CoseSign1::from_slice`, not `CoseSign1::from_tagged_slice`).

## signer_pubkey Encoding

Format: `ed25519:<base64(raw-32-byte-pubkey)>`.

Plain base64 (no URL-safe, no padding-stripped). 44 characters after `ed25519:` prefix. Canon consumers use this string to identify which key signed.

## Key Loading (Priority Order)

1. **Env `CANON_SIGNER_KEY_HEX`** (64 hex chars = 32-byte Ed25519 seed). Preferred for production deploys.
2. **Flag `--keyfile <path>`**. File contains 64 hex chars, optional trailing whitespace.
3. **Auto-generate** at startup. Derives from `OsRng`. Logs `using ephemeral key: ed25519:<base64>` to **stderr** (never stdout). Writes the seed-hex to `${TMPDIR:-/tmp}/canon-signer.key` with `0600` perms so a later restart can resume the same identity. Logs the path.

**Startup failure modes:**
- Env set but not 64 hex chars → exit 2, `ERROR: CANON_SIGNER_KEY_HEX must be 64 hex chars` on stderr.
- `--keyfile` path unreadable → exit 2.
- Auto-gen file write fails → continue but warn on stderr (ephemeral key for this run only).

## Stdin Loop Semantics

```rust
let stdin = io::stdin().lock();
let stdout = io::stdout();
for line in stdin.lines() {
    let line = match line {
        Ok(l) if l.trim().is_empty() => continue, // skip blank lines
        Ok(l) => l,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
        Err(_) => break,  // other IO errors end the loop
    };
    let response = handle_line(&line, &signer);
    let mut out = stdout.lock();
    writeln!(out, "{}", serde_json::to_string(&response).unwrap())?;
    out.flush()?;  // critical — Canon will deadlock without this
}
// EOF → exit 0
```

Parse errors and sign errors return an error-response; the loop continues. Only fatal: missing keys at startup.

## ephemeral-crypto Extension (minimal)

Add one variant to `AnchorRole`:
```rust
pub enum AnchorRole {
    // existing variants unchanged
    CanonSigner,  // AAD = b"canon/fact/v1"
}
```
- Wire string: `"canon-signer"`.
- `from_wire_str` / `as_wire_str` updated (exhaustive match, no silent default).
- No new tests in `ephemeral-crypto` beyond the existing roundtrip (which already covers every variant via a for-loop).

This is additive; `#[non_exhaustive]` on `AnchorRole` means downstream crates do not need to update their match arms.

## Workspace Placement

`reference/validator/tools/canon-signer/` — analogous to `tools/vector-signer/`. Registered as a workspace member in `reference/validator/Cargo.toml`.

Dependencies (workspace-resolved): `ephemeral-crypto`, `coset`, `ed25519-dalek`, `ciborium`, `sha2`, `hex`, `serde`, `serde_json`, `serde_bytes`, `rand_core`, `base64`, `zeroize`, `anyhow`, `thiserror`.

New workspace dep: `base64 = "0.22"` (for pubkey encoding). `rand_core` comes transitively via `ed25519-dalek`; if not, add directly.

## Test Matrix

`tools/canon-signer/tests/`:

1. **`smoke.rs`** — spawn the binary as subprocess, send one sign request, parse response, assert all 5 response fields are present and syntactically valid (event_hash is 64 hex chars, cose_sign1_hex decodes to valid CBOR).
2. **`round_trip.rs`** — same spawn-flow, then parse the `cose_sign1_hex`, build a `TrustAnchorSet` with the returned pubkey under `AnchorRole::CanonSigner`, and run `ephemeral_crypto::verify_cose_sign1(..., aad=b"canon/fact/v1", AnchorRole::CanonSigner)`. Assert success, assert `verified.payload` matches the expected canonical CBOR we would have built independently, assert `SHA256(verified.payload) == event_hash`. **This is the load-bearing test.**
3. **`chain.rs`** — sign Fact A (parent=""), capture event_hash_a. Sign Fact B with parent=event_hash_a. Re-sign Fact A → exact same event_hash_a bytes (determinism pin).
4. **`persistence.rs`** — 100 sequential signs in one subprocess. Median < 5ms, p99 < 20ms on Nelson's Windows dev box. Memory does not grow (RSS check optional, not CI-enforced).
5. **`error_recovery.rs`** — send malformed JSON, assert error-response on stdout, send valid request next, assert success (loop stays alive).

All via `std::process::Command` with `Stdio::piped()` — no test-only backdoor into the binary's main loop.

## Build Artifacts

**Windows (local dev):**
```bash
cargo build --release -p canon-signer
# → target/release/canon-signer.exe
```

**Linux (Canon's deploy):** NOT cross-compiled locally. Canon's Dockerfile will include:
```dockerfile
FROM rust:1.82-alpine AS signer-builder
RUN apk add --no-cache musl-dev git
WORKDIR /build
RUN git clone --depth 1 --branch feat/canon-signer https://github.com/ThePyth0nKid/empheral.git
WORKDIR /build/empheral/reference/validator
RUN cargo build --release -p canon-signer --target x86_64-unknown-linux-musl
# Binary at /build/empheral/reference/validator/target/x86_64-unknown-linux-musl/release/canon-signer

FROM node:20-alpine
COPY --from=signer-builder /build/empheral/reference/validator/target/x86_64-unknown-linux-musl/release/canon-signer /usr/local/bin/canon-signer
# ... rest of Canon's Node.js app
```

(The `feat/canon-signer` branch is referenced here pre-merge; Canon's actual Dockerfile will use `main` after Nelson merges.)

This saves ~1h of Windows-host cross-compile toolchain setup. Railway builds the Docker image on Linux where musl-cross is trivial.

## Performance Targets

Local Windows (Ryzen 7): median < 5ms, p99 < 20ms. Budget breakdown:
- JSON parse: ~50µs
- CBOR encode 7-field array: ~50µs
- SHA-256 over ~500-byte payload: ~1µs
- Ed25519 sign: ~20µs
- COSE_Sign1 envelope build: ~100µs
- JSON encode response + hex + base64: ~100µs
- Stdout write + flush: variable, ~100µs-1ms

Total expected: ~500µs median. 5ms budget has ~10x headroom.

## Deliverables Checklist

- [ ] `tools/canon-signer/Cargo.toml` — workspace member, deps configured
- [ ] `tools/canon-signer/src/main.rs` — stdin loop + sign orchestration
- [ ] `tools/canon-signer/src/event.rs` — canonical CBOR encoder + event_hash
- [ ] `tools/canon-signer/src/cose.rs` — COSE_Sign1 envelope builder
- [ ] `tools/canon-signer/src/key.rs` — key loading (env/flag/auto-gen)
- [ ] `tools/canon-signer/src/io.rs` — stdin-loop + request/response types
- [ ] `tools/canon-signer/README.md` — build + example I/O
- [ ] `tools/canon-signer/tests/smoke.rs`
- [ ] `tools/canon-signer/tests/round_trip.rs`
- [ ] `tools/canon-signer/tests/chain.rs`
- [ ] `tools/canon-signer/tests/persistence.rs`
- [ ] `tools/canon-signer/tests/error_recovery.rs`
- [ ] `reference/validator/Cargo.toml` — members list updated
- [ ] `reference/validator/crates/ephemeral-crypto/src/anchors.rs` — `AnchorRole::CanonSigner` added
- [ ] `cargo test --workspace` green
- [ ] `cargo clippy --workspace -- -D warnings` green
- [ ] Manual smoke-test passed (echo-pipeline from `main` branch prompt §Deliverables item 7)
- [ ] `feat/canon-signer` branch pushed
- [ ] Final-report on stdout after push

## Merge Instructions (for Nelson after validation)

1. `cargo test --workspace` — must be green
2. Manual smoke:
   ```bash
   echo '{"op":"sign","fact_id":"t1","entity":"x","claim":"hello","source_ref":"","source_excerpt":null,"parent_hash":"","created_at_ms":0}' | ./target/release/canon-signer.exe
   ```
   expect valid JSON with all 5 fields.
3. If green: `git checkout main && git merge --no-ff feat/canon-signer && git push origin main`
4. Public-Go is Nelson's manual step via GitHub Settings → Repository Visibility. `canon-signer` does NOT gate on public status.

## Rollback

Branch is isolated. If anything goes sideways: `git checkout main && git branch -D feat/canon-signer` leaves `main` untouched (HEAD `87e28cd`, EPHEMERAL C.4 Session 5-B Commit C).

Canon's fallback is Plan B2 (`@noble/ed25519` JS-only signing). `canon-signer` is a speed/compliance upgrade, not a functional hard dependency.
