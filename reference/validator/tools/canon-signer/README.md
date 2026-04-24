# canon-signer

A thin CLI sidecar that re-exposes EPHEMERAL's `COSE_Sign1` + Ed25519 primitives as a long-running stdin/stdout NDJSON service.  Intended to be spawned once by [Canon](https://github.com/ultranova/canon) (or any Node/Python consumer) and kept alive for the lifetime of the parent process.

One line of JSON in → one line of JSON out.  No HTTP, no socket, no shared state.

## Deeper docs

- **[docs/TECHNICAL.md](./docs/TECHNICAL.md)** — architecture, wire protocol, CBOR layout, threat model, test matrix (for engineers/auditors).
- **[docs/EXPLAINER.md](./docs/EXPLAINER.md)** — notary & hash-chain analogies, the "why it matters" story (no crypto background needed).
- **[docs/HACKATHON.md](./docs/HACKATHON.md)** — demo playbook, audience FAQ, rescue answers (Nelson's personal guide).

## Build

```bash
# From inside reference/validator/
cargo build -p canon-signer --release
# binary at: target/release/canon-signer(.exe)
```

Musl static build (for Railway / Alpine containers):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build -p canon-signer --release --target x86_64-unknown-linux-musl
# binary at: target/x86_64-unknown-linux-musl/release/canon-signer
```

## CLI

```
canon-signer [--keyfile <path>]
canon-signer --help
canon-signer --version
```

Key-loading priority (first match wins):

1. **Env var** `CANON_SIGNER_KEY_HEX` — 64 hex chars = 32-byte Ed25519 seed.
2. **`--keyfile <path>`** — file containing the same 64-hex seed (trailing whitespace trimmed).
3. **Auto-generate** — fresh OS-entropy seed; persisted to `${TMPDIR:-/tmp}/canon-signer.key` (chmod 0600 on unix) so a restart can resume the same identity.  The public kid is logged to **stderr** so operators can recover it.

On startup a single `stderr` line is emitted, e.g.:

```
canon-signer started kid=canon/a1b2c3d4e5f60708 pubkey=ed25519:oBE6m... source=Env
```

## Wire protocol

Each line on `stdin` is one request; each line on `stdout` is one response.  Lines are `\n`-terminated; `stdout` is flushed after every write.  Unknown fields in requests are ignored.  Blank lines are skipped.

### Request

```json
{
  "op": "sign",
  "fact_id": "f_01HQR...",
  "entity": "customer:acme",
  "claim": "Q1 revenue was EUR 127,000",
  "source_ref": "gmail:msg_abc",
  "source_excerpt": "Our Q1 came in at 127k EUR...",
  "parent_hash": "",
  "created_at_ms": 1713974400000
}
```

Fields:

| field            | type         | notes                                                        |
|------------------|--------------|--------------------------------------------------------------|
| `op`             | string       | must be `"sign"`                                             |
| `fact_id`        | string       | caller-supplied stable id (e.g. ULID)                        |
| `entity`         | string       | subject reference, e.g. `customer:acme`                      |
| `claim`          | string       | the assertion being signed                                   |
| `source_ref`     | string       | opaque upstream pointer (mail id, doc id, …)                 |
| `source_excerpt` | string\|null | optional verbatim slice of the source                        |
| `parent_hash`    | string       | `""` for genesis; otherwise lowercase hex of prior event     |
| `created_at_ms`  | uint         | caller-supplied Unix milliseconds (caller owns the clock)    |

### Response (success)

```json
{
  "fact_id": "f_01HQR...",
  "event_hash": "4f3c...<64 hex chars>",
  "cose_sign1_hex": "d28443a10127...",
  "signer_pubkey": "ed25519:oBE6m...",
  "signed_at_ms": 1713974400017
}
```

`event_hash` is `SHA-256(canonical_cbor_payload)`, hex-lowercase.  `cose_sign1_hex` is the full `COSE_Sign1` envelope (RFC 9052 §4.2) over that payload under external AAD `b"canon/fact/v1"`.

### Response (error)

```json
{ "error": "parse_error", "detail": "parent_hash is not valid hex: ..." }
```

The loop always writes *exactly one* line per input line and continues to the next.  A malformed line never terminates the subprocess.

## Canonical payload

The signed payload is a CBOR **array of 7 elements** in fixed positional order:

| idx | field            | CBOR type     |
|-----|------------------|---------------|
| 0   | `parent_hash`    | `bstr` (hex-decoded; `bstr<0>` for genesis) |
| 1   | `fact_id`        | `tstr`        |
| 2   | `entity`         | `tstr`        |
| 3   | `claim`          | `tstr`        |
| 4   | `source_ref`     | `tstr`        |
| 5   | `source_excerpt` | `tstr` / `null` |
| 6   | `created_at_ms`  | `uint`        |

Positional arrays avoid map-ordering ambiguity; `ciborium`'s default encoder emits shortest-length ints and length-prefixed strings — canonical per RFC 8949 §4.2 for the subset we use.

## Verification

Any `ephemeral-crypto` consumer can verify a produced envelope:

```rust
use ephemeral_crypto::{verify_cose_sign1, AnchorRole, TrustAnchor, TrustAnchorSet};

let mut anchors = TrustAnchorSet::new();
anchors.insert(
    TrustAnchor::new_ed25519(kid, &pubkey_bytes, AnchorRole::CanonSigner)?
)?;

let verified = verify_cose_sign1(
    &cose_bytes,
    &anchors,
    b"canon/fact/v1",
    AnchorRole::CanonSigner,
)?;
assert_eq!(verified.payload, expected_canonical_cbor);
```

## Dockerfile snippet (Canon / Railway)

Add to Canon's Dockerfile, before the Node.js stage:

```dockerfile
# Stage 1: build canon-signer (static musl binary)
FROM rust:1.82-alpine AS signer-builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY reference/validator ./validator
RUN cd validator \
 && cargo build -p canon-signer --release --target x86_64-unknown-linux-musl
RUN cp validator/target/x86_64-unknown-linux-musl/release/canon-signer /out/canon-signer

# Stage 2: Node.js app
FROM node:20-alpine
COPY --from=signer-builder /out/canon-signer /usr/local/bin/canon-signer
# ... rest of Canon image
```

Canon spawns the subprocess with:

```js
const { spawn } = require('child_process');
const signer = spawn('canon-signer', [], {
  env: { ...process.env, CANON_SIGNER_KEY_HEX: process.env.CANON_KEY },
  stdio: ['pipe', 'pipe', 'inherit'],   // stderr passes through to logs
});
```

## Guarantees and non-goals

**Guaranteed**

- `event_hash` is a pure function of the request fields (same input → same output, always). No wall-clock, no random salt, no monotonic counter silently mixed in.
- Changing any request field (including `parent_hash`) produces a different `event_hash`, so re-parenting and truncation attacks are detectable.
- Every produced envelope verifies via the production `ephemeral_crypto::verify_cose_sign1` library under `AnchorRole::CanonSigner` and external AAD `b"canon/fact/v1"`.
- Tampering with any byte of the envelope (payload or signature) causes verification to fail.

**Non-goals**

- Not a supervisor: the binary exits on EOF or unrecoverable I/O error. Canon is responsible for respawning.
- No key rotation protocol. To rotate, restart the subprocess with a new seed.
- No batching.  One request line = one response line. If throughput matters, run multiple subprocesses.

## Tests

```bash
cargo test -p canon-signer
```

- `src/*` unit tests (encoding, hash derivation, COSE build + verify, key loading, stdin loop).
- `tests/smoke.rs` — single sign request, well-formed response.
- `tests/round_trip.rs` — produced envelope verifies via `ephemeral_crypto::verify_cose_sign1`; tampered envelope rejected. Load-bearing.
- `tests/chain.rs` — determinism of re-signed fact; parent-hash flip changes event-hash.
- `tests/persistence.rs` — 100 signs in one subprocess; latency + chain integrity.
- `tests/error_recovery.rs` — malformed lines return error, loop stays alive.
