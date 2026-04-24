# Canon Verifier (web)

> **Status:** hackathon preview, 2026-04-24.  Merged to `main` ahead of
> schedule to enable the GitHub Pages deploy during the Berlin Hack
> 2026-04-25/26.  Post-event this deploy may be taken down pending the
> full public-release gate (`LICENSE-APACHE` + `LICENSE-MIT` committed,
> secrets-scan, CODEOWNERS review).  The in-page banner and this block
> are the removable "preview" flag.

**Client-side Canon-fact verifier.**  A single-page app that runs the
canonical `canon-verify` logic inside your browser via WebAssembly and
shows every step of the verification — so a viewer can see **why** a
signature is valid, not just **that** it is.

```
┌──────────────────────────────────────────────────────────────────┐
│  Canon Verifier                                                  │
│  Paste envelope + pubkey →  verify  →  ✓ / ✗  + 10 named steps   │
│  Zero network calls after the initial page load.                 │
└──────────────────────────────────────────────────────────────────┘
```

## What's in this directory

| Path                        | Purpose                                                               |
|-----------------------------|-----------------------------------------------------------------------|
| `index.html`                | Static shell with input, verdict, steps, and raw-bytes panels.       |
| `style.css`                 | Parchment + wax-seal brand; mobile-first single-column layout.       |
| `app.js`                    | ES-module glue: loads WASM, shuttles input, renders panels.          |
| `pkg/`                      | `wasm-pack --target web` build — the bundle the page consumes.       |
| `pkg-node/`                 | `wasm-pack --target nodejs` build — consumed by `test/smoke.mjs`.    |
| `test/smoke.mjs`            | CLI-vs-WASM parity smoke test (see below).                           |

## How verification works

```
┌──────────────────┐      ┌────────────────────────────┐
│ envelope_hex +   │ ───▶ │ verify_canon_envelope(...) │
│ ed25519:<b64>    │      │   in canon-verify-wasm     │
└──────────────────┘      └───────────┬────────────────┘
                                      │
          ┌───────────────────────────┴────────────────────────────┐
          ▼                                                        ▼
┌────────────────────┐                              ┌──────────────────────────┐
│ decoded payload    │                              │ 10 named steps:          │
│ (fact_id, entity,  │                              │   0 hex decode           │
│  claim, parent…,   │                              │   1 parse COSE_Sign1     │
│  event_hash)       │                              │   2 extract pieces       │
│                    │                              │   3 extract kid          │
│                    │                              │   4 parse pubkey         │
│                    │                              │   5 derive expected kid  │
│                    │                              │   6 build TBS            │
│                    │                              │   7 Ed25519 verify       │
│                    │                              │   8 event_hash = sha256  │
│                    │                              │   9 decode 7-field array │
└────────────────────┘                              └──────────────────────────┘
```

The crate [`canon-verify-wasm`](../crates/canon-verify-wasm) holds *no*
independent signature primitives — it bottom-out on the same
`ephemeral-crypto::verify_cose_sign1` that the CLI uses.  The signing
side of the code (`SigningKey`, `OsRng`, `zeroize`) is **deliberately
excluded** from the wasm32 build graph, so the audit surface of the
browser bundle is strictly verify-only.

## Running locally

Any static-file server works — the page must be fetched over
`http://` or `https://` (not `file://`) so the browser's fetch loader
accepts the streaming `instantiateStreaming` call.

```bash
# From the workspace root:
cd reference/validator/tools/canon-signer/web
python3 -m http.server 8080
#   or: npx http-server -p 8080 .
#   or: caddy file-server --listen :8080
open http://localhost:8080/
```

Click **Load demo fact** and then **Verify** to see a successful
verification.  Paste your own envelope + pubkey from a `canon-signer`
response to verify a real fact.

## Rebuilding the WASM

Any time the `canon-verify-wasm` crate changes, regenerate **both**
bundles (browser + node) and commit the artefacts so GitHub Pages
picks them up:

```bash
# From reference/validator/
wasm-pack build tools/canon-signer/crates/canon-verify-wasm \
    --target web --release \
    --out-dir ../../web/pkg --out-name canon_verify_wasm

wasm-pack build tools/canon-signer/crates/canon-verify-wasm \
    --target nodejs --release \
    --out-dir ../../web/pkg-node --out-name canon_verify_wasm

# Delete the wasm-pack-generated .gitignore so the output lands in git:
rm tools/canon-signer/web/pkg/.gitignore tools/canon-signer/web/pkg-node/.gitignore
```

Build requires `wasm-pack ≥ 0.14` and the `wasm32-unknown-unknown`
rustup target.  See [VALIDATION.md §4](../docs/VALIDATION.md#4-wasm-verifier-roadmap)
for toolchain specifics.

## Test gates

Four layers of testing, each protecting a different invariant:

| Gate                          | Command                                                   | What it proves                                                              |
|-------------------------------|-----------------------------------------------------------|-----------------------------------------------------------------------------|
| **Parity** (native)           | `cargo test -p canon-verify-wasm --tests`                 | AAD, kid-derivation, and 7-field CBOR payload are byte-identical to signer. |
| **Roundtrip** (native)        | (part of the same command)                                | Signing with `canon-signer` + verifying via the wasm crate succeeds.         |
| **wasm-bindgen-test** (node)  | `wasm-pack test --node tools/canon-signer/crates/canon-verify-wasm` | The crate compiles and runs under wasm32 (curve25519-dalek, ciborium, …).    |
| **Smoke** (node)              | `node tools/canon-signer/web/test/smoke.mjs`              | CLI and WASM agree on `event_hash` + `kid` for the same envelope.           |

The smoke test requires release binaries:

```bash
cargo build --workspace --release
node tools/canon-signer/web/test/smoke.mjs
```

## Privacy

Once the page is loaded there are **no network calls** — no
telemetry, no error reporting, no CDN fetches.  The verification
happens entirely in-browser against a pre-downloaded wasm bundle.
The page does not set any cookies or read `localStorage`.

## Deploying on GitHub Pages

See [`.github/workflows/deploy-web-verifier.yml`](../../../../.github/workflows/deploy-web-verifier.yml)
for the manual-trigger deploy workflow.  The flow is:

1. Push to `main` (no deploy).
2. Go to **Actions → Deploy web verifier → Run workflow**.
3. The action copies `tools/canon-signer/web/` into an artefact,
   uploads it to Pages, and flips the live URL.

The workflow is `workflow_dispatch`-only so routine merges never
auto-publish.
