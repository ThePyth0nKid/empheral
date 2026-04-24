// End-to-end smoke test for the Canon web verifier.
//
// What this proves
// ----------------
// 1. `canon-signer` (CLI) produces an envelope.
// 2. `canon-verify` (CLI) accepts that envelope and reports `ok: true`.
// 3. The **WASM verifier** shipped in `web/pkg-node/` accepts the same
//    envelope, reports `verified: true`, and returns the same
//    `event_hash` as the CLI — i.e. both verification paths are
//    byte-compatible, which is the hackathon's load-bearing claim.
//
// The test uses `--target nodejs` output (`web/pkg-node/`) so it runs
// under a stock `node >= 20` without any bundler.  The browser-facing
// `web/pkg/` build is identical byte-for-byte at the wasm level; only
// the JS glue differs.
//
// Run from the workspace root:
//   node tools/canon-signer/web/test/smoke.mjs

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import fs from "node:fs";

// Resolve paths relative to this file so the script is location-
// independent (works from any cwd).
const HERE         = path.dirname(fileURLToPath(import.meta.url));
const WEB          = path.resolve(HERE, "..");
const CRATES       = path.resolve(WEB,  "..");
const VALIDATOR    = path.resolve(CRATES, "..", "..");
const WORKSPACE    = path.resolve(VALIDATOR);
const TARGET_DIR   = path.resolve(WORKSPACE, "target", "release");
const CANON_SIGNER = path.join(TARGET_DIR, process.platform === "win32" ? "canon-signer.exe" : "canon-signer");
const CANON_VERIFY = path.join(TARGET_DIR, process.platform === "win32" ? "canon-verify.exe" : "canon-verify");

const PKG_NODE_JS = path.resolve(WEB, "pkg-node", "canon_verify_wasm.js");

let failed = 0;
function pass(msg) { console.log(`\x1b[32m ok \x1b[0m ${msg}`); }
function fail(msg) { console.log(`\x1b[31mFAIL\x1b[0m ${msg}`); failed += 1; }

// ───────── Phase 1: binaries exist ─────────
function checkBinaries() {
  for (const [label, p] of [["canon-signer", CANON_SIGNER], ["canon-verify", CANON_VERIFY]]) {
    if (!fs.existsSync(p)) {
      fail(`${label} not found at ${p} — run: cargo build --workspace --release`);
      return false;
    }
    pass(`${label} binary present`);
  }
  if (!fs.existsSync(PKG_NODE_JS)) {
    fail(`nodejs wasm bundle not found at ${PKG_NODE_JS} — run: wasm-pack build tools/canon-signer/crates/canon-verify-wasm --target nodejs --release --out-dir ../../web/pkg-node --out-name canon_verify_wasm`);
    return false;
  }
  pass(`web/pkg-node bundle present`);
  return true;
}

// ───────── Phase 2: produce an envelope via the CLI ─────────
function signOne() {
  const req = JSON.stringify({
    op: "sign",
    fact_id: "f_smoke_0001",
    entity: "customer:smoketest",
    claim: "The smoke test ran at " + new Date().toISOString(),
    source_ref: "smoke.mjs",
    source_excerpt: null,
    parent_hash: "",
    created_at_ms: Date.now(),
  });
  // canon-signer reads its seed from env CANON_SIGNER_KEY_HEX (takes
  // priority over --keyfile).  We pin it to the same 32-byte seed as
  // the unit fixtures (`[1;32]` hex-repeated) so the kid stays stable
  // across runs and matches tests/fixtures/mod.rs.
  const signer = spawnSync(CANON_SIGNER, [], {
    input: req + "\n",
    encoding: "utf8",
    timeout: 10_000,
    env: { ...process.env, CANON_SIGNER_KEY_HEX: "01".repeat(32) },
  });
  if (signer.status !== 0) {
    fail(`canon-signer exited ${signer.status}: ${signer.stderr?.slice(0, 400)}`);
    return null;
  }
  const line = (signer.stdout || "").split(/\r?\n/).find((l) => l.trim().length > 0);
  if (!line) {
    fail("canon-signer produced no stdout lines");
    return null;
  }
  let resp;
  try { resp = JSON.parse(line); } catch (e) {
    fail(`canon-signer output was not JSON: ${e.message}`);
    return null;
  }
  if (!resp.cose_sign1_hex || !resp.signer_pubkey) {
    fail(`canon-signer response missing fields: ${JSON.stringify(resp)}`);
    return null;
  }
  pass(`canon-signer produced a ${resp.cose_sign1_hex.length / 2}-byte envelope`);
  return resp;
}

// ───────── Phase 3: CLI verifier agrees ─────────
function verifyCli(envelopeHex, pubkey) {
  const v = spawnSync(CANON_VERIFY, ["--pubkey", pubkey, "--envelope-hex", envelopeHex], {
    encoding: "utf8",
    timeout: 10_000,
  });
  if (v.status !== 0) {
    fail(`canon-verify (CLI) exited ${v.status}: ${(v.stdout || "") + (v.stderr || "")}`);
    return null;
  }
  const line = (v.stdout || "").split(/\r?\n/).find((l) => l.trim().length > 0);
  let r;
  try { r = JSON.parse(line); } catch (e) {
    fail(`canon-verify output was not JSON: ${e.message}`);
    return null;
  }
  if (!r.verified) {
    fail(`canon-verify (CLI) rejected envelope: ${r.error || "unknown"}`);
    return null;
  }
  pass(`canon-verify (CLI) accepted, event_hash = ${r.event_hash?.slice(0, 16)}…`);
  return r;
}

// ───────── Phase 4: WASM verifier agrees ─────────
async function verifyWasm(envelopeHex, pubkey) {
  let mod;
  try {
    mod = await import(pathToFileURL(PKG_NODE_JS).href);
  } catch (e) {
    fail(`failed to import WASM bundle: ${e.message}`);
    return null;
  }
  const result = mod.verify_canon_envelope(envelopeHex, pubkey, undefined);
  if (!result.verified) {
    fail(`WASM verifier rejected envelope: ${result.error || "unknown"}`);
    return null;
  }
  pass(`WASM verify OK, event_hash = ${result.event_hash.slice(0, 16)}…`);
  return result;
}

// ───────── Phase 5: both verifiers report identical event_hash + kid ─
function assertParity(cli, wasm) {
  if (cli.event_hash !== wasm.event_hash) {
    fail(`event_hash mismatch: CLI=${cli.event_hash}, WASM=${wasm.event_hash}`);
    return;
  }
  pass(`event_hash matches across CLI and WASM`);

  if (cli.kid && wasm.kid && cli.kid !== wasm.kid) {
    fail(`kid mismatch: CLI=${cli.kid}, WASM=${wasm.kid}`);
    return;
  }
  pass(`kid matches across CLI and WASM (${wasm.kid})`);

  // Steps invariant: WASM verifier always emits exactly 10 named steps
  // and all must be "ok" on a successful verification.
  if (!Array.isArray(wasm.steps) || wasm.steps.length !== 10) {
    fail(`WASM steps array had ${wasm.steps?.length} entries, expected 10`);
    return;
  }
  const nonOk = wasm.steps.filter((s) => s.status !== "ok").map((s) => s.name);
  if (nonOk.length) {
    fail(`WASM verifier reported non-ok steps on a valid envelope: ${nonOk.join(", ")}`);
    return;
  }
  pass(`WASM reported all 10 steps as ok`);
}

// ───────── Phase 6: tamper check — WASM must detect ─────────
async function tamperCheck(envelopeHex, pubkey) {
  // Flip one byte near the end of the signature.
  const bytes = Buffer.from(envelopeHex, "hex");
  bytes[bytes.length - 5] ^= 0x01;
  const tampered = bytes.toString("hex");
  const mod = await import(pathToFileURL(PKG_NODE_JS).href);
  const r = mod.verify_canon_envelope(tampered, pubkey, undefined);
  if (r.verified) {
    fail("tampered envelope was accepted — signature check is broken");
  } else {
    pass("WASM verifier rejected tampered envelope");
  }
}

// ───────── main ─────────
(async () => {
  console.log("Canon Verifier — smoke test");
  console.log("---------------------------");

  if (!checkBinaries()) { process.exit(1); }
  const signed = signOne();
  if (!signed) { process.exit(1); }

  const cli  = verifyCli(signed.cose_sign1_hex, signed.signer_pubkey);
  const wasm = await verifyWasm(signed.cose_sign1_hex, signed.signer_pubkey);
  if (!cli || !wasm) { process.exit(1); }

  assertParity(cli, wasm);
  await tamperCheck(signed.cose_sign1_hex, signed.signer_pubkey);

  if (failed > 0) {
    console.log(`\n${failed} failure(s).`);
    process.exit(1);
  }
  console.log("\nAll smoke checks passed.");
})().catch((err) => {
  console.error("smoke test crashed:", err);
  process.exit(2);
});
