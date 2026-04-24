// Canon Verifier — browser glue.
//
// Two imports and then everything is pure DOM: the actual verification
// happens inside WebAssembly.  This file only has to (a) shuttle
// user input into `verify_canon_envelope`, (b) unpack the returned
// `VerifyResult`, and (c) render three panels (verdict, steps, raw).
//
// No dependencies, no build step.  One <script type="module"> tag in
// index.html is enough to boot the whole page.

import init, { verify_canon_envelope } from "./pkg/canon_verify_wasm.js";

// ───────── boot + build stamp ─────────
const buildStamp = document.getElementById("build-stamp");
const verifyBtn  = document.getElementById("verify-btn");

let wasmReady = false;
init().then(() => {
  wasmReady = true;
  buildStamp.textContent = "wasm ready";
  verifyBtn.disabled = false;
}).catch((err) => {
  wasmReady = false;
  buildStamp.textContent = "wasm load failed — open the console";
  console.error("wasm init failed:", err);
});

// Disable verify until wasm is ready so a click before init resolves
// gives the user a clear "not yet" rather than a silent no-op.
verifyBtn.disabled = true;

// ───────── DOM refs ─────────
const envelopeEl = document.getElementById("envelope");
const pubkeyEl   = document.getElementById("pubkey");
const demoBtn    = document.getElementById("demo-btn");
const clearBtn   = document.getElementById("clear-btn");

const verdictPanel = document.getElementById("verdict-panel");
const verdictTitle = document.getElementById("verdict-title");
const verdictSub   = document.getElementById("verdict-sub");
const sealMount    = document.getElementById("seal-mount");
const factList     = document.getElementById("fact-facts");

const stepsPanel = document.getElementById("steps-panel");
const stepList   = document.getElementById("step-list");

const rawPanel = document.getElementById("raw-panel");

// ───────── hard-coded demo vector ─────────
// Byte-identical to what `canon-signer` emits for seed [1;32] and the
// standard demo request.  Pinned by tests/roundtrip_native.rs and
// tests/wasm_golden.rs — see crates/canon-verify-wasm/tests/fixtures/mod.rs.
const DEMO = {
  envelope:
    "84581ba20127045663616e6f6e2f38613838653364643734303966313935a0587187406b665f64656d6f5f303030316d637573746f6d65723a61636d65781a513120726576656e75652077617320455552203132372c30303070676d61696c3a6d73675f616263313233781d4f75722051312063616d6520696e206174203132376b204555522e2e2e1b0000018f10d5d4005840f1da68f2c73f1f53ead697488daa1fb18cbedf9f003c7cb3a68c4df80893f3cb96559c5abd192a89d4fb05245f7190da6bd4036e3c7c41bb1d778d085a2d1c0d",
  pubkey: "ed25519:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
};

demoBtn.addEventListener("click", () => {
  envelopeEl.value = DEMO.envelope;
  pubkeyEl.value   = DEMO.pubkey;
  envelopeEl.focus();
});

clearBtn.addEventListener("click", () => {
  envelopeEl.value = "";
  pubkeyEl.value   = "";
  hide(verdictPanel); hide(stepsPanel); hide(rawPanel);
  envelopeEl.focus();
});

verifyBtn.addEventListener("click", runVerify);

// Enter in either input triggers verify, matching customer muscle-memory
// from CLI tools.
for (const el of [envelopeEl, pubkeyEl]) {
  el.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && (e.ctrlKey || e.metaKey || el.tagName !== "TEXTAREA")) {
      e.preventDefault();
      runVerify();
    }
  });
}

// ───────── Share-URL: read `?e=...&pk=...` on load ─────────
const params = new URLSearchParams(location.search);
if (params.has("e") && params.has("pk")) {
  envelopeEl.value = params.get("e") || "";
  pubkeyEl.value   = params.get("pk") || "";
  // Wait for wasm before running so the result actually renders.
  const waitAndRun = () => {
    if (wasmReady) runVerify();
    else setTimeout(waitAndRun, 50);
  };
  waitAndRun();
}

// ───────── Verify entry point ─────────
function runVerify() {
  if (!wasmReady) return;

  const env = envelopeEl.value.trim();
  const pk  = pubkeyEl.value.trim();
  if (!env || !pk) {
    flashError("Both an envelope and a public key are required.");
    return;
  }

  let result;
  try {
    result = verify_canon_envelope(env, pk, undefined);
  } catch (err) {
    // verify_canon_envelope is designed to be total, but guard anyway
    // — any throw is an internal bug worth surfacing, not swallowing.
    console.error(err);
    flashError("Internal verifier error — check the console.");
    return;
  }

  renderVerdict(result);
  renderSteps(result.steps);
  renderRaw(result.raw);
}

function flashError(msg) {
  verdictPanel.classList.remove("ok");
  verdictPanel.classList.add("fail");
  sealMount.innerHTML = sealBrokenSVG();
  verdictTitle.textContent = "Input incomplete";
  verdictSub.textContent = msg;
  factList.hidden = true;
  show(verdictPanel);
  hide(stepsPanel);
  hide(rawPanel);
}

// ───────── Verdict panel ─────────
function renderVerdict(r) {
  verdictPanel.classList.remove("ok", "fail");
  verdictPanel.classList.add(r.verified ? "ok" : "fail");

  const wrap = verdictPanel.querySelector(".seal-wrap");
  wrap.classList.remove("animate", "ok", "fail");

  if (r.verified) {
    sealMount.innerHTML = sealGreenSVG();
    verdictTitle.textContent = "Signature valid";
    verdictSub.textContent =
      "The fact below was signed by " + shortKid(r.kid) +
      " and has not been altered since.";
    populateFacts(r);
    factList.hidden = false;
  } else {
    sealMount.innerHTML = sealBrokenSVG();
    verdictTitle.textContent = "Signature invalid";
    verdictSub.textContent = r.error || "Unknown verification error.";
    factList.hidden = true;
  }

  show(verdictPanel);

  // Retrigger animation each render.
  requestAnimationFrame(() => {
    wrap.classList.add("animate", r.verified ? "ok" : "fail");
  });
}

function populateFacts(r) {
  const p = r.decoded_payload || {};
  setText("f-fact-id", p.fact_id || "");
  setText("f-entity", p.entity || "");
  setText("f-claim", p.claim || "");
  setText("f-source", p.source_ref || "");
  setText("f-excerpt", p.source_excerpt ?? "—");
  setText("f-parent", p.parent_hash ? p.parent_hash : "(genesis fact)");
  setText("f-signed-at", formatMs(p.created_at_ms));
  setText("f-kid", r.kid || "");
  setText("f-event-hash", r.event_hash || "");
}

function formatMs(ms) {
  if (typeof ms !== "number" && typeof ms !== "bigint") return "";
  const d = new Date(Number(ms));
  if (isNaN(d.getTime())) return String(ms);
  return `${d.toISOString()}  (${ms} ms)`;
}

function shortKid(kid) {
  // `canon/8a88e3dd7409f195` → `canon/8a88…`
  if (!kid) return "unknown";
  return kid.length > 14 ? kid.slice(0, 12) + "…" : kid;
}

// ───────── Steps panel ─────────
function renderSteps(steps) {
  stepList.innerHTML = "";
  for (const s of (steps || [])) {
    const li = document.createElement("li");
    const glyph = document.createElement("span");
    glyph.className = `step-glyph ${s.status}`;
    glyph.textContent =
      s.status === "ok"   ? "\u2713" :
      s.status === "fail" ? "\u2717" :
                            "\u2014";

    const body = document.createElement("div");
    body.className = "step-body";
    const name = document.createElement("div");
    name.className = "step-name";
    name.textContent = s.name;
    const detail = document.createElement("div");
    detail.className = "step-detail";
    detail.textContent = s.detail || "";
    body.appendChild(name);
    body.appendChild(detail);

    li.appendChild(glyph);
    li.appendChild(body);
    stepList.appendChild(li);
  }
  show(stepsPanel);
}

// ───────── Raw panel ─────────
function renderRaw(raw) {
  if (!raw) { hide(rawPanel); return; }
  setText("r-payload",   raw.payload_cbor     || "");
  setText("r-protected", raw.protected_header || "");
  setText("r-aad",       raw.aad              || "");
  setText("r-signature", raw.signature        || "");
  show(rawPanel);
}

// ───────── utils ─────────
function show(el) { el.classList.remove("hidden"); }
function hide(el) { el.classList.add("hidden"); }
function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

// ───────── Seal SVGs (inline so we don't need extra HTTP requests) ─
function sealGreenSVG() {
  return `
<svg viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="valid seal">
  <defs>
    <radialGradient id="g-ok" cx="40%" cy="35%" r="65%">
      <stop offset="0%"  stop-color="#5bb36d"/>
      <stop offset="70%" stop-color="#2e6e3b"/>
      <stop offset="100%" stop-color="#1e4a26"/>
    </radialGradient>
  </defs>
  <circle cx="60" cy="60" r="50" fill="url(#g-ok)" stroke="#14381d" stroke-width="3"/>
  <circle cx="60" cy="60" r="40" fill="none" stroke="rgba(255,255,255,.45)" stroke-width="1.2" stroke-dasharray="3 3"/>
  <path d="M40 62 L54 76 L82 46" fill="none" stroke="#f6efd8" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
}

function sealBrokenSVG() {
  return `
<svg viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="broken seal">
  <defs>
    <radialGradient id="g-fail" cx="40%" cy="35%" r="65%">
      <stop offset="0%"  stop-color="#c84232"/>
      <stop offset="70%" stop-color="#8b1d13"/>
      <stop offset="100%" stop-color="#4a0f08"/>
    </radialGradient>
  </defs>
  <g transform="translate(-6 0)">
    <path d="M60 10 A50 50 0 0 1 110 60 L82 60 L70 50 L62 66 L54 52 Z"
          fill="url(#g-fail)" stroke="#3c0a05" stroke-width="2.5" stroke-linejoin="round"/>
  </g>
  <g transform="translate(8 2)">
    <path d="M60 110 A50 50 0 0 1 10 60 L38 60 L50 70 L58 54 L66 68 Z"
          fill="url(#g-fail)" stroke="#3c0a05" stroke-width="2.5" stroke-linejoin="round"/>
  </g>
  <path d="M35 52 L62 64 L48 82" fill="none" stroke="#f6efd8" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
}
