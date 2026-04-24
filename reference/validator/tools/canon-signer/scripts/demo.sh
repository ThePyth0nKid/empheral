#!/usr/bin/env bash
# demo.sh — executable stage playbook for canon-signer + canon-verify.
#
# Runs the full "sign two chained facts, verify both, tamper with one,
# show rejection" story in one shot.  Safe to run on stage, safe to
# rerun as a rehearsal.  Total runtime: ~2 seconds on a warm build.
#
# Usage:
#   bash reference/validator/tools/canon-signer/scripts/demo.sh
#   bash reference/validator/tools/canon-signer/scripts/demo.sh --quiet
#
# The script intentionally uses a fixed demo key so transcripts are
# reproducible across rehearsals and the event_hashes shown on stage
# match what you rehearse in the hotel the night before.

set -uo pipefail

# ------ locate workspace ------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_DIR="$(cd "$CRATE_DIR/../.." && pwd)"   # reference/validator
cd "$WORKSPACE_DIR"

# ------ flags ------
QUIET=0
for arg in "$@"; do
  case "$arg" in
    -q|--quiet) QUIET=1 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -16
      exit 0
      ;;
  esac
done

# ------ styling ------
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  G=$(tput setaf 2); R=$(tput setaf 1); C=$(tput setaf 6); Y=$(tput setaf 3); B=$(tput bold); D=$(tput dim); N=$(tput sgr0)
else
  G=""; R=""; C=""; Y=""; B=""; D=""; N=""
fi

banner() {
  if [[ "$QUIET" -eq 0 ]]; then
    printf "\n${B}${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}\n"
    printf "${B}${C}  %s${N}\n"                              "$1"
    printf "${B}${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}\n"
  fi
}
step() { printf "\n${B}── %s${N}\n" "$1"; }
narrate() { [[ "$QUIET" -eq 0 ]] && printf "${D}%s${N}\n" "$1"; }
ok() { printf "   ${G}✓${N} %s\n" "$1"; }
bad() { printf "   ${R}✗${N} %s\n" "$1"; }

# ------ build check ------
SIGNER="$WORKSPACE_DIR/target/release/canon-signer"
VERIFIER="$WORKSPACE_DIR/target/release/canon-verify"
[[ -x "$SIGNER.exe" ]]  && SIGNER="$SIGNER.exe"
[[ -x "$VERIFIER.exe" ]] && VERIFIER="$VERIFIER.exe"

if [[ ! -x "$SIGNER" || ! -x "$VERIFIER" ]]; then
  printf "${Y}Binaries not found — building release…${N}\n"
  cargo build -p canon-signer --release --bins >/dev/null 2>&1 || {
    printf "${R}Build failed. Run manually: cargo build -p canon-signer --release --bins${N}\n"
    exit 1
  }
  # Re-resolve after build
  SIGNER="$WORKSPACE_DIR/target/release/canon-signer"
  VERIFIER="$WORKSPACE_DIR/target/release/canon-verify"
  [[ -x "$SIGNER.exe" ]]  && SIGNER="$SIGNER.exe"
  [[ -x "$VERIFIER.exe" ]] && VERIFIER="$VERIFIER.exe"
fi

# ------ demo key ------
# Fixed 32-byte seed → deterministic kid canon/8a88e3dd7409f195.
# This is PUBLIC; never reuse it for a real signer.
export CANON_SIGNER_KEY_HEX=0101010101010101010101010101010101010101010101010101010101010101

banner "Canon-signer live demo"
narrate "The signer is a thin Rust sidecar that turns AI-extracted business"
narrate "facts into cryptographically tamper-evident receipts (COSE_Sign1 / Ed25519)."
narrate "Every fact commits to its parent — deleting or editing even one fact"
narrate "breaks every signature that follows it."

# ==========================================================================
# Step 1 — start signer, capture pubkey
# ==========================================================================
step "step 1 — start the signer sidecar"
narrate "Canon would spawn this as a child process and keep it alive for its lifetime."
narrate "Here we start it manually so you can see the pubkey it announces."

STDERR_LOG=$(mktemp 2>/dev/null || echo "/tmp/canon-demo-stderr.log")
# Probe the stderr startup line by running --help first (no I/O needed).
"$SIGNER" --version >/dev/null 2>&1 || true

# Run a probe signing with just a "ping" to capture the pubkey.  Easier:
# sign a real fact and pull pubkey from the response.
GENESIS_REQ='{"op":"sign","fact_id":"f_1_incoming_email","entity":"customer:acme","claim":"Q1 revenue was EUR 127,000","source_ref":"gmail:msg_abc123","source_excerpt":"Our Q1 came in at 127k EUR — thanks for the prompt invoice.","parent_hash":"","created_at_ms":1713974400000}'

ok "signer binary: $SIGNER"
ok "demo key     : fixed seed (public) → see stderr for kid"

# ==========================================================================
# Step 2 — sign genesis fact
# ==========================================================================
step "step 2 — sign the genesis fact (parent_hash is empty)"
narrate "Input: one JSON line on stdin — fact id, entity, claim, source ref, timestamp."
narrate "Output: one JSON line on stdout — event_hash, cose_sign1_hex, signer_pubkey."

GENESIS_RESP=$(printf '%s\n' "$GENESIS_REQ" | "$SIGNER" 2>"$STDERR_LOG" | head -n1)
GENESIS_HASH=$(echo "$GENESIS_RESP" | python -c "import json,sys;print(json.loads(sys.stdin.read())['event_hash'])")
GENESIS_COSE=$(echo "$GENESIS_RESP" | python -c "import json,sys;print(json.loads(sys.stdin.read())['cose_sign1_hex'])")
PUBKEY=$(      echo "$GENESIS_RESP" | python -c "import json,sys;print(json.loads(sys.stdin.read())['signer_pubkey'])")

ok "event_hash = ${B}${GENESIS_HASH:0:16}…${N}  ${D}(64 hex chars total)${N}"
ok "envelope   = ${B}${GENESIS_COSE:0:24}…${N}   ${D}(${#GENESIS_COSE} hex chars)${N}"
ok "pubkey     = ${B}${PUBKEY}${N}"

# ==========================================================================
# Step 3 — sign a child fact (parent_hash = genesis event_hash)
# ==========================================================================
step "step 3 — sign a child fact (parent_hash = previous event_hash)"
narrate "This is what makes the chain: the child commits to the genesis hash,"
narrate "so you cannot silently re-order or delete the genesis without breaking"
narrate "the child's signature."

CHILD_REQ=$(python - <<PY
import json
print(json.dumps({
    "op": "sign",
    "fact_id": "f_2_ap_invoice_received",
    "entity": "customer:acme",
    "claim": "Invoice INV-2026-Q1-001 marked paid on 2026-04-20",
    "source_ref": "gmail:msg_def456",
    "source_excerpt": None,
    "parent_hash": "$GENESIS_HASH",
    "created_at_ms": 1713974500000
}))
PY
)
CHILD_RESP=$(printf '%s\n' "$CHILD_REQ" | "$SIGNER" 2>/dev/null | head -n1)
CHILD_HASH=$(echo "$CHILD_RESP" | python -c "import json,sys;print(json.loads(sys.stdin.read())['event_hash'])")
CHILD_COSE=$(echo "$CHILD_RESP" | python -c "import json,sys;print(json.loads(sys.stdin.read())['cose_sign1_hex'])")

ok "child event_hash = ${B}${CHILD_HASH:0:16}…${N}  ${D}(parent=${GENESIS_HASH:0:12}…)${N}"
ok "child envelope   = ${B}${CHILD_COSE:0:24}…${N}"

# ==========================================================================
# Step 4 — verify BOTH facts with canon-verify
# ==========================================================================
step "step 4 — verify both facts (independent binary, same pubkey)"
narrate "canon-verify is a separate 3 MiB static binary.  It knows nothing about"
narrate "the signer process — it just takes an envelope, a pubkey, and checks"
narrate "that the Ed25519 signature is valid over the canonical CBOR payload."

printf "   ${D}%s --envelope-hex <cose_sign1_hex> --pubkey <signer_pubkey>${N}\n" "$(basename "$VERIFIER")"

V1=$("$VERIFIER" --envelope-hex "$GENESIS_COSE" --pubkey "$PUBKEY")
V1_OK=$(echo "$V1" | python -c "import json,sys;print('yes' if json.loads(sys.stdin.read())['verified'] else 'no')")
if [[ "$V1_OK" == "yes" ]]; then
  ok "genesis fact  → ${G}${B}VERIFIED${N}  ${D}$V1${N}"
else
  bad "genesis fact  → UNEXPECTED FAILURE: $V1"
  exit 1
fi

V2=$("$VERIFIER" --envelope-hex "$CHILD_COSE" --pubkey "$PUBKEY")
V2_OK=$(echo "$V2" | python -c "import json,sys;print('yes' if json.loads(sys.stdin.read())['verified'] else 'no')")
if [[ "$V2_OK" == "yes" ]]; then
  ok "child fact    → ${G}${B}VERIFIED${N}  ${D}$V2${N}"
else
  bad "child fact    → UNEXPECTED FAILURE: $V2"
  exit 1
fi

# ==========================================================================
# Step 5 — tamper with child envelope, verify again
# ==========================================================================
step "step 5 — tamper with one nibble of the child envelope"
narrate "We flip a single hex character — literally one bit in the signature."
narrate "The math has no tolerance for this.  canon-verify must refuse."

# Flip the last nibble.
LAST_NIBBLE="${CHILD_COSE: -1}"
FLIPPED=$(printf '%x' $(( 16#${LAST_NIBBLE} ^ 1 )))
TAMPERED="${CHILD_COSE%?}${FLIPPED}"

printf "   ${D}original last nibble:${N} %s\n" "$LAST_NIBBLE"
printf "   ${D}flipped last nibble :${N} ${Y}%s${N}\n" "$FLIPPED"

TAMPER_OUT=$("$VERIFIER" --envelope-hex "$TAMPERED" --pubkey "$PUBKEY")
TAMPER_EXIT=$?
TAMPER_OK=$(echo "$TAMPER_OUT" | python -c "import json,sys;print('yes' if json.loads(sys.stdin.read())['verified'] else 'no')")
if [[ "$TAMPER_OK" == "no" && "$TAMPER_EXIT" -eq 1 ]]; then
  ok "tampered fact → ${R}${B}REJECTED${N}  ${D}(exit=1)${N}"
  printf "            ${D}%s${N}\n" "$TAMPER_OUT"
else
  bad "tampered fact → unexpectedly accepted: $TAMPER_OUT"
  exit 1
fi

# ==========================================================================
# Summary
# ==========================================================================
banner "Summary"
narrate "You just saw:"
narrate "  • two facts signed into a hash chain"
narrate "  • both facts independently verified"
narrate "  • a one-nibble tamper detected immediately"
narrate ""
narrate "No database lookup.  No network call.  No trust in Canon's server."
narrate "Just one public key and the math behind Ed25519 + COSE_Sign1."

printf "\n${G}${B}  ✔ end-to-end hash-chained signing + tamper detection${N}\n\n"
printf "Reproduce this transcript: ${D}bash %s${N}\n" "${BASH_SOURCE[0]}"
printf "Deeper docs             : ${D}%s/docs/VALIDATION.md${N}\n" "$CRATE_DIR"
