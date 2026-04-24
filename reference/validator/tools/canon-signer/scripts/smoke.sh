#!/usr/bin/env bash
# smoke.sh — end-to-end hackathon-readiness gate for canon-signer
#
# Runs 10 checks against the current working tree.
# Exit 0 ⇔ everything is green ⇔ safe to demo / safe to go public.
#
# Usage (from anywhere):
#   bash reference/validator/tools/canon-signer/scripts/smoke.sh
#   bash reference/validator/tools/canon-signer/scripts/smoke.sh --skip-musl
#
# Notes
# -----
# * Runs in the workspace root (auto-detected from script path).
# * Uses a fixed demo key so binary output is reproducible.
# * Captures full logs under target/smoke-logs/ for post-mortem.

set -uo pipefail

# ------ locate workspace root ------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_DIR="$(cd "$CRATE_DIR/../.." && pwd)"      # reference/validator
cd "$WORKSPACE_DIR"

# ------ config ------
SKIP_MUSL=0
for arg in "$@"; do
  case "$arg" in
    --skip-musl) SKIP_MUSL=1 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -20
      exit 0
      ;;
  esac
done

LOG_DIR="$WORKSPACE_DIR/target/smoke-logs"
mkdir -p "$LOG_DIR"

DEMO_KEY_HEX=0101010101010101010101010101010101010101010101010101010101010101
export CANON_SIGNER_KEY_HEX="$DEMO_KEY_HEX"

# ------ styling ------
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  G=$(tput setaf 2); R=$(tput setaf 1); Y=$(tput setaf 3); B=$(tput bold); N=$(tput sgr0)
else
  G=""; R=""; Y=""; B=""; N=""
fi

# ------ tracker ------
PASS=0
FAIL=0
SKIP=0
FAIL_NAMES=()

step() {
  local name="$1"
  printf "\n${B}──▶ %s${N}\n" "$name"
}
pass() {
  PASS=$((PASS + 1))
  printf "   ${G}✓ PASS${N}  %s\n" "$1"
}
fail() {
  FAIL=$((FAIL + 1))
  FAIL_NAMES+=("$1")
  printf "   ${R}✗ FAIL${N}  %s\n" "$1"
  [[ -n "${2:-}" ]] && printf "          ${R}%s${N}\n" "$2"
}
skip() {
  SKIP=$((SKIP + 1))
  printf "   ${Y}‣ SKIP${N}  %s  ${Y}(%s)${N}\n" "$1" "$2"
}

# ==========================================================================
# 1. Release build
# ==========================================================================
step "1/11  cargo build -p canon-signer --release --bins"
if cargo build -p canon-signer --release --bins >"$LOG_DIR/01-build.log" 2>&1; then
  pass "release binaries built (canon-signer + canon-verify)"
else
  fail "release build" "see $LOG_DIR/01-build.log"
  printf "${R}→ can't continue without binary, aborting.${N}\n"
  exit 1
fi

# Locate binary (Windows adds .exe)
BIN="$WORKSPACE_DIR/target/release/canon-signer"
[[ -x "$BIN.exe" ]] && BIN="$BIN.exe"
if [[ ! -x "$BIN" ]]; then
  fail "binary not executable" "expected at $BIN"
  exit 1
fi

# ==========================================================================
# 2. Full test suite
# ==========================================================================
step "2/11  cargo test -p canon-signer --release"
if cargo test -p canon-signer --release >"$LOG_DIR/02-tests.log" 2>&1; then
  TOTAL=$(grep -E "test result:.*passed" "$LOG_DIR/02-tests.log" | awk '{s+=$4} END {print s}')
  pass "all tests passed (${TOTAL:-?} total)"
else
  fail "test suite" "see $LOG_DIR/02-tests.log"
fi

# ==========================================================================
# 3. Clippy (strict)
# ==========================================================================
step "3/11  cargo clippy -p canon-signer -- -D warnings"
if cargo clippy -p canon-signer --all-targets --release -- -D warnings \
      >"$LOG_DIR/03-clippy.log" 2>&1; then
  pass "clippy clean (no warnings)"
else
  fail "clippy warnings/errors" "see $LOG_DIR/03-clippy.log"
fi

# ==========================================================================
# 4. Golden-path sign via live subprocess
# ==========================================================================
step "4/11  golden-path: live sign request → well-formed response"
REQ='{"op":"sign","fact_id":"f_smoke_1","entity":"customer:acme","claim":"Q1 revenue was EUR 127,000","source_ref":"gmail:msg_abc","source_excerpt":"Our Q1 came in at 127k EUR","parent_hash":"","created_at_ms":1713974400000}'
RESP=$(printf '%s\n' "$REQ" | "$BIN" 2>"$LOG_DIR/04-stderr.log" | head -n1)
printf '%s\n' "$RESP" >"$LOG_DIR/04-response.json"

VALIDATE_RESP=$(CANON_RESP="$RESP" python -c '
import json, os, sys
try:
    d = json.loads(os.environ["CANON_RESP"])
    assert d["fact_id"] == "f_smoke_1",                "fact_id mismatch"
    assert len(d["event_hash"]) == 64,                 "event_hash not 64 hex"
    assert all(c in "0123456789abcdef" for c in d["event_hash"]), "event_hash not lowercase hex"
    cose = d["cose_sign1_hex"]
    # RFC 9052 COSE_Sign1: tagged (0xd28440...) or untagged array of 4 (0x84...)
    assert cose.startswith(("84", "d28")),             "cose envelope not COSE_Sign1 shape (expected 0x84 or 0xd2 prefix)"
    assert d["signer_pubkey"].startswith("ed25519:"),  "signer_pubkey bad prefix"
    assert isinstance(d["signed_at_ms"], int),         "signed_at_ms not int"
    print("ok")
except Exception as e:
    print(f"FAIL: {e}")
' 2>&1)
if [[ "$VALIDATE_RESP" == "ok" ]]; then
  pass "response well-formed (event_hash, cose_sign1_hex, signer_pubkey, signed_at_ms)"
else
  fail "golden-path response validation" "$VALIDATE_RESP"
fi

# Save the envelope for later steps
EVENT_HASH_1=$(printf '%s\n' "$RESP" | python -c "import json,sys;print(json.loads(sys.stdin.read())['event_hash'])" 2>/dev/null || echo "")
COSE_HEX_1=$(printf '%s\n' "$RESP" | python -c "import json,sys;print(json.loads(sys.stdin.read())['cose_sign1_hex'])" 2>/dev/null || echo "")
PUBKEY_1=$(printf '%s\n' "$RESP" | python -c "import json,sys;print(json.loads(sys.stdin.read())['signer_pubkey'])" 2>/dev/null || echo "")

# ==========================================================================
# 5. Determinism: same input → same event_hash, different subprocess
# ==========================================================================
step "5/11  determinism: two separate runs, same input, same event_hash"
RESP2=$(printf '%s\n' "$REQ" | "$BIN" 2>/dev/null | head -n1)
EVENT_HASH_2=$(printf '%s\n' "$RESP2" | python -c "import json,sys;print(json.loads(sys.stdin.read())['event_hash'])" 2>/dev/null || echo "")
if [[ -n "$EVENT_HASH_1" && "$EVENT_HASH_1" == "$EVENT_HASH_2" ]]; then
  pass "event_hash stable across subprocesses (${EVENT_HASH_1:0:16}…)"
else
  fail "determinism violated" "run1=$EVENT_HASH_1 run2=$EVENT_HASH_2"
fi

# ==========================================================================
# 6. Chain integrity: parent_hash flip changes event_hash
# ==========================================================================
step "6/11  chain: flipping parent_hash produces different event_hash"
REQ_CHILD_A='{"op":"sign","fact_id":"f_child","entity":"customer:acme","claim":"same claim","source_ref":"gmail:msg","source_excerpt":null,"parent_hash":"'"$EVENT_HASH_1"'","created_at_ms":1713974500000}'
REQ_CHILD_B='{"op":"sign","fact_id":"f_child","entity":"customer:acme","claim":"same claim","source_ref":"gmail:msg","source_excerpt":null,"parent_hash":"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100","created_at_ms":1713974500000}'
HASH_A=$(printf '%s\n' "$REQ_CHILD_A" | "$BIN" 2>/dev/null | head -n1 | python -c "import json,sys;print(json.loads(sys.stdin.read())['event_hash'])" 2>/dev/null || echo "")
HASH_B=$(printf '%s\n' "$REQ_CHILD_B" | "$BIN" 2>/dev/null | head -n1 | python -c "import json,sys;print(json.loads(sys.stdin.read())['event_hash'])" 2>/dev/null || echo "")
if [[ -n "$HASH_A" && -n "$HASH_B" && "$HASH_A" != "$HASH_B" ]]; then
  pass "parent_hash flip detected (${HASH_A:0:12}… ≠ ${HASH_B:0:12}…)"
else
  fail "chain integrity violated" "parent flip did not change event_hash (A=$HASH_A B=$HASH_B)"
fi

# ==========================================================================
# 7. Error recovery: malformed line, then valid line still works
# ==========================================================================
step "7/11  error recovery: bad line → error response → good line still signs"
ERR_INPUT=$'not json at all\n'"$REQ"$'\n'
ERR_OUT=$(printf '%s' "$ERR_INPUT" | "$BIN" 2>/dev/null)
printf '%s\n' "$ERR_OUT" >"$LOG_DIR/07-error-recovery.log"
LINE1=$(printf '%s\n' "$ERR_OUT" | sed -n '1p')
LINE2=$(printf '%s\n' "$ERR_OUT" | sed -n '2p')
HAS_ERR=$(printf '%s' "$LINE1" | python -c 'import json,sys; d=json.loads(sys.stdin.read()); print("yes" if "error" in d else "no")' 2>/dev/null || echo "parse_fail")
HAS_HASH=$(printf '%s' "$LINE2" | python -c 'import json,sys; d=json.loads(sys.stdin.read()); print("yes" if len(d.get("event_hash","")) == 64 else "no")' 2>/dev/null || echo "parse_fail")
if [[ "$HAS_ERR" == "yes" && "$HAS_HASH" == "yes" ]]; then
  pass "loop survives malformed input, next request succeeds"
else
  fail "error recovery broken" "line1 has_error=$HAS_ERR  line2 has_hash=$HAS_HASH"
fi

# ==========================================================================
# 8. Persistence: 100 signs in one subprocess under 5 seconds
# ==========================================================================
step "8/11  persistence: 100-sign marathon in a single subprocess"
MARATHON_INPUT=$(python - <<PY
import json
parent = ""
for i in range(100):
    req = {
        "op": "sign",
        "fact_id": f"f_mara_{i:03d}",
        "entity": "customer:acme",
        "claim": f"marathon fact #{i}",
        "source_ref": "synthetic",
        "source_excerpt": None,
        "parent_hash": parent,
        "created_at_ms": 1713974400000 + i,
    }
    print(json.dumps(req))
    # parent_hash not updated between lines (we don't know event_hash yet);
    # loop behaviour is what we're measuring — determinism + no panic.
PY
)
T_START=$(date +%s%N 2>/dev/null || python -c "import time;print(int(time.time()*1e9))")
MARA_OUT=$(printf '%s\n' "$MARATHON_INPUT" | "$BIN" 2>/dev/null)
T_END=$(date +%s%N 2>/dev/null || python -c "import time;print(int(time.time()*1e9))")
ELAPSED_MS=$(( (T_END - T_START) / 1000000 ))
GOOD_LINES=$(printf '%s\n' "$MARA_OUT" | python -c '
import json, sys
ok = 0
for ln in sys.stdin:
    ln = ln.strip()
    if not ln: continue
    try:
        d = json.loads(ln)
        if len(d.get("event_hash", "")) == 64:
            ok += 1
    except Exception:
        pass
print(ok)
' 2>/dev/null || echo 0)
if [[ "$GOOD_LINES" == "100" && "$ELAPSED_MS" -lt 5000 ]]; then
  pass "100/100 signs in ${ELAPSED_MS} ms (≈$(( ELAPSED_MS * 1000 / 100 )) µs avg)"
else
  fail "marathon" "signed ${GOOD_LINES}/100 in ${ELAPSED_MS} ms"
fi

# ==========================================================================
# 9. Musl static build (simulates Canon Docker Alpine stage)
# ==========================================================================
step "9/11  musl static build: x86_64-unknown-linux-musl"
if [[ "$SKIP_MUSL" -eq 1 ]]; then
  skip "musl build" "skipped via --skip-musl"
elif ! rustup target list --installed 2>/dev/null | grep -q x86_64-unknown-linux-musl; then
  skip "musl build" "target not installed — run: rustup target add x86_64-unknown-linux-musl"
elif cargo build -p canon-signer --release --target x86_64-unknown-linux-musl \
     >"$LOG_DIR/09-musl.log" 2>&1; then
  MUSL_BIN="$WORKSPACE_DIR/target/x86_64-unknown-linux-musl/release/canon-signer"
  SIZE=$(du -h "$MUSL_BIN" 2>/dev/null | awk '{print $1}')
  pass "musl binary built (${SIZE:-?})"
else
  fail "musl build" "see $LOG_DIR/09-musl.log"
fi

# ==========================================================================
# 10. canon-verify CLI: round-trip + tamper rejection
# ==========================================================================
step "10/11 canon-verify CLI: verifies real envelope, rejects tampered one"
VERIFIER="$WORKSPACE_DIR/target/release/canon-verify"
[[ -x "$VERIFIER.exe" ]] && VERIFIER="$VERIFIER.exe"
if [[ ! -x "$VERIFIER" ]]; then
  fail "canon-verify binary missing" "expected at $VERIFIER — add to release build?"
elif [[ -z "${COSE_HEX_1:-}" || -z "${PUBKEY_1:-}" ]]; then
  fail "canon-verify" "step 4 didn't capture envelope/pubkey for reuse"
else
  VERIFY_OK_OUT=$("$VERIFIER" --envelope-hex "$COSE_HEX_1" --pubkey "$PUBKEY_1" 2>"$LOG_DIR/10-verify.err")
  VERIFY_OK_EXIT=$?
  VERIFIED_GOOD=$(printf '%s' "$VERIFY_OK_OUT" | python -c 'import json,sys; d=json.loads(sys.stdin.read()); print("yes" if d.get("verified") is True and len(d.get("event_hash","")) == 64 else "no")' 2>/dev/null || echo "parse_fail")

  TAMPERED_HEX="${COSE_HEX_1%?}$(printf '%x' $(( 16#${COSE_HEX_1: -1} ^ 1 )))"
  VERIFY_BAD_OUT=$("$VERIFIER" --envelope-hex "$TAMPERED_HEX" --pubkey "$PUBKEY_1" 2>>"$LOG_DIR/10-verify.err")
  VERIFY_BAD_EXIT=$?
  VERIFIED_BAD=$(printf '%s' "$VERIFY_BAD_OUT" | python -c 'import json,sys; d=json.loads(sys.stdin.read()); print("yes" if d.get("verified") is False else "no")' 2>/dev/null || echo "parse_fail")

  if [[ "$VERIFIED_GOOD" == "yes" && "$VERIFY_OK_EXIT" -eq 0 && \
        "$VERIFIED_BAD"  == "yes" && "$VERIFY_BAD_EXIT" -eq 1 ]]; then
    pass "real envelope verified (exit 0); tampered envelope rejected (exit 1)"
  else
    fail "canon-verify behaviour" \
      "good: verified=$VERIFIED_GOOD exit=$VERIFY_OK_EXIT  tampered: verified=$VERIFIED_BAD exit=$VERIFY_BAD_EXIT"
  fi
fi

# ==========================================================================
# 11. Docs sanity: all referenced diagrams + logos exist
# ==========================================================================
step "11/11 docs sanity: SVG + excalidraw + logo assets present"
DOCS_DIR="$CRATE_DIR/docs"
MISSING=()
for f in architecture cbor-layout notary chain review-swarm; do
  [[ -f "$DOCS_DIR/diagrams/$f.svg" ]] || MISSING+=("$f.svg")
  [[ -f "$DOCS_DIR/diagrams/$f.excalidraw" ]] || MISSING+=("$f.excalidraw")
done
[[ -f "$CRATE_DIR/assets/logo.svg" ]] || MISSING+=("assets/logo.svg")
[[ -f "$CRATE_DIR/assets/logo-banner.svg" ]] || MISSING+=("assets/logo-banner.svg")
[[ -f "$DOCS_DIR/VALIDATION.md" ]] || MISSING+=("docs/VALIDATION.md")
[[ -f "$SCRIPT_DIR/demo.sh" ]] || MISSING+=("scripts/demo.sh")
if [[ ${#MISSING[@]} -eq 0 ]]; then
  pass "all 14 asset/doc files present"
else
  fail "missing assets/docs" "${MISSING[*]}"
fi

# ==========================================================================
# Summary
# ==========================================================================
printf "\n${B}════════════════════════════════════════════════════════${N}\n"
printf "${B}  Smoke Summary${N}\n"
printf "${B}════════════════════════════════════════════════════════${N}\n"
printf "   ${G}✓ PASS : %d${N}\n" "$PASS"
printf "   ${Y}‣ SKIP : %d${N}\n" "$SKIP"
if [[ "$FAIL" -gt 0 ]]; then
  printf "   ${R}✗ FAIL : %d${N}\n" "$FAIL"
  printf "\n${R}Failed steps:${N}\n"
  for f in "${FAIL_NAMES[@]}"; do
    printf "   • %s\n" "$f"
  done
  printf "\nLogs: %s\n" "$LOG_DIR"
  exit 1
fi
printf "\n${G}${B}  ✔ canon-signer is hackathon-ready.${N}\n\n"
printf "Logs: %s\n" "$LOG_DIR"
exit 0
