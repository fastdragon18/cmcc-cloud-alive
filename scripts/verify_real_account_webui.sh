#!/usr/bin/env bash
# Real-account end-to-end verification for the WebUI 产出.
# Run this WHERE THE MACHINE CAN REACH China Mobile (aijia.10086.cn / soho.komect.com).
# It does NOT print secrets (usernames are masked; tokens never echoed).
#
# Usage:
#   scripts/verify_real_account_webui.sh            # dry-run round only (safe)
#   LIVE=1 scripts/verify_real_account_webui.sh     # also one REAL keepalive round
#
# Prereqs: an existing logged-in profile under ~/.cmcc-cloud-alive/profiles/*.json
# (created via the WebUI login or `python3 -m cmcc_cloud_alive login`).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
PORT="${PORT:-28170}"
BASE="http://127.0.0.1:${PORT}"
PY="${PY:-python3}"

say() { printf '\n=== %s ===\n' "$*"; }

say "0. network reachability (must be OK for real-account)"
code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' https://aijia.10086.cn 2>/dev/null || echo 000)
echo "aijia.10086.cn -> HTTP ${code}"
if [ "$code" = "000" ]; then
  echo "!! No route to China Mobile. Real-account keepalive cannot run here."
  echo "   Run this script from a network that can reach aijia.10086.cn."
  exit 2
fi

say "1. start WebUI (uvicorn) on :${PORT}"
CMCC_WEBUI_PORT="$PORT" CMCC_WEBUI_HOST=127.0.0.1 \
  "$PY" -m uvicorn cmcc_cloud_alive.webui.app:app --host 127.0.0.1 --port "$PORT" \
  >/tmp/cmcc_webui_verify.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
for i in $(seq 1 20); do
  curl -s -m 2 "$BASE/api/health" >/dev/null 2>&1 && break; sleep 0.5
done
curl -s -m 3 "$BASE/api/health"; echo

say "2. real profiles visible (usernames masked by the API)"
curl -s -m 5 "$BASE/api/profiles" | "$PY" -c '
import sys,json
d=json.load(sys.stdin); ps=d.get("profiles",[])
print("profiles:",len(ps))
for p in ps: print(" -",p["id"],"| user",p["usernameMasked"],"| tokenPresent",p["tokenPresent"],"| desktop",p["userServiceId"] or "-")
' || { echo "no profiles — log in first (WebUI or: $PY -m cmcc_cloud_alive login)"; exit 3; }

PID="$(curl -s -m 5 "$BASE/api/profiles" | "$PY" -c 'import sys,json; ps=json.load(sys.stdin)["profiles"]; print(ps[0]["id"] if ps else "")')"
[ -n "$PID" ] || { echo "no usable profile"; exit 3; }
echo "using profile: $PID"

say "3. DRY-RUN keepalive round (no real traffic, proves the chain)"
curl -s -m 5 -X POST "$BASE/api/profiles/$PID/jobs" -H 'Content-Type: application/json' \
  -d '{"protocol":"ZTE","mode":"dry-run"}' -o /dev/null -w "start -> HTTP %{http_code}\n"
sleep 2
curl -s -m 5 "$BASE/api/profiles/$PID/logs" | "$PY" -c 'import sys,json; L=json.load(sys.stdin)["lines"]; print("log lines:",len(L)); [print("  ",x["line"][:80]) for x in L[-4:]]'
curl -s -m 8 -X DELETE "$BASE/api/profiles/$PID/jobs/current" -o /dev/null -w "stop -> HTTP %{http_code}\n"

if [ "${LIVE:-0}" = "1" ]; then
  say "4. ONE REAL keepalive round (mode=live, durationSec small)"
  curl -s -m 5 -X POST "$BASE/api/profiles/$PID/jobs" -H 'Content-Type: application/json' \
    -d '{"protocol":"ZTE","mode":"live","trafficSec":30,"durationSec":30}' -o /dev/null -w "live start -> HTTP %{http_code}\n"
  for i in $(seq 1 20); do
    sleep 3
    curl -s -m 5 "$BASE/api/profiles/$PID/logs" | "$PY" -c '
import sys,json
L=json.load(sys.stdin)["lines"]; t="\n".join(x["line"] for x in L)
done = ("保活完成" in t) or ("keepalive-done" in t) or ("MAIN_INIT" in t)
print("  round done:" , done, "| lines", len(L))
[print("   ",x["line"][:90]) for x in L[-3:]]
sys.exit(0 if done else 1)
' && break
  done
  curl -s -m 10 -X DELETE "$BASE/api/profiles/$PID/jobs/current" -o /dev/null -w "live stop -> HTTP %{http_code}\n"
else
  echo
  echo "(skipped real round; re-run with LIVE=1 to send one real keepalive round.)"
fi

say "DONE — see /tmp/cmcc_webui_verify.log for the server log"
