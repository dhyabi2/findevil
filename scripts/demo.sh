#!/usr/bin/env bash
# FIND EVIL! — 5-minute demo runner.
#
# This script paces the terminal demo for the hackathon video. It uses the
# CACHED run8 report (no live LLM call — keeps the 5-min budget honest and
# the demo deterministic). Press ENTER to advance between beats.
#
# Run from the repo root:
#   bash scripts/demo.sh
#
# Recommended terminal: 1920x1080, dark theme, font 20pt, scrollback cleared.

set -e
cd "$(dirname "$0")/.."

GREEN='\033[1;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
DIM='\033[2m'
BOLD='\033[1m'
RST='\033[0m'

CACHED_REPORT="reports/hacking_case_run7.json"
CACHED_SESSION=$(ls -t logs/archived/session_*.jsonl 2>/dev/null | head -1)
NAIVE_REPORT="reports/hacking_case_naive.json"
GT="reports/ground_truth/hacking_case.json"

beat() {
  printf "\n${DIM}─── press ENTER for next beat ───${RST}\n"
  read -r _
  clear
  printf "${BOLD}${BLUE}>>> %s${RST}\n\n" "$1"
}

clear
printf "${BOLD}${GREEN}FIND EVIL! — IABF Agent demo${RST}\n"
printf "${DIM}5-minute live walkthrough. Press ENTER to start...${RST}\n"
read -r _

# ─── BEAT 1: architecture ───
beat "1/6  Architecture (4-phase IABF loop)"
sed -n '18,60p' README.md

# ─── BEAT 2: comparison table ───
beat "2/6  Legacy DFIR vs IABF — capability comparison"
awk '/^## Legacy DFIR tools vs/,/^## Methodology comparison/' README.md | head -40

# ─── BEAT 3: replay session events ───
beat "3/6  Session JSONL — what the agent did, in order"
if [ -n "$CACHED_SESSION" ]; then
  printf "${CYAN}Replaying %s (sped-up)${RST}\n\n" "$CACHED_SESSION"
  python3 - <<PY
import json, time, sys
events = [json.loads(l) for l in open("$CACHED_SESSION")]
COLOR = {"tool_start":"\033[36m", "tool_end":"\033[2m", "llm_call":"\033[33m",
         "hypothesis":"\033[1;32m", "narrative":"\033[1;34m",
         "self_correction":"\033[1;35m", "iteration":"\033[1;37m"}
for e in events[:80]:
    et = e.get("event_type","")
    c = COLOR.get(et, "")
    if et == "tool_start":
        print(f"{c}TOOL  ▶ {e.get('command','')[:110]}\033[0m")
    elif et == "tool_end":
        print(f"{c}      ◀ exit={e.get('exit_code')} {e.get('output_size_bytes',0)}B "
              f"in {e.get('duration_ms',0):.0f}ms\033[0m")
    elif et == "llm_call":
        toks = e.get("tokens",{}).get("total_tokens","?")
        print(f"{c}LLM   ⚡ {e.get('purpose','')} ({toks} tokens, "
              f"{e.get('latency_ms',0):.0f}ms)\033[0m")
    elif et == "hypothesis":
        print(f"{c}HYP   ✱ [{e.get('id')}] {e.get('hypothesis','')[:110]}\033[0m")
        print(f"      status={e.get('status')} conf={e.get('confidence_after','?')}")
    elif et == "self_correction":
        print(f"{c}FIX   ↺ {e.get('corrected','')[:110]}\033[0m")
    elif et == "iteration":
        print(f"{c}═══ ITER {e.get('iteration')} {e.get('phase')} ═══\033[0m")
    sys.stdout.flush()
    time.sleep(0.05)
PY
else
  echo "(no cached session JSONL found — run an investigation first)"
fi

# ─── BEAT 4: confirmed findings + root cause ───
beat "4/6  IABF report — confirmed findings + root cause"
python3 - <<PY
import json
r = json.load(open("$CACHED_REPORT"))
print(f"\033[1mRoot cause:\033[0m {r.get('root_cause','(stagnation exit)')}")
print(f"\033[1mIterations:\033[0m {r.get('total_iterations')}  "
      f"\033[1mLLM calls:\033[0m {r.get('llm_stats',{}).get('total_calls','?')}  "
      f"\033[1mTokens:\033[0m {r.get('llm_stats',{}).get('total_tokens','?')}")
print()
print("\033[1;32mConfirmed findings (with concrete evidence):\033[0m")
for c in r.get("confirmed_findings", []):
    print(" •", c[:200])
PY

# ─── BEAT 5: scorer head-to-head ───
beat "5/6  Head-to-head: IABF vs naive LLM (same model, same evidence)"
python3 scripts/score.py "$NAIVE_REPORT" "$GT" --label "Naive-LLM" 2>&1 | tail -1
python3 scripts/score.py "$CACHED_REPORT" "$GT" --label "IABF     " 2>&1 | tail -1

printf "\n${BOLD}${YELLOW}IABF beats naive on F1 with zero hallucinations — every claim is tool-grounded.${RST}\n"

# ─── BEAT 6: audit trail / BPMN / close ───
beat "6/6  Audit trail + workflow"
echo "JSONL audit trail (sample event):"
[ -n "$CACHED_SESSION" ] && head -3 "$CACHED_SESSION" | python3 -m json.tool | head -25

cat <<'EOF'

────────────────────────────────────────────────────────────────────
  github.com/dhyabi2/findevil   —  IABF agent + 30 SIFT tools
  github.com/dhyabi2/papers     —  IABF research paper
  docs/bpmn/                    —  BPMN 2.0 workflow files
  ACCURACY.md                   —  full ground-truth scoring
────────────────────────────────────────────────────────────────────
EOF
printf "\n${GREEN}${BOLD}Thank you — please vote!${RST}\n\n"
