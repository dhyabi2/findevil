#!/usr/bin/env python3
"""Naive LLM baseline — single-shot prompt, no IABF loop, no tools.

Gives the LLM the same evidence description and lets it answer blindly.
This is the control to prove IABF's advantage for the paper.

Usage:
    python scripts/naive_baseline.py \
        --evidence "NIST Hacking Case ..." \
        --out reports/hacking_case_naive.json
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.llm_client import LLMClient, LLMConfig
import yaml


PROMPT = """You are a DFIR analyst. Answer the following investigation based ONLY on your prior knowledge of the case described — you have NO tools, NO disk access, NO tool output.

Evidence description:
{evidence}

Produce a JSON object with keys:
  "root_cause": short string
  "confirmed_findings": list of concrete findings (owner, tools, IPs, emails, IRC nicks, OS, dates, etc.)
  "final_narrative": full prose narrative of what happened

Output ONLY the JSON object, no prose around it."""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.is_absolute():
        cfg_path = Path(__file__).resolve().parent.parent / cfg_path
    cfg = yaml.safe_load(cfg_path.read_text())
    llm = LLMClient(LLMConfig.from_yaml(cfg))

    t0 = time.time()
    resp = llm.chat(
        messages=[{"role": "user", "content": PROMPT.format(evidence=args.evidence)}],
        system="You are a DFIR analyst producing structured JSON.",
    )
    dur = time.time() - t0

    text = resp.content
    try:
        start = text.index("{")
        end = text.rindex("}") + 1
        data = json.loads(text[start:end])
    except Exception as e:
        data = {"root_cause": "", "confirmed_findings": [], "final_narrative": text,
                "_parse_error": str(e)}

    data["_baseline"] = "naive_single_shot"
    data["_duration_s"] = round(dur, 2)
    data["_tokens"] = resp.usage
    data["total_iterations"] = 0
    total_toks = resp.usage.get("total_tokens", 0) if resp.usage else 0
    data["llm_stats"] = {"total_calls": 1, "total_tokens": total_toks}

    Path(args.out).write_text(json.dumps(data, indent=2))
    print(f"Saved: {args.out}  ({dur:.1f}s, {total_toks} tokens)")


if __name__ == "__main__":
    main()
