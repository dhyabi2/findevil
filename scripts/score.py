#!/usr/bin/env python3
"""Score an IABF investigation report against ground truth.

Usage:
    python scripts/score.py reports/hacking_case_final.json \
        reports/ground_truth/hacking_case.json \
        --out reports/hacking_case_score.json
"""
import argparse
import json
import re
import sys
from pathlib import Path


def normalize(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def _flat(x) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    if isinstance(x, (list, tuple)):
        return " ".join(_flat(i) for i in x)
    if isinstance(x, dict):
        return " ".join(_flat(v) for v in x.values())
    return str(x)


def haystack_from_report(report: dict) -> tuple[str, str]:
    parts = []
    parts.append(_flat(report.get("root_cause", "")))
    parts.append(_flat(report.get("confirmed_findings", [])))
    parts.append(_flat(report.get("final_narrative", "")))
    parts.append(_flat(report.get("hypotheses", [])))
    parts.append(_flat(report.get("findings", [])))
    confirmed_only = _flat(report.get("root_cause", "")) + "\n" + _flat(report.get("confirmed_findings", []))
    full = "\n".join(p for p in parts if p)
    return full, confirmed_only


def score_question(q: dict, full_hay: str, confirmed_hay: str) -> dict:
    expected = q["a"] if isinstance(q["a"], list) else [q["a"]]
    n_full = normalize(full_hay)
    n_conf = normalize(confirmed_hay)
    hit_confirmed = any(normalize(str(a)) in n_conf for a in expected if str(a).strip())
    hit_any = any(normalize(str(a)) in n_full for a in expected if str(a).strip())
    if hit_confirmed:
        verdict = "TP"
    elif hit_any:
        verdict = "TP_inferred"
    else:
        verdict = "FN"
    return {"id": q["id"], "q": q["q"], "expected": expected, "verdict": verdict}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("ground_truth")
    ap.add_argument("--out", default=None)
    ap.add_argument("--label", default="IABF")
    args = ap.parse_args()

    report = json.loads(Path(args.report).read_text())
    gt = json.loads(Path(args.ground_truth).read_text())

    full_hay, confirmed_hay = haystack_from_report(report)
    per_q = [score_question(q, full_hay, confirmed_hay) for q in gt["questions"]]

    tp = sum(1 for x in per_q if x["verdict"] == "TP")
    tp_inf = sum(1 for x in per_q if x["verdict"] == "TP_inferred")
    fn = sum(1 for x in per_q if x["verdict"] == "FN")
    total = len(per_q)

    claims_raw = report.get("confirmed_findings") or []
    claims = [_flat(c) for c in claims_raw]
    fp_candidates = []
    gt_blob = normalize(json.dumps(gt))
    for c in claims:
        if normalize(c) and normalize(c) not in gt_blob:
            fp_candidates.append(c)

    recall = (tp + tp_inf) / total if total else 0.0
    recall_confirmed = tp / total if total else 0.0
    precision_claims = tp / (tp + len(fp_candidates)) if (tp + len(fp_candidates)) else 0.0
    f1 = (2 * precision_claims * recall_confirmed / (precision_claims + recall_confirmed)
          if (precision_claims + recall_confirmed) else 0.0)

    out = {
        "label": args.label,
        "report": args.report,
        "ground_truth": args.ground_truth,
        "total_questions": total,
        "TP_confirmed": tp,
        "TP_inferred": tp_inf,
        "FN": fn,
        "candidate_FP": len(fp_candidates),
        "candidate_FP_items": fp_candidates,
        "recall_overall": round(recall, 3),
        "recall_confirmed_only": round(recall_confirmed, 3),
        "precision_on_claims": round(precision_claims, 3),
        "f1_confirmed": round(f1, 3),
        "per_question": per_q,
        "llm_stats": report.get("llm_stats", {}),
        "iterations": report.get("total_iterations"),
    }

    text = json.dumps(out, indent=2)
    if args.out:
        Path(args.out).write_text(text)
        print(f"Saved: {args.out}")
    print(f"[{args.label}] TP={tp} TP_inf={tp_inf} FN={fn} cand_FP={len(fp_candidates)} "
          f"recall_overall={recall:.2%} recall_confirmed={recall_confirmed:.2%} "
          f"precision={precision_claims:.2%} F1={f1:.2%}")


if __name__ == "__main__":
    sys.exit(main())
