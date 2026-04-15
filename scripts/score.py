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


# Tokens that are too generic to count as a substring match (would TP-trigger
# anywhere). Numerics <= 2 chars and very short common words get word-boundary
# matching against the original text rather than the normalized blob.
_GENERIC_SHORT = {"yes", "no", "n/a", "0", "1", "2", "3", "4", "5", "6", "7",
                  "8", "9", "10", "11", "12", "evil", "cdt"}


def _strict_match(answer: str, full_text: str) -> bool:
    """Word-boundary match for short/generic answers; substring for the rest."""
    a = answer.strip()
    if not a:
        return False
    if a.lower() in _GENERIC_SHORT or len(a) <= 3:
        # Require word-boundary match to avoid "5" matching "5294" or "Evil"
        # matching "evilfork".
        pattern = r"\b" + re.escape(a) + r"\b"
        return re.search(pattern, full_text, flags=re.IGNORECASE) is not None
    return normalize(a) in normalize(full_text)


def _split_claims(claims: list[str]) -> list[str]:
    """Split blob-style confirmed_findings into atomic claims for FP analysis.

    Splits on em-dashes, semicolons, and sentence-end punctuation — but only
    when followed by whitespace AND not inside a quoted/bracketed token. Fix #6:
    run8 produced artefact FPs like "evil@www.netstumbler[2].txt' (inode
    11981), directly linking the alias 'Mr." because atom-split cut mid-quote.
    """
    atoms: list[str] = []
    for c in claims:
        # Mask single-quoted and double-quoted substrings, and bracketed tokens,
        # so punctuation inside them can't be used as split boundaries.
        masked = c
        preserved: list[str] = []

        def _mask(m):
            preserved.append(m.group(0))
            return f"\x00{len(preserved) - 1}\x00"
        masked = re.sub(r"'[^']{1,120}'|\"[^\"]{1,120}\"|\[[^\]]{1,40}\]", _mask, masked)

        parts = re.split(r"\s+—\s+|;\s+|(?<=[.!?])\s+(?=[A-Z])", masked)
        # Unmask each part
        def _unmask(s: str) -> str:
            return re.sub(r"\x00(\d+)\x00", lambda m: preserved[int(m.group(1))], s)
        for p in parts:
            p = _unmask(p).strip().rstrip(".,;:")
            if len(p) > 8:
                atoms.append(p)
    return atoms


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
    hit_confirmed = any(_strict_match(str(a), confirmed_hay) for a in expected if str(a).strip())
    hit_any = any(_strict_match(str(a), full_hay) for a in expected if str(a).strip())
    matched_token = next(
        (str(a) for a in expected if str(a).strip() and _strict_match(str(a), full_hay)),
        None,
    )
    if hit_confirmed:
        verdict = "TP"
    elif hit_any:
        verdict = "TP_inferred"
    else:
        verdict = "FN"
    return {"id": q["id"], "q": q["q"], "expected": expected,
            "verdict": verdict, "matched": matched_token}


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
    claims_text = [_flat(c) for c in claims_raw]
    atomic_claims = _split_claims(claims_text)
    fp_candidates = []
    gt_blob = json.dumps(gt)  # raw, for word-boundary matching
    for atom in atomic_claims:
        # An atom is a hallucination only if NONE of its meaningful tokens
        # appear in ground truth. Single-word generic claims get strict match.
        # Skip atoms that already substring-match ground truth (legit claim).
        if normalize(atom) and normalize(atom) in normalize(gt_blob):
            continue
        # Also skip if any noun-ish token (>=4 chars) of the atom is in GT blob
        tokens = [t for t in re.findall(r"[A-Za-z0-9_.@-]{4,}", atom)]
        if any(re.search(r"\b" + re.escape(t) + r"\b", gt_blob, re.IGNORECASE) for t in tokens):
            continue
        fp_candidates.append(atom)

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
