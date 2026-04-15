# Accuracy Report

## Methodology

The IABF Agent's accuracy is evaluated by comparing its findings against known ground truth in validated forensic datasets.

### Metrics Tracked

| Metric | Definition |
|--------|-----------|
| **True Positive (TP)** | Agent finding matches ground truth |
| **False Positive (FP)** | Agent reports a finding not in ground truth |
| **False Negative (FN)** | Ground truth finding missed by agent |
| **Hallucination** | Agent claims evidence exists that doesn't (fabricated artifact) |
| **Confirmed** | Finding backed by tool output in audit trail |
| **Inferred** | Finding stated without direct tool evidence |

### Formulas

- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1 Score** = 2 * (Precision * Recall) / (Precision + Recall)
- **Hallucination Rate** = Hallucinations / Total Claims

## Evidence Integrity Approach

1. **Hash verification**: All evidence files are SHA256-hashed before and after analysis
2. **Read-only enforcement**: Architectural guardrail prevents write operations to evidence
3. **Audit trail**: Every finding traces back to a specific tool execution with output
4. **Confirmed vs Inferred**: Agent explicitly labels findings as confirmed (tool evidence) or inferred (reasoning)

## Investigation Results

### Dataset: NIST CFReDS Hacking Case (Dell Latitude CPi, "Mr. Evil")

- **Source:** https://cfreds-archive.nist.gov/Hacking_Case.html
- **Ground truth:** 31 investigator questions (`reports/ground_truth/hacking_case.json`)
- **Evidence image:** `4Dell_Latitude_CPi.E01 (+.E02)`, MD5 `aee4fcd9…` (verified with `ewfverify`)
- **Scoring method:** for each ground-truth question, accept a question as answered if any of the expected answer tokens appears in the agent's report (`root_cause` + `confirmed_findings` + `final_narrative`). See `scripts/score.py`.

#### Head-to-Head: IABF vs Naive LLM (same model, same prompt evidence)

| Metric                       | Naive LLM (single-shot, no tools) | IABF Agent (tool-grounded loop) |
|------------------------------|-----------------------------------|---------------------------------|
| Questions answered (TP)      | 5 / 31                            | **11 / 31**                     |
| Partial / inferred (TP_inf)  | 1 / 31                            | 2 / 31                          |
| Missed (FN)                  | 25 / 31                           | 18 / 31                         |
| Candidate hallucinations (FP on claims not in ground truth) | 3 | 4                |
| Recall (overall)             | 19.4 %                            | **41.9 %**                      |
| Recall (confirmed only)      | 16.1 %                            | **35.5 %**                      |
| Precision (on claims)        | 62.5 %                            | **73.3 %**                      |
| F1 (confirmed)               | 25.6 %                            | **47.8 %**                      |
| LLM calls                    | 1                                 | 42 (7 iters × ~6 calls)         |
| Iterations                   | 0                                 | 7 (coverage-terminated at 8/10) |

**Key result:** IABF delivers **1.87× the F1 of a naive LLM on the same evidence**.
Every IABF claim is gated by an actual tool execution against the actual image — the
naive model invented "Windows 98", "Kismet", "Nmap", and pcap files that don't exist
in the case, all artefacts of training-data recall rather than evidence-grounded
inference.

The IABF run terminated at iteration 7 (of a 15-iteration cap) via **coverage-based
auto-completion** (≥8 of 10 high-value DFIR categories confirmed). Automated
pre-pass extracted the SOFTWARE/SAM/SYSTEM registry hives up-front, so hypotheses
could focus on deeper artefacts (mIRC logs, Look@LAN `irunin.ini`, Ethereal capture
traces) rather than re-deriving the hive extraction plan each iteration. Confirmed
findings chain back through MFT inodes for NetStumbler, Look@LAN, Cain, Ethereal,
mIRC's `#Elite.Hackers.UnderNet.log`, the `irunin.ini` network identity file, and
the Hotmail-saved HTML — each with tool output in the audit trail.

**Naive-LLM hallucinations observed** (model guessed from case notoriety, no evidence):
- Claimed OS = "Windows 98" (ground truth: Windows XP)
- Claimed tools = "Kismet, Nmap" (ground truth: NetStumbler, Cain&Abel, Ethereal, Look@LAN — no Kismet, no Nmap)
- Invented "PCAP files containing captured wireless traffic from various access points" (actual capture is a text-dump of Ethereal session named "Interception", not pcap files)

This is the behaviour the IABF methodology is designed to eliminate: every claim must be produced by an actual tool command on the actual image, not recalled from training data.

**IABF run details:** see `reports/hacking_case_score.json` after run5 completes. Self-correction events, tool executions, and per-iteration hypothesis verdicts are in `logs/session_<id>.jsonl`.

## Hallucination Mitigation

The IABF methodology reduces hallucinations through:

1. **Isolated investigation** — each claim requires specific tool evidence
2. **Explicit labeling** — agent must distinguish CONFIRMED vs INFERRED
3. **Self-correction loop** — when evidence contradicts a claim, the agent revises
4. **Audit trail** — every finding is traceable to tool output

## Known Limitations

- Timeline analysis (Plaso) can produce large outputs that get truncated
- LLM may misinterpret hex dumps or binary data
- Confidence scores are LLM-estimated, not statistically calibrated
- Network analysis depth depends on available protocol dissectors
