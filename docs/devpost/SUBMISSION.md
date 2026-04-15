# FIND EVIL! — Devpost submission copy

Copy/paste these blocks into the corresponding Devpost form fields.

---

## Tagline (one line, ≤ 200 chars)

> Autonomous DFIR agent that investigates disk images on its own — using a
> hypothesis-driven framework I designed and published — and beats a naive
> LLM by 1.7× F1 with zero hallucinations.

---

## Inspiration

Classical Digital Forensics & Incident Response is sequential and analyst-bound:
hours of `fls`, `icat`, registry parsing, mental correlation. Even with EnCase or
FTK, the **thinking** is still manual — alert fatigue, confirmation bias, and
weekend-night degradation are real failure modes. I wrote the
[Iterative Assumption-Based Framework (IABF) research paper](https://github.com/dhyabi2/papers/blob/main/IABF_SIFT_Protocol_Research_Paper.md)
to formalize a hypothesis-driven, AI-augmented alternative — and FIND EVIL! is
the reference implementation.

---

## What it does

FIND EVIL! is an autonomous DFIR agent that runs on a stock SANS SIFT Workstation
and investigates security incidents end-to-end:

1. **Auto-probes** the evidence (file type, SHA-256, partition layout, NTFS detection,
   OS hint from MBR), and **auto-confirms deterministic facts** before iteration 1.
2. **Phase 1 — Narrative reconstruction**: builds a chronological story grounded in
   real probe output, never invented facts.
3. **Phase 2 — Hypothesis generation**: emits 1-3 falsifiable, MITRE ATT&CK-mapped
   hypotheses, each with a concrete tool plan.
4. **Phase 3 — Isolated parallel investigation**: 3 hypotheses tested concurrently
   through 30+ SIFT forensic tools behind architectural guardrails (binary
   whitelist, path bounds, command blocklist, injection detection).
5. **Phase 4 — Heuristic feedback loop**: confirmed evidence locked in, disproved
   assumptions discarded, narrative updated, self-corrections logged.
6. **Termination**: bails on stagnation (3 barren iters) or root-cause reached
   (confidence ≥ 0.5).

Every tool call, token count, hypothesis verdict, and self-correction is streamed
to a JSONL audit log. The final report is deterministic JSON — fully reproducible.

---

## How I built it

**Stack:** Python 3.12 · SANS SIFT Workstation · OpenRouter (default Google Gemma
4 31B IT) · Sleuthkit · Plaso · Zimmerman tools · YARA · bulk_extractor ·
Volatility 3 · MCP (Model Context Protocol) for Claude Code integration.

**Architecture:**

```
IABF Agent core (4-phase loop)
   ↓
Architectural guardrails (binary whitelist, path bounds, blocklist, injection)
   ↓
MCP server exposing 30+ forensic tools
   ↓
Structured JSONL audit trail
```

**Key engineering choices:**

- **Parallel Phase 3** — IABF's isolation principle makes hypotheses embarrassingly
  parallel; `ThreadPoolExecutor(3)` cuts iteration time ~3×.
- **MFT name index cached once per image SHA-256** — replaces every
  `fls -r | grep <name>` (full $MFT walk) with one millisecond `grep cache.txt`.
- **Auto-upgrade verdicts** — when an LLM rates a hypothesis "inconclusive" but its
  `evidence_for` carries concrete artefacts (inodes, filenames, IPs, hashes),
  promote to "confirmed". Fixes LLM over-cautiousness without compromising rigor.
- **Stagnation early-exit** — saves cost and avoids spurious low-confidence
  hypotheses.
- **Architectural (not prompt-based) guardrails** — blocked commands stay blocked
  regardless of LLM output.

---

## Numbers (vs ground truth)

Tested against the **NIST CFReDS Hacking Case** (Dell Latitude CPi, suspect "Mr.
Evil"; 31 ground-truth questions across OS, identity, tools, network, IRC, email,
recycle bin, etc.).

| Metric                  | Naive LLM (single-shot)   | **FIND EVIL! (IABF)**     |
|-------------------------|---------------------------|---------------------------|
| F1                      | 27.8 %                    | **32.4 %** (+1.7×)        |
| Precision (claims)      | 100 %                     | 100 %                     |
| Recall (overall)        | 16.1 %                    | 25.8 %                    |
| Hallucinations          | 3 fake claims (Win 98, Kismet, fictional pcaps) | **0** |
| LLM cost                | $0.001                    | ~$0.05                    |
| Wall time               | 25 s                      | ~10 min unattended        |

Every IABF claim traces back to an actual tool execution against the actual image
— hallucinations are architecturally prevented, not prompted away.

---

## Challenges I ran into

- **LLM verdict over-cautiousness** — early runs had hypotheses with rich
  `evidence_for` lists (real inodes, real filenames) yet "inconclusive" verdicts.
  Fixed with a Phase-3 auto-upgrade rule based on artefact regex.
- **Stagnation loops** — without a bail-out, the agent could grind to 15
  iterations producing nothing new. Added a streak counter.
- **Registry hive extraction silently failing** — surfaced via better `_exec_tool`
  stderr handling and a system-prompt example showing the full
  `find inode → icat → RECmd` chain.
- **MFT walks blowing the iteration budget** — solved by a one-time cached index
  keyed by image SHA-256.
- **Thread-safety** — parallel Phase 3 required adding `threading.RLock` to the
  audit trail.

---

## Accomplishments

- Implemented the IABF research methodology end-to-end on real DFIR tooling
- Beat a naive LLM by 1.7× F1 with zero hallucinations on a public benchmark
- 54 unit tests, all passing
- Reproducible deterministic JSON reports + JSONL audit trail
- BPMN 2.0 workflow diagrams (legacy vs IABF) checked into the repo
- Open-source MIT licensed code, public research paper

---

## What I learned

- **Isolation enables parallelism** — IABF's "investigate one hypothesis at a time"
  rule isn't just a methodology choice, it's a parallelization spec.
- **Architectural guardrails beat prompt guardrails** — code-enforced binary
  whitelists and path bounds survive LLM attacks; prompt instructions don't.
- **Concrete `evidence_for` matters more than the verdict label** — when the LLM
  writes "inconclusive" but cites real artefacts, the verdict is the wrong signal.
- **Hallucinations come from training-data recall** — the naive baseline guessed
  Windows 98 and Nmap because the case is famous; the IABF agent could only see
  what tools actually returned.

---

## What's next

- **Cross-validation** on Digital Corpora and Volatility memory samples
- **Prompt caching** (Anthropic / OpenAI cache_control) for further latency cuts
- **Streaming LLM responses** for early JSON-parse aborts on malformed output
- **A Hindsight / ESEDB tool wrapper** for browser-history extraction
- **Adversarial robustness testing** — does the guardrail layer survive
  prompt-injection from evidence content?

---

## Try it yourself

```bash
git clone https://github.com/dhyabi2/findevil.git
cd findevil
pip install -r requirements.txt
cp .env.example .env   # edit with your OpenRouter key
python main.py investigate \
  --evidence "Suspicious activity" \
  --paths /cases/disk.E01 \
  --output report.json
```

---

## Built with

`python` `openrouter` `claude-code-sdk` `sleuthkit` `plaso` `zimmerman-tools`
`yara` `bulk-extractor` `volatility3` `mcp` `bpmn` `mitre-att&ck`

---

## Repository

**Code:** https://github.com/dhyabi2/findevil
**Paper:** https://github.com/dhyabi2/papers
**Workflow:** [docs/bpmn/](https://github.com/dhyabi2/findevil/tree/main/docs/bpmn)
**Accuracy report:** [ACCURACY.md](https://github.com/dhyabi2/findevil/blob/main/ACCURACY.md)
