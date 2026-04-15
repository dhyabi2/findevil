# FIND EVIL! — Progress Kanban

> **Persistent progress tracker.** Survives reboots. Update as tasks move columns.
> **Deadline:** 2026-06-15 | **Today:** 2026-04-14 | **Machine:** SANS SIFT (hackathon workstation)

---

## Strategy (why this order)

Paper's core claim = "IABF reduces hallucinations vs. blind scanning."
To win, we need **numbers proving it**. Code is built; validation isn't. Everything below is ordered to produce that proof fastest.

---

## 📋 BACKLOG

- [ ] **B1** — Record demo video (5 min) showing self-correction loop on Hacking Case
- [ ] **B2** — Add 2nd dataset (Digital Corpora or Volatility sample) for cross-validation
- [ ] **B3** — Write Devpost submission copy (elevator pitch, architecture diagram)
- [ ] **B4** — Verify `ARCHITECTURE.md` and `DEPLOYMENT.md` match current code
- [ ] **B5** — Populate `mcp_server/tools/` or document that inlining in `server.py` is intentional
- [ ] **B6** — Document `.env` / `OPENROUTER_API_KEY` setup for reproducibility in README
- [ ] **B7** — Run baseline "naive LLM (no IABF)" on same dataset → comparison table for paper
- [ ] **B8** — Add pytest CI config + `make test` target
- [ ] **B9** — Tag v1.0 release on GitHub for Devpost submission

---

## 🎯 NEXT UP (this session)


- [ ] **N2** — SHA256 hash the image, record in `DATASETS.md`
- [ ] **N3** — Run `python main.py investigate` end-to-end against Hacking Case
- [ ] **N4** — Capture full session JSONL + investigation JSON for audit trail
- [ ] **N5** — Score agent findings vs `reports/ground_truth/hacking_case.json`
- [ ] **N6** — Fill `ACCURACY.md` with real TP / FP / FN / Hallucination / Precision / Recall / F1
- [ ] **N7** — `git init`, commit, push to `github.com/dhyabi2/findevil`

---

## 🔨 IN PROGRESS

- [ ] **N3** — Run `python main.py investigate` end-to-end against Hacking Case _(run1+run2 surfaced 10 bugs, all fixed; ready for run3)_

---

## ✅ DONE

- [x] Core IABF 4-phase loop implemented (`agent/iabf.py`, 691 lines)
- [x] LLM client with OpenRouter default (`agent/llm_client.py`)
- [x] Structured audit trail (`agent/audit.py`)
- [x] MCP server with 30+ forensic tools (`mcp_server/server.py`)
- [x] Architectural guardrails (command blocklist, binary whitelist, path boundaries) (`mcp_server/guardrails.py`)
- [x] Unit tests: audit, guardrails, llm_client, iabf_phases
- [x] `config.yaml`, `requirements.txt`, `pyproject.toml`, `main.py` CLI
- [x] README.md, ARCHITECTURE.md, DATASETS.md (template), ACCURACY.md (template), DEPLOYMENT.md
- [x] Ground-truth JSON prepared for Hacking Case (`reports/ground_truth/hacking_case.json`)
- [x] **N1** Acquired NIST Hacking Case E01+E02 → `datasets/hacking_case/` (1.04 GB)
- [x] **N2** SHA256 hashed + MD5 verified via `ewfinfo` — embedded MD5 matches ground truth. Documented in `DATASETS.md`.
- [x] `deploy/install.sh` automated setup script
- [x] Research paper published on GitHub (`github.com/dhyabi2/papers`)

---

## 🚫 BLOCKED / RISKS

_(none yet — log blockers here with date + reason)_

---

## 📝 SESSION LOG

_One line per session. Newest first._

- **2026-04-14** — Cleared all prior logs/reports/scratch (runs 1-4). Model switched to `google/gemma-4-31b-it`. Launched clean single run → `reports/hacking_case_final.json`.
- **2026-04-14** — Diagnosed 10 critical bugs from run1/run2 logs; fixed all: (1) broken default model `gemma-4-27b-it` → `gemma-3-27b-it`; (2) byte-vs-sector offset in system prompt; (3) hash hallucination (prompt now templated with real sha256); (4) empty-output → "inconclusive" override in phase3; (5) Windows dead-disk playbook injected; (6) auto bulk_extractor pre-pass before iter-1; (7) `/cases/` hardcoded path removed, real paths templated; (8) `_conversation` trimmed to 8 turns; (9) confidence threshold 0.85→0.75; (10) mmls-derived sector offset propagated into system prompt. All 54 tests pass.
- **2026-04-14** — N1+N2 complete: Hacking Case E01/E02 acquired (1.04GB), MD5 `aee4fcd9…` verified by ewfverify. First investigate run (raw E01) failed — sleuthkit on SIFT not libewf-enabled. Mounted via `ewfmount` → `/tmp/findevil/ewf/ewf1` (NTFS @ sector 63). Rerun in progress (run2).
- **2026-04-14** — Created PROGRESS.md kanban. Audited repo: code built, validation missing. Next = acquire Hacking Case image.

---

## 🔄 HOW TO USE THIS FILE

1. **Start of session:** read top-to-bottom, pick from 🎯 NEXT UP.
2. **When starting a task:** move it to 🔨 IN PROGRESS.
3. **When done:** `[x]` check it and move to ✅ DONE with a short outcome.
4. **New idea:** add to 📋 BACKLOG, don't interrupt current work.
5. **Hit a wall:** move to 🚫 BLOCKED with date + reason.
6. **End of session:** add one line to 📝 SESSION LOG.
