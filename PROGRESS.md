# FIND EVIL! — Progress Kanban

> **Persistent progress tracker.** Survives reboots. Update as tasks move columns.
> **Deadline:** 2026-06-15 | **Today:** 2026-04-15 | **Machine:** SANS SIFT (hackathon workstation)

---

## Strategy (why this order)

Paper's core claim = "IABF reduces hallucinations vs. blind scanning."
We have the numbers: **IABF F1 = 32.4 % vs naive LLM 27.8 %, with 100 % precision and zero hallucinations** on the NIST Hacking Case. Now closing the gap to a polished hackathon submission.

---

## 📋 BACKLOG (post-submission polish)

- [ ] **B2** — 2nd dataset cross-validation (Digital Corpora or Volatility memory sample)
- [ ] **B4** — Verify ARCHITECTURE.md / DEPLOYMENT.md are current (light audit done; deeper pass deferred)
- [ ] **B11** — Streaming LLM responses (perf #3 from 10-issue analysis)
- [ ] **B12** — Anthropic prompt-caching support for cache_control (perf #2)
- [ ] **B13** — Hindsight / ESEDB tool wrappers for browser history
- [ ] **B14** — Adversarial robustness test (prompt injection from evidence content)

---

## 🎯 NEXT UP (submission-blocking)

- [x] **S1** — Run8 scored: F1 21.6 % / precision 66.7 % — worse than run7 (stagnation at iter 6, only 3 confirmed). ACCURACY.md kept at run7 numbers.
- [x] **S2** — Pushed to https://github.com/dhyabi2/findevil (2026-04-15)
- [x] **S3** — Tagged `v1.0` and pushed (2026-04-15)
- [ ] **S4** — Record 5-min video using `docs/video/` kit
- [ ] **S5** — Submit to Devpost using `docs/devpost/SUBMISSION.md` copy

---

## 🔨 IN PROGRESS

_(nothing in flight)_

---

## ✅ DONE

### Code & methodology
- [x] Core IABF 4-phase loop (`agent/iabf.py`)
- [x] LLM client with OpenRouter default (`agent/llm_client.py`)
- [x] Structured audit trail with thread-safe RLock (`agent/audit.py`)
- [x] MCP server with 30+ forensic tools (`mcp_server/server.py`)
- [x] Architectural guardrails (`mcp_server/guardrails.py`)
- [x] **Parallel Phase 3** (ThreadPoolExecutor, 3 workers) — ~3× speedup
- [x] **MFT name index cached** per image SHA-256 — eliminates repeated fls walks
- [x] **Auto-upgrade verdict** on rich evidence_for — fixes LLM over-cautiousness
- [x] **Stagnation early-exit** after 3 barren iterations
- [x] **Auto-confirm probe facts** at session init (SHA-256, NTFS, OS from MBR)
- [x] **Pinned iter-1 narrative** to system prompt
- [x] Playbook expansion for mIRC, Outlook Express, browser history, recycle bin, AV
- [x] 54/54 unit tests pass

### Validation
- [x] Naive-LLM baseline + scorer (`scripts/score.py`, `scripts/naive_baseline.py`)
- [x] Strict scorer with word-boundary matching + atomic claim splitting
- [x] NIST Hacking Case ground truth (31 questions)
- [x] **ACCURACY.md populated** with real numbers — IABF F1 32.4 % vs naive 27.8 %

### Docs
- [x] README — capability comparison table (12 rows)
- [x] README — methodology comparison table (11 rows)
- [x] BPMN 2.0 workflow files (IABF + legacy) in `docs/bpmn/`
- [x] Video kit in `docs/video/` — storyboard, OBS scene, recording recipe, README
- [x] Devpost submission copy in `docs/devpost/SUBMISSION.md`
- [x] CI workflow in `.github/workflows/test.yml`

### Repo
- [x] `git init` + initial commit, perf merge, 10-fix merge, 10-fix-v2 merge
- [x] `.env.example`, `.gitignore` (no E01/.env leaks)
- [x] Remote `origin` set to `https://github.com/dhyabi2/findevil.git`

---

## 🚫 BLOCKED / RISKS

- **S2 (push)** — needs user's GitHub token; agent cannot push without auth
- **S4 (video)** — needs user to record; agent cannot operate webcam/mic

---

## 📝 SESSION LOG

- **2026-04-15** — Final session. Added video kit, Devpost copy, CI workflow. Run8 in flight with auto-upgrade firing. PROGRESS.md refreshed for handoff.
- **2026-04-15** — 10 quality fixes v2: scorer word-boundary + atom-split; agent auto-upgrade, stagnation=3, probe-fact auto-confirm, lower confidence_threshold, pinned narrative, playbook expansion. Run7 score: F1 32.4 %, precision 100 %, 0 hallucinations.
- **2026-04-15** — Perf branch merged: parallel Phase 3 (3× speedup), MFT index cache, retry tightening. 10 quality fixes (run5/6 stagnation analysis): MFT explicit greps, stagnation early-exit, scratch dir pre-create, concrete evidence in confirmed_findings, Phase 2 pivot prompt, NTFS inode resolution, conv-trim 12, Phase 4 tactic-change requirement, auto-mkdir, pre-pass reinforcement.
- **2026-04-14** — Cleared logs/reports. Diagnosed 10 critical bugs from run1/run2 logs; fixed all. Hacking Case acquired and verified.
- **2026-04-14** — Created PROGRESS.md kanban. Audited repo: code built, validation missing.

---

## 🔄 HOW TO USE THIS FILE

1. **Start of session:** read top-to-bottom, pick from 🎯 NEXT UP.
2. **When starting a task:** move it to 🔨 IN PROGRESS.
3. **When done:** `[x]` check it and move to ✅ DONE with a short outcome.
4. **New idea:** add to 📋 BACKLOG, don't interrupt current work.
5. **Hit a wall:** move to 🚫 BLOCKED with date + reason.
6. **End of session:** add one line to 📝 SESSION LOG.
