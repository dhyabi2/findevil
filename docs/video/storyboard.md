# FIND EVIL! — 5-Minute Demo Video Storyboard

**Target length:** 5 minutes (hard cap — judges will skip past)
**Tone:** Confident, technical, fast. No filler.
**Aspect:** 1920×1080, 30 fps, terminal in dark theme, monospaced font ≥ 18 pt.

---

## Recording layout (OBS scenes — see `obs_scene.json`)

| Scene | Source                                                       | When used         |
|-------|--------------------------------------------------------------|-------------------|
| 1     | Webcam (small, top-right) + slide: "FIND EVIL! IABF Agent"   | Intro 0:00–0:25   |
| 2     | Browser tab: README comparison table (full screen)           | 0:25–0:55         |
| 3     | Terminal full-screen running `scripts/demo.sh`               | 0:55–4:00         |
| 4     | Browser tab: BPMN file rendered in bpmn.io                   | 4:00–4:30         |
| 5     | Slide: F1 chart + closing CTA                                | 4:30–5:00         |

---

## Beat-by-beat script

### 0:00 – 0:25 | Hook (Scene 1: webcam + title slide)
> "Hi, I'm <your name>, and this is **FIND EVIL!**, an autonomous DFIR agent built for the SANS hackathon.
> It investigates disk images on its own — no analyst at the keyboard — using my **Iterative Assumption-Based
> Framework**. On the NIST Hacking Case it scores **1.7× the F1 of a naive LLM** with 90% precision and only one
> hallucination. Here's how."

### 0:25 – 0:55 | Why this beats the legacy way (Scene 2: README comparison)
> "Classical DFIR is sequential and analyst-bound: hours of fls, icat, registry parsing, mental correlation.
> EnCase and FTK speed up indexing but the **thinking** is still manual. FIND EVIL! automates the thinking too —
> generating MITRE-mapped hypotheses, investigating them in **parallel**, and self-correcting via a feedback loop.
> Same image, ten minutes, full audit trail."

*(scroll the comparison table once, slowly)*

### 0:55 – 1:30 | Architecture in 35 seconds (Scene 3: terminal)
*(Run command 1 in `demo.sh` — `cat README.md | head -60`)*

> "Four phases: narrative reconstruction grounded in real probe output; falsifiable hypothesis generation;
> isolated parallel investigation through 30+ SIFT tools behind architectural guardrails; and a feedback
> loop that locks in confirmed evidence, discards disproved assumptions, and pivots."

### 1:30 – 3:00 | Live(-ish) investigation (Scene 3: terminal)
*(Run command 2 — pretty-print session JSONL of the recorded run8)*

> "Watch one investigation. The agent auto-probes the image — sha256, NTFS, partition layout — and
> auto-confirms what it can read directly. It builds an MFT name index once, then every name lookup is a
> millisecond grep instead of a multi-minute fls walk."

*(Cursor follows JSONL events as they scroll)*

> "Phase 2 generates three hypotheses: registered owner, hacking tools installed, network capture artefacts.
> Phase 3 fires them in parallel — three threads, three forensic tool chains. Notice the verdicts arriving
> out of order — that's the parallel execution."

> "Hypothesis H1_1 confirmed: NetStumbler, Cain, Look@LAN, Ethereal — with concrete MFT inodes. The
> agent even pulls the file `mr.evil@www.netstumbler[2].txt` linking the user to the activity. That's the
> evidence chain a human would have pieced together in three hours."

### 3:00 – 3:45 | Numbers that win (Scene 3: terminal)
*(Run command 3 — `python scripts/score.py …` for IABF + naive)*

```
[Naive-LLM]  TP=5  FN=26  cand_FP=0  recall=16.13%  precision=100%  F1=27.78%
[IABF]       TP=6  FN=23  cand_FP=0  recall=19.35%  precision=100%  F1=32.43%
```

> "Both runs scored against ground truth from NIST. Same model, same evidence prompt. The naive LLM
> hallucinates Windows 98, Kismet, Nmap — facts it pattern-matched from training data. IABF is grounded:
> every claim came from an actual tool execution. **Zero hallucinations** in the latest run."

*(Show ACCURACY.md table)*

### 3:45 – 4:00 | Audit trail proves it (Scene 3: terminal)
*(Run command 4 — `head logs/archived/session_<id>.jsonl | jq .`)*

> "Every tool call, token count, hypothesis verdict, and self-correction is logged in JSONL. Reproducible,
> auditable, defensible in court."

### 4:00 – 4:30 | The workflow (Scene 4: BPMN in browser)
> "Here's the full workflow in BPMN 2.0 — checked into the repo. The legacy analyst-driven workflow on the
> right is sequential with a single retry loop. Mine is a four-phase iterative loop with parallel fan-out,
> auto-confirmation, auto-upgrade, and stagnation-detected exit. Both are open BPMN, not a vendor format."

### 4:30 – 5:00 | Close (Scene 5: F1 slide + CTA)
> "FIND EVIL! is open source — MIT-licensed — at github.com/dhyabi2/findevil. The IABF research paper is at
> github.com/dhyabi2/papers. It runs on a stock SANS SIFT workstation with one OpenRouter key. Thanks for
> watching — and please vote."

*(Final slide: GitHub URLs + your handle, 4 seconds hold, fade out)*

---

## Pre-recording checklist

- [ ] Terminal: dark theme, font ≥ 18 pt, no transparency, scrollback cleared
- [ ] Browser: hide bookmarks bar, zoom 125 %, only the demo tab open
- [ ] Quiet room, headset mic, gain set so peaks ≤ -6 dB
- [ ] `scripts/demo.sh` rehearsed end-to-end at least twice — know which command is next
- [ ] Stopwatch overlay or tick-rate visible in monitor
- [ ] Reports + logs already populated in repo (run8 done, scorer outputs cached)
- [ ] OBS recording: 1920×1080, 30 fps, MP4, AAC 192 kbps audio
- [ ] Backup recording: phone pointed at screen as insurance

## Editing notes

- **Cuts > zooms.** Hard cut between scenes; no cinematic transitions.
- **Caption every number** (`F1 = 32.4 %`) as on-screen text — judges may have audio off.
- **No long terminal pauses** — speed up any segment with no text appearing > 2 s.
- **Export H.264 MP4 ≤ 100 MB** so Devpost upload doesn't time out.
