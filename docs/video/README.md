# Demo video — requirements checklist

The hackathon expects a **5-minute video**. Everything you need to record one is
already in this directory; this README is the handoff so you can pick it up later.

## Hard requirements (Devpost rules)

- [ ] **Length:** ≤ 5 minutes (judges skip past 5:00)
- [ ] **Format:** MP4 (H.264 video, AAC audio)
- [ ] **Resolution:** 1920 × 1080 minimum, 30 fps
- [ ] **Size:** ≤ 100 MB for direct Devpost upload — otherwise host on YouTube unlisted and embed
- [ ] **Audio:** intelligible voice-over, peaks ≤ -6 dB
- [ ] **No music with copyright** — silence or royalty-free only

## Content requirements (judge expectations)

- [ ] **What it is** — name + one-line elevator pitch (in first 10 s)
- [ ] **Problem solved** — why classical DFIR is slow / error-prone
- [ ] **How it works** — IABF 4-phase loop, MITRE mapping, parallel investigation
- [ ] **Live demo** — agent actually doing the thing on real evidence
- [ ] **Numbers** — F1 = 32.4 %, precision = 100 %, 1.7× the F1 of naive LLM, zero hallucinations
- [ ] **Architecture / workflow** — show the BPMN or the README architecture diagram
- [ ] **Call to action** — GitHub URL, "please vote"

## Files in this directory (already prepared)

| File                 | What it is                                                          |
|----------------------|---------------------------------------------------------------------|
| `storyboard.md`      | Beat-by-beat script with timing + narration. Read first.            |
| `RECORDING.md`       | Step-by-step recording recipe (OBS install, slides, upload).        |
| `obs_scene.json`     | Importable OBS Studio scene collection — 5 scenes wired up.         |
| `slide_title.png`    | _Generate via the ImageMagick line in `RECORDING.md` step 2._       |
| `slide_close.png`    | _Generate via the ImageMagick line in `RECORDING.md` step 2._       |

The terminal demo runner is at `../../scripts/demo.sh` — paces 6 beats with ENTER
between them, replays cached session JSONL with color, prints scoring head-to-head.
Reads from `reports/hacking_case_run7.json` (already committed).

## To-do when you sit down to record

1. [ ] Install OBS Studio (Linux: `sudo apt install obs-studio`)
2. [ ] Generate the two slide PNGs — copy-paste the two `convert` blocks from `RECORDING.md` step 2
3. [ ] OBS → Scene Collection → Import → `obs_scene.json`
4. [ ] Edit OBS sources to point at your webcam, mic, and terminal window
5. [ ] Open browser tabs:
       - GitHub README anchored to the comparison table
       - https://demo.bpmn.io/ with `docs/bpmn/findevil_iabf_workflow.bpmn` loaded
6. [ ] Rehearse `bash scripts/demo.sh` once end-to-end (~3 min)
7. [ ] Read `storyboard.md` aloud against a stopwatch — make sure you fit 5:00
8. [ ] Record. Cut dead air. Caption every numeric claim. Export H.264 MP4.
9. [ ] Upload to YouTube unlisted, embed link on Devpost

## Optional polish (nice-to-have, skip if short on time)

- [ ] Lower-third title card with your name + handle
- [ ] On-screen tick-rate / iteration counter overlay during the terminal demo
- [ ] B-roll: 1 s zoom-in on the BPMN diagram during the workflow beat
- [ ] Captions / subtitles file (.srt) — accessibility + judges with audio off

## Risks & fallbacks

| If…                                          | Then…                                                                       |
|----------------------------------------------|-----------------------------------------------------------------------------|
| OBS won't capture the terminal window        | Use full-screen "Display Capture" instead of "Window Capture"               |
| Webcam isn't required                        | Drop scene 1 + 5 webcam sources — voice-over only is fine                   |
| Slide rendering fails                        | Skip slides; use a plain title-card screenshot or just talk over scene 2/3  |
| Demo runs longer than 3 min                  | In `scripts/demo.sh` change `time.sleep(0.05)` to `0.02` to speed JSONL replay |
| You blow past 5:00                           | Cut beat 6 (audit trail) — least essential, BPMN already covers reproducibility |
| Devpost upload fails                         | Re-export at lower bitrate (4000 kbps) OR YouTube unlisted + embed link     |

When you're ready: open `storyboard.md` first, then `RECORDING.md`. Good luck.
