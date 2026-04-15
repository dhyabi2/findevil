# Recording recipe

Three things in this directory:

| File              | Purpose                                                                        |
|-------------------|--------------------------------------------------------------------------------|
| `storyboard.md`   | Beat-by-beat script + narration — read it, tweak voice, rehearse twice.        |
| `obs_scene.json`  | Importable OBS Studio scene collection (5 scenes wired up).                    |
| `RECORDING.md`    | This file — actual recording steps.                                            |

The terminal demo runner lives at `../../scripts/demo.sh`.

## Step 1 — install OBS

- Linux:   `sudo apt install obs-studio`  (or flatpak)
- macOS:   download from https://obsproject.com
- Windows: download from https://obsproject.com

## Step 2 — generate the two slide PNGs (Title + Close)

The OBS scene references `slide_title.png` and `slide_close.png`. Generate with any
tool — Keynote / PowerPoint / Figma / even ImageMagick:

```bash
# Title slide (1920x1080, dark background, white text)
convert -size 1920x1080 xc:'#0d1117' \
  -gravity center -fill '#58a6ff' -font DejaVu-Sans-Bold -pointsize 96 \
  -annotate +0-100 'FIND EVIL!' \
  -fill '#c9d1d9' -pointsize 48 \
  -annotate +0+30 'Autonomous DFIR Agent  ·  IABF Methodology' \
  -fill '#8b949e' -pointsize 32 \
  -annotate +0+150 'github.com/dhyabi2/findevil' \
  docs/video/slide_title.png

# Close slide
convert -size 1920x1080 xc:'#0d1117' \
  -gravity center -fill '#58a6ff' -font DejaVu-Sans-Bold -pointsize 80 \
  -annotate +0-180 'F1 = 32.4 %  ·  Precision = 100 %' \
  -fill '#c9d1d9' -pointsize 48 \
  -annotate +0-50 '1.7 × the F1 of a naive LLM' \
  -fill '#c9d1d9' -pointsize 40 \
  -annotate +0+80 'github.com/dhyabi2/findevil' \
  -annotate +0+150 'github.com/dhyabi2/papers' \
  -fill '#3fb950' -pointsize 36 \
  -annotate +0+260 'Please vote!' \
  docs/video/slide_close.png
```

## Step 3 — import the OBS scene collection

OBS → **Scene Collection** → **Import** → pick `docs/video/obs_scene.json`.

Edit the file paths in `Title_Slide` / `Close_Slide` sources to match your machine
before recording. On Windows or Mac, also swap `xcomposite_input` / `v4l2_input` /
`pulse_input_capture` to the platform equivalents (commented in the JSON).

## Step 4 — open the three browser tabs

1. README on GitHub (or local rendered) scrolled to the comparison table
2. https://demo.bpmn.io/ with `docs/bpmn/findevil_iabf_workflow.bpmn` loaded
3. (optional) ACCURACY.md

## Step 5 — open one terminal and rehearse `scripts/demo.sh`

```bash
clear
bash scripts/demo.sh
```

The script walks 6 beats; press ENTER between each. Total runtime ~3 min terminal time
(leaving 2 min for intro + close + scene transitions).

## Step 6 — record

- Hit **Start Recording** in OBS
- Switch to scene 1 (Intro), narrate 25 s
- Switch to scene 2 (Comparison) at 0:25, narrate 30 s
- Switch to scene 3 (Terminal) at 0:55, run `bash scripts/demo.sh`, narrate as it pages
- Switch to scene 4 (BPMN) at 4:00, narrate 30 s
- Switch to scene 5 (Close) at 4:30, narrate 30 s
- Hit **Stop Recording** at 5:00 (use a stopwatch overlay or your phone)

## Step 7 — quick edit

Open the MP4 in any editor (DaVinci Resolve free, iMovie, Shotcut). Cut dead air,
add captions on every numeric claim (F1 = 32.4 %, precision = 100 %, etc.), export
**H.264 1920×1080 30 fps ≤ 100 MB** so Devpost upload doesn't time out.

## Step 8 — upload to Devpost

YouTube unlisted is the safest backup; Devpost lets you embed a YouTube link.
