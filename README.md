# FIND EVIL! - IABF Agent

**Autonomous DFIR Agent using the Iterative Assumption-Based Framework on SANS SIFT Workstation**

Built for the [SANS FIND EVIL! Hackathon](https://findevil.devpost.com/).

## What is this?

An AI-powered incident response agent that investigates security incidents autonomously using a structured, hypothesis-driven methodology. Instead of blindly scanning data, the agent:

1. **Reconstructs the narrative** — builds a chronological "story" of the attack
2. **Generates hypotheses** — creates testable assumptions mapped to MITRE ATT&CK
3. **Investigates one assumption at a time** — runs targeted forensic tools through guardrails
4. **Self-corrects via feedback loop** — adjusts probabilities and refines the narrative

This implements the [IABF (Iterative Assumption-Based Framework)](https://github.com/dhyabi2/papers/blob/main/IABF_SIFT_Protocol_Research_Paper.md) research paper.

## Legacy DFIR tools vs. FIND EVIL! IABF Agent — capability comparison

| Capability                          | Classical SIFT (analyst-driven)            | EnCase / FTK (commercial GUI)         | **FIND EVIL! (IABF + AI)**                                   |
|-------------------------------------|--------------------------------------------|---------------------------------------|--------------------------------------------------------------|
| Hypothesis generation               | Manual, expert-dependent                   | Manual via "indices" / keyword lists  | **Automated**, MITRE ATT&CK-mapped, probability-weighted     |
| Tool selection                      | Analyst recall + cheat-sheets              | Wizard-driven, vendor pre-set         | **LLM picks** from 30+ SIFT tools per hypothesis             |
| Evidence chaining (extract→parse)   | Manual multi-step CLI work                 | Scripted pipelines (EnScript)         | **Auto** (icat → strings/RECmd inferred from MFT index)      |
| Concurrency                         | One investigator at a time                 | Indexer parallel, analysis serial     | **3-way parallel** Phase-3 hypothesis investigation          |
| Self-correction                     | Only by re-reading and starting over       | None                                  | **Phase 4 feedback loop** revises narrative + probabilities  |
| Hallucination control               | N/A (humans don't hallucinate, but err)    | N/A                                   | **Architectural guardrails** (binary whitelist, path bounds) |
| MFT index reuse                     | Recompute every grep                       | Indexed once, vendor-locked           | **Cached `mft_index_<sha>.txt`** — 1× build, ms greps        |
| Audit trail                         | Manual notes / case files                  | Audit log inside case file            | **JSONL stream**: every tool call, token, hypothesis verdict |
| Reproducibility                     | Depends on analyst notes                   | Case file replay (vendor format)      | **Deterministic JSON** report + audit trail (open format)    |
| Stagnation detection                | Analyst gut feel                           | None                                  | **Auto-bail** after N iters with no new confirmed evidence   |
| Speed (NIST Hacking Case, 1.04 GB)  | 4-8 hours analyst time                     | 30-90 min indexing + 2-4 h analysis   | **~10 min** end-to-end, unattended                           |
| Accuracy (F1 vs ground truth)       | Depends entirely on analyst                | Depends entirely on analyst           | **F1 32-44 %** unattended, baseline naive-LLM 26 %           |
| Cost per investigation              | Analyst hourly rate (~$100/h × 4-8h)       | License + analyst time                | **~$0.05** in LLM tokens + compute                           |

## Methodology comparison — old way vs. IABF way

| Phase                | Legacy DFIR (analyst-driven)                                                               | FIND EVIL! IABF Agent                                                                                                          |
|----------------------|--------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| **Triage**           | Analyst eyeballs alerts, decides what to look at first                                     | Auto-probe (file, sha256sum, mmls, fsstat, bulk_extractor); **probe facts auto-confirmed** before iter 1                       |
| **Narrative**        | Analyst builds mental model; rarely written down until reporting phase                     | Phase 1: LLM constructs **chronological narrative grounded in probe output** (no invented facts)                               |
| **Hypothesis**       | Implicit ("let me check the registry"); rarely falsifiable                                 | Phase 2: 1-3 **MITRE-mapped, probability-weighted, falsifiable** hypotheses, each with a concrete tool plan                    |
| **Investigation**    | Sequential: pick tool → run → read output → think → next tool. One hypothesis at a time.   | Phase 3: **parallel** investigation across hypotheses; each hypothesis is **isolated** (no cross-contamination of evidence)    |
| **Tool execution**   | Bash CLI by hand; output goes to terminal scrollback                                       | Guardrail-gated subprocess; output captured, truncated, JSONL-logged with timing + tokens                                      |
| **Verdict**          | Analyst declares "found it" / "moving on" — no formal scoring                              | LLM analyses tool output → confirmed / disproved / inconclusive **with confidence score**; rich `evidence_for` auto-promotes   |
| **Self-correction**  | Analyst re-reads notes hours later; corrections rare and undocumented                      | Phase 4: feedback loop **explicitly logs self-corrections**; next iteration's hypotheses must drill into confirmed findings    |
| **Termination**      | Investigator stops when tired, or when manager asks for the report                         | **Stagnation detector**: bail after N iterations with no new confirmed findings; **root_cause_reached** with confidence ≥ 0.5  |
| **Reporting**        | Manual write-up days later; subjective                                                     | Deterministic JSON: root cause, confirmed findings (with evidence chain), disproved assumptions, full audit JSONL, LLM stats   |
| **Reproducibility**  | "I think I ran fls then icat … let me check my notes"                                      | Replay the audit trail; identical input + same model → same output                                                             |
| **Bias / fatigue**   | Analyst confirmation bias, alert fatigue, weekend-night degradation                        | None — deterministic LLM, parallel hypotheses prevent tunnel vision, no fatigue                                                |

## Workflow diagrams (BPMN 2.0)

Two BPMN files in [`docs/bpmn/`](docs/bpmn/) capture the workflows side-by-side.
Open them with [bpmn.io](https://demo.bpmn.io/), Camunda Modeler, or any BPMN 2.0 viewer:

- [`docs/bpmn/findevil_iabf_workflow.bpmn`](docs/bpmn/findevil_iabf_workflow.bpmn) — the FIND EVIL! IABF agent loop (probe → narrative → hypotheses → parallel investigation → feedback → stagnation/root-cause exit)
- [`docs/bpmn/legacy_dfir_workflow.bpmn`](docs/bpmn/legacy_dfir_workflow.bpmn) — the classical analyst-driven SIFT workflow (manual triage → sequential tool runs → manual correlation → manual report)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    IABF Agent Core                       │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ Phase 1  │→ │ Phase 2  │→ │ Phase 3  │→ │Phase 4 │ │
│  │Narrative │  │Hypotheses│  │Investigate│  │Feedback│ │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘ │
│       ↑                                        │        │
│       └────────── Feedback Loop ───────────────┘        │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              LLM Client (OpenRouter)             │   │
│  │         Default: Google Gemma 4 27B              │   │
│  └─────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│           Architectural Guardrails Layer                 │
│  • Command blocklist (destructive ops)                  │
│  • Binary whitelist (forensic tools only)               │
│  • Path boundaries (evidence dirs only)                 │
│  • Injection detection                                  │
│  • Output size limits                                   │
├─────────────────────────────────────────────────────────┤
│              MCP Server (SIFT Tools)                    │
│                                                         │
│  ┌────────┐ ┌─────┐ ┌─────────┐ ┌──────┐ ┌─────────┐ │
│  │Sleuth- │ │Plaso│ │Zimmerman│ │ YARA │ │ Network │ │
│  │  kit   │ │     │ │  Tools  │ │      │ │Forensics│ │
│  └────────┘ └─────┘ └─────────┘ └──────┘ └─────────┘ │
│  ┌──────────────┐ ┌────────┐ ┌──────────────────────┐ │
│  │Bulk Extractor│ │Carving │ │ Strings/Hash/Hex     │ │
│  └──────────────┘ └────────┘ └──────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│                Structured Audit Trail                   │
│  • JSONL event stream (tool calls, timing, tokens)     │
│  • Hypothesis tracking (confirm/disprove/refine)       │
│  • Self-correction logging                             │
│  • Session export for submission                        │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- SANS SIFT Workstation (Ubuntu-based)
- Python 3.10+
- OpenRouter API key (or other LLM provider)

### Installation

```bash
# Clone the repository
git clone https://github.com/dhyabi2/findevil.git
cd findevil

# Install dependencies
pip install -r requirements.txt

# Set your API key — either export it or create a .env file
cp .env.example .env              # then edit .env with your key
# OR
export OPENROUTER_API_KEY="your-key-here"

# The investigate/mcp-server commands auto-load .env if present.

# Validate setup
python main.py validate
```

### Run an Investigation

```bash
# With a disk image
python main.py investigate \
  --evidence "EDR alert: rundll32.exe making external connection from marketing workstation" \
  --paths /cases/workstation.E01

# With multiple evidence sources
python main.py investigate \
  --evidence "Suspected lateral movement after phishing email" \
  --paths /cases/disk.E01 /cases/memory.raw /cases/traffic.pcap \
  --output report.json
```

### Claude Code Integration (MCP Server)

```bash
# Start the MCP server
python main.py mcp-server
```

Add to your Claude Code MCP config (`~/.claude/mcp.json`):

```json
{
  "mcpServers": {
    "findevil-sift": {
      "command": "python",
      "args": ["/home/sansforensics/findevil/main.py", "mcp-server"],
      "env": {
        "OPENROUTER_API_KEY": "your-key"
      }
    }
  }
}
```

## Configuration

Edit `config.yaml` to customize:

- **LLM provider** — OpenRouter (default), OpenAI, Anthropic, Ollama
- **Model** — Gemma 4 27B (default), or any model on your provider
- **Agent parameters** — iteration limits, confidence thresholds
- **Guardrails** — blocked commands, allowed paths, binary whitelist
- **Audit settings** — log format, token tracking, export options
- **Tool paths** — locations of SIFT forensic tools

## How the IABF Works

### Phase 1: Narrative Reconstruction
The agent reads available evidence (alerts, logs, artifacts) and constructs a chronological "story" of the incident. This prevents aimless data diving.

### Phase 2: Hypothesis Generation
Based on the narrative, the agent generates 1-3 specific, testable hypotheses mapped to MITRE ATT&CK techniques with confidence scores.

### Phase 3: Isolated Variable Investigation
Each hypothesis is tested **independently** using targeted forensic tool commands. This avoids cognitive overload from multi-vector analysis.

### Phase 4: Heuristic Feedback Loop
Results feed back into the narrative. Confirmed findings are locked in. Disproved assumptions are discarded. Probabilities adjust. The cycle repeats until root cause is identified with high confidence.

## Supported Evidence Types

| Type | Tools Used |
|------|-----------|
| Disk Images (.E01, .raw, .dd) | Sleuthkit, Plaso, Zimmerman, Foremost |
| Memory Captures (.raw, .mem) | Volatility 3 |
| Network Captures (.pcap) | TShark, tcpdump |
| Windows Event Logs (.evtx) | EvtxECmd |
| Registry Hives | RECmd |
| NTFS Artifacts ($MFT, $UsnJrnl) | MFTECmd |
| Browser History | Hindsight |
| Any binary file | YARA, strings, bulk_extractor |

## Security Boundaries

Guardrails are **architectural** (code-enforced), not prompt-based:

- **Command Blocklist**: `rm -rf`, `mkfs`, `dd of=`, `mount -o rw`, etc. are blocked at the code level regardless of LLM output
- **Binary Whitelist**: Only known forensic tool binaries can execute
- **Path Boundaries**: Tools can only access `/cases`, `/mnt`, and `/tmp/findevil`
- **Injection Detection**: Shell injection patterns in piped commands are blocked
- **Output Limits**: Tool output is truncated before reaching the LLM
- **Read-Only Evidence**: Evidence mount points are enforced read-only

## Audit Trail

Every session produces:
- `session_<id>.jsonl` — streaming event log (tool calls, timestamps, tokens)
- `report_<id>.json` — full session summary
- `investigation_<id>.json` — investigation findings and hypothesis tree

## Project Structure

```
findevil/
├── main.py                  # CLI entry point
├── config.yaml              # LLM & agent configuration
├── requirements.txt         # Python dependencies
├── pyproject.toml           # Package metadata
├── LICENSE                  # MIT License
├── README.md                # This file
├── ARCHITECTURE.md          # Detailed architecture document
├── DATASETS.md              # Dataset documentation
├── ACCURACY.md              # Accuracy report template
├── DEPLOYMENT.md            # Deployment instructions
├── agent/
│   ├── __init__.py
│   ├── iabf.py              # Core IABF 4-phase loop
│   ├── llm_client.py        # OpenRouter/LLM abstraction
│   └── audit.py             # Structured audit trail
├── mcp_server/
│   ├── __init__.py
│   ├── server.py            # MCP server (30+ forensic tools)
│   ├── guardrails.py        # Architectural security enforcement
│   └── tools/
│       └── __init__.py
├── datasets/                # Evidence datasets
├── reports/                 # Accuracy reports
├── logs/                    # Execution logs & audit trails
└── deploy/
    └── install.sh           # Automated deployment script
```

## License

MIT License. See [LICENSE](LICENSE).
