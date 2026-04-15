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
