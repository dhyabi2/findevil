# Architecture Document

## System Overview

FIND EVIL! is a 3-layer autonomous DFIR agent:

```
┌─────────────────────────────────────────────────────────────┐
│                     Layer 1: IABF Agent                      │
│                                                              │
│  Implements the 4-phase investigation loop:                  │
│  Narrative → Hypothesis → Investigation → Feedback           │
│                                                              │
│  Components:                                                 │
│  • iabf.py      — Core loop controller                      │
│  • llm_client.py — LLM abstraction (OpenRouter/Gemma 4)     │
│  • audit.py     — Structured audit trail                     │
│                                                              │
│  Security: LLM output is NEVER executed directly.            │
│  All tool commands pass through Layer 2 first.               │
├──────────────────────────────────────────────────────────────┤
│                  Layer 2: Guardrails                          │
│                                                              │
│  ARCHITECTURAL enforcement (not prompt-based):               │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Command     │  │   Binary     │  │     Path         │  │
│  │   Blocklist   │  │   Whitelist  │  │   Boundaries     │  │
│  │              │  │              │  │                  │  │
│  │ rm -rf       │  │ Only known   │  │ /cases, /mnt,    │  │
│  │ mkfs         │  │ forensic     │  │ /tmp/findevil    │  │
│  │ dd of=       │  │ tools can    │  │ only             │  │
│  │ mount -o rw  │  │ execute      │  │                  │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│  ┌──────────────┐  ┌──────────────┐                         │
│  │  Injection   │  │   Output     │                         │
│  │  Detection   │  │   Limits     │                         │
│  │              │  │              │                         │
│  │ Shell pipes  │  │ 10MB max     │                         │
│  │ Backticks    │  │ 50K chars    │                         │
│  │ $() chains   │  │ to LLM      │                         │
│  └──────────────┘  └──────────────┘                         │
├──────────────────────────────────────────────────────────────┤
│                   Layer 3: MCP Server                        │
│                                                              │
│  Type-safe tool wrappers for 30+ SIFT forensic tools:       │
│                                                              │
│  Disk Analysis    │ Timeline        │ Windows Artifacts      │
│  ─────────────── │ ─────────────── │ ──────────────────     │
│  mmls            │ log2timeline    │ MFTECmd                │
│  fls / icat      │ psort           │ EvtxECmd               │
│  fsstat          │ pinfo           │ RECmd                  │
│  img_stat        │                 │ AmcacheParser          │
│  tsk_recover     │                 │ AppCompatCacheParser   │
│                  │                 │ JLECmd / LECmd         │
│  Scanning        │ Network         │ SBECmd / RBCmd         │
│  ─────────────── │ ─────────────── │                        │
│  yara            │ tshark          │ Utilities              │
│  bulk_extractor  │ tcpdump         │ ──────────────────     │
│  foremost        │ capinfos        │ strings / file         │
│  scalpel         │                 │ xxd / hexdump          │
│                  │                 │ md5sum/sha256sum       │
└──────────────────────────────────────────────────────────────┘
```

## Data Flow

```
Evidence (disk image, pcap, memory dump, logs)
    │
    ▼
[MCP Server] — wraps forensic tools with type-safe interfaces
    │
    ▼
[Guardrails] — validates every command before execution
    │               • Blocks destructive operations
    │               • Enforces binary whitelist
    │               • Restricts path access
    │               • Detects injection attempts
    ▼
[Tool Execution] — subprocess with timeout, output capture
    │
    ▼
[Output Sanitization] — truncate, sanitize for LLM context
    │
    ▼
[IABF Agent] — interprets results through 4-phase loop
    │               • Phase 1: Update narrative
    │               • Phase 2: Generate/refine hypotheses
    │               • Phase 3: Plan next targeted investigation
    │               • Phase 4: Feedback → loop or conclude
    ▼
[Audit Trail] — JSONL log of every action, decision, token
    │
    ▼
[Investigation Report] — root cause, findings, evidence chain
```

## Security Boundary Model

### Architectural vs Prompt-Based Guardrails

| Protection | Type | Enforcement Point | Can LLM Bypass? |
|-----------|------|-------------------|-----------------|
| Command blocklist | Architectural | `guardrails.py:_check_blocked_patterns()` | No |
| Binary whitelist | Architectural | `guardrails.py:_check_binary_whitelist()` | No |
| Path boundaries | Architectural | `guardrails.py:_check_path_boundaries()` | No |
| Injection detection | Architectural | `guardrails.py:_check_injection()` | No |
| Output truncation | Architectural | `guardrails.py:sanitize_for_llm()` | No |
| Evidence read-only | Config | `config.yaml:evidence_read_only` | No |
| MITRE ATT&CK mapping | Prompt-based | System prompt instruction | Yes (graceful) |
| Self-correction behavior | Prompt-based | System prompt instruction | Yes (graceful) |
| Confidence thresholds | Architectural | `iabf.py` confidence checks | No |

### Threat Model

- **LLM hallucination** → Mitigated by requiring tool evidence for every claim; audit trail tracks confirmed vs inferred
- **Prompt injection via evidence** → Guardrails prevent destructive commands regardless of LLM output
- **Evidence tampering** → Read-only mount enforcement; hash verification available
- **Resource exhaustion** → Timeouts, output limits, iteration caps

## LLM Integration

```
config.yaml
    │
    ▼
LLMConfig.from_yaml() — resolves provider, API key from env, model
    │
    ▼
LLMClient — httpx-based client
    │
    ├── chat() — general conversation (narrative, feedback)
    │
    └── chat_json() — structured output (hypotheses, verdicts)
            │
            ▼
        OpenRouter API (default)
        Model: google/gemma-4-31b-it
        Fallback: google/gemma-3-27b-it
```

## Audit Trail Schema

Each JSONL event:
```json
{
  "timestamp": "2026-04-13T20:00:00Z",
  "session_id": "abc12345",
  "event_type": "tool_start|tool_end|hypothesis|iteration|llm_call|guardrail_violation|self_correction|narrative",
  "...event-specific fields..."
}
```
