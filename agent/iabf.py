"""
IABF Agent - Iterative Assumption-Based Framework for autonomous DFIR.

Implements the 4-phase methodology from the IABF research paper:
  Phase 1: Contextual Narrative Reconstruction
  Phase 2: Hypothesis Generation (MITRE ATT&CK mapped)
  Phase 3: Isolated Variable Investigation
  Phase 4: Heuristic Feedback Loop

Each cycle refines the narrative until root cause is identified.
"""

import json
import logging
import subprocess
import shlex
import time
from pathlib import Path
from dataclasses import dataclass, field

import yaml

from .llm_client import LLMClient, LLMConfig
from .audit import AuditTrail, HypothesisRecord, IterationRecord
from mcp_server.guardrails import ForensicGuardrails

logger = logging.getLogger("findevil.iabf")


@dataclass
class Hypothesis:
    """A testable assumption about the incident."""
    id: str
    description: str
    mitre_technique: str = ""
    mitre_id: str = ""
    confidence: float = 0.5
    status: str = "pending"  # pending | testing | confirmed | disproved | refined
    investigation_plan: str = ""
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    tool_commands: list[str] = field(default_factory=list)


@dataclass
class InvestigationState:
    """Current state of the IABF investigation."""
    narrative: str = ""
    hypotheses: list[Hypothesis] = field(default_factory=list)
    confirmed_findings: list[str] = field(default_factory=list)
    disproved_assumptions: list[str] = field(default_factory=list)
    iteration: int = 0
    root_cause: str = ""
    evidence_sources: list[str] = field(default_factory=list)
    timeline_events: list[dict] = field(default_factory=list)


SYSTEM_PROMPT_TEMPLATE = """You are an expert Digital Forensics analyst performing OFFLINE DEAD-DISK forensics on a SANS SIFT Workstation. You operate under the Iterative Assumption-Based Framework (IABF).

CRITICAL CONTEXT:
- The evidence is a FORENSIC IMAGE FILE (e.g. .E01, .raw, .dd) sitting on disk. It is NOT a live running system.
- You CANNOT run live-system commands (netstat, schtasks, Get-ScheduledTask, tcpdump, history, ps, psscan, logparser, powershell, Get-*). They will fail — there is no running OS.
- You CAN run SIFT forensic tools against the image file.
- To query registry hives, event logs, MFT, etc., EXTRACT them first (icat/tsk_recover) then parse with Zimmerman tools.

EVIDENCE IN THIS CASE (use these EXACT paths and offsets — do NOT invent):
{evidence_block}

OFFSET RULES — MISREAD THESE AND EVERY COMMAND FAILS:
- Sleuthkit's `-o` flag takes a SECTOR offset (integer number of 512-byte sectors), NOT a byte offset.
- The partition offset above is already in SECTORS. Use it verbatim: `fls -r -o {primary_offset} {primary_image}`.
- NEVER multiply by 512. NEVER pass byte offsets to `-o`.

METHODOLOGY (IABF):
1. NARRATIVE: Chronological story grounded in probe output — quote real facts (hashes, offsets, filesystem type) from the EVIDENCE block above. Never invent hashes or dates.
2. HYPOTHESIZE: 1-3 testable assumptions mapped to MITRE ATT&CK, each with a concrete tool plan.
3. INVESTIGATE: Run the plan. If tool output is empty or errors, the hypothesis is INCONCLUSIVE, not disproved.
4. FEEDBACK: Update narrative; keep confirmed facts; re-plan next iteration.

WINDOWS DEAD-DISK PLAYBOOK (priority order — use this, don't guess random tools):
  (a) System identity:
        icat -o <sec> <img> <inode_of_SOFTWARE_hive>  > /tmp/findevil/hives/SOFTWARE
        dotnet /opt/zimmermantools/net6/RECmd.dll -f /tmp/findevil/hives/SOFTWARE --kn "Microsoft\\Windows NT\\CurrentVersion"
        → RegisteredOwner, ProductName, InstallDate, TimeZone
  (b) User accounts:
        icat SAM hive → RECmd with --kn "SAM\\Domains\\Account\\Users"
  (c) Installed software (hacking tools):
        fls -r -o <sec> <img> | grep -iE 'Program Files|Uninstall'
        RECmd on SOFTWARE → "Microsoft\\Windows\\CurrentVersion\\Uninstall"
  (d) Network identity (IP/MAC):
        RECmd on SYSTEM → "ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces"
        bulk_extractor -o /tmp/findevil/be <img>   → ip.txt, ether.txt, email.txt
  (e) Artefact sweep:
        strings extracted user files for IRC/email/newsgroup keywords
  (f) Timeline if needed:
        log2timeline.py, then psort.py

SIFT TOOL CHEAT-SHEET (command MUST start with one of these binaries):
  mmls, fsstat, fls, icat, ifind, tsk_recover, blkls, blkcat, srch_strings, mactime,
  log2timeline.py, psort.py, pinfo.py,
  bulk_extractor, foremost, scalpel,
  strings, file, xxd, hexdump, sha256sum, md5sum, exiftool, pdftotext, olevba,
  grep, head, tail, wc, sort, uniq, awk, sed, cut, find, ls, cat,
  dotnet, python3, yara, tshark

PATH RULES:
- Evidence is READ-ONLY at the paths listed in the EVIDENCE block above.
- Write scratch output ONLY to /tmp/findevil/ (guardrails enforce this).
- Do NOT reference /cases/ unless the EVIDENCE block above lists a /cases/ path.

CRITICAL RULES:
- Distinguish CONFIRMED (quote tool output) from INFERRED (reasoning).
- Empty output or non-zero exit = INCONCLUSIVE, not DISPROVED.
- Map findings to MITRE ATT&CK when applicable.
- Self-correct when results contradict the narrative."""


def build_system_prompt(evidence_sources: list[str], probe_summary: dict) -> str:
    """Render the system prompt with real evidence paths and sector offsets."""
    lines = []
    for p in evidence_sources or []:
        info = probe_summary.get(p, {})
        lines.append(f"- path: {p}")
        if info.get("sha256"):
            lines.append(f"  sha256: {info['sha256']}")
        if info.get("filesystem"):
            lines.append(f"  filesystem: {info['filesystem']}")
        if info.get("primary_sector_offset") is not None:
            lines.append(f"  primary_partition_sector_offset: {info['primary_sector_offset']}")
    evidence_block = "\n".join(lines) if lines else "(no evidence paths provided)"
    primary = (evidence_sources or ["<image>"])[0]
    primary_offset = "0"
    for p in evidence_sources or []:
        off = probe_summary.get(p, {}).get("primary_sector_offset")
        if off is not None:
            primary_offset = str(off)
            break
    return SYSTEM_PROMPT_TEMPLATE.format(
        evidence_block=evidence_block,
        primary_offset=primary_offset,
        primary_image=primary,
    )


# Backwards-compat alias so tests/fixtures importing SYSTEM_PROMPT still work.
SYSTEM_PROMPT = SYSTEM_PROMPT_TEMPLATE


class IABFAgent:
    """Core IABF investigation agent."""

    def __init__(self, config_path: str = "config.yaml", llm=None, dry_run: bool = False):
        """
        Args:
            config_path: Path to config.yaml.
            llm: Optional pre-built LLM client (e.g. FakeLLMClient for tests).
                 If None, a real LLMClient is constructed from config.
            dry_run: When True, forensic tool commands are NOT executed. Instead,
                 a synthetic "dry-run" output is returned. Combine with a
                 FakeLLMClient for fully offline runs.
        """
        with open(config_path) as f:
            self.config = yaml.safe_load(f)

        self.llm = llm if llm is not None else LLMClient(LLMConfig.from_yaml(self.config))
        self.guardrails = ForensicGuardrails(self.config.get("guardrails", {}))
        self.audit = AuditTrail(
            log_dir=self.config.get("audit", {}).get("log_dir", "./logs")
        )
        self.state = InvestigationState()
        self.max_iterations = self.config.get("agent", {}).get("max_iterations", 15)
        self.confidence_threshold = self.config.get("agent", {}).get("confidence_threshold", 0.85)
        self.discard_threshold = self.config.get("agent", {}).get("discard_threshold", 0.15)
        self.dry_run = dry_run
        self._conversation: list[dict] = []
        self._max_conversation_turns = 8  # user+assistant pairs retained
        self._probe_summary: dict[str, dict] = {}
        self._system_prompt: str = SYSTEM_PROMPT_TEMPLATE

    def _exec_tool(self, command: str) -> tuple[int, str]:
        """Execute a forensic tool command through guardrails."""
        violation = self.guardrails.validate_command(command)
        if violation:
            self.audit.log_guardrail_violation(violation.detail, command)
            return -1, f"BLOCKED: {violation.detail}"

        if self.dry_run:
            tool = shlex.split(command)[0] if command else "unknown"
            fake_out = f"[DRY-RUN] would execute: {command}\n[DRY-RUN] tool={tool}"
            exec_id = self.audit.log_tool_start(
                tool_name=tool,
                command=command,
                args=shlex.split(command)[1:] if command else [],
            )
            self.audit.log_tool_end(exec_id, 0, fake_out)
            return 0, fake_out

        exec_id = self.audit.log_tool_start(
            tool_name=shlex.split(command)[0] if command else "unknown",
            command=command,
            args=shlex.split(command)[1:] if command else [],
        )

        try:
            timeout = self.config.get("agent", {}).get("tool_timeout", 300)
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=timeout,
            )
            output = result.stdout
            if result.stderr:
                output += f"\nSTDERR: {result.stderr}"

            output = self.guardrails.sanitize_for_llm(output)
            self.audit.log_tool_end(exec_id, result.returncode, output)
            return result.returncode, output

        except subprocess.TimeoutExpired:
            self.audit.log_tool_end(exec_id, -1, "", "Timeout")
            return -1, f"Tool timed out after {timeout}s"
        except Exception as e:
            self.audit.log_tool_end(exec_id, -1, "", str(e))
            return -1, f"Error: {e}"

    def _llm_chat(self, user_message: str, purpose: str = "") -> str:
        """Send a message to the LLM and track usage."""
        self._conversation.append({"role": "user", "content": user_message})

        resp = self.llm.chat(
            messages=self._conversation,
            system=self._system_prompt,
        )

        self._conversation.append({"role": "assistant", "content": resp.content})
        # Trim: keep only last N user/assistant turns to prevent context blowup.
        max_msgs = self._max_conversation_turns * 2
        if len(self._conversation) > max_msgs:
            self._conversation = self._conversation[-max_msgs:]
        self.audit.log_llm_call(
            model=resp.model,
            tokens=resp.usage,
            latency_ms=resp.latency_ms,
            purpose=purpose,
        )
        return resp.content

    def _llm_json(self, user_message: str, purpose: str = "") -> dict:
        """Send a message expecting JSON response."""
        resp = self.llm.chat_json(
            messages=[{"role": "user", "content": user_message}],
            system=self._system_prompt,
        )
        self.audit.log_llm_call(
            model="json_call",
            tokens={},
            latency_ms=0,
            purpose=purpose,
        )
        return resp

    # ================================================================
    # Phase 1: Contextual Narrative Reconstruction
    # ================================================================

    def _probe_evidence(self, evidence_paths: list[str]) -> str:
        """Run quick read-only probes; also populate self._probe_summary for prompt templating.

        Returns a human-readable probe block for inclusion in Phase-1 prompt.
        Side effect: fills self._probe_summary[path] with sha256, filesystem,
        primary_sector_offset so the system prompt can render real evidence facts.
        """
        if not evidence_paths:
            return "(no evidence paths provided)"
        lines: list[str] = []
        for p in evidence_paths:
            path = Path(p)
            info: dict = {}
            self._probe_summary[p] = info
            if not path.exists():
                lines.append(f"{p}: MISSING")
                continue
            lines.append(f"=== {p} ===")
            code, out = self._exec_tool(f"file {shlex.quote(p)}")
            if code == 0 and out:
                lines.append(out.strip().splitlines()[0])
            code, out = self._exec_tool(f"sha256sum {shlex.quote(p)}")
            if code == 0 and out:
                full = out.split()[0]
                info["sha256"] = full
                lines.append(f"sha256: {full}")
            # Attempt partition layout parsing (works on raw; also on .E01 when libewf is compiled in).
            code, out = self._exec_tool(f"mmls {shlex.quote(p)}")
            if code == 0 and out:
                lines.append("Partition layout (mmls):")
                lines.append(out.strip())
                # Parse sector offset of the first non-meta, non-unallocated partition
                for line in out.splitlines():
                    tokens = line.split()
                    if len(tokens) >= 6 and tokens[0].rstrip(":").isdigit():
                        slot = tokens[1]
                        if slot == "Meta" or slot.startswith("---"):
                            continue
                        try:
                            start_sector = int(tokens[2])
                            length = int(tokens[4])
                        except ValueError:
                            continue
                        if length < 1024:  # skip tiny unallocated gaps
                            continue
                        info["primary_sector_offset"] = start_sector
                        # Follow up with fsstat to get filesystem type.
                        code2, out2 = self._exec_tool(
                            f"fsstat -o {start_sector} {shlex.quote(p)}"
                        )
                        if code2 == 0 and out2:
                            fs_line = out2.strip().splitlines()[0] if out2.strip() else ""
                            info["filesystem"] = fs_line
                            lines.append(f"fsstat @ sector {start_sector}: {fs_line}")
                        break
            else:
                lines.append(f"mmls failed (exit {code}) — image may not be a raw disk")
        return "\n".join(lines)

    def phase1_narrative(self, evidence_description: str) -> str:
        """Build initial narrative from available evidence."""
        logger.info(f"[Iteration {self.state.iteration}] Phase 1: Narrative Reconstruction")

        if self.state.iteration == 0 or (self.state.iteration == 1 and not self.state.narrative):
            probe = self._probe_evidence(self.state.evidence_sources)
            prompt = f"""PHASE 1 - NARRATIVE RECONSTRUCTION

You are beginning an OFFLINE DISK-IMAGE investigation. Evidence description:

{evidence_description}

Evidence paths (READ-ONLY, at /cases/): {self.state.evidence_sources}

Real probe output (file type, hash, partition layout) — ground your narrative in THESE facts, not assumptions:
---
{probe}
---

Previously confirmed findings:
{json.dumps(self.state.confirmed_findings, indent=2) if self.state.confirmed_findings else "None yet."}

Previously disproved assumptions:
{json.dumps(self.state.disproved_assumptions, indent=2) if self.state.disproved_assumptions else "None yet."}

Construct a chronological NARRATIVE of what likely happened. This is your "story" of the incident so far. Be specific about:
1. What events occurred and in what order
2. What artifacts/evidence exist
3. What is CONFIRMED vs what is INFERRED
4. What gaps exist in the story

End with: "KEY UNKNOWNS:" followed by what we still need to determine."""
        else:
            prompt = f"""PHASE 1 - NARRATIVE UPDATE (Iteration {self.state.iteration})

Based on the latest investigation results, update the narrative.

Current narrative:
{self.state.narrative}

New evidence from last investigation:
{self._conversation[-2]['content'] if len(self._conversation) >= 2 else 'None'}

Previously confirmed findings:
{json.dumps(self.state.confirmed_findings, indent=2)}

Previously disproved assumptions:
{json.dumps(self.state.disproved_assumptions, indent=2)}

Update the chronological narrative. Mark what changed. Note any SELF-CORRECTIONS where previous assumptions were wrong."""

        narrative = self._llm_chat(prompt, purpose="phase1_narrative")
        self.state.narrative = narrative
        self.audit.log_narrative(narrative, self.state.iteration)

        return narrative

    # ================================================================
    # Phase 2: Hypothesis Generation
    # ================================================================

    def phase2_hypotheses(self) -> list[Hypothesis]:
        """Generate testable hypotheses from the narrative."""
        logger.info(f"[Iteration {self.state.iteration}] Phase 2: Hypothesis Generation")

        prompt = f"""PHASE 2 - HYPOTHESIS GENERATION

Current narrative:
{self.state.narrative}

Already tested hypotheses:
{json.dumps([{
    'description': h.description,
    'status': h.status,
    'confidence': h.confidence
} for h in self.state.hypotheses], indent=2)}

Generate 1-3 NEW testable hypotheses. For each:
1. A specific, falsifiable assumption
2. The MITRE ATT&CK technique it maps to (ID + name)
3. Your confidence level (0.0-1.0)
4. The EXACT SIFT forensic tool command(s) needed to test it
5. What result would CONFIRM vs DISPROVE it

HARD CONSTRAINTS for tool_commands (any violation = command BLOCKED, iteration wasted):
- Every command MUST begin with one of these SIFT binaries:
  mmls, fls, fsstat, icat, ifind, tsk_recover, blkls, blkcat, srch_strings, mactime,
  log2timeline.py, psort.py, pinfo.py,
  bulk_extractor, foremost, scalpel,
  strings, file, xxd, hexdump, sha256sum, md5sum, exiftool, pdftotext, olevba,
  grep, head, tail, wc, sort, uniq, awk, sed, cut, find, ls, cat,
  dotnet, python3, yara, tshark
- Operate ONLY on files under /cases/ (read-only evidence) or /tmp/findevil/ (scratch).
- Do NOT use: PowerShell, Get-*, netstat, tcpdump on -i, schtasks, psscan, logparser,
  ps, history, cmd.exe builtins, or any command assuming a live Windows host.
- Registry hives / EVTX / MFT must be EXTRACTED FIRST (icat or tsk_recover) before
  Zimmerman tools (RECmd, EvtxECmd, MFTECmd) can parse them.

Respond in this JSON format:
{{
  "hypotheses": [
    {{
      "description": "...",
      "mitre_technique": "T1003 - OS Credential Dumping",
      "confidence": 0.7,
      "investigation_plan": "...",
      "tool_commands": ["fls -r -o 63 /cases/image.E01 | grep -i 'lsass'"],
      "confirms_if": "...",
      "disproves_if": "..."
    }}
  ]
}}"""

        try:
            data = self._llm_json(prompt, purpose="phase2_hypotheses")
        except (json.JSONDecodeError, Exception) as e:
            logger.warning(f"Failed to parse hypotheses JSON: {e}")
            # Fallback: ask as plain text and manually parse
            text = self._llm_chat(prompt, purpose="phase2_hypotheses_fallback")
            return self.state.hypotheses

        new_hypotheses = []
        raw_hyps = data.get("hypotheses", []) or []
        for i, h in enumerate(raw_hyps):
            if not isinstance(h, dict):
                logger.warning(f"Skipping non-dict hypothesis at index {i}: {type(h).__name__}")
                continue
            hyp = Hypothesis(
                id=f"H{self.state.iteration}_{i}",
                description=h.get("description", ""),
                mitre_technique=h.get("mitre_technique", ""),
                confidence=h.get("confidence", 0.5),
                investigation_plan=h.get("investigation_plan", ""),
                tool_commands=h.get("tool_commands", []),
            )
            new_hypotheses.append(hyp)
            self.state.hypotheses.append(hyp)

            self.audit.log_hypothesis(HypothesisRecord(
                id=hyp.id,
                iteration=self.state.iteration,
                hypothesis=hyp.description,
                mitre_technique=hyp.mitre_technique,
                confidence_before=hyp.confidence,
                status="pending",
            ))

        return new_hypotheses

    # ================================================================
    # Phase 3: Isolated Variable Investigation
    # ================================================================

    def phase3_investigate(self, hypothesis: Hypothesis) -> dict:
        """Test ONE hypothesis with targeted forensic tool execution."""
        logger.info(f"[Iteration {self.state.iteration}] Phase 3: Investigating {hypothesis.id}")
        hypothesis.status = "testing"

        results = {}
        all_empty = True
        any_success = False
        for cmd in hypothesis.tool_commands:
            logger.info(f"  Executing: {cmd}")
            code, output = self._exec_tool(cmd)
            results[cmd] = {
                "exit_code": code,
                "output": output,
            }
            stripped = (output or "").strip()
            if stripped and not stripped.startswith("BLOCKED") and "STDERR:" not in stripped.splitlines()[0] if stripped else False:
                all_empty = False
            if code == 0 and stripped:
                any_success = True

        # Ask LLM to interpret results
        prompt = f"""PHASE 3 - INVESTIGATION RESULTS

Hypothesis being tested: {hypothesis.description}
MITRE Technique: {hypothesis.mitre_technique}
Pre-test confidence: {hypothesis.confidence}

Tool execution results:
{json.dumps(results, indent=2)}

Analyze these results and determine:
1. Does the evidence CONFIRM or DISPROVE the hypothesis?
2. What specific artifacts support your conclusion?
3. What is your updated confidence level (0.0-1.0)?
4. Are there any UNEXPECTED findings that suggest a different attack vector?
5. If DISPROVED: what should we investigate next?

Respond in JSON:
{{
  "verdict": "confirmed|disproved|inconclusive",
  "confidence_after": 0.0,
  "evidence_for": ["..."],
  "evidence_against": ["..."],
  "unexpected_findings": ["..."],
  "self_correction": "...",
  "next_suggestion": "..."
}}"""

        try:
            analysis = self._llm_json(prompt, purpose="phase3_analysis")
        except (json.JSONDecodeError, Exception):
            analysis = {
                "verdict": "inconclusive",
                "confidence_after": hypothesis.confidence,
            }

        if not isinstance(analysis, dict):
            analysis = {"verdict": "inconclusive", "confidence_after": hypothesis.confidence}

        verdict = analysis.get("verdict", "inconclusive")
        # HARD OVERRIDE: if NO command succeeded AND the LLM cited no evidence_against,
        # a "disproved" verdict is unfounded — coerce to inconclusive so the agent
        # keeps investigating instead of locking in a false negative.
        if (
            verdict == "disproved"
            and not any_success
            and not analysis.get("evidence_against")
        ):
            logger.info(f"  [{hypothesis.id}] Override: no successful output + no evidence_against -> inconclusive")
            verdict = "inconclusive"
            analysis["verdict"] = "inconclusive"
            analysis["confidence_after"] = max(hypothesis.confidence * 0.8, 0.2)
        hypothesis.confidence = analysis.get("confidence_after", hypothesis.confidence)
        hypothesis.evidence_for = analysis.get("evidence_for", [])
        hypothesis.evidence_against = analysis.get("evidence_against", [])

        if verdict == "confirmed":
            hypothesis.status = "confirmed"
            self.state.confirmed_findings.append(hypothesis.description)
        elif verdict == "disproved":
            hypothesis.status = "disproved"
            self.state.disproved_assumptions.append(hypothesis.description)
        else:
            hypothesis.status = "refined"

        # Log self-correction if present
        correction = analysis.get("self_correction", "")
        if correction and correction.lower() not in ("none", "n/a", ""):
            self.audit.log_self_correction(
                original=hypothesis.description,
                corrected=correction,
                reason=f"Evidence from {hypothesis.id}",
            )

        self.audit.log_hypothesis(HypothesisRecord(
            id=hypothesis.id,
            iteration=self.state.iteration,
            hypothesis=hypothesis.description,
            mitre_technique=hypothesis.mitre_technique,
            confidence_before=hypothesis.confidence,
            confidence_after=analysis.get("confidence_after", hypothesis.confidence),
            status=hypothesis.status,
            evidence_for=hypothesis.evidence_for,
            evidence_against=hypothesis.evidence_against,
        ))

        return analysis

    # ================================================================
    # Phase 4: Heuristic Feedback Loop
    # ================================================================

    def phase4_feedback(self, investigation_results: list[dict]) -> str:
        """Feed results back into the narrative for the next cycle."""
        logger.info(f"[Iteration {self.state.iteration}] Phase 4: Feedback Loop")

        prompt = f"""PHASE 4 - HEURISTIC FEEDBACK LOOP

Current narrative:
{self.state.narrative}

Investigation results from this iteration:
{json.dumps(investigation_results, indent=2)}

Confirmed findings so far:
{json.dumps(self.state.confirmed_findings, indent=2)}

Disproved assumptions:
{json.dumps(self.state.disproved_assumptions, indent=2)}

Perform the feedback analysis:
1. How do these results change the narrative?
2. What probabilities need adjustment?
3. Have we reached the ROOT CAUSE? (Set root_cause if yes)
4. If not, what is the SINGLE most important thing to investigate next?
5. Note any SELF-CORRECTIONS - where our previous understanding was wrong.

Respond in JSON:
{{
  "narrative_update": "...",
  "root_cause_reached": false,
  "root_cause": "",
  "confidence_in_root_cause": 0.0,
  "self_corrections": ["..."],
  "next_priority": "...",
  "probability_adjustments": {{}},
  "investigation_complete": false
}}"""

        try:
            feedback = self._llm_json(prompt, purpose="phase4_feedback")
        except (json.JSONDecodeError, Exception):
            feedback = {
                "root_cause_reached": False,
                "narrative_update": "Unable to parse feedback. Continuing investigation.",
            }

        if feedback.get("root_cause_reached"):
            self.state.root_cause = feedback.get("root_cause", "")

        corrections_raw = feedback.get("self_corrections", []) or []
        if isinstance(corrections_raw, str):
            corrections_raw = [corrections_raw]
        for correction in corrections_raw:
            if isinstance(correction, (list, dict)):
                correction = json.dumps(correction) if correction else ""
            correction = str(correction).strip()
            if correction and correction.lower() not in ("none", "n/a", ""):
                self.audit.log_self_correction(
                    original="Previous narrative assumption",
                    corrected=correction,
                    reason="Phase 4 feedback loop",
                )

        self.audit.log_iteration(IterationRecord(
            iteration=self.state.iteration,
            phase="feedback",
            narrative_summary=feedback.get("narrative_update", ""),
            feedback_summary=feedback.get("next_priority", ""),
        ))

        return json.dumps(feedback, indent=2)

    # ================================================================
    # Main Investigation Loop
    # ================================================================

    def _pre_pass(self) -> str:
        """Run automatic pre-iteration extraction: probe + bulk_extractor summary.

        Returns a text block describing what was extracted, to seed Phase 1.
        """
        lines: list[str] = []
        for p in self.state.evidence_sources:
            info = self._probe_summary.get(p, {})
            off = info.get("primary_sector_offset")
            if off is None:
                continue
            # Quick artefact scrape via bulk_extractor (short timeout, scratch dir).
            Path("/tmp/findevil").mkdir(parents=True, exist_ok=True)
            be_dir = f"/tmp/findevil/be_{Path(p).name}"
            code, _ = self._exec_tool(
                f"bulk_extractor -o {be_dir} -q -E email -E url -E ip -E ether {shlex.quote(p)}"
            )
            if code == 0:
                for art in ("email.txt", "ip.txt", "ether.txt", "url.txt"):
                    fpath = f"{be_dir}/{art}"
                    if Path(fpath).exists():
                        c, out = self._exec_tool(
                            f"head -n 30 {fpath} | awk '{{print $2}}' | sort -u | head -n 20"
                        )
                        if out and out.strip():
                            lines.append(f"--- bulk_extractor {art} (top 20 unique) ---")
                            lines.append(out.strip())
        return "\n".join(lines) if lines else "(pre-pass produced no artefacts)"

    def investigate(self, evidence_description: str, evidence_paths: list[str] | None = None) -> dict:
        """
        Run the full IABF investigation loop.

        Args:
            evidence_description: Human-readable description of available evidence
            evidence_paths: Paths to forensic images, pcaps, logs, etc.

        Returns:
            Final investigation report
        """
        self.state.evidence_sources = evidence_paths or []
        logger.info("=" * 60)
        logger.info("IABF Investigation Started")
        logger.info("=" * 60)

        # Pre-pass: probe evidence and build a grounded system prompt BEFORE iteration 1.
        self._probe_evidence(self.state.evidence_sources)
        self._system_prompt = build_system_prompt(
            self.state.evidence_sources, self._probe_summary
        )
        pre_pass_summary = self._pre_pass()
        if pre_pass_summary:
            evidence_description = (
                evidence_description
                + "\n\nAUTOMATED PRE-PASS ARTEFACTS (bulk_extractor):\n"
                + pre_pass_summary
            )

        while self.state.iteration < self.max_iterations:
            self.state.iteration += 1
            logger.info(f"\n{'='*60}")
            logger.info(f"ITERATION {self.state.iteration}")
            logger.info(f"{'='*60}")

            # Phase 1: Narrative
            narrative = self.phase1_narrative(evidence_description)
            print(f"\n--- NARRATIVE (Iteration {self.state.iteration}) ---")
            print(narrative[:2000])

            # Phase 2: Hypotheses
            new_hypotheses = self.phase2_hypotheses()
            if not new_hypotheses:
                logger.info("No new hypotheses generated. Investigation may be complete.")
                break

            print(f"\n--- HYPOTHESES ---")
            for h in new_hypotheses:
                print(f"  [{h.id}] {h.description} (confidence: {h.confidence})")

            # Phase 3: Investigate each hypothesis INDEPENDENTLY
            iteration_results = []
            for hypothesis in new_hypotheses:
                if hypothesis.confidence < self.discard_threshold:
                    logger.info(f"  Skipping {hypothesis.id} - below confidence threshold")
                    hypothesis.status = "disproved"
                    continue

                result = self.phase3_investigate(hypothesis)
                iteration_results.append({
                    "hypothesis": hypothesis.description,
                    "result": result,
                })

                print(f"\n  [{hypothesis.id}] Verdict: {result.get('verdict', 'unknown')} "
                      f"(confidence: {result.get('confidence_after', '?')})")

            # Phase 4: Feedback
            feedback_raw = self.phase4_feedback(iteration_results)
            feedback = json.loads(feedback_raw)

            print(f"\n--- FEEDBACK ---")
            print(f"  Root cause reached: {feedback.get('root_cause_reached', False)}")
            if feedback.get('root_cause'):
                print(f"  ROOT CAUSE: {feedback['root_cause']}")
            print(f"  Next priority: {feedback.get('next_priority', 'N/A')}")

            # Check if investigation is complete
            if feedback.get("investigation_complete") or feedback.get("root_cause_reached"):
                conf = feedback.get("confidence_in_root_cause", 0)
                if conf >= self.confidence_threshold:
                    self.state.root_cause = feedback.get("root_cause", "")
                    logger.info(f"ROOT CAUSE IDENTIFIED: {self.state.root_cause}")
                    break

        # Generate final report
        report = self._generate_report()
        self.audit.save_report()
        return report

    def _generate_report(self) -> dict:
        """Generate the final investigation report."""
        report = {
            "session_id": self.audit.session_id,
            "total_iterations": self.state.iteration,
            "root_cause": self.state.root_cause,
            "confirmed_findings": self.state.confirmed_findings,
            "disproved_assumptions": self.state.disproved_assumptions,
            "narrative": self.state.narrative,
            "hypotheses": [
                {
                    "id": h.id,
                    "description": h.description,
                    "mitre_technique": h.mitre_technique,
                    "confidence": h.confidence,
                    "status": h.status,
                }
                for h in self.state.hypotheses
            ],
            "evidence_sources": self.state.evidence_sources,
            "llm_stats": self.llm.stats,
            "audit_log": str(self.audit._log_file),
        }

        report_path = self.audit.log_dir / f"investigation_{self.audit.session_id}.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        logger.info(f"Investigation report saved to {report_path}")

        return report


def run_investigation(
    evidence_description: str,
    evidence_paths: list[str] | None = None,
    config_path: str = "config.yaml",
) -> dict:
    """Convenience function to run a full IABF investigation."""
    agent = IABFAgent(config_path=config_path)
    return agent.investigate(evidence_description, evidence_paths)
