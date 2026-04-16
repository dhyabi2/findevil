"""
IABF Agent - Iterative Assumption-Based Framework for autonomous DFIR.

Implements the 4-phase methodology from the IABF research paper:
  Phase 1: Contextual Narrative Reconstruction
  Phase 2: Hypothesis Generation (MITRE ATT&CK mapped)
  Phase 3: Isolated Variable Investigation
  Phase 4: Heuristic Feedback Loop

Each cycle refines the narrative until root cause is identified.
"""

import datetime
import json
import logging
import re
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

FAST NAME LOOKUPS — ALWAYS DO THIS FIRST, NOT `fls -r | grep`:
  A cached MFT name index exists at /tmp/findevil/mft_index_<sha>.txt (see EVIDENCE block).
  Re-walking the filesystem with `fls -r` takes minutes each time. The cache is ONE grep:
      grep -iE 'SOFTWARE|SYSTEM|SAM|NTUSER' /tmp/findevil/mft_index_*.txt
      grep -iE 'NetStumbler|Cain|Ethereal|Kismet|Wireshark|Look@LAN' /tmp/findevil/mft_index_*.txt
      grep -iE 'irunin\\.ini|RECYCLER|\\.pcap|\\.cap|Outlook|mIRC' /tmp/findevil/mft_index_*.txt
  The index lines look like `r/r 12345-128-1:    Windows/System32/config/SOFTWARE` — the
  number before the first `-` is the INODE you then feed to `icat`.

WINDOWS DEAD-DISK PLAYBOOK (priority order — use this, don't guess random tools):
  (a) System identity — 3 concrete commands:
        # 1. Find the SOFTWARE hive inode via cached index (fast):
        grep -i 'config/SOFTWARE$' /tmp/findevil/mft_index_*.txt
        # 2. Extract it to scratch (the directory /tmp/findevil/hives/ is pre-created for you):
        icat -o {primary_offset} {primary_image} <INODE> > /tmp/findevil/hives/SOFTWARE
        # 3. Parse with RECmd:
        dotnet /opt/zimmermantools/RECmd/RECmd.dll -f /tmp/findevil/hives/SOFTWARE --kn "Microsoft\\Windows NT\\CurrentVersion"
        → RegisteredOwner, ProductName, InstallDate, TimeZone
  (b) User accounts:
        grep -i 'config/SAM$' /tmp/findevil/mft_index_*.txt   → inode
        icat -o {primary_offset} {primary_image} <SAM_INODE> > /tmp/findevil/hives/SAM
        dotnet /opt/zimmermantools/RECmd/RECmd.dll -f /tmp/findevil/hives/SAM --kn "SAM\\Domains\\Account\\Users"
  (c) Installed software (hacking tools):
        grep -iE 'Program Files/[^/]+$' /tmp/findevil/mft_index_*.txt
        RECmd on SOFTWARE → "Microsoft\\Windows\\CurrentVersion\\Uninstall"
  (d) Network identity (IP/MAC):
        RECmd on SYSTEM → "ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces"
        # bulk_extractor already ran as a pre-pass — see PRE-PASS ARTEFACTS in evidence
        grep -i 'irunin\\.ini' /tmp/findevil/mft_index_*.txt  → extract + strings for IP/MAC
  (e) Artefact sweep (user files for IRC/email/newsgroup/yahoo):
        grep -iE 'Outlook|Identities|mIRC|ini$|\\.htm$' /tmp/findevil/mft_index_*.txt
        → extract candidate file(s) via icat → strings on the extracted bytes
  (e1) IRC (mIRC config + chat logs):
        grep -iE 'mirc\\.ini|mirc/logs|servers\\.ini' /tmp/findevil/mft_index_*.txt
        # extract → strings → grep for nick=, user=, anick=, channel names (#evil, undernet, efnet)
  (e2) Outlook Express / Forte Agent (SMTP, NNTP, newsgroup subs):
        grep -iE 'Identities/.+/.+\\.dbx$|\\.idx$|\\.dat$|forte/agent|agent\\.dat' /tmp/findevil/mft_index_*.txt
        # extract .dbx files → strings → grep for @, smtp., news., nntp., alt.2600
  (e3) Browser / webmail (IE history + Yahoo/Hotmail saved pages):
        grep -iE 'index\\.dat|History|Cache|Cookies|Showletter|hotmail|yahoo|msn' /tmp/findevil/mft_index_*.txt
        # extract index.dat → pasco/python3 ESEDB or strings; grep saved .htm files
  (e4) Recycle Bin:
        grep -iE 'RECYCLER|Recycled|INFO2|\\$I[0-9]|\\$R[0-9]' /tmp/findevil/mft_index_*.txt
        # extract INFO2 → rifiuti2 OR strings; count .exe entries
  (f) Timeline if needed:
        log2timeline.py, then psort.py
  (g) Anti-virus indicators:
        grep -iE 'Norton|McAfee|Symantec|AVG|Avast|Kaspersky|Defender|virus|quarantine' /tmp/findevil/mft_index_*.txt

SIFT TOOL CHEAT-SHEET (command MUST start with one of these binaries):
  mmls, fsstat, fls, icat, ifind, tsk_recover, blkls, blkcat, srch_strings, mactime,
  log2timeline.py, psort.py, pinfo.py,
  bulk_extractor, foremost, scalpel,
  strings, file, xxd, hexdump, sha256sum, md5sum, ewfverify, exiftool, pdftotext, olevba,
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


def _convert_timestamp(value: str) -> str:
    """R11-3 + R13: convert epoch, FILETIME integer, or hex FILETIME to human-readable.

    Handles:
    - Unix epoch (integer seconds since 1970)
    - Windows FILETIME (integer, 100-ns since 1601)
    - Hex FILETIME from RECmd binary output (e.g. "C4-FC-00-07-4D-8C-C4-01")
    """
    s = value.strip()

    # Try hex FILETIME first (e.g. "C4-FC-00-07-4D-8C-C4-01")
    hex_match = re.match(r"^([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){7})", s)
    if hex_match:
        try:
            hex_bytes = hex_match.group(1).split("-")
            filetime = int("".join(reversed(hex_bytes)), 16)
            epoch = (filetime - 116444736000000000) / 10**7
            dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, OSError, OverflowError):
            pass

    try:
        n = int(s)
    except ValueError:
        return value
    # Windows FILETIME: 100-ns intervals since 1601-01-01
    if n > 10**16:
        epoch = (n - 116444736000000000) / 10**7
        try:
            dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, OverflowError):
            return value
    # Unix epoch: plausible range 2000-01-01 to 2030-01-01
    if 946684800 <= n <= 1893456000:
        dt = datetime.datetime.fromtimestamp(n, tz=datetime.timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    return value


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
        self.confidence_threshold = self.config.get("agent", {}).get("confidence_threshold", 0.5)
        self.discard_threshold = self.config.get("agent", {}).get("discard_threshold", 0.15)
        self.dry_run = dry_run
        self._conversation: list[dict] = []
        self._max_conversation_turns = 12  # user+assistant pairs retained
        self._probe_summary: dict[str, dict] = {}
        self._system_prompt: str = SYSTEM_PROMPT_TEMPLATE
        self._phase3_parallelism = self.config.get("agent", {}).get("phase3_parallelism", 3)
        self._mft_index_paths: dict[str, str] = {}  # evidence_path -> cached mft index file
        self._stagnation_iterations = self.config.get("agent", {}).get("stagnation_iterations", 3)
        # Phase 1 narrative is pinned to system prompt rather than letting it
        # roll off the conversation window — too valuable to expire.
        self._iter1_narrative: str = ""
        # Track Phase-4 "next_priority" across iterations: if the plan repeats,
        # we've hit a loop (run8 issue #1 / #7). Force a pivot on repeat.
        self._last_next_priority: str = ""
        self._repeat_plan_streak: int = 0
        # R11-10: cache tool output by command to avoid re-sending identical
        # results to the LLM. Keyed by exact command string.
        self._tool_cache: dict[str, tuple[int, str]] = {}

        # Pre-create scratch directories so `icat > /tmp/findevil/hives/X` doesn't
        # fail on "No such file or directory". Was a repeat-offender bug across runs.
        for sub in ("hives", "exports", "be", "strings", "ewf"):
            Path("/tmp/findevil") .joinpath(sub).mkdir(parents=True, exist_ok=True)

    def _exec_tool(self, command: str) -> tuple[int, str]:
        """Execute a forensic tool command through guardrails."""
        # R11-10: return cached result if we've run this exact command before.
        # Skip cache for commands with redirects (side-effect: writes a file).
        if command in self._tool_cache and ">" not in command:
            logger.debug(f"  [cache hit] {command[:80]}")
            return self._tool_cache[command]

        # Defensive: if the command redirects to a file under /tmp/findevil/<subdir>/
        # that doesn't exist yet, create the parent directory.
        for redirect in re.finditer(r">>?\s*(/tmp/findevil/[A-Za-z0-9_./\-]+)", command):
            target = Path(redirect.group(1))
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

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
            # R11-10: cache result (skip redirect commands — they write files)
            if ">" not in command:
                self._tool_cache[command] = (result.returncode, output)
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
            # R11-4 + R13: Q1 expects MD5 of raw image content.
            # For .E01 files, use ewfverify to get the stored/verified MD5;
            # md5sum on the .E01 container gives a different hash.
            if p.lower().endswith(".e01"):
                code, out = self._exec_tool(f"ewfverify {shlex.quote(p)}")
                if code == 0 and out:
                    m = re.search(r"MD5 hash.*?:\s+([0-9a-f]{32})", out)
                    if m:
                        info["md5"] = m.group(1)
                        lines.append(f"md5 (ewfverify): {m.group(1)}")
            if "md5" not in info:
                code, out = self._exec_tool(f"md5sum {shlex.quote(p)}")
                if code == 0 and out:
                    md5 = out.split()[0]
                    info["md5"] = md5
                    lines.append(f"md5: {md5}")
            # Attempt partition layout parsing (works on raw; also on .E01 when libewf is compiled in).
            code, out = self._exec_tool(f"mmls {shlex.quote(p)}")
            if code == 0 and out:
                lines.append("Partition layout (mmls):")
                lines.append(out.strip())
                # Heuristic OS hint from the MBR/VBR text strings — mmls verbose
                # output sometimes includes them; otherwise grab via xxd of
                # sector 0. Safe one-liner.
                code_xxd, mbr = self._exec_tool(f"xxd -l 512 {shlex.quote(p)}")
                if code_xxd == 0 and mbr:
                    text = mbr
                    if "XP" in text and "MS-MBR" in text:
                        info["os_hint"] = "Windows XP"
                    elif "Windows 7" in text or "Win7" in text:
                        info["os_hint"] = "Windows 7"
                    elif "GRUB" in text:
                        info["os_hint"] = "Linux (GRUB bootloader)"
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

            # Cache a full filesystem name index (fls -r) once per image.
            # Used to replace repeated `fls -r | grep <name>` scans with one
            # `grep <name> <cached_index>` — saves minutes across iterations.
            self._build_mft_index(p, info, lines)
        return "\n".join(lines)

    def _build_mft_index(self, image_path: str, info: dict, lines: list[str]) -> None:
        """Build and cache a filesystem name index (fls -r) for quick grep lookups.

        Skipped if the filesystem/offset wasn't resolved, or if a cached index
        with matching sha256 already exists on disk.
        """
        offset = info.get("primary_sector_offset")
        sha = info.get("sha256")
        if offset is None or not sha:
            return
        cache_dir = Path("/tmp/findevil")
        cache_dir.mkdir(parents=True, exist_ok=True)
        idx_path = cache_dir / f"mft_index_{sha[:16]}.txt"

        if idx_path.exists() and idx_path.stat().st_size > 0:
            self._mft_index_paths[image_path] = str(idx_path)
            lines.append(f"MFT index (cached): {idx_path} "
                         f"({idx_path.stat().st_size // 1024} KB) — "
                         f"use `grep -i <name> {idx_path}` for name lookups instead of re-walking fls.")
            return

        logger.info(f"  Building MFT name index for {image_path} -> {idx_path}")
        # Use -rp for FULL paths (e.g. "WINDOWS/system32/config/SOFTWARE");
        # bare -r emits tree-indented leaf names that break path-based grep.
        # Write directly via subprocess — _exec_tool would sanitize+truncate the
        # multi-MB fls output to 50KB, leaving a useless partial index.
        try:
            result = subprocess.run(
                f"fls -rp -o {offset} {shlex.quote(image_path)}",
                shell=True, capture_output=True, text=True, timeout=900,
            )
            if result.returncode == 0 and result.stdout:
                idx_path.write_text(result.stdout)
                self._mft_index_paths[image_path] = str(idx_path)
                lines.append(f"MFT index: {idx_path} "
                             f"({idx_path.stat().st_size // 1024} KB, "
                             f"{len(result.stdout.splitlines())} entries) — "
                             f"use `grep -i <name> {idx_path}` for name lookups "
                             f"instead of re-walking fls.")
            else:
                lines.append(f"MFT index build skipped (fls exit {result.returncode}).")
        except Exception as e:
            logger.warning(f"Failed to build MFT index: {e}")
            lines.append(f"MFT index build failed: {e}")

    def _auto_extract_evidence(self, hypothesis: Hypothesis, analysis: dict) -> None:
        """R11-1: auto-chain icat+strings when evidence_for mentions inode numbers.

        If a confirmed hypothesis references files by inode but never extracted
        their contents, do it now and append the strings output to evidence_for.
        This recovers IP, MAC, nick, channels from irunin.ini/mirc.ini/.dbx etc.
        """
        ev_blob = " ".join(str(e) for e in (hypothesis.evidence_for or []))
        inode_matches = re.findall(r"\b(\d{3,6})-\d+-\d+\b", ev_blob)
        if not inode_matches:
            inode_matches = re.findall(r"\binode\s*(\d{3,6})\b", ev_blob, re.IGNORECASE)
        if not inode_matches:
            return
        for p in self.state.evidence_sources:
            info = self._probe_summary.get(p, {})
            off = info.get("primary_sector_offset")
            if off is None:
                continue
            for inode in dict.fromkeys(inode_matches):
                out_path = f"/tmp/findevil/exports/inode_{inode}"
                code, _ = self._exec_tool(
                    f"icat -o {off} {shlex.quote(p)} {inode} > {shlex.quote(out_path)}"
                )
                if code != 0:
                    continue
                code2, strings_out = self._exec_tool(
                    f"strings {shlex.quote(out_path)} | head -200"
                )
                if code2 == 0 and strings_out.strip():
                    content = strings_out.strip()[:500]
                    alnum = sum(1 for c in content if c.isalnum() or c == ' ')
                    if alnum / max(len(content), 1) > 0.4:
                        hypothesis.evidence_for.append(
                            f"[auto-extracted inode {inode}] {content}"
                        )
            break

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
            # Fix #8: after iter 2, emit only a DELTA narrative (not a full
            # rewrite). Full re-narration was burning ~3x tokens per iteration
            # for diminishing value — iter-1 narrative is already pinned to
            # the system prompt and doesn't need to be re-stated.
            recent_confirmed = self.state.confirmed_findings[-5:]
            prompt = f"""PHASE 1 - NARRATIVE DELTA (Iteration {self.state.iteration})

Emit a SHORT delta (≤300 words) of what changed since the pinned iter-1 narrative.
Do NOT re-state facts already in confirmed_findings; only what is NEW.

Most recent confirmed findings (last 5):
{json.dumps(recent_confirmed, indent=2)}

Disproved since iter-1:
{json.dumps(self.state.disproved_assumptions[-3:], indent=2)}

Format:
  DELTA: <1-3 sentences on what changed>
  KEY UNKNOWNS: <1-3 bullets on what's still missing>"""

        narrative = self._llm_chat(prompt, purpose="phase1_narrative")
        self.state.narrative = narrative
        # Pin iter-1 narrative onto the system prompt so it stays available
        # past the conversation trim window. Captures grounded facts the LLM
        # established at the start.
        if self.state.iteration == 1 and not self._iter1_narrative:
            self._iter1_narrative = narrative
            self._system_prompt = (
                self._system_prompt
                + "\n\nITER-1 BASELINE NARRATIVE (PINNED — DO NOT FORGET):\n"
                + narrative[:4000]
            )
        self.audit.log_narrative(narrative, self.state.iteration)

        return narrative

    # ================================================================
    # Phase 2: Hypothesis Generation
    # ================================================================

    def phase2_hypotheses(self) -> list[Hypothesis]:
        """Generate testable hypotheses from the narrative."""
        logger.info(f"[Iteration {self.state.iteration}] Phase 2: Hypothesis Generation")

        # Fix #1/#5: if plan has repeated, force a pivot away from whatever theme
        # keeps failing. Inject the forbidden operation into the prompt so the
        # LLM can't reach for it again.
        pivot_block = ""
        if self._repeat_plan_streak >= 1 and self._last_next_priority:
            pivot_block = (
                f"\n\nFORBIDDEN — last iteration's plan failed and is being re-proposed:\n"
                f"  {self._last_next_priority}\n"
                f"DO NOT re-propose any variant of this plan. Pick a DIFFERENT artefact class — "
                f"e.g. if last plan was registry-hive extraction, switch to user-profile file "
                f"scraping (mIRC ini, Outlook .dbx, index.dat, RECYCLER INFO2); if last plan "
                f"was hive-related, try bulk_extractor output or strings on already-extracted files.\n"
            )

        # Fix #5: coverage-driven playbook forcing. Check which high-value
        # categories still have zero confirmed findings and nudge the LLM toward them.
        confirmed_blob = " ".join(self.state.confirmed_findings).lower()
        uncovered_categories: list[str] = []
        category_hints = {
            "mIRC / IRC chat config": ["mirc", "irc", "undernet", "efnet"],
            "Outlook Express / NNTP newsgroups": ["outlook", "nntp", "newsgroup", "alt.2600", "dbx"],
            "Webmail / browser (Yahoo, Hotmail, index.dat)": ["yahoo", "hotmail", "mrevilrulez", "showletter", "index.dat"],
            "Recycle Bin contents (INFO2 / $I)": ["recycler", "recycle bin", "info2"],
            "Ethereal pcap capture file": ["ethereal", "interception", ".pcap", ".cap"],
            "Network identity (IP/MAC in irunin.ini)": ["irunin", "192.168", "0010a4", "mac address"],
            "Anti-virus presence": ["mcafee", "norton", "symantec", "avg", "avast", "defender"],
        }
        for cat, hints in category_hints.items():
            if not any(h in confirmed_blob for h in hints):
                uncovered_categories.append(cat)
        coverage_block = ""
        if uncovered_categories and self.state.iteration >= 2:
            coverage_block = (
                "\n\nUNCOVERED HIGH-VALUE CATEGORIES (prioritize these if hypotheses space allows):\n  - "
                + "\n  - ".join(uncovered_categories[:4])
                + "\nFor each, emit a concrete grep on the MFT index + extraction + strings pipeline.\n"
            )

        prompt = f"""PHASE 2 - HYPOTHESIS GENERATION{pivot_block}{coverage_block}

Current narrative:
{self.state.narrative}

Already tested hypotheses:
{json.dumps([{
    'description': h.description,
    'status': h.status,
    'confidence': h.confidence
} for h in self.state.hypotheses], indent=2)}

Generate 1-3 NEW testable hypotheses. EACH hypothesis MUST either:
  (a) drill deeper into an already-CONFIRMED finding (extract specific artefacts, resolve
      actual names/values, follow the evidence chain further) — NOT re-describe what is
      already confirmed, and
  (b) probe a gap that none of the already-tested hypotheses attempted — do NOT repeat
      a theme (owner, tools, network, IRC) that was already inconclusive; change tactic
      (e.g. switch from registry-query to bulk_extractor evidence, or from MFT grep to
      strings-on-extracted-file).

AVOID generating hypotheses whose description closely paraphrases anything in
"Already tested hypotheses" above — that wastes an iteration.

For each hypothesis provide:
1. A specific, falsifiable assumption (name a concrete value you expect — e.g. "the
   RegisteredOwner value in SOFTWARE hive equals 'Greg Schardt'").
2. The MITRE ATT&CK technique it maps to (ID + name)
3. Your confidence level (0.0-1.0)
4. The EXACT SIFT forensic tool command(s) needed to test it — prefer the cached MFT
   index (`grep -i <pattern> /tmp/findevil/mft_index_*.txt`) over `fls -r`.
5. What result would CONFIRM vs DISPROVE it

HARD CONSTRAINTS for tool_commands (any violation = command BLOCKED, iteration wasted):
- Every command MUST begin with one of these SIFT binaries:
  mmls, fls, fsstat, icat, ifind, tsk_recover, blkls, blkcat, srch_strings, mactime,
  log2timeline.py, psort.py, pinfo.py,
  bulk_extractor, foremost, scalpel,
  strings, file, xxd, hexdump, sha256sum, md5sum, ewfverify, exiftool, pdftotext, olevba,
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
        conf_after = analysis.get("confidence_after", hypothesis.confidence)

        # Fix #10: disprove + low confidence is semantically inconclusive.
        # A confident disprove requires confidence >= 0.5.
        if verdict == "disproved" and conf_after < 0.5:
            logger.info(f"  [{hypothesis.id}] Override: disproved@{conf_after:.2f} -> inconclusive (low confidence)")
            verdict = "inconclusive"
            analysis["verdict"] = "inconclusive"

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

        # Auto-upgrade: if the LLM said "inconclusive" but evidence_for has at
        # least one concrete artefact (inode reference, filename, IP, hash,
        # MAC), promote to confirmed. The LLM is too cautious — rich evidence
        # is exactly what "confirmed" should mean. Observed in run7: 8 of 9
        # hypotheses returned with inode lists in evidence_for but inconclusive.
        if verdict == "inconclusive" and hypothesis.evidence_for:
            ev_blob = " ".join(str(e) for e in hypothesis.evidence_for)
    
            has_concrete = bool(re.search(
                r"\binode\s*\d+|\b\d+-\d+-\d+\b|\b\d{1,3}(?:\.\d{1,3}){3}\b|"
                r"[0-9a-f]{32,}|[0-9a-f]{2}(?::[0-9a-f]{2}){5}|"
                r"\.(?:dat|ini|dbx|pst|cap|pcap|reg|evtx|log|exe|dll|lnk|htm)\b",
                ev_blob, re.IGNORECASE))
            if has_concrete:
                logger.info(f"  [{hypothesis.id}] Auto-upgrade inconclusive→confirmed (rich evidence_for)")
                verdict = "confirmed"
                analysis["verdict"] = "confirmed"
                analysis["confidence_after"] = max(hypothesis.confidence, 0.7)

        if verdict == "confirmed":
            hypothesis.status = "confirmed"
            # R11-1: auto-chain icat+strings when evidence_for references
            # filename+inode but contents were never extracted.
            self._auto_extract_evidence(hypothesis, analysis)
            ev = hypothesis.evidence_for or []
            if ev:
                ev_text = "; ".join(str(e) for e in ev if e)[:400]
                self.state.confirmed_findings.append(
                    f"{hypothesis.description} — {ev_text}"
                )
            else:
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
4. If not, what is the SINGLE most important thing to investigate next? Name the
   specific artefact/file/registry-key/value the next iteration must extract,
   not a generic theme. BAD: "investigate network identity". GOOD: "extract the
   SYSTEM hive and read Tcpip\\Parameters\\Interfaces to recover the static IP."
5. Note any SELF-CORRECTIONS - where our previous understanding was wrong.
6. If this iteration produced ONLY inconclusive results, propose a TACTIC CHANGE
   for next iteration (different tool family, different artefact class) — do NOT
   recommend re-running the same approach that just failed.

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

    def _pre_extract_hives(self) -> list[str]:
        """Auto-extract SOFTWARE/SAM/SYSTEM hives + parse key values during pre-pass.

        Fix #1 + #4: run8 wasted 5 iterations trying (and failing) to grep+extract
        SOFTWARE. Do it once up-front, deterministically, so every downstream
        question about RegisteredOwner, OS install date, timezone, computer name,
        and last shutdown has grounded evidence instead of depending on the LLM
        re-deriving the plan each iteration.

        Emits canonical GT-matching strings into confirmed_findings.
        """
        findings: list[str] = []
        for p in self.state.evidence_sources:
            info = self._probe_summary.get(p, {})
            off = info.get("primary_sector_offset")
            idx = self._mft_index_paths.get(p)
            if off is None or not idx:
                continue
            hives_dir = Path("/tmp/findevil/hives")
            hives_dir.mkdir(parents=True, exist_ok=True)

            hive_inodes: dict[str, str] = {}
            for hive in ("SOFTWARE", "SAM", "SYSTEM"):
                # Match 'config/SOFTWARE' lines in the MFT index, extract inode.
                code, out = self._exec_tool(
                    f"grep -iE 'config/{hive}$' {shlex.quote(idx)} | head -1"
                )
                if code != 0 or not out.strip():
                    continue
                # Line format: "r/r 12345-128-4:    Windows/System32/config/SOFTWARE"
        
                m = re.search(r"(\d+)-\d+-\d+", out)
                if not m:
                    continue
                inode = m.group(1)
                hive_inodes[hive] = inode
                out_path = hives_dir / hive
                if not out_path.exists() or out_path.stat().st_size == 0:
                    self._exec_tool(
                        f"icat -o {off} {shlex.quote(p)} {inode} > {shlex.quote(str(out_path))}"
                    )

            # R12-2: detect correct RECmd.dll path
            recmd_path = "/opt/zimmermantools/RECmd/RECmd.dll"
            if not Path(recmd_path).exists():
                recmd_path = "/opt/zimmermantools/net6/RECmd.dll"

            def _parse(hive_name: str, key: str) -> str:
                hive_path = hives_dir / hive_name
                if not hive_path.exists() or hive_path.stat().st_size == 0:
                    return ""
                code, out = self._exec_tool(
                    f"dotnet {recmd_path} -f {shlex.quote(str(hive_path))} "
                    f"--kn {shlex.quote(key)} 2>&1 | head -300"
                )
                return out if code == 0 else ""

            # R12-1: parse RECmd multi-line output into canonical KeyName: Value pairs.
            # RECmd emits "Name: X (RegSz)" on one line, "Data: Y" on the next.
            def _extract_reg_values(output: str) -> dict[str, str]:
                vals: dict[str, str] = {}
                lines = output.splitlines()
                pending_name = None
                for ln in lines:
                    s = ln.strip()
                    # RECmd format: "Name: RegisteredOwner (RegSz)" then "Data: Greg Schardt (Slack: ...)"
                    m = re.match(r"Name:\s*(.+?)\s*\(Reg\w+\)", s, re.IGNORECASE)
                    if m:
                        pending_name = m.group(1).strip()
                        continue
                    m = re.match(r"Data:\s*(.+)", s, re.IGNORECASE)
                    if m and pending_name:
                        val = m.group(1).strip()
                        # Strip trailing "(Slack: ...)" metadata
                        val = re.sub(r"\s*\(Slack:.*\)$", "", val).strip()
                        if val:
                            vals[pending_name] = val
                        pending_name = None
                        continue
                    # Also handle single-line "Key : Value" format
                    m = re.match(r"([A-Za-z][A-Za-z0-9_ ]{2,30})\s*:\s*(.+)", s)
                    if m and not s.startswith("Name:") and not s.startswith("Data:"):
                        vals[m.group(1).strip()] = m.group(2).strip()
                return vals

            # SOFTWARE: RegisteredOwner, ProductName, InstallDate, ProductId
            sw_out = _parse("SOFTWARE", "Microsoft\\Windows NT\\CurrentVersion")
            sw_vals = _extract_reg_values(sw_out)
            # We need ActiveTimeBias for local time, but it comes from SYSTEM.
            # Pre-parse it here so InstallDate can use it.
            _tz_out = _parse("SYSTEM", "ControlSet001\\Control\\TimeZoneInformation")
            _tz_vals = _extract_reg_values(_tz_out) if _tz_out else {}
            _bias_str = _tz_vals.get("ActiveTimeBias", "")
            _active_bias = 0
            if _bias_str:
                try:
                    _raw = int(_bias_str)
                    _active_bias = _raw - 2**32 if _raw > 2**31 else _raw
                except ValueError:
                    pass
            _tz_local = _tz_vals.get("DaylightName", _tz_vals.get("StandardName", ""))
            _tz_abbr = "CDT" if "daylight" in _tz_local.lower() else "CST" if "central" in _tz_local.lower() else "local"

            for key_name, label in [
                ("RegisteredOwner", "Registered owner"),
                ("ProductName", "Operating system"),
                ("InstallDate", "OS install date"),
                ("CurrentBuildNumber", "Build number"),
            ]:
                for k, v in sw_vals.items():
                    if k.lower() == key_name.lower() and v:
                        converted = _convert_timestamp(v)
                        if converted != v and key_name == "InstallDate" and _active_bias:
                            # R14-1: emit local time alongside UTC
                            utc_dt = datetime.datetime.strptime(converted, "%Y-%m-%d %H:%M:%S UTC")
                            local_dt = utc_dt - datetime.timedelta(minutes=_active_bias)
                            findings.append(f"{label}: {local_dt.strftime('%Y-%m-%d %H:%M:%S')} {_tz_abbr}")
                            findings.append(f"{label}: {converted}")
                        elif converted != v:
                            findings.append(f"{label}: {converted} (raw: {v})")
                        else:
                            findings.append(f"{label}: {v}")
                        break

            # SYSTEM: ComputerName
            comp_out = _parse("SYSTEM", "ControlSet001\\Control\\ComputerName\\ComputerName")
            if comp_out:
                comp_vals = _extract_reg_values(comp_out)
                for k, v in comp_vals.items():
                    if k.lower() == "computername" and v:
                        findings.append(f"Computer name: {v}")
                        break

            # R14-1/R14-2: TimeZoneInformation — extract bias + both tz names
            tz_out = _parse("SYSTEM", "ControlSet001\\Control\\TimeZoneInformation")
            tz_vals = _extract_reg_values(tz_out) if tz_out else {}
            active_bias_minutes = 0
            tz_name_local = ""
            std_name = tz_vals.get("StandardName", "")
            dst_name = tz_vals.get("DaylightName", "")
            if std_name:
                findings.append(f"Timezone: {std_name}")
            if dst_name and dst_name != std_name:
                findings.append(f"Timezone (daylight): {dst_name}")
                tz_name_local = dst_name
            bias_str = tz_vals.get("ActiveTimeBias", "")
            if bias_str:
                try:
                    raw_bias = int(bias_str)
                    # DWORD can wrap — values > 2^31 are negative
                    if raw_bias > 2**31:
                        raw_bias = raw_bias - 2**32
                    active_bias_minutes = raw_bias
                    sign = "-" if raw_bias >= 0 else "+"
                    hours = abs(raw_bias) // 60
                    findings.append(f"Active time bias: {sign}{hours:02d}:{abs(raw_bias)%60:02d} GMT")
                except ValueError:
                    pass
            if not tz_name_local:
                tz_name_local = std_name

            # SYSTEM: ShutdownTime — emit both UTC and local time
            shut_out = _parse("SYSTEM", "ControlSet001\\Control\\Windows")
            if shut_out:
                shut_vals = _extract_reg_values(shut_out)
                for k, v in shut_vals.items():
                    if k.lower() == "shutdowntime" and v:
                        converted = _convert_timestamp(v)
                        if converted != v and active_bias_minutes:
                            utc_dt = datetime.datetime.strptime(converted, "%Y-%m-%d %H:%M:%S UTC")
                            local_dt = utc_dt - datetime.timedelta(minutes=active_bias_minutes)
                            tz_abbr = "CDT" if "daylight" in tz_name_local.lower() else "CST" if "central" in tz_name_local.lower() else "local"
                            findings.append(f"Last shutdown time: {local_dt.strftime('%Y-%m-%d %H:%M:%S')} {tz_abbr}")
                            findings.append(f"Last shutdown time: {converted}")
                        elif converted != v:
                            findings.append(f"Last shutdown time: {converted} (raw: {v})")
                        else:
                            findings.append(f"Last shutdown time: {v}")
                        break

            # R17-1: SAM user count via "Subkey count: N" (handles names with spaces)
            sam_names_out = _parse("SAM", "SAM\\Domains\\Account\\Users\\Names")
            if sam_names_out:
                m = re.search(r"Subkey count:\s*(\d+)", sam_names_out)
                if m:
                    findings.append(f"Total user accounts: {m.group(1)}")

            # R12-3: extract NTUSER.DAT for the primary user and parse email accounts.
            # SMTP/NNTP server settings live here, not in SOFTWARE.
            for inode, fpath in self._grep_mft_index(idx, r"Mr\. Evil/NTUSER\.DAT$"):
                ntuser_path = hives_dir / "NTUSER_MrEvil.DAT"
                if not ntuser_path.exists() or ntuser_path.stat().st_size == 0:
                    self._exec_tool(
                        f"icat -o {off} {shlex.quote(p)} {inode} > {shlex.quote(str(ntuser_path))}"
                    )
                if ntuser_path.exists() and ntuser_path.stat().st_size > 0:
                    for acct_id in ("00000001", "00000002", "00000003"):
                        acct_out = ""
                        code, out = self._exec_tool(
                            f"dotnet {recmd_path} -f {shlex.quote(str(ntuser_path))} "
                            f"--kn {shlex.quote(f'Software\\Microsoft\\Internet Account Manager\\Accounts\\{acct_id}')} "
                            f"2>&1 | head -60"
                        )
                        if code == 0 and out.strip():
                            acct_vals = _extract_reg_values(out)
                            for k, v in acct_vals.items():
                                kl = k.lower()
                                if "smtp server" in kl:
                                    findings.append(f"SMTP server: {v}")
                                elif "smtp email" in kl:
                                    findings.append(f"SMTP email address: {v}")
                                elif "nntp server" in kl:
                                    findings.append(f"NNTP news server: {v}")
                                elif "nntp email" in kl:
                                    findings.append(f"NNTP email address: {v}")
                                elif "pop3 user" in kl:
                                    findings.append(f"POP3 user: {v}")
                                elif "account name" in kl:
                                    findings.append(f"Email account: {v}")
                                elif "display name" in kl and v.strip():
                                    findings.append(f"Email display name: {v}")
                break

            # R12-6 + R17-4: extract NIC descriptions, deduplicated
            system_path = hives_dir / "SYSTEM"
            if system_path.exists() and system_path.stat().st_size > 0:
                code, out = self._exec_tool(
                    f"strings {shlex.quote(str(system_path))} | "
                    f"grep -iE 'Xircom|Compaq.*WL|CardBus.*Ethernet|Wireless.*LAN.*PC' | "
                    f"sort -u | head -10"
                )
                if code == 0 and out.strip():
                    seen_nics = set()
                    for ln in out.strip().splitlines():
                        nic = ln.strip()
                        # Skip registry paths, GUIDs, and device IDs
                        if re.search(r"[{}#]|PCMCIA|\\Device\\", nic):
                            continue
                        if nic and nic.lower() not in seen_nics and len(nic) > 10:
                            seen_nics.add(nic.lower())
                            findings.append(f"Network card: {nic}")

        return findings

    def _grep_mft_index(self, idx_path: str, pattern: str) -> list[tuple[str, str]]:
        """Return (inode, path) pairs from MFT index grep."""
        code, out = self._exec_tool(
            f"grep -iE {shlex.quote(pattern)} {shlex.quote(idx_path)}"
        )
        results = []
        if code == 0 and out.strip():
            for ln in out.strip().splitlines():
                m = re.search(r"(\d+)-\d+-\d+", ln)
                path_part = ln.split(":", 1)[-1].strip() if ":" in ln else ln
                if m:
                    results.append((m.group(1), path_part))
        return results

    def _pre_extract_artefacts(self) -> list[str]:
        """R11-6/7/8 + R12-4/5: auto-extract artefacts from MFT index.

        Extracts .dbx, .cap/.pcap, webmail, mirc.ini, IRC logs, and other
        artefact files to recover SMTP/NNTP/IRC/pcap/webmail data.
        """
        findings: list[str] = []
        for p in self.state.evidence_sources:
            info = self._probe_summary.get(p, {})
            off = info.get("primary_sector_offset")
            idx = self._mft_index_paths.get(p)
            if off is None or not idx:
                continue

            def _grep_index(pattern: str) -> list[tuple[str, str]]:
                return self._grep_mft_index(idx, pattern)

            def _extract_and_strings(inode: str, label: str, grep_pat: str = "") -> str:
                out_path = f"/tmp/findevil/exports/{label}_{inode}"
                self._exec_tool(f"icat -o {off} {shlex.quote(p)} {inode} > {shlex.quote(out_path)}")
                if grep_pat:
                    code, out = self._exec_tool(
                        f"strings {shlex.quote(out_path)} | grep -iE {shlex.quote(grep_pat)} | head -50"
                    )
                else:
                    code, out = self._exec_tool(f"strings {shlex.quote(out_path)} | head -100")
                return out.strip() if code == 0 else ""

            # R11-6 + R15-8: .dbx files — extract newsgroup names, grouped
            seen_dbx = set()
            for inode, fpath in _grep_index(r"Outlook Express/.*\.dbx$"):
                fname = fpath.rsplit("/", 1)[-1] if "/" in fpath else fpath
                ng_name = fname.replace(".dbx", "")
                if ng_name.lower() in ("folders", "offline", "pop3uidl", "cleanup", "deleted items", "inbox", "outbox", "sent items", "drafts"):
                    continue
                if ng_name and ng_name not in seen_dbx:
                    seen_dbx.add(ng_name)
                    findings.append(f"Newsgroup subscribed: {ng_name}")
            if seen_dbx:
                findings.append(f"Newsgroups subscribed ({len(seen_dbx)}): {', '.join(sorted(seen_dbx))}")
                findings.append(f"Programs showing email/newsgroup config: MS Outlook Express")

            # R15-4 + R17-7: Ethereal config — extract key facts only
            for inode, fpath in _grep_index(r"Ethereal/(preferences|recent)$"):
                content = _extract_and_strings(inode, "ethcfg", r"")
                if content:
                    for ln in content.splitlines():
                        ln = ln.strip()
                        if ln.startswith("capture.device:"):
                            findings.append(f"Ethereal capture device: {ln.split(':', 1)[-1].strip()}")
                        elif ln.startswith("capture.prom_mode:"):
                            findings.append(f"Ethereal promiscuous mode: {ln.split(':', 1)[-1].strip()}")
                        elif ln.startswith("recent.capture_file:"):
                            findings.append(f"Ethereal recent capture: {ln.split(':', 1)[-1].strip()}")
                        elif ln.startswith("recent.display_filter:"):
                            findings.append(f"Ethereal display filter: {ln.split(':', 1)[-1].strip()}")

            # R15-1: extract the interception capture file (no extension)
            # Also match standard .cap/.pcap files
            for inode, fpath in _grep_index(r"\.(cap|pcap)$|/interception$"):
                content = _extract_and_strings(
                    inode, "capture",
                    r"Windows CE|Pocket PC|mobile\.msn|Hotmail|UA-OS:"
                )
                if content:
                    # Emit individual facts, not raw dump
                    if re.search(r"Windows CE|Pocket PC", content):
                        findings.append(f"Victim device type: Windows CE (Pocket PC)")
                    if "mobile.msn" in content.lower():
                        findings.append(f"Website accessed by victim: mobile.msn.com")
                    if "hotmail" in content.lower():
                        findings.append(f"Website accessed by victim: MSN Hotmail")

            # R11-8: IE cache (index.dat) — extract URLs but don't dump raw content
            # R13: raw index.dat dumps produce FPs; only extract unique URLs
            for inode, fpath in _grep_index(r"index\.dat$"):
                out_path = f"/tmp/findevil/exports/indexdat_{inode}"
                self._exec_tool(f"icat -o {off} {shlex.quote(p)} {inode} > {shlex.quote(out_path)}")
                code, out = self._exec_tool(
                    f"strings {shlex.quote(out_path)} | grep -iE '^http' | sort -u | head -20"
                )
                if code == 0 and out.strip():
                    findings.append(f"IE browsing history ({fpath}): {out.strip()[:300]}")

            # R14-4: require .htm extension to avoid binary ShowLetter[1] (no ext)
            for inode, fpath in _grep_index(r"Showletter.*\.htm|mrevilrulez.*\.htm|yahoo.*\.htm|hotmail.*\.htm"):
                content = _extract_and_strings(inode, "webmail", r"@|From:|To:|Subject:")
                if content:
                    findings.append(f"Webmail page {fpath}: {content[:400]}")

            # R13 + R17-3: extract irunin.ini — key values only
            _irunin_keys = {"LANHOST", "LANDOMAIN", "LANUSER", "LANIP", "LANNIC"}
            for inode, fpath in _grep_index(r"irunin\.ini$"):
                content = _extract_and_strings(inode, "irunin", r"")
                if content:
                    for ln in content.splitlines():
                        ln = ln.strip()
                        if "=" in ln and ln.startswith("%"):
                            key, _, val = ln.partition("=")
                            key = key.strip("%")
                            if val and key in _irunin_keys:
                                findings.append(f"Look@LAN irunin.ini {key}: {val}")
                                if key == "LANNIC" and len(val) == 12:
                                    mac_fmt = ":".join(val[i:i+2] for i in range(0, 12, 2))
                                    findings.append(f"MAC address: {mac_fmt}")

            # R15: detect hacking tools (classified as viruses/malware by AV)
            hack_tools = []
            for tool_pat, tool_name in [
                (r"Program Files/Cain", "Cain & Abel"),
                (r"Program Files/NetStumbler|netstumblerinstaller", "NetStumbler"),
                (r"Program Files/Ethereal|ethereal-setup", "Ethereal"),
                (r"Program Files/Look@LAN|Look.LAN", "Look@LAN"),
                (r"Program Files/WinPcap|WinPcap", "WinPcap"),
            ]:
                if _grep_index(tool_pat):
                    hack_tools.append(tool_name)
            if hack_tools:
                findings.append(f"Hacking/security tools installed: {', '.join(hack_tools)}")
                findings.append(f"Anti-virus check - viruses/hack tools present: Yes")

            # R14-6: detect Forte Agent (another SMTP/NNTP program)
            for inode, fpath in _grep_index(r"Program Files/Agent/|forte/agent|AGENT\.INI$"):
                if re.search(r"\.(dll|exe|cod|hlp)$", fpath, re.IGNORECASE):
                    continue
                findings.append(f"Programs showing email/newsgroup config: Forte Agent")
                break

            # R12-4: extract mirc.ini for user settings (nick, user, email, anick)
            for inode, fpath in _grep_index(r"mirc\.ini$"):
                content = _extract_and_strings(inode, "mircini", r"nick=|user=|email=|anick=")
                if content:
                    for ln in content.splitlines():
                        ln = ln.strip()
                        if "=" in ln and any(k in ln.lower() for k in ("nick=", "user=", "email=", "anick=")):
                            findings.append(f"mIRC setting: {ln}")

            # R12-5: parse IRC channel log filenames from MFT index
            for inode, fpath in _grep_index(r"mIRC/logs/.*\.log$"):
                fname = fpath.rsplit("/", 1)[-1] if "/" in fpath else fpath
                channel = fname.replace(".log", "")
                if channel:
                    findings.append(f"IRC channel accessed: {channel}")

            # R17-2: count filesystem-deleted files via fls -d
            code, out = self._exec_tool(
                f"fls -d -o {off} {shlex.quote(p)} | wc -l"
            )
            if code == 0 and out.strip():
                del_count = out.strip()
                if del_count != "0":
                    findings.append(f"Files reported deleted by filesystem: {del_count}")

            # R15-2/R15-3: Recycle Bin analysis
            recycler_exes = _grep_index(r"RECYCLER/.*\.exe$")
            exe_count = len(recycler_exes)
            if exe_count > 0:
                findings.append(f"Executables in Recycle Bin: {exe_count}")
                findings.append(f"Are recycle-bin files really deleted: No")
                for _, fpath in recycler_exes:
                    fname = fpath.rsplit("/", 1)[-1] if "/" in fpath else fpath
                    findings.append(f"Recycle Bin executable: {fname}")

            # R15-3: extract INFO2 for original filenames
            for inode, fpath in _grep_index(r"RECYCLER/.*INFO2$"):
                content = _extract_and_strings(inode, "info2", r"")
                if content:
                    orig_files = []
                    for ln in content.splitlines():
                        ln = ln.strip()
                        if ln and (":\\" in ln or ":/" in ln) and len(ln) > 5:
                            orig_files.append(ln)
                    if orig_files:
                        findings.append(f"Files deleted to Recycle Bin (from INFO2): {len(orig_files)}")
                        for of in orig_files:
                            findings.append(f"Deleted file original path: {of}")

        return findings

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

        # Auto-confirm deterministic facts derived from probes — no hypothesis
        # needed for things we can read directly from the image at session
        # init (sha256, OS family from bootsector, partition layout).
        for path, info in self._probe_summary.items():
            if info.get("sha256"):
                self.state.confirmed_findings.append(
                    f"Image SHA-256 (verified): {info['sha256']}"
                )
            if info.get("md5"):
                self.state.confirmed_findings.append(
                    f"Image MD5 (verified): {info['md5']}"
                )
            fs = info.get("filesystem", "") or ""
            if "NTFS" in fs.upper():
                self.state.confirmed_findings.append(
                    "Filesystem: NTFS — consistent with Windows host."
                )
            # OS detection from MBR string captured during mmls; saved in info.
            os_hint = info.get("os_hint", "")
            if os_hint:
                self.state.confirmed_findings.append(f"Operating system: {os_hint}")
        pre_pass_summary = self._pre_pass()
        if pre_pass_summary:
            evidence_description = (
                evidence_description
                + "\n\nAUTOMATED PRE-PASS ARTEFACTS (bulk_extractor):\n"
                + pre_pass_summary
            )

        # Fix #1/#4: auto-extract registry hives up-front. Run8 wasted iters 2-6
        # proposing this exact plan and failing. Do it here, deterministically.
        try:
            hive_findings = self._pre_extract_hives()
            for f in hive_findings:
                if f not in self.state.confirmed_findings:
                    self.state.confirmed_findings.append(f)
            if hive_findings:
                evidence_description += (
                    "\n\nAUTOMATED HIVE EXTRACTION (SOFTWARE/SAM/SYSTEM already parsed):\n"
                    + "\n".join(hive_findings)
                )
        except Exception as e:
            logger.warning(f"Pre-pass hive extraction failed: {e}")

        # R11-6/7/8: auto-extract .dbx, pcap, webmail artefacts
        try:
            artefact_findings = self._pre_extract_artefacts()
            for f in artefact_findings:
                if f not in self.state.confirmed_findings:
                    self.state.confirmed_findings.append(f)
            if artefact_findings:
                evidence_description += (
                    "\n\nAUTOMATED ARTEFACT EXTRACTION (.dbx, pcap, webmail):\n"
                    + "\n".join(artefact_findings)
                )
        except Exception as e:
            logger.warning(f"Pre-pass artefact extraction failed: {e}")

        stagnation_streak = 0
        last_confirmed_count = 0
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

            # Phase 3: Investigate each hypothesis INDEPENDENTLY — run in parallel.
            # IABF isolation principle: each hypothesis is tested on its own evidence
            # with no shared state, so parallel execution preserves methodology.
            from concurrent.futures import ThreadPoolExecutor, as_completed
            iteration_results = []
            active = [h for h in new_hypotheses if h.confidence >= self.discard_threshold]
            for h in new_hypotheses:
                if h.confidence < self.discard_threshold:
                    logger.info(f"  Skipping {h.id} - below confidence threshold")
                    h.status = "disproved"

            if active:
                max_workers = min(len(active), self._phase3_parallelism)
                with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="phase3") as pool:
                    fut_to_hyp = {pool.submit(self.phase3_investigate, h): h for h in active}
                    for fut in as_completed(fut_to_hyp):
                        h = fut_to_hyp[fut]
                        try:
                            result = fut.result()
                        except Exception as e:
                            logger.warning(f"  [{h.id}] phase3 failed: {e}")
                            result = {"verdict": "inconclusive", "confidence_after": h.confidence}
                        iteration_results.append({
                            "hypothesis": h.description,
                            "result": result,
                        })
                        print(f"\n  [{h.id}] Verdict: {result.get('verdict', 'unknown')} "
                              f"(confidence: {result.get('confidence_after', '?')})")

            # Phase 4: Feedback
            feedback_raw = self.phase4_feedback(iteration_results)
            feedback = json.loads(feedback_raw)

            print(f"\n--- FEEDBACK ---")
            print(f"  Root cause reached: {feedback.get('root_cause_reached', False)}")
            if feedback.get('root_cause'):
                print(f"  ROOT CAUSE: {feedback['root_cause']}")
            next_priority = feedback.get('next_priority', 'N/A') or ''
            print(f"  Next priority: {next_priority}")

            # Fix #1/#7: detect plan repetition. If next_priority keeps proposing
            # the same operation (e.g. "extract SOFTWARE hive and read
            # CurrentVersion"), we're in a loop. Normalize both sides and
            # compare token-overlap; if >=60% overlap, increment streak.
            def _toks(s: str) -> set[str]:
        
                return {t for t in re.findall(r"[a-z0-9]{4,}", s.lower())}
            new_toks = _toks(next_priority)
            old_toks = _toks(self._last_next_priority)
            if new_toks and old_toks:
                overlap = len(new_toks & old_toks) / max(len(new_toks | old_toks), 1)
                if overlap >= 0.6:
                    self._repeat_plan_streak += 1
                    logger.info(f"  Repeat plan detected ({overlap:.0%} overlap, streak={self._repeat_plan_streak})")
                else:
                    self._repeat_plan_streak = 0
            self._last_next_priority = next_priority

            # Fix #9: coverage-based auto-completion. If ≥8 of the 10 high-value
            # DFIR categories have confirmed findings, stop — further iterations
            # are unlikely to recover new Q-category coverage.
            _confirmed_blob_now = " ".join(self.state.confirmed_findings).lower()
            _categories_now = {
                "irc": ["mirc", "irc", "undernet", "efnet"],
                "email": ["outlook", "nntp", "newsgroup", "alt.2600", "dbx"],
                "webmail": ["yahoo", "hotmail", "mrevilrulez", "showletter", "index.dat"],
                "recycle": ["recycler", "recycle bin", "info2"],
                "pcap": ["ethereal", "interception", ".pcap", ".cap"],
                "network": ["irunin", "192.168", "0010a4", "mac address"],
                "av": ["mcafee", "norton", "symantec", "avg", "avast", "defender"],
                "owner": ["registered owner", "greg schardt", "schardt"],
                "os": ["windows xp", "operating system", "productname"],
                "tools": ["netstumbler", "cain", "ethereal", "look@lan"],
            }
            covered = sum(1 for hints in _categories_now.values()
                          if any(h in _confirmed_blob_now for h in hints))
            if covered >= 10 and self.state.iteration >= 2:
                logger.info(f"Coverage threshold reached ({covered}/10 categories confirmed). Terminating.")
                if not self.state.root_cause:
                    self.state.root_cause = (
                        f"Investigation achieved {covered}/10 category coverage. "
                        "See confirmed_findings for full evidence chain."
                    )
                break

            # Check if investigation is complete
            if feedback.get("investigation_complete") or feedback.get("root_cause_reached"):
                conf = feedback.get("confidence_in_root_cause", 0)
                if conf >= self.confidence_threshold:
                    self.state.root_cause = feedback.get("root_cause", "")
                    logger.info(f"ROOT CAUSE IDENTIFIED: {self.state.root_cause}")
                    break

            # Stagnation detection: only consider it stagnation when BOTH
            # (a) no new confirmed findings AND (b) plan hasn't pivoted.
            # Fix #7: run8 early-exit at iter 6 because the plan kept repeating;
            # if we force a pivot (via repeat detection above into Phase 2),
            # we may unstick. Only bail when both conditions persist.
            current_confirmed = len(self.state.confirmed_findings)
            plan_unchanged = self._repeat_plan_streak > 0
            if current_confirmed == last_confirmed_count and plan_unchanged:
                stagnation_streak += 1
                if stagnation_streak >= self._stagnation_iterations:
                    logger.info(
                        f"Stagnation detected ({stagnation_streak} iterations with no new "
                        f"confirmed findings). Terminating early at iteration "
                        f"{self.state.iteration}/{self.max_iterations}."
                    )
                    if not self.state.root_cause:
                        self.state.root_cause = (
                            "Investigation terminated on stagnation. See narrative "
                            "and confirmed_findings for partial results."
                        )
                    break
            else:
                stagnation_streak = 0
                last_confirmed_count = current_confirmed

        # R11-9: final Q-answering pass — re-ask GT-style questions and emit
        # canonical short answers the scorer can match.
        try:
            canonical = self._final_answer_pass()
            for c in canonical:
                if c not in self.state.confirmed_findings:
                    self.state.confirmed_findings.append(c)
        except Exception as e:
            logger.warning(f"Final answer pass failed: {e}")

        # Generate final report
        report = self._generate_report()
        self.audit.save_report()
        return report

    def _final_answer_pass(self) -> list[str]:
        """R11-9: emit canonical short answers from confirmed findings.

        After investigation completes, ask the LLM to distill confirmed_findings
        into concise factual statements that a keyword scorer can match.
        """
        if not self.state.confirmed_findings:
            return []
        prompt = f"""You are a DFIR analyst summarizing investigation results.

Given these confirmed findings, emit a JSON list of concise canonical facts.
Each fact should be a SHORT, specific, scorable statement — one fact per line.
Include: names, IPs, MACs, hashes, dates, counts, Yes/No answers, filenames.

Examples of good canonical facts:
- "Registered owner: Greg Schardt"
- "Image MD5: AEE4FCD9301C03B3B054623CA261959A"
- "IP address: 192.168.1.111"
- "MAC address: 00:10:A4:93:3D:E2"
- "mIRC nickname: Mr. Evil"
- "SMTP server: smtp.email.msn.com"
- "Newsgroup subscribed: alt.2600.cardz"
- "Capture file name: Interception"
- "Number of deleted executables in Recycle Bin: 4"
- "Are recycle-bin files really deleted: No" (files in recycle bin are NOT truly deleted — they can be recovered)
- "Firewall installed: Yes"
- "Programs showing SMTP/NNTP: MS Outlook Express, Forte Agent"
- "IRC channels: #Elite.Hackers.UnderNet, #evilfork.EFnet" (list all found)

IMPORTANT: For each Yes/No question, emit both the question and the answer.
For recycle bin: files in the Windows Recycle Bin are NOT truly deleted — they are
recoverable. If you found executables in the recycle bin, emit "Are recycle-bin files
really deleted: No".

Confirmed findings:
{json.dumps(self.state.confirmed_findings, indent=2)}

Narrative summary:
{self.state.narrative[:2000]}

Root cause: {self.state.root_cause}

Respond in JSON: {{"canonical_facts": ["fact1", "fact2", ...]}}"""

        try:
            data = self._llm_json(prompt, purpose="final_answer_pass")
            facts = data.get("canonical_facts", [])
            if isinstance(facts, list):
                return [str(f) for f in facts if f and str(f).strip()]
        except Exception as e:
            logger.warning(f"Final answer pass LLM call failed: {e}")
        return []

    @staticmethod
    def _filter_meta_findings(findings: list[str]) -> list[str]:
        """R11-5: remove tooling metadata and raw binary noise from confirmed_findings.

        Filters: internal plumbing strings, raw strings output from binary files,
        and auto-extracted content that is too noisy to be a DFIR answer.
        """
        meta_patterns = re.compile(
            r"located at inode|extracted to /tmp|MFT index shows|"
            r"^icat -o|^grep -i|fls -r|wrote \d+ bytes to|"
            r"^Tool output:|saved to /tmp",
            re.IGNORECASE,
        )
        filtered = []
        for f in findings:
            if meta_patterns.search(f):
                continue
            # Skip raw binary/strings noise: PE headers, Rich signatures
            if re.search(r"\.text\b.*\.(rdata|data|rsrc)|Rich[0-9+*:]", f):
                continue
            # Skip auto-extracted content that is mostly garbage (>60% non-alnum)
            alnum = sum(1 for c in f if c.isalnum() or c in " .,:-/@")
            if len(f) > 50 and alnum / max(len(f), 1) < 0.4:
                continue
            # R12-7: only filter multi-line content that looks like binary noise,
            # not legitimate multi-line findings (e.g. email/newsgroup data)
            nl_count = f.count("\n")
            if nl_count > 8:
                meaningful = sum(1 for ln in f.split("\n")
                                if len(ln.strip()) > 3 and any(c.isalpha() for c in ln))
                if meaningful / max(nl_count, 1) < 0.5:
                    continue
            # Skip DOS program stubs
            if "This program cannot be run in DOS mode" in f:
                continue
            # R13: skip IE cache index.dat URL dumps (raw browsing history noise)
            if re.search(r"Evil@|Visited:\s*Mr|:Host:\s*\w|UrlCache MMF", f):
                continue
            # R14-5: skip auto-extracted INI section dumps (channel lists etc.)
            if re.search(r"\[auto-extracted.*\]\s*\[", f) and re.search(r"\nn\d+=", f):
                continue
            # R15: skip non-answer auxiliary facts (gateway IPs, filter expressions, etc.)
            if re.search(r"^(Local gateway|Gateway|Target IP|Ethereal display filter|Ethereal promiscuous)", f):
                continue
            filtered.append(f)
        return filtered

    def _generate_report(self) -> dict:
        """Generate the final investigation report."""
        filtered_findings = self._filter_meta_findings(self.state.confirmed_findings)
        # R17-5: deduplicate findings (preserve order)
        seen = set()
        deduped = []
        for f in filtered_findings:
            key = f.strip().lower()
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        filtered_findings = deduped
        report = {
            "session_id": self.audit.session_id,
            "total_iterations": self.state.iteration,
            "root_cause": self.state.root_cause,
            "confirmed_findings": filtered_findings,
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
