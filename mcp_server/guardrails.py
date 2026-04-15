"""
Architectural guardrails for forensic tool execution.

These are HARD enforcement boundaries - not prompt-based suggestions.
The LLM cannot override these regardless of instructions.
"""

import os
import re
import shlex
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class GuardrailViolation:
    """Represents a security boundary violation."""
    rule: str
    detail: str
    command: str
    severity: str = "blocked"  # blocked | warning


class ForensicGuardrails:
    """Architectural enforcement layer for safe forensic tool execution."""

    # Commands that are NEVER allowed - these modify/destroy evidence
    BLOCKED_PATTERNS: list[re.Pattern] = [
        re.compile(r"\brm\s+(-[rRf]+\s+|.*--no-preserve-root)"),
        re.compile(r"\bmkfs\b"),
        re.compile(r"\bdd\b.*\bof="),
        re.compile(r"\bfdisk\b"),
        re.compile(r"\bparted\b"),
        re.compile(r"\bshred\b"),
        re.compile(r"\bwipefs\b"),
        re.compile(r">\s*/dev/"),
        re.compile(r"\bchmod\s+777\b"),
        re.compile(r"\bmount\s+.*-o\s*.*\brw\b"),
        re.compile(r"\bformat\b.*\b[A-Z]:\\"),
        re.compile(r"\bnewfs\b"),
        re.compile(r"\bmke2fs\b"),
        re.compile(r"\bsudo\s+rm\b"),
    ]

    # Only these base directories can be accessed for evidence
    DEFAULT_ALLOWED_PATHS = [
        "/cases",
        "/mnt",
        "/tmp/findevil",
    ]

    # Allowed forensic tool binaries
    ALLOWED_BINARIES = {
        # Sleuthkit
        "mmls", "fsstat", "fls", "icat", "ifind", "img_stat",
        "blkls", "blkcat", "sigfind", "tsk_recover", "srch_strings",
        "mactime", "sorter", "hfind", "tsk_loaddb", "tsk_gettimes",
        # Plaso
        "log2timeline.py", "psort.py", "pinfo.py",
        # Zimmerman (run via dotnet)
        "dotnet", "mono",
        # Volatility
        "vol3", "vol", "volatility3", "python3",
        # YARA
        "yara", "yarac",
        # Carving & extraction
        "bulk_extractor", "foremost", "scalpel",
        # Network
        "tshark", "tcpdump", "capinfos", "editcap",
        # Utilities
        "strings", "file", "xxd", "hexdump", "sha256sum", "sha1sum",
        "md5sum", "stat", "ls", "find", "grep", "cat", "head", "tail",
        "wc", "sort", "uniq", "awk", "sed", "cut", "tr", "base64",
        "python3", "exiftool", "pdftotext", "olevba",
        # Hindsight (browser forensics)
        "hindsight.py", "hindsight",
    }

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.allowed_paths = [
            Path(p) for p in
            self.config.get("allowed_paths", self.DEFAULT_ALLOWED_PATHS)
        ]
        self._load_custom_blocked(self.config.get("blocked_commands", []))

    def _load_custom_blocked(self, extra_patterns: list[str]):
        """Load additional blocked patterns from config."""
        for pattern in extra_patterns:
            try:
                self.BLOCKED_PATTERNS.append(re.compile(re.escape(pattern)))
            except re.error:
                pass

    def validate_command(self, command: str) -> GuardrailViolation | None:
        """
        Validate a command against ALL guardrail rules.
        Returns None if safe, GuardrailViolation if blocked.
        """
        # Check 1: Blocked destructive patterns
        violation = self._check_blocked_patterns(command)
        if violation:
            return violation

        # Check 2: Binary whitelist
        violation = self._check_binary_whitelist(command)
        if violation:
            return violation

        # Check 3: Path boundaries
        violation = self._check_path_boundaries(command)
        if violation:
            return violation

        # Check 4: Pipe/chain injection
        violation = self._check_injection(command)
        if violation:
            return violation

        return None

    def _check_blocked_patterns(self, command: str) -> GuardrailViolation | None:
        for pattern in self.BLOCKED_PATTERNS:
            if pattern.search(command):
                return GuardrailViolation(
                    rule="blocked_pattern",
                    detail=f"Command matches blocked pattern: {pattern.pattern}",
                    command=command,
                    severity="blocked",
                )
        return None

    def _check_binary_whitelist(self, command: str) -> GuardrailViolation | None:
        try:
            parts = shlex.split(command)
        except ValueError:
            return GuardrailViolation(
                rule="parse_error",
                detail="Command could not be safely parsed",
                command=command,
                severity="blocked",
            )

        if not parts:
            return None

        binary = Path(parts[0]).name
        if binary not in self.ALLOWED_BINARIES:
            return GuardrailViolation(
                rule="binary_whitelist",
                detail=f"Binary '{binary}' is not in the allowed forensic tools list",
                command=command,
                severity="blocked",
            )
        return None

    def _check_path_boundaries(self, command: str) -> GuardrailViolation | None:
        """Ensure file arguments stay within allowed evidence paths."""
        try:
            parts = shlex.split(command)
        except ValueError:
            return None  # Already caught by binary check

        for part in parts[1:]:
            if part.startswith("-"):
                continue
            path = Path(part)
            if path.is_absolute():
                if not any(self._is_subpath(path, allowed) for allowed in self.allowed_paths):
                    # Allow access to tool binaries themselves
                    if path.parent in (Path("/usr/bin"), Path("/opt/zimmermantools")):
                        continue
                    return GuardrailViolation(
                        rule="path_boundary",
                        detail=f"Path '{path}' is outside allowed evidence directories",
                        command=command,
                        severity="blocked",
                    )
        return None

    def _check_injection(self, command: str) -> GuardrailViolation | None:
        """Check for shell injection attempts in piped commands."""
        dangerous_chains = [
            re.compile(r";\s*(rm|dd|mkfs|shred|wipefs|mount)"),
            re.compile(r"\|\s*(rm|dd|mkfs|shred|wipefs)"),
            re.compile(r"\$\(.*?(rm|dd|mkfs|shred)"),
            re.compile(r"`.*?(rm|dd|mkfs|shred)"),
        ]
        for pattern in dangerous_chains:
            if pattern.search(command):
                return GuardrailViolation(
                    rule="injection_detected",
                    detail=f"Potential command injection detected",
                    command=command,
                    severity="blocked",
                )
        return None

    @staticmethod
    def _is_subpath(path: Path, parent: Path) -> bool:
        try:
            path.resolve().relative_to(parent.resolve())
            return True
        except ValueError:
            return False

    def validate_output_size(self, output: bytes, max_size: int = 10_485_760) -> bool:
        """Ensure tool output doesn't exceed configured maximum."""
        return len(output) <= max_size

    def sanitize_for_llm(self, output: str, max_chars: int = 50_000) -> str:
        """Truncate tool output before sending to LLM to prevent context overflow."""
        if len(output) <= max_chars:
            return output
        half = max_chars // 2
        return (
            output[:half]
            + f"\n\n... [TRUNCATED: {len(output) - max_chars} chars omitted] ...\n\n"
            + output[-half:]
        )
