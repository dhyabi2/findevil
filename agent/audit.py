"""
Structured audit trail for IABF agent execution.

Logs every tool call, reasoning step, hypothesis, and iteration
with timestamps and token usage for competition submission.
"""

import json
import time
import uuid
import logging
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("findevil.audit")


@dataclass
class ToolExecution:
    """Record of a single forensic tool execution."""
    tool_name: str
    command: str
    args: list[str]
    start_time: str
    end_time: str = ""
    duration_ms: float = 0.0
    exit_code: int = 0
    output_size_bytes: int = 0
    output_preview: str = ""  # First 500 chars
    error: str = ""
    guardrail_check: str = "passed"


@dataclass
class HypothesisRecord:
    """Record of a hypothesis and its resolution."""
    id: str
    iteration: int
    hypothesis: str
    mitre_technique: str = ""
    confidence_before: float = 0.0
    confidence_after: float = 0.0
    status: str = "pending"  # pending | confirmed | disproved | refined
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    tool_executions: list[str] = field(default_factory=list)  # tool execution IDs
    refinement_note: str = ""


@dataclass
class IterationRecord:
    """Record of one IABF iteration cycle."""
    iteration: int
    phase: str  # narrative | hypothesis | investigation | feedback
    narrative_summary: str = ""
    hypotheses: list[str] = field(default_factory=list)
    tool_executions: list[str] = field(default_factory=list)
    feedback_summary: str = ""
    tokens_used: int = 0
    duration_ms: float = 0.0
    timestamp: str = ""


class AuditTrail:
    """Manages the full audit trail for an investigation session."""

    def __init__(self, log_dir: str = "./logs", session_id: str | None = None):
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.start_time = datetime.now(timezone.utc).isoformat()
        self._tool_executions: list[ToolExecution] = []
        self._hypotheses: list[HypothesisRecord] = []
        self._iterations: list[IterationRecord] = []
        self._llm_calls: list[dict] = []
        self._events: list[dict] = []

        # JSONL file for streaming logs
        self._log_file = self.log_dir / f"session_{self.session_id}.jsonl"

    def _emit(self, event_type: str, data: dict):
        """Write a structured event to the JSONL log."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "event_type": event_type,
            **data,
        }
        self._events.append(event)
        with open(self._log_file, "a") as f:
            f.write(json.dumps(event) + "\n")

    def log_tool_start(self, tool_name: str, command: str, args: list[str]) -> str:
        """Log the start of a tool execution. Returns execution ID."""
        exec_id = f"tool_{len(self._tool_executions):04d}"
        record = ToolExecution(
            tool_name=tool_name,
            command=command,
            args=args,
            start_time=datetime.now(timezone.utc).isoformat(),
        )
        self._tool_executions.append(record)
        self._emit("tool_start", {
            "exec_id": exec_id,
            "tool_name": tool_name,
            "command": command,
        })
        return exec_id

    def log_tool_end(self, exec_id: str, exit_code: int, output: str, error: str = ""):
        """Log the completion of a tool execution."""
        idx = int(exec_id.split("_")[1])
        record = self._tool_executions[idx]
        record.end_time = datetime.now(timezone.utc).isoformat()
        record.exit_code = exit_code
        record.output_size_bytes = len(output.encode())
        record.output_preview = output[:500]
        record.error = error

        start = datetime.fromisoformat(record.start_time)
        end = datetime.fromisoformat(record.end_time)
        record.duration_ms = (end - start).total_seconds() * 1000

        self._emit("tool_end", {
            "exec_id": exec_id,
            "exit_code": exit_code,
            "duration_ms": record.duration_ms,
            "output_size_bytes": record.output_size_bytes,
        })

    def log_hypothesis(self, hypothesis: HypothesisRecord):
        """Log a hypothesis creation or update."""
        self._hypotheses.append(hypothesis)
        self._emit("hypothesis", asdict(hypothesis))

    def log_iteration(self, iteration: IterationRecord):
        """Log a complete IABF iteration."""
        iteration.timestamp = datetime.now(timezone.utc).isoformat()
        self._iterations.append(iteration)
        self._emit("iteration", asdict(iteration))

    def log_llm_call(self, model: str, tokens: dict, latency_ms: float, purpose: str):
        """Log an LLM API call."""
        record = {
            "model": model,
            "tokens": tokens,
            "latency_ms": latency_ms,
            "purpose": purpose,
        }
        self._llm_calls.append(record)
        self._emit("llm_call", record)

    def log_narrative(self, narrative: str, iteration: int):
        """Log a narrative reconstruction."""
        self._emit("narrative", {
            "iteration": iteration,
            "narrative": narrative,
        })

    def log_guardrail_violation(self, violation_detail: str, command: str):
        """Log a guardrail violation (blocked command)."""
        self._emit("guardrail_violation", {
            "detail": violation_detail,
            "command": command,
        })

    def log_self_correction(self, original: str, corrected: str, reason: str):
        """Log when the agent self-corrects."""
        self._emit("self_correction", {
            "original": original,
            "corrected": corrected,
            "reason": reason,
        })

    def export_session(self) -> dict:
        """Export the full session for submission."""
        return {
            "session_id": self.session_id,
            "start_time": self.start_time,
            "end_time": datetime.now(timezone.utc).isoformat(),
            "total_iterations": len(self._iterations),
            "total_tool_executions": len(self._tool_executions),
            "total_hypotheses": len(self._hypotheses),
            "total_llm_calls": len(self._llm_calls),
            "total_tokens": sum(
                c.get("tokens", {}).get("total_tokens", 0) for c in self._llm_calls
            ),
            "hypotheses": [asdict(h) for h in self._hypotheses],
            "iterations": [asdict(i) for i in self._iterations],
            "tool_executions": [asdict(t) for t in self._tool_executions],
            "llm_calls": self._llm_calls,
        }

    def save_report(self, filename: str | None = None):
        """Save the full session report as JSON."""
        filename = filename or f"report_{self.session_id}.json"
        path = self.log_dir / filename
        with open(path, "w") as f:
            json.dump(self.export_session(), f, indent=2)
        logger.info(f"Session report saved to {path}")
        return path
