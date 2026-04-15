#!/usr/bin/env python3
"""
FIND EVIL! - IABF Agent CLI

Autonomous DFIR agent using the Iterative Assumption-Based Framework
on SANS SIFT Workstation.

Usage:
    python main.py investigate --evidence "description" --paths /cases/image.E01
    python main.py mcp-server
    python main.py demo
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import yaml


def setup_logging(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )


def cmd_investigate(args):
    """Run a full IABF investigation."""
    from agent.iabf import IABFAgent

    setup_logging(args.log_level)

    llm = None
    if args.dry_run:
        from agent.llm_client import FakeLLMClient
        llm = FakeLLMClient([
            "NARRATIVE: Dry-run scripted narrative. KEY UNKNOWNS: none.",
            {"hypotheses": [{
                "description": "Dry-run hypothesis",
                "mitre_technique": "T0000 - Test",
                "confidence": 0.7,
                "investigation_plan": "Run a safe noop command.",
                "tool_commands": ["echo dry-run-probe"],
                "confirms_if": "any output",
                "disproves_if": "no output",
            }]},
            {"verdict": "confirmed", "confidence_after": 0.95,
             "evidence_for": ["Dry-run probe returned synthetic output"],
             "evidence_against": [], "unexpected_findings": [],
             "self_correction": "", "next_suggestion": ""},
            {"narrative_update": "Dry-run complete.",
             "root_cause_reached": True,
             "root_cause": "Dry-run synthetic root cause",
             "confidence_in_root_cause": 0.95,
             "self_corrections": [], "next_priority": "",
             "probability_adjustments": {},
             "investigation_complete": True},
        ])
        print("[DRY-RUN] Using FakeLLMClient + stubbed tool execution. No network, no subprocess.")

    agent = IABFAgent(config_path=args.config, llm=llm, dry_run=args.dry_run)

    evidence_paths = args.paths if args.paths else []
    report = agent.investigate(
        evidence_description=args.evidence,
        evidence_paths=evidence_paths,
    )

    print("\n" + "=" * 60)
    print("INVESTIGATION COMPLETE")
    print("=" * 60)
    print(f"Root Cause: {report.get('root_cause', 'Not determined')}")
    print(f"Iterations: {report['total_iterations']}")
    print(f"Confirmed Findings: {len(report['confirmed_findings'])}")
    print(f"Disproved Assumptions: {len(report['disproved_assumptions'])}")
    print(f"Audit Log: {report['audit_log']}")
    print(f"LLM Stats: {json.dumps(report['llm_stats'], indent=2)}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nFull report saved to: {args.output}")


def cmd_mcp_server(args):
    """Start the MCP server for Claude Code integration."""
    setup_logging(args.log_level)
    from mcp_server.server import main as mcp_main
    mcp_main()


def cmd_demo(args):
    """Run a demonstration with sample evidence."""
    setup_logging("INFO")
    logger = logging.getLogger("findevil.demo")

    print("=" * 60)
    print("FIND EVIL! - IABF Agent Demo")
    print("=" * 60)
    print()

    # Check for evidence
    evidence_dirs = ["/cases", "/mnt"]
    found_evidence = []
    for d in evidence_dirs:
        p = Path(d)
        if p.exists():
            for f in p.rglob("*"):
                if f.is_file() and f.suffix.lower() in (
                    ".e01", ".raw", ".dd", ".img", ".vmdk",
                    ".pcap", ".pcapng", ".evtx", ".mem",
                ):
                    found_evidence.append(str(f))

    if found_evidence:
        print("Found evidence files:")
        for e in found_evidence:
            print(f"  - {e}")
        print()
        print("To investigate, run:")
        print(f'  python main.py investigate --evidence "Analyze these forensic images" --paths {" ".join(found_evidence[:3])}')
    else:
        print("No evidence files found in /cases or /mnt.")
        print()
        print("To get started:")
        print("  1. Place forensic images in /cases/")
        print("  2. Mount evidence images to /mnt/")
        print("  3. Run: python main.py investigate --evidence 'description' --paths /path/to/evidence")
        print()
        print("Or start the MCP server for Claude Code integration:")
        print("  python main.py mcp-server")

    print()
    print("Available SIFT tools on this system:")
    tools = [
        ("Sleuthkit", "mmls, fls, icat, fsstat, img_stat, tsk_recover"),
        ("Plaso", "log2timeline.py, psort.py, pinfo.py"),
        ("Zimmerman", "MFTECmd, EvtxECmd, RECmd, AmcacheParser, AppCompatCacheParser"),
        ("YARA", "yara, yarac"),
        ("Carving", "foremost, scalpel, bulk_extractor"),
        ("Network", "tshark, tcpdump"),
        ("Other", "autopsy, strings, exiftool"),
    ]
    for category, tool_list in tools:
        print(f"  [{category}] {tool_list}")


def cmd_validate(args):
    """Validate configuration and tool availability."""
    setup_logging("INFO")
    print("Validating FIND EVIL! setup...\n")

    # Check config
    try:
        with open(args.config) as f:
            config = yaml.safe_load(f)
        print("[OK] Config file loaded")
    except Exception as e:
        print(f"[FAIL] Config file: {e}")
        return

    # Check LLM
    import os
    provider = config.get("llm", {}).get("provider", "openrouter")
    provider_cfg = config.get("llm", {}).get(provider, {})
    api_key_ref = provider_cfg.get("api_key", "")
    if api_key_ref.startswith("${"):
        env_var = api_key_ref[2:-1]
        if os.environ.get(env_var):
            print(f"[OK] {env_var} environment variable set")
        else:
            print(f"[WARN] {env_var} not set - LLM calls will fail")
    print(f"[INFO] Provider: {provider}, Model: {provider_cfg.get('default_model', 'unknown')}")

    # Check tools
    import shutil
    tool_checks = {
        "mmls": "Sleuthkit",
        "fls": "Sleuthkit",
        "log2timeline.py": "Plaso",
        "psort.py": "Plaso",
        "yara": "YARA",
        "bulk_extractor": "Bulk Extractor",
        "foremost": "Foremost",
        "tshark": "TShark",
        "strings": "Strings",
        "autopsy": "Autopsy",
    }
    for tool, suite in tool_checks.items():
        path = shutil.which(tool)
        if path:
            print(f"[OK] {suite}: {tool} -> {path}")
        else:
            print(f"[MISS] {suite}: {tool} not found")

    # Check Zimmerman tools
    zim_path = Path("/opt/zimmermantools")
    if zim_path.exists():
        zim_tools = list(zim_path.glob("*.dll"))
        print(f"[OK] Zimmerman Tools: {len(zim_tools)} tools in {zim_path}")
    else:
        print("[MISS] Zimmerman Tools: /opt/zimmermantools not found")

    print("\nValidation complete.")


def main():
    parser = argparse.ArgumentParser(
        description="FIND EVIL! - IABF Agent for Autonomous DFIR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py investigate --evidence "Suspicious PowerShell detected" --paths /cases/disk.E01
  python main.py mcp-server
  python main.py demo
  python main.py validate
        """,
    )
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # investigate
    p_inv = subparsers.add_parser("investigate", help="Run IABF investigation")
    p_inv.add_argument("--evidence", required=True, help="Description of evidence/incident")
    p_inv.add_argument("--paths", nargs="+", help="Paths to evidence files")
    p_inv.add_argument("--output", help="Output file for report JSON")
    p_inv.add_argument("--dry-run", action="store_true",
                       help="Run offline: FakeLLM + stubbed tools. No API cost.")
    p_inv.set_defaults(func=cmd_investigate)

    # mcp-server
    p_mcp = subparsers.add_parser("mcp-server", help="Start MCP server")
    p_mcp.set_defaults(func=cmd_mcp_server)

    # demo
    p_demo = subparsers.add_parser("demo", help="Run demo/check setup")
    p_demo.set_defaults(func=cmd_demo)

    # validate
    p_val = subparsers.add_parser("validate", help="Validate setup and tools")
    p_val.set_defaults(func=cmd_validate)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
