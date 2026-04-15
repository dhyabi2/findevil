"""
MCP Server for SIFT Workstation forensic tools.

Provides type-safe, guardrail-enforced access to 200+ forensic tools
via the Model Context Protocol using FastMCP.
"""

import asyncio
import json
import logging
import subprocess
import shlex
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .guardrails import ForensicGuardrails

logger = logging.getLogger("findevil.mcp")

app = FastMCP(
    name="findevil-sift",
    instructions="SIFT Workstation forensic tools with architectural guardrails. Use these tools to analyze disk images, memory dumps, network captures, and Windows artifacts.",
)
guardrails = ForensicGuardrails()


def _run_tool(command: str, timeout: int = 300) -> tuple[int, str, str]:
    """Execute a forensic tool command with guardrails."""
    violation = guardrails.validate_command(command)
    if violation:
        return -1, "", f"GUARDRAIL BLOCKED: {violation.rule} - {violation.detail}"

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = guardrails.sanitize_for_llm(result.stdout)
        stderr = guardrails.sanitize_for_llm(result.stderr)
        return result.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Tool execution timed out after {timeout}s"
    except Exception as e:
        return -1, "", f"Execution error: {str(e)}"


def _result(code: int, out: str, err: str) -> str:
    """Format tool output as a string result."""
    if code == -1 and "GUARDRAIL" in err:
        return f"BLOCKED: {err}"
    if code != 0:
        return f"Error (exit {code}): {err}" if err else f"Error (exit {code}): {out}"
    return out


# ============================================================
# Sleuthkit Tools
# ============================================================

@app.tool()
def disk_partition_list(image_path: str) -> str:
    """List disk partitions in a forensic image using mmls. Use this FIRST to identify partition offsets before other analysis."""
    return _result(*_run_tool(f"mmls {shlex.quote(image_path)}"))


@app.tool()
def filesystem_info(image_path: str, offset: int = 0) -> str:
    """Get filesystem details (type, size, block size) for a partition. Requires offset from mmls."""
    return _result(*_run_tool(f"fsstat -o {offset} {shlex.quote(image_path)}"))


@app.tool()
def file_listing(image_path: str, offset: int = 0, path: str = "", recursive: bool = False, deleted: bool = False) -> str:
    """List files/directories in a forensic image. Set deleted=true to include deleted files. Set recursive=true for full tree."""
    flags = "-l"
    if recursive:
        flags += "r"
    if deleted:
        flags += "d"
    path_arg = shlex.quote(path) if path else ""
    return _result(*_run_tool(f"fls {flags} -o {offset} {shlex.quote(image_path)} {path_arg}"))


@app.tool()
def extract_file(image_path: str, inode: int, offset: int = 0, output_path: str = "") -> str:
    """Extract a file from a forensic image by inode number. Without output_path, returns strings from the file."""
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        cmd = f"icat -o {offset} {shlex.quote(image_path)} {inode} > {shlex.quote(output_path)}"
    else:
        cmd = f"icat -o {offset} {shlex.quote(image_path)} {inode} | head -c 10000 | strings"
    return _result(*_run_tool(cmd))


@app.tool()
def image_info(image_path: str) -> str:
    """Get metadata about a forensic disk image (type, size, sector size)."""
    return _result(*_run_tool(f"img_stat {shlex.quote(image_path)}"))


@app.tool()
def find_file_by_name(image_path: str, filename: str, offset: int = 0) -> str:
    """Search for a file by name in a forensic image. Returns matching file entries with inode numbers."""
    cmd = f"fls -r -o {offset} {shlex.quote(image_path)} | grep -i {shlex.quote(filename)}"
    code, out, err = _run_tool(cmd)
    return out if out.strip() else f"No files matching '{filename}' found."


@app.tool()
def recover_deleted_files(image_path: str, offset: int = 0, output_dir: str = "/tmp/findevil/recovered") -> str:
    """Recover deleted files from a forensic image to output directory."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return _result(*_run_tool(f"tsk_recover -o {offset} {shlex.quote(image_path)} {shlex.quote(output_dir)}", timeout=600))


@app.tool()
def get_file_timestamps(image_path: str, offset: int = 0) -> str:
    """Extract MAC timestamps for all files in a forensic image (for timeline analysis)."""
    return _result(*_run_tool(f"fls -r -m / -o {offset} {shlex.quote(image_path)}", timeout=300))


# ============================================================
# Timeline (Plaso)
# ============================================================

@app.tool()
def create_timeline(image_path: str, output_file: str = "/tmp/findevil/timeline.plaso") -> str:
    """Create a super-timeline from a forensic image using log2timeline (Plaso). WARNING: Long-running operation (minutes to hours)."""
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    cmd = f"log2timeline.py --status_view none {shlex.quote(output_file)} {shlex.quote(image_path)}"
    code, out, err = _run_tool(cmd, timeout=3600)
    return f"Timeline created: {output_file}\n{out}" if code == 0 else f"Error: {err}"


@app.tool()
def search_timeline(plaso_file: str, query: str, output_file: str = "/tmp/findevil/timeline_filtered.csv") -> str:
    """Search/filter a Plaso timeline. Examples: 'date > \"2024-01-01\"', 'source is \"EVT\"', 'filename contains \"password\"'."""
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    cmd = f"psort.py -o l2tcsv -w {shlex.quote(output_file)} {shlex.quote(plaso_file)} {shlex.quote(query)}"
    code, out, err = _run_tool(cmd, timeout=600)
    if code == 0:
        try:
            result = Path(output_file).read_text()[:20000]
            return f"Results written to {output_file}:\n{result}"
        except Exception:
            return out
    return f"Error: {err}"


@app.tool()
def timeline_info(plaso_file: str) -> str:
    """Get information about a Plaso timeline storage file (parsers used, event count, time range)."""
    return _result(*_run_tool(f"pinfo.py {shlex.quote(plaso_file)}"))


# ============================================================
# Zimmerman Tools (Windows Artifacts)
# ============================================================

@app.tool()
def parse_mft(mft_path: str, output_dir: str = "/tmp/findevil/mft") -> str:
    """Parse NTFS $MFT file using MFTECmd. Reveals file creation, modification, access times for ALL files including deleted."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return _result(*_run_tool(f"dotnet /opt/zimmermantools/MFTECmd.dll -f {shlex.quote(mft_path)} --csv {shlex.quote(output_dir)}"))


@app.tool()
def parse_evtx(evtx_path: str, output_dir: str = "/tmp/findevil/evtx") -> str:
    """Parse Windows Event Log (.evtx) files using EvtxECmd. Can parse single file or directory of .evtx files."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    p = Path(evtx_path)
    flag = "-d" if p.is_dir() else "-f"
    return _result(*_run_tool(f"dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll {flag} {shlex.quote(evtx_path)} --csv {shlex.quote(output_dir)}"))


@app.tool()
def parse_registry(registry_path: str, output_dir: str = "/tmp/findevil/registry") -> str:
    """Parse Windows Registry hive (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat) using RECmd."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return _result(*_run_tool(f"dotnet /opt/zimmermantools/RECmd/RECmd.dll -f {shlex.quote(registry_path)} --csv {shlex.quote(output_dir)}"))


@app.tool()
def parse_amcache(amcache_path: str, output_dir: str = "/tmp/findevil/amcache") -> str:
    """Parse Amcache.hve for evidence of program execution, installed programs, and drivers."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return _result(*_run_tool(f"dotnet /opt/zimmermantools/AmcacheParser.dll -f {shlex.quote(amcache_path)} --csv {shlex.quote(output_dir)}"))


@app.tool()
def parse_shimcache(system_hive_path: str, output_dir: str = "/tmp/findevil/shimcache") -> str:
    """Parse Application Compatibility Cache (ShimCache) from SYSTEM hive. Shows evidence of program execution."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return _result(*_run_tool(f"dotnet /opt/zimmermantools/AppCompatCacheParser.dll -f {shlex.quote(system_hive_path)} --csv {shlex.quote(output_dir)}"))


@app.tool()
def parse_jumplist(jumplist_path: str, output_dir: str = "/tmp/findevil/jumplists") -> str:
    """Parse Windows Jump Lists for evidence of recent file access and application usage."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return _result(*_run_tool(f"dotnet /opt/zimmermantools/JLECmd.dll -f {shlex.quote(jumplist_path)} --csv {shlex.quote(output_dir)}"))


@app.tool()
def parse_lnk(lnk_path: str, output_dir: str = "/tmp/findevil/lnk") -> str:
    """Parse Windows Shortcut (.lnk) files. Reveals original file paths, MAC addresses, volume serial numbers."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return _result(*_run_tool(f"dotnet /opt/zimmermantools/LECmd.dll -f {shlex.quote(lnk_path)} --csv {shlex.quote(output_dir)}"))


@app.tool()
def parse_shellbags(hive_path: str, output_dir: str = "/tmp/findevil/shellbags") -> str:
    """Parse Windows Shellbags from NTUSER.DAT/UsrClass.dat for folder access history (persists after deletion)."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return _result(*_run_tool(f"dotnet /opt/zimmermantools/SBECmd.dll -f {shlex.quote(hive_path)} --csv {shlex.quote(output_dir)}"))


@app.tool()
def parse_recycle_bin(recycle_path: str, output_dir: str = "/tmp/findevil/recyclebin") -> str:
    """Parse Windows Recycle Bin ($I/$R files) to recover deleted file metadata."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return _result(*_run_tool(f"dotnet /opt/zimmermantools/RBCmd.dll -d {shlex.quote(recycle_path)} --csv {shlex.quote(output_dir)}"))


@app.tool()
def parse_prefetch(prefetch_dir: str, output_dir: str = "/tmp/findevil/prefetch") -> str:
    """Parse Windows Prefetch files for program execution evidence (execution count, timestamps, loaded DLLs)."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return _result(*_run_tool(f"dotnet /opt/zimmermantools/WxTCmd.dll -d {shlex.quote(prefetch_dir)} --csv {shlex.quote(output_dir)}"))


# ============================================================
# Memory Forensics (Volatility 3)
# ============================================================

@app.tool()
def memory_pslist(memory_path: str) -> str:
    """List running processes from a memory dump using Volatility 3."""
    return _result(*_run_tool(f"python3 -m volatility3 -f {shlex.quote(memory_path)} windows.pslist", timeout=600))


@app.tool()
def memory_pstree(memory_path: str) -> str:
    """Show process tree (parent-child relationships) from a memory dump."""
    return _result(*_run_tool(f"python3 -m volatility3 -f {shlex.quote(memory_path)} windows.pstree", timeout=600))


@app.tool()
def memory_netscan(memory_path: str) -> str:
    """List network connections and listening ports from a memory dump."""
    return _result(*_run_tool(f"python3 -m volatility3 -f {shlex.quote(memory_path)} windows.netscan", timeout=600))


@app.tool()
def memory_cmdline(memory_path: str) -> str:
    """Extract command line arguments for all processes from a memory dump."""
    return _result(*_run_tool(f"python3 -m volatility3 -f {shlex.quote(memory_path)} windows.cmdline", timeout=600))


@app.tool()
def memory_dlllist(memory_path: str, pid: int = 0) -> str:
    """List loaded DLLs for processes. Optionally filter by PID."""
    cmd = f"python3 -m volatility3 -f {shlex.quote(memory_path)} windows.dlllist"
    if pid > 0:
        cmd += f" --pid {pid}"
    return _result(*_run_tool(cmd, timeout=600))


@app.tool()
def memory_malfind(memory_path: str) -> str:
    """Detect injected/hollow code in processes (finds hidden malware in memory)."""
    return _result(*_run_tool(f"python3 -m volatility3 -f {shlex.quote(memory_path)} windows.malfind", timeout=600))


@app.tool()
def memory_handles(memory_path: str, pid: int = 0) -> str:
    """List open handles (files, registry keys, mutexes) for processes."""
    cmd = f"python3 -m volatility3 -f {shlex.quote(memory_path)} windows.handles"
    if pid > 0:
        cmd += f" --pid {pid}"
    return _result(*_run_tool(cmd, timeout=600))


@app.tool()
def memory_filescan(memory_path: str) -> str:
    """Scan memory for FILE_OBJECT structures (finds files even if hidden from directory listing)."""
    return _result(*_run_tool(f"python3 -m volatility3 -f {shlex.quote(memory_path)} windows.filescan", timeout=600))


@app.tool()
def memory_registry_hivelist(memory_path: str) -> str:
    """List registry hives loaded in memory."""
    return _result(*_run_tool(f"python3 -m volatility3 -f {shlex.quote(memory_path)} windows.registry.hivelist", timeout=600))


@app.tool()
def memory_dump_process(memory_path: str, pid: int, output_dir: str = "/tmp/findevil/memdump") -> str:
    """Dump a process's memory space from a memory capture. Useful for malware extraction."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return _result(*_run_tool(
        f"python3 -m volatility3 -f {shlex.quote(memory_path)} -o {shlex.quote(output_dir)} windows.memmap --pid {pid} --dump",
        timeout=600,
    ))


@app.tool()
def memory_info(memory_path: str) -> str:
    """Get basic info about a memory dump (OS version, build, architecture)."""
    return _result(*_run_tool(f"python3 -m volatility3 -f {shlex.quote(memory_path)} windows.info", timeout=300))


# ============================================================
# YARA Scanning
# ============================================================

@app.tool()
def yara_scan(target_path: str, rules_path: str = "", rule_string: str = "") -> str:
    """Scan a file or directory with YARA rules. Provide rules_path for a .yar file or rule_string for inline YARA rules."""
    if rule_string:
        tmp_rule = "/tmp/findevil/temp_rule.yar"
        Path(tmp_rule).parent.mkdir(parents=True, exist_ok=True)
        Path(tmp_rule).write_text(rule_string)
        rules_path = tmp_rule
    elif not rules_path:
        return "Error: provide either rules_path or rule_string"

    # Use python3-yara since yara binary isn't installed
    cmd = f"python3 -c \"import yara; r=yara.compile(filepath='{rules_path}'); m=r.match(filepath='{target_path}'); print('\\n'.join(str(x) for x in m) if m else 'No YARA matches.')\""
    code, out, err = _run_tool(cmd)
    return out if out.strip() else f"No YARA matches found. {err}"


# ============================================================
# Bulk Extractor
# ============================================================

@app.tool()
def bulk_extract(image_path: str, output_dir: str = "/tmp/findevil/bulk_extractor") -> str:
    """Run bulk_extractor to extract emails, URLs, credit card numbers, phone numbers, etc. from any file or disk image."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    code, out, err = _run_tool(f"bulk_extractor -o {shlex.quote(output_dir)} {shlex.quote(image_path)}", timeout=1800)
    if code == 0:
        try:
            files = list(Path(output_dir).glob("*.txt"))
            summary = []
            for f in files:
                size = f.stat().st_size
                if size > 0:
                    summary.append(f"  {f.name}: {size} bytes")
            return f"Extraction complete. Non-empty results:\n" + "\n".join(summary)
        except Exception:
            return out
    return f"Error: {err}"


# ============================================================
# File Carving
# ============================================================

@app.tool()
def carve_files(image_path: str, output_dir: str = "/tmp/findevil/carved", tool: str = "foremost") -> str:
    """Carve files (images, docs, executables) from unallocated space using foremost or scalpel."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    if tool == "scalpel":
        cmd = f"scalpel -o {shlex.quote(output_dir)} {shlex.quote(image_path)}"
    else:
        cmd = f"foremost -o {shlex.quote(output_dir)} -i {shlex.quote(image_path)}"
    return _result(*_run_tool(cmd, timeout=1800))


# ============================================================
# Network Forensics
# ============================================================

@app.tool()
def pcap_summary(pcap_path: str) -> str:
    """Get summary statistics of a PCAP file (packet count, duration, protocols)."""
    return _result(*_run_tool(f"capinfos {shlex.quote(pcap_path)}"))


@app.tool()
def pcap_filter(pcap_path: str, display_filter: str, max_packets: int = 100) -> str:
    """Filter and display packets from a PCAP using Wireshark display filters. Examples: 'http.request', 'ip.addr==10.0.0.1', 'tcp.port==4444'."""
    return _result(*_run_tool(f"tshark -r {shlex.quote(pcap_path)} -Y {shlex.quote(display_filter)} -c {max_packets}"))


@app.tool()
def pcap_conversations(pcap_path: str) -> str:
    """List network conversations (TCP connections with bytes transferred) in a PCAP file."""
    return _result(*_run_tool(f"tshark -r {shlex.quote(pcap_path)} -q -z conv,tcp"))


@app.tool()
def pcap_dns(pcap_path: str) -> str:
    """Extract DNS queries and responses from a PCAP file. Useful for identifying C2 domains."""
    return _result(*_run_tool(f"tshark -r {shlex.quote(pcap_path)} -Y dns -T fields -e dns.qry.name -e dns.a -e dns.aaaa"))


@app.tool()
def pcap_http_objects(pcap_path: str, output_dir: str = "/tmp/findevil/http_objects") -> str:
    """Export HTTP objects (downloaded/uploaded files) from a PCAP."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    _run_tool(f"tshark -r {shlex.quote(pcap_path)} --export-objects http,{shlex.quote(output_dir)}")
    try:
        files = list(Path(output_dir).iterdir())
        text = f"Exported {len(files)} HTTP objects to {output_dir}"
        for f in files[:20]:
            text += f"\n  {f.name} ({f.stat().st_size} bytes)"
        return text
    except Exception:
        return "No HTTP objects exported."


# ============================================================
# String & Hash Utilities
# ============================================================

@app.tool()
def extract_strings(file_path: str, min_length: int = 6, encoding: str = "auto") -> str:
    """Extract human-readable strings from a binary file. encoding: auto|ascii|unicode|both."""
    if encoding == "both":
        cmd = f"strings -n {min_length} {shlex.quote(file_path)} && strings -el -n {min_length} {shlex.quote(file_path)}"
    elif encoding == "unicode":
        cmd = f"strings -el -n {min_length} {shlex.quote(file_path)}"
    else:
        cmd = f"strings -n {min_length} {shlex.quote(file_path)}"
    return _result(*_run_tool(cmd))


@app.tool()
def hash_file(file_path: str) -> str:
    """Calculate MD5, SHA1, and SHA256 hashes of a file for integrity verification and IOC matching."""
    results = []
    for hasher in ("md5sum", "sha1sum", "sha256sum"):
        code, out, err = _run_tool(f"{hasher} {shlex.quote(file_path)}")
        if code == 0:
            results.append(out.strip())
    return "\n".join(results) if results else "Error computing hashes"


@app.tool()
def file_type(file_path: str) -> str:
    """Identify file type using magic bytes (works even if extension is wrong/missing)."""
    return _result(*_run_tool(f"file {shlex.quote(file_path)}"))


@app.tool()
def hex_dump(file_path: str, offset: int = 0, length: int = 512) -> str:
    """Show hex dump of a file section. Useful for examining file headers, embedded data, or suspicious bytes."""
    return _result(*_run_tool(f"xxd -s {offset} -l {length} {shlex.quote(file_path)}"))


# ============================================================
# Generic Safe Command Execution
# ============================================================

@app.tool()
def run_forensic_command(command: str, timeout: int = 300) -> str:
    """Run any forensic command through the guardrail system. Use this for tools not covered by specific functions above."""
    return _result(*_run_tool(command, timeout=timeout))


# ============================================================
# Main Entry
# ============================================================

def main():
    """Run the MCP server via stdio."""
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting FIND EVIL! SIFT MCP Server")
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
