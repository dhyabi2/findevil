# Deployment Instructions

## Prerequisites

- **OS**: Ubuntu 22.04+ (SANS SIFT Workstation recommended)
- **Python**: 3.10 or higher
- **SIFT Tools**: Install via `curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`
- **LLM API Key**: OpenRouter account with API key

## Automated Installation

```bash
# Clone and run installer
git clone https://github.com/dhyabi2/findevil.git
cd findevil
bash deploy/install.sh
```

## Manual Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/dhyabi2/findevil.git
cd findevil
```

### Step 2: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Configure LLM Provider

```bash
# Set your OpenRouter API key
export OPENROUTER_API_KEY="sk-or-v1-your-key-here"

# Or add to your shell profile
echo 'export OPENROUTER_API_KEY="sk-or-v1-your-key-here"' >> ~/.bashrc
source ~/.bashrc
```

### Step 4: Edit Configuration (Optional)

```bash
# Edit config.yaml to change model, thresholds, or tool paths
nano config.yaml
```

### Step 5: Validate Setup

```bash
python main.py validate
```

Expected output:
```
[OK] Config file loaded
[OK] OPENROUTER_API_KEY environment variable set
[INFO] Provider: openrouter, Model: google/gemma-4-31b-it
[OK] Sleuthkit: mmls -> /usr/bin/mmls
[OK] Sleuthkit: fls -> /usr/bin/fls
[OK] Plaso: log2timeline.py -> /usr/bin/log2timeline.py
[OK] YARA: yara -> /usr/bin/yara
[OK] Zimmerman Tools: 12 tools in /opt/zimmermantools
Validation complete.
```

## Usage Modes

### Mode 1: Standalone CLI Investigation

```bash
python main.py investigate \
  --evidence "Description of the incident" \
  --paths /cases/evidence.E01 \
  --output report.json
```

### Mode 2: MCP Server for Claude Code

```bash
# Start MCP server
python main.py mcp-server
```

Configure Claude Code (`~/.claude/mcp.json`):
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

### Mode 3: Demo/Validation

```bash
python main.py demo
python main.py validate
```

## Preparing Evidence

1. Place forensic images in `/cases/`
2. Mount images read-only:
   ```bash
   sudo mount -o ro,loop /cases/disk.raw /mnt/windows_mount
   ```
3. For E01 images, use ewfmount:
   ```bash
   sudo ewfmount /cases/disk.E01 /mnt/ewf
   sudo mount -o ro,loop /mnt/ewf/ewf1 /mnt/windows_mount
   ```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `OPENROUTER_API_KEY not set` | `export OPENROUTER_API_KEY="your-key"` |
| `mcp module not found` | `pip install mcp` |
| `mmls not found` | Install SIFT: `curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh \| bash` |
| `dotnet not found` | `sudo apt install dotnet-runtime-8.0` for Zimmerman tools |
| `Tool timed out` | Increase `agent.tool_timeout` in config.yaml |
