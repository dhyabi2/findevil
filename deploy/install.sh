#!/bin/bash
# FIND EVIL! - Automated Installation Script
# Run from the findevil/ directory: bash deploy/install.sh

set -e

echo "============================================"
echo "  FIND EVIL! - IABF Agent Installation"
echo "============================================"
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    echo "[ERROR] Python 3.10+ required. Found: $PYTHON_VERSION"
    exit 1
fi
echo "[OK] Python $PYTHON_VERSION"

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install -r requirements.txt 2>&1 | tail -5
echo "[OK] Dependencies installed"

# Create working directories
echo ""
echo "Creating working directories..."
mkdir -p logs
mkdir -p /tmp/findevil/{recovered,timeline,mft,evtx,registry,amcache,shimcache,jumplists,lnk,shellbags,recyclebin,bulk_extractor,carved,http_objects}
echo "[OK] Directories created"

# Check API key
echo ""
if [ -n "$OPENROUTER_API_KEY" ]; then
    echo "[OK] OPENROUTER_API_KEY is set"
else
    echo "[WARN] OPENROUTER_API_KEY is not set"
    echo "  Set it with: export OPENROUTER_API_KEY=\"your-key-here\""
fi

# Validate tools
echo ""
echo "Checking forensic tools..."
TOOLS=("mmls" "fls" "icat" "log2timeline.py" "psort.py" "yara" "bulk_extractor" "foremost" "strings" "tshark")
MISSING=0
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo "  [OK] $tool"
    else
        echo "  [MISS] $tool"
        MISSING=$((MISSING + 1))
    fi
done

if [ -d "/opt/zimmermantools" ]; then
    ZIM_COUNT=$(ls /opt/zimmermantools/*.dll 2>/dev/null | wc -l)
    echo "  [OK] Zimmerman Tools ($ZIM_COUNT tools)"
else
    echo "  [MISS] Zimmerman Tools (/opt/zimmermantools)"
fi

echo ""
echo "============================================"
echo "  Installation Complete!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Set API key:  export OPENROUTER_API_KEY=\"your-key\""
echo "  2. Validate:     python main.py validate"
echo "  3. Demo:         python main.py demo"
echo "  4. Investigate:  python main.py investigate --evidence '...' --paths /cases/image.E01"
echo ""
