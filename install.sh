#!/bin/bash

# Hypernode Log Analyzer - Install Script
# No virtual environment - direct system installation

set -e  # Exit on error

echo "🚀 Installing Hypernode Log Analyzer..."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Spinner function
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Function to run command with spinner
run_with_spinner() {
    local message="$1"
    local command="$2"
    
    printf "${BLUE}${message}${NC}"
    $command > /dev/null 2>&1 &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        printf "\r${GREEN}✓${NC} ${message}\n"
    else
        printf "\r${RED}✗${NC} ${message}\n"
        return $exit_code
    fi
}

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 is not installed. Please install Python 3 first.${NC}"
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}✗ pip3 is not installed. Please install pip3 first.${NC}"
    exit 1
fi

# Install Python dependencies and logcli module
INSTALL_SUCCESS=false

# Method 1: Try regular pip3
if pip3 install -r requirements.txt > /dev/null 2>&1 && pip3 install -e . > /dev/null 2>&1; then
    INSTALL_SUCCESS=true
fi

# Method 2: Try with --break-system-packages (if method 1 failed)
if [ "$INSTALL_SUCCESS" = false ]; then
    if pip3 install -r requirements.txt --break-system-packages > /dev/null 2>&1 && pip3 install -e . --break-system-packages > /dev/null 2>&1; then
        INSTALL_SUCCESS=true
    fi
fi

# Method 3: Try pipx (if available and method 1&2 failed)
if [ "$INSTALL_SUCCESS" = false ] && command -v pipx &> /dev/null; then
    if pipx install rich click pandas plotly > /dev/null 2>&1 && pip3 install -e . > /dev/null 2>&1; then
        INSTALL_SUCCESS=true
    fi
fi

# Method 4: Create a simple venv (if all else fails)
if [ "$INSTALL_SUCCESS" = false ]; then
    if python3 -m venv .venv > /dev/null 2>&1 && .venv/bin/pip install -r requirements.txt > /dev/null 2>&1 && .venv/bin/pip install -e . > /dev/null 2>&1; then
        INSTALL_SUCCESS=true
    fi
fi

if [ "$INSTALL_SUCCESS" = false ]; then
    echo -e "${RED}✗ Installation failed!${NC}"
    echo ""
    echo "🔧 Manual Installation Options:"
    echo "   1. sudo pip3 install -r requirements.txt && sudo pip3 install -e ."
    echo "   2. pip3 install -r requirements.txt --break-system-packages && pip3 install -e . --break-system-packages"
    echo "   3. python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && pip install -e ."
    echo "   4. Use system packages: apt install python3-textual python3-rich python3-click"
    echo ""
    exit 1
fi

# Create logcli wrapper script
cat > hlogcli << 'EOF'
#!/bin/bash
# Hypernode Log Analyzer - logcli wrapper
# Auto-discover logs and run analysis

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if we're in a venv
if [[ -n "$VIRTUAL_ENV" ]] || [[ -f "$SCRIPT_DIR/.venv/bin/python3" ]]; then
    if [[ -f "$SCRIPT_DIR/.venv/bin/python3" ]]; then
        PYTHON_CMD="$SCRIPT_DIR/.venv/bin/python3"
    else
        PYTHON_CMD="python3"
    fi
else
    PYTHON_CMD="python3"
fi

# Run logcli with auto-discover enabled by default
cd "$SCRIPT_DIR"
exec $PYTHON_CMD -m logcli.main "$@"
EOF

chmod +x hlogcli

# Install to user profile (no root needed)
# Create ~/bin directory if it doesn't exist
mkdir -p ~/bin

# Create symlink to ~/bin
ln -sf "$(pwd)/hlogcli" ~/bin/hlogcli

# Add ~/bin to PATH if not already there
if [[ ":$PATH:" != *":$HOME/bin:"* ]] && [[ ":$PATH:" != *":~/bin:"* ]]; then
    # Add to .bashrc if it exists
    if [ -f ~/.bashrc ]; then
        echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
    fi
    
    # Add to .profile if it exists
    if [ -f ~/.profile ]; then
        echo 'export PATH="$HOME/bin:$PATH"' >> ~/.profile
    fi
        
    # Add to current session
    export PATH="$HOME/bin:$PATH"
    
    # Create a temporary script to source the updated PATH
    echo 'export PATH="$HOME/bin:$PATH"' > /tmp/hlogcli_path_update.sh
    echo "source /tmp/hlogcli_path_update.sh" >> /tmp/hlogcli_path_update.sh
fi

# Show usage instructions
echo ""
echo "🎉 Installation Complete!"
echo ""
echo "📋 Usage:"
echo "   Command-line:     ./hlogcli analyze"
echo "   User (CLI):       hlogcli analyze (if ~/bin is in PATH)"
echo "   Direct:           ~/bin/hlogcli"
echo ""
echo "📁 Log Analysis:"
echo "   • Platform detection for Hypernode environments"
echo "   • Extended output with User Agents, IPs, Paths, Browser/OS stats"
echo "   • Real-time log monitoring and analysis"
echo ""
echo "🚀 Quick Start:"
echo "   hlogcli analyze                    # Auto-discover and analyze logs"
echo "   hlogcli analyze --summary-only     # Quick summary"
echo "   hlogcli analyze -i                 # Interactive mode"
echo "   hlogcli security                   # Security analysis"
echo "   hlogcli perf --response-time-analysis  # Performance analysis"
echo ""
echo "🔧 Troubleshooting:"
echo "   • If modules not found: pip3 install -r requirements.txt"
echo "   • If permission denied: chmod +x hlogcli"
echo "   • For CLI help: ./hlogcli --help"
echo ""
echo "✅ PATH updated - hlogcli is now available!"
echo "   If 'hlogcli' command not found, run: source ~/.bashrc"
echo ""
