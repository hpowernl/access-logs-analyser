#!/bin/bash

# Hypernode Log Analyzer - Install Script
# No virtual environment - direct system installation

set -e  # Exit on error

echo "🚀 Installing Hypernode Log Analyzer..."
echo "   Direct system installation (no venv)"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python 3 is installed
print_status "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
print_success "Found Python $PYTHON_VERSION"

# Check if pip is installed
print_status "Checking pip installation..."
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is not installed. Please install pip3 first."
    exit 1
fi

print_success "Found pip3"

# Install Python dependencies and logcli module
print_status "Installing Python packages..."
echo "   Trying different installation methods..."
echo ""

# Try different installation methods
INSTALL_SUCCESS=false

# Method 1: Try regular pip3
print_status "Method 1: Regular pip3 install..."
if pip3 install -r requirements.txt && pip3 install -e . 2>/dev/null; then
    print_success "Dependencies and logcli installed with pip3"
    INSTALL_SUCCESS=true
else
    print_warning "Regular pip3 failed (externally-managed-environment)"
fi

# Method 2: Try with --break-system-packages (if method 1 failed)
if [ "$INSTALL_SUCCESS" = false ]; then
    print_status "Method 2: pip3 with --break-system-packages..."
    if pip3 install -r requirements.txt --break-system-packages && pip3 install -e . --break-system-packages 2>/dev/null; then
        print_success "Dependencies and logcli installed with --break-system-packages"
        INSTALL_SUCCESS=true
    else
        print_warning "pip3 --break-system-packages failed"
    fi
fi

# Method 3: Try pipx (if available and method 1&2 failed)
if [ "$INSTALL_SUCCESS" = false ] && command -v pipx &> /dev/null; then
    print_status "Method 3: Using pipx..."
    if pipx install textual rich click pandas plotly && pip3 install -e . 2>/dev/null; then
        print_success "Core dependencies and logcli installed with pipx"
        INSTALL_SUCCESS=true
    else
        print_warning "pipx installation failed"
    fi
fi

# Method 4: Create a simple venv (if all else fails)
if [ "$INSTALL_SUCCESS" = false ]; then
    print_status "Method 4: Creating minimal venv..."
    if python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/pip install -e .; then
        print_success "Dependencies and logcli installed in .venv"
        print_warning "Note: You'll need to activate venv: source .venv/bin/activate"
        
        # Update opencli to use venv python (temporarily disabled)
        # sed -i '1s|#!/usr/bin/env python3|#!/usr/bin/env ./.venv/bin/python3|' opencli
        # logcli wrapper will automatically detect and use venv
        INSTALL_SUCCESS=true
    else
        print_warning "venv creation failed"
    fi
fi

if [ "$INSTALL_SUCCESS" = false ]; then
    print_error "All installation methods failed!"
    echo ""
    echo "🔧 Manual Installation Options:"
    echo "   1. sudo pip3 install -r requirements.txt && sudo pip3 install -e ."
    echo "   2. pip3 install -r requirements.txt --break-system-packages && pip3 install -e . --break-system-packages"
    echo "   3. python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && pip install -e ."
    echo "   4. Use system packages: apt install python3-textual python3-rich python3-click"
    echo ""
    exit 1
else
    print_success "Python dependencies and logcli module installed successfully"
fi

# Make opencli executable (temporarily disabled)
# print_status "Making opencli executable..."
# chmod +x opencli
# print_success "opencli is now executable"

# Create logcli wrapper script
print_status "Creating logcli wrapper script..."
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
print_success "hlogcli wrapper script created"

# Check if ~/bin is in PATH
print_status "Checking user PATH..."
if [[ ":$PATH:" == *":$HOME/bin:"* ]] || [[ ":$PATH:" == *":~/bin:"* ]]; then
    print_success "~/bin is already in PATH"
else
    print_warning "~/bin is not in PATH (will be created if needed)"
fi

# Install in user profile (no root needed)
echo ""
echo "🔧 Installation Options:"
echo "   1. Use locally: ./hlogcli (CLI) - TUI temporarily disabled"
echo "   2. Install to user profile: ~/bin/ (no root needed)"
echo ""
read -p "Install to user profile? (Y/n): " -n 1 -r
echo

# Default to Yes if just Enter is pressed
if [[ $REPLY =~ ^[Nn]$ ]]; then
    print_success "Local installation complete!"
    # print_status "Use: ./opencli for interactive TUI mode"  # Temporarily disabled
    print_status "Use: ./hlogcli for command-line analysis"
else
    print_status "Installing to user profile..."
    
    # Create ~/bin directory if it doesn't exist
    mkdir -p ~/bin
    
    # Create symlinks to ~/bin (opencli temporarily disabled)
    # if ln -sf "$(pwd)/opencli" ~/bin/opencli && ln -sf "$(pwd)/hlogcli" ~/bin/hlogcli; then
    if ln -sf "$(pwd)/hlogcli" ~/bin/hlogcli; then
        print_success "User profile installation complete!"
        # print_success "opencli installed to ~/bin/opencli"  # Temporarily disabled
        print_success "hlogcli installed to ~/bin/hlogcli"
        
        # Check if ~/bin is in PATH
        if [[ ":$PATH:" == *":$HOME/bin:"* ]] || [[ ":$PATH:" == *":~/bin:"* ]]; then
            print_success "~/bin is already in PATH"
            print_success "You can now run 'hlogcli' from anywhere"
        else
            print_warning "~/bin is not in PATH"
            echo ""
            echo "🔧 Add ~/bin to PATH by adding this to ~/.bashrc or ~/.profile:"
            echo "   export PATH=\"\$HOME/bin:\$PATH\""
            echo ""
            echo "Then reload with: source ~/.bashrc"
            echo "Or log out and log back in"
        fi
    else
        print_error "Failed to install to user profile"
        print_warning "You can still use: ./hlogcli"
    fi
fi

# Show usage instructions
echo ""
echo "🎉 Installation Complete!"
echo ""
echo "📋 Usage:"
# echo "   Interactive TUI:  ./opencli"  # Temporarily disabled
echo "   Command-line:     ./hlogcli analyze"
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    # echo "   User (TUI):       opencli (if ~/bin is in PATH)"  # Temporarily disabled
    echo "   User (CLI):       hlogcli analyze (if ~/bin is in PATH)"
    echo "   Direct:           ~/bin/hlogcli"
fi
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
print_success "Ready to analyze your logs! 🚀"
