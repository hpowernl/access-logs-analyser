#!/bin/bash

# 🚀 Hypernode Access Log Analyzer - Installation Script
# For Hypernode servers and other Linux/macOS environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Hypernode Access Log Analyzer Installation${NC}"
echo "=============================================="

# Function to print colored messages
print_status() {
    echo -e "${GREEN}✅${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ️${NC} $1"
}

# Check Python version
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3.8 or higher first."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info[0])')
PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info[1])')

print_status "Python version: $PYTHON_VERSION"

# Check if Python version is sufficient (3.8+)
if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 8 ]]; then
    print_error "Python 3.8 or higher is required. Current version: $PYTHON_VERSION"
    exit 1
fi

# Detect installation mode and set directories
if [[ $EUID -eq 0 ]]; then
    INSTALL_DIR="/opt/hypernode-logcli"
    BIN_DIR="/usr/local/bin"
    print_info "Installing as root to: $INSTALL_DIR"
else
    INSTALL_DIR="$HOME/hypernode-logcli"
    BIN_DIR="$HOME/bin"
    print_info "Installing as user to: $INSTALL_DIR"
    mkdir -p "$BIN_DIR"
fi

# Detect OS for platform-specific adjustments
OS=$(uname -s)
print_info "Detected OS: $OS"

# Create installation directory
print_info "Creating installation directory..."
mkdir -p "$INSTALL_DIR"

# Check if we're installing from the source directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/logcli/main.py" && -f "$SCRIPT_DIR/requirements.txt" ]]; then
    print_status "Installing from source directory: $SCRIPT_DIR"
    # Copy files to installation directory
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    cd "$INSTALL_DIR"
else
    cd "$INSTALL_DIR"
    print_warning "Source files not found in script directory"
fi

# Handle Git repository cloning only if not installing from source
if [[ ! -f "$INSTALL_DIR/logcli/main.py" ]]; then
    if command -v git &> /dev/null; then
        print_info "Cloning repository from GitHub..."
        if [ -d ".git" ]; then
            git pull
        else
            # Update this URL to the correct repository when available
            git clone https://github.com/yourusername/hypernode-logs.git .
        fi
    else
        print_warning "Git not available and source files not found."
        print_warning "Please manually copy the source files to $INSTALL_DIR"
        print_warning "Or download directly from GitHub."
        exit 1
    fi
fi

# Verify required files exist
if [[ ! -f "$INSTALL_DIR/requirements.txt" || ! -f "$INSTALL_DIR/logcli/main.py" ]]; then
    print_error "Required files not found in $INSTALL_DIR"
    print_error "Please ensure the following files exist:"
    print_error "  - requirements.txt"
    print_error "  - logcli/main.py"
    print_error "  - opencli"
    exit 1
fi

# Create virtual environment
print_info "Creating Python virtual environment..."
if ! python3 -m venv venv; then
    print_error "Failed to create virtual environment"
    exit 1
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
print_info "Upgrading pip..."
if ! pip install --upgrade pip; then
    print_warning "Failed to upgrade pip, continuing..."
fi

# Install dependencies
print_info "Installing Python dependencies..."
if ! pip install -r requirements.txt; then
    print_error "Failed to install dependencies"
    print_error "Please check your internet connection and try again"
    exit 1
fi

print_status "Dependencies installed successfully"

# Create CLI wrapper script
print_info "Creating CLI wrapper script..."
cat > "$BIN_DIR/logcli" << EOF
#!/bin/bash
# 🚀 Hypernode Access Log Analyzer CLI Wrapper Script

# Activate virtual environment and run logcli
source "$INSTALL_DIR/venv/bin/activate"
cd "$INSTALL_DIR"
python3 -m logcli "\$@"
EOF

# Create interactive TUI wrapper script
print_info "Creating interactive TUI wrapper script..."
cat > "$BIN_DIR/opencli" << EOF
#!/bin/bash
# 🚀 Hypernode Access Log Analyzer Interactive TUI Wrapper Script

# Activate virtual environment and run opencli
source "$INSTALL_DIR/venv/bin/activate"
cd "$INSTALL_DIR"
python3 opencli
EOF

# Make wrapper scripts executable
chmod +x "$BIN_DIR/logcli"
chmod +x "$BIN_DIR/opencli"

# Create system-wide symlinks (if root)
if [[ $EUID -eq 0 ]]; then
    print_info "Creating system-wide symlinks..."
    ln -sf "$BIN_DIR/logcli" "/usr/bin/logcli" 2>/dev/null || true
    ln -sf "$BIN_DIR/opencli" "/usr/bin/opencli" 2>/dev/null || true
fi

# Test installation
print_info "Testing installation..."
if "$BIN_DIR/logcli" --help > /dev/null 2>&1; then
    print_status "CLI installation test passed"
else
    print_warning "CLI installation test failed, but continuing..."
fi

# Test interactive mode availability
if python3 -c "import textual" 2>/dev/null; then
    print_status "Interactive TUI mode available"
else
    print_warning "Interactive TUI mode may not work (textual not properly installed)"
fi

echo ""
print_status "Installation completed successfully!"
echo ""
echo -e "${BLUE}📖 Usage Examples:${NC}"
if [[ $EUID -eq 0 ]]; then
    echo "   # CLI Commands:"
    echo "   logcli analyze --auto-discover                    # Auto-discover and analyze nginx logs"
    echo "   logcli security --auto-discover --scan-attacks   # Security analysis with attack detection"
    echo "   logcli perf --auto-discover --response-time-analysis  # Performance analysis"
    echo "   logcli bots --auto-discover --classify-types     # Bot classification and analysis"
    echo "   logcli search --auto-discover --status 404      # Search for specific patterns"
    echo "   logcli report --auto-discover --export-html     # Generate comprehensive reports"
    echo ""
    echo "   # Interactive TUI Mode:"
    echo "   opencli                                          # Launch interactive interface"
else
    echo "   # CLI Commands:"
    echo "   $BIN_DIR/logcli analyze --help                  # Show help for analyze command"
    echo "   $BIN_DIR/logcli analyze sample_access.log       # Test with sample data"
    echo "   $BIN_DIR/logcli security sample_access.log      # Security analysis"
    echo "   $BIN_DIR/logcli perf sample_access.log          # Performance analysis"
    echo ""
    echo "   # Interactive TUI Mode:"
    echo "   $BIN_DIR/opencli                                # Launch interactive interface"
    echo ""
    echo -e "${YELLOW}   💡 Add $BIN_DIR to your PATH for global access:${NC}"
    echo "   echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc"
    echo "   source ~/.bashrc"
fi

echo ""
echo -e "${BLUE}📚 Available Commands:${NC}"
echo "   analyze  - Basic log analysis with filtering options"
echo "   security - Security analysis and threat detection"
echo "   perf     - Performance monitoring and optimization insights"
echo "   bots     - Bot classification and behavior analysis"
echo "   search   - Advanced search and filtering capabilities"
echo "   report   - Comprehensive report generation with exports"
echo "   config   - Configuration management"
echo ""
echo -e "${BLUE}🎯 For Hypernode Servers:${NC}"
echo "   logcli analyze --auto-discover                   # Analyze all nginx logs"
echo "   logcli security --auto-discover --scan-attacks  # Security monitoring"
echo "   opencli                                          # Interactive dashboard"
echo ""

# Create sample log for testing if it doesn't exist
if [[ ! -f "$INSTALL_DIR/sample_access.log" ]]; then
    print_info "Creating sample log file for testing..."
    cat > "$INSTALL_DIR/sample_access.log" << 'EOL'
{"time":"2025-09-17T08:10:17+00:00", "remote_addr":"94.124.105.4", "remote_user":"", "host":"m2.znzelectronics.cz", "request":"POST /graphql HTTP/1.1", "status":"200", "body_bytes_sent":"860", "referer":"", "user_agent":"GuzzleHttp/7", "request_time":"0.098", "handler":"phpfpm", "country":"CZ", "server_name":"m2.znzelectronics.cz", "port":"8080", "ssl_cipher":"", "ssl_protocol":""}
{"time":"2025-09-17T08:10:20+00:00", "remote_addr":"34.196.114.170", "remote_user":"", "host":"m2.znzelectronics.cz", "request":"GET /stores/store/redirect/ HTTP/1.1", "status":"302", "body_bytes_sent":"5", "referer":"", "user_agent":"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot) Chrome/119.0.6045.214 Safari/537.36", "request_time":"0.052", "handler":"phpfpm", "country":"US", "server_name":"m2.znzelectronics.cz", "port":"8080", "ssl_cipher":"", "ssl_protocol":""}
{"time":"2025-09-17T08:10:21+00:00", "remote_addr":"82.103.139.165", "remote_user":"", "host":"m2.znzelectronics.cz", "request":"GET /index.php/mx_admin HTTP/1.1", "status":"200", "body_bytes_sent":"2435", "referer":"", "user_agent":"Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)", "request_time":"0.066", "handler":"phpfpm", "country":"DK", "server_name":"m2.znzelectronics.cz", "port":"8080", "ssl_cipher":"", "ssl_protocol":""}
{"time":"2025-09-17T08:10:22+00:00", "remote_addr":"192.168.1.100", "remote_user":"", "host":"m2.znzelectronics.cz", "request":"GET /admin/login HTTP/1.1", "status":"404", "body_bytes_sent":"1234", "referer":"", "user_agent":"curl/7.68.0", "request_time":"0.025", "handler":"phpfpm", "country":"NL", "server_name":"m2.znzelectronics.cz", "port":"8080", "ssl_cipher":"", "ssl_protocol":""}
{"time":"2025-09-17T08:10:23+00:00", "remote_addr":"10.0.0.1", "remote_user":"", "host":"m2.znzelectronics.cz", "request":"GET /wp-admin/ HTTP/1.1", "status":"500", "body_bytes_sent":"567", "referer":"", "user_agent":"WordPress/6.0; https://example.com", "request_time":"1.234", "handler":"phpfpm", "country":"US", "server_name":"m2.znzelectronics.cz", "port":"8080", "ssl_cipher":"", "ssl_protocol":""}
EOL
    print_status "Sample log created: $INSTALL_DIR/sample_access.log"
fi

# Final success message
echo ""
echo -e "${GREEN}🎉 Hypernode Access Log Analyzer installation completed successfully!${NC}"
echo ""
echo -e "${BLUE}📋 Installation Summary:${NC}"
echo "   Installation Directory: $INSTALL_DIR"
echo "   Binary Directory: $BIN_DIR"
echo "   CLI Command: logcli"
echo "   Interactive TUI: opencli"
echo "   Python Version: $PYTHON_VERSION"
echo ""
echo -e "${GREEN}✅ Ready to analyze your Nginx access logs!${NC}"