#!/bin/bash

#  Access Log Analyzer - Installation Script
# For Hypernode servers and other Linux environments

set -e

echo "🚀  Access Log Analyzer Installation"
echo "==========================================="

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher first."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "✅ Python version: $PYTHON_VERSION"

# Check if running as root (for system-wide installation)
if [[ $EUID -eq 0 ]]; then
    INSTALL_DIR="/opt/logcli"
    BIN_DIR="/usr/local/bin"
    echo "📁 Installing as root to: $INSTALL_DIR"
else
    INSTALL_DIR="$HOME/logcli"
    BIN_DIR="$HOME/bin"
    echo "📁 Installing as user to: $INSTALL_DIR"
    mkdir -p "$BIN_DIR"
fi

# Create installation directory
echo "📁 Creating installation directory..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Check if git is available
if command -v git &> /dev/null; then
    echo "📥 Cloning repository..."
    if [ -d ".git" ]; then
        git pull
    else
        git clone https://github.com/hpowernl/access-logs-analyser.git .
    fi
else
    echo "⚠️  Git not available. Please manually copy files to $INSTALL_DIR"
    echo "   You can also download the files directly from GitHub."
fi

# Create virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Create wrapper script
echo "📝 Creating wrapper script..."
cat > "$BIN_DIR/logcli" << EOF
#!/bin/bash
#  Access Log Analyzer Wrapper Script

# Activate virtual environment and run logcli
source "$INSTALL_DIR/venv/bin/activate"
cd "$INSTALL_DIR"
python3 -m logcli "\$@"
EOF

# Make wrapper executable
chmod +x "$BIN_DIR/logcli"

# Create symlink for system-wide access (if root)
if [[ $EUID -eq 0 ]]; then
    ln -sf "$BIN_DIR/logcli" "/usr/bin/logcli" 2>/dev/null || true
fi

# Test installation
echo "🧪 Testing installation..."
"$BIN_DIR/logcli" --help > /dev/null

echo ""
echo "✅ Installation successful!"
echo ""
echo "📖 Usage:"
if [[ $EUID -eq 0 ]]; then
    echo "   logcli --auto-discover                    # Auto-discover nginx logs"
    echo "   logcli /var/log/nginx/access.log         # Analyze specific file"
    echo "   logcli -f -i --auto-discover             # Real-time interactive mode"
else
    echo "   $BIN_DIR/logcli --help                   # Show help"
    echo "   $BIN_DIR/logcli sample_access.log        # Test with sample data"
    echo ""
    echo "   Add $BIN_DIR to your PATH for global access:"
    echo "   echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc"
    echo "   source ~/.bashrc"
fi

echo ""
echo "📚 Documentation:"
echo "   README.md - General documentation"
echo "   USAGE_EXAMPLES.md - Usage examples"
echo ""
echo "🎯 For Hypernode servers:"
echo "   logcli --auto-discover              # Analyze all nginx logs"
echo "   logcli -f -i --auto-discover       # Real-time monitoring"
echo ""

# Create sample log for testing
if [ ! -f "sample_access.log" ]; then
    echo "📄 Creating sample log file for testing..."
    cat > sample_access.log << 'EOL'
{"time":"2025-09-17T08:10:17+00:00", "remote_addr":"94.124.105.4", "remote_user":"", "host":"m2.znzelectronics.cz", "request":"POST /graphql HTTP/1.1", "status":"200", "body_bytes_sent":"860", "referer":"", "user_agent":"GuzzleHttp/7", "request_time":"0.098", "handler":"phpfpm", "country":"CZ", "server_name":"m2.znzelectronics.cz", "port":"8080", "ssl_cipher":"", "ssl_protocol":""}
{"time":"2025-09-17T08:10:20+00:00", "remote_addr":"34.196.114.170", "remote_user":"", "host":"m2.znzelectronics.cz", "request":"GET /stores/store/redirect/ HTTP/1.1", "status":"302", "body_bytes_sent":"5", "referer":"", "user_agent":"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot) Chrome/119.0.6045.214 Safari/537.36", "request_time":"0.052", "handler":"phpfpm", "country":"US", "server_name":"m2.znzelectronics.cz", "port":"8080", "ssl_cipher":"", "ssl_protocol":""}
{"time":"2025-09-17T08:10:21+00:00", "remote_addr":"82.103.139.165", "remote_user":"", "host":"m2.znzelectronics.cz", "request":"GET /index.php/mx_admin HTTP/1.1", "status":"200", "body_bytes_sent":"2435", "referer":"", "user_agent":"Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)", "request_time":"0.066", "handler":"phpfpm", "country":"DK", "server_name":"m2.znzelectronics.cz", "port":"8080", "ssl_cipher":"", "ssl_protocol":""}
EOL
    echo "✅ Sample log created: sample_access.log"
fi

echo "🎉 Installation completed! You can now use logcli."