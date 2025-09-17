#!/bin/bash

# NextGen Access Log Analyzer - Installation Script
# Voor Hypernode servers en andere Linux omgevingen

set -e

echo "🚀 NextGen Access Log Analyzer Installatie"
echo "========================================="

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is niet geïnstalleerd. Installeer eerst Python 3.8 of hoger."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "✅ Python versie: $PYTHON_VERSION"

# Check if running as root (for system-wide installation)
if [[ $EUID -eq 0 ]]; then
    INSTALL_DIR="/opt/logcli"
    BIN_DIR="/usr/local/bin"
    echo "📁 Installatie als root naar: $INSTALL_DIR"
else
    INSTALL_DIR="$HOME/logcli"
    BIN_DIR="$HOME/bin"
    echo "📁 Installatie als gebruiker naar: $INSTALL_DIR"
    mkdir -p "$BIN_DIR"
fi

# Create installation directory
echo "📁 Maken van installatie directory..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Check if git is available
if command -v git &> /dev/null; then
    echo "📥 Clonen van repository..."
    if [ -d ".git" ]; then
        git pull
    else
        git clone https://github.com/yourusername/nextgen-logcli.git .
    fi
else
    echo "⚠️  Git niet beschikbaar. Kopieer handmatig de bestanden naar $INSTALL_DIR"
    echo "   Je kunt ook de bestanden direct downloaden van GitHub."
fi

# Create virtual environment
echo "🐍 Maken van Python virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "📦 Upgraden van pip..."
pip install --upgrade pip

# Install dependencies
echo "📦 Installeren van dependencies..."
pip install -r requirements.txt

# Create wrapper script
echo "📝 Maken van wrapper script..."
cat > "$BIN_DIR/logcli" << EOF
#!/bin/bash
# NextGen Access Log Analyzer Wrapper Script

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
echo "🧪 Testen van installatie..."
"$BIN_DIR/logcli" --help > /dev/null

echo ""
echo "✅ Installatie succesvol!"
echo ""
echo "📖 Gebruik:"
if [[ $EUID -eq 0 ]]; then
    echo "   logcli --auto-discover                    # Auto-discover nginx logs"
    echo "   logcli /var/log/nginx/access.log         # Analyseer specifiek bestand"
    echo "   logcli -f -i --auto-discover             # Realtime interactieve modus"
else
    echo "   $BIN_DIR/logcli --help                   # Toon help"
    echo "   $BIN_DIR/logcli sample_access.log        # Test met sample data"
    echo ""
    echo "   Voeg $BIN_DIR toe aan je PATH voor globale toegang:"
    echo "   echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc"
    echo "   source ~/.bashrc"
fi

echo ""
echo "📚 Documentatie:"
echo "   README.md - Algemene documentatie"
echo "   USAGE_EXAMPLES.md - Gebruiksvoorbeelden"
echo ""
echo "🎯 Voor Hypernode servers:"
echo "   sudo logcli --auto-discover              # Analyseer alle nginx logs"
echo "   sudo logcli -f -i --auto-discover       # Realtime monitoring"
echo ""

# Create sample log for testing
if [ ! -f "sample_access.log" ]; then
    echo "📄 Maken van sample log bestand voor testen..."
    cat > sample_access.log << 'EOL'
{"time":"2025-09-17T08:10:17+00:00", "remote_addr":"94.124.105.4", "remote_user":"", "host":"m2.znzelectronics.cz", "request":"POST /graphql HTTP/1.1", "status":"200", "body_bytes_sent":"860", "referer":"", "user_agent":"GuzzleHttp/7", "request_time":"0.098", "handler":"phpfpm", "country":"CZ", "server_name":"m2.znzelectronics.cz", "port":"8080", "ssl_cipher":"", "ssl_protocol":""}
{"time":"2025-09-17T08:10:20+00:00", "remote_addr":"34.196.114.170", "remote_user":"", "host":"m2.znzelectronics.cz", "request":"GET /stores/store/redirect/ HTTP/1.1", "status":"302", "body_bytes_sent":"5", "referer":"", "user_agent":"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot) Chrome/119.0.6045.214 Safari/537.36", "request_time":"0.052", "handler":"phpfpm", "country":"US", "server_name":"m2.znzelectronics.cz", "port":"8080", "ssl_cipher":"", "ssl_protocol":""}
{"time":"2025-09-17T08:10:21+00:00", "remote_addr":"82.103.139.165", "remote_user":"", "host":"m2.znzelectronics.cz", "request":"GET /index.php/mx_admin HTTP/1.1", "status":"200", "body_bytes_sent":"2435", "referer":"", "user_agent":"Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)", "request_time":"0.066", "handler":"phpfpm", "country":"DK", "server_name":"m2.znzelectronics.cz", "port":"8080", "ssl_cipher":"", "ssl_protocol":""}
EOL
    echo "✅ Sample log gemaakt: sample_access.log"
fi

echo "🎉 Installatie voltooid! Je kunt nu logcli gebruiken."
