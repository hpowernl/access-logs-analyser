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

# Install Python dependencies
print_status "Installing Python dependencies..."
echo "   This will install packages system-wide"
echo "   Dependencies: textual, rich, click, pandas, plotly, etc."
echo ""

if pip3 install -r requirements.txt; then
    print_success "Python dependencies installed successfully"
else
    print_error "Failed to install Python dependencies"
    print_warning "You might need to run: sudo pip3 install -r requirements.txt"
    exit 1
fi

# Make opencli executable
print_status "Making opencli executable..."
chmod +x opencli
print_success "opencli is now executable"

# Check if /usr/local/bin is in PATH
print_status "Checking installation paths..."
if [[ ":$PATH:" == *":/usr/local/bin:"* ]]; then
    print_success "/usr/local/bin is in PATH"
else
    print_warning "/usr/local/bin is not in PATH"
fi

# Offer to install globally
echo ""
echo "🔧 Installation Options:"
echo "   1. Use locally: ./opencli"
echo "   2. Install globally to /usr/local/bin (requires sudo)"
echo ""
read -p "Install globally? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Installing globally..."
    
    # Create symlink to /usr/local/bin
    if sudo ln -sf "$(pwd)/opencli" /usr/local/bin/opencli; then
        print_success "Global installation complete!"
        print_success "You can now run 'opencli' from anywhere"
    else
        print_error "Failed to install globally"
        print_warning "You can still use: ./opencli"
    fi
else
    print_success "Local installation complete!"
    print_status "Use: ./opencli to run the application"
fi

# Test installation
echo ""
print_status "Testing installation..."
if ./opencli --help &> /dev/null; then
    print_success "Installation test passed!"
else
    print_error "Installation test failed"
    print_warning "Try running: python3 -m opencli_app.simple_app"
fi

# Show usage instructions
echo ""
echo "🎉 Installation Complete!"
echo ""
echo "📋 Usage:"
echo "   Local:  ./opencli"
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "   Global: opencli"
fi
echo ""
echo "📁 Log Analysis:"
echo "   • Automatically finds nginx logs in /var/log/nginx/"
echo "   • Falls back to sample_access.log for testing"
echo "   • Real-time log monitoring and analysis"
echo ""
echo "🔧 Troubleshooting:"
echo "   • If modules not found: pip3 install -r requirements.txt"
echo "   • If permission denied: chmod +x opencli"
echo "   • For help: ./opencli --help"
echo ""
print_success "Ready to analyze your logs! 🚀"
