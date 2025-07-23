#!/bin/bash

# Advanced SQL Injection Scanner Setup Script
# Installs Python dependencies and optional reconnaissance tools

set -e

echo "🚀 Setting up Advanced SQL Injection Scanner..."

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
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is required but not installed. Please install Python 3.7+ and try again."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
print_success "Found Python $PYTHON_VERSION"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is required but not installed. Please install pip3 and try again."
    exit 1
fi

# Install Python dependencies
print_status "Installing Python dependencies..."
if pip3 install -r requirements.txt; then
    print_success "Python dependencies installed successfully"
else
    print_error "Failed to install Python dependencies"
    exit 1
fi

# Make scripts executable
print_status "Making scripts executable..."
chmod +x sqli_scanner.py
chmod +x advanced_scanner.py
print_success "Scripts are now executable"

# Check for Go installation (for optional tools)
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    print_success "Found Go $GO_VERSION"
    
    # Ask user if they want to install optional tools
    echo ""
    read -p "Do you want to install optional reconnaissance tools (GAU, Katana)? [y/N]: " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Installing GAU (GetAllURLs)..."
        if go install github.com/lc/gau/v2/cmd/gau@latest; then
            print_success "GAU installed successfully"
        else
            print_warning "Failed to install GAU"
        fi
        
        print_status "Installing Katana web crawler..."
        if go install github.com/projectdiscovery/katana/cmd/katana@latest; then
            print_success "Katana installed successfully"
        else
            print_warning "Failed to install Katana"
        fi
        
        # Add Go bin to PATH if not already there
        if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
            print_warning "Note: Add $HOME/go/bin to your PATH to use the installed tools:"
            echo "export PATH=\$PATH:\$HOME/go/bin"
        fi
    else
        print_warning "Skipping optional tools installation"
        print_warning "Note: Without GAU and Katana, the scanner will use only Wayback Machine and common endpoints"
    fi
else
    print_warning "Go is not installed. Optional tools (GAU, Katana) will not be available."
    print_warning "Install Go from https://golang.org/dl/ to use enhanced URL discovery"
fi

# Create example configuration files
print_status "Creating example configuration files..."

# Create example URLs file
cat > example_urls.txt << EOF
# Example URLs file for testing
# Add one URL per line with parameters
https://example.com/page.php?id=1
https://example.com/search.php?q=test&category=news
https://example.com/product.php?id=123&action=view
https://example.com/user.php?id=1&admin=false
EOF

print_success "Created example_urls.txt"

# Verify installation
print_status "Verifying installation..."

if python3 -c "import aiohttp, asyncio, json, re" 2>/dev/null; then
    print_success "All Python dependencies are working correctly"
else
    print_error "Some Python dependencies are missing or broken"
    exit 1
fi

# Display usage information
echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "📖 Quick Start:"
echo "  Basic scan:    python3 sqli_scanner.py -d example.com"
echo "  Advanced scan: python3 advanced_scanner.py -d example.com"
echo ""
echo "📚 For detailed usage information, see README.md"
echo ""
echo "⚠️  Ethical Usage Reminder:"
echo "  Only use this tool on systems you own or have explicit permission to test."
echo "  Unauthorized testing may violate laws and regulations."
echo ""
print_success "Happy ethical hacking! 🛡️"