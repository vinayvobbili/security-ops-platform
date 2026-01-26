#!/bin/bash
# Mac Migration Setup Script
# Run this after manually restoring SSH keys and age encryption key
# Usage: bash misc_scripts/mac_migration_setup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "  Mac Migration Setup Script"
echo "=========================================="
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print status
print_status() {
    if [ "$2" = "ok" ]; then
        echo -e "  ${GREEN}✓${NC} $1"
    elif [ "$2" = "warn" ]; then
        echo -e "  ${YELLOW}!${NC} $1"
    else
        echo -e "  ${RED}✗${NC} $1"
    fi
}

# ==========================================
# Pre-flight Checks
# ==========================================
echo "Step 1: Pre-flight Checks"
echo "-----------------------------------------"

# Check Homebrew
if command_exists brew; then
    print_status "Homebrew installed" "ok"
else
    print_status "Homebrew not installed - installing..." "warn"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    eval "$(/opt/homebrew/bin/brew shellenv)"
fi

# Check SSH key
if [ -f ~/.ssh/id_ed25519 ]; then
    print_status "SSH key exists" "ok"
else
    print_status "SSH key missing - please restore from backup" "fail"
    echo "       Copy your id_ed25519 and id_ed25519.pub to ~/.ssh/"
    exit 1
fi

# Check age key
if [ -f ~/.config/age/key.txt ]; then
    print_status "Age encryption key exists" "ok"
else
    print_status "Age key missing - please restore from backup" "fail"
    echo "       Copy your key.txt to ~/.config/age/"
    echo "       Without this, you cannot decrypt .secrets.age"
    exit 1
fi

echo ""

# ==========================================
# Install Homebrew Packages
# ==========================================
echo "Step 2: Installing Homebrew Packages"
echo "-----------------------------------------"

PACKAGES=(
    "age"
    "git"
    "gh"
    "ollama"
    "python@3.14"
    "dnstwist"
    "ssdeep"
    "libmaxminddb"
    "cmake"
)

for pkg in "${PACKAGES[@]}"; do
    if brew list "$pkg" &>/dev/null; then
        print_status "$pkg" "ok"
    else
        echo -e "  Installing $pkg..."
        brew install "$pkg" || print_status "Failed to install $pkg" "warn"
    fi
done

echo ""

# ==========================================
# Setup NVM and Node.js
# ==========================================
echo "Step 3: Setting up NVM and Node.js"
echo "-----------------------------------------"

export NVM_DIR="$HOME/.nvm"

if [ -d "$NVM_DIR" ]; then
    print_status "NVM directory exists" "ok"
else
    echo "  Installing NVM..."
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
fi

# Load NVM
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

if command_exists nvm; then
    print_status "NVM loaded" "ok"

    # Install LTS Node if not present
    if nvm ls --no-colors | grep -q "lts"; then
        print_status "Node.js LTS installed" "ok"
    else
        echo "  Installing Node.js LTS..."
        nvm install --lts
        nvm use --lts
    fi
else
    print_status "NVM not available - restart shell and re-run" "warn"
fi

echo ""

# ==========================================
# Install Global npm Packages
# ==========================================
echo "Step 4: Installing Global npm Packages"
echo "-----------------------------------------"

if command_exists npm; then
    # Claude Code
    if npm list -g @anthropic-ai/claude-code &>/dev/null; then
        print_status "Claude Code installed" "ok"
    else
        echo "  Installing Claude Code..."
        npm install -g @anthropic-ai/claude-code || print_status "Failed to install Claude Code" "warn"
    fi

    # Gemini CLI
    if npm list -g @google/gemini-cli &>/dev/null; then
        print_status "Gemini CLI installed" "ok"
    else
        echo "  Installing Gemini CLI..."
        npm install -g @google/gemini-cli || print_status "Failed to install Gemini CLI" "warn"
    fi
else
    print_status "npm not available - ensure Node.js is installed" "warn"
fi

echo ""

# ==========================================
# Configure .zshrc
# ==========================================
echo "Step 5: Configuring Shell"
echo "-----------------------------------------"

ZSHRC_ENTRIES=(
    'export PATH=~/.claude/local/node_modules/.bin:$PATH'
    'export NVM_DIR="$HOME/.nvm"'
    'export OLLAMA_FLASH_ATTENTION=1'
)

for entry in "${ZSHRC_ENTRIES[@]}"; do
    if grep -qF "$entry" ~/.zshrc 2>/dev/null; then
        print_status "zshrc: $(echo $entry | cut -c1-50)..." "ok"
    else
        echo "$entry" >> ~/.zshrc
        print_status "Added to zshrc: $(echo $entry | cut -c1-40)..." "ok"
    fi
done

# Add NVM loader if not present
if ! grep -q 'NVM_DIR.*nvm.sh' ~/.zshrc 2>/dev/null; then
    cat >> ~/.zshrc << 'EOF'
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"
EOF
    print_status "Added NVM loader to zshrc" "ok"
fi

echo ""

# ==========================================
# Configure Git Credentials
# ==========================================
echo "Step 6: Configuring Git"
echo "-----------------------------------------"

if [ -f ~/.gitconfig ]; then
    print_status "Git config exists" "ok"
else
    print_status "Git config missing - creating basic config" "warn"
    git config --global core.autocrlf input
fi

# Setup gh credential helper
if grep -q "gh auth git-credential" ~/.gitconfig 2>/dev/null; then
    print_status "GitHub credential helper configured" "ok"
else
    git config --global credential."https://github.com".helper ""
    git config --global --add credential."https://github.com".helper "!/opt/homebrew/bin/gh auth git-credential"
    git config --global credential."https://gist.github.com".helper ""
    git config --global --add credential."https://gist.github.com".helper "!/opt/homebrew/bin/gh auth git-credential"
    print_status "Added GitHub credential helper" "ok"
fi

# Check gh auth status
if gh auth status &>/dev/null; then
    print_status "GitHub CLI authenticated" "ok"
else
    print_status "GitHub CLI not authenticated" "warn"
    echo "       Run: gh auth login"
fi

echo ""

# ==========================================
# Setup IR Project
# ==========================================
echo "Step 7: Setting up IR Project"
echo "-----------------------------------------"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"
print_status "Working directory: $PROJECT_DIR" "ok"

# Create virtual environment if not exists
if [ -d ".venv" ]; then
    print_status "Virtual environment exists" "ok"
else
    echo "  Creating virtual environment..."
    python3 -m venv .venv
    print_status "Virtual environment created" "ok"
fi

# Activate and install requirements
source .venv/bin/activate
print_status "Virtual environment activated" "ok"

echo "  Installing Python dependencies (this may take a while)..."
pip install -q -r requirements.txt
print_status "Python dependencies installed" "ok"

# Install npm packages
if [ -f "package.json" ]; then
    echo "  Installing npm packages..."
    npm install --silent
    print_status "npm packages installed" "ok"
fi

echo ""

# ==========================================
# Verify Configuration
# ==========================================
echo "Step 8: Verification"
echo "-----------------------------------------"

# Test age decryption
if [ -f "data/transient/.secrets.age" ]; then
    if age -d -i ~/.config/age/key.txt data/transient/.secrets.age > /dev/null 2>&1; then
        print_status "Age decryption working" "ok"
    else
        print_status "Age decryption failed - check key.txt" "fail"
    fi
else
    print_status "No .secrets.age found - may need to create" "warn"
fi

# Test config loading
if python -c "from my_config import get_config; get_config()" 2>/dev/null; then
    print_status "Config loading works" "ok"
else
    print_status "Config loading failed - check .env and .secrets.age" "warn"
fi

echo ""

# ==========================================
# Summary
# ==========================================
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Run 'source ~/.zshrc' to reload shell"
echo "  2. Run 'gh auth login' if not authenticated"
echo "  3. Pull Ollama models: ollama pull qwen2.5:32b"
echo "  4. Test: python -c \"from my_config import get_config; print(get_config().team_name)\""
echo ""
echo "For full documentation, see: docs/MAC_MIGRATION.MD"
echo ""
