#!/usr/bin/env bash
# ==============================================================================
# LostFuzzer Installer v2.0.0
# Installs all required tools and dependencies for the LostFuzzer framework.
# Run with: sudo ./install.sh
# ==============================================================================

set -euo pipefail  # Exit on error, undefined variable, or pipe failure

# --- Configuration ---
GO_BIN_PATH="/root/go/bin"
TOOLS_DIR="/opt/lostfuzzer-tools"
WORDLIST_DIR="/usr/share/seclists/Discovery/Web-Content"
RESOLVERS_DIR="/usr/share/seclists/Miscellaneous"
NUCLEI_TEMPLATES_DIR="/root/nuclei-templates"
PYTHON="python3"
PIP="pip3"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# --- Helper Functions ---
# Ensure a Go binary is installed globally
install_go_tool() {
    local name="$1"
    local repo="$2"
    log_info "Installing ${name}..."
    if go install -v "${repo}"@latest &>/dev/null; then
        local binary_name=$(basename "${repo}" | cut -d'@' -f1)
        if [ -f "${GO_BIN_PATH}/${binary_name}" ]; then
            cp "${GO_BIN_PATH}/${binary_name}" /usr/local/bin/
            log_success "${name} installed successfully."
        else
            log_warn "${name} binary not found after build, skipping copy to /usr/local/bin."
        fi
    else
        log_error "Failed to install ${name}. Skipping..."
    fi
}

# Ensure a Python package is installed globally
install_pip_tool() {
    local name="$1"
    local package="$2"
    log_info "Installing ${name}..."
    if ${PIP} install --upgrade "${package}" &>/dev/null; then
        log_success "${name} installed successfully."
    else
        log_error "Failed to install ${name}. Skipping..."
    fi
}

# --- Installation Steps ---
echo -e "${GREEN}===================================================${NC}"
echo -e "${GREEN}   LostFuzzer Installer - Starting Setup${NC}"
echo -e "${GREEN}===================================================${NC}"

# 1. System Updates & Essential Packages
log_info "Updating system and installing essential packages..."
apt-get update -y &>/dev/null
apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    python3 \
    python3-pip \
    python3-venv \
    golang-go \
    cargo \
    snapd \
    libpcap-dev \
    chromium-browser \
    nmap \
    &>/dev/null
log_success "Essential packages installed."

# Ensure /usr/local/bin is in PATH for root
export PATH=$PATH:/usr/local/bin:/root/go/bin

# 2. Create Directory Structure
log_info "Creating directory structure..."
mkdir -p "${TOOLS_DIR}" "${WORDLIST_DIR}" "${RESOLVERS_DIR}" "${NUCLEI_TEMPLATES_DIR}"
log_success "Directory structure created."

# 3. Install Rust Tools (feroxbuster)
log_info "Installing Rust-based tools..."
if command -v cargo &>/dev/null; then
    cargo install feroxbuster &>/dev/null && log_success "feroxbuster installed." || log_error "Failed to install feroxbuster."
else
    log_error "Cargo not found. Cannot install feroxbuster."
fi

# 4. Install Snap Tools (amass, dalfox)
log_info "Installing Snap-based tools..."
systemctl enable --now snapd &>/dev/null
snap install amass &>/dev/null && log_success "amass installed." || log_error "Failed to install amass."
snap install dalfox &>/dev/null && log_success "dalfox installed." || log_error "Failed to install dalfox."

# 5. Install Go Tools (Majority of tools)
log_info "Installing Go-based tools..."
TOOLS=(
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx"
    "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu"
    "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx"
    "katana:github.com/projectdiscovery/katana/cmd/katana"
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
    "tlsx:github.com/projectdiscovery/tlsx/cmd/tlsx"
    "asnmap:github.com/projectdiscovery/asnmap/cmd/asnmap"
    "cdncheck:github.com/projectdiscovery/cdncheck/cmd/cdncheck"
    "shuffledns:github.com/projectdiscovery/shuffledns/cmd/shuffledns"
    "gau:github.com/lc/gau/v2/cmd/gau"
    "waybackurls:github.com/tomnomnom/waybackurls"
    "assetfinder:github.com/tomnomnom/assetfinder"
    "gf:github.com/tomnomnom/gf"
    "qsreplace:github.com/tomnomnom/qsreplace"
    "ffuf:github.com/ffuf/ffuf/v2"
    "gowitness:github.com/sensepost/gowitness"
    "crlfuzz:github.com/dwisiswant0/crlfuzz"
    "subzy:github.com/LukaSikic/subzy"
    "hakrawler:github.com/hakluke/hakrawler"
    "gospider:github.com/jaeles-project/gospider"
    "cariddi:github.com/edoardottt/cariddi/cmd/cariddi"
    "kxss:github.com/tomnomnom/hacks/kxss"
    "mantra:github.com/Brosck/mantra"
)

for tool in "${TOOLS[@]}"; do
    IFS=":" read -r name repo <<< "${tool}"
    install_go_tool "${name}" "${repo}"
done

# 6. Install Python Tools
log_info "Installing Python-based tools..."
PIP_TOOLS=(
    "uro:uro"
    "dirsearch:dirsearch"
    "arjun:arjun"
)

for tool in "${PIP_TOOLS[@]}"; do
    IFS=":" read -r name package <<< "${tool}"
    install_pip_tool "${name}" "${package}"
done

# 7. Manually Clone and Setup ParamSpider
log_info "Setting up ParamSpider..."
PARAMSPIDER_DIR="${TOOLS_DIR}/ParamSpider"
if [ ! -d "${PARAMSPIDER_DIR}" ]; then
    git clone https://github.com/devanshbatham/ParamSpider "${PARAMSPIDER_DIR}" &>/dev/null
fi
cd "${PARAMSPIDER_DIR}"
${PIP} install -r requirements.txt &>/dev/null
ln -sf "${PARAMSPIDER_DIR}/paramspider.py" /usr/local/bin/paramspider
log_success "ParamSpider setup complete."

# 8. Download Wordlists
log_info "Downloading wordlists..."
if [ ! -f "${WORDLIST_DIR}/raft-medium-words.txt" ]; then
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-words.txt" -O "${WORDLIST_DIR}/raft-medium-words.txt"
    log_success "raft-medium-words.txt downloaded."
else
    log_info "raft-medium-words.txt already exists."
fi

if [ ! -f "${RESOLVERS_DIR}/dns-resolvers.txt" ]; then
    wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -O "${RESOLVERS_DIR}/dns-resolvers.txt"
    log_success "dns-resolvers.txt downloaded."
else
    log_info "dns-resolvers.txt already exists."
fi

# 9. Install & Update Nuclei Templates
log_info "Installing Nuclei templates..."
if command -v nuclei &>/dev/null; then
    nuclei -update-templates -silent &>/dev/null && log_success "Nuclei templates updated." || log_error "Failed to update Nuclei templates."
else
    log_warn "Nuclei not found, cannot update templates."
fi

# 10. Final Setup & Verification
log_info "Verifying installation..."
FAILED_TOOLS=()
for cmd in subfinder httpx naabu dnsx katana nuclei amass assetfinder waybackurls gau ffuf feroxbuster dirsearch dalfox gowitness; do
    if command -v "${cmd}" &>/dev/null; then
        log_success "${cmd} is installed."
    else
        FAILED_TOOLS+=("${cmd}")
    fi
done

if [ ${#FAILED_TOOLS[@]} -ne 0 ]; then
    log_warn "The following tools may not have installed correctly: ${FAILED_TOOLS[*]}"
else
    log_success "All core tools installed successfully!"
fi

log_info "LostFuzzer installation complete."
echo -e "${GREEN}===================================================${NC}"
echo -e "${GREEN}   Installation Finished - Happy Hacking!${NC}"
echo -e "${GREEN}===================================================${NC}"
