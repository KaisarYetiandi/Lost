#!/bin/bash

VERSION="2.1.0"
TOOLS_DIR="/opt/lostfuzzer-tools"

R='\033[0m'
PU='\033[38;5;93m'
PM='\033[38;5;129m'
PR='\033[38;5;197m'
GR='\033[0;32m'
YL='\033[0;33m'
RD='\033[0;31m'
DM='\033[2m'
BW='\033[1;37m'

ok()   { printf "  ${GR}[ OK  ]${R}  ${DM}%s${R}\n" "$1"; }
run()  { printf "  ${YL}[ RUN ]${R}  ${DM}%s${R}\n" "$1"; }
err()  { printf "  ${RD}[ ERR ]${R}  %s\n" "$1"; }
info() { printf "  ${PU}[INFO ]${R}  ${DM}%s${R}\n" "$1"; }
hdr()  { printf "\n  ${PM}──  ${BW}%s${R}  ${PM}%s${R}\n\n" "$1" "$(printf '─%.0s' {1..40})"; }

clear
printf "\n"
printf "  ${PU}${BW}  ██╗      ██████╗ ███████╗████████╗${R}\n"
printf "  ${PM}  ██║     ██╔═══██╗██╔════╝╚══██╔══╝${R}\n"
printf "  ${PR}  ██║     ██║   ██║███████╗   ██║   ${R}\n"
printf "  ${RD}  ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝   ${R}\n"
printf "\n"
printf "  ${DM}LostFuzzer v${VERSION} — Installer${R}\n\n"

if [[ $EUID -ne 0 ]]; then
    err "Must be run as root (sudo bash install.sh)"
    exit 1
fi

hdr "SYSTEM PACKAGES"

run "apt-get update"
apt-get update -qq 2>/dev/null && ok "apt updated" || err "apt update failed"

PKGS=(
    python3 python3-pip python3-dev python3-venv
    golang-go git curl wget jq unzip tar
    chromium-browser libssl-dev libffi-dev
    build-essential libpcap-dev nmap tor
)

for pkg in "${PKGS[@]}"; do
    if dpkg -s "$pkg" &>/dev/null 2>&1; then
        ok "$pkg (exists)"
    else
        run "$pkg"
        apt-get install -y -qq "$pkg" 2>/dev/null \
        && ok "$pkg" \
        || { apt-get install -y -qq "${pkg%-*}" 2>/dev/null && ok "$pkg" || info "skipped: $pkg"; }
    fi
done

hdr "GO ENVIRONMENT"

GOROOT_BIN=$(go env GOPATH 2>/dev/null || echo "$HOME/go")
GOBIN="$GOROOT_BIN/bin"
mkdir -p "$GOBIN"

PROFILE_FILE="$HOME/.bashrc"
if ! grep -q "GOPATH" "$PROFILE_FILE" 2>/dev/null; then
    echo "export GOPATH=$GOROOT_BIN" >> "$PROFILE_FILE"
    echo "export PATH=\$PATH:$GOBIN"  >> "$PROFILE_FILE"
fi
export GOPATH="$GOROOT_BIN"
export PATH="$PATH:$GOBIN"
info "GOPATH: $GOROOT_BIN"
info "GOBIN:  $GOBIN"

GO_VER=$(go version 2>/dev/null | awk '{print $3}')
info "Go: ${GO_VER:-not found}"

hdr "PROJECTDISCOVERY TOOLS"

PD_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/uncover/cmd/uncover@latest"
    "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
)

for mod in "${PD_TOOLS[@]}"; do
    name=$(basename "${mod%%@*}")
    run "$name"
    GONOSUMCHECK=off go install "$mod" 2>/dev/null \
    && ok "$name" || err "$name"
done

hdr "RECON & FUZZING TOOLS"

OTHER_GO=(
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/sensepost/gowitness@latest"
)

for mod in "${OTHER_GO[@]}"; do
    name=$(basename "${mod%%@*}")
    run "$name"
    go install "$mod" 2>/dev/null && ok "$name" || err "$name"
done

hdr "VULNERABILITY TOOLS (GO)"

VULN_GO=(
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/dwisiswant0/crlfuzz@latest"
    "github.com/lukasikic/subzy@latest"
    "github.com/trufflesecurity/trufflehog/v3@latest"
)

for mod in "${VULN_GO[@]}"; do
    name=$(basename "${mod%%@*}")
    run "$name"
    go install "$mod" 2>/dev/null && ok "$name" || err "$name"
done

hdr "FEROXBUSTER"

if command -v feroxbuster &>/dev/null; then
    ok "feroxbuster (exists)"
else
    run "feroxbuster binary"
    FEROX_URL="https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip"
    TMP=$(mktemp)
    curl -sL "$FEROX_URL" -o "$TMP" 2>/dev/null
    if [ -s "$TMP" ]; then
        unzip -qq "$TMP" -d /usr/local/bin/ feroxbuster 2>/dev/null \
        && chmod +x /usr/local/bin/feroxbuster \
        && ok "feroxbuster" \
        || err "feroxbuster extract failed"
    else
        err "feroxbuster download failed"
    fi
    rm -f "$TMP"
fi

hdr "PYTHON PACKAGES"

PIP_PKGS=(
    "uro"
    "paramspider"
    "rich>=13.0.0"
    "requests>=2.31.0"
    "pyyaml>=6.0"
    "urllib3>=2.0.0"
    "jinja2"
)

for pkg in "${PIP_PKGS[@]}"; do
    run "$pkg"
    pip3 install -q "$pkg" --break-system-packages 2>/dev/null \
    || pip3 install -q "$pkg" 2>/dev/null \
    && ok "$pkg" || err "$pkg"
done

if [ -f "requirements.txt" ]; then
    run "requirements.txt"
    pip3 install -q -r requirements.txt --break-system-packages 2>/dev/null \
    || pip3 install -q -r requirements.txt 2>/dev/null \
    && ok "requirements.txt" || err "requirements.txt"
fi

hdr "PYTHON TOOLS (GIT CLONE)"

mkdir -p "$TOOLS_DIR"

clone_tool() {
    local url="$1"
    local name="$2"
    local req="$3"
    local dst="$TOOLS_DIR/$name"
    run "$name"
    if [ -d "$dst" ]; then
        git -C "$dst" pull -q 2>/dev/null && ok "$name (updated)" || ok "$name (exists)"
    else
        git clone -q --depth 1 "$url" "$dst" 2>/dev/null && ok "$name" || { err "$name"; return; }
    fi
    if [ -n "$req" ] && [ -f "$dst/$req" ]; then
        pip3 install -q -r "$dst/$req" --break-system-packages 2>/dev/null \
        || pip3 install -q -r "$dst/$req" 2>/dev/null
    fi
}

clone_tool "https://github.com/s0md3v/XSStrike.git"           "XSStrike"      "requirements.txt"
clone_tool "https://github.com/m4ll0k/SecretFinder.git"        "SecretFinder"  "requirements.txt"
clone_tool "https://github.com/nicowillis/Corsy.git"           "Corsy"         "requirements.txt"
clone_tool "https://github.com/ticarpi/jwt_tool.git"           "jwt-tool"      "requirements.txt"
clone_tool "https://github.com/arthaud/git-dumper.git"         "git-dumper"    "requirements.txt"
clone_tool "https://github.com/0xKayala/SSRFmap.git"           "SSRFmap"       "requirements.txt"
clone_tool "https://github.com/xnl-h4ck3r/xnLinkFinder.git"   "xnLinkFinder"  "requirements.txt"

make_wrapper() {
    local bin_name="$1"
    local script_path="$2"
    local wrapper="/usr/local/bin/$bin_name"
    if [ -f "$TOOLS_DIR/$script_path" ]; then
        cat > "$wrapper" << WEOF
#!/bin/bash
exec python3 "$TOOLS_DIR/$script_path" "\$@"
WEOF
        chmod +x "$wrapper"
        ok "wrapper: $bin_name"
    fi
}

make_wrapper "xsstrike"     "XSStrike/xsstrike.py"
make_wrapper "SecretFinder" "SecretFinder/SecretFinder.py"
make_wrapper "corsy"        "Corsy/corsy.py"
make_wrapper "jwt-tool"     "jwt-tool/jwt_tool.py"
make_wrapper "ssrfmap"      "SSRFmap/ssrfmap.py"
make_wrapper "xnLinkFinder" "xnLinkFinder/xnLinkFinder.py"

hdr "DIRSEARCH"

if command -v dirsearch &>/dev/null || python3 -m dirsearch --version &>/dev/null 2>&1; then
    ok "dirsearch (exists)"
else
    run "dirsearch"
    pip3 install -q dirsearch --break-system-packages 2>/dev/null \
    || pip3 install -q dirsearch 2>/dev/null \
    || {
        clone_tool "https://github.com/maurosoria/dirsearch.git" "dirsearch" "requirements.txt"
        make_wrapper "dirsearch" "dirsearch/dirsearch.py"
    }
    ok "dirsearch"
fi

hdr "SECLISTS WORDLISTS"

if [ -d /usr/share/seclists ]; then
    ok "seclists (exists)"
else
    run "seclists"
    apt-get install -y -qq seclists 2>/dev/null && ok "seclists" || {
        info "Cloning SecLists (this may take a while)..."
        git clone -q --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null \
        && ok "seclists" || err "seclists"
    }
fi

hdr "NUCLEI TEMPLATES"

run "nuclei -update-templates"
"$GOBIN/nuclei" -update-templates -silent 2>/dev/null \
|| nuclei -update-templates -silent 2>/dev/null \
&& ok "nuclei templates" || info "nuclei update skipped (run manually)"

hdr "PROJECT SETUP"

[ -f "lost.py" ] && chmod +x lost.py && ok "chmod +x lost.py" || info "lost.py not in current directory"
mkdir -p results logs 2>/dev/null && ok "results/ logs/"

if [ ! -f config.yaml ]; then
cat > config.yaml << 'CFGEOF'
threads: 50
rate_limit: 150
timeout: 15
retries: 3
proxy: null
tor: false
tor_proxy: socks5://127.0.0.1:9050
wordlist: /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
resolvers: /usr/share/seclists/Miscellaneous/dns-resolvers.txt
nuclei_templates: ~/nuclei-templates
notify_telegram: false
telegram_token: ""
telegram_chatid: ""
output_json: true
screenshot: true
wildcard_filter: true
cdn_filter: false
user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
scope: []
exclude: []
ports: 80,443,8080,8443,8888,3000,3001,5000,5001,8000,8001,9090,9443
depth: 5
delay: 0
follow_redirects: true
nuclei_severity: critical,high,medium,low
CFGEOF
    ok "config.yaml created"
else
    ok "config.yaml exists"
fi

hdr "DEPENDENCY CHECK"

CHECK_TOOLS=(
    subfinder dnsx httpx naabu katana nuclei
    uncover cdncheck tlsx asnmap
    gau waybackurls ffuf dalfox crlfuzz
    subzy gowitness feroxbuster trufflehog
)

MISSING=()
for t in "${CHECK_TOOLS[@]}"; do
    if command -v "$t" &>/dev/null || [ -f "$GOBIN/$t" ]; then
        ok "$t"
    else
        err "$t"
        MISSING+=("$t")
    fi
done

printf "\n"
if [ ${#MISSING[@]} -eq 0 ]; then
    printf "  ${GR}${BW}All tools verified.${R}\n\n"
else
    printf "  ${YL}Missing: ${MISSING[*]}${R}\n"
    printf "  ${DM}Ensure $GOBIN is in PATH, then retry.${R}\n\n"
fi

printf "  ${PU}Usage:${R}  ${BW}python3 lost.py${R}\n"
printf "  ${PU}      ${R}  ${BW}python3 lost.py example.com${R}\n"
printf "  ${PU}      ${R}  ${BW}python3 lost.py targets.txt${R}\n\n"
