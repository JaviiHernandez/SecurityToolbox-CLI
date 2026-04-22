#!/usr/bin/env bash
# Install every external tool stbox orchestrates, on Debian/Ubuntu or Kali.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/JaviiHernandez/SecurityToolbox-CLI/main/install-linux.sh | bash
#   OR
#   ./install-linux.sh

set -euo pipefail

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; }

# Detect distro
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"
else
    err "cannot detect Linux distribution"
    exit 1
fi
info "Detected distro: $DISTRO"

SUDO=""
if [[ $EUID -ne 0 ]]; then
    SUDO="sudo"
fi

bold "==> apt packages"
$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
    ca-certificates curl wget git build-essential \
    python3 python3-pip python3-venv pipx \
    ruby ruby-dev \
    perl libnet-ssleay-perl libio-socket-ssl-perl \
    nodejs npm \
    libffi-dev libssl-dev zlib1g-dev \
    dnsutils unzip tar gzip

# ---- Go ---------------------------------------------------------------

if ! command -v go >/dev/null 2>&1; then
    bold "==> Installing Go 1.22"
    GO_VER="1.22.7"
    curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -o /tmp/go.tgz
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf /tmp/go.tgz
    rm /tmp/go.tgz
    export PATH="/usr/local/go/bin:$PATH"
    if ! grep -q '/usr/local/go/bin' "${HOME}/.profile" 2>/dev/null; then
        echo 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"' >> "${HOME}/.profile"
    fi
else
    ok "Go already installed: $(go version)"
fi

export PATH="/usr/local/go/bin:${HOME}/go/bin:$PATH"

# ---- ProjectDiscovery Go tools ---------------------------------------

bold "==> Installing nuclei / katana / httpx / subfinder / dalfox"
go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -ldflags="-s -w" github.com/projectdiscovery/katana/cmd/katana@latest
go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -ldflags="-s -w" github.com/hahwul/dalfox/v2@latest

# ---- nuclei templates -------------------------------------------------
"${HOME}/go/bin/nuclei" -update-templates -silent || warn "failed to update nuclei templates"

# ---- Rust / feroxbuster ----------------------------------------------

if ! command -v cargo >/dev/null 2>&1; then
    bold "==> Installing Rust toolchain"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
    . "${HOME}/.cargo/env"
else
    ok "Rust already installed: $(rustc --version 2>&1 | head -1)"
fi

bold "==> Installing feroxbuster"
cargo install feroxbuster --locked

# ---- Nikto ------------------------------------------------------------

bold "==> Installing Nikto"
$SUDO rm -rf /opt/nikto
$SUDO git clone --depth 1 https://github.com/sullo/nikto /opt/nikto
$SUDO ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto
$SUDO chmod +x /opt/nikto/program/nikto.pl

# ---- wpscan -----------------------------------------------------------

bold "==> Installing wpscan"
$SUDO gem install --no-document wpscan

# ---- arjun / sqlmap via pipx -----------------------------------------

bold "==> Installing arjun + sqlmap (pipx)"
pipx ensurepath || true
pipx install arjun || warn "arjun install failed (maybe already installed)"
pipx install sqlmap || warn "sqlmap install failed"

# ---- retire.js (Node) -------------------------------------------------

bold "==> Installing retire.js"
$SUDO npm install -g retire

# ---- SecLists wordlists ----------------------------------------------

if [[ ! -d /usr/share/seclists ]]; then
    bold "==> Cloning SecLists wordlists"
    $SUDO git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists
else
    ok "SecLists already present at /usr/share/seclists"
fi

# ---- stbox itself ----------------------------------------------------

bold "==> Installing stbox (pipx)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${HERE}/pyproject.toml" ]]; then
    pipx install --force "${HERE}"
else
    pipx install --force "git+https://github.com/JaviiHernandez/SecurityToolbox-CLI"
fi

ok "Done. Run 'stbox doctor' to verify all tools are on PATH."
