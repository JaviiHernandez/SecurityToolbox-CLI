# SecurityToolbox-CLI — Windows installer.
#
# Requires PowerShell 5.1+ and Administrator privileges.
# Relies on Chocolatey + Scoop + WSL for the tools that don't have native
# Windows builds (wpscan, nikto, arjun, sqlmap, feroxbuster).
#
# Run:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\install-windows.ps1

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$SkipWsl,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Err($m)  { Write-Host "[x] $m" -ForegroundColor Red }

# Must be admin for choco-global installs
$currentPrincipal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Err "This script must be run as Administrator."
    exit 1
}

# ---- Chocolatey ----------------------------------------------------------
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Info "Installing Chocolatey"
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = 3072 # TLS 1.2
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path','User')
} else {
    Ok "Chocolatey already installed"
}

# ---- Core toolchains -----------------------------------------------------

Info "Installing Go, Python 3.12, Node.js, Ruby, Git, 7zip"
choco install -y --no-progress golang python312 nodejs-lts ruby git 7zip

# Refresh PATH
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
            [Environment]::GetEnvironmentVariable('Path','User')

# ---- Go-based ProjectDiscovery tools -------------------------------------

Info "Installing nuclei / katana / httpx / subfinder / dalfox via `go install`"
$goTools = @(
    'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    'github.com/projectdiscovery/katana/cmd/katana@latest',
    'github.com/projectdiscovery/httpx/cmd/httpx@latest',
    'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    'github.com/hahwul/dalfox/v2@latest'
)
foreach ($tool in $goTools) {
    Info "  $tool"
    go install -ldflags='-s -w' $tool
}
$goBin = Join-Path $env:USERPROFILE 'go\bin'
if (-not ($env:Path -split ';' -contains $goBin)) {
    [Environment]::SetEnvironmentVariable('Path', "$([Environment]::GetEnvironmentVariable('Path','User'));$goBin", 'User')
    $env:Path += ";$goBin"
}

Info "Updating nuclei templates"
& "$goBin\nuclei.exe" -update-templates -silent 2>$null

# ---- Rust + feroxbuster --------------------------------------------------

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Info "Installing Rust (rustup)"
    Invoke-WebRequest -Uri https://win.rustup.rs/x86_64 -OutFile "$env:TEMP\rustup-init.exe"
    & "$env:TEMP\rustup-init.exe" -y --default-toolchain stable --profile minimal
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    $env:Path += ";$cargoBin"
}

Info "Installing feroxbuster (cargo)"
cargo install feroxbuster --locked

# ---- Ruby / wpscan -------------------------------------------------------

Info "Installing wpscan (gem)"
gem install --no-document wpscan

# ---- Python tools: arjun + sqlmap via pipx -------------------------------

Info "Installing pipx + arjun + sqlmap"
python -m pip install --user --upgrade pipx
python -m pipx ensurepath
python -m pipx install arjun
python -m pipx install sqlmap

# ---- Node / retire.js ----------------------------------------------------

Info "Installing retire.js (npm -g)"
npm install -g retire

# ---- Nikto (Perl) — via WSL or Strawberry Perl ---------------------------

if (-not $SkipWsl) {
    if (Get-Command wsl -ErrorAction SilentlyContinue) {
        Info "Installing nikto inside WSL (Debian)"
        wsl --install -d Debian 2>$null | Out-Null
        wsl -d Debian -- bash -c "sudo apt-get update && sudo apt-get install -y nikto"
    } else {
        Warn "WSL not found. Nikto requires WSL on Windows — skipping. Install WSL with: wsl --install"
    }
} else {
    Warn "--SkipWsl passed; nikto won't be installed. You can add it later via WSL."
}

# ---- SecLists wordlists --------------------------------------------------

$seclistsPath = 'C:\SecLists'
if (-not (Test-Path $seclistsPath)) {
    Info "Cloning SecLists to $seclistsPath"
    git clone --depth 1 https://github.com/danielmiessler/SecLists $seclistsPath
    [Environment]::SetEnvironmentVariable('SECLISTS_PATH', $seclistsPath, 'User')
} else {
    Ok "SecLists already present at $seclistsPath"
}

# ---- stbox itself --------------------------------------------------------

Info "Installing stbox via pipx"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (Test-Path (Join-Path $here 'pyproject.toml')) {
    python -m pipx install --force $here
} else {
    python -m pipx install --force 'git+https://github.com/JaviiHernandez/SecurityToolbox-CLI'
}

Ok "Done. Open a new shell and run 'stbox doctor' to verify."
