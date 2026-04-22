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

Info "Installing Go tools (nuclei, katana, httpx, subfinder, dalfox, ffuf, kiterunner)"
$goTools = @(
    'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    'github.com/projectdiscovery/katana/cmd/katana@latest',
    'github.com/projectdiscovery/httpx/cmd/httpx@latest',
    'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    'github.com/hahwul/dalfox/v2@latest',
    'github.com/ffuf/ffuf/v2@latest',
    'github.com/assetnote/kiterunner/cmd/kr@latest'
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

Info "Installing pipx + arjun + sqlmap + wfuzz"
python -m pip install --user --upgrade pipx
python -m pipx ensurepath
python -m pipx install arjun
python -m pipx install sqlmap
python -m pipx install wfuzz 2>$null

# ---- Hydra / Medusa — no native Windows build; use WSL if available -----
if (-not $SkipWsl -and (Get-Command wsl -ErrorAction SilentlyContinue)) {
    Info "Installing hydra + medusa inside WSL"
    wsl -d Debian -- bash -c "sudo apt-get update && sudo apt-get install -y hydra medusa"
} else {
    Warn "hydra/medusa require WSL on Windows — credential brute force will be disabled"
}

# ---- Kiterunner routes (~40k API routes) --------------------------------
$krPath = 'C:\kiterunner'
if (-not (Test-Path $krPath)) {
    New-Item -ItemType Directory -Path $krPath | Out-Null
}
$routesFile = Join-Path $krPath 'routes-large.kite'
if (-not (Test-Path $routesFile)) {
    Info "Fetching kiterunner routes-large.kite (~40k API routes)"
    try {
        Invoke-WebRequest -Uri 'https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite' `
                          -OutFile $routesFile
    } catch {
        Warn "kiterunner routes download failed — kiterunner runner will skip"
    }
}
[Environment]::SetEnvironmentVariable('STBOX_WL_KITE', $routesFile, 'User')

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

# Stbox config env vars so the runners find the wordlists on Windows paths.
[Environment]::SetEnvironmentVariable('STBOX_SECLISTS', $seclistsPath, 'User')
[Environment]::SetEnvironmentVariable('STBOX_WL_CONTENT_SMALL',
    "$seclistsPath\Discovery\Web-Content\common.txt", 'User')
[Environment]::SetEnvironmentVariable('STBOX_WL_PARAMS',
    "$seclistsPath\Discovery\Web-Content\burp-parameter-names.txt", 'User')
[Environment]::SetEnvironmentVariable('STBOX_WL_USERNAMES',
    "$seclistsPath\Usernames\top-usernames-shortlist.txt", 'User')
[Environment]::SetEnvironmentVariable('STBOX_WL_PASSWORDS',
    "$seclistsPath\Passwords\Common-Credentials\10k-most-common.txt", 'User')

# ---- Nuclei workflows (curated exploit chains) --------------------------
$workflowsPath = 'C:\stbox-workflows'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (Test-Path (Join-Path $here 'workflows')) {
    Info "Installing nuclei workflows to $workflowsPath"
    if (-not (Test-Path $workflowsPath)) {
        New-Item -ItemType Directory -Path $workflowsPath | Out-Null
    }
    Copy-Item -Path (Join-Path $here 'workflows\*.yaml') -Destination $workflowsPath -Force
    [Environment]::SetEnvironmentVariable('STBOX_NUCLEI_WORKFLOWS', $workflowsPath, 'User')
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
