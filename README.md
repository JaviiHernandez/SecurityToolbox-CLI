# SecurityToolbox-CLI (`stbox`)

> Orchestrates the industry's pentest tooling into a single, unified scan report.

A Python CLI that runs **Nuclei, Nikto, SQLmap, Katana, Feroxbuster, Arjun, Dalfox, wpscan, httpx, subfinder, retire.js** + native passive recon (crt.sh, Wayback Machine, DNS) against a target and produces one HTML / JSON / Markdown report.

- **3 aggressiveness modes**: `passive` (default, no payloads), `standard`, `active`.
- **Safe by default**: active mode requires the explicit `--i-have-permission` flag.
- **Scope guard**: refuses `.gov` / `.mil` / `.gob` TLDs and RFC1918 addresses unless opted in.
- **Runs on Windows, Linux, or Docker**.

---

## Install

### Docker (recommended — all tools preinstalled)

```bash
git clone https://github.com/JaviiHernandez/SecurityToolbox-CLI
cd SecurityToolbox-CLI
docker compose build
docker compose run --rm stbox scan https://example.com --out /reports/report.html
```

Reports land in `./reports/` on your host.

### Linux (Debian / Ubuntu / Kali)

```bash
git clone https://github.com/JaviiHernandez/SecurityToolbox-CLI
cd SecurityToolbox-CLI
./install-linux.sh
```

The installer:
- Installs Go 1.22 + Rust + Ruby + Node + pipx
- Installs all 11 external tools (nuclei/katana/httpx/subfinder/dalfox/nikto/wpscan/arjun/sqlmap/feroxbuster/retire.js)
- Clones SecLists to `/usr/share/seclists`
- Installs `stbox` via pipx

### Windows 10/11

Run PowerShell **as Administrator**:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install-windows.ps1
```

- Uses Chocolatey for Go/Python/Node/Ruby/Git.
- Uses `go install` / `cargo install` / `gem install` / `npm install -g` / `pipx install` for each tool.
- Nikto installs inside WSL (Debian) automatically — skip with `-SkipWsl`.

### From source (already have toolchains)

```bash
pipx install .
```

---

## Quick start

```bash
# Check what's available on your machine
stbox doctor

# Passive scan — no payloads, no bruteforce
stbox scan https://example.com

# Standard scan with HTML + JSON output
stbox scan https://example.com --mode standard \
    --out report.html --json results.json

# Active scan — requires written permission from the target
stbox scan https://example.com --mode active --i-have-permission \
    --out report.html

# Your own lab (RFC1918)
stbox scan https://192.168.1.10 --allow-internal --mode active --i-have-permission
```

---

## What runs in each mode

| Phase | Tool | `passive` | `standard` | `active` |
|-------|------|-----------|------------|----------|
| CT logs | **crt.sh** | ✓ | ✓ | ✓ |
| Historical URLs | **Wayback Machine** | ✓ | ✓ | ✓ |
| DNS recon | `dnspython` | ✓ | ✓ | ✓ |
| Subdomain enum | **subfinder** | ✓ | ✓ | ✓ |
| Liveness + tech | **httpx** | ✓ | ✓ | ✓ |
| Vuln scan | **nuclei** | passive tags only | + seclists | full |
| JS libs | **retire.js** | ✓ | ✓ | ✓ |
| WordPress (if WP) | **wpscan** | passive | passive | aggressive |
| Crawler | **katana** | — | ✓ | ✓ |
| Legacy web | **nikto** | — | ✓ | ✓ |
| Param discovery | **arjun** | — | ✓ | ✓ |
| Content brute | **feroxbuster** | — | — | ✓ |
| XSS | **dalfox** | — | — | ✓ |
| SQLi | **sqlmap** | — | — | ✓ (on arjun-discovered params) |

---

## Output

HTML report: severity-grouped cards, collapsible evidence, tech stack table, tool-run audit trail.

Example (truncated) JSON:

```json
{
  "target": "https://example.com",
  "mode": "passive",
  "findings": [
    {
      "tool": "nuclei",
      "severity": "medium",
      "title": "nginx version disclosure",
      "target": "https://example.com",
      "cve": [],
      "evidence": { ... }
    }
  ]
}
```

---

## Configuration

Environment variables (all optional):

| Var | Default | Meaning |
|-----|---------|---------|
| `STBOX_TOOL_TIMEOUT` | `300` | Per-tool timeout in seconds |
| `STBOX_MAX_CONCURRENCY` | `25` | Async task concurrency |
| `STBOX_RATE_LIMIT_RPS` | `10` | Requests per second for our own probes |
| `STBOX_USER_AGENT` | Chrome-like | User-Agent for our probes |
| `STBOX_WORKDIR` | `./stbox-runs` | Raw stdout/stderr dump dir |
| `STBOX_STRICT_BINARIES` | `0` | `1` = abort scan if any tool is missing |
| `WPSCAN_API_TOKEN` | _(unset)_ | Enables CVE data from wpscan vulnerability DB |

---

## Ethics / legal

- **Active mode is illegal in many jurisdictions** without written authorization from the target owner. The `--i-have-permission` flag is a self-declaration, not a legal shield.
- Scope guard **refuses** `.gov`, `.mil`, `.gob` TLDs and cloud control-plane hosts.
- Every active scan embeds the permission acknowledgement into the HTML report.

In the EU (Spain CPEN art. 197 bis), UK (Computer Misuse Act 1990), US (CFAA), unauthorized active scanning of systems you don't own is a criminal offence. Use this tool on your own infrastructure or with explicit written authorization.

---

## Development

```bash
git clone https://github.com/JaviiHernandez/SecurityToolbox-CLI
cd SecurityToolbox-CLI
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check src/
```

---

## License

MIT — see [LICENSE](LICENSE).
