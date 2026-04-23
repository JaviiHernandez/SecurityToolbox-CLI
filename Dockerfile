# syntax=docker/dockerfile:1.6
# SecurityToolbox-CLI — all-in-one image with every pentest tool preinstalled.
#
# Layers are ordered from "rarely rebuilt" to "frequently rebuilt" so local
# dev iterations stay fast. Base is debian:bookworm-slim — smaller than
# kali-rolling but still has apt access to nikto/sqlmap/feroxbuster.

FROM debian:bookworm-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH="/opt/go/bin:/root/go/bin:/root/.local/bin:/usr/local/bin:${PATH}" \
    GOPATH=/root/go \
    GOROOT=/opt/go

# ---- System deps -----------------------------------------------------------

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git build-essential \
        python3 python3-pip python3-venv pipx \
        ruby ruby-dev \
        perl libnet-ssleay-perl libio-socket-ssl-perl \
        nodejs npm \
        libffi-dev libssl-dev zlib1g-dev \
        unzip tar gzip \
        dnsutils \
        hydra medusa \
    && rm -rf /var/lib/apt/lists/*

# ---- Go toolchain (for nuclei / katana / httpx / subfinder / dalfox) ------

ARG GO_VERSION=1.22.7
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    | tar -C /opt -xzf - \
 && mkdir -p "$GOPATH"

# ---- ProjectDiscovery binaries (Go) ---------------------------------------

RUN go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -ldflags="-s -w" github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -ldflags="-s -w" github.com/hahwul/dalfox/v2@latest && \
    go install -ldflags="-s -w" github.com/ffuf/ffuf/v2@latest && \
    mv /root/go/bin/nuclei /root/go/bin/katana /root/go/bin/httpx \
       /root/go/bin/subfinder /root/go/bin/dalfox /root/go/bin/ffuf \
       /usr/local/bin/ && \
    rm -rf /root/go/pkg

# kiterunner — go install is broken (binary entry is cmd/kiterunner, not cmd/kr); build from source
RUN git clone --depth 1 https://github.com/assetnote/kiterunner /tmp/kiterunner && \
    cd /tmp/kiterunner && \
    go build -ldflags="-s -w" -o /usr/local/bin/kr ./cmd/kiterunner && \
    rm -rf /tmp/kiterunner /root/go/pkg

# Kiterunner routes bundle — ~40k API routes harvested from public OpenAPI
# specs. Without this file kiterunner skips the task silently.
RUN mkdir -p /opt/kiterunner && \
    curl -fsSL -o /opt/kiterunner/routes-large.kite \
      https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite

# Pre-download nuclei templates so first run is offline-ready.
RUN nuclei -update-templates -silent || true

# ---- Rust toolchain + feroxbuster -----------------------------------------

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal && \
    . "$HOME/.cargo/env" && \
    cargo install feroxbuster --locked && \
    mv /root/.cargo/bin/feroxbuster /usr/local/bin/ && \
    rm -rf /root/.cargo /root/.rustup

# ---- Perl / Nikto ---------------------------------------------------------

RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# ---- Ruby / WPScan --------------------------------------------------------

RUN gem install --no-document wpscan

# ---- Python tools ---------------------------------------------------------

RUN pipx install arjun && \
    pipx install sqlmap && \
    pipx install wfuzz || true && \
    pipx ensurepath

# ---- Node / retire.js -----------------------------------------------------

RUN npm install -g retire

# ---- SecLists wordlists (needed by feroxbuster defaults + hydra + ffuf) ---

RUN git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists

# ---- Nuclei workflows (curated exploit chains bundled with stbox) ---------

COPY workflows /opt/stbox-workflows

# ---- stbox itself ---------------------------------------------------------

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --break-system-packages .

# ---- Runtime --------------------------------------------------------------

# Mount point for reports
VOLUME ["/reports"]
WORKDIR /reports

ENTRYPOINT ["stbox"]
CMD ["--help"]
