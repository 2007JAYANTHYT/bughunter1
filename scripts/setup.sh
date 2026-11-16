#!/bin/bash
# =============================================================================
# BUG HUNTER AGENT - PHASE 0 SETUP SCRIPT
# Run inside WSL2 Kali Linux (NOT Windows PowerShell)
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running in WSL2 Kali
check_environment() {
    log_info "Checking environment..."

    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot detect OS. Are you in WSL2 Kali?"
        exit 1
    fi

    source /etc/os-release
    if [[ "$ID" != "kali" ]]; then
        log_warn "Not running on Kali Linux (detected: $ID). Some packages may differ."
    fi

    # Check RAM
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $TOTAL_RAM -lt 16 ]]; then
        log_warn "RAM is ${TOTAL_RAM}GB. Recommended: 16GB+ for running browsers + LLMs"
    else
        log_success "RAM: ${TOTAL_RAM}GB ✓"
    fi

    # Check if we're in the right directory
    if [[ ! -d "$(pwd)/config" ]]; then
        log_error "Run this script from the project root directory"
        exit 1
    fi
}

# Update system
update_system() {
    log_info "Updating system packages..."
    sudo apt update && sudo apt upgrade -y
    log_success "System updated"
}

# Install base packages
install_base_packages() {
    log_info "Installing base packages..."
    sudo apt install -y \
        git curl wget unzip jq \
        python3 python3-pip python3-venv python3-dev \
        nodejs npm \
        golang-go \
        docker.io docker-compose \
        flameshot \
        terminator \
        zsh fzf bat eza ripgrep fd-find \
        build-essential libssl-dev libffi-dev \
        pkg-config \
        libxml2-dev libxslt1-dev \
        chromium-browser \
        ffmpeg \
        sqlite3 \
        redis-server \
        postgresql-client \
        nmap \
        masscan \
        wireshark-common \
        tshark
    log_success "Base packages installed"
}

# Install Go tools (ProjectDiscovery + others)
install_go_tools() {
    log_info "Installing Go tools..."

    # Ensure Go is in PATH
    export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin' >> ~/.zshrc
    echo 'export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin' >> ~/.bashrc

    # ProjectDiscovery tools
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
    go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
    go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
    go install -v github.com/projectdiscovery/ipcdn/cmd/ipcdn@latest
    go install -v github.com/projectdiscovery/verify-http@latest
    go install -v github.com/projectdiscovery/notify/cmd/notify@latest
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
    go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest

    # Tomnomnom tools
    go install -v github.com/tomnomnom/waybackurls@latest
    go install -v github.com/tomnomnom/gf@latest
    go install -v github.com/tomnomnom/anew@latest
    go install -v github.com/tomnomnom/httprobe@latest
    go install -v github.com/tomnomnom/assetfinder@latest
    go install -v github.com/tomnomnom/meg@latest
    go install -v github.com/tomnomnom/waybackurls@latest

    # Other essential tools
    go install -v github.com/ffuf/ffuf/v2@latest
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/jaeles-project/gospider@latest
    go install -v github.com/hakluke/hakrawler@latest
    go install -v github.com/hakluke/hakcheckurl@latest
    go install -v github.com/hakluke/hakrevdns@latest
    go install -v github.com/hakluke/hakoriginfinder@latest
    go install -v github.com/dwisiswant0/crlfuzz@latest
    go install -v github.com/dwisiswant0/ppm@latest
    go install -v github.com/dwisiswant0/subscriber@latest
    go install -v github.com/dwisiswant0/hetty@latest
    go install -v github.com/hahwul/dalfox/v2@latest
    go install -v github.com/OWASP/Amass/v3/...@latest
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

    log_success "Go tools installed"
}

# Install Python packages
install_python_packages() {
    log_info "Installing Python packages..."

    # Create virtual environment for the project
    python3 -m venv ~/bug-hunter-venv
    source ~/bug-hunter-venv/bin/activate

    pip install --upgrade pip setuptools wheel

    # Core packages
    pip install \
        playwright \
        mitmproxy \
        requests \
        beautifulsoup4 \
        lxml \
        rich \
        textual \
        pydantic \
        pydantic-settings \
        sqlalchemy \
        aiosqlite \
        fastapi \
        uvicorn \
        websockets \
        python-multipart \
        jinja2 \
        python-dotenv \
        openai \
        anthropic \
        google-generativeai \
        aiohttp \
        aiofiles \
        pytest \
        pytest-asyncio \
        httpx \
        tenacity \
        tqdm \
        pyyaml \
        tomli \
        tomli-w \
        click \
        typer \
        asciinema \
        haralyzer \
        mitmproxy \
        websocket-client

    # Playwright browsers
    playwright install firefox chromium webkit
    playwright install-deps

    deactivate
    log_success "Python packages installed"
}

# Install Ollama and models
install_ollama() {
    log_info "Installing Ollama..."

    curl -fsSL https://ollama.com/install.sh | sh

    # Start Ollama service
    ollama serve &
    OLLAMA_PID=$!
    sleep 5

    # Pull models for bug hunting
    log_info "Pulling AI models (this will take a while)..."

    # Primary analysis model
    ollama pull llama3.1:70b

    # Code analysis models
    ollama pull deepseek-coder:33b
    ollama pull codellama:34b

    # Reasoning model
    ollama pull nemotron3-ultra

    # Fast triage model
    ollama pull phi3:14b
    ollama pull mistral-nemo

    # Lightweight
    ollama pull phi3:3.8b

    kill $OLLAMA_PID 2>/dev/null || true
    log_success "Ollama and models installed"
}

# Install Burp Suite Community
install_burp() {
    log_info "Installing Burp Suite Community Edition..."

    cd /tmp
    wget -q "https://portswigger.net/burp/releases/download?product=community&type=Linux" -O burp.sh
    chmod +x burp.sh

    # Run installer silently (requires X11 or manual interaction)
    log_warn "Burp Suite installer requires GUI. Run manually: ./burp.sh"
    log_warn "Or install via: sudo apt install burpsuite (Kali repo version)"

    # Alternative: install from Kali repos
    sudo apt install -y burpsuite || log_warn "Could not install from repos"

    cd -
    log_success "Burp Suite installation attempted"
}

# Install additional tools
install_additional_tools() {
    log_info "Installing additional security tools..."

    # SQLMap
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ~/tools/sqlmap

    # NoSQLMap
    git clone --depth 1 https://github.com/codingo/NoSQLMap.git ~/tools/NoSQLMap
    cd ~/tools/NoSQLMap && sudo pip install -r requirements.txt

    # XXEinjector
    git clone --depth 1 https://github.com/enjoiz/XXEinjector.git ~/tools/XXEinjector

    # SSRFmap
    git clone --depth 1 https://github.com/swisskyrepo/SSRFmap.git ~/tools/SSRFmap
    cd ~/tools/SSRFmap && sudo pip install -r requirements.txt

    # Arjun (param discovery)
    pip install arjun

    # ParamSpider
    git clone --depth 1 https://github.com/devanshbatham/ParamSpider.git ~/tools/ParamSpider
    cd ~/tools/ParamSpider && pip install -r requirements.txt

    # LinkFinder
    git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder
    cd ~/tools/LinkFinder && pip install -r requirements.txt

    # SecretFinder
    git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git ~/tools/SecretFinder
    cd ~/tools/SecretFinder && pip install -r requirements.txt

    # JSFScan
    git clone --depth 1 https://github.com/KathanP19/JSFScan.sh.git ~/tools/JSFScan

    # CloudEnum
    git clone --depth 1 https://github.com/initstring/cloud_enum.git ~/tools/cloud_enum
    cd ~/tools/cloud_enum && pip install -r requirements.txt

    # S3Scanner
    git clone --depth 1 https://github.com/sa7mon/S3Scanner.git ~/tools/S3Scanner
    cd ~/tools/S3Scanner && pip install -r requirements.txt

    # Kubernetes tools
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    chmod +x kubectl && sudo mv kubectl /usr/local/bin/

    # Helm
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

    log_success "Additional tools installed"
}

# Setup GF patterns
setup_gf_patterns() {
    log_info "Setting up GF patterns..."

    mkdir -p ~/.gf
    git clone --depth 1 https://github.com/tomnomnom/gf.git /tmp/gf
    cp /tmp/gf/examples/*.json ~/.gf/

    # Additional patterns
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/Gf-Patterns
    cp /tmp/Gf-Patterns/*.json ~/.gf/

    log_success "GF patterns configured"
}

# Setup Nuclei templates
setup_nuclei_templates() {
    log_info "Setting up Nuclei templates..."

    nuclei -update-templates
    nuclei -update

    # Additional template repos
    mkdir -p ~/nuclei-templates-custom
    cd ~/nuclei-templates-custom

    git clone --depth 1 https://github.com/0xsobky/HackVault.git
    git clone --depth 1 https://github.com/geeknik/nuclei-templates.git
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git

    log_success "Nuclei templates configured"
}

# Create project config files
create_config_files() {
    log_info "Creating project configuration files..."

    PROJECT_ROOT="$(pwd)"

    # programs.yaml.example
    cat > "$PROJECT_ROOT/config/programs.yaml.example" << 'EOF'
# Bug Bounty Program Configurations
# Copy to programs.yaml and fill in your details

programs:
  - name: "example-program"
    platform: "hackerone"  # hackerone, bugcrowd, intigriti, yeswehack, custom
    handle: "example"      # Program handle on platform
    enabled: true

    # Authentication
    auth:
      type: "api_token"    # api_token, cookie, header, none
      env_var: "H1_TOKEN"  # Environment variable name for token
      # Or inline (NOT recommended for production):
      # token: "your_token_here"

    # Scope configuration
    scope:
      file: "scopes/example.yaml"  # Path to scope file
      auto_fetch: true             # Auto-fetch from platform API

    # Policy configuration
    policy:
      file: "policies/example.yaml"
      max_severity: "P1"           # P1, P2, P3, P4 (ignore P5+)
      banned_types:                # Vulnerability types to skip
        - "self-xss"
        - "clickjacking"
        - "missing-security-headers"
      rate_limit: 100              # Requests per minute
      require_poc: true            # Require POC for submission
      poc_format: "video"          # video, screenshots, curl, har

    # Custom headers for all requests
    custom_headers:
      - "X-Bug-Bounty: true"
      - "User-Agent: BugHunter/1.0"

    # Notification settings
    notifications:
      webhook: ""                  # Discord/Slack webhook
      email: ""                    # Email for critical findings

  # Add more programs here...
  # - name: "another-program"
  #   platform: "bugcrowd"
  #   handle: "another"
  #   ...
EOF

    # hunting.yaml
    cat > "$PROJECT_ROOT/config/hunting.yaml" << 'EOF'
# Hunting Configuration

hunting:
  # General settings
  threads: 50                      # Concurrent threads
  timeout: 30                      # Request timeout (seconds)
  retries: 3                       # Retry failed requests
  follow_redirects: true
  verify_ssl: false                # Set true for production

  # Rate limiting (per target)
  rate_limit:
    requests_per_second: 10
    burst: 20

  # Scope enforcement
  strict_scope: true               # Hard block out-of-scope
  allow_subdomains: true           # Allow subdomain enumeration

  # Scanner settings
  scanners:
    nuclei:
      enabled: true
      severity: ["critical", "high", "medium", "low"]  # P1-P4
      tags: []                     # Filter by tags (e.g., ["cve", "rce"])
      exclude_tags: ["info", "dos", "fuzzing"]
      rate_limit: 150              # Nuclei rate limit
      templates_path: "~/nuclei-templates-custom"
      custom_templates: true

    dalfox:
      enabled: true
      blind_xss: true
      mining: true
      worker: 50

    sqlmap:
      enabled: true
      level: 3
      risk: 2
      batch: true
      threads: 10

    custom_payloads:
      enabled: true
      payload_dir: "payloads"

  # AI hunting settings
  ai_hunting:
    enabled: true
    models:
      primary: "llama3.1:70b"
      code: "deepseek-coder:33b"
      reasoning: "nemotron3-ultra"
      fast: "phi3:14b"
    max_tokens: 8192
    temperature: 0.1
    context_window: 128000

    # Prompt templates
    prompts_dir: "skills/hunting/prompts"

  # Specialized hunters (enable/disable)
  specialized:
    xss: true
    sqli: true
    ssrf: true
    rce: true
    auth: true
    logic: true
    api: true
    mobile: false
    cloud: true
    supply_chain: false

  # Payload settings
  payloads:
    xss:
      - "payloads/xss/reflected.txt"
      - "payloads/xss/stored.txt"
      - "payloads/xss/dom.txt"
      - "payloads/xss/blind.txt"
    sqli:
      - "payloads/sqli/error.txt"
      - "payloads/sqli/blind.txt"
      - "payloads/sqli/time.txt"
    ssrf:
      - "payloads/ssrf/basic.txt"
      - "payloads/ssrf/cloud.txt"
      - "payloads/ssrf/bypass.txt"
    rce:
      - "payloads/rce/deserialization.txt"
      - "payloads/rce/template.txt"
      - "payloads/rce/command.txt"
EOF

    # validation.yaml
    cat > "$PROJECT_ROOT/config/validation.yaml" << 'EOF'
# Validation Configuration

validation:
  # Browser reproduction (Playwright + Firefox)
  browser:
    enabled: true
    headless: false                # MUST be false for real evidence
    browser: "firefox"             # firefox, chromium, webkit
    viewport:
      width: 1920
      height: 1080
    record_video: true
    video_dir: "evidence/videos"
    screenshot_on_success: true
    screenshot_on_failure: true
    screenshot_dir: "evidence/screenshots"
    har_capture: true
    har_dir: "evidence/har"
    console_logs: true
    network_logs: true
    timeout: 60000                 # 60 seconds
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    # Stealth settings
    stealth:
      disable_automation_flags: true
      disable_web_security: true
      ignore_https_errors: true

  # Burp Suite integration
  burp:
    enabled: true
    api_url: "http://127.0.0.1:1337"  # Burp REST API (Pro only)
    proxy_port: 8080
    proxy_host: "127.0.0.1"
    capture_traffic: true
    export_format: "json"           # json, xml, html
    export_dir: "evidence/burp"
    # For Community Edition: use mitmproxy instead
    use_mitmproxy_fallback: true
    mitmproxy_port: 8081

  # Terminal capture
  terminal:
    enabled: true
    tool: "asciinema"              # asciinema, script
    output_dir: "evidence/terminal"
    record_all_sessions: true

  # AI validation
  ai_validation:
    enabled: true
    model: "llama3.1:70b"
    confidence_threshold: 0.8      # Minimum confidence to auto-validate
    false_positive_checks:
      - "reflection_analysis"
      - "payload_execution"
      - "impact_verification"
      - "duplicate_detection"

  # Evidence packaging
  evidence:
    create_package: true
    package_dir: "evidence/packages"
    include:
      - screenshots
      - videos
      - har_files
      - burp_exports
      - terminal_recordings
      - annotated_screenshots
      - poc_code
    annotate_screenshots: true
    annotation_color: "red"
    annotation_width: 3
EOF

    # ai_models.yaml
    cat > "$PROJECT_ROOT/config/ai_models.yaml" << 'EOF'
# AI Model Configuration

models:
  # Primary analysis model - best for complex reasoning
  primary:
    name: "llama3.1:70b"
    provider: "ollama"
    purpose: ["analysis", "poc_generation", "report_writing", "chain_reasoning"]
    max_tokens: 8192
    temperature: 0.1
    top_p: 0.9
    context_window: 128000
    system_prompt: |
      You are an expert bug bounty hunter and security researcher.
      Analyze vulnerabilities, generate POCs, and write professional reports.
      Be precise, technical, and thorough. No fluff.

  # Code analysis and exploit development
  code:
    name: "deepseek-coder:33b"
    provider: "ollama"
    purpose: ["code_review", "exploit_dev", "poc_code", "payload_generation"]
    max_tokens: 8192
    temperature: 0.0
    top_p: 0.95
    context_window: 128000
    system_prompt: |
      You are an expert in vulnerability exploitation and secure coding.
      Generate working exploit code, analyze vulnerable patterns,
      and create proof-of-concept exploits.

  # Complex chain reasoning
  reasoning:
    name: "nemotron3-ultra"
    provider: "ollama"
    purpose: ["vuln_chaining", "impact_assessment", "bypass_strategy"]
    max_tokens: 8192
    temperature: 0.2
    top_p: 0.9
    context_window: 128000
    system_prompt: |
      You are a senior penetration tester specializing in vulnerability chaining
      and complex attack paths. Think step-by-step. Consider all possibilities.

  # Fast triage and classification
  fast:
    name: "phi3:14b"
    provider: "ollama"
    purpose: ["triage", "classification", "deduplication", "quick_analysis"]
    max_tokens: 4096
    temperature: 0.0
    top_p: 0.9
    context_window: 128000
    system_prompt: |
      Quickly classify and triage security findings.
      Identify false positives, assess severity, deduplicate.
      Be decisive and concise.

  # Lightweight for simple tasks
  lightweight:
    name: "phi3:3.8b"
    provider: "ollama"
    purpose: ["summarization", "formatting", "extraction"]
    max_tokens: 2048
    temperature: 0.0
    top_p: 0.9
    context_window: 4096

# Cloud fallback models (optional - require API keys)
cloud_models:
  enabled: false
  anthropic:
    model: "claude-3-5-sonnet-20241022"
    api_key_env: "ANTHROPIC_API_KEY"
  openai:
    model: "gpt-4o"
    api_key_env: "OPENAI_API_KEY"
  google:
    model: "gemini-1.5-pro"
    api_key_env: "GOOGLE_API_KEY"
EOF

    # .env.example
    cat > "$PROJECT_ROOT/.env.example" << 'EOF'
# Bug Hunter Agent - Environment Variables
# Copy to .env and fill in your values

# =============================================================================
# PROGRAM API TOKENS
# =============================================================================
H1_TOKEN=your_hackerone_api_token_here
BUGCROWD_TOKEN=your_bugcrowd_api_token_here
INTIGRITI_TOKEN=your_intigriti_api_token_here
YESWEHACK_TOKEN=your_yeswehack_api_token_here

# =============================================================================
# OPTIONAL: CLOUD AI APIs (fallback if local models fail)
# =============================================================================
ANTHROPIC_API_KEY=your_anthropic_key_here
OPENAI_API_KEY=your_openai_key_here
GOOGLE_API_KEY=your_google_key_here

# =============================================================================
# RECON API KEYS (optional but recommended)
# =============================================================================
SECURITYTRAILS_API_KEY=your_securitytrails_key
VIRUSTOTAL_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
GITHUB_TOKEN=your_github_token
GITLAB_TOKEN=your_gitlab_token

# =============================================================================
# NOTIFICATION WEBHOOKS
# =============================================================================
DISCORD_WEBHOOK=your_discord_webhook_url
SLACK_WEBHOOK=your_slack_webhook_url
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_telegram_chat_id

# =============================================================================
# DATABASE
# =============================================================================
DATABASE_URL=sqlite:///bug_hunter.db

# =============================================================================
# BURP SUITE
# =============================================================================
BURP_API_KEY=your_burp_pro_api_key
BURP_PROXY_PORT=8080

# =============================================================================
# MITMPROXY (fallback for Burp Community)
# =============================================================================
MITMPROXY_PORT=8081

# =============================================================================
# REDIS (for background tasks - optional)
# =============================================================================
REDIS_URL=redis://localhost:6379/0

# =============================================================================
# LOGGING
# =============================================================================
LOG_LEVEL=INFO
LOG_FILE=logs/bug_hunter.log
EOF

    log_success "Configuration files created"
}

# Setup database
setup_database() {
    log_info "Setting up database..."

    PROJECT_ROOT="$(pwd)"
    cd "$PROJECT_ROOT"

    # Create database initialization script
    cat > "$PROJECT_ROOT/scripts/init_db.py" << 'PYEOF'
#!/usr/bin/env python3
"""Initialize SQLite database with all tables."""

import sqlite3
import os
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "bug_hunter.db"

SCHEMA = """
-- Programs table
CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    platform TEXT NOT NULL,
    handle TEXT,
    enabled BOOLEAN DEFAULT 1,
    auth_type TEXT,
    auth_env_var TEXT,
    scope_file TEXT,
    policy_file TEXT,
    custom_headers TEXT,  -- JSON
    notifications TEXT,   -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Targets table (domains, IPs, services)
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    domain TEXT,
    subdomain TEXT,
    ip TEXT,
    port INTEGER,
    service TEXT,
    technology TEXT,        -- JSON array of detected tech
    status_code INTEGER,
    content_length INTEGER,
    title TEXT,
    screenshot_path TEXT,
    headers TEXT,           -- JSON
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source TEXT,            -- subfinder, httpx, katana, etc.
    FOREIGN KEY(program_id) REFERENCES programs(id)
);

-- Endpoints table (URLs with parameters)
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    parameters TEXT,        -- JSON
    discovered_by TEXT,
    crawled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(target_id) REFERENCES targets(id)
);

-- Findings table (vulnerabilities)
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    target_id INTEGER,
    endpoint_id INTEGER,
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,     -- P1, P2, P3, P4
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,              -- JSON: screenshots, requests, responses, videos
    poc TEXT,                   -- Proof of concept code/steps
    status TEXT DEFAULT 'new',  -- new, validated, reported, duplicate, false_positive, fixed
    cvss_score REAL,
    cvss_vector TEXT,
    impact TEXT,
    remediation TEXT,
    tags TEXT,                  -- JSON array
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    validated_at TIMESTAMP,
    reported_at TIMESTAMP,
    duplicate_of INTEGER,       -- Reference to another finding ID
    FOREIGN KEY(program_id) REFERENCES programs(id),
    FOREIGN KEY(target_id) REFERENCES targets(id),
    FOREIGN KEY(endpoint_id) REFERENCES endpoints(id),
    FOREIGN KEY(duplicate_of) REFERENCES findings(id)
);

-- Evidence table (detailed evidence for findings)
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    type TEXT NOT NULL,         -- screenshot, video, har, burp, terminal, annotated
    path TEXT NOT NULL,
    description TEXT,
    metadata TEXT,              -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(finding_id) REFERENCES findings(id)
);

-- Scope checklist table
CREATE TABLE IF NOT EXISTS scope_checklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    item_type TEXT NOT NULL,    -- in_scope, out_of_scope
    pattern TEXT NOT NULL,      -- Domain, CIDR, wildcard, regex
    description TEXT,
    status TEXT DEFAULT 'pending',  -- pending, testing, tested, skipped
    tested_at TIMESTAMP,
    notes TEXT,
    FOREIGN KEY(program_id) REFERENCES programs(id)
);

-- Scan sessions table
CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    scan_type TEXT NOT NULL,    -- recon, hunting, validation, full
    status TEXT DEFAULT 'running',  -- running, completed, failed, cancelled
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    config TEXT,                -- JSON
    stats TEXT,                 -- JSON
    error TEXT,
    FOREIGN KEY(program_id) REFERENCES programs(id)
);

-- Activity log
CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER,
    finding_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,               -- JSON
    user TEXT DEFAULT 'system',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(program_id) REFERENCES programs(id),
    FOREIGN KEY(finding_id) REFERENCES findings(id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_targets_program ON targets(program_id);
CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(domain);
CREATE INDEX IF NOT EXISTS idx_endpoints_target ON endpoints(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_scope_program ON scope_checklist(program_id);
CREATE INDEX IF NOT EXISTS idx_scans_program ON scan_sessions(program_id);
CREATE INDEX IF NOT EXISTS idx_activity_program ON activity_log(program_id);
"""

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")

if __name__ == "__main__":
    init_db()
PYEOF

    python3 "$PROJECT_ROOT/scripts/init_db.py"
    log_success "Database initialized"
}

# Create project structure
create_project_structure() {
    log_info "Creating project structure..."

    PROJECT_ROOT="$(pwd)"

    # Core directories
    mkdir -p "$PROJECT_ROOT"/{core,recon,hunting,validation,reporting,ui,evidence,config,skills,payloads,mcp,tests,docs,scripts,logs}

    # Evidence subdirectories
    mkdir -p "$PROJECT_ROOT/evidence"/{screenshots,videos,har,burp,terminal,packages,annotated}

    # Payload directories
    mkdir -p "$PROJECT_ROOT/payloads"/{xss,sqli,ssrf,rce,auth,logic,api,mobile,cloud,custom}

    # Skills directories
    mkdir -p "$PROJECT_ROOT/skills"/{recon,hunting,validation,reporting,methodology}

    # MCP directories
    mkdir -p "$PROJECT_ROOT/mcp/servers"

    # UI directories
    mkdir -p "$PROJECT_ROOT/ui"/{backend,frontend}

    # Test directories
    mkdir -p "$PROJECT_ROOT/tests"/{unit,integration,fixtures}

    # Config subdirectories
    mkdir -p "$PROJECT_ROOT/config"/{scopes,policies,prompts}

    log_success "Project structure created"
}

# Create __init__.py files
create_init_files() {
    log_info "Creating Python package init files..."

    PROJECT_ROOT="$(pwd)"

    for dir in core recon hunting validation reporting ui backend mcp skills; do
        find "$PROJECT_ROOT/$dir" -type d -exec touch {}/__init__.py \;
    done

    log_success "Init files created"
}

# Main setup flow
main() {
    echo "============================================================================="
    echo "  BUG HUNTER AGENT - PHASE 0 SETUP"
    echo "  Run inside WSL2 Kali Linux"
    echo "============================================================================="

    check_environment
    create_project_structure
    create_init_files
    create_config_files
    setup_database

    log_info "Starting package installations (this will take 30-60 minutes)..."

    update_system
    install_base_packages
    install_go_tools
    install_python_packages
    install_ollama
    install_burp
    install_additional_tools
    setup_gf_patterns
    setup_nuclei_templates

    echo ""
    echo "============================================================================="
    echo "  SETUP COMPLETE!"
    echo "============================================================================="
    echo ""
    echo "Next steps:"
    echo "1. Copy config files:"
    echo "   cp config/programs.yaml.example config/programs.yaml"
    echo "   cp .env.example .env"
    echo ""
    echo "2. Edit config/programs.yaml with your bug bounty programs"
    echo "3. Edit .env with your API tokens"
    echo "4. Activate Python venv: source ~/bug-hunter-venv/bin/activate"
    echo "5. Start Ollama: ollama serve"
    echo "6. Start Burp Suite (if installed)"
    echo "7. Run the agent: python -m cli.main --help"
    echo ""
    echo "Project root: $(pwd)"
}

# Run main
main "$@"