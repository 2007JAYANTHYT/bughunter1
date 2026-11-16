# 🐛 Bug Hunter Agent v1.0

> **Universal Autonomous Bug Hunting System**  
> Recon → Hunt → Validate → Report

A production-grade, fully local bug hunting AI agent that automates the complete bug bounty lifecycle. Built for WSL2 Kali Linux with 16GB+ RAM.

## ✨ Features

### 🎯 Complete Pipeline
- **Scope & Policy Management** - Fetch from HackerOne, Bugcrowd, Intigriti, YesWeHack + custom programs
- **Reconnaissance** - Subdomain enumeration (subfinder, amass, assetfinder), service discovery (naabu, httpx, tlsx), content crawling (katana, gospider, hakrawler)
- **Vulnerability Hunting** - Nuclei templates, DalFox (XSS), SQLMap (SQLi), custom payloads, AI-powered hunting
- **Validation** - Real Firefox browser reproduction (Playwright), Burp Suite/mitmproxy traffic capture, terminal recording
- **Reporting** - Professional POC reports (Markdown/HTML/PDF), platform-specific exports (HackerOne, Bugcrowd, Intigriti)
- **Bug Tracking** - SQLite database with reported/unreported separation, scope checklists, deduplication

### 🤖 AI-Powered
- **Multi-Model AI** - Llama 3.1 70B (analysis), DeepSeek Coder 33B (code/exploits), Nemotron 3 Ultra (reasoning), Phi-3 14B (fast triage)
- **Vulnerability Chaining** - Automatic exploit chain discovery (XSS→CSRF→ATO, SSRF→Metadata→RCE, etc.)
- **False Positive Reduction** - AI validation with confidence scoring
- **Contextual Payload Generation** - AI-generated payloads for specific reflection contexts

### 🔧 Specialized Hunters
- XSS (reflected, stored, DOM, blind)
- SQL Injection (error, blind, time, union)
- SSRF (basic, cloud metadata, bypass)
- RCE (command injection, deserialization, SSTI, file upload)
- Auth (JWT, OAuth, session, IDOR)
- Business Logic (race conditions, price manipulation, workflow bypass)
- API (GraphQL, REST, mass assignment, BOLA)
- Cloud (AWS, Azure, GCP, Kubernetes)
- Supply Chain (dependency confusion, typosquatting)

### 📊 Evidence & Validation
- **Real Browser** - Firefox + Playwright (visible, NOT headless)
- **Screenshots & Video** - Full-page captures, annotated highlights
- **HAR Files** - Complete network logs
- **Burp/mitmproxy** - Professional HTTP history
- **Terminal Recording** - asciinema for CLI exploits
- **Zero Synthetic Evidence** - All captures from real interactions

### 🌐 Web UI Dashboard
- React + TypeScript + Tailwind CSS
- Real-time updates via WebSocket
- Bug table with filtering (status, severity, type)
- Scope checklist with progress tracking
- Evidence viewer (images, video, HAR, Burp, terminal)
- Program management & statistics

### 🔌 MCP Integration
- **7 MCP Servers** - Burp, Nuclei, Playwright, Recon, Database, AI, Strix
- **Unified Client** - Single interface for all tools
- **Strix Pentester** - Workflows, exploit modules, methodologies (PTES, OWASP WSTG/MASTG)

### 💰 Zero Cost
- All tools free/local (Nuclei, subfinder, httpx, katana, SQLMap, DalFox, etc.)
- Local LLMs via Ollama (no API costs)
- SQLite database (no external dependencies)

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 with WSL2 enabled
- Kali Linux installed in WSL2 (`wsl --install -d kali-linux`)
- 16GB+ RAM recommended
- 50GB+ free disk space

### Installation

```bash
# Clone the repository
git clone <repo-url> bug-hunter
cd bug-hunter

# Run setup script (installs all tools, pulls AI models)
bash scripts/setup.sh

# Configure programs
cp config/programs.yaml.example config/programs.yaml
# Edit config/programs.yaml with your bug bounty programs

# Configure environment
cp .env.example .env
# Edit .env with your API tokens (HackerOne, Bugcrowd, etc.)

# Start Ollama (for AI features)
ollama serve

# Initialize database
python main.py init
```

### Usage

```bash
# CLI Commands
python main.py --help

# Program management
python main.py program add
python main.py program list

# Reconnaissance
python main.py hunt recon --program my-program --depth normal

# Vulnerability scanning
python main.py hunt scan --program my-program --scanner all

# Full pipeline (recon → scan → validate)
python main.py hunt full --program my-program

# Findings management
python main.py findings list --program my-program
python main.py findings view --id 123
python main.py findings validate --id 123
python main.py findings report --id 123

# Scope checklist
python main.py scope checklist --program my-program
python main.py scope update --item-id 1 --status tested

# Statistics
python main.py stats program --program my-program

# Generate reports
python main.py reports generate --bug-id 123 --format markdown
python main.py reports export hackerone --bug-id 123

# Web UI
python main.py ui
# Then open http://localhost:5173

# Backup
bash scripts/backup.sh
```

## 📁 Project Structure

```
bug-hunter/
├── main.py                    # Main entry point
├── cli/main.py               # CLI commands (Typer)
├── core/
│   ├── config_manager.py     # Configuration (Pydantic)
│   ├── database.py           # SQLAlchemy models + CRUD
│   └── scope_fetcher.py      # Multi-platform scope fetching
├── recon/
│   ├── subdomain_enum.py     # Subdomain enumeration
│   ├── service_discovery.py  # Port scan, TLS, CDN, ASN
│   ├── content_discovery.py  # Crawling, fuzzing, JS analysis
│   └── recon_orchestrator.py # Recon pipeline coordinator
├── hunting/
│   ├── scanner_orchestrator.py # Multi-scanner coordinator
│   ├── nuclei_manager.py     # Nuclei template management
│   ├── ai_hunter.py          # Multi-model AI hunting
│   ├── payload_manager.py    # Payload repository
│   └── specialized/          # XSS, SQLi, SSRF, RCE, Auth, Logic, API, Mobile, Cloud, Supply Chain
├── validation/
│   ├── browser_repro.py      # Firefox + Playwright reproduction
│   ├── burp_integration.py   # Burp Suite / mitmproxy
│   ├── terminal_capture.py   # asciinema terminal recording
│   ├── evidence_collector.py # Evidence packaging
│   └── validator.py          # Validation orchestrator
├── reporting/
│   ├── bug_database.py       # Bug lifecycle management
│   ├── report_generator.py   # POC reports (MD/HTML/PDF)
│   ├── scope_checklist.py    # Interactive scope tracking
│   └── export_formats/       # HackerOne, Bugcrowd, Intigriti
├── ui/
│   ├── backend/main.py       # FastAPI + WebSocket
│   └── frontend/             # React + TypeScript + Tailwind
├── mcp/
│   ├── servers/              # 7 MCP servers
│   └── client.py             # Unified MCP client
├── skills/
│   ├── loader.py             # Skills loader
│   └── github_skills.py      # GitHub skills fetcher
├── advanced/
│   ├── chaining.py           # Vulnerability chaining
│   └── monitoring.py         # Continuous monitoring
├── scripts/
│   ├── setup.sh              # Full environment setup
│   ├── backup.sh             # Backup database + evidence
│   ├── migrate.py            # Database migrations
│   └── fetch_checklist.py    # Checklist fetcher
├── config/                   # YAML configuration files
├── payloads/                 # Payload repositories
├── evidence/                 # Screenshots, videos, HAR, Burp, terminal
├── skills/                   # 50+ bug hunting skills
└── tests/                    # Unit & integration tests
```

## ⚙️ Configuration

### Programs (`config/programs.yaml`)
```yaml
programs:
  - name: "example-program"
    platform: "hackerone"
    handle: "example"
    enabled: true
    auth:
      type: "api_token"
      env_var: "H1_TOKEN"
    scope:
      file: "scopes/example.yaml"
      auto_fetch: true
    policy:
      max_severity: "P1"
      banned_types: ["self-xss", "clickjacking"]
      rate_limit: 100
```

### Hunting (`config/hunting.yaml`)
```yaml
hunting:
  threads: 50
  rate_limit_rps: 10
  scanners:
    nuclei:
      severity: ["critical", "high", "medium", "low"]
      rate_limit: 150
    dalfox:
      blind_xss: true
      worker: 50
  ai_hunting:
    enabled: true
    models:
      primary: "llama3.1:70b"
      code: "deepseek-coder:33b"
```

### Validation (`config/validation.yaml`)
```yaml
validation:
  browser:
    headless: false          # MUST be false for real evidence
    record_video: true
    har_capture: true
  burp:
    enabled: true
    use_mitmproxy_fallback: true
  evidence:
    annotate_screenshots: true
```

## 🔌 MCP Tools

The agent exposes 50+ MCP tools across 7 servers:

| Server | Tools |
|--------|-------|
| **Burp** | proxy_history, start_scan, get_issues, capture_traffic, mitmproxy |
| **Nuclei** | scan, get_templates, update_templates, create_template, validate |
| **Playwright** | new_context, navigate, click, fill, evaluate, screenshot, HAR, console, network |
| **Recon** | full_recon, subdomains, services, content |
| **Database** | CRUD for programs, findings, scope, scans, activity |
| **AI** | analyze_endpoint, generate_poc, validate_finding, chain_vulns, suggest_payloads |
| **Strix** | workflows, exploit_modules, methodologies (PTES, OWASP WSTG/MASTG) |

## 🧠 Skills System

50+ pre-loaded skills covering:
- **Recon**: Subdomain enum, content discovery, API discovery
- **Hunting**: XSS, SQLi, SSRF, RCE, Auth bypass, Logic, IDOR, CSRF, SSTI, XXE, etc.
- **Validation**: Browser repro, Burp capture, AI verification
- **Reporting**: POC generation, platform submission, evidence packaging
- **Methodology**: PTES, OWASP WSTG, MASTG, Bug bounty methodology

## 📸 Evidence Package

Each validated finding includes:
- `screenshots/` - Annotated full-page captures
- `videos/` - Playwright reproduction recordings
- `har/` - Network traffic (HAR format)
- `burp/` - Burp Suite exports
- `terminal/` - asciinema recordings
- `packages/` - Complete evidence ZIP with manifest
- `manifest.json` - Integrity hashes (SHA256)

## 🎯 Scope Checklist

Interactive tracking with:
- In-scope / Out-of-scope items
- Status: pending → testing → tested / skipped
- Coverage metrics (percentage tested)
- Findings per scope item
- Auto-mark from existing findings

## 🚀 Continuous Monitoring

- Scheduled recon (daily/weekly)
- New subdomain detection
- Technology stack changes
- Certificate expiration alerts
- New finding notifications
- Webhook/email integration

## 🛡️ Security & Legal

- **Scope Enforcement** - Hard blocks on out-of-scope targets
- **Rate Limiting** - Automatic per-program rate limits
- **No Synthetic Evidence** - All captures from real browser/proxy
- **Local Only** - No telemetry, no cloud dependencies
- **Authorized Only** - Only hunt programs you have permission for

## 📝 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## 📞 Support

- Issues: GitHub Issues
- Discussions: GitHub Discussions
- Security: security@bug-hunter.local

---

**⚠️ Disclaimer**: This tool is for authorized bug bounty hunting only. Only test targets you have explicit permission to test. The authors are not responsible for misuse.