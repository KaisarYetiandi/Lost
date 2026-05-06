<div align="center">
  
![KaisarYetiandi]([[https://raw.githubusercontent.com/KaisarYetiandi/Lost/refs/heads/main/LostFuz.png](https://raw.githubusercontent.com/KaisarYetiandi/Lost/refs/heads/main/LostFuz.jpg)])
  
  <h1>LostFuzzer</h1>
  
  **Advanced Bug Bounty Automation & Web Security Testing Framework**

  [![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
  [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
  [![Version](https://img.shields.io/badge/Version-1.0.0-purple.svg)](https://github.com/KaisarYetiandi/Lost)
  [![Stars](https://img.shields.io/github/stars/KaisarYetiandi/Lost?style=social)](https://github.com/KaisarYetiandi/Lost)

  **All-in-One** automated penetration testing toolkit with a beautiful TUI interface.

</div>

---

**What is LostFuzzer?** LostFuzzer is a tool I built to automate the boring parts of bug bounty and web pentesting. Instead of running 20 different tools manually, LostFuzzer puts everything in one place with a simple TUI menu. Just pick your target, choose a module, and let it run.

It handles recon, crawling, fuzzing, vulnerability scanning, and reporting. Basically everything you need from start to finish.

---
**Features**

### 🎮 Beautiful Interactive Terminal UI
- **Keyboard Navigation** — Intuitive navigation with up/down arrow keys
- **Rich Terminal UI** — Color-coded output, progress indicators, formatted tables
- **Real-time Status** — Live tool execution status updates
- **Findings Browser** — In-terminal vulnerability review with severity coloring
- **Resume Support** — Checkpoint-based scan resumption for large engagements

### 🔍 Reconnaissance
- **Subdomain Discovery** — Recursive subdomain enumeration using Subfinder with multiple sources
- **Live Host Probing** — HTTP/HTTPS service detection with Httpx (status codes, titles, technologies, IPs)
- **Port Scanning** — Fast TCP port scanning via Naabu with smart protocol detection
- **SSL/TLS Analysis** — Certificate transparency, SAN enumeration, expiry checks with Tlsx
- **ASN Mapping** — Autonomous System Number discovery and IP range expansion
- **CDN Detection** — Content Delivery Network identification and bypass assessment

### 🕷️ Crawling & URL Harvesting
- **Historical URL Collection** — Wayback Machine + AlienVault OTX + CommonCrawl via Gau & Waybackurls
- **Deep Crawling** — JavaScript-aware crawling with Katana (SPA support, JS rendering)
- **Link Discovery** — Endpoint and hidden path extraction with xnLinkFinder
- **Parameter Mining** — Automated parameter discovery via ParamSpider with injectable parameter classification
- **URL Deduplication** — Intelligent URL normalization and filtering with Uro
- **JavaScript Analysis** — JS file extraction, endpoint discovery, and secret scanning

### 🗂️ Content Discovery
- **Directory Fuzzing** — High-performance fuzzing with Ffuf (auto-calibration, JSON output)
- **Directory Bruteforce** — Recursive content discovery with Feroxbuster and Dirsearch
- **Wordlist Support** — SecLists integration with customizable wordlists (raft-medium, common, directory-list)

### 🔐 Vulnerability Scanning
- **XSS Detection** — Reflected/DOM XSS via Dalfox + XSStrike + Nuclei templates
- **SQL Injection** — Automated detection with SQLMap (tamper scripts, evasion techniques)
- **SSRF** — Server-Side Request Forgery detection with Nuclei DAST
- **LFI/Path Traversal** — Local File Inclusion and directory traversal testing
- **Open Redirect** — URL redirection vulnerability scanning
- **CORS Misconfiguration** — Cross-Origin Resource Sharing policy analysis
- **Subdomain Takeover** — DNS-based takeover detection with Subzy
- **JWT Attacks** — JSON Web Token analysis, algorithm confusion, key cracking
- **GraphQL** — Introspection query detection and endpoint discovery
- **CRLF Injection** — HTTP header injection testing
- **Nuclei Full Scan** — 5000+ templates covering CVEs, misconfigurations, and exposures

### 🔑 Secret Detection
- **API Key Scanning** — Regex-based secret extraction from JavaScript files
- **Credential Leaks** — Git history, file system scanning with TruffleHog
- **SecretFinder** — API keys, tokens, passwords in JS endpoints

### 📸 Visual Recon
- **Screenshots** — Automated webpage screenshots via GoWitness
- **Visual Gallery** — Organized screenshot directory for quick manual review

### 📊 Reporting
- **HTML Report** — Beautiful, dark-themed responsive HTML report with statistics and findings
- **JSON Export** — Machine-readable JSON output for integration with other tools
- **SQLite Database** — Persistent findings storage with scan history
- **Telegram Notifications** — Real-time alerts for scan completion and critical vulnerabilities

---

## 🛠️ Integrated Tools

| Category | Tools |
|----------|-------|
| **Subdomain Enumeration** | Subfinder, ASNMap |
| **Port Scanning** | Naabu |
| **HTTP Probing** | Httpx |
| **SSL/TLS** | Tlsx |
| **CDN Detection** | CdnCheck |
| **URL Harvesting** | Gau, Waybackurls, Katana, xnLinkFinder |
| **Parameter Discovery** | ParamSpider, Uro |
| **Content Discovery** | Ffuf, Feroxbuster, Dirsearch |
| **XSS** | Dalfox, XSStrike, Nuclei |
| **SQL Injection** | SQLMap, Nuclei |
| **SSRF** | Nuclei (DAST) |
| **LFI** | Nuclei (DAST) |
| **CORS** | Corsy, Nuclei |
| **Subdomain Takeover** | Subzy, Nuclei |
| **JWT** | jwt-tool, Nuclei |
| **CRLF** | CRLFuzz |
| **Secret Scanning** | SecretFinder, TruffleHog |
| **Screenshots** | GoWitness |
| **Vulnerability Scanning** | Nuclei (5000+ templates) |
| **Reporting** | Custom HTML/JSON/SQLite |

---

## 📋 Requirements

### System Requirements
- **OS**: Linux (Ubuntu 20.04+, Debian 11+, Kali Linux recommended)
- **RAM**: Minimum 4GB (8GB+ recommended for full scans)
- **Disk**: 10GB+ free space (for tools, wordlists, dependencies)
- **Python**: 3.8 or higher
- **Go**: 1.19 or higher
- **Root/Sudo**: Required for installation and some tooling

### Dependencies
All dependencies are automatically installed via `install.sh`:
- Python packages: rich, requests, pyyaml, urllib3, jinja2, uro, paramspider
- System packages: python3, golang, git, curl, wget, jq, unzip, tor
- Go tools: 25+ security tools from ProjectDiscovery and community
- External: SecLists wordlists, Nuclei templates, Chromium browser

---

## 🚀 Installation

### One-Line Installation

```bash
git clone https://github.com/KaisarYetiandi/Lost.git && cd Lost && sudo bash install.sh
```
## 👤 Author

- **Name**: KaisarYetiandi
- **GitHub**: [github.com/KaisarYetiandi](https://github.com/KaisarYetiandi)
- **Telegram**: [t.me/Darkness_Lock](https://t.me/Darkness_Lock)

## Support

<a href="https://buymeacoffee.com/KaisarYetiandi" target="_blank">
  <img src="https://img.shields.io/badge/☕-Buy_me_a_coffee-orange?style=for-the-badge" />
</a>
