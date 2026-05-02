<div align="center">

  <img src="[https://raw.githubusercontent.com/KaisarYetiandi/Lost/refs/heads/main/LostFuz.png]" width="180" alt="LostFuzzer Logo">
  
  <h1>LostFuzzer v1.0.0</h1>
  
  **Advanced Bug Bounty Automation & Web Security Testing Framework**

  [![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
  [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
  [![Version](https://img.shields.io/badge/Version-3.0.0-purple.svg)](https://github.com/KaisarYetiandi/LostFuzzer)
  [![Stars](https://img.shields.io/github/stars/KaisarYetiandi/LostFuzzer?style=social)](https://github.com/KaisarYetiandi/LostFuzzer)

  **All-in-One** automated penetration testing toolkit with a beautiful TUI interface.

</div>

---

## 📖 Overview

**LostFuzzer** is a comprehensive, all-in-one web security assessment and bug bounty automation tool designed for penetration testers, security researchers, and bug bounty hunters. It integrates over 30+ industry-standard security tools into a single, interactive TUI (Terminal User Interface) that streamlines the entire reconnaissance, crawling, vulnerability scanning, and reporting workflow.

Built with Python 3 and powered by the ProjectDiscovery ecosystem, LostFuzzer automates everything from initial subdomain discovery to final vulnerability reporting with minimal manual intervention.

---

## 🌟 Key Features

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
git clone https://github.com/KaisarYetiandi/LostFuzzer.git && cd LostFuzzer && sudo bash install.sh
