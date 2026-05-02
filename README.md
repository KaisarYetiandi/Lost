<div align="center">

  <img src="https://github.com/user-attachments/assets/0e8e8f8e-0e8e-4f8e-9e8e-0e8e8f8e0e8e" width="180" alt="LostFuzzer Logo">
  
  <h1>🔍 LostFuzzer v3.0.0</h1>
  
  **Framework Otomatisasi Bug Bounty & Pengujian Keamanan Web Tingkat Lanjut**

  [![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
  [![Lisensi](https://img.shields.io/badge/Lisensi-MIT-green.svg)](LICENSE)
  [![Versi](https://img.shields.io/badge/Versi-3.0.0-purple.svg)](https://github.com/KaisarYetiandi/LostFuzzer)
  [![Bintang](https://img.shields.io/github/stars/KaisarYetiandi/LostFuzzer?style=social)](https://github.com/KaisarYetiandi/LostFuzzer)

  **All-in-One** alat otomatisasi penetration testing dengan tampilan TUI yang cantik.

</div>

---

## 📖 Gambaran Umum

**LostFuzzer** adalah alat otomatisasi pengujian keamanan web dan bug bounty lengkap yang dirancang untuk penetration tester, peneliti keamanan, dan pemburu bug bounty. Alat ini mengintegrasikan lebih dari 30+ tools keamanan standar industri ke dalam satu TUI (Terminal User Interface) interaktif yang menyederhanakan seluruh alur kerja mulai dari reconnaissance, crawling, pemindaian kerentanan, hingga pelaporan.

Dibangun dengan Python 3 dan didukung oleh ekosistem ProjectDiscovery, LostFuzzer mengotomatiskan semuanya mulai dari penemuan subdomain awal hingga laporan kerentanan akhir dengan intervensi manual yang minimal.

---

## 🌟 Fitur Utama

### 🎮 Antarmuka Terminal Interaktif yang Cantik
- **Navigasi Keyboard** — Navigasi intuitif dengan tombol panah atas/bawah
- **Rich Terminal UI** — Output berwarna, indikator progres, tabel terformat
- **Status Real-time** — Status eksekusi tools secara langsung
- **Browser Temuan** — Review kerentanan dalam terminal dengan pewarnaan severity
- **Dukungan Resume** — Resume pemindaian berbasis checkpoint untuk engagement besar

### 🔍 Reconnaissance (Pengintaian)
- **Penemuan Subdomain** — Enumerasi subdomain rekursif menggunakan Subfinder dengan banyak sumber
- **Probing Host Live** — Deteksi layanan HTTP/HTTPS dengan Httpx (kode status, judul, teknologi, IP)
- **Pemindaian Port** — Pemindaian port TCP cepat via Naabu dengan deteksi protokol pintar
- **Analisis SSL/TLS** — Transparansi sertifikat, enumerasi SAN, pengecekan kadaluarsa dengan Tlsx
- **Pemetaan ASN** — Penemuan Autonomous System Number dan ekspansi rentang IP
- **Deteksi CDN** — Identifikasi Content Delivery Network dan penilaian bypass

### 🕷️ Crawling & Pengumpulan URL
- **Pengumpulan URL Historis** — Wayback Machine + AlienVault OTX + CommonCrawl via Gau & Waybackurls
- **Deep Crawling** — Crawling sadar JavaScript dengan Katana (dukungan SPA, rendering JS)
- **Penemuan Link** — Ekstraksi endpoint dan path tersembunyi dengan xnLinkFinder
- **Penambangan Parameter** — Penemuan parameter otomatis via ParamSpider dengan klasifikasi parameter injectable
- **Deduplikasi URL** — Normalisasi dan filtering URL cerdas dengan Uro
- **Analisis JavaScript** — Ekstraksi file JS, penemuan endpoint, dan pemindaian secret

### 🗂️ Penemuan Konten
- **Fuzzing Direktori** — Fuzzing performa tinggi dengan Ffuf (auto-kalibrasi, output JSON)
- **Bruteforce Direktori** — Penemuan konten rekursif dengan Feroxbuster dan Dirsearch
- **Dukungan Wordlist** — Integrasi SecLists dengan wordlist yang dapat disesuaikan (raft-medium, common, directory-list)

### 🔐 Pemindaian Kerentanan
- **Deteksi XSS** — Reflected/DOM XSS via Dalfox + XSStrike + template Nuclei
- **SQL Injection** — Deteksi otomatis dengan SQLMap (tamper scripts, teknik evasion)
- **SSRF** — Deteksi Server-Side Request Forgery dengan Nuclei DAST
- **LFI/Path Traversal** — Pengujian Local File Inclusion dan directory traversal
- **Open Redirect** — Pemindaian kerentanan pengalihan URL
- **CORS Misconfiguration** — Analisis kebijakan Cross-Origin Resource Sharing
- **Subdomain Takeover** — Deteksi takeover berbasis DNS dengan Subzy
- **Serangan JWT** — Analisis JSON Web Token, kebingungan algoritma, cracking kunci
- **GraphQL** — Deteksi query introspeksi dan penemuan endpoint
- **CRLF Injection** — Pengujian injeksi header HTTP
- **Nuclei Full Scan** — 5000+ template mencakup CVE, miskonfigurasi, dan eksposur

### 🔑 Deteksi Secret
- **Pemindaian API Key** — Ekstraksi secret berbasis regex dari file JavaScript
- **Kebocoran Kredensial** — Pemindaian riwayat Git dan sistem file dengan TruffleHog
- **SecretFinder** — API keys, token, password di endpoint JS

### 📸 Visual Recon
- **Screenshot** — Screenshot halaman web otomatis via GoWitness
- **Galeri Visual** — Direktori screenshot terorganisir untuk review manual cepat

### 📊 Pelaporan
- **HTML Report** — Laporan HTML responsif bertema gelap yang cantik dengan statistik dan temuan
- **JSON Export** — Output JSON machine-readable untuk integrasi dengan tools lain
- **Database SQLite** — Penyimpanan temuan persisten dengan riwayat pemindaian
- **Notifikasi Telegram** — Alert real-time untuk penyelesaian pemindaian dan kerentanan kritis

---

## 🛠️ Tools Terintegrasi

| Kategori | Tools |
|----------|-------|
| **Enumerasi Subdomain** | Subfinder, ASNMap |
| **Pemindaian Port** | Naabu |
| **Probing HTTP** | Httpx |
| **SSL/TLS** | Tlsx |
| **Deteksi CDN** | CdnCheck |
| **Pengumpulan URL** | Gau, Waybackurls, Katana, xnLinkFinder |
| **Penemuan Parameter** | ParamSpider, Uro |
| **Penemuan Konten** | Ffuf, Feroxbuster, Dirsearch |
| **XSS** | Dalfox, XSStrike, Nuclei |
| **SQL Injection** | SQLMap, Nuclei |
| **SSRF** | Nuclei (DAST) |
| **LFI** | Nuclei (DAST) |
| **CORS** | Corsy, Nuclei |
| **Subdomain Takeover** | Subzy, Nuclei |
| **JWT** | jwt-tool, Nuclei |
| **CRLF** | CRLFuzz |
| **Pemindaian Secret** | SecretFinder, TruffleHog |
| **Screenshot** | GoWitness |
| **Pemindaian Kerentanan** | Nuclei (5000+ template) |
| **Pelaporan** | HTML/JSON/SQLite Kustom |

---

## 📋 Persyaratan

### Persyaratan Sistem
- **OS**: Linux (Ubuntu 20.04+, Debian 11+, Kali Linux direkomendasikan)
- **RAM**: Minimum 4GB (8GB+ direkomendasikan untuk pemindaian penuh)
- **Disk**: 10GB+ ruang kosong (untuk tools, wordlist, dependencies)
- **Python**: 3.8 atau lebih tinggi
- **Go**: 1.19 atau lebih tinggi
- **Root/Sudo**: Diperlukan untuk instalasi dan beberapa tools

### Dependencies
Semua dependencies diinstal otomatis melalui `install.sh`:
- Paket Python: rich, requests, pyyaml, urllib3, jinja2, uro, paramspider
- Paket sistem: python3, golang, git, curl, wget, jq, unzip, tor
- Go tools: 25+ tools keamanan dari ProjectDiscovery dan komunitas
- Eksternal: wordlist SecLists, template Nuclei, browser Chromium

---

## 🚀 Instalasi

### Instalasi Satu Baris

```bash
git clone https://github.com/KaisarYetiandi/LostFuzzer.git && cd LostFuzzer && sudo bash install.sh
