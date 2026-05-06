import os
import sys
import csv
import json
import yaml
import time
import re
import sqlite3
import shutil
import signal
import threading
import subprocess

from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple

from rich.console import Console
from rich.text import Text
from rich.theme import Theme

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError as e:
    print(f"[!] Missing dependency: {e}\n    pip install requests rich pyyaml urllib3")
    sys.exit(1)

VERSION     = "2.0.0"
AUTHOR      = "KaisarYetiandi"
GITHUB      = "github.com/KaisarYetiandi"
TELEGRAM    = "t.me/Darkness_Lock"
RESULTS_DIR = Path("results")
CONFIG_FILE = Path("config.yaml")
DB_FILE     = Path("lostfuzzer.db")

THEME = Theme({
    "ok":        "bold bright_green",
    "run":       "bold yellow",
    "err":       "bold red",
    "skip":      "dim white",
    "warn":      "bold yellow",
    "accent":    "bold color(51)",
    "dim":       "dim white",
    "sep":       "color(238)",
    "label":     "color(245)",
    "value":     "bold white",
    "target":    "bold bright_white",
    "path":      "color(244)",
    "critical":  "bold bright_red",
    "high":      "bold color(203)",
    "medium":    "bold yellow",
    "low":       "bold bright_cyan",
    "info_sev":  "dim white",
    "cat_recon": "bold color(39)",
    "cat_crawl": "bold color(51)",
    "cat_sec":   "bold color(226)",
    "cat_vuln":  "bold color(203)",
    "cat_out":   "bold color(141)",
    "mn":        "color(240)",
    "sel":       "bold white",
    "prompt":    "bold color(196)",
    "muted":     "color(238)",
    "stat_n":    "bold color(51)",
    "stat_l":    "color(240)",
    "found":     "bold color(118)",
    "notfound":  "dim color(240)",
    "phase":     "bold color(226)",
    "tool_hdr":  "bold bright_white",
    "arrow":     "bold color(196)",
})

console = Console(theme=THEME)

BANNER = """\
  ██╗      ██████╗ ███████╗████████╗    ███████╗██╗   ██╗███████╗███████╗
  ██║     ██╔═══██╗██╔════╝╚══██╔══╝    ██╔════╝██║   ██║╚══███╔╝╚══███╔╝
  ██║     ██║   ██║███████╗   ██║       █████╗  ██║   ██║  ███╔╝   ███╔╝
  ██║     ██║   ██║╚════██║   ██║       ██╔══╝  ██║   ██║ ███╔╝   ███╔╝
  ███████╗╚██████╔╝███████║   ██║       ██║     ╚██████╔╝███████╗███████╗
  ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝      ╚═════╝ ╚══════╝╚══════╝
"""

MENU_ITEMS = [
    (1,  "RECON",  "cat_recon",  "Subdomain Recon",        "subfinder + amass + assetfinder + crt.sh"),
    (2,  "RECON",  "cat_recon",  "Deep Recon",             "subfinder + naabu + tlsx + asnmap"),
    (3,  "RECON",  "cat_recon",  "Port Scan",              "naabu + rustscan + nmap"),
    (4,  "CRAWL",  "cat_crawl",  "URL Harvest",            "gau + waybackurls + katana + gospider"),
    (5,  "CRAWL",  "cat_crawl",  "Historical URLs",        "gau + waybackurls"),
    (6,  "CRAWL",  "cat_crawl",  "Crawl & Probe",          "katana + hakrawler → httpx"),
    (7,  "CRAWL",  "cat_crawl",  "Parameter Discovery",    "paramspider + arjun + gf"),
    (8,  "CRAWL",  "cat_crawl",  "JS Discovery",           "xnLinkFinder + mantra + cariddi"),
    (9,  "CRAWL",  "cat_crawl",  "Hidden Endpoints",       "ffuf + feroxbuster + dirsearch"),
    (10, "SECRET", "cat_sec",    "Secret Hunt",            "SecretFinder + trufflehog"),
    (11, "VULN",   "cat_vuln",   "XSS",                    "gf + kxss + dalfox + xsstrike + nuclei"),
    (12, "VULN",   "cat_vuln",   "SQLi",                   "gf + sqlmap"),
    (13, "VULN",   "cat_vuln",   "SSRF",                   "nuclei -tags ssrf -dast"),
    (14, "VULN",   "cat_vuln",   "LFI",                    "nuclei -tags lfi -dast"),
    (15, "VULN",   "cat_vuln",   "Open Redirect",          "gf + qsreplace + nuclei"),
    (16, "VULN",   "cat_vuln",   "CORS",                   "corsy + nuclei"),
    (17, "VULN",   "cat_vuln",   "Subdomain Takeover",     "subzy + nuclei"),
    (18, "VULN",   "cat_vuln",   "JWT Audit",              "jwt-tool + nuclei"),
    (19, "VULN",   "cat_vuln",   "GraphQL Probe",          "introspection + nuclei"),
    (20, "VULN",   "cat_vuln",   "Nuclei Full Scan",       "nuclei all templates"),
    (21, "OUTPUT", "cat_out",    "Screenshot",             "gowitness"),
    (22, "OUTPUT", "cat_out",    "Full Auto Scan",         "complete pipeline"),
    (23, "OUTPUT", "cat_out",    "HTML / JSON / CSV",      "generate reports"),
    (24, "OUTPUT", "cat_out",    "Telegram Notify",        "configure bot"),
    (25, "OUTPUT", "cat_out",    "Update Tools",           "go install @latest"),
    (26, "OUTPUT", "cat_out",    "Exit",                   ""),
]

INJECTABLE_PARAMS = re.compile(
    r"[?&](?:"
    r"id|uid|gid|pid|sid|tid|cid|nid|eid|fid|rid|vid|mid|aid|bid|did|hid|oid|"
    r"uuid|gu?id|hash|token|nonce|state|session|ses|sess|csrf|xsrf|"
    r"auth|jwt|bearer|access_token|refresh_token|api_key|apikey|secret|pass|password|passwd|pwd|pin|otp|mfa|"
    r"key|priv|private_key|public_key|cert|certificate|sign|signature|sig|hmac|"
    r"page|pg|p|offset|limit|size|per_page|pagesize|start|end|cursor|after|before|since|until|"
    r"next|prev|back|goto|redirect|redir|return|returnurl|return_url|callback_url|cb|jsonp|"
    r"url|link|href|ref|referer|referrer|origin|target|path|uri|endpoint|route|"
    r"cat|categories|category|subcat|subcategory|tag|tags|label|labels|type|kind|class|group|"
    r"order|sort|orderby|sortby|by|direction|dir|asc|desc|filter|filters|q|query|search|s|k|kw|keyword|term|terms|text|"
    r"search_query|find|lookup|match|regex|pattern|like|contains|where|condition|"
    r"file|filename|files|file_path|fullpath|path|dir|directory|folder|include|require|require_once|load|import|"
    r"src|source|source_file|template|tpl|theme|layout|view|partial|component|module|widget|plugin|extension|"
    r"style|css|script|js|javascript|asset|assets|static|public|storage|uploads|downloads|media|"
    r"user|users|username|uname|userid|user_id|login|logon|signin|signup|register|account|profile|"
    r"email|mail|mailto|phone|mobile|contact|address|city|country|zip|postal|region|locale|lang|language|l|"
    r"name|first_name|last_name|fullname|nickname|display_name|avatar|photo|pic|image|img|thumb|thumbnail|"
    r"title|subject|headline|heading|subtitle|body|content|desc|description|summary|excerpt|text|msg|message|"
    r"comment|comments|review|reviews|rating|score|post|article|news|blog|story|page_content|entry|"
    r"item|product|products|sku|upc|ean|isbn|model|serial|barcode|"
    r"date|time|datetime|timestamp|year|month|day|hour|minute|second|week|quarter|fiscal|period|range|"
    r"action|do|method|op|operation|mode|cmd|command|exec|execute|run|invoke|trigger|dispatch|"
    r"task|job|process|function|func|handler|callback|hook|event|listener|middleware|interceptor|"
    r"data|input|value|val|payload|body|params|param|parameter|argument|arg|args|options|config|setting|settings|"
    r"field|fields|attribute|attributes|property|properties|column|columns|variable|var|env|environment|"
    r"format|fmt|output|export|download|dl|save|report|print|pdf|csv|json|xml|rss|atom|feed|api|rest|graphql|soap|"
    r"response_type|accept|content_type|mime|encoding|charset|"
    r"template|tpl|layout|theme|skin|module|widget|component|section|block|region|slot|placeholder|"
    r"tx|txn|transaction|payment|invoice|order_id|receipt|checkout|cart|basket|amount|price|total|subtotal|fee|tax|"
    r"currency|curr|wallet|balance|deposit|withdraw|transfer|"
    r"preview|draft|published|status|state|flag|flags|archived|deleted|trashed|restore|"
    r"read|show|fetch|get|load|open|display|render|stream|pipe|channel|socket|ws|wss|"
    r"notification|alert|toast|popup|modal|dialog|overlay|panel|sidebar|drawer|tab|accordion|"
    r"upload|uploaded|multipart|form-data|chunk|resumable|progress|"
    r"webhook|webhooks|endpoint|hook_url|notify_url|cancel_url|success_url|failure_url|"
    r"debug|test|sandbox|staging|production|dev|live|preview_mode|draft_mode|"
    r"version|v|rev|revision|build|release|branch|commit|tag_ref|"
    r"client_id|client_secret|consumer_key|consumer_secret|app_id|app_key|app_secret|developer_key|"
    r"scope|scopes|permission|permissions|role|roles|grant|grants|policy|policies|acl|"
    r"trace|trace_id|span|span_id|parent_id|correlation_id|request_id|x_request_id|x_trace_id|"
    r"cache|ttl|expire|expires|max_age|etag|last_modified|if_modified_since|if_none_match|"
    r"proxy|proxies|gateway|upstream|downstream|relay|forward|tunnel|"
    r"ai|ml|model|prompt|completion|embedding|vector|similarity|score|predict|infer|classify|analyze|generate"
    r")=",
    re.IGNORECASE
)

DEFAULT_CONFIG = {
    "threads":          50,
    "rate_limit":       150,
    "timeout":          15,
    "retries":          3,
    "proxy":            None,
    "tor":              False,
    "tor_proxy":        "socks5://127.0.0.1:9050",
    "wordlist":         "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "resolvers":        "/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
    "nuclei_templates": os.path.expanduser("~/nuclei-templates"),
    "notify_telegram":  False,
    "telegram_token":   "",
    "telegram_chatid":  "",
    "screenshot":       True,
    "wildcard_filter":  True,
    "ports":            "80,443,8080,8443,8888,3000,3001,5000,5001,8000,8001,9090,9443",
    "depth":            5,
    "delay":            0,
    "nuclei_severity":  "critical,high,medium,low",
    "user_agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "github_token":     "",
    "chaos_key":        "",
}


def gradient_text(text: str, start=(255, 0, 0), end=(0, 80, 255)) -> Text:
    out   = Text()
    total = len(text.replace("\n", ""))
    i     = 0
    for ch in text:
        if ch == "\n":
            out.append("\n")
            continue
        t = i / max(total - 1, 1)
        r = int(start[0] + (end[0] - start[0]) * t)
        g = int(start[1] + (end[1] - start[1]) * t)
        b = int(start[2] + (end[2] - start[2]) * t)
        out.append(ch, style=f"rgb({r},{g},{b})")
        i += 1
    return out


class Config:
    def __init__(self, path: Path = CONFIG_FILE):
        self.path = path
        self.data: Dict[str, Any] = {}
        self.load()

    def load(self):
        if self.path.exists():
            with open(self.path) as f:
                loaded = yaml.safe_load(f) or {}
            self.data = {**DEFAULT_CONFIG, **loaded}
        else:
            self.data = dict(DEFAULT_CONFIG)
            self.save()

    def save(self):
        with open(self.path, "w") as f:
            yaml.dump(self.data, f, default_flow_style=False, sort_keys=False)

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def set(self, key: str, value: Any):
        self.data[key] = value
        self.save()

    @property
    def proxy_dict(self) -> Optional[Dict]:
        if self.data.get("tor"):
            p = self.data["tor_proxy"]
        elif self.data.get("proxy"):
            p = self.data["proxy"]
        else:
            return None
        return {"http": p, "https": p}

    @property
    def proxy_url(self) -> Optional[str]:
        d = self.proxy_dict
        return (d.get("https") or d.get("http")) if d else None


class Database:
    def __init__(self, path: Path = DB_FILE):
        self.path = path
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.lock = threading.Lock()
        self._init()

    def _init(self):
        with self.lock:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL, module TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    started_at TEXT, finished_at TEXT,
                    result_count INTEGER DEFAULT 0,
                    UNIQUE(domain, module)
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, module TEXT, severity TEXT,
                    title TEXT, url TEXT, detail TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, url TEXT UNIQUE,
                    live INTEGER DEFAULT 0, status_code INTEGER,
                    created_at TEXT DEFAULT (datetime('now'))
                );
            """)
            self.conn.commit()

    def upsert_scan(self, domain: str, module: str, status: str, result_count: int = 0):
        with self.lock:
            now = datetime.now().isoformat()
            self.conn.execute(
                """INSERT INTO scans (domain,module,status,started_at,finished_at,result_count)
                   VALUES(?,?,?,?,?,?)
                   ON CONFLICT(domain,module) DO UPDATE SET
                   status=excluded.status, finished_at=excluded.finished_at,
                   result_count=excluded.result_count""",
                (domain, module, status, now, now, result_count)
            )
            self.conn.commit()

    def get_scan_status(self, domain: str, module: str) -> Optional[str]:
        with self.lock:
            c = self.conn.execute(
                "SELECT status FROM scans WHERE domain=? AND module=?", (domain, module)
            )
            row = c.fetchone()
            return row[0] if row else None

    def add_finding(self, domain: str, module: str, severity: str, title: str, url: str, detail: str = ""):
        with self.lock:
            self.conn.execute(
                "INSERT INTO findings (domain,module,severity,title,url,detail) VALUES(?,?,?,?,?,?)",
                (domain, module, severity, title, url, detail)
            )
            self.conn.commit()

    def get_findings(self, domain: str) -> List[Dict]:
        with self.lock:
            c = self.conn.execute(
                "SELECT module,severity,title,url,detail,created_at FROM findings WHERE domain=? ORDER BY created_at DESC",
                (domain,)
            )
            return [{"module": r[0], "severity": r[1], "title": r[2], "url": r[3], "detail": r[4], "created_at": r[5]}
                    for r in c.fetchall()]

    def add_urls(self, domain: str, urls: List[str]):
        with self.lock:
            self.conn.executemany(
                "INSERT OR IGNORE INTO urls (domain,url) VALUES(?,?)",
                [(domain, u) for u in urls if u.strip()]
            )
            self.conn.commit()

    def close(self):
        self.conn.close()


class FileManager:
    DIRS = ["subdomains", "live", "ports", "urls", "params", "js", "endpoints",
            "secrets", "xss", "sqli", "nuclei", "screenshots", "reports", "logs"]

    def __init__(self, domain: str):
        self.domain = domain
        self.base   = RESULTS_DIR / domain
        self.dirs   = {d: self.base / d for d in self.DIRS}
        for d in self.dirs.values():
            d.mkdir(parents=True, exist_ok=True)

    def path(self, cat: str, name: str) -> Path:
        return self.dirs[cat] / name

    def write(self, cat: str, name: str, lines: List[str]) -> Path:
        p       = self.path(cat, name)
        content = "\n".join(str(l).strip() for l in lines if str(l).strip())
        p.write_text(content + "\n" if content else "")
        return p

    def append(self, cat: str, name: str, lines: List[str]):
        p = self.path(cat, name)
        with open(p, "a") as f:
            for l in lines:
                if l.strip():
                    f.write(l.strip() + "\n")

    def read(self, cat: str, name: str) -> List[str]:
        p = self.path(cat, name)
        if not p.exists() or p.stat().st_size == 0:
            return []
        return [l.strip() for l in p.read_text().splitlines() if l.strip()]

    def count(self, cat: str, name: str) -> int:
        return len(self.read(cat, name))

    def exists(self, cat: str, name: str) -> bool:
        p = self.path(cat, name)
        return p.exists() and p.stat().st_size > 0


class Runner:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def run(
        self,
        cmd: List[str],
        stdin_data: str = None,
        stdin_file: Path = None,
        stdout_file: Path = None,
        env: Dict = None,
        timeout: int = None,
        retries: int = None,
    ) -> Tuple[int, str, str]:
        t        = timeout or self.cfg.get("timeout", 15) * 20
        ret      = retries if retries is not None else self.cfg.get("retries", 3)
        env_full = {**os.environ}
        if env:
            env_full.update(env)
        if stdin_file and stdin_file.exists() and stdin_data is None:
            stdin_data = stdin_file.read_text()
        for attempt in range(ret + 1):
            try:
                sout   = open(stdout_file, "w") if stdout_file else subprocess.PIPE
                result = subprocess.run(
                    cmd,
                    input=stdin_data,
                    stdout=sout,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=t,
                    env=env_full,
                )
                if stdout_file and hasattr(sout, "close"):
                    sout.close()
                stdout_val = "" if stdout_file else (result.stdout or "").strip()
                return result.returncode, stdout_val, (result.stderr or "").strip()
            except subprocess.TimeoutExpired:
                if attempt == ret:
                    return -1, "", "timeout"
            except FileNotFoundError:
                return -2, "", f"not installed: {cmd[0]}"
            except Exception as e:
                if attempt == ret:
                    return -1, "", str(e)
            time.sleep(1.5)
        return -1, "", "max retries"

    def exists(self, name: str) -> bool:
        return shutil.which(name) is not None


class URLFilter:
    @staticmethod
    def dedupe(urls: List[str]) -> List[str]:
        seen, result = set(), []
        for u in urls:
            u = u.strip()
            if u and u not in seen:
                seen.add(u)
                result.append(u)
        return result

    @staticmethod
    def injectable(urls: List[str]) -> List[str]:
        result = [u for u in urls if INJECTABLE_PARAMS.search(u)]
        if not result:
            result = [u for u in urls if "?" in u and "=" in u]
        return URLFilter.dedupe(result)

    @staticmethod
    def js_files(urls: List[str]) -> List[str]:
        return [u for u in urls if re.search(r'\.js(\?|$)', u)]

    @staticmethod
    def base_url(line: str) -> str:
        return line.split()[0].strip() if line.strip() else ""

    @staticmethod
    def strip_scheme(host: str) -> str:
        return re.sub(r"https?://", "", host).split("/")[0].split(":")[0]

    @staticmethod
    def naabu_to_urls(lines: List[str]) -> List[str]:
        urls = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                host, port = line.rsplit(":", 1)
                port       = port.strip()
                proto      = "https" if port in ("443", "8443", "8888") else "http"
                urls.append(f"{proto}://{host}:{port}")
            else:
                urls.append(f"http://{line}")
        return urls

    @staticmethod
    def normalize_host(raw: str) -> str:
        return re.sub(r"https?://", "", raw).split("/")[0].split(":")[0].strip()


class UI:
    @staticmethod
    def clear():
        os.system("cls" if os.name == "nt" else "clear")

    @staticmethod
    def banner():
        UI.clear()
        console.print()
        console.print(gradient_text(BANNER))
        info = Text()
        info.append("  LostFuzzer ", style="bold white")
        info.append(f"v{VERSION}", style="color(93) dim")
        info.append("  ·  ", style="color(238)")
        info.append(f"@{AUTHOR}", style="color(162) dim")
        info.append("  ·  ", style="color(238)")
        info.append(GITHUB, style="color(57) dim")
        console.print(info)

    @staticmethod
    def hsep(label: str = "", color: str = "sep"):
        if label:
            pad = max(0, 42 - len(label))
            console.print(f"  [sep]──[/sep]  [{color}]{label}[/{color}]  [sep]{'─'*pad}[/sep]")
        else:
            console.print(f"  [sep]{'─'*50}[/sep]")

    @staticmethod
    def section(title: str, color: str = "color(93)"):
        console.print()
        pad = max(0, 42 - len(title))
        console.print(f"  [sep]──[/sep]  [{color}]{title}[/{color}]  [sep]{'─'*pad}[/sep]")
        console.print()

    @staticmethod
    def phase_header(phase: str, desc: str, color: str = "color(196)"):
        console.print()
        console.print()
        console.print(f"  [{color}]◈  {phase}[/{color}]  [sep]──[/sep]  [label]{desc}[/label]")
        console.print(f"  [sep]{'═' * 54}[/sep]")
        console.print()

    @staticmethod
    def tool_start(name: str):
        bar = "─" * (len(name) + 2)
        console.print()
        console.print(f"  [tool_hdr]{name}[/tool_hdr]")
        console.print(f"  [sep]{bar}[/sep]")

    @staticmethod
    def tool_done(state: str, detail: str = ""):
        tags = {
            "ok":   ("[ok]",   "[/ok]",   " OK  "),
            "err":  ("[err]",  "[/err]",  " ERR "),
            "skip": ("[skip]", "[/skip]", "SKIP "),
            "done": ("[ok]",   "[/ok]",   "DONE "),
        }
        o, c, label = tags.get(state, ("[dim]", "[/dim]", state[:4].upper()))
        d = f"  [dim]{detail}[/dim]" if detail else ""
        console.print(f"  {o}[{label}]{c}{d}")

    @staticmethod
    def show_lines(lines: List[str], max_lines: int = 8):
        for line in lines[:max_lines]:
            console.print(f"  [accent]↳[/accent]  [dim]{line}[/dim]")
        if len(lines) > max_lines:
            console.print(f"  [muted]  ↳  ... {len(lines) - max_lines} more[/muted]")

    @staticmethod
    def stat(label: str, value: Any):
        vstr   = str(value)
        vstyle = "stat_n" if vstr.isdigit() and int(vstr) > 0 else "label"
        console.print(f"  [stat_l]{label:<24}[/stat_l]  [{vstyle}]{vstr}[/{vstyle}]")

    @staticmethod
    def finding(severity: str, module: str, title: str, url: str):
        sev_map = {
            "critical": "[critical]CRIT[/critical]",
            "high":     "[high]HIGH[/high]",
            "medium":   "[medium] MED[/medium]",
            "low":      "[low] LOW[/low]",
            "info":     "[info_sev]INFO[/info_sev]",
        }
        tag = sev_map.get(severity.lower(), f"[dim]{severity[:4].upper():<4}[/dim]")
        console.print(f"  {tag}  [dim]{module:<14}[/dim]  [value]{title}[/value]  [path]{url[:55]}[/path]")

    @staticmethod
    def err(msg: str):
        console.print(f"  [err]✘[/err]  [dim]{msg}[/dim]")

    @staticmethod
    def warn(msg: str):
        console.print(f"  [warn]⚠[/warn]  [dim]{msg}[/dim]")

    @staticmethod
    def ok(msg: str):
        console.print(f"  [ok]✔[/ok]  [dim]{msg}[/dim]")

    @staticmethod
    def info(msg: str):
        console.print(f"  [accent]·[/accent]  [dim]{msg}[/dim]")

    @staticmethod
    def ask(label: str) -> str:
        console.print(f"  [label]{label}[/label]", end="")
        console.print(f"  [prompt] ❯ [/prompt]", end="")
        sys.stdout.flush()
        try:
            return input().strip()
        except (EOFError, KeyboardInterrupt):
            return ""

    @staticmethod
    def pause():
        console.print()
        try:
            input("  Press Enter to return to menu... ")
        except (EOFError, KeyboardInterrupt):
            pass

    @staticmethod
    def render_menu(target: str, domain_count: int):
        UI.clear()
        UI.banner()
        console.print()
        cat_colors = {
            "RECON":  "cat_recon",
            "CRAWL":  "cat_crawl",
            "SECRET": "cat_sec",
            "VULN":   "cat_vuln",
            "OUTPUT": "cat_out",
        }
        cats_seen: Dict[str, bool] = {}
        for num, cat, ckey, label, hint in MENU_ITEMS:
            if cat not in cats_seen:
                cats_seen[cat] = True
                col = cat_colors.get(cat, "sep")
                pad = max(0, 46 - len(cat))
                console.print(f"  [sep]──[/sep]  [{col}]{cat}[/{col}]  [sep]{'─'*pad}[/sep]")
            num_s  = f"{num:02d}"
            hint_p = f"  [muted]{hint}[/muted]" if hint else ""
            console.print(f"  [mn]{num_s}[/mn]  [color(250)]{label:<28}[/color(250)]{hint_p}")
        console.print()
        UI.hsep()
        tgt = target if target else "[dim](not set)[/dim]"
        cnt = f"  [muted]({domain_count} domains)[/muted]" if domain_count > 1 else ""
        console.print(f"  [label]Target[/label]  [sep]──[/sep]  [target]{tgt}[/target]{cnt}")
        UI.hsep()
        console.print()

    @staticmethod
    def interactive_menu(target: str, domain_count: int) -> int:
        while True:
            UI.render_menu(target, domain_count)
            console.print(f"  [prompt]❯[/prompt] Select [sep][01-26][/sep]: ", end="")
            sys.stdout.flush()
            try:
                raw = input().strip()
            except (EOFError, KeyboardInterrupt):
                return 26
            if raw.lower() in ("q", "quit", "exit"):
                return 26
            try:
                n = int(raw)
                if 1 <= n <= 26:
                    return n
            except ValueError:
                pass
            console.print(f"  [err]✘[/err]  [dim]Invalid option. Enter 01-26 or q to exit.[/dim]")
            time.sleep(0.8)

    @staticmethod
    def print_findings(domain: str, db: "Database"):
        findings = db.get_findings(domain)
        if not findings:
            return
        console.print()
        UI.hsep("FINDINGS", "color(203)")
        console.print()
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings  = sorted(findings, key=lambda f: sev_order.get(f["severity"].lower(), 5))
        for f in findings:
            UI.finding(f["severity"], f["module"], f["title"], f["url"])


class PassiveEnum:
    def __init__(self, domain: str, targets: List[str], fm: FileManager, r: Runner, db: Database):
        self.domain  = domain
        self.targets = targets
        self.fm      = fm
        self.r       = r
        self.db      = db
        self.cfg     = r.cfg

    def subfinder(self) -> int:
        out = self.fm.path("subdomains", "subfinder.txt")
        cmd = [
            "subfinder", "-silent", "-all", "-recursive",
            "-timeout", "30", "-max-time", "20", "-rl", "100",
            "-o", str(out),
        ]
        if len(self.targets) == 1:
            cmd += ["-d", self.targets[0]]
        else:
            tf = self.fm.path("subdomains", "targets.txt")
            self.fm.write("subdomains", "targets.txt", self.targets)
            cmd += ["-dL", str(tf)]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            return -2
        n = self.fm.count("subdomains", "subfinder.txt")
        self.db.upsert_scan(self.domain, "subfinder", "done", n)
        return n

    def amass(self) -> int:
        out = self.fm.path("subdomains", "amass.txt")
        cmd = [
            "amass", "enum", "-passive",
            "-d",       self.domain,
            "-o",       str(out),
            "-timeout", "20",
            "-silent",
        ]
        rc, _, _ = self.r.run(cmd, timeout=1200)
        if rc == -2:
            return -2
        n = self.fm.count("subdomains", "amass.txt")
        self.db.upsert_scan(self.domain, "amass", "done", n)
        return n

    def assetfinder(self) -> int:
        out = self.fm.path("subdomains", "assetfinder.txt")
        rc, stdout, _ = self.r.run(["assetfinder", "--subs-only", self.domain], timeout=300)
        if rc == -2:
            return -2
        if stdout:
            lines = [l for l in stdout.splitlines() if self.domain in l]
            self.fm.write("subdomains", "assetfinder.txt", lines)
        n = self.fm.count("subdomains", "assetfinder.txt")
        self.db.upsert_scan(self.domain, "assetfinder", "done", n)
        return n

    def findomain(self) -> int:
        out = self.fm.path("subdomains", "findomain.txt")
        cmd = ["findomain", "-t", self.domain, "-u", str(out), "--quiet"]
        rc, _, _ = self.r.run(cmd, timeout=300)
        if rc == -2:
            return -2
        n = self.fm.count("subdomains", "findomain.txt")
        self.db.upsert_scan(self.domain, "findomain", "done", n)
        return n

    def crtsh(self) -> int:
        out_lines: List[str] = []
        try:
            sess = requests.Session()
            sess.headers["User-Agent"] = self.cfg.get("user_agent", "Mozilla/5.0")
            if self.cfg.proxy_dict:
                sess.proxies = self.cfg.proxy_dict
            resp = sess.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=30, verify=False
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.splitlines():
                        sub = sub.strip().lstrip("*.")
                        if sub and self.domain in sub and sub not in out_lines:
                            out_lines.append(sub)
        except Exception:
            pass
        if out_lines:
            self.fm.write("subdomains", "crtsh.txt", out_lines)
        n = len(out_lines)
        self.db.upsert_scan(self.domain, "crtsh", "done", n)
        return n

    def chaos(self) -> int:
        key = self.cfg.get("chaos_key", "")
        if not key:
            return -2
        out = self.fm.path("subdomains", "chaos.txt")
        cmd = ["chaos", "-d", self.domain, "-o", str(out), "-silent", "-key", key]
        rc, _, _ = self.r.run(cmd, timeout=300)
        if rc == -2:
            return -2
        n = self.fm.count("subdomains", "chaos.txt")
        self.db.upsert_scan(self.domain, "chaos", "done", n)
        return n

    def merge_passive(self) -> int:
        combined: List[str] = []
        for name in ["subfinder.txt", "amass.txt", "assetfinder.txt", "findomain.txt", "crtsh.txt", "chaos.txt"]:
            combined.extend(self.fm.read("subdomains", name))
        normalized: List[str] = []
        for h in combined:
            h = URLFilter.normalize_host(h)
            if h and "." in h and self.domain in h:
                normalized.append(h)
        deduped = URLFilter.dedupe(normalized)
        self.fm.write("subdomains", "passive.txt", deduped)
        n = len(deduped)
        self.db.upsert_scan(self.domain, "passive_merge", "done", n)
        return n


class DNSValidator:
    def __init__(self, domain: str, fm: FileManager, r: Runner, db: Database):
        self.domain = domain
        self.fm     = fm
        self.r      = r
        self.db     = db
        self.cfg    = r.cfg

    def _passive_src(self) -> Path:
        for name in ["passive.txt", "subfinder.txt", "targets.txt"]:
            if self.fm.exists("subdomains", name):
                return self.fm.path("subdomains", name)
        tf = self.fm.path("subdomains", "targets.txt")
        return tf

    def dnsx(self) -> int:
        src     = self._passive_src()
        out_raw = self.fm.path("subdomains", "dnsx_raw.txt")
        cmd     = [
            "dnsx", "-silent",
            "-l",     str(src),
            "-o",     str(out_raw),
            "-a", "-cname", "-resp",
            "-retry", "3",
            "-rl",    "100",
            "-t",     "50",
        ]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            fallback = self.fm.read("subdomains", src.name)
            self.fm.write("subdomains", "dnsx_clean.txt", fallback or [self.domain])
            return -2
        raw   = self.fm.read("subdomains", "dnsx_raw.txt")
        clean = list(dict.fromkeys(
            URLFilter.normalize_host(line.split()[0])
            for line in raw
            if line.split() and "." in line.split()[0]
        ))
        if not clean:
            clean = self.fm.read("subdomains", src.name)
        self.fm.write("subdomains", "dnsx_clean.txt", clean)
        n = len(clean)
        self.db.upsert_scan(self.domain, "dnsx", "done", n)
        return n

    def shuffledns(self) -> int:
        src = self._passive_src()
        rsl = self.cfg.get("resolvers", "")
        if not rsl or not os.path.exists(rsl):
            return -2
        out = self.fm.path("subdomains", "shuffledns.txt")
        cmd = [
            "shuffledns",
            "-list",      str(src),
            "-r",         rsl,
            "-o",         str(out),
            "-silent",
            "-t",         "5000",
            "-mode",      "resolve",
        ]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            return -2
        n = self.fm.count("subdomains", "shuffledns.txt")
        self.db.upsert_scan(self.domain, "shuffledns", "done", n)
        return n

    def puredns(self) -> int:
        src = self._passive_src()
        rsl = self.cfg.get("resolvers", "")
        if not rsl or not os.path.exists(rsl):
            return -2
        out = self.fm.path("subdomains", "puredns.txt")
        cmd = [
            "puredns", "resolve", str(src),
            "-r",         rsl,
            "--write",    str(out),
            "--quiet",
        ]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            return -2
        n = self.fm.count("subdomains", "puredns.txt")
        self.db.upsert_scan(self.domain, "puredns", "done", n)
        return n

    def merge_validated(self) -> int:
        combined: List[str] = []
        for name in ["dnsx_clean.txt", "shuffledns.txt", "puredns.txt"]:
            combined.extend(self.fm.read("subdomains", name))
        deduped = URLFilter.dedupe([h for h in combined if h and "." in h])
        if not deduped:
            deduped = [self.domain]
        self.fm.write("subdomains", "validated.txt", deduped)
        n = len(deduped)
        self.db.upsert_scan(self.domain, "validated_merge", "done", n)
        return n

    def httpx_hosts(self) -> int:
        input_hosts: List[str] = []
        for name in ["validated.txt", "dnsx_clean.txt", "passive.txt", "subfinder.txt"]:
            lines = self.fm.read("subdomains", name)
            if lines:
                for l in lines:
                    h = URLFilter.normalize_host(l.split()[0])
                    if h and "." in h:
                        input_hosts.append(h)
                break
        if not input_hosts:
            input_hosts = [self.domain]
        for port_url in self.fm.read("ports", "port_urls.txt"):
            input_hosts.append(port_url)
        input_hosts = list(dict.fromkeys(h for h in input_hosts if h.strip()))
        self.fm.write("subdomains", "httpx_input.txt", input_hosts)
        merged_file = self.fm.path("subdomains", "httpx_input.txt")
        out         = self.fm.path("live", "live_hosts.txt")
        cmd         = [
            "httpx", "-silent",
            "-l",               str(merged_file),
            "-o",               str(out),
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-follow-redirects",
            "-web-server",
            "-favicon",
            "-jarm",
            "-asn",
            "-ip",
            "-cname",
            "-mc",              "200,201,202,204,206,301,302,307,308,401,403,405,429,500,502,503",
            "-threads",         "50",
            "-rl",              "100",
            "-timeout",         "20",
            "-retries",         "2",
        ]
        rc, _, _ = self.r.run(cmd, timeout=900)
        if rc == -2:
            return -2
        raw   = self.fm.read("live", "live_hosts.txt")
        hosts = [URLFilter.base_url(l) for l in raw if URLFilter.base_url(l).startswith("http")]
        if not hosts:
            sess = requests.Session()
            sess.headers["User-Agent"] = self.cfg.get("user_agent", "Mozilla/5.0")
            if self.cfg.proxy_dict:
                sess.proxies = self.cfg.proxy_dict
            for h in input_hosts[:10]:
                for scheme in ["https", "http"]:
                    test = f"{scheme}://{h}" if not h.startswith("http") else h
                    try:
                        rsp = sess.head(test, timeout=12, verify=False, allow_redirects=True)
                        if rsp.status_code < 600:
                            hosts.append(test)
                            break
                    except Exception:
                        continue
        hosts = list(dict.fromkeys(hosts))
        self.fm.write("live", "live_hosts_clean.txt", hosts)
        n = len(hosts)
        self.db.upsert_scan(self.domain, "httpx_hosts", "done", n)
        return n

    def httpx_probe_urls(self, url_file: Path) -> int:
        if not url_file.exists() or url_file.stat().st_size == 0:
            return 0
        out = self.fm.path("live", "live_urls.txt")
        cmd = [
            "httpx", "-silent",
            "-l",               str(url_file),
            "-o",               str(out),
            "-threads",         "50",
            "-rl",              "100",
            "-timeout",         "20",
            "-retries",         "2",
            "-mc",              "200,201,204,301,302,307,308,401,403,405,429,500,502,503",
            "-follow-redirects",
            "-status-code",
        ]
        rc, _, _ = self.r.run(cmd, timeout=900)
        if rc == -2:
            return -2
        raw  = self.fm.read("live", "live_urls.txt")
        urls = [URLFilter.base_url(l) for l in raw if URLFilter.base_url(l).startswith("http")]
        self.fm.write("live", "live_urls.txt", urls)
        self.db.add_urls(self.domain, urls)
        n = len(urls)
        self.db.upsert_scan(self.domain, "httpx_urls", "done", n)
        return n

    def naabu(self) -> int:
        src = None
        for cat, name in [("subdomains", "validated.txt"), ("subdomains", "dnsx_clean.txt"),
                          ("subdomains", "passive.txt"), ("subdomains", "subfinder.txt")]:
            if self.fm.exists(cat, name):
                src = self.fm.path(cat, name)
                break
        if not src:
            tf = self.fm.path("subdomains", "targets.txt")
            self.fm.write("subdomains", "targets.txt", [self.domain])
            src = tf
        out = self.fm.path("ports", "naabu.txt")
        cmd = [
            "naabu", "-silent",
            "-l",            str(src),
            "-top-ports",    "1000",
            "-rate",         "1500",
            "-retries",      "2",
            "-warm-up-time", "2",
            "-verify",
            "-o",            str(out),
            "-ep",           "22,23,25,445,3389",
            "-t",            "25",
        ]
        rc, _, _ = self.r.run(cmd, timeout=900)
        if rc == -2:
            return -2
        raw       = self.fm.read("ports", "naabu.txt")
        port_urls = URLFilter.naabu_to_urls(raw)
        self.fm.write("ports", "port_urls.txt", port_urls)
        n = len(raw)
        self.db.upsert_scan(self.domain, "naabu", "done", n)
        return n

    def tlsx(self) -> int:
        if not self.fm.exists("live", "live_hosts_clean.txt"):
            return 0
        src = self.fm.path("live", "live_hosts_clean.txt")
        out = self.fm.path("live", "tlsx.txt")
        cmd = ["tlsx", "-silent", "-l", str(src), "-o", str(out), "-san", "-cn", "-so", "-expired"]
        rc, _, _ = self.r.run(cmd, timeout=300)
        return -2 if rc == -2 else self.fm.count("live", "tlsx.txt")

    def asnmap(self) -> int:
        out = self.fm.path("subdomains", "asnmap.txt")
        cmd = ["asnmap", "-silent", "-d", self.domain, "-o", str(out)]
        rc, _, _ = self.r.run(cmd, timeout=120)
        return -2 if rc == -2 else self.fm.count("subdomains", "asnmap.txt")

    def cdncheck(self) -> int:
        if not self.fm.exists("live", "live_hosts_clean.txt"):
            return 0
        src = self.fm.path("live", "live_hosts_clean.txt")
        out = self.fm.path("live", "cdn_check.txt")
        cmd = ["cdncheck", "-silent", "-l", str(src), "-o", str(out), "-resp"]
        rc, _, _ = self.r.run(cmd, timeout=120)
        return -2 if rc == -2 else self.fm.count("live", "cdn_check.txt")


class PortScanner:
    def __init__(self, domain: str, fm: FileManager, r: Runner, db: Database):
        self.domain = domain
        self.fm     = fm
        self.r      = r
        self.db     = db
        self.cfg    = r.cfg

    def _target_file(self) -> Path:
        for cat, name in [("subdomains", "validated.txt"), ("subdomains", "dnsx_clean.txt"),
                          ("subdomains", "passive.txt"), ("subdomains", "subfinder.txt")]:
            if self.fm.exists(cat, name):
                return self.fm.path(cat, name)
        tf = self.fm.path("subdomains", "targets.txt")
        self.fm.write("subdomains", "targets.txt", [self.domain])
        return tf

    def naabu(self) -> int:
        src = self._target_file()
        out = self.fm.path("ports", "naabu.txt")
        cmd = [
            "naabu", "-silent",
            "-l",            str(src),
            "-top-ports",    "1000",
            "-rate",         "1500",
            "-retries",      "2",
            "-warm-up-time", "2",
            "-verify",
            "-o",            str(out),
            "-ep",           "22,23,25,445,3389",
            "-t",            "25",
        ]
        rc, _, _ = self.r.run(cmd, timeout=900)
        if rc == -2:
            return -2
        raw       = self.fm.read("ports", "naabu.txt")
        port_urls = URLFilter.naabu_to_urls(raw)
        self.fm.write("ports", "port_urls.txt", port_urls)
        n = len(raw)
        self.db.upsert_scan(self.domain, "naabu", "done", n)
        return n

    def rustscan(self) -> int:
        src   = self._target_file()
        hosts = self.fm.read("subdomains", src.name)[:20]
        if not hosts:
            hosts = [self.domain]
        out   = self.fm.path("ports", "rustscan.txt")
        lines = []
        for host in hosts:
            cmd = ["rustscan", "-a", host, "--ulimit", "5000", "-b", "500", "--", "-sV", "--open"]
            rc, stdout, _ = self.r.run(cmd, timeout=300, retries=0)
            if rc == -2:
                return -2
            if stdout:
                lines.extend(stdout.splitlines())
        if lines:
            self.fm.write("ports", "rustscan.txt", lines)
        n = self.fm.count("ports", "rustscan.txt")
        self.db.upsert_scan(self.domain, "rustscan", "done", n)
        return n

    def nmap_fingerprint(self) -> int:
        port_data = self.fm.read("ports", "naabu.txt") or self.fm.read("ports", "rustscan.txt")
        if not port_data:
            return 0
        out = self.fm.path("ports", "nmap.txt")
        cmd = [
            "nmap", "-sV", "-sC",
            "--open",
            "-T4",
            "-oN", str(out),
            "--host-timeout", "120s",
            self.domain,
        ]
        rc, _, _ = self.r.run(cmd, timeout=300, retries=0)
        if rc == -2:
            return -2
        n = self.fm.count("ports", "nmap.txt")
        self.db.upsert_scan(self.domain, "nmap", "done", n)
        return n

    def merge_ports(self) -> int:
        combined: List[str] = []
        for name in ["naabu.txt", "rustscan.txt"]:
            combined.extend(self.fm.read("ports", name))
        port_urls = URLFilter.naabu_to_urls(combined)
        existing  = self.fm.read("ports", "port_urls.txt")
        merged    = URLFilter.dedupe(existing + port_urls)
        self.fm.write("ports", "port_urls.txt", merged)
        return len(merged)


class URLCollector:
    def __init__(self, domain: str, targets: List[str], fm: FileManager, r: Runner, db: Database):
        self.domain  = domain
        self.targets = targets
        self.fm      = fm
        self.r       = r
        self.db      = db
        self.cfg     = r.cfg

    def _host_src(self) -> Optional[Path]:
        for name in ["live_hosts_clean.txt", "live_hosts.txt"]:
            if self.fm.exists("live", name):
                return self.fm.path("live", name)
        return None

    def _live_urls(self) -> List[str]:
        for name in ["live_urls.txt", "live_hosts_clean.txt", "live_hosts.txt"]:
            data = self.fm.read("live", name)
            if data:
                return [URLFilter.base_url(l) for l in data if URLFilter.base_url(l).startswith("http")]
        return []

    def gau(self) -> int:
        out = self.fm.path("urls", "gau.txt")
        cmd = ["gau", "--subs", "--threads", "80", "--o", str(out), self.domain]
        rc, stdout, _ = self.r.run(cmd, timeout=900)
        if rc == -2:
            rc2, stdout2, _ = self.r.run(["gau", "--threads", "5", self.domain], timeout=600)
            if stdout2:
                self.fm.write("urls", "gau.txt", stdout2.splitlines())
        n = self.fm.count("urls", "gau.txt")
        self.db.upsert_scan(self.domain, "gau", "done", n)
        return n

    def waybackurls(self) -> int:
        rc, stdout, _ = self.r.run(["waybackurls"], stdin_data=self.domain + "\n", timeout=600)
        if rc == -2:
            return -2
        if stdout:
            self.fm.write("urls", "wayback.txt", stdout.splitlines())
        n = self.fm.count("urls", "wayback.txt")
        return n

    def katana(self) -> int:
        src = self._host_src()
        if not src:
            tf = self.fm.path("live", "katana_input.txt")
            self.fm.write("live", "katana_input.txt",
                          [f"https://{t}" if not t.startswith("http") else t for t in self.targets])
            src = tf
        out = self.fm.path("urls", "katana.txt")
        cmd = [
            "katana", "-silent",
            "-list",    str(src),
            "-o",       str(out),
            "-jc",
            "-kf",      "all",
            "-d",       "5",
            "-c",       "20",
            "-p",       "10",
            "-rl",      "150",
            "-timeout", "15",
            "-ef",      "woff,woff2,css,png,jpg,jpeg,gif,ico,svg,ttf,eot",
            "-xhr",
        ]
        rc, _, _ = self.r.run(cmd, timeout=1200)
        if rc == -2:
            return -2
        n = self.fm.count("urls", "katana.txt")
        self.db.upsert_scan(self.domain, "katana", "done", n)
        return n

    def hakrawler(self) -> int:
        urls = self._live_urls()
        if not urls:
            urls = [f"https://{self.domain}"]
        out   = self.fm.path("urls", "hakrawler.txt")
        lines = []
        for url in urls[:5]:
            cmd = ["hakrawler", "-url", url, "-depth", "3", "-plain", "-subs", "-u"]
            rc, stdout, _ = self.r.run(cmd, timeout=300, retries=0)
            if rc == -2:
                return -2
            if stdout:
                lines.extend(stdout.splitlines())
        if lines:
            self.fm.write("urls", "hakrawler.txt", lines)
        n = self.fm.count("urls", "hakrawler.txt")
        self.db.upsert_scan(self.domain, "hakrawler", "done", n)
        return n

    def gospider(self) -> int:
        urls = self._live_urls()
        if not urls:
            urls = [f"https://{self.domain}"]
        out  = self.fm.path("urls", "gospider.txt")
        cmd  = [
            "gospider",
            "-s",       urls[0],
            "-o",       str(out.parent),
            "-c",       "10",
            "-d",       "3",
            "-t",       "20",
            "--include-subs",
            "--no-redirect",
            "-q",
        ]
        rc, stdout, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            return -2
        spider_dir = self.fm.dirs["urls"]
        all_lines  = []
        for f in spider_dir.glob("*.txt"):
            if f.name != "gospider.txt":
                continue
            all_lines.extend(f.read_text().splitlines())
        if stdout:
            all_lines.extend(stdout.splitlines())
        if all_lines:
            urls_only = [re.sub(r'^\[.*?\]\s+', '', l).strip() for l in all_lines if "http" in l]
            self.fm.write("urls", "gospider.txt", urls_only)
        n = self.fm.count("urls", "gospider.txt")
        self.db.upsert_scan(self.domain, "gospider", "done", n)
        return n

    def xnlinkfinder(self) -> int:
        src = self._host_src()
        if not src:
            return 0
        hosts  = self.fm.read("live", "live_hosts_clean.txt") if self.fm.exists("live", "live_hosts_clean.txt") else self.fm.read("live", "live_hosts.txt")
        target = hosts[0] if hosts else f"https://{self.domain}"
        out    = self.fm.path("urls", "xnlinkfinder.txt")
        cmd    = ["xnLinkFinder", "-i", target, "-op", str(out), "-sp", target, "-d", "4", "-p", "80"]
        rc, _, _ = self.r.run(cmd, timeout=300)
        return -2 if rc == -2 else self.fm.count("urls", "xnlinkfinder.txt")

    def merge_and_filter(self) -> Tuple[int, int, int]:
        combined: List[str] = []
        for cat, name in [
            ("urls", "gau.txt"), ("urls", "wayback.txt"), ("urls", "katana.txt"),
            ("urls", "hakrawler.txt"), ("urls", "gospider.txt"), ("urls", "xnlinkfinder.txt"),
            ("ports", "port_urls.txt"),
        ]:
            combined.extend(self.fm.read(cat, name))
        combined = URLFilter.dedupe(combined)
        self.fm.write("urls", "all_raw.txt", combined)
        rc, stdout, _ = self.r.run(["uro"], stdin_data="\n".join(combined), timeout=300)
        filtered = URLFilter.dedupe(stdout.splitlines()) if rc == 0 and stdout else combined
        filtered = [u for u in filtered if re.match(r'https?://', u)]
        self.fm.write("urls", "all_urls.txt", filtered)
        self.db.add_urls(self.domain, filtered)
        self.db.upsert_scan(self.domain, "uro", "done", len(filtered))
        param_urls = URLFilter.injectable(filtered)
        self.fm.write("urls", "param_urls.txt", param_urls)
        js_urls = URLFilter.js_files(filtered)
        self.fm.write("js", "js_urls.txt", js_urls)
        return len(filtered), len(param_urls), len(js_urls)


class ParamDiscovery:
    def __init__(self, domain: str, fm: FileManager, r: Runner, db: Database):
        self.domain = domain
        self.fm     = fm
        self.r      = r
        self.db     = db
        self.cfg    = r.cfg

    def paramspider(self) -> int:
        out  = self.fm.path("params", "paramspider.txt")
        cmd1 = ["paramspider", "-d", self.domain, "--level", "high", "-s", "-o", str(out)]
        rc, _, _ = self.r.run(cmd1, timeout=300)
        if rc == -2:
            cmd2 = [sys.executable, "-m", "paramspider", "-d", self.domain, "--level", "high", "-o", str(out)]
            rc, _, _ = self.r.run(cmd2, timeout=300)
        return self.fm.count("params", "paramspider.txt")

    def arjun(self) -> int:
        live = self.fm.read("live", "live_urls.txt") or self.fm.read("live", "live_hosts_clean.txt")
        if not live:
            return 0
        out = self.fm.path("params", "arjun.txt")
        urls_sample = [URLFilter.base_url(l) for l in live[:10] if URLFilter.base_url(l).startswith("http")]
        if not urls_sample:
            return 0
        all_lines: List[str] = []
        for url in urls_sample:
            cmd = [
                "arjun",
                "-u",  url,
                "-oT", str(out),
                "-t",  "10",
                "-d",  "5",
                "-q",
            ]
            rc, stdout, _ = self.r.run(cmd, timeout=120, retries=0)
            if rc == -2:
                return -2
            if stdout:
                all_lines.extend(stdout.splitlines())
        if all_lines:
            self.fm.append("params", "arjun.txt", all_lines)
        n = self.fm.count("params", "arjun.txt")
        self.db.upsert_scan(self.domain, "arjun", "done", n)
        return n

    def gf_params(self) -> int:
        all_u = self.fm.read("urls", "all_urls.txt")
        if not all_u:
            return 0
        out = self.fm.path("params", "gf_params.txt")
        rc, stdout, _ = self.r.run(
            ["gf", "params"],
            stdin_data="\n".join(all_u),
            timeout=120
        )
        if rc == -2:
            return -2
        if stdout:
            self.fm.write("params", "gf_params.txt", stdout.splitlines())
        n = self.fm.count("params", "gf_params.txt")
        self.db.upsert_scan(self.domain, "gf_params", "done", n)
        return n

    def merge_params(self) -> int:
        combined: List[str] = []
        for name in ["paramspider.txt", "arjun.txt", "gf_params.txt"]:
            combined.extend(self.fm.read("params", name))
        combined.extend(self.fm.read("urls", "param_urls.txt"))
        merged = URLFilter.dedupe([u for u in combined if "=" in u and u.startswith("http")])
        self.fm.write("params", "all_params.txt", merged)
        n = len(merged)
        self.db.upsert_scan(self.domain, "params_merge", "done", n)
        return n


class JSAnalyzer:
    TOOLS_BASE = Path("/opt/lostfuzzer-tools")

    def __init__(self, domain: str, fm: FileManager, r: Runner, db: Database):
        self.domain = domain
        self.fm     = fm
        self.r      = r
        self.db     = db
        self.cfg    = r.cfg

    def _live_urls(self) -> List[str]:
        for name in ["live_urls.txt", "live_hosts_clean.txt"]:
            data = self.fm.read("live", name)
            if data:
                return [URLFilter.base_url(l) for l in data if URLFilter.base_url(l).startswith("http")]
        return []

    def js_discovery(self) -> int:
        all_u = self.fm.read("urls", "all_urls.txt")
        js    = URLFilter.js_files(all_u)
        xnl   = URLFilter.js_files(self.fm.read("urls", "xnlinkfinder.txt"))
        js    = URLFilter.dedupe(js + xnl)
        self.fm.write("js", "js_urls.txt", js)
        return len(js)

    def secretfinder(self) -> int:
        js_urls = self.fm.read("js", "js_urls.txt")
        if not js_urls:
            all_u   = self.fm.read("urls", "all_urls.txt")
            js_urls = URLFilter.js_files(all_u)
        if not js_urls:
            return 0
        out_lines: List[str] = []
        scripts = [self.TOOLS_BASE / "SecretFinder" / "SecretFinder.py", Path("SecretFinder.py")]
        sf      = next((str(p) for p in scripts if p.exists()), None)
        for url in js_urls[:60]:
            cmd = [sys.executable, sf, "-i", url, "-o", "cli"] if sf else ["SecretFinder", "-i", url, "-o", "cli"]
            rc, stdout, _ = self.r.run(cmd, timeout=60, retries=0)
            if rc != -2 and stdout:
                hits = [l for l in stdout.splitlines() if l.strip() and "No secret" not in l and "[" in l]
                if hits:
                    out_lines.extend([f"[{url}]  {h}" for h in hits])
        if out_lines:
            self.fm.write("secrets", "secretfinder.txt", out_lines)
            for l in out_lines:
                self.db.add_finding(self.domain, "secretfinder", "medium", "Secret Exposed", "", l)
        return len(out_lines)

    def trufflehog(self) -> int:
        urls  = self._live_urls()
        hits: List[str] = []
        for url in urls[:10]:
            cmd = [
                "trufflehog", "url", url,
                "--json", "--no-update", "--only-verified",
                "--concurrency=72", "--filter-entropy=3.0",
                "--detector-timeout=40s", "--archive-max-size=40MB",
                "--archive-max-depth=6", "--archive-timeout=90s",
                "--allow-verification-overlap", "--filter-unverified",
            ]
            rc, stdout, _ = self.r.run(cmd, timeout=120, retries=0)
            if rc == -2:
                cmd2 = [
                    "trufflehog", "filesystem",
                    "--directory", str(self.fm.base),
                    "--json", "--no-update", "--filter-entropy=3.0",
                    "--results=verified,unverified,unknown",
                ]
                rc2, stdout2, _ = self.r.run(cmd2, timeout=120, retries=0)
                if stdout2:
                    hits.extend(stdout2.splitlines())
                break
            if stdout:
                hits.extend(stdout.splitlines())
        if hits:
            self.fm.write("secrets", "trufflehog.txt", hits)
            for h in hits:
                self.db.add_finding(self.domain, "trufflehog", "high", "Credential Leak", "", h[:300])
        return len(hits)

    def mantra(self) -> int:
        js_urls = self.fm.read("js", "js_urls.txt")
        if not js_urls:
            return 0
        out = self.fm.path("secrets", "mantra.txt")
        rc, stdout, _ = self.r.run(
            ["mantra"],
            stdin_data="\n".join(js_urls),
            timeout=300
        )
        if rc == -2:
            return -2
        if stdout:
            hits = [l for l in stdout.splitlines() if l.strip()]
            self.fm.write("secrets", "mantra.txt", hits)
            for h in hits:
                self.db.add_finding(self.domain, "mantra", "medium", "Secret in JS", "", h)
        n = self.fm.count("secrets", "mantra.txt")
        self.db.upsert_scan(self.domain, "mantra", "done", n)
        return n

    def cariddi(self) -> int:
        urls = self._live_urls()
        if not urls:
            return 0
        out = self.fm.path("urls", "cariddi.txt")
        cmd = [
            "cariddi",
            "-s",
            "-e",
            "-info",
            "-err",
            "-cache",
            "-d",  "3",
        ]
        rc, stdout, _ = self.r.run(cmd, stdin_data="\n".join(urls[:10]), timeout=300)
        if rc == -2:
            return -2
        if stdout:
            self.fm.write("urls", "cariddi.txt", stdout.splitlines())
        n = self.fm.count("urls", "cariddi.txt")
        self.db.upsert_scan(self.domain, "cariddi", "done", n)
        return n

    def gowitness(self) -> int:
        urls = self._live_urls()
        if not urls:
            return 0
        src = self.fm.path("live", "live_urls.txt")
        if not self.fm.exists("live", "live_urls.txt"):
            src = self.fm.path("live", "live_hosts_clean.txt")
            if not src.exists():
                return 0
        out_dir = self.fm.dirs["screenshots"]
        cmd     = [
            "gowitness", "scan", "file",
            "-f",                str(src),
            "--screenshot-path", str(out_dir),
            "--threads",         "30",
            "--timeout",         "20",
            "--write-db",
        ]
        rc, _, _ = self.r.run(cmd, timeout=900)
        return -2 if rc == -2 else len(list(out_dir.glob("*.png")))


class ContentDiscovery:
    def __init__(self, domain: str, fm: FileManager, r: Runner, db: Database):
        self.domain = domain
        self.fm     = fm
        self.r      = r
        self.db     = db
        self.cfg    = r.cfg

    def _wordlist(self) -> str:
        cfg_wl = self.cfg.get("wordlist", "")
        if cfg_wl and os.path.exists(cfg_wl):
            return cfg_wl
        candidates = [
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/big.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirb/big.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            "/opt/SecLists/Discovery/Web-Content/raft-medium-words.txt",
            "/opt/SecLists/Discovery/Web-Content/common.txt",
            os.path.expanduser("~/SecLists/Discovery/Web-Content/raft-medium-words.txt"),
            os.path.expanduser("~/SecLists/Discovery/Web-Content/common.txt"),
            os.path.expanduser("~/wordlists/common.txt"),
        ]
        for p in candidates:
            if p and os.path.exists(p):
                return p
        for pattern_name in ["raft-medium-words.txt", "common.txt", "raft-small-words.txt"]:
            try:
                result = subprocess.run(
                    ["find", "/usr/share", "/opt", os.path.expanduser("~"),
                     "-name", pattern_name, "-type", "f"],
                    capture_output=True, text=True, timeout=8
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and os.path.exists(line):
                        return line
            except Exception:
                pass
        return ""

    def _live_urls(self) -> List[str]:
        for name in ["live_urls.txt", "live_hosts_clean.txt", "live_hosts.txt"]:
            data = self.fm.read("live", name)
            if data:
                return [URLFilter.base_url(l) for l in data if URLFilter.base_url(l).startswith("http")]
        return []

    def ffuf(self, target: Optional[str] = None) -> int:
        wl = self._wordlist()
        if not wl:
            return -1
        urls  = [target] if target else self._live_urls()[:5]
        if not urls:
            return 0
        total = 0
        for url in urls:
            base  = url.rstrip("/")
            ofile = self.fm.path("endpoints", f"ffuf_{abs(hash(base)) % 99999}.json")
            cmd   = [
                "ffuf", "-s",
                "-u",            f"{base}/FUZZ",
                "-w",            wl,
                "-t",            str(min(self.cfg.get("threads", 50), 50)),
                "-rate",         str(self.cfg.get("rate_limit", 150)),
                "-mc",           "200,201,204,301,302,307,308,401,403,405",
                "-ac",
                "-o",            str(ofile),
                "-of",           "json",
                "-timeout",      str(self.cfg.get("timeout", 15)),
                "-maxtime",      "300",
                "-maxtime-job",  "120",
                "-ic",
                "-noninteractive",
            ]
            if self.cfg.proxy_url:
                cmd += ["-x", self.cfg.proxy_url]
            rc, _, _ = self.r.run(cmd, timeout=400)
            if rc == -2:
                return -2
            if ofile.exists() and ofile.stat().st_size > 2:
                try:
                    data = json.loads(ofile.read_text())
                    hits = data.get("results", [])
                    total += len(hits)
                    lines = []
                    for h in hits:
                        u = h.get("url", "") or h.get("input", {}).get("FUZZ", "")
                        if u:
                            lines.append(f"{h.get('status', 0)} {u} [{h.get('length', 0)}]")
                    if lines:
                        self.fm.append("endpoints", "ffuf_all.txt", lines)
                except Exception:
                    pass
        return total

    def feroxbuster(self, target: Optional[str] = None) -> int:
        wl   = self._wordlist()
        urls = [target] if target else self._live_urls()[:3]
        if not wl:
            return -1
        if not urls:
            return 0
        out  = self.fm.path("endpoints", "feroxbuster.txt")
        cmd  = [
            "feroxbuster", "--stdin",
            "-w",            wl,
            "-x",            "php", "-x", "html", "-x", "js",
            "-x",            "json", "-x", "txt", "-x", "bak",
            "-x",            "env", "-x", "sql", "-x", "zip",
            "-d",            "4",
            "-t",            str(min(self.cfg.get("threads", 50), 50)),
            "--rate-limit",  str(self.cfg.get("rate_limit", 150)),
            "-o",            str(out),
            "--quiet",
            "--no-state",
            "-r", "-k",
            "-T",            str(self.cfg.get("timeout", 15)),
            "--auto-bail",
            "-s",            "200", "-s", "201", "-s", "204",
            "-s",            "301", "-s", "302", "-s", "307",
            "-s",            "308", "-s", "401", "-s", "403",
            "-s",            "405",
        ]
        if self.cfg.proxy_url:
            cmd += ["-p", self.cfg.proxy_url]
        rc, _, _ = self.r.run(cmd, stdin_data="\n".join(urls), timeout=900)
        if rc == -2:
            return -2
        return self.fm.count("endpoints", "feroxbuster.txt")

    def dirsearch(self, target: Optional[str] = None) -> int:
        urls = [target] if target else self._live_urls()[:3]
        if not urls:
            return 0
        out = self.fm.path("endpoints", "dirsearch.txt")
        cmd = [
            "dirsearch", "-u", urls[0],
            "-t",        str(min(self.cfg.get("threads", 50), 100)),
            "-o",        str(out),
            "--format",  "plain", "-q",
            "-x",        "404,400,429",
            "-e",        "php,html,js,txt,json,asp,aspx,bak,zip,sql,env,git,conf,swp,old",
            "--timeout", str(self.cfg.get("timeout", 15)),
        ]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            cmd2 = [sys.executable, "-m", "dirsearch", "-u", urls[0], "-q", "-o", str(out), "--format", "plain"]
            rc, _, _ = self.r.run(cmd2, timeout=600)
        return self.fm.count("endpoints", "dirsearch.txt")

    def merge_endpoint_urls(self) -> int:
        lines: List[str] = []
        for name in ["ffuf_all.txt", "feroxbuster.txt", "dirsearch.txt"]:
            for line in self.fm.read("endpoints", name):
                parts = line.split()
                for p in parts:
                    if p.startswith("http"):
                        lines.append(p)
                        break
        lines = URLFilter.dedupe(lines)
        if not lines:
            return 0
        rc, stdout, _ = self.r.run(["uro"], stdin_data="\n".join(lines), timeout=120)
        if rc == 0 and stdout:
            lines = URLFilter.dedupe(stdout.splitlines())
        self.fm.write("endpoints", "merged_endpoints.txt", lines)
        return len(lines)


class VulnScanner:
    TOOLS_BASE = Path("/opt/lostfuzzer-tools")

    def __init__(self, domain: str, fm: FileManager, r: Runner, db: Database):
        self.domain = domain
        self.fm     = fm
        self.r      = r
        self.db     = db
        self.cfg    = r.cfg

    def _tdir(self) -> Optional[str]:
        tdir = self.cfg.get("nuclei_templates", os.path.expanduser("~/nuclei-templates"))
        for p in [str(tdir), os.path.expanduser("~/nuclei-templates"), "/root/nuclei-templates"]:
            if p and os.path.isdir(p):
                return p
        return None

    def _params_file(self) -> Optional[Path]:
        for cat, name in [("params", "all_params.txt"), ("urls", "param_urls.txt"), ("params", "paramspider.txt")]:
            if self.fm.exists(cat, name):
                return self.fm.path(cat, name)
        all_u = self.fm.read("urls", "all_urls.txt")
        inj   = URLFilter.injectable(all_u)
        if inj:
            self.fm.write("urls", "param_urls.txt", inj)
            return self.fm.path("urls", "param_urls.txt")
        return None

    def _live_file(self) -> Optional[Path]:
        for name in ["live_urls.txt", "live_hosts_clean.txt"]:
            if self.fm.exists("live", name):
                return self.fm.path("live", name)
        return None

    def _first_live(self) -> str:
        f = self._live_file()
        if f:
            lines = self.fm.read("live", f.name)
            if lines:
                return URLFilter.base_url(lines[0]) or f"https://{self.domain}"
        return f"https://{self.domain}"

    def nuclei(self, tags: List[str] = None, severity: str = None, dast: bool = False, src: Optional[Path] = None) -> int:
        if src is None:
            src = self._params_file() if dast else self._live_file()
        if not src:
            return 0
        sev    = severity or self.cfg.get("nuclei_severity", "critical,high,medium,low")
        suffix = "_" + "_".join(tags) if tags else ("_dast" if dast else "")
        out    = self.fm.path("nuclei", f"nuclei{suffix}.txt")
        cmd    = [
            "nuclei", "-silent",
            "-l",          str(src),
            "-o",          str(out),
            "-as",
            "-headless",
            "-rate-limit", "250",
            "-c",          "100",
            "-bulk-size",  "50",
            "-retries",    "1",
            "-timeout",    str(self.cfg.get("timeout", 15)),
            "-severity",   sev,
            "-fr",
            "-system-resolvers",
            "-hm",
        ]
        tdir = self._tdir()
        if tdir:
            cmd += ["-t", tdir]
        if dast:
            cmd += ["-dast"]
        if tags:
            cmd += ["-tags", ",".join(tags)]
        if self.cfg.proxy_url:
            cmd += ["-proxy", self.cfg.proxy_url]
        rc, _, _ = self.r.run(cmd, timeout=3600)
        if rc == -2:
            return -2
        results = self.fm.read("nuclei", f"nuclei{suffix}.txt")
        for line in results:
            sm = re.search(r'\[(critical|high|medium|low|info)\]', line, re.I)
            um = re.search(r'https?://\S+', line)
            tm = re.search(r'^\[([^\]]+)\]', line)
            self.db.add_finding(
                self.domain, "nuclei",
                sm.group(1).lower() if sm else "info",
                tm.group(1) if tm else line[:60],
                um.group(0) if um else "",
                line
            )
        n = len(results)
        self.db.upsert_scan(self.domain, f"nuclei{suffix}", "done", n)
        return n

    def gf_filter(self, pattern: str) -> List[str]:
        all_u = self.fm.read("urls", "all_urls.txt")
        if not all_u:
            return []
        rc, stdout, _ = self.r.run(
            ["gf", pattern],
            stdin_data="\n".join(all_u),
            timeout=60
        )
        if rc == -2:
            return []
        return [l for l in stdout.splitlines() if l.strip()] if stdout else []

    def xss_pipeline(self) -> int:
        gf_urls = self.gf_filter("xss")
        param_urls = self.fm.read("params", "all_params.txt") or self.fm.read("urls", "param_urls.txt")
        all_targets = URLFilter.dedupe(gf_urls + param_urls)
        valid       = [u for u in all_targets if u.startswith("http") and "=" in u][:100]
        if valid:
            self.fm.write("xss", "xss_targets.txt", valid)
        kxss_hits: List[str] = []
        if valid:
            rc, stdout, _ = self.r.run(
                ["kxss"],
                stdin_data="\n".join(valid),
                timeout=300
            )
            if rc != -2 and stdout:
                kxss_hits = [l for l in stdout.splitlines() if l.strip()]
                if kxss_hits:
                    self.fm.write("xss", "kxss.txt", kxss_hits)
                    for h in kxss_hits:
                        self.db.add_finding(self.domain, "kxss", "medium", "XSS Reflection", "", h)
        return len(kxss_hits)

    def dalfox(self) -> int:
        lines = self.fm.read("xss", "xss_targets.txt") or self.fm.read("params", "all_params.txt") or self.fm.read("urls", "param_urls.txt")
        if not lines:
            return 0
        valid = [l for l in lines if l.strip().startswith("http") and "=" in l][:50]
        if not valid:
            return 0
        out = self.fm.path("xss", "dalfox.txt")
        cmd = [
            "dalfox", "pipe",
            "--mining-dom",
            "--follow-redirects",
            "--worker",  "20",
            "--timeout", str(self.cfg.get("timeout", 30)),
            "--delay",   "0",
            "--max-cpu", "4",
            "-S",
            "-o",        str(out),
            "--no-color",
        ]
        if self.cfg.proxy_url:
            cmd += ["--proxy", self.cfg.proxy_url]
        rc, _, _ = self.r.run(cmd, stdin_data="\n".join(valid), timeout=600)
        if rc == -2:
            return -2
        results = self.fm.read("xss", "dalfox.txt")
        for v in results:
            um = re.search(r'https?://\S+', v)
            self.db.add_finding(self.domain, "dalfox", "high", "XSS (Reflected)", um.group(0) if um else "", v)
        n = len(results)
        self.db.upsert_scan(self.domain, "dalfox", "done", n)
        return n

    def xsstrike(self, target_url: Optional[str] = None) -> int:
        url     = target_url or self._first_live()
        scripts = [self.TOOLS_BASE / "XSStrike" / "xsstrike.py", Path("XSStrike/xsstrike.py")]
        sc      = next((str(p) for p in scripts if p.exists()), None)
        out     = self.fm.path("xss", "xsstrike.txt")
        if sc:
            cmd = [sys.executable, sc, "--url", url, "--crawl", "--blind",
                   "--timeout", str(self.cfg.get("timeout", 15)),
                   "--threads", str(min(self.cfg.get("threads", 50), 10))]
        else:
            cmd = ["xsstrike", "--url", url, "--crawl"]
        rc, stdout, _ = self.r.run(cmd, timeout=300)
        if rc == -2:
            return -2
        if stdout:
            self.fm.write("xss", "xsstrike.txt", stdout.splitlines())
        return self.fm.count("xss", "xsstrike.txt")

    def sqlmap(self, target_url: Optional[str] = None) -> int:
        gf_urls = self.gf_filter("sqli")
        src     = self._params_file()
        if not target_url and not src and not gf_urls:
            return 0
        if gf_urls and not target_url:
            filtered = gf_urls[:50]
            tmp      = self.fm.path("params", "gf_sqli.txt")
            self.fm.write("params", "gf_sqli.txt", filtered)
            src = tmp
        base_cmd = [
            "sqlmap",
            "--batch", "--random-agent", "--smart",
            "--level",      "4",
            "--risk",       "2",
            "--threads",    str(min(self.cfg.get("threads", 50), 10)),
            "--timeout",    str(self.cfg.get("timeout", 30)),
            "--retries",    "2",
            "--output-dir", str(self.fm.dirs["sqli"]),
            "--forms",
            "--tamper=space2comment,between,randomcase,charencode",
            "--crawl",      "2",
            "-q",
        ]
        if target_url:
            cmd = base_cmd + ["-u", target_url]
        else:
            cmd = base_cmd + ["-m", str(src)]
        if self.cfg.proxy_url:
            cmd += ["--proxy", self.cfg.proxy_url]
        rc, stdout, _ = self.r.run(cmd, timeout=3600)
        if rc == -2:
            return -2
        vuln_count = (stdout or "").count("is vulnerable")
        self.db.upsert_scan(self.domain, "sqlmap", "done", vuln_count)
        return vuln_count

    def show_param_urls(self) -> List[str]:
        return self.fm.read("params", "all_params.txt") or self.fm.read("urls", "param_urls.txt")

    def ssrf_scan(self) -> int:
        src = self._params_file() or self._live_file()
        if not src:
            return 0
        out = self.fm.path("nuclei", "ssrf.txt")
        cmd = [
            "nuclei", "-silent",
            "-l",        str(src),
            "-tags",     "ssrf",
            "-severity", "critical,high,medium",
            "-o",        str(out),
            "-rl",       "250",
            "-dast",
        ]
        tdir = self._tdir()
        if tdir:
            cmd += ["-t", tdir]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            return -2
        results = self.fm.read("nuclei", "ssrf.txt")
        for v in results:
            um = re.search(r'https?://\S+', v)
            self.db.add_finding(self.domain, "ssrf", "high", "SSRF", um.group(0) if um else "", v)
        return len(results)

    def lfi_scan(self) -> int:
        src = self._params_file() or self._live_file()
        if not src:
            return 0
        out = self.fm.path("nuclei", "lfi.txt")
        cmd = [
            "nuclei", "-silent",
            "-l",        str(src),
            "-tags",     "lfi,path-traversal",
            "-severity", "critical,high,medium",
            "-o",        str(out),
            "-rl",       "250",
            "-dast",
        ]
        tdir = self._tdir()
        if tdir:
            cmd += ["-t", tdir]
        rc, _, _ = self.r.run(cmd, timeout=900)
        if rc == -2:
            return -2
        results = self.fm.read("nuclei", "lfi.txt")
        for v in results:
            um = re.search(r'https?://\S+', v)
            self.db.add_finding(self.domain, "lfi", "high", "LFI / Path Traversal",
                                um.group(0) if um else "", v)
        return len(results)

    def redirect_scan(self) -> int:
        gf_urls = self.gf_filter("redirect")
        if gf_urls:
            redir_file = self.fm.path("params", "gf_redirect.txt")
            self.fm.write("params", "gf_redirect.txt", gf_urls[:100])
            if self.r.exists("qsreplace"):
                rc, stdout, _ = self.r.run(
                    ["qsreplace", "https://evil.com"],
                    stdin_data="\n".join(gf_urls[:100]),
                    timeout=30
                )
                if rc == 0 and stdout:
                    qsr_urls = stdout.splitlines()
                    sess     = requests.Session()
                    sess.verify = False
                    hits: List[str] = []
                    for u in qsr_urls[:50]:
                        try:
                            r = sess.get(u, timeout=self.cfg.get("timeout", 10), allow_redirects=True)
                            if "evil.com" in r.url:
                                hits.append(f"[OPEN REDIRECT] {u}")
                                self.db.add_finding(self.domain, "redirect", "medium", "Open Redirect", u, "")
                        except Exception:
                            pass
                    if hits:
                        self.fm.write("nuclei", "redirect_manual.txt", hits)
        out = self.fm.path("nuclei", "redirect.txt")
        src = self._params_file() or self._live_file()
        if not src:
            return len(gf_urls)
        cmd = [
            "nuclei", "-silent",
            "-l",        str(src),
            "-tags",     "redirect,open-redirect",
            "-severity", "high,medium",
            "-o",        str(out),
            "-rl",       "250",
            "-dast",
        ]
        tdir = self._tdir()
        if tdir:
            cmd += ["-t", tdir]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            return len(gf_urls)
        results = self.fm.read("nuclei", "redirect.txt")
        for v in results:
            um = re.search(r'https?://\S+', v)
            self.db.add_finding(self.domain, "redirect", "medium", "Open Redirect",
                                um.group(0) if um else "", v)
        return len(results)

    def corsy(self) -> int:
        urls  = self.fm.read("live", "live_urls.txt") or self.fm.read("live", "live_hosts_clean.txt")
        if not urls:
            return 0
        ifile = self.fm.path("live", "cors_input.txt")
        self.fm.write("live", "cors_input.txt", urls[:50])
        scripts = [self.TOOLS_BASE / "Corsy" / "corsy.py", Path("corsy.py")]
        sc      = next((str(p) for p in scripts if p.exists()), None)
        if sc:
            cmd = [sys.executable, sc, "-i", str(ifile), "-t", "10",
                   "--headers", "Origin: https://evil.com"]
            rc, stdout, _ = self.r.run(cmd, timeout=300)
            if rc == -2:
                return self.nuclei(tags=["cors"], severity="high,medium", src=ifile)
            if stdout:
                self.fm.write("nuclei", "corsy.txt", stdout.splitlines())
                vulns = [l for l in stdout.splitlines() if "vulnerable" in l.lower() or "CORS" in l]
                for v in vulns:
                    self.db.add_finding(self.domain, "corsy", "medium", "CORS Misconfiguration", "", v)
                return len(vulns)
            return 0
        return self.nuclei(tags=["cors"], severity="high,medium", src=ifile)

    def crlfuzz(self) -> int:
        src = self._live_file()
        if not src:
            return 0
        out = self.fm.path("nuclei", "crlfuzz.txt")
        cmd = ["crlfuzz", "-l", str(src), "-o", str(out), "-s",
               "-t", str(min(self.cfg.get("threads", 50), 50))]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            return self.nuclei(tags=["crlf"], severity="high,medium")
        results = self.fm.read("nuclei", "crlfuzz.txt")
        for v in results:
            self.db.add_finding(self.domain, "crlfuzz", "medium", "CRLF Injection", v, "")
        return len(results)

    def subzy(self) -> int:
        for name in ["passive.txt", "subfinder.txt"]:
            if self.fm.exists("subdomains", name):
                src = self.fm.path("subdomains", name)
                break
        else:
            return 0
        out = self.fm.path("nuclei", "subzy.txt")
        cmd = ["subzy", "run", "--targets", str(src), "--output", str(out),
               "--hide_fails", "--concurrency", str(min(self.cfg.get("threads", 50), 50))]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            return self.nuclei(tags=["takeover"], severity="critical,high")
        results = self.fm.read("nuclei", "subzy.txt")
        for v in results:
            self.db.add_finding(self.domain, "subzy", "high", "Subdomain Takeover", v, "")
        return len(results)

    def jwt_audit(self, target_url: Optional[str] = None) -> int:
        url = target_url or self._first_live()
        n   = self.nuclei(tags=["jwt"], severity="critical,high,medium", src=self._live_file())
        scripts = [self.TOOLS_BASE / "jwt-tool" / "jwt_tool.py", Path("jwt_tool.py")]
        sc      = next((str(p) for p in scripts if p.exists()), None)
        if sc:
            cmd2 = [sys.executable, sc, "-t", url, "-M", "at", "-np"]
            rc2, stdout2, _ = self.r.run(cmd2, timeout=120, retries=0)
            if rc2 != -2 and stdout2:
                hits = [l for l in stdout2.splitlines()
                        if any(k in l for k in ["Found", "Cracked", "Vulnerable", "alg:none", "weak"])]
                if hits:
                    self.fm.write("nuclei", "jwt.txt", hits)
                    for h in hits:
                        self.db.add_finding(self.domain, "jwt", "high", "JWT Vulnerability", url, h)
                    n += len(hits)
        return n

    def graphql_probe(self) -> int:
        live  = self.fm.read("live", "live_urls.txt") or self.fm.read("live", "live_hosts_clean.txt")
        found: List[str] = []
        paths = [
            "/graphql", "/api/graphql", "/gql", "/query",
            "/graphiql", "/playground", "/api/v1/graphql", "/v1/graphql",
            "/api/v2/graphql", "/graphql/console", "/graphql/playground",
        ]
        sess = requests.Session()
        sess.headers["User-Agent"] = self.cfg.get("user_agent", "Mozilla/5.0")
        if self.cfg.proxy_dict:
            sess.proxies = self.cfg.proxy_dict
        for base in live[:30]:
            for path in paths:
                url = base.rstrip("/") + path
                try:
                    r = sess.post(url, json={"query": "{ __typename }"},
                                  timeout=self.cfg.get("timeout", 10), verify=False)
                    if r.status_code == 200 and "__typename" in r.text:
                        found.append(f"[INTROSPECTION] {url}")
                        self.db.add_finding(self.domain, "graphql", "medium", "GraphQL Introspection", url, r.text[:200])
                    elif r.status_code in (200, 400, 422) and any(k in r.text.lower() for k in ["graphql", "query", "mutation"]):
                        found.append(f"[ENDPOINT] {url}")
                except Exception:
                    pass
        if found:
            self.fm.write("nuclei", "graphql.txt", found)
        return len(found)


class Reporter:
    def __init__(self, domain: str, fm: FileManager, db: Database):
        self.domain = domain
        self.fm     = fm
        self.db     = db

    def json_export(self) -> Path:
        findings = self.db.get_findings(self.domain)
        data = {
            "tool":      "LostFuzzer",
            "version":   VERSION,
            "domain":    self.domain,
            "generated": datetime.now().isoformat(),
            "stats": {
                "subdomains":  self.fm.count("subdomains", "passive.txt") or self.fm.count("subdomains", "subfinder.txt"),
                "validated":   self.fm.count("subdomains", "validated.txt"),
                "live_hosts":  self.fm.count("live", "live_hosts_clean.txt"),
                "live_urls":   self.fm.count("live", "live_urls.txt"),
                "total_urls":  self.fm.count("urls", "all_urls.txt"),
                "param_urls":  self.fm.count("params", "all_params.txt"),
                "js_files":    self.fm.count("js", "js_urls.txt"),
                "open_ports":  self.fm.count("ports", "naabu.txt"),
                "endpoints":   self.fm.count("endpoints", "merged_endpoints.txt"),
                "secrets":     self.fm.count("secrets", "secretfinder.txt") + self.fm.count("secrets", "trufflehog.txt"),
                "findings":    len(findings),
            },
            "findings": findings,
        }
        out = self.fm.path("reports", "report.json")
        out.write_text(json.dumps(data, indent=2))
        return out

    def csv_export(self) -> Path:
        findings = self.db.get_findings(self.domain)
        out      = self.fm.path("reports", "findings.csv")
        with open(out, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["domain", "severity", "module", "title", "url", "detail", "created_at"])
            writer.writeheader()
            for fnd in findings:
                writer.writerow({
                    "domain":     self.domain,
                    "severity":   fnd["severity"],
                    "module":     fnd["module"],
                    "title":      fnd["title"],
                    "url":        fnd["url"],
                    "detail":     fnd["detail"][:200],
                    "created_at": fnd["created_at"],
                })
        return out

    def html_report(self) -> Path:
        findings  = self.db.get_findings(self.domain)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings  = sorted(findings, key=lambda f: sev_order.get(f["severity"].lower(), 5))
        sev_colors = {"critical": "#ff2d55", "high": "#ff6b35", "medium": "#ffd60a", "low": "#34c759", "info": "#3a3a3c"}

        stats = {
            "Subdomains":  self.fm.count("subdomains", "passive.txt") or self.fm.count("subdomains", "subfinder.txt"),
            "Validated":   self.fm.count("subdomains", "validated.txt"),
            "Live Hosts":  self.fm.count("live", "live_hosts_clean.txt"),
            "Live URLs":   self.fm.count("live", "live_urls.txt"),
            "All URLs":    self.fm.count("urls", "all_urls.txt"),
            "Param URLs":  self.fm.count("params", "all_params.txt"),
            "JS Files":    self.fm.count("js", "js_urls.txt"),
            "Open Ports":  self.fm.count("ports", "naabu.txt"),
            "Endpoints":   self.fm.count("endpoints", "merged_endpoints.txt"),
            "Secrets":     self.fm.count("secrets", "secretfinder.txt") + self.fm.count("secrets", "trufflehog.txt"),
            "Findings":    len(findings),
        }

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev_counts[f["severity"].lower()] = sev_counts.get(f["severity"].lower(), 0) + 1

        rows = ""
        for f in findings:
            c = sev_colors.get(f["severity"].lower(), "#3a3a3c")
            rows += (f'<tr><td><span class="badge" style="background:{c}">'
                     f'{f["severity"].upper()}</span></td>'
                     f'<td>{f["module"]}</td><td>{f["title"]}</td>'
                     f'<td class="url" title="{f["url"]}">{f["url"][:70]}</td>'
                     f'<td class="ts">{f["created_at"][:19]}</td></tr>')

        stat_html = "".join(
            f'<div class="stat"><div class="sv">{v}</div><div class="sl">{k}</div></div>'
            for k, v in stats.items()
        )

        chart_bars = ""
        for sev, count in sev_counts.items():
            color = sev_colors.get(sev, "#3a3a3c")
            pct   = min(100, count * 20) if count > 0 else 0
            chart_bars += (f'<div class="bar-row"><div class="bar-label">{sev.upper()}</div>'
                           f'<div class="bar-wrap"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>'
                           f'<div class="bar-count">{count}</div></div>')

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LostFuzzer — {self.domain}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter','SF Pro Display',system-ui,-apple-system,sans-serif;background:#060609;color:#d4d4d8;min-height:100vh;font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased}}
.hdr{{padding:42px 56px 30px;border-bottom:1px solid #1a1a22;background:linear-gradient(180deg,rgba(15,15,20,.95),rgba(8,8,12,.98))}}
.hdr h1{{font-size:22px;font-weight:800;background:linear-gradient(135deg,#dc2626,#7c3aed 50%,#2563eb);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-.02em;margin-bottom:6px}}
.hdr .sub{{font-size:10px;color:#5a5a6e;letter-spacing:.06em;text-transform:uppercase;font-weight:500}}
.stats{{display:flex;gap:1px;background:#1a1a22;border-bottom:1px solid #1a1a22;flex-wrap:wrap}}
.stat{{flex:1;min-width:100px;background:#0c0c12;padding:18px 22px;transition:all .15s ease}}
.stat:hover{{background:#12121a}}
.sv{{font-size:24px;font-weight:800;color:#fff;font-variant-numeric:tabular-nums;letter-spacing:-.02em}}
.sl{{font-size:8px;color:#4a4a5a;margin-top:4px;letter-spacing:.1em;text-transform:uppercase;font-weight:700}}
.two-col{{display:flex;gap:1px;background:#1a1a22}}
.sec{{padding:28px 56px;background:#060609}}
.sec h2{{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#4a4a5a;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #1a1a22;font-weight:700}}
table{{width:100%;border-collapse:collapse;background:#0c0c12;border:1px solid #1a1a22;border-radius:8px;overflow:hidden}}
th{{text-align:left;padding:10px 14px;font-size:8.5px;letter-spacing:.1em;text-transform:uppercase;color:#3a3a4a;border-bottom:1px solid #1a1a22;background:#0f0f16;font-weight:700}}
td{{padding:12px 14px;border-bottom:1px solid #101016;vertical-align:middle;font-size:11px}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#12121c}}
.badge{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:8px;font-weight:800;letter-spacing:.06em;color:#000}}
.url{{color:#5a5a6e;font-size:10px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:'JetBrains Mono',monospace}}
.ts{{color:#3a3a44;font-size:9px;white-space:nowrap;font-variant-numeric:tabular-nums;font-family:'JetBrains Mono',monospace}}
.chart-sec{{flex:0 0 300px;padding:28px 32px;background:#060609;border-left:1px solid #1a1a22}}
.bar-row{{display:flex;align-items:center;gap:10px;margin-bottom:10px}}
.bar-label{{font-size:8.5px;letter-spacing:.08em;text-transform:uppercase;color:#5a5a6e;width:56px;font-weight:700}}
.bar-wrap{{flex:1;background:#1a1a22;border-radius:2px;height:6px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:2px;transition:width .3s}}
.bar-count{{font-size:10px;color:#d4d4d8;font-variant-numeric:tabular-nums;width:24px;text-align:right;font-weight:700}}
.ftr{{padding:18px 56px;border-top:1px solid #1a1a22;font-size:9px;color:#3a3a44;letter-spacing:.06em;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;background:#08080c}}
.ftr span{{color:#5a5a6e}}
.none{{color:#3a3a44;font-size:12px;padding:20px 0;text-align:center;font-style:italic}}
@media(max-width:768px){{.hdr{{padding:28px 24px 22px}}.sec{{padding:24px}}.ftr{{padding:14px 24px;flex-direction:column}}.stat{{min-width:80px}}.two-col{{flex-direction:column}}}}
</style></head><body>
<div class="hdr">
<h1>LOSTFUZZER — {self.domain}</h1>
<div class="sub">Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;·&nbsp; @{AUTHOR} &nbsp;·&nbsp; v{VERSION} &nbsp;·&nbsp; TLP:AMBER</div>
</div>
<div class="stats">{stat_html}</div>
<div class="two-col">
<div class="sec" style="flex:1">
<h2>Vulnerability Findings</h2>
{'<table><thead><tr><th>Sev</th><th>Module</th><th>Title</th><th>URL</th><th>Time</th></tr></thead><tbody>'+rows+'</tbody></table>' if findings else '<p class="none">No findings recorded.</p>'}
</div>
<div class="chart-sec">
<h2 style="font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#4a4a5a;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #1a1a22;font-weight:700">Severity Chart</h2>
{chart_bars}
</div>
</div>
<div class="ftr">
<span>LostFuzzer v{VERSION} &nbsp;·&nbsp; {GITHUB}</span>
<span>Confidential &nbsp;·&nbsp; Authorized Testing Only</span>
</div>
</body></html>"""
        out = self.fm.path("reports", "report.html")
        out.write_text(html)
        return out


class Notifier:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def _ok(self) -> bool:
        return bool(self.cfg.get("notify_telegram") and
                    self.cfg.get("telegram_token") and
                    self.cfg.get("telegram_chatid"))

    def send(self, text: str) -> bool:
        if not self._ok():
            return False
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{self.cfg.get('telegram_token')}/sendMessage",
                json={"chat_id": self.cfg.get("telegram_chatid"), "text": text, "parse_mode": "Markdown"},
                timeout=15, proxies=self.cfg.proxy_dict,
            )
            return r.status_code == 200
        except Exception:
            return False

    def scan_start(self, domain: str, module: str):
        self.send(f"🔍 *LostFuzzer v{VERSION}* started\nTarget: `{domain}`\nModule: `{module}`")

    def scan_done(self, domain: str, stats: Dict):
        body = [f"✅ *LostFuzzer* complete\nTarget: `{domain}`"]
        body += [f"  {k}: `{v}`" for k, v in stats.items()]
        self.send("\n".join(body))

    def vuln_alert(self, domain: str, sev: str, title: str, url: str):
        e = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev.lower(), "⚪")
        self.send(f"{e} *{sev.upper()}*\nTarget: `{domain}`\n`{title}`\n{url}")


class Pipeline:
    def __init__(self, domain: str, targets: List[str], cfg: Config, db: Database):
        self.domain   = domain
        self.targets  = targets
        self.cfg      = cfg
        self.db       = db
        self.fm       = FileManager(domain)
        self.runner   = Runner(cfg)
        self.passive  = PassiveEnum(domain, targets, self.fm, self.runner, db)
        self.dns      = DNSValidator(domain, self.fm, self.runner, db)
        self.ports    = PortScanner(domain, self.fm, self.runner, db)
        self.collector = URLCollector(domain, targets, self.fm, self.runner, db)
        self.params   = ParamDiscovery(domain, self.fm, self.runner, db)
        self.js       = JSAnalyzer(domain, self.fm, self.runner, db)
        self.content  = ContentDiscovery(domain, self.fm, self.runner, db)
        self.vuln     = VulnScanner(domain, self.fm, self.runner, db)
        self.reporter = Reporter(domain, self.fm, db)
        self.notifier = Notifier(cfg)

    def _done(self, mod: str) -> bool:
        return self.db.get_scan_status(self.domain, mod) == "done"

    def full_auto(self, resume: bool = True) -> Dict:
        self.notifier.scan_start(self.domain, "full_auto")

        UI.phase_header("PHASE 1", "Passive Enumeration", "color(196)")

        UI.tool_start("Subfinder")
        n = self.passive.subfinder()
        if n > 0:
            UI.show_lines(self.fm.read("subdomains", "subfinder.txt"))
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} subdomains" if n >= 0 else "not installed")

        UI.tool_start("Amass")
        n = self.passive.amass()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} subdomains" if n >= 0 else "not installed")

        UI.tool_start("Assetfinder")
        n = self.passive.assetfinder()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("Findomain")
        n = self.passive.findomain()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("crt.sh")
        n = self.passive.crtsh()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "failed")

        UI.tool_start("Merge Passive")
        n = self.passive.merge_passive()
        UI.tool_done("ok", f"{n} unique subdomains")

        UI.phase_header("PHASE 2", "DNS Validation", "color(93)")

        UI.tool_start("DNSx")
        n = self.dns.dnsx()
        if n > 0:
            UI.show_lines(self.fm.read("subdomains", "dnsx_clean.txt"))
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} resolved" if n >= 0 else "not installed")

        UI.tool_start("ShuffleDNS")
        n = self.dns.shuffledns()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed / no resolvers")

        UI.tool_start("PureDNS")
        n = self.dns.puredns()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed / no resolvers")

        UI.tool_start("Merge Validated")
        n = self.dns.merge_validated()
        UI.tool_done("ok", f"{n} validated hosts")

        UI.phase_header("PHASE 3", "Port & Service Discovery", "color(128)")

        UI.tool_start("Naabu")
        n = self.ports.naabu()
        if n > 0:
            UI.show_lines(self.fm.read("ports", "naabu.txt"))
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} open ports" if n >= 0 else "not installed")

        UI.tool_start("RustScan")
        n = self.ports.rustscan()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("Merge Ports")
        n = self.ports.merge_ports()
        UI.tool_done("ok", f"{n} port URLs")

        UI.phase_header("PHASE 4", "HTTP Probe", "color(51)")

        UI.tool_start("HTTPX Hosts")
        n = self.dns.httpx_hosts()
        if n > 0:
            UI.show_lines(self.fm.read("live", "live_hosts_clean.txt"))
        UI.tool_done("ok" if n >= 0 else "err", f"{n} live hosts" if n >= 0 else "not installed")

        UI.tool_start("TLSx")
        n = self.dns.tlsx()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("ASNmap")
        n = self.dns.asnmap()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("CDNCheck")
        n = self.dns.cdncheck()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.phase_header("PHASE 5", "URL Collection", "color(226)")

        UI.tool_start("GAU")
        n = self.collector.gau()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} URLs" if n >= 0 else "not installed")

        UI.tool_start("Waybackurls")
        n = self.collector.waybackurls()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} URLs" if n >= 0 else "not installed")

        UI.tool_start("Katana")
        n = self.collector.katana()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} URLs" if n >= 0 else "not installed")

        UI.tool_start("Hakrawler")
        n = self.collector.hakrawler()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} URLs" if n >= 0 else "not installed")

        UI.tool_start("GoSpider")
        n = self.collector.gospider()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} URLs" if n >= 0 else "not installed")

        UI.tool_start("Merge → URO → HTTPX")
        total, params, js_c = self.collector.merge_and_filter()
        n = self.dns.httpx_probe_urls(self.fm.path("urls", "all_urls.txt"))
        UI.tool_done("ok", f"{total} unique · {n} live · {params} injectable · {js_c} JS")

        UI.phase_header("PHASE 6", "Parameter Discovery", "color(203)")

        UI.tool_start("ParamSpider")
        n = self.params.paramspider()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("Arjun")
        n = self.params.arjun()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("GF Params")
        n = self.params.gf_params()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("Merge Params")
        n = self.params.merge_params()
        UI.tool_done("ok", f"{n} injectable params")

        UI.phase_header("PHASE 7", "JavaScript Analysis", "color(141)")

        UI.tool_start("JS Discovery")
        n = self.js.js_discovery()
        if n > 0:
            UI.show_lines(self.fm.read("js", "js_urls.txt"))
        UI.tool_done("ok", f"{n} JS files")

        UI.tool_start("SecretFinder")
        n = self.js.secretfinder()
        if n > 0:
            UI.show_lines(self.fm.read("secrets", "secretfinder.txt"))
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} secrets" if n >= 0 else "not installed")

        UI.tool_start("TruffleHog")
        n = self.js.trufflehog()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} leaks" if n >= 0 else "not installed")

        UI.tool_start("Mantra")
        n = self.js.mantra()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("Cariddi")
        n = self.js.cariddi()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.phase_header("PHASE 8", "Content Discovery", "color(39)")

        wl = self.content._wordlist()
        if wl:
            UI.info(f"Wordlist → {wl}")
        else:
            UI.warn("No wordlist found — ffuf/feroxbuster will be skipped")

        UI.tool_start("Feroxbuster")
        n = self.content.feroxbuster()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} endpoints" if n >= 0 else "not installed" if n == -2 else "no wordlist")

        UI.tool_start("FFuf")
        n = self.content.ffuf()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} hits" if n >= 0 else "no wordlist")

        UI.tool_start("Dirsearch")
        n = self.content.dirsearch()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} paths" if n >= 0 else "not installed")

        UI.tool_start("Merge Endpoints → HTTPX")
        ep_count = self.content.merge_endpoint_urls()
        if ep_count > 0:
            n = self.dns.httpx_probe_urls(self.fm.path("endpoints", "merged_endpoints.txt"))
            UI.tool_done("ok", f"{ep_count} endpoints · {n} live")
        else:
            UI.tool_done("skip", "no endpoints found")

        UI.phase_header("PHASE 9", "Vulnerability Scanning", "color(196)")

        param_count = self.fm.count("params", "all_params.txt") or self.fm.count("urls", "param_urls.txt")
        UI.info(f"Live URLs: {self.fm.count('live', 'live_urls.txt')}  ·  Param URLs: {param_count}")

        UI.tool_start("GF XSS → KXSS")
        n = self.vuln.xss_pipeline()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} reflections" if n >= 0 else "not installed")

        UI.tool_start("Dalfox")
        n = self.vuln.dalfox()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} XSS" if n >= 0 else "not installed")

        UI.tool_start("GF SQLi → SQLMap")
        n = self.vuln.sqlmap()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} injectable" if n >= 0 else "not installed")

        UI.tool_start("CORS")
        n = self.vuln.corsy()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("CRLF")
        n = self.vuln.crlfuzz()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("Subdomain Takeover")
        n = self.vuln.subzy()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("LFI")
        n = self.vuln.lfi_scan()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("GF Redirect → Open Redirect")
        n = self.vuln.redirect_scan()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("SSRF")
        n = self.vuln.ssrf_scan()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

        UI.tool_start("Nuclei")
        n = self.vuln.nuclei()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} findings" if n >= 0 else "not installed")

        UI.tool_start("Nuclei DAST")
        n = self.vuln.nuclei(dast=True)
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} dast findings" if n >= 0 else "not installed")

        UI.phase_header("PHASE 10", "Reporting & Output", "color(141)")

        UI.tool_start("HTML Report")
        html_p = self.reporter.html_report()
        UI.tool_done("ok", str(html_p))

        UI.tool_start("JSON Export")
        json_p = self.reporter.json_export()
        UI.tool_done("ok", str(json_p))

        UI.tool_start("CSV Export")
        csv_p = self.reporter.csv_export()
        UI.tool_done("ok", str(csv_p))

        UI.tool_start("Gowitness")
        n = self.js.gowitness()
        UI.tool_done("ok" if n >= 0 else "skip", f"{n} screenshots" if n >= 0 else "not installed")

        findings = self.db.get_findings(self.domain)
        stats    = {
            "Subdomains":  self.fm.count("subdomains", "passive.txt") or self.fm.count("subdomains", "subfinder.txt"),
            "Validated":   self.fm.count("subdomains", "validated.txt"),
            "Live Hosts":  self.fm.count("live", "live_hosts_clean.txt"),
            "Live URLs":   self.fm.count("live", "live_urls.txt"),
            "Param URLs":  self.fm.count("params", "all_params.txt"),
            "Endpoints":   self.fm.count("endpoints", "merged_endpoints.txt"),
            "Findings":    len(findings),
        }

        UI.tool_start("Telegram Notify")
        self.notifier.scan_done(self.domain, stats)
        UI.tool_done("ok" if self.cfg.get("notify_telegram") else "skip",
                     "sent" if self.cfg.get("notify_telegram") else "not configured")

        return stats


def parse_target(raw: str) -> Tuple[str, List[str]]:
    raw = raw.strip()
    if os.path.isfile(raw):
        lines = [l.strip() for l in Path(raw).read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
        lines = [re.sub(r"https?://", "", l).split("/")[0].strip() for l in lines]
        lines = list(dict.fromkeys(l for l in lines if l))
        return (lines[0] if lines else raw), lines
    domain = re.sub(r"https?://", "", raw).split("/")[0].split(":")[0].strip()
    return domain, [domain]


class LostFuzzer:
    def __init__(self):
        self.cfg     = Config()
        self.db      = Database()
        self.domain  = ""
        self.targets: List[str] = []
        RESULTS_DIR.mkdir(exist_ok=True)
        signal.signal(signal.SIGINT, self._sigint)

    def _sigint(self, *_):
        console.print()
        UI.warn("Interrupted.")
        self.db.close()
        sys.exit(0)

    def _pipe(self) -> Pipeline:
        return Pipeline(self.domain, self.targets, self.cfg, self.db)

    def _set_target(self):
        console.print()
        raw = UI.ask("Target  (domain / domain.txt / https://domain)")
        if not raw:
            return
        self.domain, self.targets = parse_target(raw)
        UI.ok(f"Target set  →  {self.domain}  ({len(self.targets)} domain{'s' if len(self.targets) > 1 else ''})")
        time.sleep(0.5)

    def _need_target(self) -> bool:
        if not self.domain:
            UI.section("SET TARGET", "color(93)")
            self._set_target()
        return bool(self.domain)

    def _show_findings(self):
        UI.print_findings(self.domain, self.db)

    def _show_params(self, p: Pipeline):
        params = p.vuln.show_param_urls()
        if params:
            console.print()
            UI.hsep("INJECTABLE PARAM URLs", "color(203)")
            console.print()
            for u in params[:30]:
                high = re.sub(INJECTABLE_PARAMS, lambda m: f"[high]{m.group(0)}[/high]", u)
                console.print(f"  [path]→[/path]  [dim]{high}[/dim]")
            if len(params) > 30:
                UI.info(f"... and {len(params) - 30} more in {p.fm.path('params', 'all_params.txt')}")
        else:
            UI.warn("No injectable param URLs found. Run menu 7 (Parameter Discovery) first.")

    def run(self):
        if len(sys.argv) > 1:
            self.domain, self.targets = parse_target(sys.argv[1])

        while True:
            try:
                opt = UI.interactive_menu(self.domain, len(self.targets))
            except KeyboardInterrupt:
                self.db.close()
                break

            if opt == 26:
                UI.clear()
                UI.ok("Exiting. Goodbye.")
                self.db.close()
                break

            if opt in range(1, 26) and opt not in (23, 24, 25):
                if not self._need_target():
                    continue

            p = self._pipe()

            if opt == 1:
                UI.banner()
                UI.section(f"SUBDOMAIN RECON  —  {self.domain}", "color(39)")

                UI.tool_start("Subfinder")
                n = p.passive.subfinder()
                if n > 0:
                    UI.show_lines(p.fm.read("subdomains", "subfinder.txt"))
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} subdomains" if n >= 0 else "not installed")

                UI.tool_start("Amass")
                n = p.passive.amass()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("Assetfinder")
                n = p.passive.assetfinder()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("Findomain")
                n = p.passive.findomain()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("crt.sh")
                n = p.passive.crtsh()
                UI.tool_done("ok", f"{n}")

                UI.tool_start("Merge Passive")
                n = p.passive.merge_passive()
                UI.tool_done("ok", f"{n} unique")

                UI.tool_start("DNSx Validate")
                n = p.dns.dnsx()
                if n > 0:
                    UI.show_lines(p.fm.read("subdomains", "dnsx_clean.txt"))
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} resolved" if n >= 0 else "not installed")

                UI.tool_start("Merge Validated")
                n = p.dns.merge_validated()
                UI.tool_done("ok", f"{n} validated")

                UI.tool_start("HTTPX Probe")
                n = p.dns.httpx_hosts()
                if n > 0:
                    UI.show_lines(p.fm.read("live", "live_hosts_clean.txt"))
                UI.tool_done("ok" if n >= 0 else "err", f"{n} live hosts" if n >= 0 else "not installed")

                console.print()
                UI.stat("Passive subdomains", p.fm.count("subdomains", "passive.txt"))
                UI.stat("Validated",          p.fm.count("subdomains", "validated.txt"))
                UI.stat("Live web hosts",     p.fm.count("live", "live_hosts_clean.txt"))
                UI.stat("Results path",       str(p.fm.dirs["subdomains"]))
                UI.pause()

            elif opt == 2:
                UI.banner()
                UI.section(f"DEEP RECON  —  {self.domain}", "color(39)")

                for label, fn, read_cat, read_name in [
                    ("Subfinder",    p.passive.subfinder,  "subdomains", "subfinder.txt"),
                    ("Amass",        p.passive.amass,       "subdomains", "amass.txt"),
                    ("Assetfinder",  p.passive.assetfinder, "subdomains", "assetfinder.txt"),
                    ("Findomain",    p.passive.findomain,   "subdomains", "findomain.txt"),
                ]:
                    UI.tool_start(label)
                    n = fn()
                    if n > 0:
                        UI.show_lines(p.fm.read(read_cat, read_name))
                    UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("crt.sh")
                n = p.passive.crtsh()
                UI.tool_done("ok", f"{n}")

                UI.tool_start("Merge Passive")
                n = p.passive.merge_passive()
                UI.tool_done("ok", f"{n} unique")

                UI.tool_start("DNSx")
                n = p.dns.dnsx()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("Naabu")
                n = p.ports.naabu()
                if n > 0:
                    UI.show_lines(p.fm.read("ports", "naabu.txt"))
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} open ports" if n >= 0 else "not installed")

                UI.tool_start("HTTPX")
                n = p.dns.httpx_hosts()
                if n > 0:
                    UI.show_lines(p.fm.read("live", "live_hosts_clean.txt"))
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} live" if n >= 0 else "not installed")

                UI.tool_start("TLSx")
                n = p.dns.tlsx()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("ASNmap")
                n = p.dns.asnmap()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("CDNCheck")
                n = p.dns.cdncheck()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                console.print()
                UI.stat("Subdomains",   p.fm.count("subdomains", "passive.txt"))
                UI.stat("Validated",    p.fm.count("subdomains", "validated.txt"))
                UI.stat("Live Hosts",   p.fm.count("live", "live_hosts_clean.txt"))
                UI.stat("Open Ports",   p.fm.count("ports", "naabu.txt"))
                UI.pause()

            elif opt == 3:
                UI.banner()
                UI.section(f"PORT SCAN  —  {self.domain}", "color(39)")

                UI.tool_start("Naabu")
                n = p.ports.naabu()
                if n > 0:
                    UI.show_lines(p.fm.read("ports", "naabu.txt"))
                UI.tool_done("ok" if n >= 0 else "err", f"{n} open ports" if n >= 0 else "not installed")

                UI.tool_start("RustScan")
                n = p.ports.rustscan()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("Nmap Fingerprint")
                n = p.ports.nmap_fingerprint()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                console.print()
                UI.stat("Naabu results",    p.fm.count("ports", "naabu.txt"))
                UI.stat("Port URLs",        p.fm.count("ports", "port_urls.txt"))
                UI.pause()

            elif opt == 4:
                UI.banner()
                UI.section(f"URL HARVEST  —  {self.domain}", "color(51)")

                UI.tool_start("GAU")
                n = p.collector.gau()
                UI.tool_done("ok" if n >= 0 else "err", f"{n} URLs" if n >= 0 else "not installed")

                UI.tool_start("Waybackurls")
                n = p.collector.waybackurls()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} URLs" if n >= 0 else "not installed")

                UI.tool_start("Katana")
                n = p.collector.katana()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} URLs" if n >= 0 else "not installed")

                UI.tool_start("Hakrawler")
                n = p.collector.hakrawler()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("GoSpider")
                n = p.collector.gospider()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("Merge → URO")
                total, params, js_c = p.collector.merge_and_filter()
                UI.tool_done("ok", f"{total} unique · {params} injectable · {js_c} JS")

                UI.tool_start("HTTPX Probe")
                n = p.dns.httpx_probe_urls(p.fm.path("urls", "all_urls.txt"))
                UI.tool_done("ok" if n >= 0 else "err", f"{n} live URLs" if n >= 0 else "not installed")

                console.print()
                UI.stat("Total URLs",  p.fm.count("urls", "all_urls.txt"))
                UI.stat("Live URLs",   p.fm.count("live", "live_urls.txt"))
                UI.stat("Param URLs",  p.fm.count("urls", "param_urls.txt"))
                UI.stat("JS Files",    p.fm.count("js", "js_urls.txt"))
                UI.pause()

            elif opt == 5:
                UI.banner()
                UI.section(f"HISTORICAL URLs  —  {self.domain}", "color(51)")

                UI.tool_start("GAU")
                n = p.collector.gau()
                UI.tool_done("ok" if n >= 0 else "err", f"{n} URLs" if n >= 0 else "not installed")

                UI.tool_start("Waybackurls")
                n = p.collector.waybackurls()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} URLs" if n >= 0 else "not installed")

                UI.tool_start("Merge → URO")
                total, params, js_c = p.collector.merge_and_filter()
                UI.tool_done("ok", f"{total} unique")

                UI.tool_start("HTTPX Probe")
                n = p.dns.httpx_probe_urls(p.fm.path("urls", "all_urls.txt"))
                UI.tool_done("ok" if n >= 0 else "err", f"{n} live" if n >= 0 else "not installed")

                console.print()
                UI.stat("Total collected", p.fm.count("urls", "all_urls.txt"))
                UI.stat("Live",            p.fm.count("live", "live_urls.txt"))
                UI.stat("Param URLs",      p.fm.count("urls", "param_urls.txt"))
                UI.pause()

            elif opt == 6:
                UI.banner()
                UI.section(f"CRAWL & PROBE  —  {self.domain}", "color(51)")

                UI.tool_start("Katana")
                n = p.collector.katana()
                UI.tool_done("ok" if n >= 0 else "err", f"{n} URLs" if n >= 0 else "not installed")

                UI.tool_start("Hakrawler")
                n = p.collector.hakrawler()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("GoSpider")
                n = p.collector.gospider()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("xnLinkFinder")
                n = p.collector.xnlinkfinder()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} links" if n >= 0 else "not installed")

                UI.tool_start("Merge → URO")
                total, params, js_c = p.collector.merge_and_filter()
                UI.tool_done("ok", f"{total} URLs")

                UI.tool_start("HTTPX Probe")
                n = p.dns.httpx_probe_urls(p.fm.path("urls", "all_urls.txt"))
                UI.tool_done("ok" if n >= 0 else "err", f"{n} live" if n >= 0 else "failed")

                console.print()
                UI.stat("Live URLs",  p.fm.count("live", "live_urls.txt"))
                UI.stat("Param URLs", p.fm.count("urls", "param_urls.txt"))
                UI.pause()

            elif opt == 7:
                UI.banner()
                UI.section(f"PARAMETER DISCOVERY  —  {self.domain}", "color(51)")

                UI.tool_start("ParamSpider")
                n = p.params.paramspider()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("Arjun")
                n = p.params.arjun()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("GF Params")
                n = p.params.gf_params()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("Merge Params")
                n = p.params.merge_params()
                UI.tool_done("ok", f"{n} total params")

                self._show_params(p)
                UI.pause()

            elif opt == 8:
                UI.banner()
                UI.section(f"JS DISCOVERY  —  {self.domain}", "color(51)")

                UI.tool_start("xnLinkFinder")
                n = p.collector.xnlinkfinder()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} links" if n >= 0 else "not installed")

                UI.tool_start("Cariddi")
                n = p.js.cariddi()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("JS Extract")
                n = p.js.js_discovery()
                if n > 0:
                    UI.show_lines(p.fm.read("js", "js_urls.txt"))
                UI.tool_done("ok", f"{n} JS files")

                UI.tool_start("Mantra")
                n = p.js.mantra()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.pause()

            elif opt == 9:
                UI.banner()
                UI.section(f"HIDDEN ENDPOINTS  —  {self.domain}", "color(51)")

                wl = p.content._wordlist()
                if wl:
                    UI.info(f"Wordlist → {wl}")
                else:
                    UI.warn("No wordlist found — install seclists or set wordlist in config.yaml")

                UI.tool_start("Feroxbuster")
                n = p.content.feroxbuster()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} endpoints" if n >= 0 else "not installed" if n == -2 else "no wordlist")

                UI.tool_start("FFuf")
                n = p.content.ffuf()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} hits" if n >= 0 else "no wordlist")

                UI.tool_start("Dirsearch")
                n = p.content.dirsearch()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} paths" if n >= 0 else "not installed")

                UI.tool_start("Merge → URO → HTTPX")
                ep_count = p.content.merge_endpoint_urls()
                if ep_count > 0:
                    n = p.dns.httpx_probe_urls(p.fm.path("endpoints", "merged_endpoints.txt"))
                    UI.tool_done("ok", f"{ep_count} endpoints · {n} live")
                else:
                    UI.tool_done("skip", "no endpoints")

                console.print()
                UI.stat("Feroxbuster", p.fm.count("endpoints", "feroxbuster.txt"))
                UI.stat("FFuf hits",   p.fm.count("endpoints", "ffuf_all.txt"))
                UI.stat("Dirsearch",   p.fm.count("endpoints", "dirsearch.txt"))
                UI.pause()

            elif opt == 10:
                UI.banner()
                UI.section(f"SECRET HUNT  —  {self.domain}", "color(226)")

                UI.tool_start("JS Discovery")
                n = p.js.js_discovery()
                UI.tool_done("ok", f"{n} JS files")

                UI.tool_start("SecretFinder")
                n = p.js.secretfinder()
                if n > 0:
                    UI.show_lines(p.fm.read("secrets", "secretfinder.txt"))
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("TruffleHog")
                n = p.js.trufflehog()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("Mantra")
                n = p.js.mantra()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                self._show_findings()
                UI.pause()

            elif opt == 11:
                UI.banner()
                UI.section(f"XSS  —  {self.domain}", "color(203)")
                param_count = p.fm.count("params", "all_params.txt") or p.fm.count("urls", "param_urls.txt")
                if param_count == 0:
                    UI.warn("No param URLs. Run menu 7 first for best results.")
                else:
                    UI.info(f"Param URLs available: {param_count}")

                UI.tool_start("GF XSS → KXSS")
                n = p.vuln.xss_pipeline()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} reflections" if n >= 0 else "not installed")

                UI.tool_start("Dalfox")
                n = p.vuln.dalfox()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} XSS" if n >= 0 else "not installed")

                UI.tool_start("XSStrike")
                n = p.vuln.xsstrike()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("Nuclei XSS")
                n = p.vuln.nuclei(tags=["xss"], severity="critical,high,medium")
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                self._show_findings()
                UI.pause()

            elif opt == 12:
                UI.banner()
                UI.section(f"SQLi  —  {self.domain}", "color(203)")
                self._show_params(p)
                console.print()
                manual = UI.ask("Specific URL with ?param=  (Enter to use all param URLs)")

                UI.tool_start("GF SQLi → SQLMap")
                n = p.vuln.sqlmap(target_url=manual or None)
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} vulnerable" if n >= 0 else "not installed")

                UI.tool_start("Nuclei SQLi")
                n = p.vuln.nuclei(tags=["sqli", "sql-injection"], severity="critical,high")
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                self._show_findings()
                UI.pause()

            elif opt == 13:
                UI.banner()
                UI.section(f"SSRF  —  {self.domain}", "color(203)")

                UI.tool_start("Nuclei SSRF")
                n = p.vuln.ssrf_scan()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                self._show_findings()
                UI.pause()

            elif opt == 14:
                UI.banner()
                UI.section(f"LFI / PATH TRAVERSAL  —  {self.domain}", "color(203)")

                UI.tool_start("Nuclei LFI")
                n = p.vuln.lfi_scan()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                self._show_findings()
                UI.pause()

            elif opt == 15:
                UI.banner()
                UI.section(f"OPEN REDIRECT  —  {self.domain}", "color(203)")

                UI.tool_start("GF Redirect → qsreplace → Nuclei")
                n = p.vuln.redirect_scan()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                self._show_findings()
                UI.pause()

            elif opt == 16:
                UI.banner()
                UI.section(f"CORS  —  {self.domain}", "color(203)")

                UI.tool_start("Corsy")
                n = p.vuln.corsy()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                UI.tool_start("Nuclei CORS")
                n = p.vuln.nuclei(tags=["cors"], severity="high,medium")
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                self._show_findings()
                UI.pause()

            elif opt == 17:
                UI.banner()
                UI.section(f"SUBDOMAIN TAKEOVER  —  {self.domain}", "color(203)")

                UI.tool_start("Subzy")
                n = p.vuln.subzy()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} vulnerable" if n >= 0 else "not installed")

                UI.tool_start("Nuclei Takeover")
                n = p.vuln.nuclei(tags=["takeover"], severity="critical,high")
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                self._show_findings()
                UI.pause()

            elif opt == 18:
                UI.banner()
                UI.section(f"JWT AUDIT  —  {self.domain}", "color(203)")
                manual = UI.ask("URL with JWT  (Enter for first live host)")

                UI.tool_start("JWT Tool + Nuclei")
                n = p.vuln.jwt_audit(target_url=manual or None)
                UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")

                self._show_findings()
                UI.pause()

            elif opt == 19:
                UI.banner()
                UI.section(f"GRAPHQL PROBE  —  {self.domain}", "color(203)")

                UI.tool_start("GraphQL Introspection")
                n = p.vuln.graphql_probe()
                results = p.fm.read("nuclei", "graphql.txt")
                if results:
                    UI.show_lines(results)
                UI.tool_done("ok", f"{n} endpoints found")

                self._show_findings()
                UI.pause()

            elif opt == 20:
                UI.banner()
                UI.section(f"NUCLEI FULL SCAN  —  {self.domain}", "color(203)")
                lf = p.vuln._live_file()
                if not lf:
                    UI.warn("No live URLs. Run menu 4 or 6 first.")
                else:
                    UI.info(f"Scanning {p.fm.count('live', lf.name)} URLs with all templates")

                    UI.tool_start("Nuclei")
                    n = p.vuln.nuclei()
                    UI.tool_done("ok" if n >= 0 else "err", f"{n} findings" if n >= 0 else "not installed")

                    UI.tool_start("Nuclei DAST")
                    n = p.vuln.nuclei(dast=True)
                    UI.tool_done("ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "no params")

                self._show_findings()
                UI.pause()

            elif opt == 21:
                UI.banner()
                UI.section(f"SCREENSHOT  —  {self.domain}", "color(141)")

                UI.tool_start("Gowitness")
                n = p.js.gowitness()
                UI.tool_done("ok" if n >= 0 else "skip", f"{n} screenshots" if n >= 0 else "not installed")
                if n > 0:
                    UI.info(f"Saved to: {p.fm.dirs['screenshots']}")

                UI.pause()

            elif opt == 22:
                UI.banner()
                console.print()
                UI.hsep(f"FULL AUTO SCAN  —  {self.domain}", "color(141)")
                stats = p.full_auto(resume=True)
                console.print()
                UI.hsep("SUMMARY", "color(51)")
                console.print()
                for k, v in stats.items():
                    UI.stat(k, v)
                self._show_findings()
                UI.pause()

            elif opt == 23:
                UI.banner()
                UI.section("REPORTS", "color(141)")
                if not self.domain:
                    UI.warn("No target set. Set a target first.")
                else:
                    UI.tool_start("HTML Report")
                    html_p = p.reporter.html_report()
                    UI.tool_done("ok", str(html_p))

                    UI.tool_start("JSON Export")
                    json_p = p.reporter.json_export()
                    UI.tool_done("ok", str(json_p))

                    UI.tool_start("CSV Export")
                    csv_p = p.reporter.csv_export()
                    UI.tool_done("ok", str(csv_p))

                UI.pause()

            elif opt == 24:
                UI.banner()
                UI.section("TELEGRAM NOTIFY", "color(141)")
                if self.cfg.get("notify_telegram") and self.cfg.get("telegram_token"):
                    UI.info("Already configured. Leave blank to keep.")
                token  = UI.ask("Bot token")
                chatid = UI.ask("Chat ID")
                if token:
                    self.cfg.set("telegram_token", token)
                if chatid:
                    self.cfg.set("telegram_chatid", chatid)
                if token or chatid:
                    self.cfg.set("notify_telegram", True)
                notifier = Notifier(self.cfg)
                ok = notifier.send(f"✅ LostFuzzer v{VERSION}\nTarget: `{self.domain or 'not set'}`\nBot connected.")
                UI.ok("Test message sent." if ok else "Failed — check token/chatid.")
                UI.pause()

            elif opt == 25:
                UI.banner()
                UI.section("UPDATE TOOLS", "color(141)")
                go_tools = [
                    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
                    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
                    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
                    "github.com/projectdiscovery/katana/cmd/katana@latest",
                    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                    "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
                    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
                    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
                    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
                    "github.com/lc/gau/v2/cmd/gau@latest",
                    "github.com/tomnomnom/waybackurls@latest",
                    "github.com/tomnomnom/assetfinder@latest",
                    "github.com/tomnomnom/gf@latest",
                    "github.com/ffuf/ffuf/v2@latest",
                    "github.com/sensepost/gowitness@latest",
                    "github.com/hahwul/dalfox/v2@latest",
                    "github.com/dwisiswant0/crlfuzz@latest",
                    "github.com/lukasikic/subzy@latest",
                    "github.com/trufflesecurity/trufflehog/v3@latest",
                    "github.com/hakluke/hakrawler@latest",
                    "github.com/jaeles-project/gospider@latest",
                    "github.com/edoardottt/cariddi/cmd/cariddi@latest",
                    "github.com/mr-rizwan-syed/kxss@latest",
                    "github.com/tomnomnom/qsreplace@latest",
                ]
                runner = Runner(self.cfg)
                for mod in go_tools:
                    name = mod.split("/")[-1].split("@")[0]
                    UI.tool_start(name)
                    rc, _, err = runner.run(["go", "install", mod], timeout=180, retries=0)
                    UI.tool_done("ok" if rc == 0 else "err", "" if rc == 0 else err[:40])

                UI.tool_start("nuclei-templates")
                rc, _, _ = runner.run(["nuclei", "-update-templates", "-silent"], timeout=180, retries=0)
                UI.tool_done("ok" if rc == 0 else "err")

                UI.tool_start("pip packages")
                rc, _, _ = runner.run([sys.executable, "-m", "pip", "install", "-q", "-U",
                                       "uro", "paramspider", "rich", "requests", "pyyaml"], timeout=120, retries=0)
                UI.tool_done("ok" if rc == 0 else "err")

                UI.pause()


def main():
    app = LostFuzzer()
    app.run()


if __name__ == "__main__":
    main()