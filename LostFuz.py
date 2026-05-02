#!/usr/bin/env python3

import os
import sys
import tty
import termios
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

try:
    import requests
    import urllib3
    from rich.console import Console
    from rich.text import Text
    from rich.theme import Theme
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError as e:
    print(f"[!] Missing dependency: {e}\n    pip install -r requirements.txt")
    sys.exit(1)

VERSION     = "1.0.0"
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
    "arrow":     "bold color(196)",
    "prompt":    "bold color(196)",
    "muted":     "color(238)",
    "stat_n":    "bold color(51)",
    "stat_l":    "color(240)",
    "found":     "bold color(118)",
    "notfound":  "dim color(240)",
})

console = Console(theme=THEME, highlight=False)

BANNER_LINES = [
    ("  ██╗      ██████╗ ███████╗████████╗\n", "color(196)"),
    ("  ██║     ██╔═══██╗██╔════╝╚══██╔══╝\n", "color(162)"),
    ("  ██║     ██║   ██║███████╗   ██║   \n", "color(128)"),
    ("  ██║     ██║   ██║╚════██║   ██║   \n", "color(93)"),
    ("  ███████╗╚██████╔╝███████║   ██║   \n", "color(57)"),
    ("  ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝   \n", "color(27)"),
]

MENU_ITEMS = [
    (1,  "RECON",  "cat_recon",  "Subdomain Recon",       "subfinder"),
    (2,  "RECON",  "cat_recon",  "Deep Recon",             "subfinder + naabu + tlsx + asnmap"),
    (3,  "RECON",  "cat_recon",  "Port Scan",              "naabu"),
    (4,  "CRAWL",  "cat_crawl",  "URL Harvest",            "gau + waybackurls + katana"),
    (5,  "CRAWL",  "cat_crawl",  "Historical URLs",        "gau + waybackurls"),
    (6,  "CRAWL",  "cat_crawl",  "Crawl & Probe",          "katana → httpx"),
    (7,  "CRAWL",  "cat_crawl",  "Parameter Discovery",   "paramspider + grep injectable"),
    (8,  "CRAWL",  "cat_crawl",  "JS Discovery",          "xnLinkFinder + extract"),
    (9,  "CRAWL",  "cat_crawl",  "Hidden Endpoints",      "ffuf + feroxbuster + dirsearch"),
    (10, "SECRET", "cat_sec",    "Secret Hunt",            "SecretFinder + trufflehog"),
    (11, "VULN",   "cat_vuln",   "XSS",                   "dalfox + xsstrike + nuclei"),
    (12, "VULN",   "cat_vuln",   "SQLi",                  "sqlmap -m param_urls"),
    (13, "VULN",   "cat_vuln",   "SSRF",                  "nuclei -tags ssrf -dast"),
    (14, "VULN",   "cat_vuln",   "LFI",                   "nuclei -tags lfi -dast"),
    (15, "VULN",   "cat_vuln",   "Open Redirect",         "nuclei -tags redirect -dast"),
    (16, "VULN",   "cat_vuln",   "CORS",                  "corsy + nuclei"),
    (17, "VULN",   "cat_vuln",   "Subdomain Takeover",    "subzy + nuclei"),
    (18, "VULN",   "cat_vuln",   "JWT Audit",             "jwt-tool + nuclei"),
    (19, "VULN",   "cat_vuln",   "GraphQL Probe",         "introspection + nuclei"),
    (20, "VULN",   "cat_vuln",   "Nuclei Full Scan",      "nuclei all templates"),
    (21, "OUTPUT", "cat_out",    "Screenshot",            "gowitness"),
    (22, "OUTPUT", "cat_out",    "Full Auto Scan",        "complete pipeline"),
    (23, "OUTPUT", "cat_out",    "HTML Report",           "generate report"),
    (24, "OUTPUT", "cat_out",    "Telegram Notify",       "configure bot"),
    (25, "OUTPUT", "cat_out",    "Update Tools",          "go install @latest"),
    (26, "OUTPUT", "cat_out",    "Exit",                  ""),
]

INJECTABLE_PARAMS = re.compile(
    r"[?&](id|pid|uid|nid|cid|tid|sid|eid|fid|gid|rid|vid|mid|aid|"
    r"page|pg|p|cat|category|sub|subcat|"
    r"file|filename|path|dir|folder|include|require|load|src|source|"
    r"search|q|query|keyword|kw|term|s|k|"
    r"user|username|uname|login|account|email|mail|"
    r"name|title|type|view|item|product|news|article|post|"
    r"year|month|day|date|time|"
    r"order|sort|orderby|sortby|by|"
    r"lang|language|locale|l|"
    r"cmd|exec|command|run|"
    r"url|link|href|ref|redirect|return|next|back|goto|redir|"
    r"data|input|value|val|"
    r"content|template|module|action|option|method|op|mode|"
    r"token|key|apikey|api_key|access|"
    r"callback|cb|jsonp|"
    r"image|img|photo|pic|thumb|"
    r"doc|document|read|show|fetch|preview|open|display|"
    r"body|msg|message|comment|text|desc|description|"
    r"from|to|cc|subject|"
    r"report|export|download|format|output)=",
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
}


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
            return [{"module":r[0],"severity":r[1],"title":r[2],"url":r[3],"detail":r[4],"created_at":r[5]}
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
    DIRS = ["subdomains","live","ports","urls","params","js","endpoints",
            "secrets","xss","sqli","nuclei","screenshots","reports","logs"]

    def __init__(self, domain: str):
        self.domain = domain
        self.base   = RESULTS_DIR / domain
        self.dirs   = {d: self.base / d for d in self.DIRS}
        for d in self.dirs.values():
            d.mkdir(parents=True, exist_ok=True)

    def path(self, cat: str, name: str) -> Path:
        return self.dirs[cat] / name

    def write(self, cat: str, name: str, lines: List[str]) -> Path:
        p = self.path(cat, name)
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
        t   = timeout or self.cfg.get("timeout", 15) * 20
        ret = retries if retries is not None else self.cfg.get("retries", 3)
        env_full = {**os.environ}
        if env:
            env_full.update(env)

        if stdin_file and stdin_file.exists() and stdin_data is None:
            stdin_data = stdin_file.read_text()

        for attempt in range(ret + 1):
            try:
                sout = open(stdout_file, "w") if stdout_file else subprocess.PIPE
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
                port = port.strip()
                proto = "https" if port in ("443","8443","8888") else "http"
                urls.append(f"{proto}://{host}:{port}")
            else:
                urls.append(f"http://{line}")
        return urls


def _getch() -> str:
    if not sys.stdin.isatty():
        try:
            return input().strip()
        except (EOFError, KeyboardInterrupt):
            return "q"
    fd  = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = os.read(fd, 1)
        if ch == b'\x1b':
            try:
                rest = os.read(fd, 2)
                return (ch + rest).decode("utf-8", errors="replace")
            except Exception:
                return "\x1b"
        return ch.decode("utf-8", errors="replace")
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


KEY_UP    = "\x1b[A"
KEY_DOWN  = "\x1b[B"
KEY_ENTER = "\r"
KEY_ENTER2= "\n"


class UI:
    @staticmethod
    def clear():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

    @staticmethod
    def banner():
        b = Text("\n")
        for line, color in BANNER_LINES:
            b.append(line, style=color)
        console.print(b)
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
    def status(tool: str, state: str, detail: str = ""):
        w   = 20
        tfmt = f"[accent]{tool:<{w}}[/accent]"
        tags = {
            "run":  "[run][ RUN ][/run]",
            "ok":   "[ok][ OK  ][/ok]",
            "err":  "[err][ ERR ][/err]",
            "skip": "[skip][SKIP][/skip]",
            "done": "[ok][DONE][/ok]",
        }
        tag = tags.get(state, f"[dim][{state[:4].upper():^4}][/dim]")
        d   = f"  [dim]{detail}[/dim]" if detail else ""
        console.print(f"  {tfmt}  {tag}{d}")

    @staticmethod
    def stat(label: str, value: Any):
        vstr = str(value)
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
        console.print(f"  [label]{label}[/label]  [prompt]❯[/prompt] ", end="")
        sys.stdout.flush()
        try:
            if not sys.stdin.isatty():
                return input().strip()
            fd  = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            tty.setcbreak(fd)
            return input().strip()
        except (EOFError, KeyboardInterrupt):
            return ""

    @staticmethod
    def pause():
        console.print()
        console.print("  [muted]↵ back to menu[/muted]", end="")
        sys.stdout.flush()
        try:
            if sys.stdin.isatty():
                fd  = sys.stdin.fileno()
                old = termios.tcgetattr(fd)
                try:
                    tty.setraw(fd)
                    os.read(fd, 1)
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
            else:
                input()
        except Exception:
            pass

    @staticmethod
    def render_menu(target: str, domain_count: int, sel: int, num_buf: str):
        UI.clear()
        UI.banner()
        console.print()

        cats_seen: Dict[str, bool] = {}
        cat_colors = {
            "RECON":  "cat_recon",
            "CRAWL":  "cat_crawl",
            "SECRET": "cat_sec",
            "VULN":   "cat_vuln",
            "OUTPUT": "cat_out",
        }
        for idx, (num, cat, ckey, label, hint) in enumerate(MENU_ITEMS):
            if cat not in cats_seen:
                cats_seen[cat] = True
                col = cat_colors.get(cat, "sep")
                console.print(f"  [sep]──[/sep]  [{col}]{cat}[/{col}]")

            is_sel = (idx == sel)
            arrow  = "→" if is_sel else " "
            num_s  = f"{num:02d}"

            if is_sel:
                a_style  = "arrow"
                n_style  = "bold color(196)"
                l_style  = "sel"
                h_style  = "dim color(93)"
            else:
                a_style  = "muted"
                n_style  = "mn"
                l_style  = "color(250)"
                h_style  = "dim color(238)"

            hint_part = f"  [{h_style}]{hint}[/{h_style}]" if hint and is_sel else ""
            console.print(
                f"  [{a_style}]{arrow}[/{a_style}] [{n_style}]{num_s}[/{n_style}]  [{l_style}]{label:<28}[/{l_style}]{hint_part}"
            )

        console.print()
        UI.hsep()
        tgt = target if target else "[dim](not set)[/dim]"
        cnt = f"  [muted]({domain_count} domains)[/muted]" if domain_count > 1 else ""
        console.print(f"  [label]Target  [/label]  [target]{tgt}[/target]{cnt}")
        UI.hsep()
        inp_disp = num_buf if num_buf else ""
        console.print(
            f"  [muted]↑↓ navigate   ↵ select   [0-9] type number[/muted]"
            + (f"   [prompt]input: {inp_disp}[/prompt]" if inp_disp else "")
        )
        sys.stdout.flush()

    @staticmethod
    def interactive_menu(target: str, domain_count: int) -> int:
        sel     = 0
        num_buf = ""
        while True:
            UI.render_menu(target, domain_count, sel, num_buf)
            ch = _getch()

            if ch == KEY_UP:
                sel = (sel - 1) % len(MENU_ITEMS)
                num_buf = ""

            elif ch == KEY_DOWN:
                sel = (sel + 1) % len(MENU_ITEMS)
                num_buf = ""

            elif ch in (KEY_ENTER, KEY_ENTER2):
                if num_buf:
                    try:
                        n = int(num_buf)
                        for i, item in enumerate(MENU_ITEMS):
                            if item[0] == n:
                                sel = i
                                break
                    except ValueError:
                        pass
                    num_buf = ""
                return MENU_ITEMS[sel][0]

            elif ch.isdigit():
                num_buf += ch
                try:
                    n = int(num_buf)
                    for i, item in enumerate(MENU_ITEMS):
                        if item[0] == n:
                            sel = i
                            break
                except ValueError:
                    pass

            elif ch == "\x03":
                raise KeyboardInterrupt

            elif ch in ("q", "Q", "\x1b"):
                return 26

            elif ch in ("\x7f", "\x08"):
                num_buf = num_buf[:-1]

    @staticmethod
    def print_findings(domain: str, db: Database):
        findings = db.get_findings(domain)
        if not findings:
            return
        console.print()
        UI.hsep("FINDINGS", "color(203)")
        console.print()
        sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        findings  = sorted(findings, key=lambda f: sev_order.get(f["severity"].lower(), 5))
        for f in findings:
            UI.finding(f["severity"], f["module"], f["title"], f["url"])


class Recon:
    def __init__(self, domain: str, targets: List[str], fm: FileManager, r: Runner, db: Database):
        self.domain  = domain
        self.targets = targets
        self.fm      = fm
        self.r       = r
        self.db      = db
        self.cfg     = r.cfg

    def subfinder(self) -> int:
        out = self.fm.path("subdomains", "subfinder.txt")
        cmd = ["subfinder", "-silent", "-all", "-recursive",
               "-t", str(self.cfg.get("threads", 50)), "-o", str(out)]
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

    def httpx_hosts(self) -> int:
        src = None
        for name in ["subfinder.txt", "targets.txt"]:
            if self.fm.exists("subdomains", name):
                src = self.fm.path("subdomains", name)
                break
        if not src:
            tf = self.fm.path("subdomains", "targets.txt")
            self.fm.write("subdomains", "targets.txt", self.targets)
            src = tf
        out = self.fm.path("live", "live_hosts.txt")
        cmd = [
            "httpx", "-silent",
            "-l",         str(src),
            "-o",         str(out),
            "-threads",   str(self.cfg.get("threads", 50)),
            "-rl",        str(self.cfg.get("rate_limit", 150)),
            "-timeout",   str(self.cfg.get("timeout", 15)),
            "-mc",        "200,204,301,302,307,308,401,403,404,405,500,502,503",
            "-follow-redirects",
            "-sc",
            "-title",
            "-server",
            "-ip",
            "-td",
        ]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            return -2
        raw   = self.fm.read("live", "live_hosts.txt")
        hosts = [URLFilter.base_url(l) for l in raw if URLFilter.base_url(l).startswith("http")]
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
            "-l",         str(url_file),
            "-o",         str(out),
            "-threads",   str(self.cfg.get("threads", 50)),
            "-rl",        str(self.cfg.get("rate_limit", 150)),
            "-timeout",   str(self.cfg.get("timeout", 15)),
            "-mc",        "200,204,301,302,307,308,401,403",
            "-follow-redirects",
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
        for cat, name in [("subdomains","subfinder.txt"),("subdomains","targets.txt")]:
            if self.fm.exists(cat, name):
                src = self.fm.path(cat, name)
                break
        if not src:
            tf = self.fm.path("subdomains", "targets.txt")
            self.fm.write("subdomains", "targets.txt", self.targets)
            src = tf
        out = self.fm.path("ports", "naabu.txt")
        cmd = [
            "naabu", "-silent",
            "-l",     str(src),
            "-p",     self.cfg.get("ports", "80,443,8080,8443"),
            "-o",     str(out),
            "-rate",  "1500",
            "-retries","2",
            "-timeout","10",
            "-ep",    "22,23,25,445,3389",
        ]
        rc, _, _ = self.r.run(cmd, timeout=900)
        if rc == -2:
            return -2
        raw  = self.fm.read("ports", "naabu.txt")
        port_urls = URLFilter.naabu_to_urls(raw)
        self.fm.write("ports", "port_urls.txt", port_urls)
        n = len(raw)
        self.db.upsert_scan(self.domain, "naabu", "done", n)
        return n

    def tlsx(self) -> int:
        src = self.fm.path("live", "live_hosts_clean.txt")
        if not self.fm.exists("live", "live_hosts_clean.txt"):
            return 0
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
        src = self.fm.path("live", "live_hosts_clean.txt")
        if not self.fm.exists("live", "live_hosts_clean.txt"):
            return 0
        out = self.fm.path("live", "cdn_check.txt")
        cmd = ["cdncheck", "-silent", "-l", str(src), "-o", str(out), "-resp"]
        rc, _, _ = self.r.run(cmd, timeout=120)
        return -2 if rc == -2 else self.fm.count("live", "cdn_check.txt")


class Crawler:
    def __init__(self, domain: str, fm: FileManager, r: Runner, db: Database):
        self.domain = domain
        self.fm     = fm
        self.r      = r
        self.db     = db
        self.cfg    = r.cfg

    def _host_src(self) -> Optional[Path]:
        for name in ["live_hosts_clean.txt", "live_hosts.txt"]:
            if self.fm.exists("live", name):
                return self.fm.path("live", name)
        return None

    def gau(self) -> int:
        out = self.fm.path("urls", "gau.txt")
        cmd = ["gau", "--subs", "--threads", "10", "--o", str(out), self.domain]
        rc, stdout, _ = self.r.run(cmd, timeout=900)
        if rc == -2:
            rc2, stdout2, _ = self.r.run(
                ["gau", "--threads", "5", self.domain], timeout=600
            )
            if stdout2:
                self.fm.write("urls", "gau.txt", stdout2.splitlines())
        n = self.fm.count("urls", "gau.txt")
        self.db.upsert_scan(self.domain, "gau", "done", n)
        return n

    def waybackurls(self) -> int:
        rc, stdout, _ = self.r.run(
            ["waybackurls"],
            stdin_data=self.domain + "\n",
            timeout=600
        )
        if rc == -2:
            return -2
        if stdout:
            self.fm.write("urls", "wayback.txt", stdout.splitlines())
        n = self.fm.count("urls", "wayback.txt")
        return n

    def katana(self) -> int:
        src = self._host_src()
        if not src:
            return 0
        out = self.fm.path("urls", "katana.txt")
        cmd = [
            "katana", "-silent",
            "-list",        str(src),
            "-o",           str(out),
            "-d",           str(self.cfg.get("depth", 5)),
            "-c",           str(self.cfg.get("threads", 50)),
            "-rl",          str(self.cfg.get("rate_limit", 150)),
            "-jc",
            "-kf",          "all",
            "-hl",
            "-ef",          "woff,woff2,css,png,jpg,jpeg,gif,ico,svg,ttf,eot",
            "-timeout",     str(self.cfg.get("timeout", 15)),
        ]
        rc, _, _ = self.r.run(cmd, timeout=1200)
        if rc == -2:
            return -2
        n = self.fm.count("urls", "katana.txt")
        self.db.upsert_scan(self.domain, "katana", "done", n)
        return n

    def merge_and_filter(self) -> Tuple[int, int, int]:
        combined: List[str] = []
        for cat, name in [("urls","gau.txt"),("urls","wayback.txt"),("urls","katana.txt"),
                          ("ports","port_urls.txt")]:
            combined.extend(self.fm.read(cat, name))
        combined = URLFilter.dedupe(combined)
        self.fm.write("urls", "all_raw.txt", combined)

        rc, stdout, _ = self.r.run(["uro"], stdin_data="\n".join(combined), timeout=300)
        filtered = URLFilter.dedupe(stdout.splitlines()) if rc == 0 and stdout else combined
        self.fm.write("urls", "all_urls.txt", filtered)
        self.db.add_urls(self.domain, filtered)
        self.db.upsert_scan(self.domain, "uro", "done", len(filtered))

        param_urls = URLFilter.injectable(filtered)
        self.fm.write("urls", "param_urls.txt", param_urls)
        js_urls    = URLFilter.js_files(filtered)
        self.fm.write("js", "js_urls.txt", js_urls)

        return len(filtered), len(param_urls), len(js_urls)

    def paramspider(self) -> int:
        out  = self.fm.path("params", "paramspider.txt")
        cmd1 = ["paramspider", "-d", self.domain, "-s", "-o", str(out)]
        rc, _, _ = self.r.run(cmd1, timeout=300)
        if rc == -2:
            cmd2 = [sys.executable, "-m", "paramspider", "-d", self.domain, "-o", str(out)]
            rc, _, _ = self.r.run(cmd2, timeout=300)
        existing = self.fm.read("urls", "param_urls.txt")
        spider   = self.fm.read("params", "paramspider.txt")
        merged   = URLFilter.dedupe(existing + spider)
        merged   = [u for u in merged if "=" in u]
        self.fm.write("params", "all_params.txt", merged)
        n = len(merged)
        self.db.upsert_scan(self.domain, "paramspider", "done", n)
        return n

    def xnlinkfinder(self) -> int:
        src = self._host_src()
        if not src:
            return 0
        hosts = self.fm.read(*(("live","live_hosts_clean.txt") if self.fm.exists("live","live_hosts_clean.txt") else ("live","live_hosts.txt")))
        target = hosts[0] if hosts else f"https://{self.domain}"
        out    = self.fm.path("urls", "xnlinkfinder.txt")
        cmd    = ["xnLinkFinder", "-i", target, "-op", str(out), "-sp", target, "-d", "3"]
        rc, _, _ = self.r.run(cmd, timeout=300)
        return -2 if rc == -2 else self.fm.count("urls", "xnlinkfinder.txt")


class Discovery:
    TOOLS_BASE = Path("/opt/lostfuzzer-tools")

    def __init__(self, domain: str, fm: FileManager, r: Runner, db: Database):
        self.domain = domain
        self.fm     = fm
        self.r      = r
        self.db     = db
        self.cfg    = r.cfg

    def _wordlist(self) -> str:
        for p in [
            self.cfg.get("wordlist",""),
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]:
            if p and os.path.exists(p):
                return p
        return ""

    def _live_urls(self) -> List[str]:
        for name in ["live_urls.txt","live_hosts_clean.txt","live_hosts.txt"]:
            data = self.fm.read("live", name)
            if data:
                return [URLFilter.base_url(l) for l in data if URLFilter.base_url(l).startswith("http")]
        return []

    def ffuf(self, target: Optional[str] = None) -> int:
        wl = self._wordlist()
        if not wl:
            return -1
        urls  = [target] if target else self._live_urls()[:5]
        total = 0
        for url in urls:
            base  = url.rstrip("/")
            ofile = self.fm.path("endpoints", f"ffuf_{hash(base)%99999}.json")
            cmd   = [
                "ffuf", "-s",
                "-u",      f"{base}/FUZZ",
                "-w",      wl,
                "-t",      str(min(self.cfg.get("threads", 50), 100)),
                "-rate",   str(self.cfg.get("rate_limit", 150)),
                "-mc",     "200,204,301,302,307,308,401,403",
                "-ac",
                "-o",      str(ofile),
                "-of",     "json",
                "-timeout",str(self.cfg.get("timeout", 15)),
                "-maxtime","300",
            ]
            if self.cfg.proxy_url:
                cmd += ["-x", self.cfg.proxy_url]
            rc, _, _ = self.r.run(cmd, timeout=400)
            if rc == 0 and ofile.exists():
                try:
                    hits = json.loads(ofile.read_text()).get("results", [])
                    total += len(hits)
                    self.fm.append("endpoints", "ffuf_all.txt",
                        [f"{h.get('status')} {h.get('url','')} [{h.get('length',0)}]" for h in hits])
                except Exception:
                    total += 1
        return total

    def feroxbuster(self, target: Optional[str] = None) -> int:
        wl   = self._wordlist()
        urls = [target] if target else self._live_urls()[:3]
        if not urls or not wl:
            return 0
        out = self.fm.path("endpoints", "feroxbuster.txt")
        cmd = [
            "feroxbuster",
            "-u",           urls[0],
            "-w",           wl,
            "-t",           str(min(self.cfg.get("threads", 50), 100)),
            "--rate-limit", str(self.cfg.get("rate_limit", 150)),
            "-o",           str(out),
            "--quiet",
            "-x",           "php,html,js,txt,json,asp,aspx,bak",
            "--timeout",    str(self.cfg.get("timeout", 15)),
            "--auto-tune",
            "--no-recursion",
        ]
        if self.cfg.proxy_url:
            cmd += ["--proxy", self.cfg.proxy_url]
        rc, _, _ = self.r.run(cmd, timeout=600)
        return -2 if rc == -2 else self.fm.count("endpoints", "feroxbuster.txt")

    def dirsearch(self, target: Optional[str] = None) -> int:
        urls = [target] if target else self._live_urls()[:3]
        if not urls:
            return 0
        out = self.fm.path("endpoints", "dirsearch.txt")
        cmd = [
            "dirsearch", "-u", urls[0],
            "-t",       str(min(self.cfg.get("threads", 50), 100)),
            "-o",       str(out),
            "--format", "plain", "-q",
            "-x",       "404,400,500,429",
            "-e",       "php,html,js,txt,json,asp,aspx,bak,zip",
            "--timeout",str(self.cfg.get("timeout", 15)),
        ]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            cmd2 = [sys.executable, "-m", "dirsearch", "-u", urls[0], "-q", "-o", str(out), "--format", "plain"]
            rc, _, _ = self.r.run(cmd2, timeout=600)
        return self.fm.count("endpoints", "dirsearch.txt")

    def secretfinder(self) -> int:
        js_urls = self.fm.read("js", "js_urls.txt")
        if not js_urls:
            all_u = self.fm.read("urls", "all_urls.txt")
            js_urls = URLFilter.js_files(all_u)
        if not js_urls:
            return 0
        out_lines: List[str] = []
        scripts = [self.TOOLS_BASE/"SecretFinder"/"SecretFinder.py", Path("SecretFinder.py")]
        sf = next((str(p) for p in scripts if p.exists()), None)
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
        urls = self._live_urls()
        hits: List[str] = []
        for url in urls[:10]:
            cmd = ["trufflehog", "url", url, "--json", "--no-update", "--only-verified"]
            rc, stdout, _ = self.r.run(cmd, timeout=120, retries=0)
            if rc == -2:
                cmd2 = ["trufflehog", "filesystem", "--directory", str(self.fm.base), "--json", "--no-update"]
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

    def gowitness(self) -> int:
        urls = self._live_urls()
        if not urls:
            return 0
        src = self.fm.path("live", "live_urls.txt")
        if not self.fm.exists("live", "live_urls.txt"):
            hosts_f = self.fm.path("live", "live_hosts_clean.txt")
            if not hosts_f.exists():
                return 0
            src = hosts_f
        out_dir = self.fm.dirs["screenshots"]
        cmd = [
            "gowitness", "file",
            "-f",                  str(src),
            "--screenshot-path",   str(out_dir),
            "--disable-logging",
            "--timeout",           str(self.cfg.get("timeout", 15)),
            "--threads",           str(min(self.cfg.get("threads", 50), 10)),
        ]
        rc, _, _ = self.r.run(cmd, timeout=900)
        return -2 if rc == -2 else len(list(out_dir.glob("*.png")))

    def js_discovery(self) -> int:
        all_u = self.fm.read("urls", "all_urls.txt")
        js    = URLFilter.js_files(all_u)
        xnl   = URLFilter.js_files(self.fm.read("urls", "xnlinkfinder.txt"))
        js    = URLFilter.dedupe(js + xnl)
        self.fm.write("js", "js_urls.txt", js)
        return len(js)


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
        for cat, name in [("params","all_params.txt"),("urls","param_urls.txt"),("params","paramspider.txt")]:
            if self.fm.exists(cat, name):
                return self.fm.path(cat, name)
        all_u = self.fm.read("urls", "all_urls.txt")
        inj   = URLFilter.injectable(all_u)
        if inj:
            self.fm.write("urls", "param_urls.txt", inj)
            return self.fm.path("urls", "param_urls.txt")
        return None

    def _live_file(self) -> Optional[Path]:
        for name in ["live_urls.txt","live_hosts_clean.txt"]:
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
            "-l",             str(src),
            "-o",             str(out),
            "-rl",            str(self.cfg.get("rate_limit", 150)),
            "-c",             str(min(self.cfg.get("threads", 50), 50)),
            "-retries",       str(self.cfg.get("retries", 3)),
            "-timeout",       str(self.cfg.get("timeout", 15)),
            "-severity",      sev,
            "-fr",
            "-system-resolvers",
            "-bs",            "100",
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
                tm.group(1)         if tm else line[:60],
                um.group(0)         if um else "",
                line
            )
        n = len(results)
        self.db.upsert_scan(self.domain, f"nuclei{suffix}", "done", n)
        return n

    def dalfox(self) -> int:
        src = self._params_file()
        if not src:
            return 0
        lines = self.fm.read(*(("params","all_params.txt") if self.fm.exists("params","all_params.txt") else ("urls","param_urls.txt")))
        if not lines:
            return 0
        out = self.fm.path("xss", "dalfox.txt")
        cmd = [
            "dalfox", "file", str(src),
            "--silence",
            "-o",              str(out),
            "--skip-bav",
            "--timeout",       str(self.cfg.get("timeout", 15)),
            "--worker",        str(min(self.cfg.get("threads", 50), 20)),
            "--delay",         str(self.cfg.get("delay", 0)),
        ]
        if self.cfg.proxy_url:
            cmd += ["--proxy", self.cfg.proxy_url]
        rc, _, _ = self.r.run(cmd, timeout=1800)
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
        url  = target_url or self._first_live()
        scripts = [self.TOOLS_BASE/"XSStrike"/"xsstrike.py", Path("XSStrike/xsstrike.py")]
        sc   = next((str(p) for p in scripts if p.exists()), None)
        out  = self.fm.path("xss", "xsstrike.txt")
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
        src = self._params_file()
        if not target_url and not src:
            return 0

        base_cmd = [
            "sqlmap",
            "--batch",
            "--random-agent",
            "--level",      "3",
            "--risk",       "2",
            "--threads",    str(min(self.cfg.get("threads", 50), 10)),
            "--timeout",    str(self.cfg.get("timeout", 30)),
            "--retries",    str(self.cfg.get("retries", 3)),
            "--output-dir", str(self.fm.dirs["sqli"]),
            "--forms",
            "--tamper=space2comment,between,charunicodeencode",
            "-q",
        ]
        if target_url:
            cmd = base_cmd + ["-u", target_url, "--crawl=3"]
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
        params = self.fm.read("params", "all_params.txt") or self.fm.read("urls", "param_urls.txt")
        return params

    def corsy(self) -> int:
        urls  = self.fm.read("live","live_urls.txt") or self.fm.read("live","live_hosts_clean.txt")
        if not urls:
            return 0
        ifile = self.fm.path("live", "cors_input.txt")
        self.fm.write("live", "cors_input.txt", urls[:50])
        out   = self.fm.path("nuclei", "corsy.txt")
        scripts = [self.TOOLS_BASE/"Corsy"/"corsy.py", Path("corsy.py")]
        sc = next((str(p) for p in scripts if p.exists()), None)
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
        src = None
        for name in ["subfinder.txt"]:
            if self.fm.exists("subdomains", name):
                src = self.fm.path("subdomains", name)
                break
        if not src:
            return 0
        out = self.fm.path("nuclei", "subzy.txt")
        cmd = ["subzy", "run", "--targets", str(src), "--output", str(out),
               "--hide_fails", "--concurrency", str(min(self.cfg.get("threads",50),50))]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            return self.nuclei(tags=["takeover"], severity="critical,high")
        results = self.fm.read("nuclei", "subzy.txt")
        for v in results:
            self.db.add_finding(self.domain, "subzy", "high", "Subdomain Takeover", v, "")
        return len(results)

    def jwt_audit(self, target_url: Optional[str] = None) -> int:
        url  = target_url or self._first_live()
        out  = self.fm.path("nuclei", "jwt_nuclei.txt")
        n    = self.nuclei(tags=["jwt"], severity="critical,high,medium",
                           src=self._live_file())
        scripts = [self.TOOLS_BASE/"jwt-tool"/"jwt_tool.py", Path("jwt_tool.py")]
        sc = next((str(p) for p in scripts if p.exists()), None)
        if sc:
            cmd2 = [sys.executable, sc, "-t", url, "-M", "at", "-np"]
            rc2, stdout2, _ = self.r.run(cmd2, timeout=120, retries=0)
            if rc2 != -2 and stdout2:
                hits = [l for l in stdout2.splitlines()
                        if any(k in l for k in ["Found","Cracked","Vulnerable","alg:none","weak"])]
                if hits:
                    self.fm.write("nuclei", "jwt.txt", hits)
                    for h in hits:
                        self.db.add_finding(self.domain, "jwt", "high", "JWT Vulnerability", url, h)
                    n += len(hits)
        return n

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
            "-rl",       str(self.cfg.get("rate_limit", 150)),
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
        src = self._params_file() or self._live_file()
        if not src:
            return 0
        out = self.fm.path("nuclei", "redirect.txt")
        cmd = [
            "nuclei", "-silent",
            "-l",        str(src),
            "-tags",     "redirect,open-redirect",
            "-severity", "high,medium",
            "-o",        str(out),
            "-rl",       str(self.cfg.get("rate_limit", 150)),
            "-dast",
        ]
        tdir = self._tdir()
        if tdir:
            cmd += ["-t", tdir]
        rc, _, _ = self.r.run(cmd, timeout=600)
        if rc == -2:
            return -2
        results = self.fm.read("nuclei", "redirect.txt")
        for v in results:
            um = re.search(r'https?://\S+', v)
            self.db.add_finding(self.domain, "redirect", "medium", "Open Redirect",
                                um.group(0) if um else "", v)
        return len(results)

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
            "-rl",       str(self.cfg.get("rate_limit", 150)),
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

    def graphql_probe(self) -> int:
        live = self.fm.read("live","live_urls.txt") or self.fm.read("live","live_hosts_clean.txt")
        found: List[str] = []
        paths = ["/graphql","/api/graphql","/gql","/query","/graphiql","/playground","/api/v1/graphql","/v1/graphql"]
        sess  = requests.Session()
        sess.headers["User-Agent"] = self.cfg.get("user_agent","Mozilla/5.0")
        if self.cfg.proxy_dict:
            sess.proxies = self.cfg.proxy_dict
        for base in live[:30]:
            for path in paths:
                url = base.rstrip("/") + path
                try:
                    r = sess.post(url, json={"query":"{ __typename }"},
                                  timeout=self.cfg.get("timeout",10), verify=False)
                    if r.status_code == 200 and "__typename" in r.text:
                        found.append(f"[INTROSPECTION] {url}")
                        self.db.add_finding(self.domain,"graphql","medium","GraphQL Introspection",url,r.text[:200])
                    elif r.status_code in (200,400,422) and any(k in r.text.lower() for k in ["graphql","query","mutation"]):
                        found.append(f"[ENDPOINT] {url}")
                except Exception:
                    pass
        if found:
            self.fm.write("nuclei","graphql.txt",found)
        return len(found)


class Reporter:
    def __init__(self, domain: str, fm: FileManager, db: Database):
        self.domain = domain
        self.fm     = fm
        self.db     = db

    def json_export(self) -> Path:
        findings = self.db.get_findings(self.domain)
        data = {
            "tool": "LostFuzzer", "version": VERSION,
            "domain": self.domain, "generated": datetime.now().isoformat(),
            "stats": {
                "subdomains": self.fm.count("subdomains","subfinder.txt"),
                "live_hosts": self.fm.count("live","live_hosts_clean.txt"),
                "live_urls":  self.fm.count("live","live_urls.txt"),
                "total_urls": self.fm.count("urls","all_urls.txt"),
                "param_urls": self.fm.count("params","all_params.txt"),
                "js_files":   self.fm.count("js","js_urls.txt"),
                "findings":   len(findings),
            },
            "findings": findings,
        }
        out = self.fm.path("reports","report.json")
        out.write_text(json.dumps(data, indent=2))
        return out

    def html_report(self) -> Path:
        findings = self.db.get_findings(self.domain)
        stats = {
            "Subdomains":  self.fm.count("subdomains","subfinder.txt"),
            "Live Hosts":  self.fm.count("live","live_hosts_clean.txt"),
            "Live URLs":   self.fm.count("live","live_urls.txt"),
            "All URLs":    self.fm.count("urls","all_urls.txt"),
            "Param URLs":  self.fm.count("params","all_params.txt"),
            "JS Files":    self.fm.count("js","js_urls.txt"),
            "Open Ports":  self.fm.count("ports","naabu.txt"),
            "Findings":    len(findings),
        }
        sev_order  = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        findings   = sorted(findings, key=lambda f: sev_order.get(f["severity"].lower(), 5))
        sev_colors = {"critical":"#ff2d55","high":"#ff6b35","medium":"#ffd60a","low":"#34c759","info":"#3a3a3c"}

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

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>LostFuzzer — {self.domain}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'JetBrains Mono','SF Mono',monospace;background:#050505;color:#c7c7cc;min-height:100vh;font-size:12px}}
.hdr{{padding:36px 48px 28px;border-bottom:1px solid #111}}
.hdr h1{{font-size:18px;font-weight:700;background:linear-gradient(90deg,#c62828,#6a1b9a,#1565c0);-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:.04em}}
.hdr .sub{{margin-top:6px;font-size:10px;color:#3a3a3c;letter-spacing:.06em}}
.stats{{display:flex;gap:1px;background:#111;border-bottom:1px solid #111;flex-wrap:wrap}}
.stat{{flex:1;min-width:90px;background:#080808;padding:18px 24px}}
.sv{{font-size:24px;font-weight:700;color:#fff;font-variant-numeric:tabular-nums}}
.sl{{font-size:9px;color:#3a3a3c;margin-top:3px;letter-spacing:.08em;text-transform:uppercase}}
.sec{{padding:24px 48px}}
.sec h2{{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#3a3a3c;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #111}}
table{{width:100%;border-collapse:collapse}}
th{{text-align:left;padding:7px 12px;font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:#2c2c2e;border-bottom:1px solid #111}}
td{{padding:9px 12px;border-bottom:1px solid #0d0d0d;vertical-align:top}}
tr:hover td{{background:#0a0a0a}}
.badge{{display:inline-block;padding:1px 6px;border-radius:2px;font-size:8px;font-weight:800;letter-spacing:.06em;color:#000}}
.url{{color:#3a3a3c;font-size:10px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.ts{{color:#1c1c1e;font-size:9px;white-space:nowrap}}
.ftr{{padding:16px 48px;border-top:1px solid #111;font-size:9px;color:#1c1c1e;letter-spacing:.06em}}
.none{{color:#2c2c2e;font-size:11px;padding:16px 0}}
</style></head><body>
<div class="hdr">
  <h1>LOSTFUZZER — {self.domain}</h1>
  <div class="sub">Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;·&nbsp; @{AUTHOR} &nbsp;·&nbsp; v{VERSION}</div>
</div>
<div class="stats">{stat_html}</div>
<div class="sec">
  <h2>Vulnerability Findings</h2>
  {'<table><thead><tr><th>Sev</th><th>Module</th><th>Title</th><th>URL</th><th>Time</th></tr></thead><tbody>'+rows+'</tbody></table>' if findings else '<p class="none">No findings recorded.</p>'}
</div>
<div class="ftr">LostFuzzer v{VERSION} &nbsp;·&nbsp; {GITHUB}</div>
</body></html>"""
        out = self.fm.path("reports","report.html")
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
        self.send(f"🔍 *LostFuzzer* started\nTarget: `{domain}`\nModule: `{module}`")

    def scan_done(self, domain: str, stats: Dict):
        body = [f"✅ *LostFuzzer* complete\nTarget: `{domain}`"]
        body += [f"  {k}: `{v}`" for k, v in stats.items()]
        self.send("\n".join(body))

    def vuln_alert(self, domain: str, sev: str, title: str, url: str):
        e = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}.get(sev.lower(),"⚪")
        self.send(f"{e} *{sev.upper()}*\nTarget: `{domain}`\n`{title}`\n{url}")


class Pipeline:
    def __init__(self, domain: str, targets: List[str], cfg: Config, db: Database):
        self.domain   = domain
        self.targets  = targets
        self.cfg      = cfg
        self.db       = db
        self.fm       = FileManager(domain)
        self.runner   = Runner(cfg)
        self.recon    = Recon(domain, targets, self.fm, self.runner, db)
        self.crawler  = Crawler(domain, self.fm, self.runner, db)
        self.discover = Discovery(domain, self.fm, self.runner, db)
        self.vuln     = VulnScanner(domain, self.fm, self.runner, db)
        self.reporter = Reporter(domain, self.fm, db)
        self.notifier = Notifier(cfg)

    def _done(self, mod: str) -> bool:
        return self.db.get_scan_status(self.domain, mod) == "done"

    def step(self, name: str, fn, key: Optional[str] = None, resume: bool = False):
        if resume and key and self._done(key):
            UI.status(name, "skip", "cached")
            return -99
        UI.status(name, "run")
        n = fn()
        st = "ok" if n >= 0 else ("skip" if n == -2 else "err")
        UI.status(name, st, str(n) if n >= 0 else ("not installed" if n == -2 else "failed"))
        return n

    def full_auto(self, resume: bool = True) -> Dict:
        self.notifier.scan_start(self.domain, "full_auto")

        UI.section("PHASE 1 · SUBDOMAIN DISCOVERY", "color(196)")
        self.step("subfinder",    self.recon.subfinder,          "subfinder",    resume)
        self.step("httpx-hosts",  self.recon.httpx_hosts,        "httpx_hosts",  resume)

        UI.section("PHASE 2 · URL HARVEST", "color(128)")
        self.step("gau",          self.crawler.gau,              "gau",          resume)
        self.step("waybackurls",  self.crawler.waybackurls,      None,           False)
        self.step("katana",       self.crawler.katana,           "katana",       resume)
        self.step("naabu",        self.recon.naabu,              "naabu",        resume)

        UI.section("PHASE 3 · MERGE + URO + HTTPX PROBE", "color(57)")
        UI.status("merge+uro", "run")
        total, params, js = self.crawler.merge_and_filter()
        UI.status("merge+uro", "ok", f"{total} URLs  ·  {params} param  ·  {js} JS")

        all_urls_file = self.fm.path("urls", "all_urls.txt")
        UI.status("httpx-probe", "run")
        n = self.recon.httpx_probe_urls(all_urls_file)
        UI.status("httpx-probe", "ok" if n >= 0 else "err", f"{n} live URLs" if n >= 0 else "failed")

        UI.status("paramspider", "run")
        n = self.crawler.paramspider()
        UI.status("paramspider", "ok" if n >= 0 else "skip", str(n) if n >= 0 else "not found")

        UI.section("PHASE 4 · SECRET HUNT", "color(226)")
        self.step("secretfinder", self.discover.secretfinder, None, False)
        self.step("trufflehog",   self.discover.trufflehog,   None, False)

        UI.section("PHASE 5 · VULNERABILITY SCAN", "color(203)")
        p_file = self.vuln._params_file()
        l_file = self.vuln._live_file()
        params_count = self.fm.count("params","all_params.txt") or self.fm.count("urls","param_urls.txt")
        UI.info(f"Live URLs: {self.fm.count('live','live_urls.txt')}  ·  Param URLs: {params_count}")

        self.step("nuclei",       lambda: self.vuln.nuclei(),           "nuclei",   resume)
        self.step("nuclei-dast",  lambda: self.vuln.nuclei(dast=True),  None,       False)
        self.step("dalfox",       self.vuln.dalfox,                     "dalfox",   resume)
        self.step("sqlmap",       self.vuln.sqlmap,                     "sqlmap",   resume)
        self.step("corsy",        self.vuln.corsy,                      None,       False)
        self.step("crlfuzz",      self.vuln.crlfuzz,                    None,       False)
        self.step("subzy",        self.vuln.subzy,                      None,       False)
        self.step("lfi",          self.vuln.lfi_scan,                   None,       False)
        self.step("redirect",     self.vuln.redirect_scan,              None,       False)
        self.step("ssrf",         self.vuln.ssrf_scan,                  None,       False)

        UI.section("PHASE 6 · REPORT", "color(27)")
        UI.status("html", "run")
        html_p = self.reporter.html_report()
        UI.status("html", "ok", str(html_p))
        UI.status("json", "run")
        json_p = self.reporter.json_export()
        UI.status("json", "ok", str(json_p))

        findings = self.db.get_findings(self.domain)
        stats = {
            "Subdomains": self.fm.count("subdomains","subfinder.txt"),
            "Live Hosts": self.fm.count("live","live_hosts_clean.txt"),
            "Live URLs":  self.fm.count("live","live_urls.txt"),
            "Param URLs": self.fm.count("params","all_params.txt"),
            "Findings":   len(findings),
        }
        self.notifier.scan_done(self.domain, stats)
        return stats


def parse_target(raw: str) -> Tuple[str, List[str]]:
    raw = raw.strip()
    if os.path.isfile(raw):
        lines = [l.strip() for l in Path(raw).read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
        lines = [re.sub(r"https?://","",l).split("/")[0].strip() for l in lines]
        lines = list(dict.fromkeys(l for l in lines if l))
        return (lines[0] if lines else raw), lines
    domain = re.sub(r"https?://","",raw).split("/")[0].split(":")[0].strip()
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
        UI.ok(f"Target set  →  {self.domain}  ({len(self.targets)} domain{'s' if len(self.targets)>1 else ''})")
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
                UI.info(f"... and {len(params)-30} more in {p.fm.path('params','all_params.txt')}")
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
                UI.clear()
                UI.banner()
                UI.section(f"SUBDOMAIN RECON  —  {self.domain}", "color(39)")
                UI.status("subfinder",   "run")
                n = p.recon.subfinder()
                UI.status("subfinder",   "ok" if n >= 0 else "err", f"{n} subdomains" if n >= 0 else "not installed")
                UI.status("httpx-hosts", "run")
                n2 = p.recon.httpx_hosts()
                UI.status("httpx-hosts", "ok" if n2 >= 0 else "err", f"{n2} live hosts" if n2 >= 0 else "not installed")
                console.print()
                UI.stat("Subdomains found",  p.fm.count("subdomains","subfinder.txt"))
                UI.stat("Live web hosts",    p.fm.count("live","live_hosts_clean.txt"))
                UI.stat("Results path",      str(p.fm.dirs["subdomains"]))
                UI.pause()

            elif opt == 2:
                UI.clear()
                UI.banner()
                UI.section(f"DEEP RECON  —  {self.domain}", "color(39)")
                for name, fn in [
                    ("subfinder",   p.recon.subfinder),
                    ("httpx-hosts", p.recon.httpx_hosts),
                    ("naabu",       p.recon.naabu),
                    ("tlsx",        p.recon.tlsx),
                    ("asnmap",      p.recon.asnmap),
                    ("cdncheck",    p.recon.cdncheck),
                ]:
                    UI.status(name, "run")
                    n = fn()
                    UI.status(name, "ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                console.print()
                UI.stat("Subdomains",   p.fm.count("subdomains","subfinder.txt"))
                UI.stat("Live hosts",   p.fm.count("live","live_hosts_clean.txt"))
                UI.stat("Open ports",   p.fm.count("ports","naabu.txt"))
                UI.pause()

            elif opt == 3:
                UI.clear()
                UI.banner()
                UI.section(f"PORT SCAN  —  {self.domain}", "color(39)")
                UI.info(f"Ports: {self.cfg.get('ports')}")
                UI.status("naabu", "run")
                n = p.recon.naabu()
                UI.status("naabu", "ok" if n >= 0 else "err", f"{n} open ports" if n >= 0 else "not installed")
                if n > 0:
                    results = p.fm.read("ports","naabu.txt")
                    console.print()
                    for line in results[:20]:
                        console.print(f"  [found]·[/found]  [dim]{line}[/dim]")
                UI.pause()

            elif opt == 4:
                UI.clear()
                UI.banner()
                UI.section(f"URL HARVEST  —  {self.domain}", "color(51)")
                UI.info("Phase: gau + waybackurls + katana → merge → uro → httpx probe")
                console.print()
                UI.status("gau",         "run")
                n = p.crawler.gau()
                UI.status("gau",         "ok" if n >= 0 else "err", f"{n}" if n >= 0 else "not installed")
                UI.status("waybackurls", "run")
                n = p.crawler.waybackurls()
                UI.status("waybackurls", "ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")
                UI.status("katana",      "run")
                n = p.crawler.katana()
                UI.status("katana",      "ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")
                UI.status("merge+uro",   "run")
                total, params, js = p.crawler.merge_and_filter()
                UI.status("merge+uro",   "ok", f"{total} unique  ·  {params} injectable  ·  {js} JS")
                UI.status("httpx-probe", "run")
                n = p.recon.httpx_probe_urls(p.fm.path("urls","all_urls.txt"))
                UI.status("httpx-probe", "ok" if n >= 0 else "err", f"{n} live URLs" if n >= 0 else "not installed")
                console.print()
                UI.stat("Total URLs",    p.fm.count("urls","all_urls.txt"))
                UI.stat("Live URLs",     p.fm.count("live","live_urls.txt"))
                UI.stat("Param URLs",    p.fm.count("urls","param_urls.txt"))
                UI.stat("JS Files",      p.fm.count("js","js_urls.txt"))
                UI.pause()

            elif opt == 5:
                UI.clear()
                UI.banner()
                UI.section(f"HISTORICAL URLs  —  {self.domain}", "color(51)")
                UI.status("gau",         "run")
                n = p.crawler.gau()
                UI.status("gau",         "ok" if n >= 0 else "err", f"{n}" if n >= 0 else "not installed")
                UI.status("waybackurls", "run")
                n = p.crawler.waybackurls()
                UI.status("waybackurls", "ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")
                UI.status("merge+uro",   "run")
                total, params, js = p.crawler.merge_and_filter()
                UI.status("merge+uro",   "ok", f"{total} unique")
                UI.status("httpx-probe", "run")
                n = p.recon.httpx_probe_urls(p.fm.path("urls","all_urls.txt"))
                UI.status("httpx-probe", "ok" if n >= 0 else "err", f"{n} live" if n >= 0 else "not installed")
                console.print()
                UI.stat("Total collected", p.fm.count("urls","all_urls.txt"))
                UI.stat("Live",            p.fm.count("live","live_urls.txt"))
                UI.stat("Param URLs",      p.fm.count("urls","param_urls.txt"))
                UI.pause()

            elif opt == 6:
                UI.clear()
                UI.banner()
                UI.section(f"CRAWL & PROBE  —  {self.domain}", "color(51)")
                UI.info("katana crawls live hosts → httpx probes all discovered URLs")
                UI.status("katana",      "run")
                n = p.crawler.katana()
                UI.status("katana",      "ok" if n >= 0 else "err", f"{n} URLs" if n >= 0 else "not installed")
                UI.status("xnlinkfinder","run")
                n = p.crawler.xnlinkfinder()
                UI.status("xnlinkfinder","ok" if n >= 0 else "skip", f"{n}" if n >= 0 else "not installed")
                UI.status("merge+uro",   "run")
                total, params, js = p.crawler.merge_and_filter()
                UI.status("merge+uro",   "ok", f"{total} URLs")
                UI.status("httpx-probe", "run")
                n = p.recon.httpx_probe_urls(p.fm.path("urls","all_urls.txt"))
                UI.status("httpx-probe", "ok" if n >= 0 else "err", f"{n} live" if n >= 0 else "failed")
                console.print()
                UI.stat("Live URLs",  p.fm.count("live","live_urls.txt"))
                UI.stat("Param URLs", p.fm.count("urls","param_urls.txt"))
                UI.pause()

            elif opt == 7:
                UI.clear()
                UI.banner()
                UI.section(f"PARAMETER DISCOVERY  —  {self.domain}", "color(51)")
                UI.info("Finding injectable parameters: ?id=, ?cat=, ?file=, ?redirect=, etc.")
                UI.status("paramspider", "run")
                n = p.crawler.paramspider()
                UI.status("paramspider", "ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                self._show_params(p)
                UI.pause()

            elif opt == 8:
                UI.clear()
                UI.banner()
                UI.section(f"JS DISCOVERY  —  {self.domain}", "color(51)")
                UI.status("xnlinkfinder","run")
                n = p.crawler.xnlinkfinder()
                UI.status("xnlinkfinder","ok" if n >= 0 else "skip", f"{n} links" if n >= 0 else "not installed")
                UI.status("js-extract",  "run")
                n = p.discover.js_discovery()
                UI.status("js-extract",  "ok", f"{n} JS files")
                js = p.fm.read("js","js_urls.txt")
                if js:
                    console.print()
                    for u in js[:20]:
                        console.print(f"  [path]·[/path]  [dim]{u}[/dim]")
                    if len(js) > 20:
                        UI.info(f"... +{len(js)-20} more")
                UI.pause()

            elif opt == 9:
                UI.clear()
                UI.banner()
                UI.section(f"HIDDEN ENDPOINTS  —  {self.domain}", "color(51)")
                UI.status("ffuf",        "run")
                n = p.discover.ffuf()
                UI.status("ffuf",        "ok" if n >= 0 else "err", f"{n} hits" if n >= 0 else "no wordlist")
                UI.status("feroxbuster", "run")
                n = p.discover.feroxbuster()
                UI.status("feroxbuster", "ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                UI.status("dirsearch",   "run")
                n = p.discover.dirsearch()
                UI.status("dirsearch",   "ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                console.print()
                UI.stat("ffuf hits",     p.fm.count("endpoints","ffuf_all.txt"))
                UI.stat("feroxbuster",   p.fm.count("endpoints","feroxbuster.txt"))
                UI.stat("dirsearch",     p.fm.count("endpoints","dirsearch.txt"))
                UI.pause()

            elif opt == 10:
                UI.clear()
                UI.banner()
                UI.section(f"SECRET HUNT  —  {self.domain}", "color(226)")
                UI.status("secretfinder","run")
                n = p.discover.secretfinder()
                UI.status("secretfinder","ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                UI.status("trufflehog",  "run")
                n = p.discover.trufflehog()
                UI.status("trufflehog",  "ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                self._show_findings()
                UI.pause()

            elif opt == 11:
                UI.clear()
                UI.banner()
                UI.section(f"XSS  —  {self.domain}", "color(203)")
                param_count = p.fm.count("params","all_params.txt") or p.fm.count("urls","param_urls.txt")
                if param_count == 0:
                    UI.warn("No param URLs. Run menu 7 first for best results.")
                else:
                    UI.info(f"Param URLs available: {param_count}")
                UI.status("dalfox",   "run")
                n = p.vuln.dalfox()
                UI.status("dalfox",   "ok" if n >= 0 else "skip", f"{n} XSS" if n >= 0 else "not installed")
                UI.status("xsstrike", "run")
                n = p.vuln.xsstrike()
                UI.status("xsstrike", "ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                UI.status("nuclei",   "run")
                n = p.vuln.nuclei(tags=["xss"], severity="critical,high,medium")
                UI.status("nuclei",   "ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                self._show_findings()
                UI.pause()

            elif opt == 12:
                UI.clear()
                UI.banner()
                UI.section(f"SQLi  —  {self.domain}", "color(203)")
                UI.info("Checking for injectable params (?id=, ?cat=, ?page=, etc.)")
                self._show_params(p)
                console.print()
                manual = UI.ask("Specific URL with ?param=  (Enter to use all param URLs)")
                UI.status("sqlmap",  "run")
                n = p.vuln.sqlmap(target_url=manual or None)
                UI.status("sqlmap",  "ok" if n >= 0 else "skip", f"{n} vulnerable" if n >= 0 else "not installed")
                UI.status("nuclei",  "run")
                n = p.vuln.nuclei(tags=["sqli","sql-injection"], severity="critical,high")
                UI.status("nuclei",  "ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                self._show_findings()
                UI.pause()

            elif opt == 13:
                UI.clear()
                UI.banner()
                UI.section(f"SSRF  —  {self.domain}", "color(203)")
                UI.status("nuclei-ssrf","run")
                n = p.vuln.ssrf_scan()
                UI.status("nuclei-ssrf","ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                self._show_findings()
                UI.pause()

            elif opt == 14:
                UI.clear()
                UI.banner()
                UI.section(f"LFI / PATH TRAVERSAL  —  {self.domain}", "color(203)")
                UI.status("nuclei-lfi","run")
                n = p.vuln.lfi_scan()
                UI.status("nuclei-lfi","ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                self._show_findings()
                UI.pause()

            elif opt == 15:
                UI.clear()
                UI.banner()
                UI.section(f"OPEN REDIRECT  —  {self.domain}", "color(203)")
                UI.status("nuclei-redir","run")
                n = p.vuln.redirect_scan()
                UI.status("nuclei-redir","ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                self._show_findings()
                UI.pause()

            elif opt == 16:
                UI.clear()
                UI.banner()
                UI.section(f"CORS  —  {self.domain}", "color(203)")
                UI.status("corsy",  "run")
                n = p.vuln.corsy()
                UI.status("corsy",  "ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                UI.status("nuclei", "run")
                n = p.vuln.nuclei(tags=["cors"], severity="high,medium")
                UI.status("nuclei", "ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                self._show_findings()
                UI.pause()

            elif opt == 17:
                UI.clear()
                UI.banner()
                UI.section(f"SUBDOMAIN TAKEOVER  —  {self.domain}", "color(203)")
                UI.status("subzy",  "run")
                n = p.vuln.subzy()
                UI.status("subzy",  "ok" if n >= 0 else "skip", f"{n} vulnerable" if n >= 0 else "not installed")
                UI.status("nuclei", "run")
                n = p.vuln.nuclei(tags=["takeover"], severity="critical,high")
                UI.status("nuclei", "ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                self._show_findings()
                UI.pause()

            elif opt == 18:
                UI.clear()
                UI.banner()
                UI.section(f"JWT AUDIT  —  {self.domain}", "color(203)")
                manual = UI.ask("URL with JWT  (Enter for first live host)")
                UI.status("jwt-tool","run")
                n = p.vuln.jwt_audit(target_url=manual or None)
                UI.status("jwt-tool","ok" if n >= 0 else "skip", str(n) if n >= 0 else "not installed")
                self._show_findings()
                UI.pause()

            elif opt == 19:
                UI.clear()
                UI.banner()
                UI.section(f"GRAPHQL PROBE  —  {self.domain}", "color(203)")
                UI.status("graphql", "run")
                n = p.vuln.graphql_probe()
                UI.status("graphql", "ok", f"{n} endpoints found")
                results = p.fm.read("nuclei","graphql.txt")
                if results:
                    console.print()
                    for line in results:
                        tag  = "[high]" if "INTROSPECTION" in line else "[ok]"
                        etag = "[/high]" if "INTROSPECTION" in line else "[/ok]"
                        console.print(f"  {tag}→{etag}  [dim]{line}[/dim]")
                self._show_findings()
                UI.pause()

            elif opt == 20:
                UI.clear()
                UI.banner()
                UI.section(f"NUCLEI FULL SCAN  —  {self.domain}", "color(203)")
                lf = p.vuln._live_file()
                if not lf:
                    UI.warn("No live URLs. Run menu 4 or 6 first.")
                else:
                    UI.info(f"Scanning {p.fm.count('live', lf.name)} URLs with all templates")
                    UI.status("nuclei", "run")
                    n = p.vuln.nuclei()
                    UI.status("nuclei", "ok" if n >= 0 else "err", f"{n} findings" if n >= 0 else "not installed")
                    UI.status("nuclei-dast","run")
                    n = p.vuln.nuclei(dast=True)
                    UI.status("nuclei-dast","ok" if n >= 0 else "skip", str(n) if n >= 0 else "no params")
                self._show_findings()
                UI.pause()

            elif opt == 21:
                UI.clear()
                UI.banner()
                UI.section(f"SCREENSHOT  —  {self.domain}", "color(141)")
                UI.status("gowitness","run")
                n = p.discover.gowitness()
                UI.status("gowitness","ok" if n >= 0 else "skip", f"{n} screenshots" if n >= 0 else "not installed")
                if n > 0:
                    UI.info(f"Saved to: {p.fm.dirs['screenshots']}")
                UI.pause()

            elif opt == 22:
                UI.clear()
                UI.banner()
                UI.section(f"FULL AUTO SCAN  —  {self.domain}", "color(141)")
                resume_yn = UI.ask("Resume from checkpoint? [y/N]").lower() == "y"
                stats = p.full_auto(resume=resume_yn)
                console.print()
                UI.hsep("SUMMARY", "color(51)")
                for k, v in stats.items():
                    UI.stat(k, v)
                self._show_findings()
                UI.pause()

            elif opt == 23:
                UI.clear()
                UI.banner()
                UI.section("TELEGRAM NOTIFY", "color(141)")
                if self.cfg.get("notify_telegram") and self.cfg.get("telegram_token"):
                    UI.info("Already configured. Leave blank to keep.")
                token  = UI.ask("Bot token")
                chatid = UI.ask("Chat ID")
                if token:
                    self.cfg.set("telegram_token",  token)
                if chatid:
                    self.cfg.set("telegram_chatid", chatid)
                if token or chatid:
                    self.cfg.set("notify_telegram", True)
                notifier = Notifier(self.cfg)
                ok = notifier.send(f"✅ LostFuzzer v{VERSION}\nTarget: `{self.domain or 'not set'}`\nBot connected.")
                UI.ok("Test message sent." if ok else "Failed — check token/chatid.")
                UI.pause()

            elif opt == 24:
                UI.clear()
                UI.banner()
                UI.section("UPDATE TOOLS", "color(141)")
                go_tools = [
                    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
                    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
                    "github.com/projectdiscovery/katana/cmd/katana@latest",
                    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                    "github.com/projectdiscovery/uncover/cmd/uncover@latest",
                    "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
                    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
                    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
                    "github.com/lc/gau/v2/cmd/gau@latest",
                    "github.com/tomnomnom/waybackurls@latest",
                    "github.com/ffuf/ffuf/v2@latest",
                    "github.com/sensepost/gowitness@latest",
                    "github.com/hahwul/dalfox/v2@latest",
                    "github.com/dwisiswant0/crlfuzz@latest",
                    "github.com/lukasikic/subzy@latest",
                    "github.com/trufflesecurity/trufflehog/v3@latest",
                ]
                runner = Runner(self.cfg)
                for mod in go_tools:
                    name = mod.split("/")[-1].split("@")[0]
                    UI.status(name, "run")
                    rc, _, err = runner.run(["go","install",mod], timeout=180, retries=0)
                    UI.status(name, "ok" if rc == 0 else "err", "" if rc == 0 else err[:40])
                UI.status("nuclei-tpl", "run")
                rc, _, _ = runner.run(["nuclei","-update-templates","-silent"], timeout=180, retries=0)
                UI.status("nuclei-tpl", "ok" if rc == 0 else "err")
                UI.status("pip",        "run")
                rc, _, _ = runner.run([sys.executable,"-m","pip","install","-q","-U",
                                       "uro","paramspider","rich","requests","pyyaml"], timeout=120, retries=0)
                UI.status("pip",        "ok" if rc == 0 else "err")
                UI.pause()

            elif opt == 25:
                UI.clear()
                UI.banner()
                UI.section("CUSTOM COMMAND", "color(141)")
                UI.info("Placeholders: {domain} {live_urls} {param_urls}")
                cmd_raw = UI.ask("Command")
                if cmd_raw:
                    repls = {
                        "{domain}":     self.domain,
                        "{live_urls}":  str(p.fm.path("live","live_urls.txt")),
                        "{param_urls}": str(p.fm.path("params","all_params.txt")),
                    }
                    for k, v in repls.items():
                        cmd_raw = cmd_raw.replace(k, v)
                    out_f_raw = UI.ask("Save output to file (Enter to skip)")
                    out_f = Path(out_f_raw) if out_f_raw else None
                    rc, stdout, stderr = p.runner.run(cmd_raw.split(), stdout_file=out_f, timeout=900)
                    if stdout:
                        console.print()
                        for line in stdout.splitlines()[:100]:
                            console.print(f"  [dim]{line}[/dim]")
                    if rc not in (0,-2) and stderr:
                        UI.err(stderr[:200])
                    if out_f and out_f.exists():
                        UI.ok(f"Saved: {out_f}")
                UI.pause()


def main():
    app = LostFuzzer()
    app.run()


if __name__ == "__main__":
    main()
