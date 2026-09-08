"""dirsociety command-line interface."""
import argparse
import json
import os
import sys
from urllib.parse import urlparse

from . import __version__
from .scanner import Fetcher, calibrate, scan
from .ai import analyze
from .spray import spray, load_list

_LOGO = r"""
██████╗ ██╗██████╗ ███████╗ ██████╗  ██████╗██╗███████╗████████╗██╗   ██╗
██╔══██╗██║██╔══██╗██╔════╝██╔═══██╗██╔════╝██║██╔════╝╚══██╔══╝╚██╗ ██╔╝
██║  ██║██║██████╔╝███████╗██║   ██║██║     ██║█████╗     ██║    ╚████╔╝
██║  ██║██║██╔══██╗╚════██║██║   ██║██║     ██║██╔══╝     ██║     ╚██╔╝
██████╔╝██║██║  ██║███████║╚██████╔╝╚██████╗██║███████╗   ██║      ██║
╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝╚═╝╚══════╝   ╚═╝      ╚═╝"""


def _count_words(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return sum(1 for l in f if l.strip() and not l.startswith("#"))
    except OSError:
        return 0


def banner(url=None, threads=None, stealth=None, wordlist=None, exts=None):
    color = os.environ.get("NO_COLOR") is None and sys.stderr.isatty()
    cy, dim, rs = ("\033[36m", "\033[90m", "\033[0m") if color else ("", "", "")
    out = [cy + _LOGO + rs, f"{' ' * 59}{dim}umrsrn{rs}", ""]
    meta = [f"v{__version__}",
            f"Threads: {threads}" if threads else None,
            f"Wordlist: {os.path.basename(wordlist)} ({_count_words(wordlist)})" if wordlist else None,
            f"Extensions: {','.join(exts) if exts else '-'}",
            f"Stealth: {'on' if stealth else 'off'}"]
    out.append("  " + " | ".join(m for m in meta if m))
    if url:
        out.append(f"  Target: {url}")
    return "\n".join(out)


def _c(text, code, on):
    return f"\033[{code}m{text}\033[0m" if on else text


def _color_status(status, on):
    code = {2: "32", 3: "36", 4: "33", 5: "31"}.get(status // 100, "90")
    if status in (401, 403):
        code = "1;33"
    return _c(str(status), code, on)


def _human(n):
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.0f}KB"
    return f"{n / 1024 / 1024:.1f}MB"


_WL = os.path.join(os.path.dirname(__file__), "wordlists")
DEFAULT_WORDLIST = os.path.join(_WL, "dirsociety.txt")
DEFAULT_PASSWORDS = os.path.join(_WL, "weak-passwords.txt")


def _resolve_wordlist(spec):
    """A real path, or a bundled name like 'indonesia' / 'common.txt'. None if missing."""
    if os.path.isfile(spec):
        return spec
    for cand in (os.path.join(_WL, spec), os.path.join(_WL, spec + ".txt")):
        if os.path.isfile(cand):
            return cand
    return None


def build_parser():
    p = argparse.ArgumentParser(
        prog="dirsociety",
        description="Fast, stealthy web content-discovery scanner (authorized testing only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
example:
  # scan dasar
  dirsociety -u https://target

  # cepat: wordlist kecil high-signal (nama bawaan boleh singkat)
  dirsociety -u https://target -w common

  # wordlist Indonesia + ekstensi (tiap kata juga dicoba .php .bak .zip)
  dirsociety -u https://target -w indonesia -x php,bak,zip

  # wordlist eksternal (dirb / SecLists) — pakai path lengkap
  dirsociety -u https://target -w /usr/share/dirb/wordlists/common.txt
  dirsociety -u https://target -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html
  dirsociety -u https://target -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt

  # mode stealth + triage AI + simpan JSON
  export ANTHROPIC_API_KEY=sk-ant-...
  dirsociety -u https://target --stealth --ai -o hasil.json

  # filter status code + header + jitter custom
  dirsociety -u https://target --codes 200,301,403 -H "Cookie: sid=abc" --delay 0.5,2

  # password-spray HTTP Basic auth
  dirsociety -u https://target/protected --spray --auth basic --users admin,root

  # password-spray form login (butuh --data + --fail/--success)
  dirsociety -u https://target/login --spray --auth form \\
    --data 'user=^USER^&pass=^PASS^' --fail "Login gagal" \\
    --users @users.txt --stealth --round-delay 5

legenda: [!] path menarik/perlu dicek manual (bukan vuln terkonfirmasi)   [+] 403/401 berhasil di-bypass
PERINGATAN: gunakan HANYA pada target yang kamu berwenang uji.
""",
    )
    p.add_argument("-u", "--url", required=True, help="base URL, e.g. https://target")
    p.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST,
                   help="wordlist path, or bundled name: dirsociety (default ~12k, dirsearch-parity), "
                        "big (~106k, max coverage), common, indonesia")
    p.add_argument("-x", "--extensions", default="",
                   help="append extensions to each word, e.g. php,bak,zip "
                        "(word 'admin' -> also admin.php, admin.bak, admin.zip)")
    p.add_argument("-t", "--threads", type=int, default=40)
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--stealth", action="store_true",
                   help="low concurrency + random jitter + UA rotation")
    p.add_argument("--delay", default="",
                   help="jitter seconds 'min,max' (overrides stealth default)")
    p.add_argument("--codes", default="",
                   help="only report these status codes, e.g. 200,301,403 (default: all but 404)")
    p.add_argument("--no-bypass", action="store_true", help="skip 403/401 bypass attempts")
    p.add_argument("--follow-redirects", action="store_true",
                   help="follow 3xx (default: report redirects with their Location, like dirsearch)")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="'Name: value' extra header (repeatable)")
    p.add_argument("--ai", action="store_true",
                   help="triage findings with an LLM (see --ai-provider)")
    p.add_argument("--ai-provider", choices=["anthropic", "openai"], default="anthropic",
                   help="anthropic (ANTHROPIC_API_KEY) or openai-compatible "
                        "/chat/completions incl. Groq/OpenRouter/DeepSeek/Ollama (OPENAI_API_KEY)")
    p.add_argument("--ai-base-url", default="https://api.openai.com/v1",
                   help="base URL for --ai-provider openai (e.g. http://localhost:11434/v1 "
                        "for Ollama, https://openrouter.ai/api/v1)")
    p.add_argument("--model", default="",
                   help="model id (default: claude-sonnet-5 / gpt-4o-mini per provider)")
    p.add_argument("-o", "--output", help="write findings as JSON to this file")
    sp = p.add_argument_group("password-spray (authorized use only)")
    sp.add_argument("--spray", action="store_true",
                    help="password-spray mode instead of content discovery")
    sp.add_argument("--auth", choices=["basic", "form"], default="basic",
                    help="auth type: HTTP Basic or POST form (default basic)")
    sp.add_argument("--users", default="",
                    help="usernames: comma-list or @file")
    sp.add_argument("--passwords", default=DEFAULT_PASSWORDS,
                    help="password list path (default: bundled weak-passwords.txt)")
    sp.add_argument("--data",
                    help="form body template, e.g. 'user=^USER^&pass=^PASS^'")
    sp.add_argument("--fail", help="string present in body on FAILED form login")
    sp.add_argument("--success", help="string present in body on SUCCESSFUL form login")
    sp.add_argument("--round-delay", type=float, default=0,
                    help="seconds to wait between password rounds (anti-lockout)")
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("-V", "--version", action="version", version=f"dirsociety {__version__}")
    return p


def _run_spray(a, target, fetcher):
    if not a.users:
        sys.stderr.write("--spray requires --users (comma-list or @file)\n")
        return 2
    if a.auth == "form":
        if not a.data:
            sys.stderr.write("--auth form requires --data 'user=^USER^&pass=^PASS^'\n")
            return 2
        if not (a.fail or a.success):
            sys.stderr.write("--auth form requires --fail or --success to detect login\n")
            return 2
    pw_path = _resolve_wordlist(a.passwords)
    if pw_path is None:
        sys.stderr.write(f"password list not found: {a.passwords}\n")
        return 2
    users = load_list(a.users)
    passwords = load_list("@" + pw_path)
    sys.stderr.write(f"[*] spraying {target} auth={a.auth} "
                     f"users={len(users)} passwords={len(passwords)}\n")
    hits = spray(fetcher, target, users, passwords, a.auth, a.data,
                 a.fail, a.success, a.round_delay)
    sys.stderr.write(f"[*] done: {len(hits)} valid credential(s)\n\n")
    for u, pw, st in hits:
        print(f"[+] VALID  {u}:{pw}  (HTTP {st})")
    if not hits:
        print("[-] no valid credentials found")
    if a.output:
        with open(a.output, "w") as fp:
            json.dump({"target": target, "auth": a.auth,
                       "hits": [{"user": u, "password": p, "status": s}
                                for u, p, s in hits]}, fp, indent=2)
        sys.stderr.write(f"[*] JSON written to {a.output}\n")
    return 0


def main(argv=None):
    try:
        return _run(argv)
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Dibatalkan (Ctrl+C).\n")
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(130)  # skip threadpool atexit-join (avoids ugly shutdown traceback)


def _run(argv=None):
    a = build_parser().parse_args(argv)

    if not a.spray:
        wl = _resolve_wordlist(a.wordlist)
        if wl is None:
            sys.stderr.write(f"wordlist not found: {a.wordlist}\n"
                             f"  give a real path, or a bundled name: dirsociety / common / indonesia\n")
            return 2
        a.wordlist = wl

    base = a.url if a.url.endswith("/") else a.url + "/"
    host = urlparse(base).netloc
    exts = [e for e in a.extensions.split(",") if e]
    codes = {int(c) for c in a.codes.split(",") if c.strip()} if a.codes else None

    jitter = None
    threads = a.threads
    if a.stealth:
        threads, jitter = min(threads, 4), (0.4, 1.8)
    if a.delay:
        lo, hi = a.delay.split(",")
        jitter = (float(lo), float(hi))

    if not a.no_banner:
        sys.stderr.write(banner(base, threads, a.stealth, a.wordlist, exts) + "\n\n")

    headers = {"Accept": "*/*", "Connection": "keep-alive"}
    for hh in a.header:
        if ":" in hh:
            k, v = hh.split(":", 1)
            headers[k.strip()] = v.strip()

    fetcher = Fetcher(a.stealth, headers, a.timeout, jitter, host, a.follow_redirects)

    if a.spray:
        return _run_spray(a, base, fetcher)

    cal = calibrate(fetcher, base, exts)
    sys.stderr.write(f"[*] soft-404 calibration: {cal}\n"
                     f"[*] scanning {base} (threads={threads}, stealth={a.stealth})\n")

    color = os.environ.get("NO_COLOR") is None and sys.stdout.isatty()

    def on_hit(f):
        mark = "[!]" if f["tags"] else ("[+]" if f.get("bypass") else "   ")
        loc = f"  ->  {f['location']}" if f.get("location") else ""
        st = _color_status(f["status"], color)
        print(f"{mark} {st}  {f['url']}  ({_human(f['length'])}){loc}")
        for tech, code in f.get("bypass", []):
            print(f"      {_c(f'-> 403 BYPASS via {tech} => {code}', '1;32', color)}")
        sys.stdout.flush()

    import time
    t0 = time.time()
    findings, total, stopped, rate_limited, aborted = scan(base, a.wordlist, exts, threads,
                                                           fetcher, cal, codes,
                                                           not a.no_bypass, on_hit=on_hit)
    dt = time.time() - t0
    rate = total / dt if dt else 0
    if stopped:
        sys.stderr.write(f"\n[!] Scan dihentikan (Ctrl+C) — hasil parsial "
                         f"({len(findings)} hits / {total} requests)\n")
    else:
        sys.stderr.write(f"[*] done: {len(findings)} hits from {total} requests "
                         f"in {dt:.1f}s ({rate:.0f} req/s)\n")
    if aborted:
        sys.stderr.write(_c(
            "[!] DIHENTIKAN DINI: target me-rate-limit (429) hampir semua request.\n"
            "    IP-mu kemungkinan sudah di-throttle situs ini. Yang bisa dilakukan:\n"
            "    - tunggu beberapa menit lalu coba lagi\n"
            "    - --stealth  atau  -t 3 --delay 1,3   (lebih pelan)\n"
            "    - pakai proxy/VPN (ganti IP)\n", "1;33", color))
    elif rate_limited:
        pct = rate_limited * 100 // total if total else 0
        sys.stderr.write(_c(
            f"[!] target rate-limit (429) pada {rate_limited} request ({pct}%) — sebagian hasil hilang.\n"
            f"    pelan-pelankan: --stealth  |  -t 5  |  --delay 0.5,2\n", "1;33", color))

    summary = {}
    for f in findings:
        summary[f["status"]] = summary.get(f["status"], 0) + 1

    if summary:
        parts = " | ".join(f"{_color_status(s, color)}:{n}" for s, n in sorted(summary.items()))
        print(f"\n  {parts}")

    # flag redirect clusters: many paths -> same Location = likely auth/catch-all, not distinct finds
    locs = {}
    for f in findings:
        if f.get("location"):
            locs[f["location"]] = locs.get(f["location"], 0) + 1
    for loc, n in sorted(locs.items(), key=lambda x: -x[1]):
        if n >= 10:
            print(_c(f"  note: {n} path -> {loc} (kemungkinan catch-all/auth, bukan {n} temuan berbeda)",
                     "90", color))

    if a.ai and not stopped:
        print("\n=== AI TRIAGE ===")
        print(analyze(findings, a.model, base, a.ai_provider, a.ai_base_url))

    if a.output:
        with open(a.output, "w") as fp:
            json.dump({"target": base, "total_requests": total, "findings": findings},
                      fp, indent=2)
        sys.stderr.write(f"[*] JSON written to {a.output}\n")

    if stopped:  # in-flight worker threads still alive; skip atexit-join
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(130)
    return 0
