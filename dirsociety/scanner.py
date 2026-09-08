"""Core scanning: HTTP fetch, soft-404 calibration, wordlist expansion, worker."""
import concurrent.futures as cf
import hashlib
import os
import random
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse, quote

from .bypass import try_bypass
from .signatures import vuln_tags

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


def _sslctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE  # pentest targets are often self-signed
    return c
SSLCTX = _sslctx()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # report 3xx as a finding instead of following it


_OPENER_FOLLOW = urllib.request.build_opener(urllib.request.HTTPSHandler(context=SSLCTX))
_OPENER_NOFOLLOW = urllib.request.build_opener(
    _NoRedirect, urllib.request.HTTPSHandler(context=SSLCTX))


class Fetcher:
    def __init__(self, ua_rotate, base_headers, timeout, jitter, host, follow=False):
        self.ua_rotate = ua_rotate
        self.base_headers = base_headers
        self.timeout = timeout
        self.jitter = jitter          # (min,max) seconds or None
        self.host = host
        self.opener = _OPENER_FOLLOW if follow else _OPENER_NOFOLLOW

    def get(self, url, method="GET", extra=None, data=None):
        if self.jitter:
            time.sleep(random.uniform(*self.jitter))
        h = dict(self.base_headers)
        h["User-Agent"] = random.choice(UA_POOL) if self.ua_rotate else UA_POOL[0]
        if data is not None and not any(k.lower() == "content-type" for k in h):
            h["Content-Type"] = "application/x-www-form-urlencoded"
        if extra:
            for k, v in extra.items():
                v = url if v == "PATH" else (self.host if v == "SAMEHOST" else v)
                h[k] = v
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            r = self.opener.open(req, timeout=self.timeout)
            body = r.read(65536)
            return r.status, len(body), body, r.headers.get("Location")
        except urllib.error.HTTPError as e:
            body = e.read(65536)
            return e.code, len(body), body, e.headers.get("Location")
        except Exception:
            return None, 0, b"", None  # transient/timeout — single attempt (retry hurts under rate-limit)


def calibrate(fetcher, base, exts=None):
    """Fingerprint the server's response to random nonexistent paths so we can
    filter soft-404s / wildcard responders (accuracy). Probes a bare random path
    and one per extension, recording (status, length, location) — the Location
    catches apps that redirect every unknown path to /login or /home.
    Returns a list of such signatures."""
    sigs = []
    suffixes = [""] + [f".{e.lstrip('.')}" for e in (exts or [])]
    for suf in suffixes:
        rnd = "zz" + hashlib.md5(os.urandom(8)).hexdigest()[:20] + suf
        st, ln, _, loc = fetcher.get(urljoin(base, rnd))
        sig = (st, ln, loc)
        if sig not in sigs:
            sigs.append(sig)
    return sigs


def is_soft404(status, length, cal, location=None, tol=48):
    """True if this response matches the server's catch-all. Redirects match on
    Location (an app that 302s all unknown paths to the same place); others match
    on status + approximate length."""
    for st, ln, loc in cal:
        if status != st:
            continue
        if loc or location:
            if loc == location:
                return True
        elif abs(length - ln) <= tol:
            return True
    return False


def build_paths(wordlist, exts):
    """Yield each word plus word.<ext> for every requested extension."""
    with open(wordlist, encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            w = w.lstrip("/")
            yield w
            for e in exts:
                yield f"{w}.{e.lstrip('.')}"


def scan(base, wordlist, exts, threads, fetcher, cal, codes, do_bypass,
         on_hit=None, progress=True):
    """Run the scan, streaming each finding to on_hit(f) as it is discovered.
    Returns (findings, requests_done, stopped)."""
    paths = list(build_paths(wordlist, exts))
    total = len(paths)
    findings, lock, done, errors, rl = [], threading.Lock(), [0], [0], [0]
    t0 = time.time()

    def draw():
        el = time.time() - t0
        rate = done[0] / el if el else 0
        pct = done[0] * 100 // total if total else 0
        extra = f"  rate-limited:{rl[0]}" if rl[0] else ""
        sys.stderr.write(f"\r[*] {done[0]}/{total} ({pct}%)  {rate:.0f}/s  "
                         f"errors:{errors[0]}{extra}   ")
        sys.stderr.flush()

    def work(p):
        url = urljoin(base, quote(p, safe="/._-~"))
        st, ln, _, loc = fetcher.get(url)
        hit = None
        # 429 = rate-limited, not a discovery — count it, never report it as a hit
        if st is not None and st not in (404, 429) and not is_soft404(st, ln, cal, loc) \
                and not (codes and st not in codes):
            hit = {"url": url, "path": p, "status": st, "length": ln, "tags": vuln_tags(p)}
            if loc:
                hit["location"] = loc
            if st in (403, 401) and do_bypass:
                wins = try_bypass(fetcher, url, "/" + p)
                if wins:
                    hit["bypass"] = wins
        with lock:
            done[0] += 1
            if st is None:
                errors[0] += 1
            elif st == 429:
                rl[0] += 1
            if hit is not None:
                findings.append(hit)
                if on_hit and progress:
                    sys.stderr.write("\r" + " " * 60 + "\r")  # clear progress line
                if on_hit:
                    on_hit(hit)
            if progress and (hit is not None or done[0] % 50 == 0):
                draw()
        return None

    stopped = False
    ex = cf.ThreadPoolExecutor(max_workers=threads)
    try:
        list(ex.map(work, paths))
    except KeyboardInterrupt:
        stopped = True
        ex.shutdown(wait=False, cancel_futures=True)  # drop the queued rest, quit fast
    else:
        ex.shutdown(wait=True)
    if progress:
        sys.stderr.write("\r" + " " * 60 + "\r")
    findings.sort(key=lambda f: (not f["tags"], f["status"]))
    return findings, done[0] if stopped else total, stopped, rl[0]
