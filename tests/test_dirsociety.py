"""Runnable checks for dirsociety core logic. Run: python -m pytest, or just
`python tests/test_dirsociety.py` (uses asserts, no framework required)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dirsociety.scanner import is_soft404, build_paths
from dirsociety.signatures import vuln_tags
from dirsociety.bypass import path_variants
from dirsociety.spray import load_list, _basic_ok, _form_ok


def test_soft404():
    cal = [(200, 100, None), (200, 110, None)]
    assert is_soft404(200, 105, cal)          # within tolerance of catch-all
    assert not is_soft404(200, 5000, cal)     # real, distinct page
    assert not is_soft404(301, 100, cal)      # different status
    # redirect catch-all: app 302s every unknown path to /login
    rcal = [(302, 0, "/login.jsp")]
    assert is_soft404(302, 0, rcal, "/login.jsp")       # same redirect target -> soft
    assert not is_soft404(302, 0, rcal, "/admin/panel")  # different target -> real


def test_vuln_tags():
    assert vuln_tags(".git/config")
    assert vuln_tags(".env")
    assert vuln_tags("backup.sql")
    assert vuln_tags("admin")
    assert not vuln_tags("index.html")


def test_path_variants():
    v = path_variants("/admin")
    assert "/admin/" in v
    assert "/admin;/" in v
    assert "/admin..;/" in v


def test_build_paths():
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as t:
        t.write("admin\n# comment\n\n/login\n")
        name = t.name
    try:
        got = list(build_paths(name, ["php", ".bak"]))
        assert got == ["admin", "admin.php", "admin.bak",
                       "login", "login.php", "login.bak"], got
    finally:
        os.unlink(name)


def test_spray_oracle():
    assert _basic_ok(200) and _basic_ok(302)
    assert not _basic_ok(401) and not _basic_ok(None)
    # form: success oracle
    assert _form_ok(200, b"Welcome back, admin", None, "Welcome back")
    assert not _form_ok(200, b"Login gagal", None, "Welcome back")
    # form: fail oracle (failure string absent => success)
    assert _form_ok(200, b"redirecting to /home", "Login gagal", None)
    assert not _form_ok(200, b"Login gagal, coba lagi", "Login gagal", None)
    # no oracle => never a hit
    assert not _form_ok(200, b"whatever", None, None)


def test_load_list(tmpfile=None):
    assert load_list("admin,root,user") == ["admin", "root", "user"]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as t:
        t.write("admin\n#skip\n\nroot\n")
        name = t.name
    try:
        assert load_list("@" + name) == ["admin", "root"]
    finally:
        os.unlink(name)


if __name__ == "__main__":
    for fn in [test_soft404, test_vuln_tags, test_path_variants, test_build_paths,
               test_spray_oracle, test_load_list]:
        fn()
        print(f"ok  {fn.__name__}")
    print("all checks passed")
