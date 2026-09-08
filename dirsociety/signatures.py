"""Signature-based flagging of potentially vulnerable / sensitive paths."""
import re

VULN_SIGS = [
    (re.compile(r"\.git($|/)"),                 "Git repo exposed — source bisa di-dump (git-dumper)"),
    (re.compile(r"\.svn($|/)"),                 "SVN metadata exposed"),
    (re.compile(r"\.env$"),                     "Environment file — kemungkinan kredensial/secret"),
    (re.compile(r"\.(sql|dump)$"),              "Database dump — data sensitif"),
    (re.compile(r"\.(bak|old|backup|save|swp|swo|orig|tmp)$"), "Backup file — mungkin berisi source/secret"),
    (re.compile(r"\.(tar\.gz|tgz|zip|rar|7z|tar)$"), "Archive — kemungkinan backup source/data"),
    (re.compile(r"(config|configuration|settings|secrets)\.(php|json|ya?ml|xml|ini|js)$"), "File konfigurasi"),
    (re.compile(r"(admin|manager|dashboard|phpmyadmin|wp-admin|adminer)($|/|\.)"), "Panel admin"),
    (re.compile(r"\.log$"),                     "Log file — bisa bocorkan info internal"),
    (re.compile(r"(id_rsa|id_dsa|\.ssh|\.htpasswd|\.aws|\.netrc)"), "Kredensial / kunci privat"),
    (re.compile(r"(swagger|openapi|api-docs|graphql|actuator|metrics|debug)"), "API surface / debug endpoint"),
    (re.compile(r"(\.DS_Store|web\.config|\.npmrc|composer\.lock|package-lock\.json|yarn\.lock)$"), "Metadata bocor"),
    (re.compile(r"(phpinfo|info)\.php$"),       "phpinfo — bocorkan konfigurasi server"),
    (re.compile(r"(backup|dump|export|old|test|dev|staging)($|/)"), "Direktori berisiko (backup/dev/test)"),
]


def vuln_tags(path):
    """Return list of human-readable risk notes matching this path."""
    return [msg for rx, msg in VULN_SIGS if rx.search(path)]
