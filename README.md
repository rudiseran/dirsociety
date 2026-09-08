# dirsociety

**Fast, stealthy web content-discovery scanner** — like `dirsearch`/`ffuf`, plus
automatic **403/401 bypass**, **soft-404 calibration** for accuracy, and optional
**AI triage** of findings. Pure Python standard library — **no dependencies**.

> ⚠️ **Authorized use only.** Run `dirsociety` exclusively against systems you own or
> have explicit written permission to test. You are solely responsible for your use.

## Features

- 📁 **Directory / file discovery** from any wordlist, with extension expansion (`-x php,bak,zip`).
- 🥷 **Stealth mode** (`--stealth`): low concurrency + randomized request jitter + User-Agent rotation to stay quiet.
- 🎯 **Accuracy**: calibrates the server's soft-404 / wildcard response and filters false positives automatically.
- 🔓 **403/401 bypass**: on every forbidden hit, tries header tricks (`X-Forwarded-For`, `X-Original-URL`, …), path mutations (`..;/`, `;/`, trailing slash/space/case), and HTTP method overrides.
- ‼️ **Vulnerability signals**: flags exposed `.git`, `.env`, backups/dumps, admin panels, private keys, debug/API endpoints, and more.
- 🤖 **AI triage** (`--ai`): sends findings to Claude (Anthropic API) to rank the most likely vulnerabilities and suggest verification steps.
- 🧵 **Speed**: multithreaded; hundreds of requests/sec in normal mode.
- 📦 **Output**: colored console summary + optional JSON (`-o`).

## Install

```bash
git clone https://github.com/rudiseran/dirsociety.git
cd dirsociety
# run directly — no install needed:
python -m dirsociety --help
# or install as a command:
pip install .
dirsociety --help
```

Requires **Python 3.8+**. No third-party packages.

## Usage

```bash
# basic scan with the bundled wordlist
python -m dirsociety -u https://target

# bundled list by short name (works from any directory)
dirsociety -u https://target -w indonesia      # or: common / dirsociety

# external wordlists (dirb / SecLists) by full path
dirsociety -u https://target -w /usr/share/dirb/wordlists/common.txt
dirsociety -u https://target -w /usr/share/seclists/Discovery/Web-Content/common.txt

# -x appends extensions: each word is also tried with .php .bak .zip
# (e.g. "admin" -> admin, admin.php, admin.bak, admin.zip)
dirsociety -u https://target -w /path/to/words.txt -x php,bak,zip,old

# stealth + AI triage + JSON output
export ANTHROPIC_API_KEY=sk-ant-...
python -m dirsociety -u https://target --stealth --ai -o results.json

# only interesting codes, custom header, tuned jitter
python -m dirsociety -u https://target --codes 200,301,403 \
  -H "Cookie: session=abc" --delay 0.5,2
```

### Options

| Flag | Description |
|------|-------------|
| `-u, --url` | Target base URL (required) |
| `-w, --wordlist` | Wordlist path, or bundled name: `dirsociety` (default ~12.7k), `big` (~106k), `common`, `indonesia` |
| `-x, --extensions` | Comma-separated extensions to append |
| `-t, --threads` | Concurrency (default 40; capped at 4 in stealth) |
| `--stealth` | Low concurrency + jitter + UA rotation |
| `--delay min,max` | Random per-request delay in seconds |
| `--codes` | Only report these status codes |
| `--no-bypass` | Skip 403/401 bypass attempts |
| `--follow-redirects` | Follow 3xx (default: report them with `Location`, like dirsearch) |
| `-H, --header` | Extra request header (repeatable) |
| `--ai` | Triage findings with an LLM (see `--ai-provider`) |
| `--ai-provider` | `anthropic` or `openai` (OpenAI-compatible) |
| `--ai-base-url` | Base URL for `openai` provider (Ollama/OpenRouter/…) |
| `--model` | Model id (default per provider) |
| `-o, --output` | Write findings as JSON |

## AI triage providers

`--ai` supports two backends — the `openai` one is any OpenAI-compatible
`/chat/completions` endpoint, which covers most providers and local models.

```bash
# Anthropic (default)
export ANTHROPIC_API_KEY=sk-ant-...
dirsociety -u https://target --ai

# OpenAI
export OPENAI_API_KEY=sk-...
dirsociety -u https://target --ai --ai-provider openai --model gpt-4o

# Groq / OpenRouter / DeepSeek / Together (OpenAI-compatible)
export OPENAI_API_KEY=<your-key>
dirsociety -u https://target --ai --ai-provider openai \
  --ai-base-url https://openrouter.ai/api/v1 --model deepseek/deepseek-chat

# Local Ollama — no API key needed
dirsociety -u https://target --ai --ai-provider openai \
  --ai-base-url http://localhost:11434/v1 --model llama3.1
```

## Password-spray mode (`--spray`)

Test weak credentials against **HTTP Basic auth** or a **POST login form**. Sprays
password-outer / user-inner (low-and-slow); `--round-delay` pauses between password
rounds to reduce lockout risk. Uses the bundled `weak-passwords.txt` by default.

```bash
# HTTP Basic auth
dirsociety -u https://target/protected --spray --auth basic \
  --users admin,root,operator

# POST login form — give the body template + a failure string oracle
dirsociety -u https://target/login --spray --auth form \
  --data 'user=^USER^&pass=^PASS^' --fail "Login gagal" \
  --users @users.txt --passwords dirsociety/wordlists/weak-passwords.txt \
  --stealth --round-delay 5
```

Form mode needs `--data` (with `^USER^`/`^PASS^` markers) **and** either `--fail`
(string shown on failed login) or `--success` (string shown on success). `--users`
takes a comma-list or `@file`.

## Bundled wordlists (`dirsociety/wordlists/`)

| File | Entries | Use |
|------|--------:|-----|
| `dirsociety.txt` | ~12,700 | **Default** — dirsearch `dicc.txt` with its default extensions expanded (php,asp,aspx,jsp,html,htm) + our Indonesian & leak lists. **dirsearch-parity coverage out of the box**, at dirsearch-like speed |
| `big.txt` | ~106,000 | **Max coverage** (`-w big`) — the default plus SecLists raft-large. Deepest, but many more requests (slower) |
| `common.txt` | 130 | Small/fast high-signal list — quick sweeps |
| `indonesia.txt` | 174 | Path bernuansa Indonesia (PHP native, instansi, bank, e-commerce, kampus): `masuk`, `koneksi.php`, `keuangan`, `data_nasabah`, `cadangan.sql`, … |
| `weak-passwords.txt` | 119 | Weak-password list for **authorized** password audits (`Bank2006`, `P@ssw0rd`, `Admin@123`, kota/bank + tahun, leetspeak) |

```bash
# scan pakai wordlist Indonesia
dirsociety -u https://target -w dirsociety/wordlists/indonesia.txt
```

> Note: content discovery memakai path wordlists (`dirsociety.txt`, `common.txt`,
> `indonesia.txt`). `weak-passwords.txt` dipakai oleh mode `--spray`.

## Output legend

- `[!]` — path matched an **interest signature** (sensitive/exposed name) — a lead to
  check manually, **not** a confirmed vulnerability.
- `[+]` — a **403/401 was bypassed**.
- Each line shows status code, URL, and response size. A `note:` line flags a redirect
  to a login page (likely protected, not a finding).

## Tests

```bash
python tests/test_dirsociety.py      # or: python -m pytest
```

## Credits & licensing

- **Code:** MIT — see [LICENSE](LICENSE).
- **Wordlists** `dirsociety.txt` (default) and `big.txt` combine our own lists (MIT),
  [dirsearch](https://github.com/maurosoria/dirsearch) `dicc.txt` (GPL-2.0), and — for
  `big.txt` only — [SecLists](https://github.com/danielmiessler/SecLists) raft-large (MIT).
  Because they include GPL-2.0 entries, **those two files are distributed under GPL-2.0**
  (the code stays MIT — the wordlists are bundled as data, mere aggregation). For a 100%
  MIT build, delete them and use `common.txt`/`indonesia.txt` or your own via `-w`.

See [NOTICE](NOTICE) for full attribution.
