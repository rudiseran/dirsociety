"""Optional AI triage of findings (stdlib only, no SDK).

Two providers cover almost everything:
  - anthropic : Anthropic Messages API (ANTHROPIC_API_KEY)
  - openai    : any OpenAI-compatible /chat/completions endpoint — OpenAI, Groq,
                OpenRouter, DeepSeek, Together, and local Ollama / LM Studio.
                Key from OPENAI_API_KEY (optional for local servers).
"""
import json
import urllib.request

from .scanner import SSLCTX
import os

DEFAULT_MODEL = {"anthropic": "claude-sonnet-5", "openai": "gpt-4o-mini"}


def _prompt(findings, target):
    items = "\n".join(
        f"- [{f['status']}] {f['url']}"
        + (f"  TAGS={f['tags']}" if f.get("tags") else "")
        + ("  BYPASSED" if f.get("bypass") else "")
        for f in findings[:150]
    )
    return (f"Kamu analis keamanan aplikasi web. Target (uji terotorisasi): {target}\n"
            f"Berikut hasil content-discovery. Urutkan temuan yang paling berpotensi "
            f"rentan, jelaskan singkat kenapa berisiko, dan beri langkah verifikasi "
            f"manual yang aman. Jawab ringkas dalam Bahasa Indonesia.\n\n{items}")


def _post(url, headers, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=90, context=SSLCTX) as r:
        return json.load(r)


def _anthropic(prompt, model):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return "[AI dilewati: set ANTHROPIC_API_KEY]"
    data = _post("https://api.anthropic.com/v1/messages",
                 {"x-api-key": key, "anthropic-version": "2023-06-01",
                  "content-type": "application/json"},
                 {"model": model, "max_tokens": 1500,
                  "messages": [{"role": "user", "content": prompt}]})
    return data["content"][0]["text"]


def _openai(prompt, model, base_url):
    headers = {"content-type": "application/json"}
    key = os.environ.get("OPENAI_API_KEY")
    if key:  # optional: local Ollama/LM Studio need no key
        headers["Authorization"] = "Bearer " + key
    data = _post(base_url.rstrip("/") + "/chat/completions", headers,
                 {"model": model, "max_tokens": 1500,
                  "messages": [{"role": "user", "content": prompt}]})
    return data["choices"][0]["message"]["content"]


def analyze(findings, model, target, provider="anthropic",
            base_url="https://api.openai.com/v1"):
    if not findings:
        return "[AI dilewati: tidak ada temuan]"
    model = model or DEFAULT_MODEL.get(provider)
    prompt = _prompt(findings, target)
    try:
        if provider == "anthropic":
            return _anthropic(prompt, model)
        return _openai(prompt, model, base_url)
    except Exception as e:
        return f"[AI error ({provider}): {e}]"
