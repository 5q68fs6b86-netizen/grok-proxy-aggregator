#!/usr/bin/env python3
"""
Call a Grok/OpenAI-compatible chat API, extract .yaml URLs from the response,
and test URLs whose host is explicitly allowed, or all extracted URLs with
--no-host-filter.

This script is intended for authorized assets only. Do not use it to collect or
validate third-party leaked proxy subscriptions or credentials.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlparse

import requests


URL_RE = re.compile(r"https?://[^\s<>'\"`]+?\.ya?ml(?:\?[^\s<>'\"`]*)?", re.IGNORECASE)
RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}


@dataclass(frozen=True)
class UrlCheck:
    url: str
    ok: bool
    status_code: int | None
    content_type: str
    bytes_read: int
    error: str


def read_prompt(args: argparse.Namespace) -> str:
    if args.prompt:
        return args.prompt
    if args.prompt_file:
        with open(args.prompt_file, "r", encoding="utf-8") as f:
            return f.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit("Provide --prompt, --prompt-file, or pipe a prompt on stdin.")


def response_excerpt(response: requests.Response, limit: int = 400) -> str:
    text = response.text.strip().replace("\r", " ").replace("\n", " ")
    if not text:
        return "<empty>"
    return text[:limit] + ("..." if len(text) > limit else "")


def extract_message_content(payload: dict) -> str:
    try:
        choice = payload["choices"][0]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"Unexpected API response shape: {payload!r}") from exc

    message = choice.get("message")
    if isinstance(message, dict) and isinstance(message.get("content"), str):
        return message["content"]

    delta = choice.get("delta")
    if isinstance(delta, dict) and isinstance(delta.get("content"), str):
        return delta["content"]

    raise RuntimeError(f"Unexpected API response shape: {payload!r}")


def parse_sse_chat_response(body: str) -> str:
    chunks: list[str] = []
    saw_data = False
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or not stripped.startswith("data:"):
            continue
        data = stripped[5:].strip()
        if not data:
            continue
        saw_data = True
        if data == "[DONE]":
            break
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid SSE JSON chunk: {data[:200]!r}") from exc

        choice = payload.get("choices", [{}])[0]
        delta = choice.get("delta")
        if isinstance(delta, dict) and isinstance(delta.get("content"), str):
            chunks.append(delta["content"])
            continue

        message = choice.get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            chunks.append(message["content"])

    if saw_data and chunks:
        return "".join(chunks)
    raise RuntimeError("Chat API returned SSE data without any message content.")


def parse_chat_response(response: requests.Response, endpoint: str) -> str:
    try:
        payload = response.json()
    except ValueError:
        body = response.text
        if body.lstrip().startswith("data:"):
            return parse_sse_chat_response(body)
        raise RuntimeError(
            f"Chat API returned non-JSON response from {endpoint}; "
            f"response={response_excerpt(response)!r}"
        )
    return extract_message_content(payload)


def call_chat_api(
    base_url: str,
    api_key: str,
    model: str,
    prompt: str,
    timeout: float,
    retries: int,
    retry_delay: float,
) -> str:
    endpoint = base_url.rstrip("/") + "/chat/completions"
    last_error = ""
    for attempt in range(retries + 1):
        try:
            response = requests.post(
                endpoint,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0,
                    "stream": False,
                },
                timeout=timeout,
            )
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < retries:
                time.sleep(retry_delay * (attempt + 1))
                continue
            raise RuntimeError(f"Chat API request failed after {attempt + 1} attempts: {last_error}") from exc
        except requests.RequestException as exc:
            raise RuntimeError(f"Chat API request failed: {exc}") from exc

        if response.status_code in RETRYABLE_STATUS_CODES and attempt < retries:
            last_error = (
                f"HTTP {response.status_code} from {endpoint}; "
                f"response={response_excerpt(response)!r}"
            )
            time.sleep(retry_delay * (attempt + 1))
            continue

        if response.status_code >= 400:
            raise RuntimeError(
                f"Chat API returned HTTP {response.status_code} from {endpoint}; "
                f"response={response_excerpt(response)!r}"
            )

        return parse_chat_response(response, endpoint)

    raise RuntimeError(f"Chat API request failed after retries: {last_error}")


def extract_yaml_urls(text: str) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for match in URL_RE.finditer(text):
        url = match.group(0).rstrip(").,;]")
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def host_allowed(url: str, allowed_hosts: set[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in allowed_hosts


def check_url(url: str, timeout: float, max_bytes: int) -> UrlCheck:
    try:
        with requests.get(url, timeout=timeout, stream=True, allow_redirects=True) as response:
            content_type = response.headers.get("content-type", "")
            chunk = response.raw.read(max_bytes + 1, decode_content=True)
            bytes_read = len(chunk[:max_bytes])
            ok = (
                response.status_code == 200
                and bytes_read > 0
                and len(chunk) <= max_bytes
                and looks_like_yaml(chunk[:max_bytes])
            )
            error = "" if ok else "not a reachable YAML document within size/status constraints"
            return UrlCheck(url, ok, response.status_code, content_type, bytes_read, error)
    except requests.RequestException as exc:
        return UrlCheck(url, False, None, "", 0, str(exc))


def looks_like_yaml(data: bytes) -> bool:
    sample = data[:2048].decode("utf-8", errors="ignore").strip()
    if not sample:
        return False
    return any(marker in sample for marker in (":", "- ", "proxies:", "proxy-groups:", "rules:"))


def write_csv(path: str, rows: Iterable[UrlCheck]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["url", "ok", "status_code", "content_type", "bytes_read", "error"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row.__dict__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompt", help="Prompt text to send to the model.")
    parser.add_argument("--prompt-file", help="UTF-8 prompt file to send to the model.")
    parser.add_argument("--base-url", default=os.getenv("GROK_API_BASE", "https://api.x.ai/v1"))
    parser.add_argument("--model", default=os.getenv("GROK_MODEL", "grok-4.20-multi-agent-xhigh"))
    parser.add_argument("--api-key", default=os.getenv("GROK_API_KEY"))
    parser.add_argument("--allow-host", action="append", default=[], help="Authorized host to test.")
    parser.add_argument(
        "--no-host-filter",
        action="store_true",
        help="Test all extracted YAML URLs without applying the allow-host filter.",
    )
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--retries", type=int, default=2, help="Retry count for transient chat API failures.")
    parser.add_argument("--retry-delay", type=float, default=1.5, help="Base delay in seconds between retries.")
    parser.add_argument("--max-bytes", type=int, default=1_000_000)
    parser.add_argument("--out", default="authorized_yaml_report.csv")
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        if not args.api_key:
            raise SystemExit("Set GROK_API_KEY or pass --api-key.")
        allowed_hosts = {host.lower() for host in args.allow_host}
        if not args.no_host_filter and not allowed_hosts:
            raise SystemExit("Pass at least one --allow-host for assets you are authorized to test.")

        prompt = read_prompt(args)
        model_output = call_chat_api(
            args.base_url,
            args.api_key,
            args.model,
            prompt,
            args.timeout,
            args.retries,
            args.retry_delay,
        )
        urls = extract_yaml_urls(model_output)
        checked_urls = urls if args.no_host_filter else [url for url in urls if host_allowed(url, allowed_hosts)]
        checks = [check_url(url, args.timeout, args.max_bytes) for url in checked_urls]
        write_csv(args.out, checks)

        summary = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "model": args.model,
            "host_filter_enabled": not args.no_host_filter,
            "extracted_yaml_urls": len(urls),
            "allowed_yaml_urls": len(checked_urls),
            "checked_yaml_urls": len(checked_urls),
            "valid_yaml_urls": sum(1 for check in checks if check.ok),
            "report": args.out,
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    raise SystemExit(main())
