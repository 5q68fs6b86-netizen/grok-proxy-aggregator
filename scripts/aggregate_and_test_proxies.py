#!/usr/bin/env python3
"""
Aggregate YAML proxies from CSV report, test with mihomo, group by country,
and generate a production mihomo config.

Workflow:
1. Parse CSV report for status 200 YAML URLs
2. Download and parse YAML/base64 subscriptions
3. Deduplicate proxies by (type, server, port, credential)
4. Start mihomo daemon and test latency via REST API
5. Filter proxies with latency < threshold
6. GeoIP lookup to determine country
7. Group working proxies by country
8. Generate final mihomo config with country groups
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import requests
import yaml


BASE64_PROXY_RE = re.compile(
    r"(vmess|vless|trojan|ss|ssr|hysteria|tuic)://[^\s]+",
    re.IGNORECASE,
)

IP_API_BATCH = "http://ip-api.com/batch"
MIHOMO_API_PORT = 9090
MIHOMO_API_BASE = f"http://127.0.0.1:{MIHOMO_API_PORT}"


def flag(code: str) -> str:
    """Country flag emoji from ISO code."""
    if not code or len(code) != 2:
        return "🌐"
    return chr(0x1F1E6 + ord(code[0]) - 65) + chr(0x1F1E6 + ord(code[1]) - 65)


@dataclass(frozen=True)
class Proxy:
    name: str
    type: str
    server: str
    port: int
    password: str | None = None
    uuid: str | None = None
    cipher: str | None = None
    alter_id: int = 0
    udp: bool = False
    tls: bool = False
    sni: str | None = None
    skip_cert_verify: bool = False
    network: str | None = None
    ws_path: str | None = None
    ws_headers: dict | None = None
    plugin: str | None = None
    plugin_opts: str | None = None
    country: str | None = None
    country_code: str | None = None

    def key(self) -> tuple:
        return (self.type, self.server, self.port, self.password or self.uuid)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name, "type": self.type,
            "server": self.server, "port": self.port,
        }
        if self.password: d["password"] = self.password
        if self.uuid: d["uuid"] = self.uuid
        if self.cipher: d["cipher"] = self.cipher
        if self.type == "vmess":
            d["alterId"] = self.alter_id
            if not self.cipher: d["cipher"] = "auto"
        if self.udp: d["udp"] = True
        if self.tls: d["tls"] = True
        if self.sni: d["sni"] = self.sni
        if self.skip_cert_verify: d["skip-cert-verify"] = True
        if self.network: d["network"] = self.network
        if self.ws_path: d["ws-path"] = self.ws_path
        if self.ws_headers: d["ws-headers"] = self.ws_headers
        if self.plugin: d["plugin"] = self.plugin
        if self.plugin_opts: d["plugin-opts"] = self.plugin_opts
        return d

    def with_country(self, country: str, code: str) -> "Proxy":
        prefix = f"[{code}]" if not self.name.startswith("[") else ""
        return Proxy(
            name=f"{prefix}{self.name}", type=self.type,
            server=self.server, port=self.port,
            password=self.password, uuid=self.uuid,
            cipher=self.cipher, alter_id=self.alter_id,
            udp=self.udp, tls=self.tls, sni=self.sni,
            skip_cert_verify=self.skip_cert_verify,
            network=self.network, ws_path=self.ws_path,
            ws_headers=self.ws_headers, plugin=self.plugin,
            plugin_opts=self.plugin_opts,
            country=country, country_code=code,
        )


@dataclass
class CountryGroup:
    code: str
    name: str
    proxies: list[Proxy] = field(default_factory=list)
    avg_latency: float = 0.0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--out", default="proxy_report.csv")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--max-proxies", type=int, default=0)
    p.add_argument("--latency-threshold", type=int, default=500)
    p.add_argument("--test-ip", action="store_true")
    p.add_argument("--timeout", type=float, default=15.0)
    return p.parse_args()


def read_csv_urls(path: str) -> list[str]:
    urls = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("status_code") == "200" and row.get("ok", "").lower() == "true":
                urls.append(row["url"])
    return urls


def download(url: str, timeout: float) -> str | None:
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"  [WARN] Download failed {url}: {e}")
        return None


def parse_base64_proxies(content: str) -> list[dict]:
    proxies = []
    for m in BASE64_PROXY_RE.finditer(content):
        s = m.group(0)
        try:
            if s.startswith("vmess://"):
                import base64
                b64 = s[8:] + "=="
                d = json.loads(base64.b64decode(b64))
                proxies.append({
                    "name": d.get("ps", f"vmess-{len(proxies)}"),
                    "type": "vmess", "server": d.get("add", ""),
                    "port": int(d.get("port", 443)),
                    "uuid": d.get("id", ""), "alterId": int(d.get("aid", 0)),
                    "cipher": d.get("scy", "auto"),
                    "tls": d.get("tls") == "tls",
                    "network": d.get("net", "tcp"),
                    "ws-path": d.get("path", ""),
                    "ws-headers": {"Host": d.get("host", "")} if d.get("host") else None,
                    "sni": d.get("sni", ""),
                })
            elif s.startswith(("vless://", "trojan://", "ss://")):
                import urllib.parse as up
                p = up.urlparse(s)
                scheme = p.scheme
                frag = up.unquote(p.fragment) if p.fragment else f"{scheme}-{len(proxies)}"
                params = up.parse_qs(p.query)
                netloc = p.netloc
                if "@" in netloc:
                    cred, hostport = netloc.split("@", 1)
                else:
                    cred, hostport = "", netloc
                hp = hostport.rsplit(":", 1)
                host = hp[0]
                port = int(hp[1]) if len(hp) > 1 else 443
                tls_on = params.get("security", [""])[0] == "tls"
                skip = params.get("allowInsecure", ["0"])[0] == "1"
                sni = params.get("sni", [""])[0]
                net = params.get("type", ["tcp"])[0]
                if scheme == "vless":
                    proxies.append({"name": frag, "type": "vless", "server": host,
                                    "port": port, "uuid": cred, "tls": tls_on,
                                    "network": net, "sni": sni, "skip-cert-verify": skip})
                elif scheme == "trojan":
                    proxies.append({"name": frag, "type": "trojan", "server": host,
                                    "port": port, "password": cred, "sni": sni,
                                    "skip-cert-verify": skip})
                elif scheme == "ss":
                    import base64
                    try:
                        dec = base64.b64decode(cred + "==").decode()
                        method, pw = dec.split(":", 1)
                    except Exception:
                        method, pw = "aes-256-gcm", cred
                    proxies.append({"name": frag, "type": "ss", "server": host,
                                    "port": port, "password": pw, "cipher": method})
        except Exception as e:
            print(f"  [WARN] Parse failed {s[:40]}...: {e}")
    return proxies


def parse_yaml_proxies(content: str) -> list[dict]:
    try:
        data = yaml.safe_load(content)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    for key in ("proxies", "Proxy", "proxy"):
        if key in data and isinstance(data[key], list):
            return [p for p in data[key] if isinstance(p, dict) and "server" in p]
    return []


def extract_proxies(content: str) -> list[dict]:
    p = parse_yaml_proxies(content)
    return p if p else parse_base64_proxies(content)


def normalize(d: dict, idx: int) -> Proxy:
    t = d.get("type", "").lower()
    return Proxy(
        name=d.get("name", f"{t}-{idx}"), type=t,
        server=d.get("server", ""), port=int(d.get("port", 443)),
        password=d.get("password"), uuid=d.get("uuid"),
        cipher=d.get("cipher"), alter_id=int(d.get("alterId", 0)),
        udp=d.get("udp", False),
        tls=d.get("tls", False) or d.get("security") == "tls",
        sni=d.get("sni"), skip_cert_verify=d.get("skip-cert-verify", False),
        network=d.get("network"), ws_path=d.get("ws-path"),
        ws_headers=d.get("ws-headers"),
        plugin=d.get("plugin"), plugin_opts=d.get("plugin-opts"),
    )


def geoip_batch(ips: list[str], timeout: float) -> dict[str, dict]:
    """Batch GeoIP lookup using ip-api.com (max 100 per request)."""
    result = {}
    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        try:
            payload = [
                {"query": ip, "fields": "status,country,countryCode,city,isp,org,as,query"}
                for ip in batch
            ]
            r = requests.post(IP_API_BATCH, json=payload, timeout=timeout)
            r.raise_for_status()
            for entry in r.json():
                if entry.get("status") == "success":
                    ip = entry.get("query", "")
                    result[ip] = {
                        "country": entry.get("country", "Unknown"),
                        "country_code": entry.get("countryCode", "XX"),
                        "city": entry.get("city", ""),
                        "isp": entry.get("isp", ""),
                        "org": entry.get("org", ""),
                        "as": entry.get("as", ""),
                    }
        except Exception as e:
            print(f"  [WARN] GeoIP batch failed: {e}")
            for ip in batch:
                try:
                    r = requests.get(
                        f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as",
                        timeout=timeout,
                    )
                    r.raise_for_status()
                    entry = r.json()
                    if entry.get("status") == "success":
                        result[ip] = {
                            "country": entry.get("country", "Unknown"),
                            "country_code": entry.get("countryCode", "XX"),
                            "city": entry.get("city", ""),
                            "isp": entry.get("isp", ""),
                            "org": entry.get("org", ""),
                            "as": entry.get("as", ""),
                        }
                except Exception:
                    pass
                time.sleep(0.5)
        if i + 100 < len(ips):
            time.sleep(1.5)
    return result


def generate_mihomo_config(proxies: list[Proxy], path: str) -> None:
    """Generate mihomo config with external controller enabled."""
    plist = [p.to_dict() for p in proxies]
    # Sanitize proxy names - remove chars that mihomo might choke on
    for p in plist:
        p["name"] = re.sub(r'[^\w\[\]\-\.\s一-鿿]', '_', p["name"])
    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "debug",
        "external-controller": f"127.0.0.1:{MIHOMO_API_PORT}",
        "proxies": plist,
        "proxy-groups": [{
            "name": "ALL",
            "type": "url-test",
            "proxies": [p["name"] for p in plist],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 60,
            "tolerance": 50,
        }],
        "rules": ["MATCH,ALL"],
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
    print(f"[INFO] Mihomo config: {path} ({len(proxies)} proxies)")


def run_mihomo_latency_test(
    config_path: str,
    timeout: float = 120,
) -> dict[str, int]:
    """
    Start mihomo daemon, trigger url-test via API, collect latency, then stop.
    Returns {proxy_name: latency_ms}.
    """
    config_dir = os.path.dirname(os.path.abspath(config_path))
    print(f"[INFO] Starting mihomo daemon (config={config_path})...")

    # Log file for mihomo output
    log_path = os.path.join(config_dir, "mihomo.log")
    log_fh = open(log_path, "w")

    proc = subprocess.Popen(
        ["mihomo", "-d", config_dir, "-f", config_path],
        stdout=log_fh,
        stderr=subprocess.STDOUT,
    )

    latency_map: dict[str, int] = {}

    try:
        # Wait for mihomo to be ready
        started = False
        for attempt in range(30):
            if proc.poll() is not None:
                log_fh.flush()
                print(f"[ERROR] Mihomo exited with code {proc.returncode}")
                with open(log_path) as f:
                    print(f"[ERROR] Mihomo log:\n{f.read()[-2000:]}")
                return {}

            try:
                r = requests.get(f"{MIHOMO_API_BASE}/version", timeout=2)
                if r.status_code == 200:
                    ver = r.json().get("version", "unknown")
                    print(f"[INFO] Mihomo v{ver} started (pid={proc.pid})")
                    started = True
                    break
            except Exception:
                time.sleep(1)

        if not started:
            print("[ERROR] Mihomo failed to start within 30s")
            log_fh.flush()
            with open(log_path) as f:
                print(f"[ERROR] Mihomo log:\n{f.read()[-2000:]}")
            proc.terminate()
            return {}

        # Get list of all proxies
        try:
            r = requests.get(f"{MIHOMO_API_BASE}/proxies", timeout=10)
            r.raise_for_status()
            proxies_data = r.json()
            all_names = [
                name for name in proxies_data.get("proxies", {}).keys()
                if name not in ("GLOBAL", "DIRECT", "REJECT", "ALL")
            ]
            print(f"[INFO] Registered {len(all_names)} proxies")
        except Exception as e:
            print(f"[ERROR] Failed to list proxies: {e}")
            proc.terminate()
            return {}

        # Trigger url-test on ALL group
        print("[INFO] Triggering url-test on ALL group...")
        try:
            url = f"{MIHOMO_API_BASE}/proxies/ALL"
            params = {"timeout": 5000, "url": "http://www.gstatic.com/generate_204"}
            r = requests.put(url, params=params, timeout=10)
            print(f"[INFO] url-test trigger: HTTP {r.status_code}")
        except Exception as e:
            print(f"[WARN] url-test trigger failed: {e}")

        # Wait for tests to run
        test_timeout = min(timeout, 90)
        print(f"[INFO] Waiting {test_timeout}s for latency tests...")
        time.sleep(test_timeout)

        # Collect results
        print("[INFO] Collecting latency results...")
        for name in all_names:
            try:
                encoded = requests.utils.quote(name, safe="")
                r = requests.get(f"{MIHOMO_API_BASE}/proxies/{encoded}", timeout=3)
                if r.status_code == 200:
                    history = r.json().get("history", [])
                    if history:
                        delay = history[-1].get("delay", 0)
                        if delay > 0:
                            latency_map[name] = delay
            except Exception:
                pass

        print(f"[INFO] Collected latency for {len(latency_map)}/{len(all_names)} proxies")

    finally:
        print("[INFO] Stopping mihomo daemon...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    return latency_map


def generate_final_config(groups: dict[str, CountryGroup], all_proxies: list[Proxy], path: str) -> None:
    """Generate final mihomo config grouped by country."""
    proxy_list = [p.to_dict() for p in all_proxies]
    glist = []

    for code in sorted(groups, key=lambda c: groups[c].avg_latency):
        g = groups[code]
        if g.proxies:
            glist.append({
                "name": f"{flag(code)} {g.name}",
                "type": "url-test",
                "proxies": [p.name for p in g.proxies],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
            })

    glist.insert(0, {
        "name": "🚀 Auto-Select",
        "type": "url-test",
        "proxies": [p.name for p in all_proxies],
        "url": "http://www.gstatic.com/generate_204",
        "interval": 300,
        "tolerance": 50,
    })

    glist.append({
        "name": "🐟 Fallback",
        "type": "select",
        "proxies": ["DIRECT"] + [p.name for p in all_proxies],
    })

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "proxies": proxy_list,
        "proxy-groups": glist,
        "rules": [
            "DOMAIN-SUFFIX,google.com,🚀 Auto-Select",
            "DOMAIN-SUFFIX,github.com,🚀 Auto-Select",
            "DOMAIN-SUFFIX,githubusercontent.com,🚀 Auto-Select",
            "DOMAIN-SUFFIX,youtube.com,🚀 Auto-Select",
            "DOMAIN-SUFFIX,twitter.com,🚀 Auto-Select",
            "DOMAIN-SUFFIX,x.com,🚀 Auto-Select",
            "DOMAIN-SUFFIX,telegram.org,🚀 Auto-Select",
            "DOMAIN-SUFFIX,openai.com,🚀 Auto-Select",
            "DOMAIN-SUFFIX,anthropic.com,🚀 Auto-Select",
            "GEOIP,CN,DIRECT",
            "MATCH,🐟 Fallback",
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
    print(f"[INFO] Final config: {path} ({len(all_proxies)} proxies, {len(glist)} groups)")


def main() -> int:
    args = parse_args()

    # Step 1: Read CSV
    print(f"[STEP 1] Reading CSV: {args.csv}")
    urls = read_csv_urls(args.csv)
    print(f"  Found {len(urls)} valid YAML URLs")
    if not urls:
        print("[WARN] No URLs. Exiting.")
        return 0

    # Step 2: Download & extract
    print(f"\n[STEP 2] Downloading & extracting proxies...")
    all_proxies: list[Proxy] = []
    seen: set[tuple] = set()
    for i, url in enumerate(urls, 1):
        print(f"  [{i}/{len(urls)}] {url}")
        content = download(url, args.timeout)
        if not content:
            continue
        for pd in extract_proxies(content):
            p = normalize(pd, len(all_proxies))
            k = p.key()
            if k not in seen:
                seen.add(k)
                all_proxies.append(p)
    print(f"  Total unique: {len(all_proxies)}")
    if not all_proxies:
        return 0
    if args.max_proxies > 0:
        all_proxies = all_proxies[:args.max_proxies]
        print(f"  Limited to {len(all_proxies)} proxies")

    # Step 3: Generate config & run mihomo latency test
    print(f"\n[STEP 3] Mihomo latency test...")
    tmp_config = "/tmp/mihomo_test.yaml"
    generate_mihomo_config(all_proxies, tmp_config)
    latency = run_mihomo_latency_test(tmp_config, timeout=args.timeout)

    # Step 4: GeoIP
    print(f"\n[STEP 4] GeoIP lookup...")
    unique_ips = list({p.server for p in all_proxies})
    geo_map = geoip_batch(unique_ips, args.timeout) if args.test_ip else {}
    print(f"  Resolved {len(geo_map)}/{len(unique_ips)} IPs")

    # Assign country
    for i, p in enumerate(all_proxies):
        geo = geo_map.get(p.server)
        if geo:
            all_proxies[i] = p.with_country(geo["country"], geo["country_code"])

    # Step 5: Filter & group
    print(f"\n[STEP 5] Filtering (< {args.latency_threshold}ms) & grouping...")
    groups: dict[str, CountryGroup] = {}
    available: list[Proxy] = []
    for p in all_proxies:
        lat = latency.get(p.name, -1)
        if 0 < lat <= args.latency_threshold:
            code = p.country_code or "XX"
            name = p.country or "Unknown"
            if code not in groups:
                groups[code] = CountryGroup(code=code, name=name)
            groups[code].proxies.append(p)
            available.append(p)
    for g in groups.values():
        g.proxies.sort(key=lambda p: latency.get(p.name, 9999))
        g.avg_latency = (
            sum(latency.get(p.name, 0) for p in g.proxies) / len(g.proxies)
            if g.proxies else 0
        )

    print(f"  Available: {len(available)}/{len(all_proxies)}")
    for code in sorted(groups, key=lambda c: groups[c].avg_latency):
        g = groups[code]
        print(f"    {flag(code)} [{code}] {g.name}: {len(g.proxies)} proxies, avg {g.avg_latency:.0f}ms")

    if not available:
        print("[WARN] No proxies passed latency test.")
        return 0

    # Step 6: Generate final config
    print(f"\n[STEP 6] Generating final config...")
    generate_final_config(groups, available, args.config)

    # Step 7: Write report CSV
    print(f"\n[STEP 7] Writing report: {args.out}")
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["name", "type", "server", "port", "country", "country_code",
                     "latency_ms", "available", "isp", "org"])
        for p in all_proxies:
            lat = latency.get(p.name, -1)
            geo = geo_map.get(p.server, {})
            w.writerow([p.name, p.type, p.server, p.port,
                        p.country or "", p.country_code or "",
                        lat if lat > 0 else "", 0 < lat <= args.latency_threshold,
                        geo.get("isp", ""), geo.get("org", "")])

    print(f"\n{'='*60}")
    print(f"DONE")
    print(f"{'='*60}")
    print(f"  Total: {len(all_proxies)}")
    print(f"  Available: {len(available)}")
    print(f"  Countries: {len(groups)}")
    print(f"  Config: {args.config}")
    print(f"  Report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
