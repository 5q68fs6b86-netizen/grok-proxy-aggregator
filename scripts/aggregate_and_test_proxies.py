#!/usr/bin/env python3
"""
Aggregate YAML proxies from CSV report, test with mihomo, group by country,
and generate a production mihomo config.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
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
TEST_URL = "http://www.gstatic.com/generate_204"


def flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🌐"
    return chr(0x1F1E6 + ord(code[0]) - 65) + chr(0x1F1E6 + ord(code[1]) - 65)


def sanitize_name(name: str, proxy_type: str = "", server: str = "") -> str:
    name = re.sub(r'[^\w\[\]\-\.\s一-鿿]', '_', name)
    name = re.sub(r'_+', '_', name).strip('_')
    if not name or len(name) < 2:
        name = f"{proxy_type}-{server[:8]}" if proxy_type else f"proxy-{server[:8]}"
    return name[:64]


def dedup_names(plist: list[dict]) -> list[dict]:
    """Deduplicate proxy names by appending index."""
    seen: dict[str, int] = {}
    for p in plist:
        orig = p["name"]
        if orig in seen:
            seen[orig] += 1
            p["name"] = f"{orig}_{seen[orig]}"
        else:
            seen[orig] = 0
    return plist


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
            "name": sanitize_name(self.name, self.type, self.server),
            "type": self.type, "server": self.server, "port": self.port,
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
    p.add_argument("--batch-size", type=int, default=80, help="Proxies per mihomo batch")
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
                cred, hostport = (netloc.split("@", 1) + [""])[:2] if "@" in netloc else ("", netloc)
                hp = hostport.rsplit(":", 1)
                host, port = hp[0], int(hp[1]) if len(hp) > 1 else 443
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


def kill_port(port: int) -> None:
    """Kill process listening on port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', port))
        s.close()
    except OSError:
        subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True, timeout=5)
        time.sleep(1)


def is_port_open(port: int, timeout: float = 1.0) -> bool:
    """Check if port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except (OSError, socket.timeout):
        return False


def run_mihomo_batch(
    batch: list[Proxy],
    port: int,
    api_port: int,
    timeout: float,
) -> dict[str, int]:
    """
    Start mihomo with a batch of proxies, wait for url-test, collect results.
    Returns {proxy_name: latency_ms}.
    """
    # Build config
    plist = [p.to_dict() for p in batch]
    plist = dedup_names(plist)

    # Build name mapping: sanitized -> original
    name_map: dict[str, str] = {}
    for p_dict, p_orig in zip(plist, batch):
        name_map[p_dict["name"]] = p_orig.name

    config = {
        "mixed-port": port,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": f"127.0.0.1:{api_port}",
        "proxies": plist,
        "proxy-groups": [{
            "name": "ALL",
            "type": "url-test",
            "proxies": [p["name"] for p in plist],
            "url": TEST_URL,
            "interval": 300,
            "tolerance": 100,
        }],
        "rules": ["MATCH,ALL"],
    }

    config_path = f"/tmp/mihomo_batch_{port}.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    # Validate
    r = subprocess.run(["mihomo", "-t", config_path], capture_output=True, text=True, timeout=30)
    if "successful" not in r.stdout:
        print(f"    [WARN] Config invalid, skipping")
        return {}

    # Kill any existing process on our ports
    kill_port(port)
    kill_port(api_port)

    # Start mihomo daemon
    proc = subprocess.Popen(
        ["mihomo", "-f", config_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    latency_map: dict[str, int] = {}

    try:
        # Wait for mihomo to start (check API port)
        started = False
        for _ in range(20):
            if proc.poll() is not None:
                err = proc.stderr.read().decode() if proc.stderr else ""
                print(f"    [WARN] Mihomo exited with code {proc.returncode}")
                if err:
                    print(f"    [WARN] stderr: {err[-500:]}")
                return {}
            if is_port_open(api_port):
                started = True
                break
            time.sleep(0.5)

        if not started:
            print(f"    [WARN] Mihomo API port {api_port} not open after 10s")
            proc.terminate()
            return {}

        # Trigger url-test
        try:
            api_base = f"http://127.0.0.1:{api_port}"
            # PUT /proxies/ALL to trigger test
            requests.put(
                f"{api_base}/proxies/ALL",
                json={"name": "ALL"},
                timeout=5,
            )
        except Exception:
            pass

        # Wait for url-test to complete
        wait_time = min(timeout, 60)
        time.sleep(wait_time)

        # Collect latency from API
        try:
            api_base = f"http://127.0.0.1:{api_port}"
            r = requests.get(f"{api_base}/proxies/ALL", timeout=5)
            if r.status_code == 200:
                group_data = r.json()
                # Get all proxy names in the group
                all_names = group_data.get("all", [])
                for name in all_names:
                    try:
                        encoded = requests.utils.quote(name, safe="")
                        r2 = requests.get(f"{api_base}/proxies/{encoded}", timeout=3)
                        if r2.status_code == 200:
                            history = r2.json().get("history", [])
                            if history:
                                delay = history[-1].get("delay", 0)
                                if delay > 0:
                                    original = name_map.get(name, name)
                                    latency_map[original] = delay
                    except Exception:
                        pass
        except Exception as e:
            print(f"    [WARN] API query failed: {e}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    return latency_map


def run_mihomo_latency_test(
    proxies: list[Proxy],
    timeout: float = 15,
    batch_size: int = 80,
) -> dict[str, int]:
    """Test proxy latency in batches using mihomo daemon + REST API."""
    all_latency: dict[str, int] = {}
    total_batches = (len(proxies) + batch_size - 1) // batch_size

    print(f"[INFO] Testing {len(proxies)} proxies in {total_batches} batches (size={batch_size})")

    for i in range(0, len(proxies), batch_size):
        batch = proxies[i:i + batch_size]
        batch_num = i // batch_size + 1
        # Use unique ports per batch to avoid conflicts
        port = 17890 + batch_num
        api_port = 19090 + batch_num

        print(f"[INFO] Batch {batch_num}/{total_batches}: {len(batch)} proxies (port={port}, api={api_port})")

        result = run_mihomo_batch(batch, port, api_port, timeout)
        all_latency.update(result)

        pct = len(result) / len(batch) * 100 if batch else 0
        print(f"    [INFO] {len(result)}/{len(batch)} proxies have latency ({pct:.0f}%)")

    print(f"[INFO] Total: {len(all_latency)}/{len(proxies)} proxies have latency")
    return all_latency


def generate_final_config(groups: dict[str, CountryGroup], all_proxies: list[Proxy], path: str) -> None:
    """Generate final mihomo config grouped by country."""
    proxy_list = [p.to_dict() for p in all_proxies]
    proxy_list = dedup_names(proxy_list)

    glist = []
    for code in sorted(groups, key=lambda c: groups[c].avg_latency):
        g = groups[code]
        if g.proxies:
            glist.append({
                "name": f"{flag(code)} {g.name}",
                "type": "url-test",
                "proxies": [sanitize_name(p.name, p.type, p.server) for p in g.proxies],
                "url": TEST_URL,
                "interval": 300,
                "tolerance": 50,
            })

    all_names = [p["name"] for p in proxy_list]
    glist.insert(0, {
        "name": "🚀 Auto-Select",
        "type": "url-test",
        "proxies": all_names,
        "url": TEST_URL,
        "interval": 300,
        "tolerance": 50,
    })
    glist.append({
        "name": "🐟 Fallback",
        "type": "select",
        "proxies": ["DIRECT"] + all_names,
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

    # Step 3: Validate config
    print(f"\n[STEP 3] Validating mihomo config...")
    tmp_config = "/tmp/mihomo_validate.yaml"
    plist = [p.to_dict() for p in all_proxies]
    plist = dedup_names(plist)
    validate_config = {
        "mixed-port": 17800,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": plist,
        "proxy-groups": [{"name": "ALL", "type": "select", "proxies": [p["name"] for p in plist]}],
        "rules": ["MATCH,ALL"],
    }
    with open(tmp_config, "w") as f:
        yaml.dump(validate_config, f, default_flow_style=False)
    r = subprocess.run(["mihomo", "-t", tmp_config], capture_output=True, text=True, timeout=60)
    if "successful" in r.stdout:
        print("[INFO] Config validation: ✅ successful")
    else:
        print(f"[WARN] Config validation issues:\n{r.stdout[:500]}")

    # Step 4: Mihomo latency test (batched)
    print(f"\n[STEP 4] Mihomo latency test (batched)...")
    latency = run_mihomo_latency_test(
        all_proxies,
        timeout=args.timeout,
        batch_size=args.batch_size,
    )

    # Step 5: GeoIP
    print(f"\n[STEP 5] GeoIP lookup...")
    unique_ips = list({p.server for p in all_proxies})
    geo_map = geoip_batch(unique_ips, args.timeout) if args.test_ip else {}
    print(f"  Resolved {len(geo_map)}/{len(unique_ips)} IPs")

    for i, p in enumerate(all_proxies):
        geo = geo_map.get(p.server)
        if geo:
            all_proxies[i] = p.with_country(geo["country"], geo["country_code"])

    # Step 6: Filter & group
    print(f"\n[STEP 6] Filtering (< {args.latency_threshold}ms) & grouping...")
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

    # Step 7: Generate final config
    print(f"\n[STEP 7] Generating final config...")
    generate_final_config(groups, available, args.config)

    # Step 8: Write report CSV
    print(f"\n[STEP 8] Writing report: {args.out}")
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
