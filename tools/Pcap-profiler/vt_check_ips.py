#!/usr/bin/env python3
"""
VirusTotal IP reputation checker

Sources of IPs:
  1) JSON summary produced by your PCAP Quick Profiler (--json path)
  2) A raw PCAP/PCAPNG (--pcap path) by extracting unique IPs via tshark

Usage (examples):
  # From your profiler JSON report
  python vt_check_ips.py --json C:\path\to\reports\pcap-profiler\capture_2025-11-08_1203.json

  # Extract IPs directly from a PCAP (requires tshark on PATH)
  python vt_check_ips.py --pcap C:\path\capture.pcap

  # Include RFC1918/private IPs too
  python vt_check_ips.py --pcap C:\path\capture.pcap --include-private

  # Limit checks to 40 IPs and save to a specific folder
  python vt_check_ips.py --json report.json --limit 40 --outdir reports\vt-ip-check
"""

import argparse
import csv
import ipaddress
import json
import os
import sys
import time
import datetime as dt
import subprocess
from typing import Dict, Set, List, Any, Optional

import urllib.request
import urllib.error

VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
# Free API rate limit is ~4 requests/minute; we’ll be polite.
DEFAULT_SLEEP_SECONDS = 16

# ------------------------ Helpers ------------------------

def load_env_api_key() -> str:
    key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
    if not key:
        raise SystemExit(
            "ERROR: VirusTotal API key not found.\n"
            "Set an environment variable, e.g. (PowerShell):\n"
            "  setx VT_API_KEY \"<your_api_key>\"\n"
            "Then open a NEW terminal and re-run."
        )
    return key

def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def ensure_outdir(outdir: str) -> str:
    os.makedirs(outdir, exist_ok=True)
    return outdir

def http_get(url: str, headers: Dict[str, str], timeout: int = 30) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        payload = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {payload[:300]}")
    except Exception as e:
        raise RuntimeError(str(e))

def vt_lookup_ip(ip: str, api_key: str) -> Dict[str, Any]:
    url = VT_API_URL.format(ip=ip)
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    return http_get(url, headers)

def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")

# ------------------------ IP Collection ------------------------

def ip_set_from_profiler_json(path: str) -> Set[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    ips: Set[str] = set()
    for k in ("src_ips", "dst_ips"):
        for ip, _count in data.get(k, []):
            ips.add(ip)
    return ips

def ip_set_from_pcap(path: str) -> Set[str]:
    # Requires tshark on PATH
    if not shutil_which("tshark"):
        raise SystemExit("ERROR: tshark not found on PATH. Install Wireshark and add tshark to PATH.")
    # Extract all ip.addr (both src & dst) as a flat list, one per line
    cmd = [
        "tshark", "-r", path, "-T", "fields", "-e", "ip.addr", "-Y", "ip"
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"tshark failed: {e}")

    ips: Set[str] = set()
    for line in out.decode("utf-8", errors="ignore").splitlines():
        # ip.addr may contain multiple semicolon-separated values in a single row
        for part in line.replace(",", ";").split(";"):
            p = part.strip()
            if p:
                ips.add(p)
    return ips

def shutil_which(name: str) -> Optional[str]:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(p, name)
        if os.path.isfile(candidate):
            return candidate
        # Windows exe
        if os.path.isfile(candidate + ".exe"):
            return candidate + ".exe"
    return None

# ------------------------ Main Work ------------------------

def check_ips(ips: Set[str], *, include_private: bool, limit: Optional[int], outdir: str,
              sleep_seconds: int, api_key: str) -> Dict[str, Any]:
    """Query VirusTotal for each public IP (or private if requested).
       Returns dict with details and writes CSV/JSON in outdir."""
    # Filter & limit
    ordered = sorted(ips)
    filtered = [ip for ip in ordered if include_private or is_public_ip(ip)]
    if limit is not None:
        filtered = filtered[:max(0, limit)]

    results: List[Dict[str, Any]] = []
    cache_path = os.path.join(outdir, "cache_ip_vt.json")
    cache: Dict[str, Any] = {}
    if os.path.isfile(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache = json.load(f)
        except Exception:
            cache = {}

    for i, ip in enumerate(filtered, 1):
        print(f"[{i}/{len(filtered)}] {ip} …", end="", flush=True)

        if ip in cache:
            data = cache[ip]
            print(" cached")
        else:
            try:
                data = vt_lookup_ip(ip, api_key)
                # Save to cache immediately
                cache[ip] = data
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(cache, f)
                # Rate-limit
                time.sleep(sleep_seconds)
                print(" ok")
            except Exception as e:
                data = {"error": str(e)}
                cache[ip] = data
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(cache, f)
                print(f" ERROR: {e}")

        # Flatten a few useful fields
        row = flatten_vt_ip(ip, data)
        results.append(row)

    # Write outputs
    stamp = now_stamp()
    json_out = os.path.join(outdir, f"vt_ip_results_{stamp}.json")
    csv_out = os.path.join(outdir, f"vt_ip_results_{stamp}.csv")

    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    with open(csv_out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "ip", "malicious", "suspicious", "harmless", "undetected",
                "reputation", "last_analysis_date", "country", "asn", "as_owner",
                "categories", "error"
            ],
        )
        w.writeheader()
        w.writerows(results)

    return {
        "count": len(results),
        "json": json_out,
        "csv": csv_out,
        "skipped_private": len(ordered) - len(filtered) if not include_private else 0
    }

def flatten_vt_ip(ip: str, data: Dict[str, Any]) -> Dict[str, Any]:
    row = {
        "ip": ip,
        "malicious": None, "suspicious": None, "harmless": None, "undetected": None,
        "reputation": None, "last_analysis_date": None,
        "country": None, "asn": None, "as_owner": None,
        "categories": None,
        "error": None,
    }
    if "error" in data:
        row["error"] = data["error"]
        return row

    try:
        attr = data["data"]["attributes"]
        cats = attr.get("categories") or {}
        stats = attr.get("last_analysis_stats") or {}
        row.update({
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "harmless": stats.get("harmless"),
            "undetected": stats.get("undetected"),
            "reputation": attr.get("reputation"),
            "last_analysis_date": ts_to_iso(attr.get("last_analysis_date")),
            "country": attr.get("country"),
            "asn": attr.get("asn"),
            "as_owner": attr.get("as_owner"),
            "categories": ",".join(sorted(cats.keys())) if isinstance(cats, dict) else None,
        })
    except Exception as e:
        row["error"] = f"parse-error: {e}"
    return row

def ts_to_iso(ts: Any) -> Optional[str]:
    try:
        if ts is None:
            return None
        return dt.datetime.utcfromtimestamp(int(ts)).isoformat() + "Z"
    except Exception:
        return None

# ------------------------ CLI ------------------------

def main():
    ap = argparse.ArgumentParser(description="Check IPs against VirusTotal (v3)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--json", help="Path to PCAP Quick Profiler JSON report")
    src.add_argument("--pcap", help="Path to PCAP/PCAPNG (requires tshark on PATH)")

    ap.add_argument("--include-private", action="store_true",
                    help="Include RFC1918/non-global IPs (default: skip)")
    ap.add_argument("--limit", type=int, default=None,
                    help="Max IPs to check (default: all)")
    ap.add_argument("--sleep", type=int, default=DEFAULT_SLEEP_SECONDS,
                    help=f"Seconds to sleep between requests (default {DEFAULT_SLEEP_SECONDS})")
    ap.add_argument("--outdir", default=os.path.join("reports", "vt-ip-check"),
                    help="Output directory for results")
    args = ap.parse_args()

    api_key = load_env_api_key()
    outdir = ensure_outdir(args.outdir)

    # Collect IPs
    if args.json:
        ips = ip_set_from_profiler_json(args.json)
    else:
        ips = ip_set_from_pcap(args.pcap)

    if not ips:
        print("No IPs found.", file=sys.stderr)
        sys.exit(2)

    summary = check_ips(
        ips,
        include_private=args.include_private,
        limit=args.limit,
        outdir=outdir,
        sleep_seconds=int(args.sleep),
        api_key=api_key,
    )

    print("\nDone.")
    print(f"IPs checked: {summary['count']}")
    if summary.get("skipped_private"):
        print(f"Private/non-global IPs skipped: {summary['skipped_private']}")
    print(f"JSON: {summary['json']}")
    print(f"CSV : {summary['csv']}")

if __name__ == "__main__":
    main()
