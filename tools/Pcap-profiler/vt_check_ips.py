#!/usr/bin/env python3
"""
VirusTotal checker for IPs found in PCAP Quick Profiler JSON output.

Usage (PowerShell / cmd):
  # Check the newest profiler JSON automatically
  python vt_check_ips.py --latest

  # Or specify a JSON file explicitly
  python vt_check_ips.py --json "C:\\path\\to\\reports\\pcap-profiler\\capture_YYYY-MM-DD_HHMM.json"

  # Optional: write a CSV of results (path will be created if missing)
  python vt_check_ips.py --latest --out "reports/vt/vt_results.csv"

Requirements:
  - Environment variable VT_API_KEY must be set:
      PowerShell:  setx VT_API_KEY "<your_api_key>"
      cmd:         setx VT_API_KEY "<your_api_key>"
    (Close and reopen your terminal after setting.)
"""

from __future__ import annotations
import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(1)


# ---------------- paths / discovery ----------------

def repo_root_from_here() -> Path:
    """Assume this script lives in tools/Pcap-profiler; repo root is 2 levels up."""
    return Path(__file__).resolve().parents[2]

def profiler_reports_dir() -> Path:
    """Return <repo_root>/reports/pcap-profiler."""
    return repo_root_from_here() / "reports" / "pcap-profiler"

def latest_profiler_json() -> Optional[Path]:
    """Find newest *.json under reports/pcap-profiler."""
    base = profiler_reports_dir()
    if not base.is_dir():
        return None
    files = sorted(base.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


# ---------------- input helpers ----------------

def ip_set_from_profiler_json(path: str | Path) -> Set[str]:
    """Read PCAP Quick Profiler JSON and return a unique set of IPs (src + dst)."""
    p = Path(path)
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)

    ips: Set[str] = set()
    for key in ("src_ips", "dst_ips"):
        for item in data.get(key, []):
            # item like ["1.2.3.4", 17] or ["1.2.3.4", "17"]
            if isinstance(item, (list, tuple)) and item:
                ip = str(item[0]).strip()
                if ip:
                    ips.add(ip)
    return ips


# ---------------- VirusTotal client ----------------

VT_BASE = "https://www.virustotal.com/api/v3"
VT_SLEEP_SECONDS = 16  # gentle pacing for free-tier (4 req/minute)

def vt_api_key() -> str:
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "VirusTotal API key not found.\n"
            "Set an environment variable, e.g. (PowerShell):\n"
            "  setx VT_API_KEY \"<your_api_key>\"\n"
            "Then open a NEW terminal and re-run."
        )
    return key

def vt_ip_report(ip: str, api_key: str) -> Dict:
    """Fetch IP intelligence from VirusTotal v3."""
    url = f"{VT_BASE}/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    r = requests.get(url, headers=headers, timeout=30)
    # Handle rate limits & server errors with a simple retry
    if r.status_code == 429:
        time.sleep(VT_SLEEP_SECONDS + 2)
        r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()

def classify_vt_stats(rep: Dict) -> Tuple[str, int]:
    """
    Return (label, malicious_count) based on last_analysis_stats.
    Labels: 'malicious', 'suspicious', 'harmless', 'undetected', 'timeout'
    """
    stats = rep.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    mal = int(stats.get("malicious", 0) or 0)
    susp = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    timeout = int(stats.get("timeout", 0) or 0)

    if mal > 0:
        return ("malicious", mal)
    if susp > 0:
        return ("suspicious", susp)
    if harmless > 0 and mal == 0 and susp == 0:
        return ("harmless", 0)
    if undetected > 0:
        return ("undetected", 0)
    if timeout > 0:
        return ("timeout", 0)
    return ("unknown", 0)


# ---------------- output helpers ----------------

def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    ensure_parent_dir(path)
    if not rows:
        # write header only so the file exists
        rows = []
    fields = ["ip", "label", "malicious_count", "vt_link"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def print_table(rows: List[Dict[str, str]]) -> None:
    if not rows:
        print("No IPs to query.")
        return
    # Simple aligned text table
    ip_w = max(2, max(len(r["ip"]) for r in rows))
    lab_w = max(5, max(len(r["label"]) for r in rows))
    print(f"{'IP'.ljust(ip_w)}  {'Label'.ljust(lab_w)}  Mal VT  Link")
    print(f"{'-'*ip_w}  {'-'*lab_w}  ------  ----")
    for r in rows:
        print(f"{r['ip'].ljust(ip_w)}  {r['label'].ljust(lab_w)}  {str(r['malicious_count']).rjust(3)}    {r['vt_link']}")


# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser(description="Check profiler IPs against VirusTotal (v3).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--json", help="Path to PCAP Profiler JSON report")
    g.add_argument("--latest", action="store_true", help="Use the newest JSON under reports/pcap-profiler")

    ap.add_argument("--out", help="Optional CSV output path (e.g., reports/vt/vt_results.csv)")
    ap.add_argument("--sleep", type=int, default=VT_SLEEP_SECONDS, help="Seconds to sleep between VT calls (default: 16)")
    args = ap.parse_args()

    # Find JSON report
    if args.latest:
        last = latest_profiler_json()
        if not last or not last.exists():
            print("ERROR: No profiler JSON found under: "
                  f"{profiler_reports_dir()}", file=sys.stderr)
            sys.exit(1)
        json_path = last
    else:
        json_path = Path(args.json)

    if not json_path.exists():
        print(f"ERROR: JSON not found: {json_path}", file=sys.stderr)
        sys.exit(1)

    # Collect IPs from profiler output
    ips = sorted(ip_set_from_profiler_json(json_path))
    if not ips:
        print(f"No IPs found in {json_path}.", file=sys.stderr)
        sys.exit(0)

    # API key
    try:
        key = vt_api_key()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    results: List[Dict[str, str]] = []
    print(f"Scanning {len(ips)} IP(s) via VirusTotal…")
    for i, ip in enumerate(ips, start=1):
        try:
            rep = vt_ip_report(ip, key)
            label, mal = classify_vt_stats(rep)
            link = f"https://www.virustotal.com/gui/ip-address/{ip}"
            results.append({
                "ip": ip,
                "label": label,
                "malicious_count": str(mal),
                "vt_link": link,
            })
            # Gentle pacing for VT free-tier
            if i < len(ips):
                time.sleep(max(0, args.sleep))
        except requests.HTTPError as he:
            code = getattr(he.response, "status_code", "HTTP")
            print(f"[!] VT HTTP error for {ip}: {code}", file=sys.stderr)
        except Exception as e:
            print(f"[!] VT error for {ip}: {e}", file=sys.stderr)

    # Print table
    print()
    print_table(results)

    # Optional CSV
    if args.out:
        out_path = Path(args.out)
        write_csv(out_path, results)
        print(f"\nCSV written to: {out_path.resolve()}")

if __name__ == "__main__":
    main()
