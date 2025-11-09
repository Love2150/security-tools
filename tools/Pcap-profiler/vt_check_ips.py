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

# Markdown summary 
from pathlib import Path

def _md_escape(s: str) -> str:
    return str(s).replace("|", r"\|")

def render_summary_markdown(results: dict, source_report_name: str) -> str:
    ok, err = {}, {}
    for ip, info in results.items():
        (err if "error" in info else ok)[ip] = info

    def as_int(x, default=0):
        try:
            return int(x)
        except Exception:
            return default

    lines = []
    lines.append(f"# VirusTotal Check — {source_report_name}")
    lines.append("")
    lines.append(f"- **Scanned IPs:** {len(results)}")
    lines.append(f"- **OK:** {len(ok)}")
    lines.append(f"- **Errors:** {len(err)}")
    lines.append("")
    # Table of flagged (descending)
    flagged = sorted(
        ((ip, info) for ip, info in ok.items() if as_int(info.get("positives", 0)) > 0),
        key=lambda t: as_int(t[1].get("positives", 0)),
        reverse=True
    )
    if flagged:
        lines.append("## IPs Flagged by Engines")
        lines.append("")
        lines.append("| IP | Positives | Harmless | Suspicious | Malicious | Undetected | Link |")
        lines.append("|---|---:|---:|---:|---:|---:|---|")
        for ip, info in flagged:
            stats = info.get("last_analysis_stats", {}) or {}
            lines.append(
                f"| `{_md_escape(ip)}` | {as_int(info.get('positives', 0))} | "
                f"{as_int(stats.get('harmless', 0))} | {as_int(stats.get('suspicious', 0))} | "
                f"{as_int(stats.get('malicious', 0))} | {as_int(stats.get('undetected', 0))} | "
                f"[Open]({_md_escape(info.get('link', ''))}) |"
            )
        lines.append("")
    else:
        lines.append("## IPs Flagged by Engines")
        lines.append("")
        lines.append("_No IPs were flagged by VirusTotal engines._")
        lines.append("")

    # Errors (rate-limit, not found, etc.)
    if err:
        lines.append("## Errors")
        lines.append("")
        lines.append("| IP | Error |")
        lines.append("|---|---|")
        for ip, info in err.items():
            lines.append(f"| `{_md_escape(ip)}` | {_md_escape(info.get('error',''))} |")
        lines.append("")

    # Appendix: all OK (no detections)
    clean = [ip for ip, info in ok.items() if as_int(info.get("positives", 0)) == 0]
    if clean:
        lines.append("## Clean IPs (0 detections)")
        lines.append("")
        lines.append(", ".join(f"`{ip}`" for ip in sorted(clean)))
        lines.append("")

    return "\n".join(lines)



# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser(description="Check IPs from PCAP Profiler JSON against VirusTotal.")
    ap.add_argument("--json", help="Path to pcap_profiler JSON report file.")
    ap.add_argument("--latest", action="store_true", help="Automatically detect the latest profiler report.")
    args = ap.parse_args()

    if not (args.json or args.latest):
        ap.error("Provide either --json path or --latest.")

    if args.latest:
        base_dir = Path(__file__).resolve().parents[1] / "reports" / "pcap-profiler"
        jsons = sorted(base_dir.glob("*.json"), key=os.path.getmtime, reverse=True)
        if not jsons:
            print("No profiler reports found.", file=sys.stderr)
            sys.exit(1)
        report_path = jsons[0]
        print(f"[+] Using latest profiler report: {report_path}")
    else:
        report_path = Path(args.json)
        if not report_path.exists():
            print(f"ERROR: file not found: {report_path}", file=sys.stderr)
            sys.exit(1)

    ips = ip_set_from_profiler_json(str(report_path))
    if not ips:
        print("No IPs found in profiler JSON.")
        return

    vt_key = os.getenv("VT_API_KEY")
    if not vt_key:
        print("ERROR: VirusTotal API key not found. Set it using:")
        print('  setx VT_API_KEY "<your_api_key>"')
        sys.exit(1)

    print(f"[+] Checking {len(ips)} IPs against VirusTotal...")
    results = run_vt_checks(ips, vt_key)

    # Save to repo: security-tools/reports/vt/
    reports_dir = Path(__file__).resolve().parents[1] / "reports" / "vt"
    reports_dir.mkdir(parents=True, exist_ok=True)

    stem = report_path.stem  # e.g., capture_2025-11-08_1203
    json_out = reports_dir / f"{stem}_viruscheck.json"
    md_out   = reports_dir / f"{stem}_viruscheck.md"

    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    md = render_summary_markdown(results, stem)
    with open(md_out, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"\n✅ Results saved:")
    print(f"  • JSON: {json_out}")
    print(f"  • Markdown: {md_out}")

    # Quick terminal summary
    print("\n--- Summary ---")
    for ip, info in results.items():
        if "error" in info:
            print(f"❌ {ip}: {info['error']}")
        else:
            print(f"🧩 {ip} → {info.get('positives', 'N/A')} engines flagged this IP")



if __name__ == "__main__":
    main()
