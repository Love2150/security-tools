#!/usr/bin/env python3
"""
VirusTotal checker for IPs produced by the PCAP Quick Profiler.

Usage (PowerShell):
  # check a specific profiler JSON
  python .\vt_check_ips.py --json "C:\\path\\to\\reports\\pcap-profiler\\capture.json"

  # or auto-pick the most recent profiler JSON (searches repo-root first)
  python .\vt_check_ips.py --latest

Requirements:
  - set your API key once (then open a NEW terminal):
      setx VT_API_KEY "<your_api_key>"
  - pip install requests
"""

from __future__ import annotations
import os, sys, json, time, argparse
from pathlib import Path
from typing import Dict, Iterable, Set, Tuple, Any, List

try:
    import requests
except Exception:
    print("ERROR: 'requests' not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(1)

API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

# ---------------------------- helpers ----------------------------
def ip_set_from_profiler_json(path: str) -> Set[str]:
    """Load profiler JSON and return a set of unique IPs (src + dst)."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    ips: Set[str] = set()

    # src_ips / dst_ips are lists of [ip, count]
    for key in ("src_ips", "dst_ips"):
        items = data.get(key) or []
        for entry in items:
            if isinstance(entry, (list, tuple)) and entry:
                ip = str(entry[0]).strip()
                if ip and _looks_like_ip(ip):
                    ips.add(ip)

    return ips


def _looks_like_ip(s: str) -> bool:
    """Very small IPv4/IPv6 check."""
    if s.count(".") == 3:
        parts = s.split(".")
        try:
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except Exception:
            return False
    # allow simple IPv6 presence
    return ":" in s


def vt_ip_report(ip: str, api_key: str, session: requests.Session) -> Dict[str, Any]:
    """Query VirusTotal v3 for an IP and return a compact dict."""
    headers = {"x-apikey": api_key}
    url = API_URL.format(ip)
    r = session.get(url, headers=headers, timeout=30)

    if r.status_code == 404:
        return {"ip": ip, "error": "not found"}
    if r.status_code == 429:
        return {"ip": ip, "error": "rate limited"}
    if r.status_code >= 400:
        return {"ip": ip, "error": f"http {r.status_code}"}

    try:
        js = r.json()
    except Exception:
        return {"ip": ip, "error": "bad json"}

    data = js.get("data", {})
    attrs = data.get("attributes", {}) if isinstance(data, dict) else {}

    stats = attrs.get("last_analysis_stats", {}) or {}
    # VT v3 has stats like: harmless, malicious, suspicious, undetected
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    positives = malicious + suspicious

    ref = f"https://www.virustotal.com/gui/ip-address/{ip}"
    return {
        "ip": ip,
        "positives": positives,
        "last_analysis_stats": stats,
        "link": ref,
    }


def run_vt_checks(ips: Iterable[str], api_key: str, delay: float = 16.0) -> Dict[str, Any]:
    """
    Query VT for each IP. Default delay ~16s is polite for the public API
    (historically ~4 req/min). Adjust via --delay if you have higher quota.
    """
    out: Dict[str, Any] = {}
    sess = requests.Session()

    for i, ip in enumerate(sorted(set(ips))):
        res = vt_ip_report(ip, api_key, sess)

        # If rate-limited, backoff once and retry
        if res.get("error") == "rate limited":
            time.sleep(max(delay, 16.0))
            res = vt_ip_report(ip, api_key, sess)

        out[ip] = res

        # sleep between calls unless it's the last one
        if i < len(set(ips)) - 1:
            time.sleep(delay)

    return out


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

    lines: List[str] = []
    lines.append(f"# VirusTotal Check — {source_report_name}")
    lines.append("")
    lines.append(f"- **Scanned IPs:** {len(results)}")
    lines.append(f"- **OK:** {len(ok)}")
    lines.append(f"- **Errors:** {len(err)}")
    lines.append("")

    flagged = sorted(
        ((ip, info) for ip, info in ok.items() if as_int(info.get("positives", 0)) > 0),
        key=lambda t: as_int(t[1].get("positives", 0)),
        reverse=True
    )
    lines.append("## IPs Flagged by Engines")
    lines.append("")
    if flagged:
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
        lines.append("_No IPs were flagged by VirusTotal engines._")
        lines.append("")

    if err:
        lines.append("## Errors")
        lines.append("")
        lines.append("| IP | Error |")
        lines.append("|---|---|")
        for ip, info in err.items():
            lines.append(f"| `{_md_escape(ip)}` | {_md_escape(info.get('error',''))} |")
        lines.append("")

    clean = [ip for ip, info in ok.items() if as_int(info.get("positives", 0)) == 0]
    if clean:
        lines.append("## Clean IPs (0 detections)")
        lines.append("")
        lines.append(", ".join(f"`{ip}`" for ip in sorted(clean)))
        lines.append("")

    return "\n".join(lines)

def write_vt_report(json_out_path: str, txt_out_path: str, results: dict) -> None:
    """
    Save VirusTotal results to JSON (full) and a readable TXT summary.
    Expected 'results' shape (as returned by run_vt_checks):
      {
        "ips_checked": [...],
        "by_ip": {
          "1.2.3.4": {
             "harmless": 10, "malicious": 1, "suspicious": 0, "undetected": 60,
             "timeout": 0, "link": "https://www.virustotal.com/gui/ip-address/1.2.3.4"
          },
          ...
        }
      }
    """
    import json
    from pathlib import Path

    # 1) JSON
    Path(json_out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(json_out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # 2) TXT
    lines = []
    lines.append("VirusTotal IP Reputation — Summary")
    lines.append("=" * 60)
    lines.append(f"IPs checked: {len(results.get('ips_checked', []))}")
    lines.append("")

    by_ip = results.get("by_ip", {})
    if not by_ip:
        lines.append("(No IP results)")
    else:
        # Sort: most concerning first (malicious+suspicious)
        def score(v):
            return int(v.get("malicious", 0)) * 100 + int(v.get("suspicious", 0))

        for ip, data in sorted(by_ip.items(), key=lambda kv: score(kv[1]), reverse=True):
            m  = int(data.get("malicious", 0))
            s  = int(data.get("suspicious", 0))
            hu = int(data.get("harmless", 0))
            und = int(data.get("undetected", 0))
            to = int(data.get("timeout", 0))
            link = data.get("link", "")
            lines.append(f"{ip}")
            lines.append(f"  malicious: {m}, suspicious: {s}, harmless: {hu}, undetected: {und}, timeout: {to}")
            if link:
                lines.append(f"  VT: {link}")
            lines.append("")

    Path(txt_out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(txt_out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ----------------------------- main ------------------------------
def main():
    ap = argparse.ArgumentParser(description="Check IPs from PCAP Profiler JSON against VirusTotal.")
    ap.add_argument("--json", help="Path to pcap_profiler JSON report file.")
    ap.add_argument("--latest", action="store_true", help="Automatically detect the latest profiler report.")
    ap.add_argument("--delay", type=float, default=16.0, help="Seconds between VT requests (public API ~4/min).")
    args = ap.parse_args()

    if not (args.json or args.latest):
        ap.error("Provide either --json path or --latest.")

    # Locate the profiler JSON
    if args.latest:
        here = Path(__file__).resolve()
        candidates = [
            here.parents[2] / "reports" / "pcap-profiler",  # repo root
            here.parents[1] / "reports" / "pcap-profiler",  # tools/
            here.parent / "reports" / "pcap-profiler",      # script folder
        ]
        jsons: List[Path] = []
        for d in candidates:
            if d.is_dir():
                jsons += list(d.glob("*.json"))
        if not jsons:
            print("No profiler reports found.", file=sys.stderr)
            print("Looked in:", *(str(p) for p in candidates), sep="\n  - ")
            sys.exit(1)
        jsons.sort(key=os.path.getmtime, reverse=True)
        report_path = jsons[0]
        print(f"[+] Using latest profiler report: {report_path}")
    else:
        report_path = Path(args.json)
        if not report_path.exists():
            print(f"ERROR: file not found: {report_path}", file=sys.stderr)
            sys.exit(1)

    # Collect IPs
    ips = ip_set_from_profiler_json(str(report_path))
    if not ips:
        print("No IPs found in profiler JSON.")
        return

    # API key
    vt_key = os.getenv("VT_API_KEY")
    if not vt_key:
        print("ERROR: VirusTotal API key not found. Set it with:")
        print('  setx VT_API_KEY "<your_api_key>"')
        print("Then open a NEW terminal and re-run.")
        sys.exit(1)

    print(f"[+] Checking {len(ips)} IPs against VirusTotal...")
    results = run_vt_checks(ips, vt_key, delay=args.delay)

    # Save JSON + Markdown under repo-root/reports/vt/
    reports_dir = Path(__file__).resolve().parents[2] / "reports" / "vt"
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

    # Console summary
    print("\n--- Summary ---")
    for ip, info in results.items():
        if "error" in info:
            print(f"❌ {ip}: {info['error']}")
        else:
            print(f"🧩 {ip} → {info.get('positives', 'N/A')} engines flagged this IP")


if __name__ == "__main__":
    main()
