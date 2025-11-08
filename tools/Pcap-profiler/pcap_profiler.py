#!/usr/bin/env python3
"""
PCAP Quick Profiler (Windows-friendly, PyShark/TShark-based)

Reports:
- Protocol counts (%), bytes by protocol
- Top src/dst IPs
- Top destination ports
- HTTP: hosts, user-agents, URLs, content types (MIME)
- TLS: record/handshake versions, cipher suites, SNI, JA3
- Capture start/end timestamps & duration
- Packet/byte totals

Usage:
  python pcap_profiler.py <pcap> [--top 10] [--json out.json] [--csv out.csv]
"""

from __future__ import annotations
import sys
import os
import json
import csv
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Tuple
import asyncio

# External dep:
#   pip install pyshark
import pyshark


# --------------------------- Utilities ---------------------------

def _ensure_event_loop() -> asyncio.AbstractEventLoop:
    """Ensure there is a current event loop without changing policy."""
    try:
        return asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


def safe_int(s: Any, default: int = 0) -> int:
    try:
        return int(str(s))
    except Exception:
        return default

from datetime import datetime, timezone

def to_dt(value):
    """
    Safely convert to datetime:
      - Supports float/int epoch timestamps
      - Supports ISO 8601 strings (e.g. '2010-07-04T20:24:16')
    Returns tz-aware UTC datetime or None.
    """
    if value is None:
        return None

    # Handle epoch timestamps
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)

    # Try string parsing
    s = str(value).strip()

    # 1) Epoch-like numeric strings
    try:
        return datetime.fromtimestamp(float(s), tz=timezone.utc)
    except Exception:
        pass

    # 2) ISO-like date strings
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue

    return None




def top_n(counter: Counter, n: int) -> Iterable[Tuple[str, int]]:
    return counter.most_common(n)


def pct(part: int, whole: int) -> float:
    return (part / whole * 100.0) if whole else 0.0


def format_bps(bytes_total: int, seconds: float) -> str:
    if not seconds or seconds <= 0:
        return "n/a"
    bps = bytes_total / seconds
    units = ["B/s", "KB/s", "MB/s", "GB/s"]
    i = 0
    while bps >= 1024 and i < len(units) - 1:
        bps /= 1024.0
        i += 1
    return f"{bps:.2f} {units[i]}"


# --------------------------- Core ---------------------------

def profile_pcap(path: str, top_n_val: int = 10) -> Dict[str, Any]:
    loop = _ensure_event_loop()

    # Aggregates
    protocols = Counter()
    bytes_by_proto = Counter()
    top_src = Counter()
    top_dst = Counter()
    top_dports = Counter()

    mime_types = Counter()
    http_user_agents = Counter()
    http_hosts = Counter()
    http_urls = Counter()

    tls_versions = Counter()
    tls_ciphers = Counter()
    tls_sni = Counter()
    tls_ja3 = Counter()

    first_ts = None
    last_ts = None
    packet_count = 0
    bytes_total = 0

    # -------- First pass: general sweep --------
    cap = pyshark.FileCapture(
        path,
        keep_packets=False,
        use_json=True,
        eventloop=loop
    )

    try:
        for pkt in cap:
            packet_count += 1

            # time (robust across TShark versions)
            dt = getattr(pkt, "sniff_time", None)  # datetime or None
            if dt:
                if dt.tzinfo is None:
                    from datetime import timezone
                    dt = dt.replace(tzinfo=timezone.utc)

                if first_ts is None or dt < first_ts:
                     first_ts = dt
                if last_ts is None or dt > last_ts:
                     last_ts = dt


            # sizes
            frame_len = safe_int(getattr(pkt.frame_info, "len", "0"))
            bytes_total += frame_len

            # highest layer (protocol-ish)
            hl = getattr(pkt, "highest_layer", None)
            if not hl and getattr(pkt, "layers", None):
                try:
                    hl = pkt.layers[-1].layer_name
                except Exception:
                    hl = None
            if hl:
                protocols[hl] += 1
                bytes_by_proto[hl] += frame_len

            # IPs
            ip_src = getattr(getattr(pkt, "ip", None), "src", None)
            ip_dst = getattr(getattr(pkt, "ip", None), "dst", None)
            if ip_src:
                top_src[ip_src] += 1
            if ip_dst:
                top_dst[ip_dst] += 1

            # Ports
            dport = None
            if hasattr(pkt, "tcp"):
                dport = getattr(pkt.tcp, "dstport", None)
            elif hasattr(pkt, "udp"):
                dport = getattr(pkt.udp, "dstport", None)
            if dport:
                top_dports[str(dport)] += 1
    finally:
        cap.close()

    # -------- HTTP pass --------
    http_cap = pyshark.FileCapture(
        path,
        keep_packets=False,
        use_json=True,
        display_filter="http",
        eventloop=loop
    )
    try:
        for pkt in http_cap:
            http = getattr(pkt, "http", None)
            if not http:
                continue
            ctype = getattr(http, "content_type", None)
            if ctype:
                mime_types[ctype.lower()] += 1
            ua = getattr(http, "user_agent", None)
            if ua:
                http_user_agents[ua] += 1
            host = getattr(http, "host", None)
            if host:
                http_hosts[host] += 1
            uri = getattr(http, "request_full_uri", None)
            if not uri:
                # fallback
                req_uri = getattr(http, "request_uri", None)
                if host and req_uri:
                    uri = f"http://{host}{req_uri}"
            if uri:
                http_urls[uri] += 1
    finally:
        http_cap.close()

    # -------- TLS pass --------
    tls_cap = pyshark.FileCapture(
        path,
        keep_packets=False,
        use_json=True,
        display_filter="tls",
        eventloop=loop
    )
    try:
        for pkt in tls_cap:
            tls = getattr(pkt, "tls", None)
            if not tls:
                continue
            ver = getattr(tls, "record_version", None) or getattr(tls, "handshake_version", None)
            if ver:
                tls_versions[ver] += 1
            cipher = getattr(tls, "handshake_ciphersuite", None)
            if cipher:
                tls_ciphers[cipher] += 1
            sni = getattr(tls, "handshake_extensions_server_name", None)
            if sni:
                tls_sni[sni] += 1
            ja3 = getattr(tls, "handshake_ja3", None)
            if ja3:
                tls_ja3[ja3] += 1
    finally:
        tls_cap.close()

    # Duration
    duration_sec = 0.0
    if first_ts and last_ts:
        duration_sec = (last_ts - first_ts).total_seconds()

    # Compose result
    result = {
        "file": os.path.abspath(path),
        "packets": packet_count,
        "bytes_total": bytes_total,
        "times": {
            "first": first_ts.isoformat() if first_ts else None,
            "last": last_ts.isoformat() if last_ts else None,
            "duration_seconds": duration_sec
        },
        "throughput": {
            "avg": format_bps(bytes_total, duration_sec)
        },
        "protocols": {
            "counts": protocols,
            "bytes": bytes_by_proto
        },
        "top": {
            "src_ips": top_src.most_common(top_n_val),
            "dst_ips": top_dst.most_common(top_n_val),
            "dst_ports": top_dports.most_common(top_n_val),
        },
        "http": {
            "content_types": mime_types.most_common(top_n_val),
            "hosts": http_hosts.most_common(top_n_val),
            "user_agents": http_user_agents.most_common(top_n_val),
            "urls": http_urls.most_common(top_n_val),
        },
        "tls": {
            "versions": tls_versions.most_common(top_n_val),
            "ciphers": tls_ciphers.most_common(top_n_val),
            "sni": tls_sni.most_common(top_n_val),
            "ja3": tls_ja3.most_common(top_n_val),
        }
    }
    return result


# --------------------------- Output ---------------------------

def print_human(summary: Dict[str, Any], top_n_val: int) -> None:
    path = summary["file"]
    pkts = summary["packets"]
    total_b = summary["bytes_total"]
    t = summary["times"]
    p = summary["protocols"]
    top = summary["top"]
    http = summary["http"]
    tls = summary["tls"]

    print(f"\nPCAP Quick Profiler — {path}")
    print("=" * 80)
    print(f"Packets: {pkts:,}")
    print(f"Bytes:   {total_b:,}")
    print(f"Start:   {t['first']}")
    print(f"End:     {t['last']}")
    print(f"Duration: {t['duration_seconds']:.2f}s    Avg throughput: {summary['throughput']['avg']}")

    print("\n🖧 Protocols (by packets):")
    total_pkts = max(1, pkts)
    for name, count in p["counts"].most_common(top_n_val):
        print(f"  - {name:<10} {count:>8}  ({pct(count, total_pkts):5.1f}%)")
    print("")

    print("📦 Bytes by protocol:")
    total_bt = max(1, total_b)
    for name, b in p["bytes"].most_common(top_n_val):
        print(f"  - {name:<10} {b:>10}  ({pct(b, total_bt):5.1f}%)")
    print("")

    def _print_top(title: str, items: Iterable[Tuple[str, int]]):
        print(title)
        for k, v in items:
            print(f"  - {k}  ({v})")
        print("")

    _print_top("🌍 Top Source IPs:", top["src_ips"])
    _print_top("🌍 Top Destination IPs:", top["dst_ips"])
    _print_top("🔢 Top Destination Ports:", top["dst_ports"])

    _print_top("🌐 HTTP Hosts:", http["hosts"])
    _print_top("🌐 HTTP User-Agents:", http["user_agents"])
    _print_top("🌐 HTTP URLs:", http["urls"])
    _print_top("📁 HTTP Content Types:", http["content_types"])

    _print_top("🔐 TLS Versions:", tls["versions"])
    _print_top("🔐 TLS Ciphers:", tls["ciphers"])
    _print_top("🔐 TLS SNI:", tls["sni"])
    _print_top("🔐 TLS JA3:", tls["ja3"])


def write_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[+] Wrote JSON: {path}")


def write_csv(path: str, data: Dict[str, Any], top_n_val: int) -> None:
    """
    Minimal CSV writer (one tab per section).
    For richer CSVs, write individual files per section.
    """
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "key", "value"])

        # High-level
        w.writerow(["meta", "file", data["file"]])
        w.writerow(["meta", "packets", data["packets"]])
        w.writerow(["meta", "bytes_total", data["bytes_total"]])
        w.writerow(["meta", "start", data["times"]["first"]])
        w.writerow(["meta", "end", data["times"]["last"]])
        w.writerow(["meta", "duration_seconds", data["times"]["duration_seconds"]])
        w.writerow(["meta", "avg_throughput", data["throughput"]["avg"]])

        # Protocols by packets
        for name, count in data["protocols"]["counts"].most_common(top_n_val):
            w.writerow(["protocols_packets", name, count])

        # Protocols by bytes
        for name, b in data["protocols"]["bytes"].most_common(top_n_val):
            w.writerow(["protocols_bytes", name, b])

        # Top IPs/ports
        for k, v in data["top"]["src_ips"]:
            w.writerow(["top_src_ips", k, v])
        for k, v in data["top"]["dst_ips"]:
            w.writerow(["top_dst_ips", k, v])
        for k, v in data["top"]["dst_ports"]:
            w.writerow(["top_dst_ports", k, v])

        # HTTP
        for k, v in data["http"]["hosts"]:
            w.writerow(["http_hosts", k, v])
        for k, v in data["http"]["user_agents"]:
            w.writerow(["http_user_agents", k, v])
        for k, v in data["http"]["urls"]:
            w.writerow(["http_urls", k, v])
        for k, v in data["http"]["content_types"]:
            w.writerow(["http_content_types", k, v])

        # TLS
        for k, v in data["tls"]["versions"]:
            w.writerow(["tls_versions", k, v])
        for k, v in data["tls"]["ciphers"]:
            w.writerow(["tls_ciphers", k, v])
        for k, v in data["tls"]["sni"]:
            w.writerow(["tls_sni", k, v])
        for k, v in data["tls"]["ja3"]:
            w.writerow(["tls_ja3", k, v])

    print(f"[+] Wrote CSV: {path}")


# --------------------------- Main ---------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="PCAP Quick Profiler")
    ap.add_argument("pcap", help="Path to .pcap / .pcapng")
    ap.add_argument("--top", type=int, default=10, help="Top N per category (default 10)")
    ap.add_argument("--json", help="Write JSON summary to this path")
    ap.add_argument("--csv", help="Write CSV summary to this path")
    args = ap.parse_args()

    # Early check: TShark available?
    try:
        import shutil
        if not shutil.which("tshark"):
            print("ERROR: 'tshark' not found on PATH. Install Wireshark (with TShark) and reopen PowerShell.", file=sys.stderr)
            sys.exit(2)
    except Exception:
        pass

    if not os.path.exists(args.pcap):
        print(f"ERROR: PCAP not found: {args.pcap}", file=sys.stderr)
        sys.exit(2)

    try:
        summary = profile_pcap(args.pcap, top_n_val=args.top)
    except Exception as e:
        print("ERROR while profiling PCAP:", e, file=sys.stderr)
        sys.exit(1)

    print_human(summary, args.top)

    if args.json:
        write_json(args.json, summary)
    if args.csv:
        write_csv(args.csv, summary, args.top)


if __name__ == "__main__":
    main()
