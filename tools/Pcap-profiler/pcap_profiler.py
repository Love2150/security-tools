#!/usr/bin/env python3
"""
PCAP Quick Profiler
- Summarizes: Protocols, Top IPs, Top Ports, Extracted MIME types, TLS info,
  HTTP headers, Timestamps, and Traffic Volume.
- Requires: tshark (Wireshark) + pyshark

Usage:
  python pcap_profiler.py capture.pcap --top 10
  python pcap_profiler.py capture.pcap --json out.json
  python pcap_profiler.py capture.pcap --csv out.csv
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Any, Optional

try:
    import pyshark
except ImportError:
    print("Error: pyshark is not installed. Install with: pip install pyshark", file=sys.stderr)
    sys.exit(1)


def safe_int(x: str, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def to_dt(ts: str) -> Optional[datetime]:
    # tshark frame.time_epoch is a float string (epoch seconds)
    try:
        return datetime.utcfromtimestamp(float(ts))
    except Exception:
        return None


def profile_pcap(path: str, top_n: int = 10, use_display_filters: bool = False) -> Dict[str, Any]:
    """
    Parse the pcap with pyshark FileCapture (streaming) and build summary counters.
    Set use_display_filters=True to make a second pass for TLS/HTTP-only fields (faster on large files).
    """
    # ---- Aggregates ----
    protocols = Counter()
    top_src = Counter()
    top_dst = Counter()
    top_dports = Counter()
    mime_types = Counter()                      # Extracted from HTTP response content-type
    http_user_agents = Counter()
    http_hosts = Counter()
    http_urls = Counter()

    tls_versions = Counter()
    tls_ciphers = Counter()
    tls_sni = Counter()
    tls_ja3 = Counter()                         # Filled only if field exists

    # Timestamps & traffic stats
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None
    packet_count = 0
    bytes_total = 0
    bytes_by_proto = Counter()

    # ---- First pass: general sweep ----
    cap = pyshark.FileCapture(path, keep_packets=False, use_json=True)
    for pkt in cap:
        packet_count += 1

        # Time info
        ts = getattr(pkt.frame_info, "time_epoch", None) or getattr(pkt.frame_info, "frame_time_epoch", None)
        dt = to_dt(ts) if ts else None
        if dt:
            if first_ts is None or dt < first_ts:
                first_ts = dt
            if last_ts is None or dt > last_ts:
                last_ts = dt

        # Bytes
        frame_len = safe_int(getattr(pkt.frame_info, "len", "0"))
        bytes_total += frame_len

        # Highest protocol layer
        hl = getattr(pkt, "highest_layer", None)
        if not hl and hasattr(pkt, "layers") and pkt.layers:
            hl = pkt.layers[-1].layer_name
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

        # Ports (dst)
        dport = None
        if hasattr(pkt, "tcp"):
            dport = getattr(pkt.tcp, "dstport", None)
        elif hasattr(pkt, "udp"):
            dport = getattr(pkt.udp, "dstport", None)
        if dport:
            top_dports[dport] += 1

    cap.close()

    # ---- Optional selective passes for protocol-specific fields ----
    # HTTP: content-type, host, user-agent, url/path
    http_cap = pyshark.FileCapture(
        path, keep_packets=False, use_json=True,
        display_filter="http"
    )
    for pkt in http_cap:
        # MIME type from response header
        ctype = getattr(getattr(pkt, "http", None), "content_type", None)
        if ctype:
            mime_types[ctype.lower()] += 1

        # Headers
        ua = getattr(pkt.http, "user_agent", None) if hasattr(pkt, "http") else None
        if ua:
            http_user_agents[ua] += 1

        host = getattr(pkt.http, "host", None) if hasattr(pkt, "http") else None
        if host:
            http_hosts[host] += 1

        # Request full URI if available, else path+host
        uri = getattr(pkt.http, "request_full_uri", None) if hasattr(pkt, "http") else None
        if not uri:
            # combine host + request_uri if present
            req_uri = getattr(pkt.http, "request_uri", None) if hasattr(pkt, "http") else None
            if host and req_uri:
                uri = f"http://{host}{req_uri}"
        if uri:
            http_urls[uri] += 1
    http_cap.close()

    # TLS: versions, ciphers, SNI, optional JA3
    tls_cap = pyshark.FileCapture(
        path, keep_packets=False, use_json=True,
        display_filter="tls"
    )
    for pkt in tls_cap:
        # Version
        ver = getattr(getattr(pkt, "tls", None), "record_version", None)
        if not ver:
            ver = getattr(getattr(pkt, "tls", None), "handshake_version", None)
        if ver:
            tls_versions[ver] += 1

        # Cipher suite (server hello)
        cipher = getattr(getattr(pkt, "tls", None), "handshake_ciphersuite", None)
        if cipher:
            tls_ciphers[cipher] += 1

        # SNI (Server Name Indication)
        sni = getattr(getattr(pkt, "tls", None), "handshake_extensions_server_name", None)
        if sni:
            tls_sni[sni] += 1

        # JA3 (depends on tshark version/fields)
        ja3 = getattr(getattr(pkt, "tls", None), "handshake_ja3", None)
        if ja3:
            tls_ja3[ja3] += 1
    tls_cap.close()

    # ---- Derive percentages and rates ----
    protos_total = sum(protocols.values()) or 1
    proto_pct = {k: round(v * 100.0 / protos_total, 2) for k, v in protocols.items()}

    duration_sec = 0.0
    if first_ts and last_ts:
        duration_sec = max(0.0, (last_ts - first_ts).total_seconds())
    pps = round(packet_count / duration_sec, 2) if duration_sec > 0 else None

    # Bytes by protocol percentages
    bytes_total_safe = bytes_total or 1
    bytes_by_proto_pct = {k: round(v * 100.0 / bytes_total_safe, 2) for k, v in bytes_by_proto.items()}

    # ---- Build result ----
    result = {
        "meta": {
            "file": path,
            "first_timestamp_utc": first_ts.isoformat() + "Z" if first_ts else None,
            "last_timestamp_utc": last_ts.isoformat() + "Z" if last_ts else None,
            "duration_seconds": duration_sec,
            "total_packets": packet_count,
            "total_bytes": bytes_total,
            "packets_per_second": pps,
        },
        "protocols": {
            "counts": protocols.most_common(),
            "percentages": dict(sorted(proto_pct.items(), key=lambda x: -x[1])),
        },
        "top_ips": {
            "sources": top_src.most_common(top_n),
            "destinations": top_dst.most_common(top_n),
        },
        "ports": {
            "top_destination_ports": top_dports.most_common(top_n),
        },
        "http": {
            "mime_types": mime_types.most_common(top_n),
            "user_agents": http_user_agents.most_common(top_n),
            "hosts": http_hosts.most_common(top_n),
            "urls": http_urls.most_common(top_n),
        },
        "tls": {
            "versions": tls_versions.most_common(top_n),
            "ciphers": tls_ciphers.most_common(top_n),
            "sni": tls_sni.most_common(top_n),
            "ja3": tls_ja3.most_common(top_n),
        },
        "traffic": {
            "bytes_by_protocol": bytes_by_proto.most_common(),
            "bytes_by_protocol_pct": dict(sorted(bytes_by_proto_pct.items(), key=lambda x: -x[1])),
        },
    }
    return result


def print_human(summary: Dict[str, Any], top_n: int):
    m = summary["meta"]
    print("=== PCAP QUICK PROFILER ===")
    print(f"File:            {m['file']}")
    print(f"First packet:    {m['first_timestamp_utc']}")
    print(f"Last packet:     {m['last_timestamp_utc']}")
    print(f"Duration (sec):  {m['duration_seconds']}")
    print(f"Total packets:   {m['total_packets']}")
    print(f"Total bytes:     {m['total_bytes']}")
    print(f"Packets/sec:     {m['packets_per_second']}")
    print()

    print("— Protocols —")
    for k, v in summary["protocols"]["counts"]:
        pct = summary["protocols"]["percentages"].get(k, 0)
        print(f"{k:<12} {v:>8}  ({pct:>6.2f}%)")
    print()

    print(f"— Top {top_n} Source IPs —")
    for ip, c in summary["top_ips"]["sources"]:
        print(f"{ip:<18} {c:>8}")
    print()

    print(f"— Top {top_n} Destination IPs —")
    for ip, c in summary["top_ips"]["destinations"]:
        print(f"{ip:<18} {c:>8}")
    print()

    print(f"— Top {top_n} Destination Ports —")
    for p, c in summary["ports"]["top_destination_ports"]:
        print(f"{p:<8} {c:>8}")
    print()

    print("— HTTP (MIME types) —")
    for k, v in summary["http"]["mime_types"]:
        print(f"{k:<35} {v:>8}")
    print()

    print("— HTTP (User-Agents) —")
    for k, v in summary["http"]["user_agents"]:
        print(f"{k[:60]:<60} {v:>6}")
    print()

    print("— HTTP (Hosts) —")
    for k, v in summary["http"]["hosts"]:
        print(f"{k:<40} {v:>6}")
    print()

    print("— HTTP (URLs) —")
    for k, v in summary["http"]["urls"]:
        print(f"{k[:80]:<80} {v:>6}")
    print()

    print("— TLS —")
    print("Versions:")
    for k, v in summary["tls"]["versions"]:
        print(f"  {k:<20} {v:>6}")
    print("Ciphers:")
    for k, v in summary["tls"]["ciphers"]:
        print(f"  {k:<20} {v:>6}")
    print("SNI:")
    for k, v in summary["tls"]["sni"]:
        print(f"  {k:<40} {v:>6}")
    if summary["tls"]["ja3"]:
        print("JA3:")
        for k, v in summary["tls"]["ja3"]:
            print(f"  {k:<40} {v:>6}")
    print()

    print("— Traffic Volume —")
    print("Bytes by protocol:")
    for k, v in summary["traffic"]["bytes_by_protocol"]:
        pct = summary["traffic"]["bytes_by_protocol_pct"].get(k, 0)
        print(f"  {k:<12} {v:>10}  ({pct:>6.2f}%)")
    print()


def write_json(path: str, data: Dict[str, Any]):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def write_csv(path: str, summary: Dict[str, Any]):
    import csv
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "key", "value", "count_or_pct"])
        # protocols
        for k, v in summary["protocols"]["counts"]:
            pct = summary["protocols"]["percentages"].get(k, 0)
            w.writerow(["protocols", k, v, pct])
        # IPs
        for ip, c in summary["top_ips"]["sources"]:
            w.writerow(["top_src", ip, c, ""])
        for ip, c in summary["top_ips"]["destinations"]:
            w.writerow(["top_dst", ip, c, ""])
        # Ports
        for p, c in summary["ports"]["top_destination_ports"]:
            w.writerow(["top_dport", p, c, ""])
        # HTTP
        for k, v in summary["http"]["mime_types"]:
            w.writerow(["http_mime", k, v, ""])
        for k, v in summary["http"]["user_agents"]:
            w.writerow(["http_ua", k, v, ""])
        for k, v in summary["http"]["hosts"]:
            w.writerow(["http_host", k, v, ""])
        for k, v in summary["http"]["urls"]:
            w.writerow(["http_url", k, v, ""])
        # TLS
        for k, v in summary["tls"]["versions"]:
            w.writerow(["tls_version", k, v, ""])
        for k, v in summary["tls"]["ciphers"]:
            w.writerow(["tls_cipher", k, v, ""])
        for k, v in summary["tls"]["sni"]:
            w.writerow(["tls_sni", k, v, ""])
        for k, v in summary["tls"]["ja3"]:
            w.writerow(["tls_ja3", k, v, ""])
        # Traffic
        for k, v in summary["traffic"]["bytes_by_protocol"]:
            pct = summary["traffic"]["bytes_by_protocol_pct"].get(k, 0)
            w.writerow(["bytes_by_proto", k, v, pct])


def main():
    ap = argparse.ArgumentParser(description="PCAP Quick Profiler")
    ap.add_argument("pcap", help="Path to pcap/pcapng file")
    ap.add_argument("--top", type=int, default=10, help="How many top items to show per section")
    ap.add_argument("--json", help="Write full JSON summary to file")
    ap.add_argument("--csv", help="Write CSV summary to file")
    args = ap.parse_args()

    summary = profile_pcap(args.pcap, top_n=args.top)
    print_human(summary, top_n=args.top)

    if args.json:
        write_json(args.json, summary)
        print(f"\n[+] JSON written to {args.json}")
    if args.csv:
        write_csv(args.csv, summary)
        print(f"[+] CSV written to {args.csv}")


if __name__ == "__main__":
    main()
