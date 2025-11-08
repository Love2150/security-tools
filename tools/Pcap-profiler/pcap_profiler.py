#!/usr/bin/env python3
# PCAP Quick Profiler (Windows-friendly, no time_epoch float parsing)
# Author: Brandon Love
# Usage:
#   python pcap_profiler.py "C:\path\to\capture.pcap" --top 10

from __future__ import annotations
import argparse
import os
import sys
import shutil
import asyncio
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# ----- Dependencies check -----
try:
    import pyshark
except Exception:
    print("ERROR: pyshark not installed. Run: pip install pyshark", file=sys.stderr)
    sys.exit(1)

def ensure_tshark() -> None:
    if shutil.which("tshark") is None:
        print("ERROR: TShark not found on PATH.\n"
              "Install Wireshark (select 'Install TShark') and add it to your PATH.",
              file=sys.stderr)
        sys.exit(1)

# ----- Helpers -----
def safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(str(x))
    except Exception:
        return default

def _parse_iso_utc(s: str) -> Optional[datetime]:
    """Parse a few common ISO forms and return tz-aware UTC datetime."""
    if not s:
        return None
    s = str(s).strip()
    # Support trailing 'Z'
    if s.endswith("Z"):
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            pass
    # Native ISO
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        pass
    # Fallback formats
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None

def safe_sniff_time(pkt) -> Optional[datetime]:
    """Return a tz-aware UTC datetime for a packet WITHOUT touching time_epoch."""
    # Best: sniff_time from pyshark (datetime or None)
    dt = getattr(pkt, "sniff_time", None)
    if dt:
        try:
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        except Exception:
            pass
    # Fallback: frame_info.time (string)
    fi = getattr(pkt, "frame_info", None)
    if fi:
        human = getattr(fi, "time", None)
        if human:
            parsed = _parse_iso_utc(str(human))
            if parsed:
                return parsed
    return None

def fmt_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    val = float(n)
    for u in units:
        if val < 1024:
            return f"{val:.1f} {u}"
        val /= 1024
    return f"{val:.1f} TB"

# ----- Core profiling -----
def profile_pcap(path: str, top_n: int = 10) -> Dict[str, Any]:
    ensure_tshark()

    # Dedicated asyncio event loop (needed on Windows for pyshark/tshark)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    total_packets = 0
    total_bytes = 0
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None
    proto_counter = Counter()
    proto_bytes = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    dst_ports = Counter()

    # Pass 1: overall scan  (use_json=False to avoid schema weirdness)
    cap = pyshark.FileCapture(path, keep_packets=False, use_json=False, eventloop=loop)
    try:
        for pkt in cap:
            total_packets += 1
            frame_len = safe_int(getattr(pkt.frame_info, "len", 0))
            total_bytes += frame_len

            dt = safe_sniff_time(pkt)
            if dt:
                if not first_ts or dt < first_ts:
                    first_ts = dt
                if not last_ts or dt > last_ts:
                    last_ts = dt

            hl = getattr(pkt, "highest_layer", "UNKNOWN")
            proto_counter[hl] += 1
            proto_bytes[hl] += frame_len

            ip = getattr(pkt, "ip", None)
            if ip:
                s = getattr(ip, "src", None)
                d = getattr(ip, "dst", None)
                if s:
                    src_ips[s] += 1
                if d:
                    dst_ips[d] += 1

            tcp = getattr(pkt, "tcp", None)
            udp = getattr(pkt, "udp", None)
            if tcp:
                p = getattr(tcp, "dstport", None)
                if p:
                    dst_ports[p] += 1
            elif udp:
                p = getattr(udp, "dstport", None)
                if p:
                    dst_ports[p] += 1
    finally:
        cap.close()

    # Pass 2: HTTP
    http_cap = pyshark.FileCapture(path, keep_packets=False, use_json=False,
                                   display_filter="http", eventloop=loop)
    http_hosts = Counter()
    http_uas = Counter()
    http_urls = Counter()
    http_ctypes = Counter()
    try:
        for pkt in http_cap:
            http = getattr(pkt, "http", None)
            if not http:
                continue
            host = getattr(http, "host", None)
            if host:
                http_hosts[host] += 1
            ua = getattr(http, "user_agent", None)
            if ua:
                http_uas[ua] += 1
            full = getattr(http, "request_full_uri", None)
            if full:
                http_urls[full] += 1
            else:
                uri = getattr(http, "request_uri", None)
                if host and uri:
                    http_urls[f"http://{host}{uri}"] += 1
            ctype = getattr(http, "content_type", None)
            if ctype:
                http_ctypes[ctype] += 1
    finally:
        http_cap.close()

    # Pass 3: TLS
    tls_cap = pyshark.FileCapture(path, keep_packets=False, use_json=False,
                                  display_filter="tls", eventloop=loop)
    tls_versions = Counter()
    tls_ciphers = Counter()
    tls_sni = Counter()
    tls_ja3 = Counter()
    try:
        for pkt in tls_cap:
            tls = getattr(pkt, "tls", None)
            if not tls:
                continue
            v = getattr(tls, "handshake_version", None)
            if v:
                tls_versions[v] += 1
            cs = getattr(tls, "handshake_ciphersuite", None)
            if cs:
                tls_ciphers[cs] += 1
            sni = getattr(tls, "handshake_extensions_server_name", None)
            if sni:
                tls_sni[sni] += 1
            ja3 = getattr(tls, "handshake_ja3", None)
            if ja3:
                tls_ja3[ja3] += 1
    finally:
        tls_cap.close()
        try:
            loop.close()
        except Exception:
            pass

    dur = (last_ts - first_ts).total_seconds() if first_ts and last_ts else 0.0

    return {
        "file": os.path.abspath(path),
        "packets": total_packets,
        "bytes": total_bytes,
        "start": first_ts.isoformat() if first_ts else None,
        "end": last_ts.isoformat() if last_ts else None,
        "duration": dur,
        "protocols": proto_counter.most_common(),
        "bytes_by_protocol": proto_bytes.most_common(),
        "src_ips": src_ips.most_common(top_n),
        "dst_ips": dst_ips.most_common(top_n),
        "dst_ports": dst_ports.most_common(top_n),
        "http_hosts": http_hosts.most_common(top_n),
        "http_user_agents": http_uas.most_common(top_n),
        "http_urls": http_urls.most_common(top_n),
        "http_content_types": http_ctypes.most_common(top_n),
        "tls_versions": tls_versions.most_common(top_n),
        "tls_ciphers": tls_ciphers.most_common(top_n),
        "tls_sni": tls_sni.most_common(top_n),
        "tls_ja3": tls_ja3.most_common(top_n),
    }

# ----- Output -----
def fmt_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    val = float(n)
    for u in units:
        if val < 1024:
            return f"{val:.1f} {u}"
        val /= 1024
    return f"{val:.1f} TB"

def print_summary(s: Dict[str, Any]) -> None:
    print(f"PCAP Quick Profiler — {s['file']}")
    print("=" * 80)
    print(f"Packets: {s['packets']:,}")
    print(f"Bytes:   {s['bytes']:,}")
    print(f"Start:   {s['start'] or 'None'}")
    print(f"End:     {s['end'] or 'None'}")
    if s["duration"] and s["duration"] > 0:
        avg = s["bytes"] / s["duration"]
        print(f"Duration: {s['duration']:.2f}s   Avg throughput: {fmt_bytes(int(avg))}/s")
    else:
        print("Duration: 0.00s   Avg throughput: n/a")

    def show(title, items):
        print(f"\n{title}:")
        if not items:
            print("  (none)")
        for k, v in items:
            print(f"  - {k}  ({v})")

    show("🖧 Protocols", s["protocols"])
    show("📦 Bytes by protocol", s["bytes_by_protocol"])
    show("🌍 Top Source IPs", s["src_ips"])
    show("🌍 Top Destination IPs", s["dst_ips"])
    show("🔢 Top Destination Ports", s["dst_ports"])
    show("🌐 HTTP Hosts", s["http_hosts"])
    show("🌐 HTTP User-Agents", s["http_user_agents"])
    show("🌐 HTTP URLs", s["http_urls"])
    show("📁 HTTP Content Types", s["http_content_types"])
    show("🔐 TLS Versions", s["tls_versions"])
    show("🔐 TLS Ciphers", s["tls_ciphers"])
    show("🔐 TLS SNI", s["tls_sni"])
    show("🔐 TLS JA3", s["tls_ja3"])

# ----- CLI -----
def main():
    ap = argparse.ArgumentParser(description="PCAP Quick Profiler (Windows-friendly, no time_epoch parsing)")
    ap.add_argument("pcap", help="Path to .pcap or .pcapng file")
    ap.add_argument("--top", type=int, default=10, help="Top-N entries per category")
    args = ap.parse_args()

    try:
        result = profile_pcap(args.pcap, args.top)
        print_summary(result)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
    except Exception as e:
        print(f"ERROR while profiling PCAP: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
