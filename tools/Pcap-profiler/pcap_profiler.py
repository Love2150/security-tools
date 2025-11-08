#!/usr/bin/env python3
# PCAP Quick Profiler (Windows-friendly, robust time parsing + event loop fix)

from __future__ import annotations
import argparse, csv, json, os, sys, shutil
from collections import Counter
from typing import Any, Dict, Optional
from datetime import datetime, timezone
import asyncio

# ----- Dependencies check -----
try:
    import pyshark
except Exception:
    print("ERROR: pyshark is not installed. Install with: pip install pyshark", file=sys.stderr)
    sys.exit(1)

def ensure_tshark() -> None:
    if shutil.which("tshark") is None:
        print(
            "ERROR: TShark is not on PATH.\n"
            "Install Wireshark (include TShark) and add "
            "C:\\Program Files\\Wireshark to PATH.",
            file=sys.stderr
        )
        sys.exit(1)

# ---- Windows event loop helper (fixes 'There is no current event loop') ----
def ensure_event_loop() -> asyncio.AbstractEventLoop:
    """
    Guarantee a running event loop in main thread and return it.
    """
    try:
        loop = asyncio.get_event_loop()
        # If it's closed, make a fresh one
        if loop.is_closed():
            raise RuntimeError
        return loop
    except Exception:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop

# ----- Helpers -----
def safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(str(x))
    except Exception:
        return default

def safe_sniff_time(pkt) -> Optional[datetime]:
    """
    tz-aware UTC datetime for a packet:
      1) pkt.sniff_time (datetime)
      2) frame_info.time_epoch (epoch)
      3) frame_info.time (ISO 'YYYY-mm-ddTHH:MM:SS' or 'YYYY-mm-dd HH:MM:SS')
    """
    dt = getattr(pkt, "sniff_time", None)
    if dt:
        try:
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

    fi = getattr(pkt, "frame_info", None)
    if fi:
        ts = getattr(fi, "time_epoch", None)
        if ts is not None:
            try:
                return datetime.fromtimestamp(float(str(ts)), tz=timezone.utc)
            except Exception:
                pass
        iso = getattr(fi, "time", None)
        if iso:
            s = str(iso).strip()
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                except Exception:
                    continue
    return None

def fmt_human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    val = float(n); idx = 0
    while val >= 1024 and idx < len(units) - 1:
        val /= 1024.0; idx += 1
    return f"{val:.1f} {units[idx]}"

def pct(part: int, whole: int) -> str:
    return f"{(100.0 * part / whole):.1f}%" if whole else "0.0%"

# ----- Core profiling -----
def profile_pcap(path: str, top_n: int = 10) -> Dict[str, Any]:
    ensure_tshark()
    loop = ensure_event_loop()  # <<< ensure loop exists

    # First pass (general stats)
    cap = pyshark.FileCapture(path, keep_packets=False, use_json=True, eventloop=loop)

    total_packets = 0
    total_bytes = 0
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None

    proto_counter = Counter()
    proto_bytes = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    dst_ports = Counter()

    try:
        for pkt in cap:
            total_packets += 1

            # time
            dt = safe_sniff_time(pkt)
            if dt:
                if first_ts is None or dt < first_ts:
                    first_ts = dt
                if last_ts is None or dt > last_ts:
                    last_ts = dt

            # sizes
            frame_len = safe_int(getattr(pkt.frame_info, "len", "0"))
            total_bytes += frame_len

            # protocol
            hl = getattr(pkt, "highest_layer", None) or "UNKNOWN"
            proto_counter[hl] += 1
            proto_bytes[hl] += frame_len

            # IPs
            ip = getattr(pkt, "ip", None)
            if ip:
                s = getattr(ip, "src", None)
                d = getattr(ip, "dst", None)
                if s: src_ips[s] += 1
                if d: dst_ips[d] += 1

            # Ports
            tcp = getattr(pkt, "tcp", None)
            udp = getattr(pkt, "udp", None)
            if tcp:
                p = getattr(tcp, "dstport", None)
                if p: dst_ports[str(p)] += 1
            elif udp:
                p = getattr(udp, "dstport", None)
                if p: dst_ports[str(p)] += 1
    finally:
        cap.close()

    # Second pass: HTTP
    http_hosts = Counter(); http_uas = Counter(); http_urls = Counter(); http_ctypes = Counter()
    http_cap = pyshark.FileCapture(path, keep_packets=False, use_json=True, display_filter="http", eventloop=loop)
    try:
        for pkt in http_cap:
            http = getattr(pkt, "http", None)
            if not http: continue
            host = getattr(http, "host", None)
            if host: http_hosts[host] += 1
            ua = getattr(http, "user_agent", None)
            if ua: http_uas[ua] += 1
            full = getattr(http, "request_full_uri", None)
            if full:
                http_urls[full] += 1
            else:
                uri = getattr(http, "request_uri", None)
                if host and uri: http_urls[f"http://{host}{uri}"] += 1
            ctype = getattr(http, "content_type", None)
            if ctype: http_ctypes[ctype] += 1
    finally:
        http_cap.close()

    # Third pass: TLS
    tls_versions = Counter(); tls_ciphers = Counter(); tls_sni = Counter(); tls_ja3 = Counter()
    tls_cap = pyshark.FileCapture(path, keep_packets=False, use_json=True, display_filter="tls", eventloop=loop)
    try:
        for pkt in tls_cap:
            tls = getattr(pkt, "tls", None)
            if not tls: continue
            for fld in ("handshake_version", "record_version"):
                v = getattr(tls, fld, None)
                if v: tls_versions[str(v)] += 1
            cs = getattr(tls, "handshake_ciphersuite", None)
            if cs: tls_ciphers[str(cs)] += 1
            sni = getattr(tls, "handshake_extensions_server_name", None)
            if sni: tls_sni[str(sni)] += 1
            ja3 = getattr(tls, "handshake_ja3", None)
            if ja3: tls_ja3[str(ja3)] += 1
            ja3s = getattr(tls, "handshake_ja3s", None)
            if ja3s: tls_ja3[str(ja3s)] += 1
    finally:
        tls_cap.close()

    return {
        "file": os.path.abspath(path),
        "packets": total_packets,
        "bytes": total_bytes,
        "start": first_ts.isoformat() if first_ts else None,
        "end": last_ts.isoformat() if last_ts else None,
        "duration_seconds": (last_ts - first_ts).total_seconds() if first_ts and last_ts else 0.0,
        "protocols": proto_counter.most_common(),
        "bytes_by_protocol": proto_bytes.most_common(),
        "top_src_ips": src_ips.most_common(top_n),
        "top_dst_ips": dst_ips.most_common(top_n),
        "top_dst_ports": dst_ports.most_common(top_n),
        "http_hosts": http_hosts.most_common(top_n),
        "http_user_agents": http_uas.most_common(top_n),
        "http_urls": http_urls.most_common(top_n),
        "http_content_types": http_ctypes.most_common(top_n),
        "tls_versions": tls_versions.most_common(top_n),
        "tls_ciphers": tls_ciphers.most_common(top_n),
        "tls_sni": tls_sni.most_common(top_n),
        "tls_ja3": tls_ja3.most_common(top_n),
    }

# ----- Rendering -----
def fmt_pct_row(title: str, items, total: int):
    print(f"\n{title}:")
    if not items:
        print("  (none)"); return
    for name, val in items:
        print(f"  - {name:<14} {val:<8} ({pct(val, total)})" if total else f"  - {name:<14} {val}")

def print_summary(s: Dict[str, Any], top_n: int) -> None:
    print(f"PCAP Quick Profiler — {s['file']}")
    print("=" * 80)
    print(f"Packets: {s['packets']:,}")
    print(f"Bytes:   {s['bytes']:,}")
    if s["start"] and s["end"]:
        print(f"Start:   {s['start']}")
        print(f"End:     {s['end']}")
    else:
        print("Start:   None"); print("End:     None")
    dur = s["duration_seconds"] or 0.0
    if dur > 0:
        avg = s["bytes"] / dur
        print(f"Duration: {dur:.2f}s    Avg throughput: {fmt_human_bytes(int(avg))}/s")
    else:
        print("Duration: 0.00s    Avg throughput: n/a")

    print("\n🖧 Protocols (by packets):")
    if s["protocols"]:
        for name, cnt in s["protocols"]:
            print(f"  - {name:<14} {cnt:<6} ({pct(cnt, s['packets'])})")
    else:
        print("  (none)")

    print("\n📦 Bytes by protocol:")
    if s["bytes_by_protocol"]:
        for name, nbytes in s["bytes_by_protocol"]:
            print(f"  - {name:<14} {nbytes:<8} ({pct(nbytes, s['bytes'])})")
    else:
        print("  (none)")

    def _list(title, items):
        print(f"\n{title}:")
        if items:
            for k, v in items: print(f"  - {k}  ({v})")
        else:
            print("  (none)")

    _list("🌍 Top Source IPs", s["top_src_ips"])
    _list("🌍 Top Destination IPs", s["top_dst_ips"])
    _list("🔢 Top Destination Ports", s["top_dst_ports"])
    _list("🌐 HTTP Hosts", s["http_hosts"])
    _list("🌐 HTTP User-Agents", s["http_user_agents"])
    _list("🌐 HTTP URLs", s["http_urls"])
    _list("📁 HTTP Content Types", s["http_content_types"])
    _list("🔐 TLS Versions", s["tls_versions"])
    _list("🔐 TLS Ciphers", s["tls_ciphers"])
    _list("🔐 TLS SNI", s["tls_sni"])
    _list("🔐 TLS JA3", s["tls_ja3"])

def write_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    print(f"\n[+] Wrote JSON: {os.path.abspath(path)}")

def write_csv(path: str, data: Dict[str, Any], top_n: int) -> None:
    rows = [
        ["file", data["file"]],
        ["packets", data["packets"]],
        ["bytes", data["bytes"]],
        ["start", data["start"] or ""],
        ["end", data["end"] or ""],
        ["duration_seconds", data["duration_seconds"]],
    ]
    def add(name, items):
        rows.append([name, "value", "count"])
        for k, v in items[:top_n]:
            rows.append(["", k, v])
    add("protocols", data["protocols"])
    add("bytes_by_protocol", data["bytes_by_protocol"])
    add("top_src_ips", data["top_src_ips"])
    add("top_dst_ips", data["top_dst_ips"])
    add("top_dst_ports", data["top_dst_ports"])
    add("http_hosts", data["http_hosts"])
    add("http_user_agents", data["http_user_agents"])
    add("http_urls", data["http_urls"])
    add("http_content_types", data["http_content_types"])
    add("tls_versions", data["tls_versions"])
    add("tls_ciphers", data["tls_ciphers"])
    add("tls_sni", data["tls_sni"])
    add("tls_ja3", data["tls_ja3"])
    with open(path, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows(rows)
    print(f"[+] Wrote CSV:  {os.path.abspath(path)}")

# ----- CLI -----
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="PCAP Quick Profiler (Windows-friendly)")
    p.add_argument("pcap", help="Path to .pcap/.pcapng")
    p.add_argument("--top", type=int, default=10, help="Top-N items per list (default: 10)")
    p.add_argument("--json", help="Write JSON summary to this file")
    p.add_argument("--csv", help="Write CSV summary to this file")
    return p.parse_args()

def main() -> None:
    args = parse_args()
    try:
        summary = profile_pcap(args.pcap, top_n=args.top)
        print_summary(summary, top_n=args.top)
        if args.json: write_json(args.json, summary)
        if args.csv:  write_csv(args.csv, summary, top_n=args.top)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr); sys.exit(130)
    except Exception as e:
        print(f"ERROR while profiling PCAP: {e}", file=sys.stderr); sys.exit(1)

if __name__ == "__main__":
    main()
