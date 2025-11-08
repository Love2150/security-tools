#!/usr/bin/env python3
# PCAP Quick Profiler (Windows-friendly, decode-as + JSON/CSV + config profiles)
# Example (PowerShell):
#   python .\pcap_profiler.py "C:\path\capture.pcap"
#   python .\pcap_profiler.py "C:\path\capture.pcap" --profile default
#   python .\pcap_profiler.py "C:\path\capture.pcap" --decode tcp.port==36050,http

from __future__ import annotations
import argparse
import os
import sys
import shutil
import asyncio
import json
import csv
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

try:
    import pyshark
except Exception:
    print("ERROR: pyshark not installed. Run: pip install pyshark", file=sys.stderr)
    sys.exit(1)

# ---------- Config loading ----------
DEFAULT_CONFIG_LOCATIONS: List[str] = []

def _init_config_locations():
    here = os.getcwd()
    DEFAULT_CONFIG_LOCATIONS.append(os.path.join(here, "pcap_profiler.config.json"))
    # Windows user locations
    home = os.path.expanduser("~")
    DEFAULT_CONFIG_LOCATIONS.append(os.path.join(home, ".pcap_profiler.json"))
    appdata = os.environ.get("APPDATA")
    if appdata:
        DEFAULT_CONFIG_LOCATIONS.append(os.path.join(appdata, "pcap_profiler", "config.json"))

_init_config_locations()

def load_config(explicit_path: Optional[str], profile: Optional[str]) -> Dict[str, Any]:
    """
    Loads JSON config from:
      1) explicit --config path (if provided)
      2) ./pcap_profiler.config.json
      3) %APPDATA%\pcap_profiler\config.json
      4) %USERPROFILE%\.pcap_profiler.json
    Supports top-level keys and named profiles.
    """
    paths = []
    if explicit_path:
        paths = [explicit_path]
    else:
        paths = DEFAULT_CONFIG_LOCATIONS

    cfg: Dict[str, Any] = {}
    for p in paths:
        try:
            if os.path.isfile(p):
                with open(p, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                break
        except Exception:
            pass

    # If a profile is requested, merge it on top
    prof_name = profile or cfg.get("default_profile")
    if prof_name:
        profiles = cfg.get("profiles", {})
        prof = profiles.get(prof_name, {})
        # Merge (profile wins)
        merged = dict(cfg)
        merged.pop("profiles", None)
        merged.update(prof)
        cfg = merged

    return cfg

# ---------- System helpers ----------
def ensure_tshark() -> None:
    if shutil.which("tshark") is None:
        print("ERROR: TShark not found on PATH.\n"
              "Install Wireshark (select 'Install TShark') and add it to your PATH.\n"
              "Then restart PowerShell/cmd.", file=sys.stderr)
        sys.exit(1)

def safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(str(x))
    except Exception:
        return default

def _parse_iso_utc(s: str) -> Optional[datetime]:
    if not s:
        return None
    s = str(s).strip()
    if s.endswith("Z"):
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            pass
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None

def safe_sniff_time(pkt) -> Optional[datetime]:
    dt = getattr(pkt, "sniff_time", None)
    if dt:
        try:
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        except Exception:
            pass
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

# ---------- Core profiling ----------
def profile_pcap(path: str, top_n: int = 10, decode_maps: list[str] | None = None) -> Dict[str, Any]:
    ensure_tshark()

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

    custom_params: list[str] = []
    for m in (decode_maps or []):
        custom_params += ["-d", m]

    cap = pyshark.FileCapture(
        path,
        keep_packets=False,
        use_json=False,
        eventloop=loop,
        custom_parameters=custom_params
    )
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

    # HTTP
    http_cap = pyshark.FileCapture(
        path,
        keep_packets=False,
        use_json=False,
        display_filter="http",
        eventloop=loop,
        custom_parameters=custom_params
    )
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

    # TLS
    tls_cap = pyshark.FileCapture(
        path,
        keep_packets=False,
        use_json=False,
        display_filter="tls",
        eventloop=loop,
        custom_parameters=custom_params
    )
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

# ---------- Output ----------
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

def write_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def write_csv(path: str, data: Dict[str, Any]) -> None:
    rows = []
    for k, v in data["src_ips"]:
        rows.append({"category": "src_ip", "key": k, "count": v})
    for k, v in data["dst_ips"]:
        rows.append({"category": "dst_ip", "key": k, "count": v})
    for k, v in data["dst_ports"]:
        rows.append({"category": "dst_port", "key": k, "count": v})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["category", "key", "count"])
        w.writeheader()
        w.writerows(rows)

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="PCAP Quick Profiler (Windows-friendly). Supports config + profiles.")
    ap.add_argument("pcap", help="Path to .pcap or .pcapng file")
    ap.add_argument("--top", type=int, help="Top-N entries per category (overrides config)")
    ap.add_argument("--decode", action="append", default=[],
                    help="Decode-as mapping like tcp.port==36050,http (repeatable; merges with config)")
    ap.add_argument("--json", help="Write full summary to JSON file")
    ap.add_argument("--csv", help="Write a flat CSV of top IPs/ports to this path")
    ap.add_argument("--config", help="Path to config JSON (optional)")
    ap.add_argument("--profile", help="Profile name from config (optional)")
    args = ap.parse_args()

    # Merge config
    cfg = load_config(args.config, args.profile)

    # Effective settings: CLI overrides config
    effective_top = args.top if args.top is not None else int(cfg.get("top", 10))
    decode_cfg = cfg.get("decode", []) or []
    # Expand http_ports/tls_ports into decode rules
    http_ports = cfg.get("http_ports", []) or []
    tls_ports = cfg.get("tls_ports", []) or []
    for p in http_ports:
        decode_cfg.append(f"tcp.port=={p},http")
    for p in tls_ports:
        decode_cfg.append(f"tcp.port=={p},tls")

    # Merge CLI --decode after config (CLI wins if duplicates)
    decode_maps = list(dict.fromkeys(decode_cfg + (args.decode or [])))

    try:
        result = profile_pcap(args.pcap, effective_top, decode_maps)
        print_summary(result)
        if args.json:
            write_json(args.json, result)
        if args.csv:
            write_csv(args.csv, result)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
    except Exception as e:
        print(f"ERROR while profiling PCAP: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

