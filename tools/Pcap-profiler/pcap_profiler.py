#!/usr/bin/env python3
# PCAP Quick Profiler (Windows-friendly, auto-save reports, decode-as, config profiles)
# Examples (PowerShell):
#   python .\pcap_profiler.py "C:\path\capture.pcap"
#   python .\pcap_profiler.py "C:\path\capture.pcap" --all
#   python .\pcap_profiler.py "C:\path\capture.pcap" --decode tcp.port==36050,http
#   python .\pcap_profiler.py "C:\path\capture.pcap" --outdir "..\..\reports\pcap-profiler"

from __future__ import annotations
import argparse
import os
import sys
import shutil
import asyncio
import json
import csv
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Tuple
from typing import Tuple
import importlib


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
      3) %APPDATA%\\pcap_profiler\\config.json
      4) %USERPROFILE%\\.pcap_profiler.json
    Supports top-level keys and named profiles.
    """
    paths = [explicit_path] if explicit_path else DEFAULT_CONFIG_LOCATIONS
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

    # helper: most_common with "all" support
    def mc(counter: Counter, n: Optional[int]):
        if n is None or n <= 0:
            return counter.most_common(None)
        return counter.most_common(n)

    return {
        "file": os.path.abspath(path),
        "packets": total_packets,
        "bytes": total_bytes,
        "start": first_ts.isoformat() if first_ts else None,
        "end": last_ts.isoformat() if last_ts else None,
        "duration": dur,
        "protocols": mc(proto_counter, None),          # all protocols
        "bytes_by_protocol": mc(proto_bytes, None),    # all protocols by bytes
        "src_ips": mc(src_ips, top_n),                 # all if top_n<=0
        "dst_ips": mc(dst_ips, top_n),                 # all if top_n<=0
        "dst_ports": mc(dst_ports, top_n),             # all if top_n<=0
        "http_hosts": mc(http_hosts, top_n),
        "http_user_agents": mc(http_uas, top_n),
        "http_urls": mc(http_urls, top_n),
        "http_content_types": mc(http_ctypes, top_n),
        "tls_versions": mc(tls_versions, top_n),
        "tls_ciphers": mc(tls_ciphers, top_n),
        "tls_sni": mc(tls_sni, top_n),
        "tls_ja3": mc(tls_ja3, top_n),
    }

# ---------- Output ----------
def render_text_summary(s: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append(f"PCAP Quick Profiler — {s['file']}")
    lines.append("=" * 80)
    lines.append(f"Packets: {s['packets']:,}")
    lines.append(f"Bytes:   {s['bytes']:,}")
    lines.append(f"Start:   {s['start'] or 'None'}")
    lines.append(f"End:     {s['end'] or 'None'}")
    if s["duration"] and s["duration"] > 0:
        avg = s["bytes"] / s["duration"]
        lines.append(f"Duration: {s['duration']:.2f}s   Avg throughput: {fmt_bytes(int(avg))}/s")
    else:
        lines.append("Duration: 0.00s   Avg throughput: n/a")

    def block(title: str, items: List[Tuple[str, int]]):
        lines.append(f"\n{title}:")
        if not items:
            lines.append("  (none)")
            return
        for k, v in items:
            lines.append(f"  - {k}  ({v})")

    block("🖧 Protocols", s["protocols"])
    block("📦 Bytes by protocol", s["bytes_by_protocol"])
    block("🌍 Top Source IPs", s["src_ips"])
    block("🌍 Top Destination IPs", s["dst_ips"])
    block("🔢 Top Destination Ports", s["dst_ports"])
    block("🌐 HTTP Hosts", s["http_hosts"])
    block("🌐 HTTP User-Agents", s["http_user_agents"])
    block("🌐 HTTP URLs", s["http_urls"])
    block("📁 HTTP Content Types", s["http_content_types"])
    block("🔐 TLS Versions", s["tls_versions"])
    block("🔐 TLS Ciphers", s["tls_ciphers"])
    block("🔐 TLS SNI", s["tls_sni"])
    block("🔐 TLS JA3", s["tls_ja3"])
    return "\n".join(lines)

def print_summary(s: Dict[str, Any]) -> None:
    print(render_text_summary(s))

def write_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def write_txt(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

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

def maybe_run_vt_check(profiler_json_path: Path, pcap_path: str, outdir: Optional[str],
                       force: bool = False, disable: bool = False) -> None:
    """
    If VT_API_KEY is set (or --vt used), call vt_check_ips to scan IPs found in the
    profiler JSON and save results next to the profile reports.
    """
    if disable:
        print("[vt] Skipping VT check (disabled).")
        return

    api_key = os.environ.get("VT_API_KEY")
    if not api_key and not force:
        print("[vt] VT_API_KEY not set; skipping VT check.")
        return

    try:
        vt = importlib.import_module("vt_check_ips")
    except Exception:
        print("[vt] vt_check_ips.py not found or import failed; skipping VT check.")
        return

    try:
        ips = vt.ip_set_from_profiler_json(str(profiler_json_path))
        if not ips:
            print("[vt] No IPs found in profiler JSON; nothing to check.")
            return

        print(f"[vt] Checking {len(ips)} IPs against VirusTotal...")
        results = vt.run_vt_checks(ips, api_key or "")
        out_json, out_txt = vt_output_paths(pcap_path, outdir)
        vt.write_vt_report(str(out_json), str(out_txt), results)
        print(f"[vt] Saved VT JSON: {out_json}")
        print(f"[vt] Saved VT TXT : {out_txt}")
    except Exception as e:
        print(f"[vt] Error during VT check: {e}", file=sys.stderr)


# ---------- Autosave paths ----------
def default_reports_dir() -> Path:
    """
    If this file is at tools/Pcap-profiler/pcap_profiler.py,
    return <repo_root>/reports/pcap-profiler.
    Fallback to CWD/reports/pcap-profiler if resolution fails.
    """
    try:
        here = Path(__file__).resolve()
        repo_root = here.parents[2]  # pcap_profiler.py -> Pcap-profiler -> tools -> repo_root
        return repo_root / "reports" / "pcap-profiler"
    except Exception:
        return Path.cwd() / "reports" / "pcap-profiler"

def output_paths(pcap_path: str, outdir: Optional[str]) -> Tuple[Path, Path, Path]:
    base_dir = Path(outdir).resolve() if outdir else default_reports_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = Path(pcap_path).stem
    json_path = base_dir / f"{stem}_{ts}.json"
    txt_path = base_dir / f"{stem}_{ts}.txt"
    csv_path = base_dir / f"{stem}_{ts}.csv"
    return json_path, txt_path, csv_path

def vt_output_paths(pcap_path: str, outdir: Optional[str]) -> Tuple[Path, Path]:
    base_dir = Path(outdir).resolve() if outdir else default_reports_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = Path(pcap_path).stem
    out_json = base_dir / f"{stem}_vt_{ts}.json"
    out_txt  = base_dir / f"{stem}_vt_{ts}.txt"
    return out_json, out_txt
    
    # Auto-run VirusTotal check (if VT_API_KEY present or --vt is set; unless --no-vt)
        maybe_run_vt_check(
            profiler_json_path=json_path,
            pcap_path=args.pcap,
            outdir=args.outdir,
            force=args.vt,
            disable=args.no_vt
        )


# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="PCAP Quick Profiler (Windows-friendly). Auto-saves reports.")
    ap.add_argument("pcap", help="Path to .pcap or .pcapng file")
    ap.add_argument("--top", type=int, help="Top-N entries per category (overrides config). Use 0 for ALL.")
    ap.add_argument("--all", action="store_true",
                    help="Return ALL IPs/ports (equivalent to --top 0).")
    ap.add_argument("--decode", action="append", default=[],
                    help="Decode-as mapping like tcp.port==36050,http (repeatable; merges with config)")
    ap.add_argument("--json", help="Additionally write full summary to this JSON file")
    ap.add_argument("--csv", help="Additionally write a flat CSV to this path (src/dst IPs, ports)")
    ap.add_argument("--outdir", help="Override auto-save directory (default: <repo>/reports/pcap-profiler)")
    ap.add_argument("--config", help="Path to config JSON (optional)")
    ap.add_argument("--profile", help="Profile name from config (optional)")
    ap.add_argument("--vt", action="store_true",
                    help="Force run VirusTotal check (even if VT_API_KEY not set; will still fail without a key).")
    ap.add_argument("--no-vt", action="store_true",
                    help="Disable automatic VirusTotal check after profiling.")

    args = ap.parse_args()

    # Merge config
    cfg = load_config(args.config, args.profile)

    # Effective settings: CLI overrides config
    if args.all:
        effective_top = 0
    elif args.top is not None:
        effective_top = args.top
    else:
        effective_top = int(cfg.get("top", 10))

    decode_cfg = cfg.get("decode", []) or []
    http_ports = cfg.get("http_ports", []) or []
    tls_ports = cfg.get("tls_ports", []) or []
    for p in http_ports:
        decode_cfg.append(f"tcp.port=={p},http")
    for p in tls_ports:
        decode_cfg.append(f"tcp.port=={p},tls")

    decode_maps = list(dict.fromkeys(decode_cfg + (args.decode or [])))

    # Where to auto-save
    json_path, txt_path, csv_path_default = output_paths(args.pcap, args.outdir)

    try:
        result = profile_pcap(args.pcap, effective_top, decode_maps)

        # Always print to console
        text = render_text_summary(result)
        print(text)

        # Auto-save JSON + TXT every run
        write_json(str(json_path), result)
        write_txt(str(txt_path), text)
        # Optionally also write CSV (top lists)
        # Use explicit --csv if you want a specific filename
        if args.csv:
            write_csv(args.csv, result)
        else:
            # If top_n > 0 or == 0, a CSV of top IPs/ports can still be handy—save it alongside
            write_csv(str(csv_path_default), result)

        # Respect explicit --json too (write a second copy where requested)
        if args.json and Path(args.json).resolve() != json_path.resolve():
            write_json(args.json, result)

        print(f"\n[autosave] JSON: {json_path}")
        print(f"[autosave] TXT : {txt_path}")
        if args.csv:
            print(f"[manual]  CSV : {Path(args.csv).resolve()}")
        else:
            print(f"[autosave] CSV : {csv_path_default}")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
    except Exception as e:
        print(f"ERROR while profiling PCAP: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

