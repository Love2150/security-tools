#!/usr/bin/env python3
# PCAP Quick Profiler (Windows-friendly)
# Examples (PowerShell / CMD):
#   python .\pcap_profiler.py .\samples\capture.pcap --outdir .\out
#   python .\pcap_profiler.py .\samples\capture.pcap --decode tcp.port==36050,http
#   python .\pcap_profiler.py .\samples\capture.pcap --vt      (requires VT_API_KEY)
#   python .\pcap_profiler.py .\samples\capture.pcap --no-vt

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---- Dependencies ----
try:
    import pyshark  # requires TShark on PATH
except Exception:
    print("ERROR: pyshark not installed. Run: python -m pip install pyshark", file=sys.stderr)
    print("Also install Wireshark/TShark and ensure 'tshark' is on PATH, then restart your terminal.", file=sys.stderr)
    sys.exit(1)

# ---------- Helpers ----------
def ensure_tshark() -> None:
    """Exit with a friendly message if TShark isn't on PATH."""
    if shutil.which("tshark") is None:
        print(
            "ERROR: TShark not found on PATH.\n"
            "Install Wireshark (select 'Install TShark') and add it to PATH.\n"
            "Then close and reopen your terminal.",
            file=sys.stderr,
        )
        sys.exit(1)

def fmt_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    val = float(n)
    for u in units:
        if val < 1024:
            return f"{val:.1f} {u}"
        val /= 1024
    return f"{val:.1f} EB"

def safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(str(x))
    except Exception:
        return default

def _parse_iso_utc(s: str) -> Optional[datetime]:
    """Parse many common timestamp formats to UTC datetime."""
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
    """Best-effort to get a packet timestamp as UTC datetime."""
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

# ---------- Report path helpers ----------
def default_reports_dir() -> Path:
    return Path.cwd() / "reports" / "pcap-profiler"

def output_paths(pcap_path: str, outdir: Optional[str]) -> tuple[Path, Path, Path]:
    base_dir = Path(outdir).resolve() if outdir else default_reports_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(pcap_path).stem
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = base_dir / f"{stem}_{ts}.json"
    txt_path  = base_dir / f"{stem}_{ts}.txt"
    csv_path  = base_dir / f"{stem}_{ts}.csv"
    return json_path, txt_path, csv_path

def vt_output_paths(pcap_path: str, outdir: Optional[str]) -> tuple[Path, Path]:
    base_dir = Path(outdir).resolve() if outdir else default_reports_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(pcap_path).stem
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return base_dir / f"{stem}_vt_{ts}.json", base_dir / f"{stem}_vt_{ts}.txt"

# ---------- Core profiling ----------
def profile_pcap(path: str, top_n: int = 10, decode_maps: Optional[List[str]] = None) -> Dict[str, Any]:
    ensure_tshark()

    # Windows-friendly asyncio loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # state / counters
    total_packets = 0
    total_bytes = 0
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None
    proto_counter = Counter()
    proto_bytes = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    dst_ports = Counter()

    # tshark params (speed first)
    custom_params: List[str] = ['-n']   # no DNS resolution (big speedup)
    for m in (decode_maps or []):
        custom_params += ['-d', m]      # decode-as maps, e.g. tcp.port==36050,http

    # --- Main pass (limit to useful protocols; faster JSON parser) ---
    cap = pyshark.FileCapture(
        path,
        display_filter="dns || tls || http",
        keep_packets=False,
        use_json=True,
        eventloop=loop,
        custom_parameters=custom_params,
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

    # --- HTTP pass (details) ---
    http_cap = pyshark.FileCapture(
        path,
        display_filter="http",
        keep_packets=False,
        use_json=True,
        eventloop=loop,
        custom_parameters=custom_params,
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

    # --- TLS pass (handshakes-only is faster: use "tls.handshake" if desired) ---
    tls_cap = pyshark.FileCapture(
        path,
        display_filter="tls",   # or "tls.handshake"
        keep_packets=False,
        use_json=True,
        eventloop=loop,
        custom_parameters=custom_params,
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
        "file": str(Path(path).resolve()),
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

# ---------- Output writers ----------
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

    def show(title: str, items):
        print(f"\n{title}:")
        if not items:
            print("  (none)")
            return
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

# ---------- Optional VirusTotal integration ----------
def maybe_run_vt_check(
    profiler_json_path: Path,
    pcap_path: str,
    outdir: Optional[str],
    force: bool = False,
    disable: bool = False,
) -> None:
    if disable:
        print("[vt] Skipping VT check (--no-vt).")
        return

    api_key = os.environ.get("VT_API_KEY")
    if not api_key and not force:
        print("[vt] VT_API_KEY not set; skipping VT check.")
        return

    try:
        import importlib
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

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="PCAP Quick Profiler — fast triage of network captures (Windows-friendly).")
    ap.add_argument("pcap", help="Path to .pcap or .pcapng file")
    ap.add_argument("--top", type=int, default=10, help="Top-N entries per category (default: 10)")
    ap.add_argument("--decode", action="append", default=[], help="Decode-as mapping, e.g. tcp.port==36050,http (repeatable)")
    ap.add_argument("--json", help="Also write summary to this JSON path (optional)")
    ap.add_argument("--csv", help="Also write CSV of top IPs/ports to this path (optional)")
    ap.add_argument("--outdir", help="Directory to auto-save JSON/TXT/CSV (default: reports/pcap-profiler)")
    ap.add_argument("--vt", action="store_true", help="Force run VirusTotal check (requires VT_API_KEY)")
    ap.add_argument("--no-vt", action="store_true", help="Disable automatic VirusTotal check")
    args = ap.parse_args()

    decode_maps = list(dict.fromkeys(args.decode or []))  # dedupe

    try:
        # 1) Profile
        result = profile_pcap(args.pcap, args.top, decode_maps)

        # 2) Console summary
        print_summary(result)

        # 3) Auto-save JSON/TXT/CSV
        json_path, txt_path, csv_path = output_paths(args.pcap, args.outdir)
        write_json(str(json_path), result)
        print(f"[save] JSON  -> {json_path}")

        from io import StringIO
        buf = StringIO()
        orig_stdout = sys.stdout
        try:
            sys.stdout = buf
            print_summary(result)
        finally:
            sys.stdout = orig_stdout
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(buf.getvalue())
        print(f"[save] TEXT  -> {txt_path}")

        write_csv(str(csv_path), result)
        print(f"[save] CSV   -> {csv_path}")

        # 4) Optional single-file outputs
        if args.json:
            write_json(args.json, result)
            print(f"[save] JSON(extra) -> {args.json}")
        if args.csv:
            write_csv(args.csv, result)
            print(f"[save] CSV(extra)  -> {args.csv}")

        # 5) Optional VT
        maybe_run_vt_check(
            profiler_json_path=json_path,
            pcap_path=args.pcap,
            outdir=args.outdir,
            force=args.vt,
            disable=args.no_vt,
        )

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
    except Exception as e:
        print(f"ERROR while profiling PCAP: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()


