#!/usr/bin/env python3
# PCAP Quick Profiler (Windows-friendly) with HTML report + Dark Mode + Allowlist
# Usage:
#   python .\pcap_profiler.py .\samples\capture.pcap --outdir .\out

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import shutil
import sys
from collections import Counter, defaultdict
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

try:
    from jinja2 import Template
except Exception:
    print("ERROR: jinja2 not installed. Run: python -m pip install jinja2", file=sys.stderr)
    sys.exit(1)

# ---------- Helpers ----------
def ensure_tshark() -> None:
    if shutil.which("tshark") is None:
        print(
            "ERROR: TShark not found on PATH.\n"
            "Install Wireshark (select 'Install TShark') and add it to PATH.\n"
            "Then close and reopen your terminal.",
            file=sys.stderr,
        )
        sys.exit(1)

def fmt_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]
    val = float(n)
    for u in units:
        if val < 1024:
            return f"{val:.1f} {u}"
        val /= 1024
    return f"{val:.1f} ZB"

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
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None

def safe_sniff_time(pkt) -> Optional[datetime]:
    """Return a UTC datetime for the packet, robust to JSON/pyshark quirks."""
    try:
        fi = getattr(pkt, "frame_info", None)
        if fi:
            epoch = getattr(fi, "time_epoch", None)
            if epoch is not None:
                try:
                    return datetime.fromtimestamp(float(str(epoch)), tz=timezone.utc)
                except Exception:
                    pass
        dt = getattr(pkt, "sniff_time", None)
        if isinstance(dt, datetime):
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        if dt:
            parsed = _parse_iso_utc(str(dt))
            if parsed:
                return parsed
        if fi:
            human = getattr(fi, "time", None)
            if human:
                parsed = _parse_iso_utc(str(human))
                if parsed:
                    return parsed
    except Exception:
        pass
    return None

# ---------- Report path helpers ----------
def default_reports_dir() -> Path:
    return Path.cwd() / "reports" / "pcap-profiler"

def output_paths(pcap_path: str, outdir: Optional[str]) -> tuple[Path, Path, Path, Path]:
    base_dir = Path(outdir).resolve() if outdir else default_reports_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(pcap_path).stem
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = base_dir / f"{stem}_{ts}.json"
    txt_path  = base_dir / f"{stem}_{ts}.txt"
    csv_path  = base_dir / f"{stem}_{ts}.csv"
    html_path = base_dir / f"{stem}_{ts}.html"
    return json_path, txt_path, csv_path, html_path

def vt_output_paths(pcap_path: str, outdir: Optional[str]) -> tuple[Path, Path]:
    base_dir = Path(outdir).resolve() if outdir else default_reports_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(pcap_path).stem
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return base_dir / f"{stem}_vt_{ts}.json", base_dir / f"{stem}_vt_{ts}.txt"

# ---------- Allowlist loader ----------
def _load_allowlist() -> dict:
    """
    Look for enrichment/allowlist.json in:
      1) current working directory
      2) alongside this script/module
    """
    candidates = [
        Path.cwd() / "enrichment" / "allowlist.json",
        (Path(__file__).resolve().parent / "enrichment" / "allowlist.json"),
    ]
    for p in candidates:
        try:
            if p.exists():
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
    return {"sni": [], "ja3": []}

# ---------- Core profiling ----------
def profile_pcap(path: str, top_n: int = 10, decode_maps: Optional[List[str]] = None) -> Dict[str, Any]:
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

    # for beacon scoring
    flow_times = defaultdict(list)  # key = (dst_ip, sni or "")
    # tshark params (speed first)
    custom_params: List[str] = ['-n']
    for m in (decode_maps or []):
        custom_params += ['-d', m]

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

            # collect times for beacon scoring (fallback to dst-only if SNI missing later)
            sni_val = None
            try:
                tls_layer = getattr(pkt, "tls", None)
                if tls_layer:
                    sni_val = getattr(tls_layer, "handshake_extensions_server_name", None)
            except Exception:
                sni_val = None
            if ip and dt:
                dst_ip = getattr(ip, "dst", None)
                if dst_ip:
                    flow_times[(dst_ip, sni_val or "")].append(dt.timestamp())

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

    # --- HTTP details ---
    http_cap = pyshark.FileCapture(
        path,
        display_filter="http",
        keep_packets=False,
        use_json=True,
        eventloop=loop,
        custom_parameters=custom_params,
    )
    http_hosts = Counter(); http_uas = Counter(); http_urls = Counter(); http_ctypes = Counter()
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

    # --- TLS details (handshakes-only speeds up SNI/JA3 extraction) ---
    tls_cap = pyshark.FileCapture(
        path,
        display_filter="tls.handshake",   # "tls" if you also want application data stats
        keep_packets=False,
        use_json=True,
        eventloop=loop,
        custom_parameters=custom_params,
    )
    tls_versions = Counter(); tls_ciphers = Counter(); tls_sni = Counter(); tls_ja3 = Counter()
    try:
        for pkt in tls_cap:
            tls = getattr(pkt, "tls", None)
            if not tls:
                continue
            v = getattr(tls, "handshake_version", None)
            if v: tls_versions[v] += 1
            cs = getattr(tls, "handshake_ciphersuite", None)
            if cs: tls_ciphers[cs] += 1
            sni = getattr(tls, "handshake_extensions_server_name", None)
            if sni: tls_sni[sni] += 1
            ja3 = getattr(tls, "handshake_ja3", None)
            if ja3: tls_ja3[ja3] += 1
    finally:
        tls_cap.close()
        try:
            loop.close()
        except Exception:
            pass

    # --- Beaconing suspects (tuned) ---
    def score_beacon(times: List[float]) -> float:
        if len(times) < 3:  # allow smaller samples
            return 0.0
        times.sort()
        deltas = [times[i+1] - times[i] for i in range(len(times)-1)]
        mu = sum(deltas) / len(deltas)
        if mu <= 0:
            return 0.0
        # simple population stddev (avoid importing pstdev)
        var = sum((x - mu) ** 2 for x in deltas) / len(deltas)
        sigma = var ** 0.5
        cv = sigma / mu  # 0 = perfectly periodic
        # map to 0..1, lower CV => higher score
        score = 1.0 - min(max(cv, 0.0), 1.0)
        return max(0.0, min(1.0, score))

    # collapse flows: keep SNI when present, otherwise group by dst only
    collapsed: Dict[tuple[str, str], List[float]] = {}
    for (dst, sni), times in flow_times.items():
        key = (dst, sni or "")
        collapsed.setdefault(key, []).extend(times)

    beacons: List[Dict[str, Any]] = []
    for (dst, sni), times in collapsed.items():
        sc = score_beacon(times)
        if sc >= 0.45:  # a bit more permissive
            avg_int = round(sum(times[i+1]-times[i] for i in range(len(times)-1)) / (len(times)-1), 2) if len(times) > 1 else 0.0
            beacons.append({"dst": dst, "sni": sni, "hits": len(times), "avg_int": avg_int, "score": round(sc, 3)})

    beacons.sort(key=lambda x: (-x["score"], -x["hits"]))
    beacons_top = beacons[:top_n]

    # --- Allowlist filtering (SNI/JA3) ---
    _allow = _load_allowlist()
    _allowed_sni = set(_allow.get("sni", []))
    _allowed_ja3 = set(_allow.get("ja3", []))

    # Filter beacon suspects by SNI
    beacons_top = [b for b in beacons_top if b.get("sni", "") not in _allowed_sni]

    # Normalize TLS counters to lists and filter them
    _tls_sni_list = list(tls_sni.items())
    _tls_ja3_list = list(tls_ja3.items())
    _tls_sni_list = [(v, c) for (v, c) in _tls_sni_list if v not in _allowed_sni]
    _tls_ja3_list = [(v, c) for (v, c) in _tls_ja3_list if v not in _allowed_ja3]

    # duration
    dur = (last_ts - first_ts).total_seconds() if first_ts and last_ts else 0.0

    # build result
    result: Dict[str, Any] = {
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
        "tls_versions": list(tls_versions.items()),
        "tls_ciphers": list(tls_ciphers.items()),
        "tls_sni": _tls_sni_list,
        "tls_ja3": _tls_ja3_list,
        "beacon_suspects": beacons_top,
    }

    # attach HTTP breakdown (after counters closed)
    result.update({
        "http_hosts": list(http_hosts.items()),
        "http_user_agents": list(http_uas.items()),
        "http_urls": list(http_urls.items()),
        "http_content_types": list(http_ctypes.items()),
    })

    return result

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
    show(
        "🚨 Beacon suspects (dst sni → hits · avg_int(s) · score)",
        [(f"{b['dst']} {b['sni']}".strip(), f"{b['hits']} · {b['avg_int']}s · {b['score']}") for b in s.get("beacon_suspects", [])],
    )

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

# ---------- HTML report (with Dark Mode toggle) ----------
HTML_TEMPLATE = """
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>PCAP Quick Profiler — Report</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{
  --ink:#0f172a; --bg:#ffffff; --muted:#475569; --line:#e2e8f0; --accent:#2563eb;
  --card:#ffffff; --shadow:0 1px 0 rgba(2,6,23,.03);
}
:root.dark{
  --ink:#e5e7eb; --bg:#0b1220; --muted:#9aa4b2; --line:#1f2937; --accent:#60a5fa;
  --card:#0f172a; --shadow:0 0 0 rgba(0,0,0,0);
}
html,body{height:100%}
body{font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Inter,sans-serif;margin:24px;color:var(--ink);background:var(--bg);transition:background .2s,color .2s}
h1{font-size:1.4rem;margin:0}
.meta{color:var(--muted);font-size:.92rem}
.card{border:1px solid var(--line);border-radius:14px;padding:16px;margin:16px 0;box-shadow:var(--shadow);background:var(--card)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}
th{background:rgba(2,6,23,.03)}
:root.dark th{background:rgba(255,255,255,.05)}
small{color:var(--muted)}
.code{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.btn{border:1px solid var(--line);background:var(--card);border-radius:999px;padding:6px 12px;font-size:.9rem;cursor:pointer}
.btn:hover{filter:brightness(1.05)}
.toolbar{display:flex;gap:8px;align-items:center;justify-content:space-between;margin-bottom:8px}
.badge{background:#eff6ff;color:#1d4ed8;padding:2px 8px;border-radius:999px;font-size:.8rem}
:root.dark .badge{background:#172554;color:#93c5fd}
</style>
<script>
(function(){
  const saved = localStorage.getItem('pp-dark') || 'auto';
  const prefers = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const isDark = saved==='dark' || (saved==='auto' && prefers);
  if(isDark) document.documentElement.classList.add('dark');
  window.__ppMode = saved;
})();
function toggleMode(){
  const root = document.documentElement;
  const nowDark = root.classList.toggle('dark');
  const mode = nowDark ? 'dark' : 'light';
  localStorage.setItem('pp-dark', mode);
  const btn = document.getElementById('modeBtn');
  if(btn) btn.textContent = nowDark ? '☀️ Light' : '🌙 Dark';
}
function initModeBtn(){
  const btn = document.getElementById('modeBtn');
  const isDark = document.documentElement.classList.contains('dark');
  btn.textContent = isDark ? '☀️ Light' : '🌙 Dark';
}
</script>
</head><body onload="initModeBtn()">
<div class="toolbar">
  <div>
    <strong>PCAP Quick Profiler — Report</strong><br>
    <small class="meta">Generated: {{ now }} UTC</small>
  </div>
  <div><button id="modeBtn" class="btn" onclick="toggleMode()">🌙 Dark</button></div>
</div>

<div class="card">
  <p class="meta">File: <span class="code">{{ s.file }}</span><br>
  Window: {{ s.start or "?" }} → {{ s.end or "?" }} · Duration: {{ "%.2fs"|format(s.duration or 0) }} · Packets: {{ "{:,}".format(s.packets) }} · Bytes: {{ "{:,}".format(s.bytes) }}</p>
</div>

<div class="card grid">
  <div><strong>Top Source IPs</strong><br><small>count</small>
    <table>{% for ip,c in s.src_ips %}<tr><td>{{ ip }}</td><td>{{ c }}</td></tr>{% endfor %}{% if not s.src_ips %}<tr><td colspan="2"><small>(none)</small></td></tr>{% endif %}</table>
  </div>
  <div><strong>Top Destination IPs</strong><br><small>count</small>
    <table>{% for ip,c in s.dst_ips %}<tr><td>{{ ip }}</td><td>{{ c }}</td></tr>{% endfor %}{% if not s.dst_ips %}<tr><td colspan="2"><small>(none)</small></td></tr>{% endif %}</table>
  </div>
  <div><strong>Top Destination Ports</strong><br><small>count</small>
    <table>{% for p,c in s.dst_ports %}<tr><td>{{ p }}</td><td>{{ c }}</td></tr>{% endfor %}{% if not s.dst_ports %}<tr><td colspan="2"><small>(none)</small></td></tr>{% endif %}</table>
  </div>
</div>

<div class="card grid">
  <div><strong>TLS SNI</strong>
    <table>{% for v,c in s.tls_sni %}<tr><td>{{ v }}</td><td>{{ c }}</td></tr>{% endfor %}{% if not s.tls_sni %}<tr><td colspan="2"><small>(none)</small></td></tr>{% endif %}</table>
  </div>
  <div><strong>TLS JA3</strong>
    <table>{% for v,c in s.tls_ja3 %}<tr><td class="code">{{ v }}</td><td>{{ c }}</td></tr>{% endfor %}{% if not s.tls_ja3 %}<tr><td colspan="2"><small>(none)</small></td></tr>{% endif %}</table>
  </div>
  <div><strong>Protocols</strong>
    <table>{% for v,c in s.protocols %}<tr><td>{{ v }}</td><td>{{ c }}</td></tr>{% endfor %}{% if not s.protocols %}<tr><td colspan="2"><small>(none)</small></td></tr>{% endif %}</table>
  </div>
</div>

<div class="card">
  <strong>🚨 Beaconing suspects</strong> <span class="badge">experimental</span>
  <table>
    <tr><th>Destination</th><th>SNI</th><th>Hits</th><th>Avg Interval (s)</th><th>Score</th></tr>
    {% for b in s.beacon_suspects %}
      <tr><td class="code">{{ b.dst }}</td><td class="code">{{ b.sni }}</td><td>{{ b.hits }}</td><td>{{ b.avg_int }}</td><td>{{ "%.3f"|format(b.score) }}</td></tr>
    {% endfor %}
    {% if not s.beacon_suspects %}
      <tr><td colspan="5"><small>(none)</small></td></tr>
    {% endif %}
  </table>
  <small>Score is based on periodicity (lower inter-arrival variance → higher score).</small>
</div>

<div class="card grid">
  <div><strong>HTTP Hosts</strong>
    <table>{% for v,c in s.http_hosts %}<tr><td>{{ v }}</td><td>{{ c }}</td></tr>{% endfor %}{% if not s.http_hosts %}<tr><td colspan="2"><small>(none)</small></td></tr>{% endif %}</table>
  </div>
  <div><strong>HTTP User-Agents</strong>
    <table>{% for v,c in s.http_user_agents %}<tr><td>{{ v }}</td><td>{{ c }}</td></tr>{% endfor %}{% if not s.http_user_agents %}<tr><td colspan="2"><small>(none)</small></td></tr>{% endif %}</table>
  </div>
  <div><strong>HTTP URLs</strong>
    <table>{% for v,c in s.http_urls %}<tr><td class="code">{{ v }}</td><td>{{ c }}</td></tr>{% endfor %}{% if not s.http_urls %}<tr><td colspan="2"><small>(none)</small></td></tr>{% endif %}</table>
  </div>
</div>

</body></html>
"""

def write_html(path: str, data: Dict[str, Any]) -> None:
    s = {
        "file": data.get("file"),
        "packets": data.get("packets"),
        "bytes": data.get("bytes"),
        "start": data.get("start"),
        "end": data.get("end"),
        "duration": data.get("duration"),
        "protocols": data.get("protocols", []),
        "bytes_by_protocol": data.get("bytes_by_protocol", []),
        "src_ips": data.get("src_ips", []),
        "dst_ips": data.get("dst_ips", []),
        "dst_ports": data.get("dst_ports", []),
        "http_hosts": data.get("http_hosts", []),
        "http_user_agents": data.get("http_user_agents", []),
        "http_urls": data.get("http_urls", []),
        "http_content_types": data.get("http_content_types", []),
        "tls_versions": data.get("tls_versions", []),
        "tls_ciphers": data.get("tls_ciphers", []),
        "tls_sni": data.get("tls_sni", []),
        "tls_ja3": data.get("tls_ja3", []),
        "beacon_suspects": data.get("beacon_suspects", []),
    }
    html = Template(HTML_TEMPLATE).render(
        s=s,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

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
    ap.add_argument("--outdir", help="Directory to auto-save JSON/TXT/CSV/HTML (default: reports/pcap-profiler)")
    ap.add_argument("--vt", action="store_true", help="Force run VirusTotal check (requires VT_API_KEY)")
    ap.add_argument("--no-vt", action="store_true", help="Disable automatic VirusTotal check")
    args = ap.parse_args()

    decode_maps = list(dict.fromkeys(args.decode or []))  # dedupe

    try:
        # 1) Profile
        result = profile_pcap(args.pcap, args.top, decode_maps)

        # 2) Console summary
        print_summary(result)

        # 3) Auto-save JSON/TXT/CSV/HTML
        json_path, txt_path, csv_path, html_path = output_paths(args.pcap, args.outdir)
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

        write_html(str(html_path), result)
        print(f"[save] HTML  -> {html_path}")

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

