#!/usr/bin/env python3
"""
Windows Log Triage — EVTX + Sysmon → HTML report (dark mode) + JSON/CSV
Author: Brandon Love (portfolio)
MVP goals:
  - Parse EVTX/Sysmon logs (python-evtx; fallback to PowerShell Get-WinEvent)
  - Normalize key fields (timestamp, provider, event_id, image, cmdline, net)
  - IOC extraction (domains, URLs, IPv4, hashes, emails)
  - Mini "Sigma-like" rules (regexes → ATT&CK techniques)
  - Produce a portable HTML report + JSON + CSV
"""

from __future__ import annotations
import argparse, os, re, sys, json, csv, shutil, subprocess
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Iterable, Dict, Any, List, Optional

# ---------- Optional dependency (preferred) ----------
EVTX_AVAILABLE = False
try:
    # pip install python-evtx
    from Evtx.Evtx import Evtx  # noqa
    import xmltodict            # pip install xmltodict
    EVTX_AVAILABLE = True
except Exception:
    pass

# ---------- Required dependency for HTML ----------
# pip install jinja2
from jinja2 import Template


# --------------------- IOC REGEXES ---------------------
RE_URL = re.compile(r'\bhttps?://[^\s"\'<>]+', re.IGNORECASE)
RE_DOMAIN = re.compile(r'\b(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}\b')
RE_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
RE_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
RE_EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}')

# --------------------- MINI "SIGMA" ---------------------
# Keep this small, fast, and readable. Each rule: name, technique, field, regex
RULES = [
    # Process creation / PowerShell
    {"name": "PowerShell EncodedCommand",
     "technique": "T1059.001",
     "field": "CommandLine",
     "pattern": re.compile(r'powershell(\.exe)?\b.*-enc(odedcommand)?\b', re.I)},

    {"name": "PowerShell Download Cradle",
     "technique": "T1059.001",
     "field": "CommandLine",
     "pattern": re.compile(r'powershell(\.exe)?\b.*(iwr|wget|Invoke-WebRequest|DownloadString)\b.*https?://', re.I)},

    # LOLBins
    {"name": "MSHTA remote script",
     "technique": "T1218.005",
     "field": "CommandLine",
     "pattern": re.compile(r'\bmshta(\.exe)?\b.*https?://', re.I)},

    {"name": "regsvr32 scrobj",
     "technique": "T1218.010",
     "field": "CommandLine",
     "pattern": re.compile(r'\bregsvr32(\.exe)?\b.*(scrobj\.dll|/i:https?://)', re.I)},

    {"name": "rundll32 scriptlet/js",
     "technique": "T1218.011",
     "field": "CommandLine",
     "pattern": re.compile(r'\brundll32(\.exe)?\b.*(javascript:|url\.dll,FileProtocolHandler\s+https?://)', re.I)},

    {"name": "certutil download",
     "technique": "T1105",
     "field": "CommandLine",
     "pattern": re.compile(r'\bcertutil(\.exe)?\b.*-urlcache.*-split.*-f.*https?://', re.I)},

    {"name": "BITSAdmin download",
     "technique": "T1197",
     "field": "CommandLine",
     "pattern": re.compile(r'\bbitsadmin(\.exe)?\b.*(transfer|addfile).*https?://', re.I)},

    {"name": "WMIC remote exec",
     "technique": "T1047",
     "field": "CommandLine",
     "pattern": re.compile(r'\bwmic(\.exe)?\b.*process\s+call\s+create\b', re.I)},

    # Suspicious encodings in cmdline
    {"name": "Base64-like token in cmdline",
     "technique": "T1027",
     "field": "CommandLine",
     "pattern": re.compile(r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{100,}={0,2}(?![A-Za-z0-9+/=])')},
]

# LOLBins list for heuristic highlights
LOLBINS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "powershell.exe", "bitsadmin.exe",
           "wmic.exe", "wscript.exe", "cscript.exe", "certutil.exe", "cmd.exe"}


# --------------------- UTILITIES ---------------------
def to_utc(dt_str: str) -> Optional[datetime]:
    try:
        # EVTX timestamps are ISO-8601-ish UTC
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def get_text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, (int, float)):
        return str(x)
    return str(x)


def safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(str(x))
    except Exception:
        return default


def extract_iocs(s: str) -> Dict[str, List[str]]:
    if not s:
        return {"urls": [], "domains": [], "ipv4": [], "md5": [], "sha1": [], "sha256": [], "emails": []}
    urls = set(RE_URL.findall(s))
    # Remove domains that are already part of a longer URL
    domains = set(d for d in RE_DOMAIN.findall(s) if not any(d in u for u in urls))
    ips = set(RE_IPV4.findall(s))
    md5 = set(RE_MD5.findall(s))
    sha1 = set(RE_SHA1.findall(s))
    sha256 = set(RE_SHA256.findall(s))
    emails = set(RE_EMAIL.findall(s))
    return {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "ipv4": sorted(ips),
        "md5": sorted(md5),
        "sha1": sorted(sha1),
        "sha256": sorted(sha256),
        "emails": sorted(emails),
    }


# --------------------- EVTX READERS ---------------------
def iter_evtx_python(evtx_path: str, limit: Optional[int] = None) -> Iterable[Dict[str, Any]]:
    """
    Preferred: python-evtx → xmltodict
    """
    seen = 0
    with Evtx(evtx_path) as log:
        for rec in log.records():
            try:
                xml = rec.xml()
                d = xmltodict.parse(xml)["Event"]
                yield d
                seen += 1
                if limit and seen >= limit:
                    break
            except Exception:
                continue


def iter_evtx_powershell(evtx_path: str, limit: Optional[int] = None) -> Iterable[Dict[str, Any]]:
    """
    Fallback: PowerShell Get-WinEvent -Path <.evtx> | % { $_.ToXml() }
    """
    cmd = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command",
        f"Get-WinEvent -Path '{evtx_path}' | ForEach-Object {{$_.ToXml()}}"
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    buf = []
    seen = 0
    for line in proc.stdout:
        line = line.rstrip("\r\n")
        if line.strip().startswith("<Event "):
            buf = [line]
        elif line.strip().startswith("</Event>"):
            buf.append(line)
            try:
                xml = "\n".join(buf)
                d = xmltodict.parse(xml)["Event"]
                yield d
                seen += 1
            except Exception:
                pass
            buf = []
            if limit and seen >= limit:
                break
        else:
            buf.append(line)
    proc.stdout.close()
    proc.wait()


def iter_evtx(evtx_path: str, limit: Optional[int] = None) -> Iterable[Dict[str, Any]]:
    if EVTX_AVAILABLE:
        yield from iter_evtx_python(evtx_path, limit)
    else:
        # Fallback for environments where python-evtx isn't available for your Python version
        if shutil.which("powershell.exe"):
            yield from iter_evtx_powershell(evtx_path, limit)
        else:
            raise RuntimeError("No EVTX backend available (install python-evtx or run on Windows with PowerShell).")


# --------------------- NORMALIZATION ---------------------
def normalize_event(raw: Dict[str, Any], source_file: str) -> Dict[str, Any]:
    """
    Map EVTX <Event> XML → flat dict with common fields
    """
    sysn = raw.get("System", {})
    edata = raw.get("EventData") or raw.get("UserData") or {}
    # EventData can be dict with 'Data' list or dict
    flat = {}
    data_items = []
    if isinstance(edata, dict):
        data_items = edata.get("Data", [])
        if isinstance(data_items, dict):  # single item
            data_items = [data_items]
    for item in data_items or []:
        name = item.get("@Name") or item.get("Name") or ""
        val = item.get("#text") or item.get("value") or ""
        if name:
            flat[name] = get_text(val)

    event_id = sysn.get("EventID")
    if isinstance(event_id, dict):
        event_id = event_id.get("#text") or event_id.get("@Qualifiers") or ""
    provider = (sysn.get("Provider") or {}).get("@Name") or sysn.get("Channel") or ""
    ts = (sysn.get("TimeCreated") or {}).get("@SystemTime") or ""
    ts_utc = to_utc(ts)
    computer = sysn.get("Computer") or ""

    # Common fields across Security 4688 / Sysmon 1,3,11,13,22 etc.
    image = flat.get("Image") or flat.get("NewProcessName") or flat.get("ProcessName") or ""
    parent_image = flat.get("ParentImage") or flat.get("ParentProcessName") or ""
    cmdline = flat.get("CommandLine") or flat.get("ProcessCommandLine") or flat.get("NewProcessCommandLine") or ""
    user = flat.get("User") or flat.get("SubjectUserName") or ""
    dest_ip = flat.get("DestinationIp") or flat.get("DestinationIP") or ""
    dest_port = flat.get("DestinationPort") or ""
    protocol = flat.get("Protocol") or ""

    return {
        "source": str(source_file),
        "timestamp": ts_utc.isoformat() if ts_utc else ts,
        "event_id": safe_int(event_id, 0),
        "provider": provider,
        "computer": computer,
        "user": user,
        "image": image,
        "parent_image": parent_image,
        "commandline": cmdline,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "protocol": protocol,
        "raw": {"system": sysn, "data": flat},
    }


# --------------------- TRIAGE / AGGREGATION ---------------------
def run_rules(evt: Dict[str, Any]) -> List[Dict[str, str]]:
    hits = []
    for r in RULES:
        field_val = evt.get("commandline") if r["field"].lower() == "commandline" else evt.get("image", "")
        if field_val and r["pattern"].search(field_val):
            hits.append({"rule": r["name"], "technique": r["technique"]})
    return hits


def triage(events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    summary = {
        "count": 0,
        "first_ts": None,
        "last_ts": None,
        "providers": Counter(),
        "event_ids": Counter(),
        "top_processes": Counter(),
        "top_parents": Counter(),
        "suspicious_cmd": [],
        "net_by_process": Counter(),  # (image, ip:port) -> count
        "persistence": [],            # simple list of registry/file events
        "rule_hits": [],              # list of {rule, technique, ts, image, cmd}
        "iocs": {"urls": set(), "domains": set(), "ipv4": set(), "md5": set(), "sha1": set(), "sha256": set(), "emails": set()},
        "sample": [],                 # a few representative events for the HTML
    }

    for e in events:
        summary["count"] += 1
        ts = e.get("timestamp")
        try:
            dt = to_utc(ts) if ts else None
        except Exception:
            dt = None
        if dt:
            if not summary["first_ts"] or dt < summary["first_ts"]:
                summary["first_ts"] = dt
            if not summary["last_ts"] or dt > summary["last_ts"]:
                summary["last_ts"] = dt

        summary["providers"][e.get("provider","")] += 1
        summary["event_ids"][e.get("event_id",0)] += 1

        img = (e.get("image") or "").lower()
        if img:
            summary["top_processes"][img] += 1
            if Path(img).name.lower() in LOLBINS:
                # flag suspicious cmdlines around LOLBins
                if e.get("commandline"):
                    summary["suspicious_cmd"].append({
                        "ts": ts, "image": img, "cmd": e.get("commandline"), "reason": "LOLBIN"
                    })

        pimg = (e.get("parent_image") or "").lower()
        if pimg:
            summary["top_parents"][pimg] += 1

        # Network by process (Sysmon EID 3 typical)
        dip = e.get("dest_ip"); dport = e.get("dest_port")
        if img and dip:
            key = (Path(img).name, f"{dip}:{dport or '?'}")
            summary["net_by_process"][key] += 1

        # Persistence heuristics (very light)
        eid = e.get("event_id", 0)
        if eid in (11, 12, 13, 22, 4697, 7045):
            summary["persistence"].append({"ts": ts, "image": img, "cmd": e.get("commandline",""), "eid": eid})

        # Mini Sigma-like rules
        for h in run_rules(e):
            summary["rule_hits"].append({
                "ts": ts, "image": img, "cmd": e.get("commandline",""), **h
            })

        # IOCs (from cmdline + raw values)
        ioc_src = " ".join([
            e.get("commandline",""),
            json.dumps(e.get("raw",{}), ensure_ascii=False)
        ])
        iocs = extract_iocs(ioc_src)
        for k,v in iocs.items():
            summary["iocs"][k].update(v)

        # Keep a tiny sample set (first 25)
        if len(summary["sample"]) < 25:
            summary["sample"].append({
                "ts": ts, "provider": e.get("provider"), "eid": e.get("event_id"),
                "image": img, "cmd": e.get("commandline","")
            })

    # finalize
    if summary["first_ts"]:
        summary["first_ts"] = summary["first_ts"].isoformat()
    if summary["last_ts"]:
        summary["last_ts"] = summary["last_ts"].isoformat()

    for k in summary["iocs"]:
        summary["iocs"][k] = sorted(summary["iocs"][k])

    return summary


# --------------------- RENDERING ---------------------
HTML_TMPL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Windows Log Triage Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{
  --bg:#0b1020; --card:#121934; --text:#e5e7eb; --muted:#9ca3af;
  --accent:#60a5fa; --accent2:#a78bfa; --border:#1f2a4d;
}
@media (prefers-color-scheme: light){
  :root{--bg:#f8fafc;--card:#fff;--text:#0f172a;--muted:#475569;--border:#e2e8f0}
}
html,body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial}
.container{width:min(1100px,92%);margin:24px auto}
h1,h2{line-height:1.2;margin:.2rem 0 .6rem}
h1{font-size:1.6rem} h2{font-size:1.2rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:16px;margin:12px 0}
.meta{color:var(--muted)}
table{width:100%;border-collapse:collapse}
th,td{border-bottom:1px solid var(--border);padding:8px 6px;vertical-align:top}
kbd{padding:.05rem .35rem;border:1px solid var(--border);border-bottom-width:2px;border-radius:6px;background:rgba(255,255,255,.05)}
.tag{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:.1rem .4rem;margin:.05rem .25rem .05rem 0;color:var(--muted);font-size:.8rem}
.small{font-size:.9rem}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media (max-width: 900px){.grid{grid-template-columns:1fr}}
pre{white-space:pre-wrap;word-break:break-word;background:#0f142d;padding:8px;border-radius:8px;border:1px solid var(--border)}
header{display:flex;justify-content:space-between;align-items:center;margin:8px 0 12px}
.btn{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:.35rem .7rem;color:var(--text);text-decoration:none}
.btn:hover{border-color:var(--accent)}
.count{font-weight:700}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Windows Log Triage Report</h1>
    <a class="btn" href="#" onclick="history.back();return false;">← Back</a>
  </header>

  <div class="card">
    <div class="grid">
      <div>
        <div><span class="meta">Events:</span> <span class="count">{{count}}</span></div>
        <div><span class="meta">Time span:</span> {{first_ts or 'n/a'}} → {{last_ts or 'n/a'}}</div>
        <div class="small meta">Generated: {{now}}</div>
      </div>
      <div>
        <div class="meta">Top Providers</div>
        {% for k,v in providers %}
          <span class="tag">{{k}} ({{v}})</span>
        {% endfor %}
      </div>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h2>Top Processes</h2>
      {% if top_processes %}
      <table><thead><tr><th>Image</th><th>Count</th></tr></thead>
      <tbody>
      {% for k,v in top_processes %}
        <tr><td>{{k}}</td><td>{{v}}</td></tr>
      {% endfor %}
      </tbody></table>
      {% else %}<p class="meta">No process data.</p>{% endif %}
    </div>

    <div class="card">
      <h2>Top Parents</h2>
      {% if top_parents %}
      <table><thead><tr><th>Parent</th><th>Count</th></tr></thead>
      <tbody>
      {% for k,v in top_parents %}
        <tr><td>{{k}}</td><td>{{v}}</td></tr>
      {% endfor %}
      </tbody></table>
      {% else %}<p class="meta">No parent data.</p>{% endif %}
    </div>
  </div>

  <div class="card">
    <h2>Network by Process</h2>
    {% if net_by_process %}
    <table><thead><tr><th>Process</th><th>Destination</th><th>Hits</th></tr></thead>
    <tbody>
    {% for (p,dst),c in net_by_process %}
      <tr><td>{{p}}</td><td>{{dst}}</td><td>{{c}}</td></tr>
    {% endfor %}
    </tbody></table>
    {% else %}<p class="meta">No network events seen.</p>{% endif %}
  </div>

  <div class="card">
    <h2>Sigma-like Rule Hits</h2>
    {% if rule_hits %}
    <table><thead><tr><th>Time</th><th>Rule</th><th>ATT&CK</th><th>Image</th><th>Command Line</th></tr></thead>
    <tbody>
    {% for h in rule_hits %}
      <tr>
        <td class="small">{{h.ts}}</td>
        <td>{{h.rule}}</td>
        <td><kbd>{{h.technique}}</kbd></td>
        <td>{{h.image}}</td>
        <td><pre>{{h.cmd}}</pre></td>
      </tr>
    {% endfor %}
    </tbody></table>
    {% else %}<p class="meta">No matches in this dataset.</p>{% endif %}
  </div>

  <div class="card">
    <h2>Suspicious Command Lines (heuristics)</h2>
    {% if suspicious_cmd %}
      {% for s in suspicious_cmd %}
        <div class="small">
          <div class="meta">{{s.ts}} · Reason: {{s.reason}}</div>
          <div><b>{{s.image}}</b></div>
          <pre>{{s.cmd}}</pre>
        </div>
        <hr style="border:0;border-top:1px solid var(--border)">
      {% endfor %}
    {% else %}
      <p class="meta">None flagged.</p>
    {% endif %}
  </div>

  <div class="card">
    <h2>IOCs</h2>
    <div class="grid">
      <div>
        <div class="meta">Domains</div>
        {% for d in iocs.domains %}<div class="small">{{d}}</div>{% endfor %}
        {% if not iocs.domains %}<div class="meta small">none</div>{% endif %}
        <div class="meta" style="margin-top:8px">URLs</div>
        {% for u in iocs.urls %}<div class="small">{{u}}</div>{% endfor %}
        {% if not iocs.urls %}<div class="meta small">none</div>{% endif %}
      </div>
      <div>
        <div class="meta">IPv4</div>
        {% for ip in iocs.ipv4 %}<div class="small">{{ip}}</div>{% endfor %}
        {% if not iocs.ipv4 %}<div class="meta small">none</div>{% endif %}
        <div class="meta" style="margin-top:8px">Hashes/Emails</div>
        {% for h in iocs.md5 %}<div class="small">MD5: {{h}}</div>{% endfor %}
        {% for h in iocs.sha1 %}<div class="small">SHA1: {{h}}</div>{% endfor %}
        {% for h in iocs.sha256 %}<div class="small">SHA256: {{h}}</div>{% endfor %}
        {% for e in iocs.emails %}<div class="small">Email: {{e}}</div>{% endfor %}
        {% if not (iocs.md5 or iocs.sha1 or iocs.sha256 or iocs.emails) %}<div class="meta small">none</div>{% endif %}
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Sample Events (first 25)</h2>
    {% if sample %}
    <table><thead><tr><th>Time</th><th>Provider</th><th>EID</th><th>Process</th><th>Cmd</th></tr></thead>
    <tbody>
    {% for e in sample %}
      <tr>
        <td class="small">{{e.ts}}</td>
        <td class="small">{{e.provider}}</td>
        <td>{{e.eid}}</td>
        <td class="small">{{e.image}}</td>
        <td><pre>{{e.cmd}}</pre></td>
      </tr>
    {% endfor %}
    </tbody></table>
    {% else %}<p class="meta">No sample available.</p>{% endif %}
  </div>

  <p class="meta small">© {{year}} Brandon Love · Windows Log Triage (MVP)</p>
</div>
</body></html>
"""

def render_html(summary: Dict[str, Any]) -> str:
    t = Template(HTML_TMPL)
    data = {
        **summary,
        "providers": summary["providers"].most_common(10),
        "top_processes": summary["top_processes"].most_common(15),
        "top_parents": summary["top_parents"].most_common(15),
        "net_by_process": summary["net_by_process"].most_common(30),
        "year": datetime.now().year,
        "now": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    return t.render(**data)


# --------------------- IO / CLI ---------------------
def collect_events(paths: List[str], max_per_file: Optional[int]) -> Iterable[Dict[str, Any]]:
    for p in paths:
        p = str(p)
        try:
            for raw in iter_evtx(p, limit=max_per_file):
                yield normalize_event(raw, p)
        except Exception as e:
            print(f"[warn] Failed to parse {p}: {e}", file=sys.stderr)


def write_json(path: str, data: Dict[str, Any]) -> None:
    """
    Make a JSON-safe copy of the summary:
      - Counters -> dict (or list of rows)
      - tuple keys (net_by_process) -> list of {process,dst,count}
      - sets in IOCs -> sorted lists
    """
    from collections import Counter

    def to_dict_counter(c: Counter, top=None):
        items = c.most_common(top) if hasattr(c, "most_common") else list(c.items())
        return {str(k): v for k, v in items}

    safe = dict(data)  # shallow copy

    # 1) net_by_process (tuple keys) -> list of rows
    nbp = safe.get("net_by_process")
    if isinstance(nbp, Counter):
        safe["net_by_process"] = [
            {"process": k[0], "dst": k[1], "count": v}
            for k, v in nbp.most_common()
        ]
    elif isinstance(nbp, dict):
        # in case it somehow already became a dict with tuple keys
        rows = []
        for k, v in nbp.items():
            if isinstance(k, tuple) and len(k) == 2:
                rows.append({"process": k[0], "dst": k[1], "count": v})
        safe["net_by_process"] = rows

    # 2) Regular Counters -> plain dicts
    for key in ("providers", "event_ids", "top_processes", "top_parents"):
        val = safe.get(key)
        if isinstance(val, Counter):
            safe[key] = to_dict_counter(val)

    # 3) IOCs (sets -> sorted lists)
    iocs = safe.get("iocs")
    if isinstance(iocs, dict):
        safe["iocs"] = {
            k: sorted(list(v)) if isinstance(v, set) else v
            for k, v in iocs.items()
        }

    # Everything else should already be JSON-safe (lists/dicts/strings/ints)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(safe, f, indent=2)



def write_csv(path: str, sample_events: List[Dict[str, Any]]) -> None:
    cols = ["ts","provider","eid","image","cmd"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for e in sample_events:
            w.writerow({
                "ts": e.get("ts",""),
                "provider": e.get("provider",""),
                "eid": e.get("eid",""),
                "image": e.get("image",""),
                "cmd": e.get("cmd",""),
            })


def main():
    ap = argparse.ArgumentParser(description="Windows Log Triage — EVTX + Sysmon → HTML report")
    ap.add_argument("target", nargs="+", help="Path(s) to .evtx files or a folder containing .evtx")
    ap.add_argument("--outdir", default="out", help="Output folder (default: out)")
    ap.add_argument("--html", default=None, help="Write HTML report to this path (default: out/wintriage-<ts>.html)")
    ap.add_argument("--json", default=None, help="Write JSON summary (default: out/wintriage-<ts>.json)")
    ap.add_argument("--csv", default=None, help="Write CSV of sample rows (default: out/wintriage-<ts>.csv)")
    ap.add_argument("--max-per-file", type=int, default=None, help="Max events to read per file (speeds demo)")
    args = ap.parse_args()

    # Expand folder(s) to .evtx list
    evtx_paths = []
    for t in args.target:
        tpath = Path(t)
        if tpath.is_dir():
            evtx_paths += [str(p) for p in tpath.glob("*.evtx")]
        elif tpath.is_file() and tpath.suffix.lower()==".evtx":
            evtx_paths.append(str(tpath))
    if not evtx_paths:
        print("No .evtx files found in the given target(s).", file=sys.stderr)
        sys.exit(2)

    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")

    html_path = Path(args.html) if args.html else outdir / f"wintriage-{ts}.html"
    json_path = Path(args.json) if args.json else outdir / f"wintriage-{ts}.json"
    csv_path  = Path(args.csv)  if args.csv  else outdir / f"wintriage-{ts}.csv"

    print(f"[+] Reading {len(evtx_paths)} file(s)…")
    evts = list(collect_events(evtx_paths, args.max_per_file))
    print(f"[+] Parsed events: {len(evts):,}")

    print("[+] Triage…")
    summary = triage(evts)

    print(f"[+] Writing JSON → {json_path}")
    write_json(str(json_path), summary)

    print(f"[+] Writing CSV  → {csv_path}")
    write_csv(str(csv_path), summary["sample"])

    print(f"[+] Writing HTML → {html_path}")
    html = render_html(summary)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print("\nDone.")
    print(f"Open report: {html_path}")


if __name__ == "__main__":
    main()
