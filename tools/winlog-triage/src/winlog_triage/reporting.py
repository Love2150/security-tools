from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from jinja2 import Environment, StrictUndefined

HTML_TMPL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Windows Log Triage Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
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
  </header>

  <div class="card">
    <div class="grid">
      <div>
        <div><span class="meta">Events:</span> <span class="count">{{count}}</span></div>
        <div><span class="meta">Time span:</span> {{first_ts or 'n/a'}} → {{last_ts or 'n/a'}}</div>
        <div class="small meta">Generated: {{now}}</div>
        <div class="small meta">Parser: {{parsing.backend}} · read {{parsing.records_read}} · skipped {{parsing.records_skipped}} · errors {{parsing.parse_errors}}</div>
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

def render_html(summary: dict[str, Any]) -> str:
    t = Environment(autoescape=True, undefined=StrictUndefined).from_string(HTML_TMPL)
    data = {
        **summary,
        "providers": summary["providers"].most_common(10),
        "top_processes": summary["top_processes"].most_common(15),
        "top_parents": summary["top_parents"].most_common(15),
        "net_by_process": summary["net_by_process"].most_common(30),
        "year": datetime.now(timezone.utc).year,
        "now": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    return t.render(**data)

def write_json(path: str, data: dict[str, Any]) -> None:
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
            k: sorted(v) if isinstance(v, set) else v
            for k, v in iocs.items()
        }

    # Everything else should already be JSON-safe (lists/dicts/strings/ints)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(safe, f, indent=2)



def write_csv(path: str, sample_events: list[dict[str, Any]]) -> None:
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
