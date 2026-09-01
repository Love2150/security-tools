from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .iocs import extract_iocs
from .normalization import to_utc
from .rules import LOLBINS, run_rules


def triage(events: Iterable[dict[str, Any]], parsing: dict[str, Any] | None = None) -> dict[str, Any]:
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
    summary["parsing"] = parsing or {"backend": "unknown", "records_read": 0, "records_skipped": 0, "parse_errors": 0}

    for e in events:
        summary["count"] += 1
        ts = e.get("timestamp")
        dt = to_utc(ts) if ts else None
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
            if Path(img).name.lower() in LOLBINS and e.get("commandline"):
                summary["suspicious_cmd"].append({
                    "ts": ts, "image": img, "cmd": e.get("commandline"), "reason": "LOLBIN"
                })

        pimg = (e.get("parent_image") or "").lower()
        if pimg:
            summary["top_parents"][pimg] += 1

        # Network by process (Sysmon EID 3 typical)
        dip = e.get("dest_ip")
        dport = e.get("dest_port")
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
