from __future__ import annotations

import re
from typing import Any

RULES = [
    # Process creation / PowerShell
    {"name": "PowerShell EncodedCommand",
     "technique": "T1059.001",
     "field": "CommandLine",
     "pattern": re.compile(r'powershell(\.exe)?\b.*-enc(odedcommand)?\b', re.IGNORECASE)},

    {"name": "PowerShell Download Cradle",
     "technique": "T1059.001",
     "field": "CommandLine",
     "pattern": re.compile(r'powershell(\.exe)?\b.*(iwr|wget|Invoke-WebRequest|DownloadString)\b.*https?://', re.IGNORECASE)},

    # LOLBins
    {"name": "MSHTA remote script",
     "technique": "T1218.005",
     "field": "CommandLine",
     "pattern": re.compile(r'\bmshta(\.exe)?\b.*https?://', re.IGNORECASE)},

    {"name": "regsvr32 scrobj",
     "technique": "T1218.010",
     "field": "CommandLine",
     "pattern": re.compile(r'\bregsvr32(\.exe)?\b.*(scrobj\.dll|/i:https?://)', re.IGNORECASE)},

    {"name": "rundll32 scriptlet/js",
     "technique": "T1218.011",
     "field": "CommandLine",
     "pattern": re.compile(r'\brundll32(\.exe)?\b.*(javascript:|url\.dll,FileProtocolHandler\s+https?://)', re.IGNORECASE)},

    {"name": "certutil download",
     "technique": "T1105",
     "field": "CommandLine",
     "pattern": re.compile(r'\bcertutil(\.exe)?\b.*-urlcache.*-split.*-f.*https?://', re.IGNORECASE)},

    {"name": "BITSAdmin download",
     "technique": "T1197",
     "field": "CommandLine",
     "pattern": re.compile(r'\bbitsadmin(\.exe)?\b.*(transfer|addfile).*https?://', re.IGNORECASE)},

    {"name": "WMIC remote exec",
     "technique": "T1047",
     "field": "CommandLine",
     "pattern": re.compile(r'\bwmic(\.exe)?\b.*process\s+call\s+create\b', re.IGNORECASE)},

    # Suspicious encodings in cmdline
    {"name": "Base64-like token in cmdline",
     "technique": "T1027",
     "field": "CommandLine",
     "pattern": re.compile(r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{100,}={0,2}(?![A-Za-z0-9+/=])')},
]

# LOLBins list for heuristic highlights
LOLBINS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "powershell.exe", "bitsadmin.exe",
           "wmic.exe", "wscript.exe", "cscript.exe", "certutil.exe", "cmd.exe"}


def run_rules(evt: dict[str, Any]) -> list[dict[str, str]]:
    hits = []
    for rule in RULES:
        value = evt.get("commandline") if rule["field"].lower() == "commandline" else evt.get("image", "")
        if value and rule["pattern"].search(value):
            hits.append({"rule": rule["name"], "technique": rule["technique"]})
    return hits
