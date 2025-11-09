# PCAP Quick Profiler — Windows & Linux Cheat Sheet

> Location in repo (recommended): `tools/Pcap-profiler/CHEATSHEET.md`

```
security-tools/
└─ tools/
   └─ Pcap-profiler/
      ├─ pcap_profiler.py
      ├─ vt_check_ips.py
      └─ reports/
         └─ pcap-profiler/        # auto-created for outputs
```

## 0) Prereqs

**Python**
- Windows: Install from https://python.org (tick **“Add Python to PATH”**).
- Linux (Debian/Ubuntu): `sudo apt-get install -y python3 python3-pip`

**Wireshark/TShark**
- Windows: Install **Wireshark**, select **“Install TShark”** and ensure `C:\Program Files\Wireshark\` is on PATH.
- Linux: `sudo apt-get install -y tshark` (allow non-root capture if prompted).

**Python packages**
```bash
# Windows PowerShell or Linux
pip install pyshark requests
```

---

## 1) Quick Start

### Windows (PowerShell)
```powershell
cd .\security-tools\tools\Pcap-profiler\

# Profile PCAP, auto-save JSON/TXT/CSV
python .\pcap_profiler.py "C:\path\to\capture.pcap"

# Also check VirusTotal (requires VT_API_KEY)
python .\pcap_profiler.py "C:\path\to\capture.pcap" --vt
```

### Linux (Bash)
```bash
cd security-tools/tools/Pcap-profiler/

# Profile PCAP, auto-save JSON/TXT/CSV
python3 ./pcap_profiler.py "/path/to/capture.pcap"

# Also check VirusTotal (requires VT_API_KEY)
python3 ./pcap_profiler.py "/path/to/capture.pcap" --vt
```

**Outputs**  
Saved to `tools/Pcap-profiler/reports/pcap-profiler/`:
- `NAME_YYYYMMDD-HHMMSS.json` — full structured summary  
- `NAME_YYYYMMDD-HHMMSS.txt` — human-readable summary  
- `NAME_YYYYMMDD-HHMMSS.csv` — flat table (IPs/ports)  
- `NAME_vt_YYYYMMDD-HHMMSS.{json,txt}` — VirusTotal results (if `--vt`)

---

## 2) VirusTotal Setup

**Windows (persist once)**
```powershell
setx VT_API_KEY "<YOUR_API_KEY>"
# Close & reopen the terminal
```

**Linux (session)**
```bash
export VT_API_KEY="<YOUR_API_KEY>"
# Persist: echo 'export VT_API_KEY="YOUR_API_KEY"' >> ~/.bashrc
```

**Run VT on an existing report**
```powershell
# Windows
python .\vt_check_ips.py --json ".\reports\pcap-profiler\your_report.json"
```
```bash
# Linux
python3 ./vt_check_ips.py --json "./reports/pcap-profiler/your_report.json"
```

**Run VT on the most recent report**
```powershell
python .\vt_check_ips.py --latest
```
```bash
python3 ./vt_check_ips.py --latest
```

---

## 3) Useful Flags & Examples

**Top-N entries**
```powershell
python .\pcap_profiler.py "C:\cap.pcap" --top 20
```
```bash
python3 ./pcap_profiler.py "/pcaps/cap.pcap" --top 20
```

**Decode-as mappings** (treat ports as HTTP/TLS so fields parse correctly)
```powershell
python .\pcap_profiler.py "C:\cap.pcap" --decode tcp.port==36050,http --decode tcp.port==8443,tls
```
```bash
python3 ./pcap_profiler.py "/pcaps/cap.pcap" --decode tcp.port==36050,http --decode tcp.port==8443,tls
```

**Config & profiles**  
Lookup order:
1) `.\pcap_profiler.config.json`  
2) `%APPDATA%\pcap_profiler\config.json` (Windows)  
3) `~/.pcap_profiler.json` (Windows home)

Run with config:
```powershell
python .\pcap_profiler.py "C:\cap.pcap" --profile default
# or
python .\pcap_profiler.py "C:\cap.pcap" --config ".\pcap_profiler.config.json"
```
```bash
python3 ./pcap_profiler.py "/pcaps/cap.pcap" --profile default
# or
python3 ./pcap_profiler.py "/pcaps/cap.pcap" --config "./pcap_profiler.config.json"
```

**Config example**
```json
{
  "top": 15,
  "decode": ["tcp.port==36050,http"],
  "http_ports": [8080],
  "tls_ports": [8443],
  "default_profile": "default",
  "profiles": {
    "default": { "top": 10 }
  }
}
```
*Notes:* `http_ports`/`tls_ports` auto-expand to `--decode` rules.

---

## 4) Handy One-Liners

**Windows**
```powershell
# Run with VT check
python .\pcap_profiler.py "C:\cap.pcap" --vt

# Only VT on latest profiler report
python .\vt_check_ips.py --latest
```

**Linux**
```bash
python3 ./pcap_profiler.py "/pcaps/cap.pcap" --vt
python3 ./vt_check_ips.py --latest
```

---

## 5) Troubleshooting

**`tshark is not on PATH`**
- Windows: Add `C:\Program Files\Wireshark\` to PATH → restart terminal.
- Linux: `sudo apt-get install -y tshark`

**`No current event loop` / asyncio errors**  
Use the latest `pcap_profiler.py` (it creates/uses its own loop).

**`could not convert string to float: 'YYYY-MM-DDTHH:MM:SS'`**  
You’re on an older script. Update to the version that normalizes timestamps.

**`requests not installed` (for VT tool)**  
`pip install requests`

**VT returns nothing**  
Confirm `VT_API_KEY` is set and you opened a *new* terminal (Windows `setx`).

---

## 6) Optional Automation

**Windows PowerShell wrapper — `run-pcap.ps1`**
```powershell
param([string]$Pcap)
if (-not $Pcap) { Write-Host "Usage: .\run-pcap.ps1 C:\path\cap.pcap"; exit 1 }
cd $PSScriptRoot
python .\pcap_profiler.py $Pcap --vt
```

**Linux Bash wrapper — `run-pcap.sh`**
```bash
#!/usr/bin/env bash
set -euo pipefail
PCAP="${1:-}"
if [[ -z "$PCAP" ]]; then
  echo "Usage: ./run-pcap.sh /path/to/cap.pcap"
  exit 1
fi
cd "$(dirname "$0")"
python3 ./pcap_profiler.py "$PCAP" --vt
```

---

## 7) Example Session

**Windows**
```powershell
cd .\security-tools\tools\Pcap-profiler\
python .\pcap_profiler.py "C:\Users\me\Desktop\capture.pcap" --top 15 --decode tcp.port==36050,http --vt
python .\vt_check_ips.py --latest
```

**Linux**
```bash
cd security-tools/tools/Pcap-profiler/
python3 ./pcap_profiler.py "/home/me/capture.pcap" --top 15 --decode tcp.port==36050,http --vt
python3 ./vt_check_ips.py --latest
```

---

**Tip:** keep this file in sync with updates to `pcap_profiler.py` / `vt_check_ips.py`.
