# 🧠 PCAP Quick Profiler

A **Windows-friendly PCAP analysis tool** that generates quick traffic summaries — including protocols, top IPs, ports, HTTP, and TLS metadata — with automatic report saving.

![Eval-Unpacker CI](https://github.com/Love2150/security-tools/actions/workflows/eval-unpacker-ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)

---

## ⚡ Quick Start

```powershell
# Basic usage
python .\pcap_profiler.py "C:\path\to\capture.pcap"

# Show top 10 IPs, ports, and protocols
python .\pcap_profiler.py "C:\path\to\capture.pcap" --top 10
```

---

## 💾 Output

By default, reports are saved automatically to:
```
security-tools\reports\pcap-profiler\
  capture_YYYYMMDD-HHMMSS.txt
  capture_YYYYMMDD-HHMMSS.json
  capture_YYYYMMDD-HHMMSS.csv
```

### Options

| Flag | Description |
|------|--------------|
| `--json results.json` | Save full structured JSON |
| `--csv results.csv` | Save simplified top IPs/ports as CSV |
| `--outdir "C:\Custom\Folder"` | Override default output path |
| `--no-autosave` | Disable automatic saving |

---

## 🧩 Decode Custom Protocols

Use Wireshark-style decode mappings to interpret traffic on unusual ports:

```powershell
# Decode TCP 36050 as HTTP
python .\pcap_profiler.py "C:\path\to\capture.pcap" --decode tcp.port==36050,http

# Multiple decode rules
python .\pcap_profiler.py "C:\path\to\capture.pcap" --decode tcp.port==36050,http --decode tcp.port==8443,tls
```

---

## ⚙️ Configuration Profiles

Define reusable settings in `pcap_profiler.config.json`:

```json
{
  "default_profile": "standard",
  "profiles": {
    "standard": {
      "top": 10,
      "http_ports": [80, 8080],
      "tls_ports": [443, 8443],
      "decode": ["tcp.port==36050,http"]
    }
  }
}
```

Run using:
```powershell
python .\pcap_profiler.py "C:\path\to\capture.pcap" --profile standard
```

---

## 🔍 Troubleshooting

| Issue | Fix |
|-------|-----|
| **`tshark not found`** | Install [Wireshark](https://www.wireshark.org/download.html) and select **TShark** during setup |
| **Event loop error** | Fixed in latest Windows-friendly build |
| **No HTTP/TLS data** | Capture may only contain TCP or encrypted traffic |

---

## 🧾 Example Workflow

```powershell
cd "C:\Users\brand\Desktop\Projects\security-tools\tools\Pcap-profiler"
python .\pcap_profiler.py "C:\Users\brand\Desktop\capture.pcap" --top 10
explorer ..\..\reports\pcap-profiler
```

---

## 🧰 Optional PowerShell Alias

Add to your PowerShell `$PROFILE` for fast access:
```powershell
Set-Alias pprof "C:\Users\brand\Desktop\Projects\security-tools\tools\Pcap-profiler\pcap_profiler.py"

# Then just run:
pprof "C:\path\to\capture.pcap" --top 10
```

---

## 📘 Docs
📄 [PCAP Profiler Cheat Sheet (PDF)](../docs/pcap_profiler_cheatsheet.pdf)

---

## 🧑‍💻 Author
**Brandon Love**  
Cybersecurity • Network Forensics • Threat Analysis  
[Let’sDefend Profile](https://app.letsdefend.io/user/shinyhunter) | [LinkedIn](https://www.linkedin.com/in/brandon-love-85b247261)

---

## 🧷 License
MIT © 2025 — Open-source under [security-tools](https://github.com/Love2150/security-tools)
