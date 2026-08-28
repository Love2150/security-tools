# PCAP Quick Profiler Cheat Sheet

## Install

```bash
# Install TShark first, then from the repository root:
python -m pip install ./tools/pcap-profiler
```

## Profile a capture

```bash
pcap-profiler capture.pcap
pcap-profiler capture.pcap --top 20
pcap-profiler capture.pcap --outdir reports
pcap-profiler capture.pcap --decode tcp.port==36050,http
```

The equivalent module command is:

```bash
python -m pcap_quick_profiler capture.pcap
```

## VirusTotal enrichment

```bash
# Set this securely in your shell environment:
export VT_API_KEY="<YOUR_API_KEY>"

pcap-profiler capture.pcap --vt
pcap-profiler-vt --json reports/capture.json
pcap-profiler-vt --latest
```

On PowerShell, use `$env:VT_API_KEY = "<YOUR_API_KEY>"` for the current session.

## Outputs

A normal run creates timestamped JSON, TXT, CSV, and HTML reports. The default destination is `reports/pcap-profiler/` beneath the current working directory. Use `--outdir` to choose another location.

## Troubleshooting

- `TShark not found`: install Wireshark/TShark and add it to `PATH`.
- No HTTP/TLS details: the capture may not contain those protocols; baseline totals still include all packets.
- VirusTotal skipped: set `VT_API_KEY`, or use `--no-vt` when enrichment is not needed.
- Show every supported option with `pcap-profiler --help`.
