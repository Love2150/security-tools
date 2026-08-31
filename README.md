# Security Tools

A collection of defensive security utilities for packet-capture triage, Windows event-log analysis, and safe inspection of packed JavaScript. The tools are organized as independent projects so each can be installed or run with only the dependencies it needs.

[![Eval-Unpacker CI](https://github.com/Love2150/security-tools/actions/workflows/eval-unpacker-ci.yml/badge.svg)](https://github.com/Love2150/security-tools/actions/workflows/eval-unpacker-ci.yml)

## Tools

| Tool | Purpose | Status | Documentation |
| --- | --- | --- | --- |
| PCAP Quick Profiler | Summarizes PCAP/PCAPNG traffic and produces JSON, text, CSV, and protected HTML reports; optional VirusTotal IP enrichment | Installable Python package | [README](tools/pcap-profiler/README.md) |
| Windows Log Triage | Parses EVTX and Sysmon data, applies lightweight ATT&CK-oriented triage rules, and creates HTML, JSON, and CSV reports | Standalone Python tool | [Source](tools/winlog-triage/wintriage.py) |
| Eval Unpacker | Unpacks JavaScript using the `eval(function(p,a,c,k,e,d){...})` pattern without executing the recovered payload | Installable Python package | [README](tools/eval-unpacker/ReadME.md) |

## Quick start

Clone the repository:

```bash
git clone https://github.com/Love2150/security-tools.git
cd security-tools
```

### PCAP Quick Profiler

Requirements:

- Python 3.10 or newer
- Wireshark/TShark available on `PATH`

Install and run:

```bash
python -m pip install ./tools/pcap-profiler
pcap-profiler capture.pcap
```

The equivalent module command is:

```bash
python -m pcap_quick_profiler capture.pcap
```

Reports are written beneath `reports/pcap-profiler/` by default. Use `--outdir` to select another location.

Optional VirusTotal enrichment reads the API key from the environment:

```bash
export VT_API_KEY="<YOUR_API_KEY>"
pcap-profiler capture.pcap --vt
pcap-profiler-vt --latest
```

The API key is not written to generated reports. See the [PCAP Quick Profiler documentation](tools/pcap-profiler/README.md) and [cheat sheet](docs/CHEATSHEET.md) for additional options.

### Windows Log Triage

Requirements:

- Python 3
- Dependencies listed in `tools/winlog-triage/requirements.txt`

Create an isolated environment, install dependencies, and analyze one or more EVTX files or a directory:

```bash
python -m venv .venv
# Linux/macOS
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1

python -m pip install -r tools/winlog-triage/requirements.txt
python tools/winlog-triage/wintriage.py path/to/logs --outdir reports/winlog-triage
```

The tool generates timestamped HTML, JSON, and CSV output. Use `--max-per-file` for a bounded demonstration run, or `--html`, `--json`, and `--csv` to choose exact output paths.

### Eval Unpacker

Requirements:

- Python 3.9 or newer

Install and run:

```bash
python -m pip install ./tools/eval-unpacker

eval-unpack packed.js --recursive
```

Install the optional beautifier when formatted output is needed:

```bash
python -m pip install "./tools/eval-unpacker[beautify]"
eval-unpack packed.js --recursive --beautify
```

Standard input is supported:

```bash
cat packed.js | eval-unpack -
```

Eval Unpacker reconstructs supported packed JavaScript; it does not execute the unpacked payload.

## Repository layout

```text
security-tools/
├── docs/
│   └── CHEATSHEET.md
├── tests/
│   ├── test_phase_one_security.py
│   └── test_phase_two_packaging.py
└── tools/
    ├── eval-unpacker/
    ├── pcap-profiler/
    └── winlog-triage/
```

See [Samples, Fixtures, and Generated Reports](docs/SAMPLES_AND_FIXTURES.md) for the strict separation between deterministic test fixtures and portfolio demonstrations, the [provenance registry](docs/SAMPLE_PROVENANCE.md), and mandatory indicator-handling precautions. No binary evidence or generated report is currently retained because redistribution permission and sanitization could not be established.

## Security design

These utilities process attacker-controlled evidence. Current safeguards include:

- HTML autoescaping for PCAP and EVTX evidence fields
- Restrictive Content Security Policy headers in generated HTML reports
- Nonce-protected scripting in PCAP HTML reports
- VirusTotal credentials loaded only from `VT_API_KEY`
- Eval Unpacker reconstructing supported source text without evaluating it

Generated reports can still contain sensitive evidence such as hostnames, IP addresses, command lines, URLs, and file paths. Review reports before sharing them and do not commit real credentials or private investigation data. Do not browse, resolve, or execute extracted domains, URLs, files, payloads, or indicators.

## Development and verification

Run the security and packaging regression suites from the repository root:

```bash
uv run --isolated \
  --with pytest \
  --with jinja2 \
  --with pyshark \
  --with requests \
  --with python-evtx \
  --with xmltodict \
  pytest -q tests/test_phase_one_security.py tests/test_phase_two_packaging.py
```

Run the Eval Unpacker tests from its package directory:

```bash
cd tools/eval-unpacker
uv run --isolated --with pytest pytest -q
```

The Eval Unpacker GitHub Actions workflow also verifies installation, imports, CLI availability, and a smoke-test unpacking operation.

## Responsible use

Use these tools only with captures, logs, systems, and code you are authorized to analyze. They are intended for defensive investigation, education, laboratory work, and incident-response support. Validate findings with additional evidence before making containment or attribution decisions.

## Contributing

1. Create a focused branch.
2. Add or update tests for behavior changes.
3. Run the relevant verification commands.
4. Open a pull request describing the change and how it was tested.

Bug reports and focused improvements are welcome through [GitHub Issues](https://github.com/Love2150/security-tools/issues).

## Author

Brandon Love — [GitHub](https://github.com/Love2150)
