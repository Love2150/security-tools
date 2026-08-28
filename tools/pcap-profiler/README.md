# PCAP Quick Profiler

PCAP Quick Profiler provides fast defensive triage of packet captures. It calculates full-capture packet, byte, protocol, endpoint, port, and duration statistics, then performs focused HTTP and TLS analysis. Reports are written as JSON, text, CSV, and CSP-protected HTML.

## Requirements

- Python 3.10 or newer
- TShark available on `PATH`

Install Wireshark/TShark first, then install this package from the repository:

```bash
python -m pip install ./tools/pcap-profiler
```

## Commands

Both supported entry points use the same canonical package implementation:

```bash
pcap-profiler capture.pcap --outdir reports
python -m pcap_quick_profiler capture.pcap --outdir reports
```

Useful options:

```text
--top N                         number of entries per summary
--decode tcp.port==36050,http  repeatable TShark decode-as mapping
--json PATH                    additional JSON output
--csv PATH                     additional CSV output
--outdir DIRECTORY             report destination
--vt                           run VirusTotal enrichment (requires VT_API_KEY)
--no-vt                        disable automatic VirusTotal enrichment
```

## VirusTotal

Set `VT_API_KEY` in the environment and either add `--vt` to a profiling command or check an existing JSON report:

```bash
pcap-profiler capture.pcap --vt
pcap-profiler-vt --json reports/capture.json
pcap-profiler-vt --latest
```

API keys are read only from the environment and are not written to reports.

## Output

Each profiler run creates timestamped `.json`, `.txt`, `.csv`, and `.html` files. The HTML report escapes evidence-derived fields and uses a restrictive Content Security Policy so untrusted packet content is displayed as text rather than executable markup.

## Development verification

```bash
uv run --isolated --with pytest --with jinja2 --with pyshark --with requests \
  pytest -q tests/test_phase_one_security.py tests/test_phase_two_packaging.py
```

The package source lives only under `src/pcap_quick_profiler/`. Do not add a second executable copy at the tool root.
