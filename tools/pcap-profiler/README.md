# PCAP Quick Profiler

PCAP Quick Profiler performs defensive packet-capture triage. It calculates full-capture packet, byte, protocol, endpoint, port, and duration statistics, then performs focused HTTP and TLS analysis. It writes JSON, text, CSV, and CSP-protected HTML reports.

## Prerequisites

- Python 3.10 or newer
- Wireshark/TShark installed and available on `PATH`
- Read permission for the target `.pcap` or `.pcapng`
- Optional VirusTotal API key in `VT_API_KEY`

Install from the repository root:

```bash
python -m pip install ./tools/pcap-profiler
```

## Usage

```bash
pcap-profiler capture.pcap --outdir reports/pcap-profiler
python -m pcap_quick_profiler capture.pcap
```

| Option | Meaning |
| --- | --- |
| `--top N` | Number of entries retained per summary category; default 10 |
| `--decode MAPPING` | Repeatable TShark decode-as mapping such as `tcp.port==36050,http` |
| `--json PATH` | Write an additional JSON summary |
| `--csv PATH` | Write an additional CSV summary |
| `--outdir DIRECTORY` | Timestamped report destination; default `reports/pcap-profiler` |
| `--vt` | Force VirusTotal enrichment; requires `VT_API_KEY` |
| `--no-vt` | Disable automatic VirusTotal enrichment |

### VirusTotal

```bash
export VT_API_KEY="<YOUR_API_KEY>"
pcap-profiler capture.pcap --vt
pcap-profiler-vt --json reports/pcap-profiler/capture.json
pcap-profiler-vt --latest --delay 16 --outdir reports/vt
```

`pcap-profiler-vt` requires either `--json PATH` or `--latest`. API keys are read from the environment and are not written to reports.

## Output schema

A profiling run writes four timestamped files with the same stem:

- JSON: complete machine-readable summary;
- TXT: human-readable console-equivalent summary;
- CSV: rows with `category`, `key`, and `count` for source IPs, destination IPs, and destination ports;
- HTML: portable escaped evidence with restrictive Content Security Policy protection.

Profiler JSON fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `file` | string | Absolute analyzed capture path |
| `packets`, `bytes` | integer | Full-capture totals |
| `start`, `end` | string or null | ISO-formatted capture bounds |
| `duration` | number | Capture duration in seconds |
| `protocols`, `bytes_by_protocol` | array of `[value, count]` | Full-capture protocol counts and bytes |
| `src_ips`, `dst_ips`, `dst_ports` | array of `[value, count]` | Top endpoint and destination-port counts |
| `http_hosts`, `http_user_agents`, `http_urls`, `http_content_types` | array of `[value, count]` | Focused HTTP observations |
| `tls_versions`, `tls_ciphers`, `tls_sni`, `tls_ja3` | array of `[value, count]` | Focused TLS observations |
| `beacon_suspects` | array of objects | Heuristic destination, SNI, hit, interval, and score data |

Standalone VirusTotal JSON is an object keyed by IP. A successful value contains `ip`, `positives`, `last_analysis_stats`, and `link`; failed lookups contain `ip` and `error`. The companion Markdown file is a human-readable summary.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Profiling completed; integrated VirusTotal enrichment may have been skipped or logged an enrichment error without changing this status |
| `1` | Missing dependency/TShark, profiling failure, or standalone `pcap-profiler-vt` report/API-key failure |
| `2` | Invalid command-line arguments |

`pcap-profiler --vt` treats enrichment as non-fatal: a missing key, unavailable enrichment support, or request exception is reported or skipped while the completed PCAP profile retains exit `0`. Inspect `[vt]` messages and expected VT output files before relying on enrichment. An interrupted profiler may also return `0`; treat partial outputs as incomplete.

## Limitations

- HTTP/TLS sections are protocol-focused and can be empty even when full-capture totals are non-zero.
- Encrypted payloads are not decrypted.
- Decode-as accuracy depends on the mapping supplied to TShark.
- Beacon scoring and VirusTotal detections are triage leads, not maliciousness verdicts.
- Large captures can require substantial processing time and memory.
- Output can contain sensitive or malicious indicators. Do not browse, resolve, or execute them.
- VirusTotal sends public IP indicators to a third party and is subject to API quotas and terms.

## Development

```bash
uv run --python 3.13 --isolated \
  --with pytest --with jinja2 --with pyshark --with requests \
  sh -c 'PYTHONPATH=tools/pcap-profiler/src pytest -q tests'
```

The canonical package source is only under `src/pcap_quick_profiler/`. Do not add a second executable implementation at the tool root.

See the [cheat sheet](../../docs/CHEATSHEET.md), [sample policy](../../docs/SAMPLES_AND_FIXTURES.md), and repository [security policy](../../SECURITY.md).

## License

MIT. See the package [LICENSE](LICENSE) and repository [license](../../LICENSE).
