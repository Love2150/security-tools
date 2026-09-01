# Windows Log Triage

Windows Log Triage parses Windows EVTX and Sysmon evidence, normalizes common event fields, extracts validated indicators, applies lightweight ATT&CK-oriented rules, and produces portable HTML, JSON, and CSV reports.

## Prerequisites

- Python 3.10 or newer
- `python-evtx`, `xmltodict`, and Jinja2, installed with the package
- Read permission for selected EVTX files
- On Windows only, PowerShell is an automatic fallback when `python-evtx` is unavailable

Install from the repository root:

```bash
python -m pip install ./tools/winlog-triage
```

## Usage

```bash
winlog-triage path/to/file.evtx --outdir reports/winlog-triage
winlog-triage path/to/folder --max-per-file 1000
python -m winlog_triage path/to/file.evtx
```

| Option | Meaning |
| --- | --- |
| `--outdir DIRECTORY` | Timestamped report destination; default `out` |
| `--html PATH` | Exact HTML report path |
| `--json PATH` | Exact JSON summary path |
| `--csv PATH` | Exact CSV sample path |
| `--max-per-file N` | Positive maximum records read from each file |

Directories are expanded to their immediate `*.evtx` files. Multiple files and directories may be supplied.

## Output schema

A successful run writes HTML, JSON, and CSV files.

Top-level JSON fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `count` | integer | Successfully normalized events |
| `first_ts`, `last_ts` | string or null | ISO-formatted observed event bounds |
| `parsing` | object | `backend`, `records_read`, `records_skipped`, and `parse_errors` |
| `providers`, `event_ids` | object | Counts keyed by provider or event ID |
| `top_processes`, `top_parents` | object | Process-path count maps |
| `suspicious_cmd` | array | LOLBIN-oriented command-line leads |
| `net_by_process` | array | Objects containing `process`, `dst`, and `count` |
| `persistence` | array | Lightweight persistence-related event leads |
| `rule_hits` | array | Rule, technique, timestamp, image, and command data |
| `iocs` | object | Sorted `urls`, `domains`, `ipv4`, `md5`, `sha1`, `sha256`, and `emails` arrays |
| `sample` | array | At most 25 representative normalized events |

CSV contains the representative sample with columns `ts`, `provider`, `eid`, `image`, and `cmd`. HTML presents escaped summary and evidence fields with restrictive browser protections.

Parsing metadata is part of the analytical result. A report with skipped records or parse errors is incomplete even if the command succeeds.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Inputs were processed and reports were written |
| `1` | EVTX backend or read failure, or another processing/output error |
| `2` | Invalid arguments, including a non-positive `--max-per-file` |

## Limitations

- Rules are lightweight triage heuristics, not full Sigma coverage or a detection verdict.
- Event normalization focuses on common Windows and Sysmon fields; unfamiliar providers can produce sparse records.
- PowerShell fallback is Windows-only and can differ from `python-evtx` behavior.
- `--max-per-file` intentionally produces partial analysis; use parsing metadata when interpreting results.
- IOC extraction is syntactic and semantic validation, not reputation analysis.
- Reports can contain sensitive usernames, hostnames, command lines, paths, and indicators.
- Do not execute commands or browse extracted indicators. Preserve original EVTX evidence separately.

## Development

```bash
uv run --python 3.13 --isolated \
  --with pytest --with jinja2 --with python-evtx --with xmltodict \
  sh -c 'PYTHONPATH=tools/winlog-triage/src pytest -q tests'
```

See the repository [security policy](../../SECURITY.md), [sample policy](../../docs/SAMPLES_AND_FIXTURES.md), and [contribution guide](../../CONTRIBUTING.md).

## License

MIT. See the package [LICENSE](LICENSE) and repository [license](../../LICENSE).
