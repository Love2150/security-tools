# Windows Log Triage

Windows Log Triage parses Windows EVTX and Sysmon evidence, normalizes common event fields, extracts validated indicators, applies lightweight ATT&CK-oriented rules, and produces portable HTML, JSON, and CSV reports.

## Install

```bash
python -m pip install ./tools/winlog-triage
```

## Use

```bash
winlog-triage path/to/file.evtx --outdir reports/winlog-triage
winlog-triage path/to/folder --max-per-file 1000
python -m winlog_triage path/to/file.evtx
```

`--max-per-file` must be a positive integer. Use `--html`, `--json`, and `--csv` to select exact output paths.

The preferred backend is `python-evtx`. On Windows, PowerShell is used as a fallback when `python-evtx` is unavailable. Report metadata records the backend, records read, records skipped, and parse errors so incomplete analysis is visible.

Findings are triage leads, not verdicts. Review generated reports before sharing because they may contain sensitive evidence.
