# Security Tools

Defensive security utilities for packet-capture profiling, Windows event-log triage, and safe reconstruction of classic packed JavaScript. Each tool is an independently installable Python package with an explicit trust boundary and machine-readable output.

[![Repository CI](https://github.com/Love2150/security-tools/actions/workflows/repository-ci.yml/badge.svg)](https://github.com/Love2150/security-tools/actions/workflows/repository-ci.yml)

## Portfolio overview

This repository is an engineering portfolio built around realistic defensive-security trust boundaries. It demonstrates secure evidence handling, analytical validation, Python packaging, regression testing, CI/CD hardening, supply-chain controls, and release governance—not just standalone scripts.

For a focused employer or interview review:

- [Portfolio guide and security engineering case studies](docs/PORTFOLIO.md)
- [Architecture, data flows, and trust boundaries](docs/ARCHITECTURE.md)
- [Repository-wide CI](.github/workflows/repository-ci.yml)
- [Security policy](SECURITY.md)
- [Fail-closed release procedure](docs/RELEASING.md)

### Engineering highlights

- Treats PCAP, EVTX, XML, filenames, command lines, and reconstructed source as attacker-controlled data.
- Prevents stored report injection with contextual escaping and restrictive Content Security Policy protection.
- Validates analytical claims against independent tooling and records parsing completeness.
- Exercises built wheels in clean environments so installed behavior—not only checkout behavior—is tested.
- Produces a pinned, least-privilege aggregate CI gate spanning tests, coverage, builds, TShark integration, dependency auditing, and secret scanning; repository administrators can require that stable result in branch protection.
- Removes evidence without established redistribution permission and enforces provenance for anything retained.

## Tools

| Tool | Purpose | Python | Primary command | Documentation |
| --- | --- | --- | --- | --- |
| PCAP Quick Profiler | Full-capture statistics plus focused HTTP/TLS triage and optional VirusTotal IP enrichment | 3.10+ | `pcap-profiler` | [README](tools/pcap-profiler/README.md) |
| Windows Log Triage | EVTX/Sysmon normalization, IOC extraction, lightweight rules, and parsing-completeness reporting | 3.10+ | `winlog-triage` | [README](tools/winlog-triage/README.md) |
| Eval Unpacker | Reconstructs the first supported classic packer occurrence without executing JavaScript | 3.9+ | `eval-unpack` | [README](tools/eval-unpacker/README.md) |

These are triage tools. Findings require analyst validation and are not verdicts.

## Quick start

```bash
git clone https://github.com/Love2150/security-tools.git
cd security-tools
```

### PCAP Quick Profiler

Install TShark first, then:

```bash
python -m pip install ./tools/pcap-profiler
pcap-profiler capture.pcap --outdir reports/pcap-profiler
```

Equivalent module command:

```bash
python -m pcap_quick_profiler capture.pcap
```

Optional VirusTotal enrichment uses only `VT_API_KEY`:

```bash
export VT_API_KEY="<YOUR_API_KEY>"
pcap-profiler capture.pcap --vt
pcap-profiler-vt --latest
```

### Windows Log Triage

```bash
python -m pip install ./tools/winlog-triage
winlog-triage path/to/logs --outdir reports/winlog-triage
```

Equivalent module command:

```bash
python -m winlog_triage path/to/file.evtx
```

### Eval Unpacker

```bash
python -m pip install "./tools/eval-unpacker[beautify]"
eval-unpack packed.js --recursive --beautify
cat packed.js | eval-unpack -
```

Eval Unpacker reconstructs supported source text; it does not execute recovered JavaScript.

## Outputs and interfaces

- PCAP Quick Profiler writes timestamped JSON, text, CSV, and CSP-protected HTML beneath `reports/pcap-profiler/` by default.
- Windows Log Triage writes timestamped JSON, CSV, and CSP-protected HTML beneath its selected output directory.
- Eval Unpacker writes reconstructed UTF-8 text to standard output and diagnostics to standard error.

Each tool README documents prerequisites, exact options, output schema, exit codes, and limitations. The PCAP [cheat sheet](docs/CHEATSHEET.md) provides common commands.

## Security model

The tools process attacker-controlled evidence. Safeguards include:

- automatic HTML escaping and restrictive Content Security Policy protection;
- no JavaScript execution by Eval Unpacker;
- bounded unpacking resources and explicit malformed-input rejection;
- full-capture PCAP totals independently checked with TShark;
- parser-completeness metadata for Windows event logs;
- environment-only VirusTotal credentials;
- strict sample provenance and generated-artifact controls;
- repository-wide lint, tests, builds, installed-wheel smoke tests, dependency auditing, and secret scanning.

Generated reports may still contain sensitive hostnames, addresses, usernames, command lines, URLs, and paths. Review reports before sharing. Do not browse, resolve, execute, or submit recovered indicators or payloads to third parties without authorization.

Report vulnerabilities privately through the [Security Policy](SECURITY.md).

## Samples and evidence

No binary evidence is currently retained because redistribution permission and sanitization could not be established. Tests generate deterministic fixtures where possible. See:

- [Samples and Fixtures](docs/SAMPLES_AND_FIXTURES.md)
- [Sample Provenance](docs/SAMPLE_PROVENANCE.md)
- [Provenance Registry](docs/sample-provenance.json)

A retained sample requires documented source, creator, redistribution permission, SHA-256, expected indicators, and sanitization status.

## Development

Run the complete source suite and Ruff gate:

```bash
uv run --python 3.13 --isolated \
  --with pytest --with coverage --with ruff \
  --with jinja2 --with pyshark --with requests \
  --with python-evtx --with xmltodict --with pyyaml --with tomli \
  sh -c 'PYTHONPATH=tools/eval-unpacker:tools/pcap-profiler/src:tools/winlog-triage/src python -m pytest -q tests tools/eval-unpacker/tests && ruff check .'
```

Audit all required and supported optional dependencies:

```bash
uvx --from pip-audit pip-audit --strict --requirement .github/requirements-audit.txt
```

The aggregate [repository CI workflow](.github/workflows/repository-ci.yml) tests Python 3.10–3.13, preserves Eval Unpacker Python 3.9 compatibility, enforces Eval Unpacker core coverage, builds every wheel and source distribution, smoke-tests installed entry points, generates a deterministic TShark fixture, audits dependencies, and scans for secrets. It produces the stable `Required repository checks` result for branch-protection use.

## Project governance

- [MIT License](LICENSE)
- [Security Policy](SECURITY.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Release Procedure](docs/RELEASING.md)

GitHub Releases are the current release channel. PyPI publication is not configured. Packages use independent semantic versions and package-prefixed tags.

## Responsible use

Use these tools only with captures, logs, systems, and code you are authorized to analyze. Preserve original evidence, use isolated analysis systems, and corroborate automated findings before containment, escalation, or attribution decisions.

## Author

Brandon Love — [GitHub](https://github.com/Love2150)
