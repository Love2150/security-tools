# Contributing

Thank you for improving Security Tools. Contributions should remain focused, reproducible, and safe for analysts handling attacker-controlled evidence.

## Before opening a change

- Use GitHub Issues for bugs and feature proposals.
- Use the private process in [SECURITY.md](SECURITY.md) for vulnerabilities.
- Do not upload real malware, credentials, private logs, customer data, or evidence without documented redistribution permission.
- Keep each pull request limited to one coherent change.

## Development setup

Requirements:

- Git
- Python 3.10 or newer for the complete repository
- Python 3.9 when changing Eval Unpacker compatibility behavior
- `uv` for the documented isolated verification commands
- TShark for PCAP integration testing

Clone the repository and create a branch:

```bash
git clone https://github.com/Love2150/security-tools.git
cd security-tools
git switch -c type/short-description
```

Use conventional branch prefixes such as `fix/`, `feat/`, `docs/`, `test/`, or `ci/`.

## Required verification

Run the complete source suite and lint gate:

```bash
uv run --python 3.13 --isolated \
  --with pytest --with coverage --with ruff \
  --with jinja2 --with pyshark --with requests \
  --with python-evtx --with xmltodict --with pyyaml --with tomli \
  sh -c 'PYTHONPATH=tools/eval-unpacker:tools/pcap-profiler/src:tools/winlog-triage/src python -m pytest -q tests tools/eval-unpacker/tests && ruff check .'
```

Run the dependency audit:

```bash
uvx --from pip-audit pip-audit --strict --requirement .github/requirements-audit.txt
```

Behavior changes require tests. Documentation changes must match installed `--help` output. Package changes must build both a wheel and source distribution and must be smoke-tested from the wheel in a clean environment.

## Evidence and fixtures

Prefer deterministic synthetic fixtures generated during tests. A retained PCAP, EVTX, malware sample, or extracted artifact requires documented source, creator, redistribution permission, SHA-256, expected indicators, and sanitization status. Follow [docs/SAMPLES_AND_FIXTURES.md](docs/SAMPLES_AND_FIXTURES.md) and [docs/SAMPLE_PROVENANCE.md](docs/SAMPLE_PROVENANCE.md).

Normal test, build, and tool runs must not leave generated files tracked. Never weaken `.gitignore`, provenance checks, report escaping, resource limits, CI permissions, or the aggregate required check merely to make a test pass.

## Pull requests

Complete the pull-request template. Describe security impact, tests, documentation, sample provenance, and generated artifacts. All jobs feeding `Required repository checks` must pass. Resolve review conversations before merge.

By contributing, you agree that your contribution is licensed under the repository's [MIT License](LICENSE).
