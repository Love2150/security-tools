# Changelog

All notable changes to this repository are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and each package follows semantic versioning independently.

## [Unreleased]

### Added

- Repository-wide MIT license, security policy, contribution guide, issue templates, pull-request template, and release procedure.
- Complete prerequisites, output schemas, exit codes, and limitation documentation for all three tools.

### Changed

- Repository and tool documentation now reference the aggregate repository CI workflow.
- VirusTotal enrichment now rejects private, reserved, multicast, and malformed IP candidates before any third-party request.

## [2026-09-01]

### eval-unpacker 0.2.0

- Added bounded input, token, replacement, output, and recursion limits.
- Added malformed-input and parser-edge tests with at least 85% core coverage.
- Documented first-occurrence behavior and explicit UTF-8 replacement warnings.
- Corrected package metadata and README naming.

### pcap-quick-profiler 0.1.0

- Consolidated the profiler into one canonical installable package.
- Escaped evidence in HTML reports and added restrictive Content Security Policy protection.
- Corrected full-capture packet and byte totals and VirusTotal report behavior.
- Added installed console and module entry points.

### winlog-triage 0.1.0

- Packaged the tool with console and module entry points.
- Split reading, normalization, IOC extraction, rules, analysis, reporting, and CLI behavior.
- Hardened the PowerShell fallback and surfaced parsing completeness metadata.
- Validated IPv4 indicators and positive record limits.

### Repository

- Added repository-wide tests, Ruff enforcement, package builds, clean-wheel smoke tests, deterministic TShark integration, dependency auditing, and secret scanning.
- Added sample-provenance and repository-hygiene policy with automated enforcement.
- Added the stable aggregate `Required repository checks` status for branch-protection use.

[Unreleased]: https://github.com/Love2150/security-tools/compare/main...HEAD
[2026-09-01]: https://github.com/Love2150/security-tools/commits/main
