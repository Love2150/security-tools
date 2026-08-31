# Samples, Fixtures, and Generated Reports

## Safety warning

Evidence and generated reports can contain hostile or sensitive domains, URLs, IP addresses, file names, command lines, hashes, and payload text. **Do not browse, resolve, or execute** extracted domains, URLs, files, payloads, or other indicators. Do not submit them to third-party services unless authorized. Treat all extracted content as untrusted data, and analyze it only in an appropriately isolated environment.

## Deterministic test fixtures

Deterministic fixtures exist only to make automated tests reproducible. They belong under `tests/fixtures/` and must be minimal, synthetic where practical, stable, and covered by the provenance registry when they are binary evidence.

The current tests use in-code synthetic dictionaries, strings, packet objects, and fake EVTX readers. No PCAP, EVTX, or other binary evidence fixture is retained.

## Portfolio demonstrations

Portfolio demonstrations are human-facing examples, not test dependencies. Approved evidence demonstrations belong under `examples/samples/`. Intentional sanitized report examples belong under `examples/reports/`. Each must have an `approved-retained` record in `sample-provenance.json` containing established redistribution rights, documented sanitization, expected indicators, and its SHA-256 before it is committed.

No portfolio evidence or generated report is currently retained. The former samples and timestamped outputs were removed during Phase 5 because permission, provenance, and sanitization could not be established.

## Generated output

Normal tool runs write generated output under `reports/` or `out/`. These directories are ignored and must remain untracked. Build products, coverage output, caches, bytecode, and package metadata are also ignored. Run `pytest -q tests/test_repository_hygiene.py` to enforce this policy against tracked files.
