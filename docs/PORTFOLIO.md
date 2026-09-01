# Portfolio Guide

This guide is for hiring managers, interviewers, and engineers reviewing the repository as a security-engineering portfolio project.

## What this project demonstrates

- Secure handling of attacker-controlled PCAP, EVTX, XML, command-line, and JavaScript-derived data.
- Root-cause remediation backed by regression tests rather than presentation-only changes.
- Python package consolidation, wheel/source-distribution builds, and clean-install verification.
- Analytical correctness checks against independent tooling such as TShark.
- CI/CD hardening with pinned actions, least-privilege permissions, dependency auditing, secret scanning, and an aggregate gate suitable for branch protection.
- Evidence provenance, responsible disclosure, release governance, and explicit analyst caveats.

## Suggested review path

A focused review can be completed in this order:

1. Read the root [README](../README.md) for scope and commands.
2. Review the [architecture and trust boundaries](ARCHITECTURE.md).
3. Read the case studies below to see the problem-solving approach.
4. Inspect the regression tests in `tests/` and `tools/eval-unpacker/tests/`.
5. Inspect [Repository CI](../.github/workflows/repository-ci.yml) and the [release procedure](RELEASING.md).
6. Review the phased pull-request history linked from the case studies.

## Phased delivery history

| Phase | Pull request | Outcome |
| --- | --- | --- |
| Security correctness | [PR #1](https://github.com/Love2150/security-tools/pull/1) | Hardened report rendering and corrected analytical totals |
| Canonical PCAP package | [PR #2](https://github.com/Love2150/security-tools/pull/2) | Consolidated installation and entry points |
| Documentation foundation | [PR #3](https://github.com/Love2150/security-tools/pull/3) | Added repository overview and usage guide |
| Windows Log Triage | [PR #4](https://github.com/Love2150/security-tools/pull/4) | Packaged and hardened EVTX analysis |
| Eval Unpacker | [PR #5](https://github.com/Love2150/security-tools/pull/5) | Added hostile-input and resource-exhaustion defenses |
| Hygiene and provenance | [PR #6](https://github.com/Love2150/security-tools/pull/6) | Removed generated/unlicensed evidence and enforced policy |
| Repository CI | [PR #7](https://github.com/Love2150/security-tools/pull/7) | Added aggregate quality and security gates |
| Governance and release readiness | [PR #8](https://github.com/Love2150/security-tools/pull/8) | Added licensing, policies, complete docs, and fail-closed releases |

## Security engineering case studies

### 1. Stored report injection and misleading PCAP totals

**Problem:** PCAP and EVTX evidence fields can contain attacker-controlled strings. Rendering them into HTML without contextual escaping creates stored script-injection risk. The profiler also reported focused-subset counts as though they represented the complete capture.

**Approach:** Traced data from parser output through JSON/text/HTML renderers, reproduced unsafe rendering with adversarial fields, compared packet and byte totals with TShark, then added regression tests before accepting the remediation.

**Result:** Reports escape untrusted evidence, use restrictive Content Security Policy protection, avoid inline event handlers, and report full-capture totals. A known sample was independently confirmed as 13 packets and 1,590 bytes.

**Evidence:** [PR #1](https://github.com/Love2150/security-tools/pull/1) and `tests/test_phase_one_security.py`.

### 2. Duplicate implementations and unreliable installation

**Problem:** Multiple PCAP implementations and stale package artifacts made it possible to patch the wrong source tree or ship behavior different from the checkout.

**Approach:** Identified the canonical execution path, consolidated code beneath one package, defined console and module entry points, and exercised what users install rather than relying only on source-tree tests.

**Result:** PCAP Quick Profiler has one canonical implementation, buildable wheel/source distributions, clean installation, functional console/module entry points, packaged enrichment resources, and deterministic report discovery.

**Evidence:** [PR #2](https://github.com/Love2150/security-tools/pull/2) and `tests/test_phase_two_packaging.py`.

### 3. Hostile EVTX paths, incomplete parsing, and weak IOC validation

**Problem:** Windows event-log tooling must safely handle hostile paths and malformed records while telling analysts when results are incomplete. Regex-only IOC extraction can also accept invalid addresses.

**Approach:** Split reading, normalization, IOC extraction, rules, analysis, reporting, and CLI concerns. Passed PowerShell paths through an environment variable with `-LiteralPath`, surfaced subprocess failures, tracked parser completeness, and validated IP candidates semantically.

**Result:** The installable Windows Log Triage package reports backend, records read, records skipped, and parse errors; rejects invalid limits; validates IPv4 candidates; and safely renders evidence.

**Evidence:** [PR #4](https://github.com/Love2150/security-tools/pull/4) and `tests/test_phase_three_winlog.py`.

### 4. Resource exhaustion in packed-source reconstruction

**Problem:** Packed JavaScript can force excessive input, token replacement, recursion, intermediate storage, or output growth. Silent UTF-8 loss can also hide evidence.

**Approach:** Added malformed and adversarial fixtures, bounded every major growth dimension, defined first-supported-occurrence behavior, and made invalid UTF-8 handling observable.

**Result:** Eval Unpacker reconstructs supported syntax without executing it, rejects unsafe limits and malformed input, bounds recursive work, reports invalid-byte offsets, and maintains 91% core coverage.

**Evidence:** [PR #5](https://github.com/Love2150/security-tools/pull/5) and `tools/eval-unpacker/tests/`.

### 5. Evidence provenance and repository hygiene

**Problem:** Security repositories can accidentally retain sensitive reports, unlicensed evidence, caches, or build artifacts. Such files create privacy, legal, and reproducibility risks.

**Approach:** Inventoried generated and binary content, removed material without established redistribution rights, documented hashes and disposition, and made hygiene/provenance policy executable through tests.

**Result:** Fifty-seven generated reports/output files and seven PCAP/EVTX samples without established redistribution permission were removed. Retained evidence now requires origin, creator, permission, SHA-256, expected indicators, and sanitization status.

**Evidence:** [PR #6](https://github.com/Love2150/security-tools/pull/6), [sample policy](SAMPLES_AND_FIXTURES.md), and `tests/test_repository_hygiene.py`.

### 6. Repository-wide quality and release assurance

**Problem:** A single-tool workflow could not prove that all packages remained testable, installable, secure, and releasable.

**Approach:** Built an aggregate CI workflow spanning supported Python versions, lint, tests, coverage, distributions, clean-install smoke tests, deterministic TShark integration, dependency auditing, secret scanning, and a fail-closed aggregate result suitable for branch protection.

**Result:** Repository CI produces the stable `Required repository checks` aggregate result for branch-protection use. Release instructions verify the exact merged commit and intended workflow, export source from the verified Git object, and use package-specific checksums.

**Evidence:** [PR #7](https://github.com/Love2150/security-tools/pull/7), [PR #8](https://github.com/Love2150/security-tools/pull/8), and `tests/test_ci_policy.py`.

## Sanitized output examples

The examples below are documentation-only, deterministic excerpts. They contain no retained third-party evidence and are not substitutes for original reports.

### PCAP profile excerpt

```text
Packets: 1
Bytes:   60
Duration: 0.00s
Top Source IPs:
  - 10.1.1.1 (1)
Top Destination IPs:
  - 10.2.2.2 (1)
Top Destination Ports:
  - 53 (1)
```

This excerpt corresponds to the synthetic one-packet capture generated by Repository CI with `text2pcap`.

### Windows Log Triage schema excerpt

```json
{
  "count": 5,
  "parsing": {
    "backend": "python-evtx",
    "records_read": 5,
    "records_skipped": 0,
    "parse_errors": 0
  },
  "rule_hits": [],
  "iocs": {
    "domains": [],
    "ipv4": [],
    "sha256": []
  }
}
```

Values are sanitized and illustrate the documented completeness contract rather than preserving source evidence.

### Eval Unpacker behavior

```text
$ eval-unpack packed.js --recursive
<reconstructed JavaScript text>
```

Recovered text is written to standard output. Diagnostics and malformed-input warnings are written to standard error. Reconstructed code is not executed.

## Interview discussion prompts

- How were parser, renderer, and packaging trust boundaries identified?
- Why is clean-wheel testing stronger than source-only testing?
- How does parsing-completeness metadata prevent false confidence?
- Why were unlicensed samples removed instead of merely adding warnings?
- How does the aggregate required check fail closed?
- How are release artifacts bound to the exact reviewed commit?

## Scope and limitations

This is a defensive portfolio and learning project, not a commercial detection platform. The tools provide triage leads rather than verdicts; encrypted traffic is not decrypted; EVTX normalization is intentionally focused; packed-code reconstruction supports a defined syntax family; and VirusTotal enrichment is optional and subject to third-party terms.
