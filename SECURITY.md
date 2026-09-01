# Security Policy

## Supported versions

Security fixes are applied to the latest code on `main` and to these current package lines:

| Package | Supported version |
| --- | --- |
| `eval-unpacker` | `0.2.x` |
| `pcap-quick-profiler` | `0.1.x` |
| `winlog-triage` | `0.1.x` |

Older commits, generated reports, and unofficial distributions are not supported.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability-reporting form for this repository:

https://github.com/Love2150/security-tools/security/advisories/new

Include:

- the affected tool, version, commit, and operating system;
- a concise impact statement and realistic attack scenario;
- exact reproduction steps and the smallest safe proof of concept;
- whether attacker-controlled PCAP, EVTX, JavaScript, paths, or report fields are involved;
- any proposed mitigation;
- confirmation that credentials, personal data, malware, and proprietary evidence were removed.

Expect acknowledgement when the report is reviewed. Remediation timing depends on severity and reproducibility. Please allow a reasonable remediation window before public disclosure.

## Security boundaries

These tools process untrusted evidence but are triage utilities, not sandboxes. Generated findings are leads rather than verdicts. Do not execute recovered JavaScript, extracted files, commands, URLs, domains, or other indicators. Use isolated analysis systems, retain original evidence separately, and review reports before sharing.

Never submit real API keys, credentials, private logs, customer data, or unredacted investigation artifacts. VirusTotal credentials must be supplied through `VT_API_KEY` and must not be embedded in code, fixtures, issues, or reports.

## Scope

Reports about stored report injection, command or path injection, unsafe parsing, resource exhaustion, credential exposure, misleading analytical totals, dependency compromise, or CI permission bypass are in scope. General feature requests and support questions belong in GitHub Issues.
