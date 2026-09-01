import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_portfolio_documents_are_linked_and_complete():
    readme = read("README.md")
    portfolio = read("docs/PORTFOLIO.md")
    architecture = read("docs/ARCHITECTURE.md")

    assert "](docs/PORTFOLIO.md)" in readme
    assert "](docs/ARCHITECTURE.md)" in readme
    for heading in (
        "## What this project demonstrates",
        "## Security engineering case studies",
        "## Sanitized output examples",
        "## Interview discussion prompts",
        "## Scope and limitations",
    ):
        assert heading in portfolio
    for pull_request in range(1, 9):
        assert f"/pull/{pull_request}" in portfolio

    assert architecture.count("```mermaid") == 1
    assert architecture.count("```") == 2
    for boundary in (
        "Untrusted evidence",
        "External process and service boundaries",
        "Local configuration boundary",
        "Controlled transformations",
        "Attacker-influenced analyst outputs",
        "Repository assurance workflow",
    ):
        assert boundary in architecture
    for required_flow in (
        "TSHARK --> P",
        "EVTXBACKEND --> W",
        "PVALID -->|globally routable unicast IPs| REQUEST",
        "VTKEY -. local authentication input .-> REQUEST",
        "REQUEST -->|HTTPS request crosses local boundary| VT",
        "PRENDER --> POUT",
        "WRENDER --> WOUT",
        "ELIMIT --> EOUT",
    ):
        assert required_flow in architecture
    assert "Wheel + sdist inspection" not in architecture
    assert "Analyst-controlled outputs" not in architecture


def test_all_relative_markdown_targets_exist():
    for markdown in ROOT.rglob("*.md"):
        if any(part in {".git", "build", "dist"} or part.endswith(".egg-info") for part in markdown.parts):
            continue
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", read(str(markdown.relative_to(ROOT)))):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            relative_target = target.split("#", 1)[0]
            if relative_target:
                assert (markdown.parent / relative_target).resolve().exists(), (
                    markdown,
                    target,
                )


def test_portfolio_examples_are_parseable_and_backed_by_contracts():
    portfolio = read("docs/PORTFOLIO.md")
    assert "documentation-only, deterministic excerpts" in portfolio
    assert "no retained third-party evidence" in portfolio
    assert "Values are sanitized" in portfolio

    match = re.search(
        r"### Windows Log Triage schema excerpt.*?```json\n(.*?)\n```",
        portfolio,
        re.DOTALL,
    )
    assert match
    example = json.loads(match.group(1))
    parsing = example["parsing"]
    assert parsing == {
        "backend": "python-evtx",
        "records_read": 5,
        "records_skipped": 0,
        "parse_errors": 0,
    }
    assert isinstance(parsing["parse_errors"], int)

    verifier = read("scripts/verify_synthetic_pcap.py")
    for value in ("10.1.1.1", "10.2.2.2", "60", "53"):
        assert value in portfolio
        assert value in verifier
    for contract in ('report.get("bytes") != 60', '[["53", 1]]'):
        assert contract in verifier
    assert "<reconstructed JavaScript text>" in portfolio


def test_virustotal_boundary_is_documented_and_enforced():
    architecture = read("docs/ARCHITECTURE.md")
    implementation = read("tools/pcap-profiler/src/pcap_quick_profiler/virustotal.py")
    assert "globally routable unicast IPv4 or IPv6" in architecture
    assert "Accepted addresses leave the local trust boundary" in architecture
    assert "address.is_global" in implementation
    assert "not address.is_multicast" in implementation
    assert "not address.is_reserved" in implementation
    assert "if _is_public_ip" in implementation


def test_portfolio_preserves_caveats_and_separates_external_state_claims():
    text = (read("README.md") + read("docs/PORTFOLIO.md") + read("docs/ARCHITECTURE.md")).lower()
    normalized = text.replace("-", " ")
    for caveat in (
        "triage",
        "not verdicts",
        "attacker controlled",
        "without executing",
        "redistribution permission",
    ):
        assert caveat in normalized
    assurance_docs = (
        read("README.md") + read("docs/PORTFOLIO.md") + read("docs/ARCHITECTURE.md") + read("CHANGELOG.md")
    ).lower()
    for unsupported_claim in ("`main` requires", "protects `main`", "protected `main`"):
        assert unsupported_claim not in assurance_docs
    assert "branch protection is external github repository state" in assurance_docs
