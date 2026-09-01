from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 CI
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_REPORTING_URL = (
    "https://github.com/Love2150/security-tools/security/advisories/new"
)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def load_toml(relative: str) -> dict:
    with (ROOT / relative).open("rb") as handle:
        return tomllib.load(handle)


def cli_help(module: str, pythonpath: str) -> str:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / pythonpath)
    result = subprocess.run(
        [sys.executable, "-m", module, "--help"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout + result.stderr


def documented_options(readme: str, help_text: str) -> None:
    options = set(re.findall(r"(?<!\w)--[a-z][a-z0-9-]*", help_text))
    options.discard("--help")
    missing = sorted(option for option in options if option not in readme)
    assert not missing, f"undocumented CLI options: {missing}"


def test_repository_governance_files_are_present_and_linked():
    required = (
        "LICENSE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "docs/RELEASING.md",
    )
    for relative in required:
        assert (ROOT / relative).is_file(), relative

    license_text = read("LICENSE")
    assert "MIT License" in license_text
    assert "Copyright (c) 2026 Brandon Love" in license_text
    assert "..." not in license_text

    root_readme = read("README.md")
    for relative in required:
        assert f"]({relative})" in root_readme
    assert "eval-unpacker-ci.yml" not in root_readme
    assert "ReadME.md" not in root_readme
    assert "repository-ci.yml" in root_readme


def test_package_license_metadata_and_build_roots_are_coherent():
    packages = (
        "tools/eval-unpacker",
        "tools/pcap-profiler",
        "tools/winlog-triage",
    )
    root_license = read("LICENSE")
    for package in packages:
        metadata = load_toml(f"{package}/pyproject.toml")["project"]
        assert metadata["license"] == "MIT", package
        package_license = read(f"{package}/LICENSE")
        assert package_license == root_license, package
        assert "..." not in package_license
        assert "MIT" in read(f"{package}/README.md")


def test_every_tool_documents_live_interfaces_schemas_and_boundaries():
    interfaces = (
        (
            "tools/eval-unpacker/README.md",
            "eval_unpacker.cli",
            "tools/eval-unpacker",
            (),
        ),
        (
            "tools/pcap-profiler/README.md",
            "pcap_quick_profiler",
            "tools/pcap-profiler/src",
            ("file", "packets", "bytes", "duration", "http_hosts", "tls_versions", "src_ips"),
        ),
        (
            "tools/winlog-triage/README.md",
            "winlog_triage",
            "tools/winlog-triage/src",
            ("count", "parsing", "providers", "event_ids", "rule_hits", "iocs", "sample"),
        ),
    )
    for relative, module, pythonpath, schema_fields in interfaces:
        text = read(relative)
        for heading in (
            "## Prerequisites",
            "## Output schema",
            "## Exit codes",
            "## Limitations",
        ):
            assert heading in text, f"{relative}: {heading}"
        documented_options(text, cli_help(module, pythonpath))
        for field in schema_fields:
            assert f"`{field}`" in text, f"{relative}: undocumented schema field {field}"
        assert "triage" in text.lower()

    pcap_readme = read("tools/pcap-profiler/README.md")
    documented_options(
        pcap_readme,
        cli_help("pcap_quick_profiler.virustotal", "tools/pcap-profiler/src"),
    )
    assert "enrichment as non-fatal" in pcap_readme
    assert "may also return `0`" in pcap_readme


def test_issue_forms_are_parseable_and_schema_shaped():
    form_paths = (
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
    )
    for relative in form_paths:
        form = yaml.safe_load(read(relative))
        assert isinstance(form, dict)
        assert all(form.get(key) for key in ("name", "description", "body"))
        assert isinstance(form["body"], list) and form["body"]
        ids = []
        for item in form["body"]:
            assert item.get("type") in {"markdown", "input", "textarea", "dropdown", "checkboxes"}
            if item["type"] != "markdown":
                assert item.get("id")
                ids.append(item["id"])
                assert isinstance(item.get("attributes"), dict)
                validations = item.get("validations", {})
                assert isinstance(validations, dict)
                if "required" in validations:
                    assert isinstance(validations["required"], bool)
        assert len(ids) == len(set(ids)), f"duplicate IDs in {relative}"

    bug = read(form_paths[0]).lower()
    feature = read(form_paths[1]).lower()
    pull_request = read(".github/pull_request_template.md").lower()
    for required in ("operating system", "python version", "sanitized", "expected", "actual"):
        assert required in bug
    assert "security" in feature
    for required in ("tests", "documentation", "security impact", "provenance", "generated artifacts"):
        assert required in pull_request


def test_private_vulnerability_reporting_links_are_consistent():
    security = read("SECURITY.md")
    config = yaml.safe_load(read(".github/ISSUE_TEMPLATE/config.yml"))
    links = config["contact_links"]
    assert any(link.get("url") == PRIVATE_REPORTING_URL for link in links)
    assert PRIVATE_REPORTING_URL in security
    assert "do not" in security.lower() and "public" in security.lower()


def test_release_process_is_exact_sha_fail_closed_and_portable():
    release = read("docs/RELEASING.md")
    changelog = read("CHANGELOG.md")

    for gate in ("Required repository checks", "wheel", "source distribution", "semantic version"):
        assert gate in release
    assert "Do not create a release" in release
    assert 'test -z "$(git status --porcelain)"' in release
    assert 'release_sha="$(git rev-parse HEAD)"' in release
    assert "--workflow repository-ci.yml" in release
    assert '--commit "$release_sha"' in release
    assert "--event push" in release
    assert "length == 1" in release
    assert "headSha, .status, .conclusion" in release
    assert 'test "$run_gate" = "$expected_gate"' in release
    assert 'git archive --format=tar "$release_sha"' in release
    assert 'test "$(git rev-parse HEAD)" = "$release_sha"' in release
    assert "sha256sum /tmp/security-tools-release/*/*" not in release
    assert "sha256sum -- *.whl *.tar.gz > SHA256SUMS" in release

    for relative in ("README.md", "CONTRIBUTING.md"):
        command_docs = read(relative)
        assert "--with pyyaml" in command_docs
        assert "--with tomli" in command_docs
    for version in (
        "eval-unpacker 0.2.0",
        "pcap-quick-profiler 0.1.0",
        "winlog-triage 0.1.0",
    ):
        assert version in changelog
