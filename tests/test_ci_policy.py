from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
EXPECTED_ACTIONS = {
    "actions/checkout": ("11d5960a326750d5838078e36cf38b85af677262", "v4"),
    "actions/setup-python": ("a26af69be951a213d495a4c3e4e4022e16d87065", "v5"),
    "actions/upload-artifact": ("ea165f8d65b6e75b540449e92b4886f43607fa02", "v4"),
    "gitleaks/gitleaks-action": ("dcedce43c6f43de0b836d1fe38946645c9c638dc", "v2"),
}


def workflow_text() -> str:
    workflows = sorted((*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")))
    assert len(workflows) == 1, "CI must expose one aggregate required-check workflow"
    return workflows[0].read_text(encoding="utf-8")


def test_aggregate_workflow_cannot_be_skipped_by_pr_filters():
    workflow = workflow_text()
    trigger = workflow.split("permissions:", 1)[0]

    assert re.search(r"(?m)^  pull_request:\s*$", trigger)
    assert re.search(r"(?m)^  push:\s*$", trigger)
    assert not re.search(r"(?m)^\s+(paths|paths-ignore|branches|branches-ignore):", trigger)
    assert re.search(r"(?m)^permissions:\s*\n  contents: read\s*$", workflow)
    security_job = workflow.split("  security:\n", 1)[1].split("\n  required:\n", 1)[0]
    assert re.search(
        r"(?m)^    permissions:\s*\n      contents: read\s*\n      pull-requests: read\s*$",
        security_job,
    )
    assert re.search(r"(?m)^  required:\s*$", workflow)
    assert "if: ${{ always() }}" in workflow
    assert "needs: [quality, eval_compatibility, package, integration, security]" in workflow


def test_every_action_is_immutably_pinned_with_version_comment():
    workflow = workflow_text()
    uses = re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)(?:\s+#\s*(\S+))?\s*$", workflow)

    assert uses
    assert workflow.count("persist-credentials: false") == workflow.count("actions/checkout@")
    assert {reference.split("@", 1)[0] for reference, _ in uses} == set(EXPECTED_ACTIONS)
    for reference, comment in uses:
        action, revision = reference.split("@", 1)
        expected_sha, expected_version = EXPECTED_ACTIONS[action]
        assert revision == expected_sha
        assert comment == expected_version


def test_quality_matrix_covers_supported_python_and_all_tests_and_lint():
    workflow = workflow_text()

    for version in ("3.10", "3.11", "3.12", "3.13"):
        assert f"'{version}'" in workflow
    assert re.search(r"(?m)^  eval_compatibility:\s*$", workflow)
    assert "name: Eval Unpacker compatibility (Python 3.9)" in workflow
    assert "python-version: '3.9'" in workflow
    assert "python -m pip install pytest" in workflow
    assert "PYTHONPATH=tools/eval-unpacker python -m pytest -q tools/eval-unpacker/tests" in workflow
    assert "python -m pytest -q tools/eval-unpacker/tests" in workflow
    assert "python -m pytest -q tests tools/eval-unpacker/tests" in workflow
    quality_job = workflow.split("  quality:\n", 1)[1].split("\n  eval_compatibility:\n", 1)[0]
    assert "python -m pip install ./tools/" not in quality_job
    assert "PYTHONPATH: tools/eval-unpacker:tools/pcap-profiler/src:tools/winlog-triage/src" in quality_job
    assert "coverage report --include='tools/eval-unpacker/eval_unpacker/core.py' --fail-under=85" in workflow
    assert "ruff check ." in workflow


def test_all_packages_are_built_and_wheels_are_isolated_smoke_tested():
    workflow = workflow_text()

    packages = ("eval-unpacker", "pcap-profiler", "winlog-triage")
    for package in packages:
        assert f'python -m build "tools/{package}"' in workflow
        assert f'python -m venv "$RUNNER_TEMP/venv-{package}"' in workflow
    for command in (
        "eval-unpack --help",
        "python -m eval_unpacker.cli --help",
        "pcap-profiler --help",
        "pcap-profiler-vt --help",
        "python -m pcap_quick_profiler --help",
        "winlog-triage --help",
        "python -m winlog_triage --help",
    ):
        assert command in workflow
    assert "actions/upload-artifact" in workflow
    assert "*.whl" in workflow
    assert "*.tar.gz" in workflow


def test_ruff_policy_scans_the_repository_with_security_rules_enabled():
    config = (ROOT / "ruff.toml").read_text(encoding="utf-8")

    assert '"S"' in config
    assert "S102" not in config  # exec must remain a blocking finding
    assert "S307" not in config  # eval must remain a blocking finding
    assert "exclude" not in config


def test_integration_and_security_gates_are_present_and_deterministic(tmp_path):
    workflow = workflow_text()
    verifier = ROOT / "scripts" / "verify_synthetic_pcap.py"

    assert verifier.exists()
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "synthetic.json").write_text(
        '{"packets": 1, "dst_ports": [["53", 1]]}', encoding="utf-8"
    )
    result = subprocess.run(
        [sys.executable, str(verifier), str(reports)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    (reports / "synthetic.json").write_text(
        '{"packets": 2, "dst_ports": [["53", 1]]}', encoding="utf-8"
    )
    result = subprocess.run(
        [sys.executable, str(verifier), str(reports)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0

    assert "text2pcap" in workflow
    assert "tshark" in workflow
    assert "synthetic.pcap" in workflow
    assert "2024-01-01T00:00:00Z" in workflow
    assert "text2pcap -q -t ISO" in workflow
    assert "mktemp -d" in workflow
    assert 'python scripts/verify_synthetic_pcap.py "$workdir/reports"' in workflow
    assert "python -m pip_audit --strict --requirement .github/requirements-audit.txt" in workflow
    audit_requirements = (ROOT / ".github" / "requirements-audit.txt").read_text(encoding="utf-8")
    for dependency in (
        "jsbeautifier>=1.15.1",
        "jinja2>=3.1",
        "pyshark>=0.6",
        "requests>=2.31",
        "python-evtx>=0.7",
        "xmltodict>=0.13",
    ):
        assert dependency in audit_requirements
    assert "gitleaks/gitleaks-action" in workflow
    assert "GITHUB_TOKEN: ${{ github.token }}" in workflow
    assert "GITLEAKS_ENABLE_COMMENTS: false" in workflow
    assert "Scan pull request and push changes for secrets" in workflow
    assert not list(ROOT.rglob("*.pcap"))
    assert not list(ROOT.rglob("*.pcapng"))
