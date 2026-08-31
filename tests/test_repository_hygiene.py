from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_SUFFIXES = {".pcap", ".pcapng", ".evtx", ".e01", ".raw", ".dmp"}
GENERATED_DIRS = {
    "__pycache__",
    ".cache",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".pyre",
    ".pytype",
    ".hypothesis",
    ".tox",
    ".nox",
    "pip-wheel-metadata",
    "htmlcov",
    "build",
    "dist",
    "out",
    "reports",
}
GENERATED_SUFFIXES = {".pyc", ".pyo"}
REQUIRED_IGNORE_RULES = {
    "__pycache__/",
    "*.py[cod]",
    "*.egg-info/",
    "build/",
    "dist/",
    ".pytest_cache/",
    ".ruff_cache/",
    ".coverage",
    "htmlcov/",
    "reports/",
    "out/",
}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [Path(item.decode()) for item in result.stdout.split(b"\0") if item]


def test_generated_artifacts_are_ignored_and_untracked():
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    rules = {line.strip() for line in gitignore if line.strip() and not line.startswith("#")}
    assert REQUIRED_IGNORE_RULES <= rules

    forbidden = []
    for path in tracked_files():
        intentional_report = path.parts[:2] == ("examples", "reports")
        generated_directory = bool(GENERATED_DIRS.intersection(path.parts))
        generated_file = (
            path.suffix in GENERATED_SUFFIXES
            or path.name == ".coverage"
            or path.name.startswith(".coverage.")
            or any(part.endswith(".egg-info") for part in path.parts)
        )
        if (generated_directory and not intentional_report) or generated_file:
            forbidden.append(path.as_posix())
    assert forbidden == []


def test_evidence_and_example_reports_have_approved_provenance():
    tracked = tracked_files()
    evidence = [path for path in tracked if path.suffix.lower() in EVIDENCE_SUFFIXES]
    example_reports = [path for path in tracked if path.parts[:2] == ("examples", "reports")]
    retained = evidence + example_reports
    manifest = json.loads(
        (ROOT / "docs" / "sample-provenance.json").read_text(encoding="utf-8")
    )
    records = {record["path"]: record for record in manifest["retained_samples"]}

    assert set(records) == {path.as_posix() for path in retained}
    for path in evidence:
        assert path.parts[:2] in {("tests", "fixtures"), ("examples", "samples")}

    unknown_markers = ("unknown", "not established", "not documented", "pending", "tbd", "todo")
    for path in retained:
        record = records[path.as_posix()]
        if path.parts[:2] == ("tests", "fixtures"):
            expected_category = "test-fixture"
        elif path.parts[:2] == ("examples", "samples"):
            expected_category = "portfolio-sample"
        else:
            assert path.parts[:2] == ("examples", "reports")
            expected_category = "sanitized-example-report"
        assert record["category"] == expected_category
        assert record["status"] == "approved-retained"
        assert record["redistribution_status"] == "permitted"
        for field in ("source_creator", "redistribution_permission", "sanitization_status"):
            value = record[field].strip().lower()
            assert value
            assert not any(marker in value for marker in unknown_markers)
        denied_markers = ("denied", "no permission", "not permitted", "prohibited", "all rights reserved")
        permission = record["redistribution_permission"].strip().lower()
        assert not any(marker in permission for marker in denied_markers)
        if expected_category == "sanitized-example-report":
            assert record["sanitization_status"].strip().lower().startswith("sanitized")
        assert isinstance(record["expected_indicators"], list)
        digest = hashlib.sha256(ROOT.joinpath(path).read_bytes()).hexdigest()
        assert record["sha256"] == digest


def test_sample_documentation_contains_indicator_safety_warning():
    guidance = (ROOT / "docs" / "SAMPLES_AND_FIXTURES.md").read_text(encoding="utf-8")
    assert "Do not browse, resolve, or execute" in guidance
