from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
WINLOG = ROOT / "tools" / "winlog-triage"
SRC = WINLOG / "src"
sys.path.insert(0, str(SRC))


def test_package_metadata_defines_installable_cli():
    text = (WINLOG / "pyproject.toml").read_text(encoding="utf-8")
    assert 'name = "winlog-triage"' in text
    assert 'winlog-triage = "winlog_triage.cli:main"' in text


def test_ioc_extraction_rejects_invalid_ipv4():
    from winlog_triage.iocs import extract_iocs

    result = extract_iocs("valid 192.0.2.10 invalid 999.999.999.999")

    assert result["ipv4"] == ["192.0.2.10"]


def test_normalization_extracts_common_sysmon_fields():
    from winlog_triage.normalization import normalize_event

    event = normalize_event(
        {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventID": {"#text": "1"},
                "TimeCreated": {"@SystemTime": "2026-01-01T00:00:00Z"},
                "Computer": "lab-host",
            },
            "EventData": {
                "Data": [
                    {"@Name": "Image", "#text": "C:\\Windows\\powershell.exe"},
                    {"@Name": "CommandLine", "#text": "powershell.exe -EncodedCommand Zg=="},
                ]
            },
        },
        "sample.evtx",
    )

    assert event["event_id"] == 1
    assert event["provider"] == "Microsoft-Windows-Sysmon"
    assert event["computer"] == "lab-host"
    assert event["commandline"].startswith("powershell.exe")


def test_rules_identify_encoded_powershell():
    from winlog_triage.rules import run_rules

    hits = run_rules({"commandline": "powershell.exe -EncodedCommand Zg=="})

    assert {hit["technique"] for hit in hits} == {"T1059.001"}


def test_powershell_reader_keeps_path_out_of_script_and_uses_literal_path():
    from winlog_triage.reader import read_evtx_powershell

    captured = {}
    hostile_path = "C:\\evidence\\case' ; Write-Output PWNED; #.evtx"

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    result = read_evtx_powershell(hostile_path, runner=fake_run)

    script = captured["command"][captured["command"].index("-Command") + 1]
    assert hostile_path not in script
    assert "-LiteralPath $env:WINTRIAGE_EVTX_PATH" in script
    assert captured["kwargs"]["env"]["WINTRIAGE_EVTX_PATH"] == hostile_path
    assert result.stats.backend == "powershell"
    assert result.stats.records_read == 0


def test_powershell_reader_surfaces_subprocess_failure():
    from winlog_triage.reader import EvtxReadError, read_evtx_powershell

    def fake_run(_command, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="Get-WinEvent failed")

    with pytest.raises(EvtxReadError, match="Get-WinEvent failed"):
        read_evtx_powershell("broken.evtx", runner=fake_run)


def test_python_reader_counts_successes_and_parse_errors(monkeypatch):
    from winlog_triage import reader

    class Record:
        def __init__(self, xml):
            self._xml = xml

        def xml(self):
            return self._xml

    class FakeEvtx:
        def __init__(self, _path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def records(self):
            return [Record("<Event><System /></Event>"), Record("<broken")]

    monkeypatch.setattr(reader, "Evtx", FakeEvtx)

    result = reader.read_evtx_python("fixture.evtx")

    assert len(result.events) == 1
    assert result.stats.backend == "python-evtx"
    assert result.stats.records_read == 1
    assert result.stats.records_skipped == 1
    assert result.stats.parse_errors == 1


def test_reader_counts_malformed_records():
    from winlog_triage.reader import read_evtx_powershell

    stdout = "<Event xmlns='x'><System /></Event>\n<Event broken></Event>"

    def fake_run(_command, **_kwargs):
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    result = read_evtx_powershell("fixture.evtx", runner=fake_run)

    assert result.stats.records_read == 1
    assert result.stats.records_skipped == 1
    assert result.stats.parse_errors == 1


def test_max_per_file_must_be_positive():
    from winlog_triage.cli import validate_max_per_file

    assert validate_max_per_file(None) is None
    assert validate_max_per_file(5) == 5
    with pytest.raises(ValueError, match="positive"):
        validate_max_per_file(0)
    with pytest.raises(ValueError, match="positive"):
        validate_max_per_file(-1)


def test_summary_includes_parser_completeness_metadata():
    from winlog_triage.analysis import triage

    parsing = {
        "backend": "python-evtx",
        "records_read": 8,
        "records_skipped": 2,
        "parse_errors": 2,
    }

    summary = triage([], parsing=parsing)

    assert summary["parsing"] == parsing


def test_module_cli_help_runs_from_source_tree():
    result = subprocess.run(
        [sys.executable, "-m", "winlog_triage", "--help"],
        env={**os.environ, "PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1"},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--max-per-file" in result.stdout


def test_cli_rejects_non_positive_max_per_file():
    result = subprocess.run(
        [sys.executable, "-m", "winlog_triage", "fake.evtx", "--max-per-file", "0"],
        env={**os.environ, "PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1"},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "must be a positive integer" in result.stderr
