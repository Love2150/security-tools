from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "pcap-profiler"
SRC = TOOL / "src"


def load_virustotal_module():
    path = SRC / "pcap_quick_profiler" / "virustotal.py"
    spec = importlib.util.spec_from_file_location("phase_two_virustotal", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repository_has_one_canonical_pcap_implementation():
    implementations = [
        path
        for path in ROOT.rglob("pcap_profiler.py")
        if ".hermes" not in path.parts and "__pycache__" not in path.parts
    ]
    assert implementations == [SRC / "pcap_quick_profiler" / "pcap_profiler.py"]
    assert not (ROOT / "tools" / "Pcap-profiler").exists()
    assert not (ROOT / "pyproject.toml").exists()


def test_package_exposes_module_and_console_entry_points():
    pyproject = (TOOL / "pyproject.toml").read_text(encoding="utf-8")
    assert 'pcap-profiler = "pcap_quick_profiler.pcap_profiler:main"' in pyproject
    assert (SRC / "pcap_quick_profiler" / "__main__.py").exists()


def test_virustotal_and_allowlist_are_packaged():
    assert (SRC / "pcap_quick_profiler" / "virustotal.py").exists()
    allowlist_path = SRC / "pcap_quick_profiler" / "enrichment" / "allowlist.json"
    data = json.loads(allowlist_path.read_text(encoding="utf-8"))
    assert sorted(data) == ["ja3", "sni"]


def test_virustotal_accepts_only_globally_routable_addresses(tmp_path, monkeypatch):
    module = load_virustotal_module()
    report = tmp_path / "capture.json"
    report.write_text(
        json.dumps(
            {
                "src_ips": [
                    ["1.1.1.1", 1],
                    ["10.0.0.8", 2],
                    ["224.0.0.251", 3],
                    ["239.255.255.250", 4],
                    ["240.0.0.1", 5],
                    ["not:an:ip", 6],
                ],
                "dst_ips": [
                    ["2606:4700:4700::1111", 1],
                    ["fc00::1", 2],
                    ["ff02::fb", 3],
                    ["ff05::c", 4],
                ],
            }
        ),
        encoding="utf-8",
    )
    assert module.ip_set_from_profiler_json(str(report)) == {
        "1.1.1.1",
        "2606:4700:4700::1111",
    }

    queried = []

    def fake_report(ip, api_key, session):
        queried.append(ip)
        return {"ip": ip, "positives": 0}

    monkeypatch.setattr(module, "vt_ip_report", fake_report)
    results = module.run_vt_checks(
        [
            "1.1.1.1",
            "10.0.0.8",
            "224.0.0.251",
            "239.255.255.250",
            "240.0.0.1",
            "not:an:ip",
            "fc00::1",
            "ff02::fb",
            "ff05::c",
        ],
        "test-key",
        delay=0,
    )
    assert queried == ["1.1.1.1"]
    assert list(results) == ["1.1.1.1"]


def test_source_distribution_excludes_capture_samples_and_generated_outputs():
    manifest = (TOOL / "MANIFEST.in").read_text(encoding="utf-8")
    for directory in ("samples", "out", "reports", "dist"):
        assert f"prune {directory}" in manifest


def test_source_module_cli_uses_canonical_package():
    result = subprocess.run(
        [sys.executable, "-m", "pcap_quick_profiler", "--help"],
        cwd=ROOT,
        env={"PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "PCAP Quick Profiler" in result.stdout


def test_virustotal_latest_finds_reports_from_current_directory(tmp_path):
    reports = tmp_path / "reports" / "pcap-profiler"
    reports.mkdir(parents=True)
    report = reports / "capture.json"
    report.write_text('{"src_ips": [], "dst_ips": []}', encoding="utf-8")
    unrelated = tmp_path / "settings.json"
    unrelated.write_text('{"theme": "dark"}', encoding="utf-8")
    newer = report.stat().st_mtime + 10
    os.utime(unrelated, (newer, newer))

    result = subprocess.run(
        [sys.executable, "-m", "pcap_quick_profiler.virustotal", "--latest"],
        cwd=tmp_path,
        env={"PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1"},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert f"Using latest profiler report: {reports / 'capture.json'}" in result.stdout
    assert "No IPs found" in result.stdout


def test_virustotal_outputs_default_to_current_directory(tmp_path, monkeypatch):
    module = load_virustotal_module()
    monkeypatch.chdir(tmp_path)

    assert module.vt_reports_dir(None) == tmp_path / "reports" / "vt"
    assert module.vt_reports_dir(str(tmp_path / "custom")) == tmp_path / "custom"
