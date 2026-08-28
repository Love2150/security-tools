from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
PCAP_MODULES = (
    ROOT / "tools/pcap-profiler/src/pcap_quick_profiler/pcap_profiler.py",
)
WINLOG_MODULE = ROOT / "tools/winlog-triage/wintriage.py"
VT_MODULE = ROOT / "tools/pcap-profiler/src/pcap_quick_profiler/virustotal.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def minimal_pcap_report(payload: str) -> dict:
    return {
        "file": payload,
        "packets": 1,
        "bytes": 1,
        "start": None,
        "end": None,
        "duration": 0,
        "protocols": [],
        "bytes_by_protocol": [],
        "src_ips": [],
        "dst_ips": [],
        "dst_ports": [],
        "http_hosts": [(payload, 1)],
        "http_user_agents": [(payload, 1)],
        "http_urls": [(payload, 1)],
        "http_content_types": [],
        "tls_versions": [],
        "tls_ciphers": [],
        "tls_sni": [(payload, 1)],
        "tls_ja3": [(payload, 1)],
        "beacon_suspects": [
            {"dst": payload, "sni": payload, "hits": 3, "avg_int": 1.0, "score": 1.0}
        ],
    }


@pytest.mark.parametrize("module_path", PCAP_MODULES)
def test_pcap_html_escapes_untrusted_evidence_and_uses_csp(tmp_path, module_path):
    module = load_module(module_path, f"pcap_{module_path.parent.name}")
    payload = '<script>alert("pcap")</script><img src=x onerror="alert(1)">'
    output = tmp_path / "report.html"

    module.write_html(str(output), minimal_pcap_report(payload))

    html = output.read_text(encoding="utf-8")
    assert payload not in html
    assert "&lt;script&gt;alert" in html
    assert 'http-equiv="Content-Security-Policy"' in html
    assert "script-src 'nonce-" in html
    csp_nonce = re.search(r"script-src 'nonce-([^']+)'", html)
    script_nonce = re.search(r'<script nonce="([^"]+)">', html)
    assert csp_nonce and script_nonce
    assert csp_nonce.group(1) == script_nonce.group(1)
    assert "onclick=" not in html
    assert "onload=" not in html


def test_winlog_html_escapes_untrusted_evidence_and_uses_csp():
    module = load_module(WINLOG_MODULE, "winlog_phase_one")
    payload = '<script>alert("evtx")</script><img src=x onerror="alert(1)">'
    event = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "provider": payload,
        "event_id": 1,
        "image": payload,
        "parent_image": "",
        "commandline": payload,
        "dest_ip": "",
        "dest_port": "",
        "raw": {"payload": payload},
    }

    html = module.render_html(module.triage([event]))

    assert payload not in html
    assert "&lt;script&gt;alert" in html
    assert 'http-equiv="Content-Security-Policy"' in html
    assert "onclick=" not in html


def packet(layer: str, src: str, dst: str, port: int, transport: str):
    pkt = SimpleNamespace(
        frame_info=SimpleNamespace(len="100", time_epoch="1704067200.0"),
        sniff_time=None,
        highest_layer=layer,
        ip=SimpleNamespace(src=src, dst=dst),
        tcp=None,
        udp=None,
        tls=None,
        http=None,
    )
    setattr(pkt, transport, SimpleNamespace(dstport=str(port)))
    return pkt


@pytest.mark.parametrize("module_path", PCAP_MODULES)
def test_pcap_baseline_counts_every_packet(monkeypatch, module_path):
    module = load_module(module_path, f"pcap_counts_{module_path.parent.name}")
    baseline = [
        packet("DNS", "10.0.0.1", "8.8.8.8", 53, "udp"),
        packet("SSH", "10.0.0.1", "10.0.0.2", 22, "tcp"),
    ]
    filters = []

    class FakeCapture:
        def __init__(self, packets):
            self.packets = packets

        def __iter__(self):
            return iter(self.packets)

        def close(self):
            return None

    def fake_capture(_path, **kwargs):
        display_filter = kwargs.get("display_filter")
        filters.append(display_filter)
        if display_filter is None:
            return FakeCapture(baseline)
        return FakeCapture([])

    monkeypatch.setattr(module, "ensure_tshark", lambda: None)
    monkeypatch.setattr(module.pyshark, "FileCapture", fake_capture)

    result = module.profile_pcap("fixture.pcap")

    assert filters[0] is None
    assert result["packets"] == 2
    assert result["bytes"] == 200
    assert dict(result["protocols"]) == {"DNS": 1, "SSH": 1}
    assert dict(result["dst_ports"]) == {"53": 1, "22": 1}


def test_vt_text_report_uses_run_vt_checks_result_shape(tmp_path):
    module = load_module(VT_MODULE, "vt_phase_one")
    results = {
        "1.2.3.4": {
            "ip": "1.2.3.4",
            "positives": 2,
            "last_analysis_stats": {
                "malicious": 1,
                "suspicious": 1,
                "harmless": 10,
                "undetected": 50,
                "timeout": 0,
            },
            "link": "https://www.virustotal.com/gui/ip-address/1.2.3.4",
        }
    }
    json_path = tmp_path / "vt.json"
    text_path = tmp_path / "vt.txt"

    module.write_vt_report(str(json_path), str(text_path), results)

    text = text_path.read_text(encoding="utf-8")
    assert "IPs checked: 1" in text
    assert "1.2.3.4" in text
    assert "malicious: 1" in text
    assert "suspicious: 1" in text
