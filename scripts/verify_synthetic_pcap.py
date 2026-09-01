from __future__ import annotations

import argparse
import json
from pathlib import Path


def verify_report_directory(report_directory: Path) -> None:
    reports = sorted(report_directory.glob("*.json"))
    if len(reports) != 1:
        raise ValueError(f"expected exactly one JSON report, found {len(reports)}")

    report = json.loads(reports[0].read_text(encoding="utf-8"))
    if report.get("packets") != 1:
        raise ValueError(f"expected one packet, found {report.get('packets')!r}")
    if report.get("bytes") != 60:
        raise ValueError(f"expected 60 bytes, found {report.get('bytes')!r}")
    if report.get("src_ips") != [["10.1.1.1", 1]]:
        raise ValueError(f"expected source 10.1.1.1, found {report.get('src_ips')!r}")
    if report.get("dst_ips") != [["10.2.2.2", 1]]:
        raise ValueError(f"expected destination 10.2.2.2, found {report.get('dst_ips')!r}")
    if report.get("dst_ports") != [["53", 1]]:
        raise ValueError(f"expected UDP destination port 53, found {report.get('dst_ports')!r}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify the synthetic PCAP profiler report")
    parser.add_argument("report_directory", type=Path)
    args = parser.parse_args()
    verify_report_directory(args.report_directory)


if __name__ == "__main__":
    main()
