from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from .analysis import triage
from .reader import EvtxReadError, collect_events
from .reporting import render_html, write_csv, write_json


def validate_max_per_file(value: int | None) -> int | None:
    if value is not None and value <= 0:
        raise ValueError("--max-per-file must be a positive integer")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Windows Log Triage — EVTX + Sysmon to HTML, JSON, and CSV")
    parser.add_argument("target", nargs="+", help="EVTX file(s) or directories containing EVTX files")
    parser.add_argument("--outdir", default="out", help="Output directory (default: out)")
    parser.add_argument("--html", help="Exact HTML report path")
    parser.add_argument("--json", help="Exact JSON summary path")
    parser.add_argument("--csv", help="Exact CSV sample path")
    parser.add_argument("--max-per-file", type=int, help="Positive maximum records read from each file")
    return parser


def _expand_targets(targets: list[str]) -> list[str]:
    paths: list[str] = []
    for target in targets:
        path = Path(target)
        if path.is_dir():
            paths.extend(str(item) for item in sorted(path.glob("*.evtx")))
        elif path.is_file() and path.suffix.lower() == ".evtx":
            paths.append(str(path))
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        limit = validate_max_per_file(args.max_per_file)
    except ValueError as exc:
        parser.error(str(exc))

    paths = _expand_targets(args.target)
    if not paths:
        parser.error("no .evtx files found in the supplied targets")

    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    html_path = Path(args.html) if args.html else outdir / f"wintriage-{stamp}.html"
    json_path = Path(args.json) if args.json else outdir / f"wintriage-{stamp}.json"
    csv_path = Path(args.csv) if args.csv else outdir / f"wintriage-{stamp}.csv"

    try:
        events, parsing = collect_events(paths, limit)
    except EvtxReadError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    summary = triage(events, parsing=parsing)
    write_json(str(json_path), summary)
    write_csv(str(csv_path), summary["sample"])
    html_path.write_text(render_html(summary), encoding="utf-8")

    print(f"Parsed events: {summary['count']}")
    print(f"Backend: {parsing['backend']}")
    print(f"Skipped records: {parsing['records_skipped']} (parse errors: {parsing['parse_errors']})")
    print(f"Open report: {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
