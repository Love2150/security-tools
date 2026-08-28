"""Compatibility wrapper for the installable winlog_triage package."""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from winlog_triage.analysis import triage  # noqa: F401
from winlog_triage.cli import main
from winlog_triage.iocs import extract_iocs  # noqa: F401
from winlog_triage.normalization import normalize_event  # noqa: F401
from winlog_triage.reader import (  # noqa: F401
    collect_events,
    iter_evtx,
    read_evtx,
    read_evtx_powershell,
    read_evtx_python,
)
from winlog_triage.reporting import (  # noqa: F401
    render_html,
    write_csv,
    write_json,
)
from winlog_triage.rules import run_rules  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
