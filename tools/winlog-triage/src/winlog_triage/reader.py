from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from typing import Any

from .normalization import normalize_event

try:
    import xmltodict
except ImportError:
    xmltodict = None

try:
    from Evtx.Evtx import Evtx
except ImportError:
    Evtx = None


class EvtxReadError(RuntimeError):
    """Raised when no EVTX backend can produce trustworthy output."""


@dataclass
class ParseStats:
    backend: str
    records_read: int = 0
    records_skipped: int = 0
    parse_errors: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReadResult:
    events: list[dict[str, Any]]
    stats: ParseStats


def _parse_event_xml(xml: str) -> dict[str, Any]:
    if xmltodict is None:
        raise EvtxReadError("xmltodict is required to parse EVTX XML")
    parsed = xmltodict.parse(xml)
    event = parsed.get("Event")
    if not isinstance(event, dict):
        raise TypeError("XML record has no Event object")
    return event


def read_evtx_python(evtx_path: str, limit: int | None = None) -> ReadResult:
    if Evtx is None:
        raise EvtxReadError("python-evtx is not installed")
    events: list[dict[str, Any]] = []
    stats = ParseStats(backend="python-evtx")
    with Evtx(evtx_path) as log:
        for record in log.records():
            try:
                events.append(_parse_event_xml(record.xml()))
                stats.records_read += 1
            except Exception:  # noqa: BLE001 - malformed records must be counted and skipped
                stats.records_skipped += 1
                stats.parse_errors += 1
            if limit is not None and stats.records_read >= limit:
                break
    return ReadResult(events, stats)


_EVENT_XML = re.compile(r"<Event\b.*?</Event>", re.DOTALL)
_POWERSHELL_SCRIPT = (
    "Get-WinEvent -LiteralPath $env:WINTRIAGE_EVTX_PATH | "
    "ForEach-Object { $_.ToXml() }"
)


def read_evtx_powershell(
    evtx_path: str,
    limit: int | None = None,
    runner: Callable[..., Any] = subprocess.run,
) -> ReadResult:
    command = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-Command", _POWERSHELL_SCRIPT,
    ]
    env = os.environ.copy()
    env["WINTRIAGE_EVTX_PATH"] = evtx_path
    process = runner(command, capture_output=True, text=True, check=False, env=env)
    if process.returncode != 0:
        detail = (process.stderr or "PowerShell EVTX reader failed").strip()
        raise EvtxReadError(detail)

    events: list[dict[str, Any]] = []
    stats = ParseStats(backend="powershell")
    for xml in _EVENT_XML.findall(process.stdout or ""):
        try:
            events.append(_parse_event_xml(xml))
            stats.records_read += 1
        except Exception:  # noqa: BLE001 - malformed records must be counted and skipped
            stats.records_skipped += 1
            stats.parse_errors += 1
        if limit is not None and stats.records_read >= limit:
            break
    return ReadResult(events, stats)


def read_evtx(evtx_path: str, limit: int | None = None) -> ReadResult:
    if Evtx is not None:
        return read_evtx_python(evtx_path, limit)
    if shutil.which("powershell.exe"):
        return read_evtx_powershell(evtx_path, limit)
    raise EvtxReadError("No EVTX backend available; install python-evtx or use Windows PowerShell.")


def iter_evtx(evtx_path: str, limit: int | None = None) -> Iterable[dict[str, Any]]:
    yield from read_evtx(evtx_path, limit).events

def collect_events(paths: list[str], max_per_file: int | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    aggregate = {"backend": "", "records_read": 0, "records_skipped": 0, "parse_errors": 0}
    backends = set()
    for path in paths:
        result = read_evtx(str(path), max_per_file)
        backends.add(result.stats.backend)
        normalized.extend(normalize_event(event, str(path)) for event in result.events)
        aggregate["records_read"] += result.stats.records_read
        aggregate["records_skipped"] += result.stats.records_skipped
        aggregate["parse_errors"] += result.stats.parse_errors
    aggregate["backend"] = ",".join(sorted(backends))
    return normalized, aggregate
