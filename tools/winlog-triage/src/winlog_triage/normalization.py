from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def to_utc(dt_str: str) -> datetime | None:
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError):
        return None


def get_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def normalize_event(raw: dict[str, Any], source_file: str) -> dict[str, Any]:
    """Map an EVTX Event XML object to common analyst fields."""
    system = raw.get("System", {})
    event_data = raw.get("EventData") or raw.get("UserData") or {}
    flat: dict[str, str] = {}
    data_items: list[Any] = []
    if isinstance(event_data, dict):
        data_items = event_data.get("Data", [])
        if isinstance(data_items, dict):
            data_items = [data_items]
    for item in data_items or []:
        name = item.get("@Name") or item.get("Name") or ""
        value = item.get("#text") or item.get("value") or ""
        if name:
            flat[name] = get_text(value)

    event_id = system.get("EventID")
    if isinstance(event_id, dict):
        event_id = event_id.get("#text") or event_id.get("@Qualifiers") or ""
    provider = (system.get("Provider") or {}).get("@Name") or system.get("Channel") or ""
    timestamp = (system.get("TimeCreated") or {}).get("@SystemTime") or ""
    timestamp_utc = to_utc(timestamp)

    return {
        "source": str(source_file),
        "timestamp": timestamp_utc.isoformat() if timestamp_utc else timestamp,
        "event_id": safe_int(event_id, 0),
        "provider": provider,
        "computer": system.get("Computer") or "",
        "user": flat.get("User") or flat.get("SubjectUserName") or "",
        "image": flat.get("Image") or flat.get("NewProcessName") or flat.get("ProcessName") or "",
        "parent_image": flat.get("ParentImage") or flat.get("ParentProcessName") or "",
        "commandline": flat.get("CommandLine") or flat.get("ProcessCommandLine") or flat.get("NewProcessCommandLine") or "",
        "dest_ip": flat.get("DestinationIp") or flat.get("DestinationIP") or "",
        "dest_port": flat.get("DestinationPort") or "",
        "protocol": flat.get("Protocol") or "",
        "raw": {"system": system, "data": flat},
    }
