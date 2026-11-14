"""
Stage 1 - Log Collection Module (Sec. 3.2).

Gathers raw logs from files or uploads, leaves their content untouched and
tags each one with the source it came from.  Source detection is rule based.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .config import SOURCES

_EPOCH_LINE = re.compile(r"^\s*\d{9,10}(\.\d+)?\s+\S+=")


@dataclass
class RawLog:
    name: str          # file name
    source: str        # one of config.SOURCES
    text: str          # raw content, unmodified

    @property
    def line_count(self) -> int:
        return sum(1 for ln in self.text.splitlines() if ln.strip())


def detect_source(name: str, text: str) -> str | None:
    """Rule-based source detection: header / line shape first, filename as fallback."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    first = lines[0].lower()
    head = "\n".join(lines[:20]).lower()

    if "," in first and "eventid" in first.replace(" ", ""):
        return "windows_sysmon"                       # CSV export with an EventID column
    if "session=" in head or "assigned_ip=" in head or "client_ip=" in head:
        return "vpn_auth"                             # key=value VPN records
    if _EPOCH_LINE.match(lines[0]) and "src=" in head:
        return "firewall"                             # epoch + key=value firewall records

    lname = name.lower()
    if any(k in lname for k in ("win", "sysmon", "evtx", "security")):
        return "windows_sysmon"
    if any(k in lname for k in ("vpn", "auth")):
        return "vpn_auth"
    if any(k in lname for k in ("fw", "firewall", "net", "zeek")):
        return "firewall"
    return None


def load_text(name: str, text: str, source: str | None = None) -> RawLog:
    src = source or detect_source(name, text)
    if src not in SOURCES:
        raise ValueError(f"Could not detect log source for '{name}'. "
                         f"Expected one of {SOURCES}.")
    return RawLog(name=name, source=src, text=text)


def load_bytes(name: str, data: bytes, source: str | None = None) -> RawLog:
    return load_text(name, data.decode("utf-8", errors="replace"), source)


def load_file(path: str | Path, source: str | None = None) -> RawLog:
    p = Path(path)
    return load_text(p.name, p.read_text(encoding="utf-8", errors="replace"), source)


def load_directory(directory: str | Path) -> list[RawLog]:
    """Collect every recognised log file in a directory (ignores non-log files)."""
    logs = []
    for p in sorted(Path(directory).iterdir()):
        if p.suffix.lower() not in (".csv", ".log", ".txt"):
            continue
        try:
            logs.append(load_file(p))
        except ValueError:
            continue
    return logs
