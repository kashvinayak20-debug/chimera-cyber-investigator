"""
Stage 2 - Log Normalization Engine (Sec. 3.3).

Converts each raw source into the canonical record schema in config.CANONICAL_COLUMNS.
- Windows / Sysmon : CSV export, "MM/DD/YYYY hh:mm:ss AM/PM" timestamps
- Firewall         : "<epoch> key=value ..." lines
- VPN / Auth       : "<ISO-8601> <gateway> key=value ..." lines
All timestamps become tz-naive datetimes in UTC.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from io import StringIO

import pandas as pd

from .collection import RawLog
from .config import CANONICAL_COLUMNS, Settings

KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
EPOCH_RE = re.compile(r"^\d{9,10}(?:\.\d+)?$")
NAIVE_FORMATS = (
    "%m/%d/%Y %I:%M:%S %p",   # 07/08/2026 10:20:05 PM  (Windows Event Viewer export)
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
)


def parse_kv(text: str) -> dict:
    """Parse key=value pairs; values may be double-quoted to contain spaces."""
    out = {}
    for m in KV_RE.finditer(text):
        out[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return out


def parse_timestamp(value, naive_offset_hours: float = 0.0) -> datetime | None:
    """
    Return a tz-naive UTC datetime, or None if unparseable.
    - epoch seconds            -> UTC
    - ISO with 'Z' or offset   -> converted to UTC
    - naive formats            -> assumed to be in a clock at `naive_offset_hours` from UTC
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.lower() == "nan":
        return None
    if EPOCH_RE.match(s):
        return datetime.fromtimestamp(float(s), tz=timezone.utc).replace(tzinfo=None)
    if s.endswith("Z"):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                pass
    for fmt in NAIVE_FORMATS:
        try:
            return datetime.strptime(s, fmt) - timedelta(hours=naive_offset_hours)
        except ValueError:
            continue
    try:
        ts = pd.Timestamp(s)
    except (ValueError, TypeError):
        return None
    if ts.tzinfo is None:
        return ts.to_pydatetime() - timedelta(hours=naive_offset_hours)
    return ts.tz_convert("UTC").tz_localize(None).to_pydatetime()


def _empty_record() -> dict:
    return {c: None for c in CANONICAL_COLUMNS}


def _clean_user(user) -> str | None:
    if user is None:
        return None
    u = str(user).strip()
    if not u or u == "-":
        return None
    if "\\" in u:                       # CORP\jsmith -> jsmith
        u = u.split("\\")[-1]
    return u.lower()


def _to_int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _get(row: dict, *names):
    for n in names:
        v = row.get(n.lower())
        if v is not None and not (isinstance(v, float) and pd.isna(v)) and str(v).strip() not in ("", "-", "nan"):
            return str(v).strip()
    return None


# --------------------------------------------------------------------------- #
# Per-source normalizers
# --------------------------------------------------------------------------- #
def normalize_windows(text: str, settings: Settings) -> pd.DataFrame:
    df = pd.read_csv(StringIO(text), dtype=str, keep_default_na=False)
    df.columns = [c.strip().lower() for c in df.columns]
    records = []
    for _, r in df.iterrows():
        row = r.to_dict()
        rec = _empty_record()
        rec["source"] = "windows_sysmon"
        rec["timestamp"] = parse_timestamp(_get(row, "TimeCreated", "TimeGenerated", "Timestamp", "Time"),
                                           settings.windows_tz_offset_hours)
        rec["event_code"] = _to_int(_get(row, "EventID", "Id"))
        rec["channel"] = _get(row, "Channel", "LogName")
        rec["host"] = (_get(row, "Computer", "Hostname", "Host") or "").upper() or None
        rec["user"] = _clean_user(_get(row, "User", "TargetUserName", "SubjectUserName", "AccountName"))
        rec["logon_type"] = _get(row, "LogonType")
        image = _get(row, "Image", "NewProcessName", "ProcessName")
        rec["process"] = image.replace("/", "\\").split("\\")[-1].lower() if image else None
        rec["command_line"] = _get(row, "CommandLine")
        rec["file_path"] = _get(row, "TargetFilename", "TargetObject", "ObjectName")
        rec["target"] = _get(row, "TargetImage", "TaskName", "TargetUser")
        rec["src_ip"] = _get(row, "SourceIp", "IpAddress")
        rec["dst_ip"] = _get(row, "DestinationIp")
        rec["dst_port"] = _to_int(_get(row, "DestinationPort"))
        rec["message"] = _get(row, "Message")
        rec["raw"] = ",".join(str(v) for v in r.values)
        records.append(rec)
    return pd.DataFrame(records, columns=CANONICAL_COLUMNS)


def normalize_firewall(text: str, settings: Settings) -> pd.DataFrame:
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        kv = parse_kv(parts[1]) if len(parts) > 1 else {}
        rec = _empty_record()
        rec["source"] = "firewall"
        rec["timestamp"] = parse_timestamp(parts[0])
        rec["action"] = (kv.get("action") or "").upper() or None
        rec["src_ip"] = kv.get("src")
        rec["dst_ip"] = kv.get("dst")
        rec["dst_port"] = _to_int(kv.get("dpt"))
        rec["protocol"] = kv.get("proto")
        rec["bytes_out"] = _to_int(kv.get("bytes_out"))
        rec["message"] = kv.get("msg")
        rec["raw"] = line
        records.append(rec)
    return pd.DataFrame(records, columns=CANONICAL_COLUMNS)


def normalize_vpn(text: str, settings: Settings) -> pd.DataFrame:
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        kv = parse_kv(parts[2]) if len(parts) > 2 else {}
        rec = _empty_record()
        rec["source"] = "vpn_auth"
        rec["timestamp"] = parse_timestamp(parts[0])
        rec["action"] = (kv.get("action") or "").lower() or None
        rec["user"] = _clean_user(kv.get("user"))
        rec["session_id"] = kv.get("session")
        rec["src_ip"] = kv.get("client_ip")
        rec["assigned_ip"] = kv.get("assigned_ip")
        device = kv.get("device")
        # The device label alone ("User Device") is generic; qualify it by user so it identifies one actor.
        rec["device"] = f"{rec['user']}/{device}" if device and rec["user"] else device
        rec["message"] = kv.get("reason") or kv.get("msg")
        rec["raw"] = line
        records.append(rec)
    return pd.DataFrame(records, columns=CANONICAL_COLUMNS)


NORMALIZERS = {
    "windows_sysmon": normalize_windows,
    "firewall": normalize_firewall,
    "vpn_auth": normalize_vpn,
}


def normalize_logs(raw_logs: list[RawLog], settings: Settings | None = None) -> tuple[pd.DataFrame, dict]:
    """Normalize all raw logs into one canonical DataFrame sorted by time."""
    settings = settings or Settings()
    frames, stats = [], {"per_source": {}, "dropped_no_timestamp": 0}
    for log in raw_logs:
        df = NORMALIZERS[log.source](log.text, settings)
        df["log_file"] = log.name
        dropped = int(df["timestamp"].isna().sum())
        stats["dropped_no_timestamp"] += dropped
        df = df[df["timestamp"].notna()]
        stats["per_source"][log.source] = stats["per_source"].get(log.source, 0) + len(df)
        frames.append(df)
    if not frames:
        return pd.DataFrame(columns=CANONICAL_COLUMNS + ["log_file", "record_id"]), stats
    out = pd.concat(frames, ignore_index=True)
    out["timestamp"] = pd.to_datetime(out["timestamp"])
    out = out.sort_values(["timestamp", "source"], kind="stable").reset_index(drop=True)
    out.insert(0, "record_id", range(len(out)))
    stats["total"] = len(out)
    return out, stats
