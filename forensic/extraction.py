"""
Stage 3 - Event Extraction Module (Sec. 3.4).

Rule-based classification of normalized records into forensic event types.
Every extracted event carries the `rule` id that produced it, so each
classification can be explained ("W-4624 fired because EventID == 4624").
Records that match no rule are low-relevance context and are not extracted
(they are still used by Entity Resolution for identifier linking).
"""
from __future__ import annotations

import ipaddress

import pandas as pd

from .config import (ARCHIVE_EXTENSIONS, AUTORUN_REGISTRY_MARKERS, CRED_DUMP_MARKERS,
                     DB_PORTS, EVENT_CATALOG, INTERNAL_NETWORKS, KNOWN_DB_CLIENTS,
                     POWERSHELL_MARKERS, SUSPICIOUS_PS_FLAGS, Settings)

_INTERNAL = [ipaddress.ip_network(n) for n in INTERNAL_NETWORKS]

EVENT_COLUMNS = [
    "event_id", "record_id", "timestamp", "source", "event_type", "stage", "risk", "rule", "summary",
    "host", "user", "src_ip", "dst_ip", "dst_port", "session_id", "assigned_ip", "device",
    "process", "command_line", "file_path", "raw",
]


def is_public_ip(ip) -> bool:
    """External = not in config.INTERNAL_NETWORKS (RFC1918, loopback, link-local, CGNAT)."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not any(addr in net for net in _INTERNAL)


def _s(v) -> str:
    return "" if v is None or (isinstance(v, float) and pd.isna(v)) else str(v)


# --------------------------------------------------------------------------- #
# Rules: each returns (event_type, rule_id, summary) or None
# --------------------------------------------------------------------------- #
def windows_rule(r: dict, settings: Settings):
    code = r.get("event_code")
    host, user = _s(r.get("host")), _s(r.get("user")) or "unknown"
    proc, cmd = _s(r.get("process")), _s(r.get("command_line"))
    cmd_l = f"{proc} {cmd}".lower()
    path = _s(r.get("file_path"))

    if code == 4624:
        lt = _s(r.get("logon_type"))
        if lt in ("10", "3", "7"):                          # RDP / network / unlock-from-remote
            return "LOGIN_REMOTE", "W-4624-REMOTE", f"User {user} logged on remotely to {host} from {_s(r.get('src_ip')) or '?'} (logon type {lt})"
        return "LOGIN", "W-4624", f"User {user} logged on to {host} (logon type {lt or '?'})"
    if code == 4625:
        return "LOGIN_FAILED", "W-4625", f"Failed logon for {user} on {host}"
    if code == 4672:
        return "PRIVILEGE_ESCALATION", "W-4672", f"Special privileges assigned to {user} on {host}"
    if code == 4698:
        return "SCHEDULED_TASK", "W-4698", f"Scheduled task '{_s(r.get('target'))}' created by {user} on {host}"
    if code == 4720:
        return "USER_CREATED", "W-4720", f"Account '{_s(r.get('target'))}' created by {user} on {host}"
    if code == 6416:
        return "USB_DEVICE_ATTACHED", "W-6416", f"Removable device attached to {host}"
    if code in (1, 4688):                                   # Sysmon 1 / Security 4688 process creation
        if any(m in cmd_l for m in CRED_DUMP_MARKERS):
            return "CREDENTIAL_DUMP", "W-PROC-CREDDUMP", f"{proc} run by {user} on {host} references a credential-dumping tool"
        if any(m in cmd_l for m in POWERSHELL_MARKERS):
            flags = [f for f in SUSPICIOUS_PS_FLAGS if f in cmd_l]
            note = f" with suspicious flags {flags}" if flags else ""
            return "POWERSHELL_EXEC", "W-PROC-POWERSHELL", f"PowerShell started by {user} on {host}{note}"
        return "PROCESS_CREATE", "W-PROC-CREATE", f"{proc} started by {user} on {host}"
    if code == 10:                                          # Sysmon 10 process access
        if "lsass" in _s(r.get("target")).lower():
            return "CREDENTIAL_DUMP", "W-SYSMON10-LSASS", f"{proc} opened a handle to lsass.exe on {host} (memory read)"
        return None
    if code == 11:                                          # Sysmon 11 file create
        if path.lower().endswith(ARCHIVE_EXTENSIONS):
            return "ARCHIVE_CREATED", "W-SYSMON11-ARCHIVE", f"Archive {path} created by {proc} on {host}"
        return "FILE_CREATE", "W-SYSMON11-FILE", f"File {path} created by {proc} on {host}"
    if code in (12, 13, 14):                                # Sysmon registry events
        if any(m in path.lower() for m in AUTORUN_REGISTRY_MARKERS):
            return "REGISTRY_RUN_KEY", "W-SYSMON13-AUTORUN", f"Autorun key {path} modified by {proc} on {host}"
        return None
    return None


def firewall_rule(r: dict, settings: Settings):
    action = _s(r.get("action")).upper()
    src, dst = _s(r.get("src_ip")), _s(r.get("dst_ip"))
    port = r.get("dst_port")
    port = int(port) if port is not None and not pd.isna(port) else None
    bytes_out = r.get("bytes_out")
    bytes_out = int(bytes_out) if bytes_out is not None and not pd.isna(bytes_out) else 0

    if action in ("DENY", "DROP", "BLOCK", "REJECT"):
        return "CONNECTION_BLOCKED", "FW-DENY", f"Firewall blocked {src} -> {dst}:{port}"
    if port in DB_PORTS and src not in KNOWN_DB_CLIENTS:
        return "DB_ACCESS", "FW-DBPORT", f"{src} connected to {DB_PORTS[port]} database at {dst}:{port}"
    if is_public_ip(dst) and bytes_out >= settings.upload_min_bytes:
        mb = bytes_out / (1024 * 1024)
        return "EXTERNAL_UPLOAD", "FW-BIGUPLOAD", f"{src} sent {mb:.0f} MB to external host {dst}:{port}"
    return None


def vpn_rule(r: dict, settings: Settings):
    action = _s(r.get("action")).lower()
    user, sess = _s(r.get("user")) or "unknown", _s(r.get("session_id"))
    if action in ("connect", "connected", "login", "session_start"):
        return "VPN_LOGIN", "VPN-CONNECT", f"VPN session {sess} established for {user} from {_s(r.get('src_ip'))} (tunnel IP {_s(r.get('assigned_ip'))})"
    if action in ("auth_failed", "failed", "denied", "reject"):
        return "VPN_AUTH_FAILED", "VPN-AUTHFAIL", f"VPN authentication failed for {user} from {_s(r.get('src_ip'))}"
    return None


RULES = {"windows_sysmon": windows_rule, "firewall": firewall_rule, "vpn_auth": vpn_rule}


def extract_events(normalized: pd.DataFrame, settings: Settings | None = None) -> pd.DataFrame:
    """Apply the rule set to every normalized record; return forensic events only."""
    settings = settings or Settings()
    events = []
    for r in normalized.to_dict("records"):
        result = RULES[r["source"]](r, settings)
        if result is None:
            continue
        event_type, rule, summary = result
        stage, risk, _ = EVENT_CATALOG[event_type]
        events.append({
            "record_id": r["record_id"], "timestamp": r["timestamp"], "source": r["source"],
            "event_type": event_type, "stage": stage, "risk": risk, "rule": rule, "summary": summary,
            "host": r.get("host"), "user": r.get("user"), "src_ip": r.get("src_ip"), "dst_ip": r.get("dst_ip"),
            "dst_port": r.get("dst_port"), "session_id": r.get("session_id"), "assigned_ip": r.get("assigned_ip"),
            "device": r.get("device"), "process": r.get("process"), "command_line": r.get("command_line"),
            "file_path": r.get("file_path"), "raw": r.get("raw"),
        })
    df = pd.DataFrame(events, columns=EVENT_COLUMNS[1:])
    df = df.sort_values(["timestamp", "record_id"], kind="stable").reset_index(drop=True)
    df.insert(0, "event_id", range(len(df)))
    return df
