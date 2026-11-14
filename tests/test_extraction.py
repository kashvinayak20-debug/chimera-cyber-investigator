import pandas as pd

from forensic.config import Settings
from forensic.extraction import extract_events, firewall_rule, is_public_ip, vpn_rule, windows_rule

S = Settings()


def test_windows_rules():
    assert windows_rule({"event_code": 4624, "host": "PC-001", "user": "a", "logon_type": "2"}, S)[0] == "LOGIN"
    assert windows_rule({"event_code": 4624, "host": "PC-001", "user": "a", "logon_type": "10", "src_ip": "10.0.0.5"}, S)[0] == "LOGIN_REMOTE"
    assert windows_rule({"event_code": 4625, "host": "PC-001", "user": "a"}, S)[0] == "LOGIN_FAILED"
    ps = windows_rule({"event_code": 1, "process": "powershell.exe", "command_line": "-nop -enc AAA", "host": "h", "user": "u"}, S)
    assert ps[0] == "POWERSHELL_EXEC" and "-enc" in ps[2]
    assert windows_rule({"event_code": 1, "process": "chrome.exe", "command_line": "", "host": "h", "user": "u"}, S)[0] == "PROCESS_CREATE"
    assert windows_rule({"event_code": 1, "process": "procdump.exe", "command_line": "-ma lsass.exe", "host": "h", "user": "u"}, S)[0] == "CREDENTIAL_DUMP"
    assert windows_rule({"event_code": 10, "process": "powershell.exe", "target": "C:\\Windows\\System32\\lsass.exe", "host": "h", "user": "u"}, S)[0] == "CREDENTIAL_DUMP"
    assert windows_rule({"event_code": 10, "process": "x.exe", "target": "C:\\notepad.exe", "host": "h", "user": "u"}, S) is None
    assert windows_rule({"event_code": 11, "process": "7z.exe", "file_path": "C:\\t\\x.zip", "host": "h", "user": "u"}, S)[0] == "ARCHIVE_CREATED"
    assert windows_rule({"event_code": 11, "process": "word.exe", "file_path": "C:\\t\\x.docx", "host": "h", "user": "u"}, S)[0] == "FILE_CREATE"
    assert windows_rule({"event_code": 3, "host": "h", "user": "u"}, S) is None


def test_firewall_rules():
    assert firewall_rule({"action": "DENY", "src_ip": "a", "dst_ip": "b", "dst_port": 8443, "bytes_out": 0}, S)[0] == "CONNECTION_BLOCKED"
    assert firewall_rule({"action": "ALLOW", "src_ip": "10.8.0.14", "dst_ip": "10.0.5.20", "dst_port": 1433, "bytes_out": 10}, S)[0] == "DB_ACCESS"
    assert firewall_rule({"action": "ALLOW", "src_ip": "10.0.5.10", "dst_ip": "10.0.5.20", "dst_port": 1433, "bytes_out": 10}, S) is None  # known client
    big = firewall_rule({"action": "ALLOW", "src_ip": "192.168.1.25", "dst_ip": "203.0.113.50", "dst_port": 443, "bytes_out": 500 * 2**20}, S)
    assert big[0] == "EXTERNAL_UPLOAD"
    assert firewall_rule({"action": "ALLOW", "src_ip": "192.168.1.25", "dst_ip": "203.0.113.50", "dst_port": 443, "bytes_out": 1000}, S) is None
    assert firewall_rule({"action": "ALLOW", "src_ip": "192.168.1.25", "dst_ip": "10.0.0.9", "dst_port": 443, "bytes_out": 500 * 2**20}, S) is None  # internal


def test_public_ip_rule():
    assert is_public_ip("203.0.113.50") and is_public_ip("8.8.8.8")
    assert not is_public_ip("192.168.1.1") and not is_public_ip("10.8.0.14") and not is_public_ip("nope")


def test_vpn_rules():
    assert vpn_rule({"action": "connect", "user": "u", "session_id": "S-1"}, S)[0] == "VPN_LOGIN"
    assert vpn_rule({"action": "auth_failed", "user": "u"}, S)[0] == "VPN_AUTH_FAILED"
    assert vpn_rule({"action": "disconnect", "user": "u"}, S) is None


def test_extract_events_keeps_rule_and_stage():
    df = pd.DataFrame([{"record_id": 0, "timestamp": pd.Timestamp("2026-07-08 10:00"), "source": "windows_sysmon",
                        "event_code": 4624, "host": "PC-001", "user": "u", "logon_type": "2"}])
    ev = extract_events(df, S)
    assert len(ev) == 1 and ev.iloc[0]["rule"] == "W-4624" and ev.iloc[0]["stage"] == "INITIAL_ACCESS"
