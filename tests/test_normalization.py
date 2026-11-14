from datetime import datetime

from forensic.collection import RawLog, detect_source
from forensic.config import CANONICAL_COLUMNS, Settings
from forensic.normalization import normalize_logs, parse_kv, parse_timestamp


def test_three_timestamp_formats_map_to_same_utc_instant():
    assert parse_timestamp("07/08/2026 10:20:15 PM") == datetime(2026, 7, 8, 22, 20, 15)
    assert parse_timestamp("2026-07-08T22:20:15Z") == datetime(2026, 7, 8, 22, 20, 15)
    assert parse_timestamp("1783549215") == datetime(2026, 7, 8, 22, 20, 15)
    assert parse_timestamp("2026-07-09T03:50:15+05:30") == datetime(2026, 7, 8, 22, 20, 15)


def test_windows_clock_offset_applied_only_to_naive_timestamps():
    assert parse_timestamp("07/08/2026 10:20:15 PM", naive_offset_hours=5.5) == datetime(2026, 7, 8, 16, 50, 15)
    assert parse_timestamp("2026-07-08T22:20:15Z", naive_offset_hours=5.5) == datetime(2026, 7, 8, 22, 20, 15)
    assert parse_timestamp("garbage") is None


def test_parse_kv_handles_quotes():
    kv = parse_kv('action=connect user=jsmith device="User Device" client_ip=192.168.1.25')
    assert kv == {"action": "connect", "user": "jsmith", "device": "User Device", "client_ip": "192.168.1.25"}


def test_detect_source_from_content():
    assert detect_source("x.csv", "TimeCreated,EventID,Computer\n1,2,3") == "windows_sysmon"
    assert detect_source("x.log", "1783549215 action=ALLOW src=1.2.3.4 dst=5.6.7.8 dpt=443") == "firewall"
    assert detect_source("x.log", "2026-07-08T22:20:15Z gw action=connect session=S-1 user=a") == "vpn_auth"


def test_normalize_all_sources_into_canonical_schema():
    logs = [
        RawLog("w.csv", "windows_sysmon", "TimeCreated,Channel,EventID,Computer,User,Image,CommandLine\n"
                                          "07/08/2026 10:20:00 AM,Security,4624,pc-001,CORP\\JSmith,,\n"
                                          "bad-time,Sysmon,1,PC-001,jsmith,C:\\x\\powershell.exe,-enc abc\n"),
        RawLog("f.log", "firewall", "1783549215 action=ALLOW src=192.168.1.25 dst=203.0.113.50 dpt=443 proto=TCP bytes_out=100\n"),
        RawLog("v.log", "vpn_auth", '2026-07-08T22:31:00Z gw action=connect user=jsmith session=S-1 device="User Device" client_ip=192.168.1.25 assigned_ip=10.8.0.14\n'),
    ]
    df, stats = normalize_logs(logs, Settings())
    assert set(CANONICAL_COLUMNS) <= set(df.columns)
    assert stats["dropped_no_timestamp"] == 1 and len(df) == 3
    win = df[df.source == "windows_sysmon"].iloc[0]
    assert win["host"] == "PC-001" and win["user"] == "jsmith" and win["event_code"] == 4624
    vpn = df[df.source == "vpn_auth"].iloc[0]
    assert vpn["session_id"] == "S-1" and vpn["assigned_ip"] == "10.8.0.14" and vpn["device"] == "jsmith/User Device"
    assert df["timestamp"].is_monotonic_increasing
