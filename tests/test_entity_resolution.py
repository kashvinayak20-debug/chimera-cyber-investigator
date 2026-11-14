import pandas as pd

from forensic.config import Settings
from forensic.entity_resolution import entities_frame, resolve_entities

T = pd.Timestamp("2026-07-08 10:00")


def _rec(i, **kw):
    base = {"record_id": i, "timestamp": T + pd.Timedelta(minutes=i), "source": None, "host": None, "user": None,
            "src_ip": None, "session_id": None, "device": None, "assigned_ip": None, "event_code": None}
    base.update(kw)
    return base


def test_hostname_ip_session_resolve_to_one_entity():
    df = pd.DataFrame([
        _rec(0, source="windows_sysmon", event_code=3, host="PC-001", user="jsmith", src_ip="192.168.1.25"),
        _rec(1, source="firewall", src_ip="192.168.1.25"),
        _rec(2, source="vpn_auth", user="jsmith", session_id="S-1", src_ip="192.168.1.25", assigned_ip="10.8.0.14", device="jsmith/User Device"),
        _rec(3, source="firewall", src_ip="10.8.0.14"),
        _rec(4, source="windows_sysmon", event_code=3, host="PC-002", user="amartin", src_ip="192.168.1.30"),
    ])
    r = resolve_entities(df, Settings())
    same = {r.entity_for(("host", "PC-001")), r.entity_for(("ip", "192.168.1.25")),
            r.entity_for(("session", "S-1")), r.entity_for(("ip", "10.8.0.14"))}
    assert len(same) == 1
    assert r.entity_for(("host", "PC-002")) not in same
    ents = entities_frame(r)
    assert len(ents) == 2
    pc1 = ents[ents.label == "PC-001"].iloc[0]
    assert 0.9 < pc1["confidence"] <= 1.0 and "session:S-1" in pc1["identifiers"]


def test_user_bridge_links_sources_without_shared_identifier():
    df = pd.DataFrame([
        _rec(0, source="windows_sysmon", event_code=4624, host="PC-009", user="bob"),
        _rec(5, source="vpn_auth", user="bob", session_id="S-9"),               # no client_ip -> only user bridge can link
        _rec(200, source="vpn_auth", user="bob", session_id="S-10"),            # outside the window
    ])
    r = resolve_entities(df, Settings(user_bridge_window_min=60))
    assert r.entity_for(("host", "PC-009")) == r.entity_for(("session", "S-9"))
    assert r.entity_for(("host", "PC-009")) != r.entity_for(("session", "S-10"))
    assert any(l["rule"] == "user_bridge" and l["confidence"] == 0.7 for l in r.links)
