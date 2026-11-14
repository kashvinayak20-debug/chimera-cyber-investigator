"""
Stage 4 - Entity Resolution Engine (Sec. 3.5).

Different logs name the same machine/actor differently: the Windows log has the
hostname PC-001, the firewall has 192.168.1.25, the VPN log has a session id and
"User Device".  This module links identifiers into resolved entities using
three explainable rules and a union-find structure:

  co_occurrence (1.00) - identifiers that appear in the same log record
                         (e.g. Sysmon EventID 3: Computer + SourceIp)
  vpn_session   (0.95) - a VPN session id and the tunnel IP it was assigned
  user_bridge   (0.70) - the same user seen in two different sources within a
                         time window (nearest record only)

Each entity's confidence is the mean confidence of the links that formed it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .config import LINK_CONFIDENCE, Settings

Identifier = tuple[str, str]        # (kind, value) e.g. ("host", "PC-001")


def _valid(v) -> bool:
    return v is not None and not (isinstance(v, float) and pd.isna(v)) and str(v).strip() not in ("", "-")


def primary_identifier(r: dict) -> Identifier | None:
    """The identifier that names the acting entity of one record."""
    src = r.get("source")
    if src == "windows_sysmon" and _valid(r.get("host")):
        return ("host", str(r["host"]))
    if src == "firewall" and _valid(r.get("src_ip")):
        return ("ip", str(r["src_ip"]))
    if src == "vpn_auth":
        if _valid(r.get("session_id")):
            return ("session", str(r["session_id"]))
        if _valid(r.get("src_ip")):
            return ("ip", str(r["src_ip"]))
    return None


def record_identifiers(r: dict) -> list[tuple[Identifier, str]]:
    """All actor-side identifiers in a record, with the link rule they support."""
    ids: list[tuple[Identifier, str]] = []
    src = r.get("source")
    if src == "windows_sysmon":
        if _valid(r.get("host")):
            ids.append((("host", str(r["host"])), "co_occurrence"))
        # Sysmon EventID 3 records the host's own source IP -> reliable host<->IP mapping.
        if r.get("event_code") == 3 and _valid(r.get("src_ip")):
            ids.append((("ip", str(r["src_ip"])), "co_occurrence"))
    elif src == "firewall":
        if _valid(r.get("src_ip")):
            ids.append((("ip", str(r["src_ip"])), "co_occurrence"))
    elif src == "vpn_auth":
        if _valid(r.get("session_id")):
            ids.append((("session", str(r["session_id"])), "co_occurrence"))
        if _valid(r.get("src_ip")):
            ids.append((("ip", str(r["src_ip"])), "co_occurrence"))
        if _valid(r.get("device")):
            ids.append((("device", str(r["device"])), "co_occurrence"))
        if _valid(r.get("assigned_ip")):
            ids.append((("ip", str(r["assigned_ip"])), "vpn_session"))
    return ids


class UnionFind:
    def __init__(self):
        self.parent: dict[Identifier, Identifier] = {}

    def add(self, x: Identifier):
        self.parent.setdefault(x, x)

    def find(self, x: Identifier) -> Identifier:
        self.add(x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: Identifier, b: Identifier):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


@dataclass
class EntityResolver:
    uf: UnionFind = field(default_factory=UnionFind)
    links: list[dict] = field(default_factory=list)
    entity_of: dict[Identifier, str] = field(default_factory=dict)
    entities: dict[str, dict] = field(default_factory=dict)

    def entity_for(self, ident: Identifier | None) -> str | None:
        if ident is None or ident not in self.uf.parent:
            return None
        return self.entity_of.get(self.uf.find(ident))


def _link(resolver: EntityResolver, a: Identifier, b: Identifier, rule: str, evidence: str, seen: set):
    key = (min(a, b), max(a, b), rule)
    resolver.uf.union(a, b)
    if key in seen:
        return
    seen.add(key)
    resolver.links.append({"a": f"{a[0]}:{a[1]}", "b": f"{b[0]}:{b[1]}", "rule": rule,
                           "confidence": LINK_CONFIDENCE[rule], "evidence": evidence})


def resolve_entities(normalized: pd.DataFrame, settings: Settings | None = None) -> EntityResolver:
    settings = settings or Settings()
    resolver = EntityResolver()
    seen: set = set()
    first_seen: dict[Identifier, pd.Timestamp] = {}
    records = normalized.to_dict("records")

    # Rule 1 & 2: identifiers inside one record belong to the same entity.
    for r in records:
        ids = record_identifiers(r)
        for ident, _ in ids:
            resolver.uf.add(ident)
            first_seen.setdefault(ident, r["timestamp"])
        if len(ids) < 2:
            continue
        anchor = ids[0][0]
        for ident, rule in ids[1:]:
            _link(resolver, anchor, ident, rule, f"record {r['record_id']} ({r['source']})", seen)

    # Rule 3: user bridge - same user seen in two sources within a window (nearest record only).
    per_user: dict[str, list[tuple[pd.Timestamp, str, Identifier]]] = {}
    for r in records:
        pid = primary_identifier(r)
        if pid is not None and _valid(r.get("user")):
            per_user.setdefault(str(r["user"]), []).append((r["timestamp"], r["source"], pid))
    window = pd.Timedelta(minutes=settings.user_bridge_window_min)
    for user, obs in per_user.items():
        obs.sort()
        for ts, src, pid in obs:
            for other_src in {o[1] for o in obs} - {src}:
                candidates = [(abs(o[0] - ts), o[2]) for o in obs if o[1] == other_src and abs(o[0] - ts) <= window]
                if not candidates:
                    continue
                _, other_pid = min(candidates)
                if other_pid != pid and resolver.uf.find(other_pid) != resolver.uf.find(pid):
                    _link(resolver, pid, other_pid, "user_bridge",
                          f"user {user} seen in {src} and {other_src} within {settings.user_bridge_window_min} min", seen)

    # Assign entity ids in order of first appearance; hostname preferred as label.
    groups: dict[Identifier, list[Identifier]] = {}
    for ident in resolver.uf.parent:
        groups.setdefault(resolver.uf.find(ident), []).append(ident)
    ordered = sorted(groups.items(), key=lambda kv: min(first_seen[i] for i in kv[1]))
    for n, (root, members) in enumerate(ordered, start=1):
        eid = f"ENT-{n:03d}"
        members = sorted(members, key=lambda i: (0 if i[0] == "host" else 1 if i[0] == "ip" else 2, i[1]))
        conf_values = [lk["confidence"] for lk in resolver.links
                       if resolver.uf.find(_parse(lk["a"])) == root]
        resolver.entity_of[root] = eid
        resolver.entities[eid] = {
            "entity_id": eid,
            "label": members[0][1],
            "identifiers": ", ".join(f"{k}:{v}" for k, v in members),
            "identifier_count": len(members),
            "link_count": len(conf_values),
            "confidence": round(sum(conf_values) / len(conf_values), 3) if conf_values else 1.0,
        }
    return resolver


def _parse(s: str) -> Identifier:
    kind, value = s.split(":", 1)
    return (kind, value)


def entities_frame(resolver: EntityResolver) -> pd.DataFrame:
    cols = ["entity_id", "label", "identifiers", "identifier_count", "link_count", "confidence"]
    return pd.DataFrame(list(resolver.entities.values()), columns=cols)


def links_frame(resolver: EntityResolver) -> pd.DataFrame:
    return pd.DataFrame(resolver.links, columns=["a", "b", "rule", "confidence", "evidence"])


def assign_entities(events: pd.DataFrame, resolver: EntityResolver) -> pd.DataFrame:
    """Attach entity_id / entity_label / entity_confidence to every extracted event."""
    events = events.copy()
    ids, labels, confs = [], [], []
    for r in events.to_dict("records"):
        eid = resolver.entity_for(primary_identifier(r))
        ent = resolver.entities.get(eid) if eid else None
        ids.append(eid)
        labels.append(ent["label"] if ent else None)
        confs.append(ent["confidence"] if ent else 1.0)
    events["entity_id"], events["entity_label"], events["entity_confidence"] = ids, labels, confs
    return events
