"""
Central configuration for the Digital Forensic Timeline Reconstruction pipeline.

Every rule, threshold and weight lives here as plain Python data so that each
module's behaviour can be read, tuned and explained without touching code.
Section numbers refer to the paper "An Explainable Framework for Digital
Forensic Timeline Reconstruction Using Heterogeneous System Logs".
"""
from dataclasses import dataclass, asdict

# --------------------------------------------------------------------------- #
# Log sources (Sec. 3.2)
# --------------------------------------------------------------------------- #
SOURCES = ("windows_sysmon", "firewall", "vpn_auth")
SOURCE_LABELS = {
    "windows_sysmon": "Windows / Sysmon",
    "firewall": "Firewall / Network",
    "vpn_auth": "VPN / Auth",
}

# --------------------------------------------------------------------------- #
# Canonical event record schema produced by the Log Normalization Engine (Sec. 3.3)
# All timestamps are tz-naive datetimes in UTC.
# --------------------------------------------------------------------------- #
CANONICAL_COLUMNS = [
    "timestamp", "source", "event_code", "channel",
    "host", "user", "src_ip", "dst_ip", "dst_port",
    "assigned_ip", "session_id", "device",
    "process", "command_line", "file_path", "target", "logon_type",
    "action", "bytes_out", "protocol", "message", "raw",
]

# --------------------------------------------------------------------------- #
# Attack stages and forensic event catalog (Sec. 3.4)
# event_type -> (stage, risk, description)
# risk: benign (context event), suspicious, high
# --------------------------------------------------------------------------- #
STAGES = [
    "INITIAL_ACCESS", "EXECUTION", "CREDENTIAL_ACCESS", "PRIVILEGE_ESCALATION",
    "PERSISTENCE", "LATERAL_MOVEMENT", "COLLECTION", "EXFILTRATION",
]
STAGE_INDEX = {s: i for i, s in enumerate(STAGES)}

EVENT_CATALOG = {
    "LOGIN":                ("INITIAL_ACCESS",       "benign",     "Successful logon"),
    "LOGIN_FAILED":         ("INITIAL_ACCESS",       "suspicious", "Failed logon attempt"),
    "LOGIN_REMOTE":         ("LATERAL_MOVEMENT",     "benign",     "Remote (RDP / network) logon"),
    "VPN_LOGIN":            ("INITIAL_ACCESS",       "benign",     "VPN session established"),
    "VPN_AUTH_FAILED":      ("INITIAL_ACCESS",       "suspicious", "VPN authentication failure"),
    "PROCESS_CREATE":       ("EXECUTION",            "benign",     "Process created"),
    "POWERSHELL_EXEC":      ("EXECUTION",            "suspicious", "PowerShell execution"),
    "CREDENTIAL_DUMP":      ("CREDENTIAL_ACCESS",    "high",       "Credential dumping (LSASS access / dumping tool)"),
    "PRIVILEGE_ESCALATION": ("PRIVILEGE_ESCALATION", "suspicious", "Special privileges assigned to logon"),
    "SCHEDULED_TASK":       ("PERSISTENCE",          "suspicious", "Scheduled task created"),
    "USER_CREATED":         ("PERSISTENCE",          "suspicious", "Local user account created"),
    "REGISTRY_RUN_KEY":     ("PERSISTENCE",          "suspicious", "Autorun registry key modified"),
    "DB_ACCESS":            ("COLLECTION",           "suspicious", "Connection to a database port"),
    "ARCHIVE_CREATED":      ("COLLECTION",           "suspicious", "Archive file created"),
    "FILE_CREATE":          ("COLLECTION",           "benign",     "File created"),
    "USB_DEVICE_ATTACHED":  ("COLLECTION",           "suspicious", "Removable storage attached"),
    "EXTERNAL_UPLOAD":      ("EXFILTRATION",         "high",       "Large outbound transfer to external host"),
    "CONNECTION_BLOCKED":   ("EXFILTRATION",         "suspicious", "Outbound connection blocked by firewall"),
}
RISK_ORDER = {"benign": 0, "suspicious": 1, "high": 2}

# --------------------------------------------------------------------------- #
# Event extraction rule parameters (Sec. 3.4)
# --------------------------------------------------------------------------- #
DB_PORTS = {1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 1521: "Oracle", 27017: "MongoDB"}
KNOWN_DB_CLIENTS = {"10.0.5.10"}          # application servers allowed to talk to the DB
INTERNAL_NETWORKS = (                     # anything outside these is treated as external
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "fc00::/7", "fe80::/10", "::1/128",
)
ARCHIVE_EXTENSIONS = (".zip", ".rar", ".7z", ".tar", ".gz", ".tgz")
CRED_DUMP_MARKERS = ("lsass", "mimikatz", "procdump", "sekurlsa", "dcsync", "ntds.dit", "comsvcs", "minidump")
POWERSHELL_MARKERS = ("powershell", "pwsh")
SUSPICIOUS_PS_FLAGS = ("-enc", "-encodedcommand", "-nop", "bypass", "downloadstring", "iex", "-w hidden", "invoke-expression")
AUTORUN_REGISTRY_MARKERS = ("\\currentversion\\run", "\\currentversion\\runonce", "\\winlogon\\")

# --------------------------------------------------------------------------- #
# Entity resolution link rules (Sec. 3.5): rule -> confidence
# --------------------------------------------------------------------------- #
LINK_CONFIDENCE = {
    "co_occurrence": 1.00,   # identifiers appear together in the same log record
    "vpn_session":   0.95,   # VPN assigned (tunnel) IP belongs to the VPN session
    "user_bridge":   0.70,   # same user seen in two sources within a time window
}

# --------------------------------------------------------------------------- #
# Cross-Source Event Graph transition weights alpha_i (Sec. 3.6, Eq. 1)
# Explicit pairs quantify how strongly event type A precedes event type B.
# Any pair not listed uses DEFAULT_TRANSITION based on stage order.
# --------------------------------------------------------------------------- #
TRANSITION_WEIGHTS = {
    ("LOGIN_FAILED", "LOGIN"): 0.80,
    ("VPN_AUTH_FAILED", "VPN_LOGIN"): 0.80,
    ("LOGIN", "POWERSHELL_EXEC"): 0.90,
    ("VPN_LOGIN", "POWERSHELL_EXEC"): 0.85,
    ("LOGIN", "PROCESS_CREATE"): 0.60,
    ("POWERSHELL_EXEC", "CREDENTIAL_DUMP"): 0.95,
    ("PROCESS_CREATE", "CREDENTIAL_DUMP"): 0.80,
    ("CREDENTIAL_DUMP", "PRIVILEGE_ESCALATION"): 0.90,
    ("PRIVILEGE_ESCALATION", "VPN_LOGIN"): 0.85,
    ("PRIVILEGE_ESCALATION", "LOGIN"): 0.80,
    ("CREDENTIAL_DUMP", "VPN_LOGIN"): 0.85,
    ("CREDENTIAL_DUMP", "LOGIN"): 0.80,
    ("CREDENTIAL_DUMP", "LOGIN_REMOTE"): 0.85,
    ("PRIVILEGE_ESCALATION", "LOGIN_REMOTE"): 0.85,
    ("LOGIN_REMOTE", "POWERSHELL_EXEC"): 0.85,
    ("LOGIN_REMOTE", "DB_ACCESS"): 0.70,
    ("VPN_LOGIN", "DB_ACCESS"): 0.80,
    ("LOGIN", "DB_ACCESS"): 0.60,
    ("DB_ACCESS", "ARCHIVE_CREATED"): 0.85,
    ("ARCHIVE_CREATED", "EXTERNAL_UPLOAD"): 0.95,
    ("DB_ACCESS", "EXTERNAL_UPLOAD"): 0.80,
    ("ARCHIVE_CREATED", "USB_DEVICE_ATTACHED"): 0.70,
    ("POWERSHELL_EXEC", "SCHEDULED_TASK"): 0.85,
    ("POWERSHELL_EXEC", "REGISTRY_RUN_KEY"): 0.85,
    ("POWERSHELL_EXEC", "USER_CREATED"): 0.80,
    ("POWERSHELL_EXEC", "EXTERNAL_UPLOAD"): 0.70,
    ("POWERSHELL_EXEC", "CONNECTION_BLOCKED"): 0.70,
    ("EXTERNAL_UPLOAD", "CONNECTION_BLOCKED"): 0.60,
}
DEFAULT_TRANSITION = {"forward": 0.55, "same": 0.35, "backward": 0.15}

# --------------------------------------------------------------------------- #
# Multi-stage attack templates (Sec. 3.7) used for pattern matching and
# missing-event detection.  template -> ordered list of (stage, indicator event types)
# --------------------------------------------------------------------------- #
ATTACK_TEMPLATES = {
    "Credential theft and data exfiltration": [
        ("INITIAL_ACCESS",       {"LOGIN", "LOGIN_FAILED", "VPN_LOGIN", "VPN_AUTH_FAILED"}),
        ("EXECUTION",            {"POWERSHELL_EXEC"}),
        ("CREDENTIAL_ACCESS",    {"CREDENTIAL_DUMP"}),
        ("PRIVILEGE_ESCALATION", {"PRIVILEGE_ESCALATION"}),
        ("LATERAL_MOVEMENT",     {"VPN_LOGIN", "LOGIN_REMOTE"}),
        ("COLLECTION",           {"DB_ACCESS", "ARCHIVE_CREATED"}),
        ("EXFILTRATION",         {"EXTERNAL_UPLOAD"}),
    ],
    "Insider data theft": [
        ("INITIAL_ACCESS", {"LOGIN", "VPN_LOGIN"}),
        ("COLLECTION",     {"DB_ACCESS", "ARCHIVE_CREATED", "USB_DEVICE_ATTACHED"}),
        ("EXFILTRATION",   {"EXTERNAL_UPLOAD"}),
    ],
    "Persistence foothold": [
        ("INITIAL_ACCESS",       {"LOGIN", "LOGIN_FAILED", "VPN_LOGIN", "LOGIN_REMOTE"}),
        ("EXECUTION",            {"POWERSHELL_EXEC"}),
        ("PRIVILEGE_ESCALATION", {"PRIVILEGE_ESCALATION"}),
        ("PERSISTENCE",          {"SCHEDULED_TASK", "USER_CREATED", "REGISTRY_RUN_KEY"}),
    ],
}

# --------------------------------------------------------------------------- #
# Attack Confidence Index tiers (Sec. 3.8, Table 1)
# --------------------------------------------------------------------------- #
ACI_TIERS = [  # (lower bound %, tier, suggested response)
    (82, "Critical", "Immediate incident response escalation"),
    (60, "High",     "Prioritize active investigation"),
    (35, "Medium",   "Analyst review within shift"),
    (0,  "Low",      "Log for review; no immediate action"),
]

# Simple recommendation rules keyed by event type (Sec. 3.8 / Table 4)
RECOMMENDATIONS = {
    "LOGIN_FAILED":         "Check for brute-force activity against {user} and enforce lockout policy",
    "VPN_AUTH_FAILED":      "Review VPN authentication failures for {user}; enforce MFA",
    "POWERSHELL_EXEC":      "Investigate PowerShell execution on {host} (command: {process})",
    "CREDENTIAL_DUMP":      "Reset credentials of every account that was logged on to {host}; treat {user} as compromised",
    "PRIVILEGE_ESCALATION": "Verify why {user} obtained elevated privileges on {host}",
    "SCHEDULED_TASK":       "Remove unauthorised scheduled task on {host}",
    "USER_CREATED":         "Disable newly created account on {host} and audit account provisioning",
    "REGISTRY_RUN_KEY":     "Remove autorun registry entry on {host}",
    "LOGIN_REMOTE":         "Verify remote logon of {user} to {host} from {src_ip}",
    "VPN_LOGIN":            "Terminate VPN session {session_id} of {user} and review VPN access policy",
    "DB_ACCESS":            "Audit database access from {src_ip} to {dst_ip}",
    "ARCHIVE_CREATED":      "Inspect archive {file_path} on {host} for staged data",
    "USB_DEVICE_ATTACHED":  "Quarantine removable media attached to {host}",
    "EXTERNAL_UPLOAD":      "Block attacker IP {dst_ip} at the perimeter and assess data loss",
    "CONNECTION_BLOCKED":   "Review blocked outbound connection from {src_ip} to {dst_ip}",
}


@dataclass
class Settings:
    """Tunable knobs. Defaults are deliberately simple and documented."""
    # normalization
    windows_tz_offset_hours: float = 0.0        # UTC offset of the Windows log clock (e.g. 5.5 for IST)
    # extraction
    upload_min_bytes: int = 50 * 1024 * 1024    # outbound bytes to count as EXTERNAL_UPLOAD
    # entity resolution
    user_bridge_window_min: int = 60            # window for user_bridge rule
    # graph construction
    same_entity_window_min: int = 60            # same-entity edge window
    temporal_window_min: int = 5                # temporal-proximity edge window (shared user, other entity)
    # chain search (Eq. 1)
    chain_threshold: float = 0.05               # keep chains with h(P) >= threshold
    min_transition: float = 0.50                # only follow edges with alpha >= this
    min_chain_length: int = 3
    max_chain_length: int = 10
    max_chains: int = 25
    # ACI weights w1..w4 (normalised at use time)
    w_src: float = 0.15
    w_coh: float = 0.15
    w_ent: float = 0.20
    w_pat: float = 0.50
    # temporal coherence
    coherence_ideal_gap_min: int = 15           # gaps up to this score 1.0
    coherence_max_gap_min: int = 120            # gaps at/after this score 0.0

    def weights(self) -> dict:
        raw = {"S_src": self.w_src, "T_coh": self.w_coh, "R_ent": self.w_ent, "M_pat": self.w_pat}
        total = sum(raw.values()) or 1.0
        return {k: v / total for k, v in raw.items()}

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Settings":
        fields = cls.__dataclass_fields__
        return cls(**{k: v for k, v in d.items() if k in fields})
